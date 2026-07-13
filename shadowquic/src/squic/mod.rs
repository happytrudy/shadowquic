//! This module is shared by sunnyquic and shadowquic
//! It handles the general tcp/udp proxying logic over quic connection
//! It contains an optional authentication feature for sunnyquic only

use std::{
    collections::{
        HashMap,
        hash_map::{self, Entry},
    },
    io::Cursor,
    ops::Deref,
    sync::{Arc, atomic::AtomicU16},
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{
        RwLock, SetOnce,
        watch::{Receiver, Sender, channel},
    },
};
use tracing::{Instrument, Level, debug, event, info, trace};

use crate::{
    AnyUdpRecv, AnyUdpSend, UdpSend,
    error::{SError, SResult},
    msgs::{
        SDecode, SEncode,
        socks5::SocksAddr,
        squic::{SQPacketDatagramHeader, SQReq, SQUdpControlHeader, SunnyCredential},
    },
    quic::QuicConnection,
};

pub mod inbound;
pub mod outbound;

/// SQuic connection, it is shared by shadowquic and sunnyquic and is a wrapper of quic connection.
/// It contains a connection object and two ID store for managing UDP sockets.
/// The IDStore stores the mapping between ids and the destionation addresses as well as associated sockets
#[derive(Clone)]
pub struct SQConn<T: QuicConnection> {
    pub(crate) conn: T,
    pub authed: Arc<SetOnce<SResult<String>>>,
    pub(crate) send_id_store: IDStore<()>,
    pub(crate) recv_id_store: IDStore<(AnyUdpSend, SocksAddr)>,
}

async fn wait_sunny_auth<T: QuicConnection>(conn: &SQConn<T>) -> SResult<String> {
    match tokio::time::timeout(Duration::from_millis(3200), conn.authed.wait()).await {
        Ok(Ok(name)) => Ok(name.clone()),
        Ok(Err(SError::SunnyAuthError(_))) => {
            Err(SError::SunnyAuthError("Wrong password/username".into()))
        }
        Err(_) => Err(SError::SunnyAuthError("timeout".into())),
        _ => unreachable!(),
    }
}

pub(crate) async fn auth_sunny<T: QuicConnection>(
    conn: &SQConn<T>,
    username: &str,
    user_hash: SunnyCredential,
) -> SResult<()> {
    if conn.authed.get().is_none() {
        let (mut send, _recv, _id) = conn.open_bi().await?;
        SQReq::SQAuthenticate(user_hash).encode(&mut send).await?;
        debug!("authentication request sent");
        conn.authed
            .set(Ok(username.to_string()))
            .map_err(|_| SError::ProtocolViolation)?;
    }
    Ok(())
}

impl<T: QuicConnection> Deref for SQConn<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

pub(crate) struct NotifyBuffer {
    pub(crate) notify: Sender<()>,
    pub(crate) buffer: Vec<Bytes>,
    pub(crate) buffered_bytes: usize,
}

impl NotifyBuffer {
    fn new(notify: Sender<()>) -> Self {
        Self {
            notify,
            buffer: Vec::new(),
            buffered_bytes: 0,
        }
    }

    fn push(&mut self, packet: Bytes) -> SResult<()> {
        let buffered_bytes = self
            .buffered_bytes
            .checked_add(packet.len())
            .ok_or(SError::ProtocolViolation)?;
        if self.buffer.len() >= MAX_PENDING_PACKETS_PER_CONTEXT
            || buffered_bytes > MAX_PENDING_BYTES_PER_CONTEXT
        {
            return Err(SError::ProtocolViolation);
        }
        self.buffered_bytes = buffered_bytes;
        self.buffer.push(packet);
        Ok(())
    }
}

const MAX_CONTEXT_IDS: usize = 4096;
const MAX_PENDING_CONTEXTS: usize = 128;
const MAX_PENDING_PACKETS_PER_CONTEXT: usize = 32;
const MAX_PENDING_BYTES_PER_CONTEXT: usize = 256 * 1024;

// Use watch channel here. Notify is not suitable here
// see https://github.com/tokio-rs/tokio/issues/3757
type IDStoreVal<T> = Result<T, NotifyBuffer>;

enum SocketLookup<T> {
    Ready(T),
    Wait(Receiver<()>),
}
/// IDStore is a thread-safe store for managing UDP sockets and their associated ids.
/// It uses a HashMap to store the mapping between ids and the destination addresses as well as associated sockets.
/// It also uses an atomic counter to generate unique ids for new sockets.
#[derive(Clone)]
pub(crate) struct IDStore<T = (AnyUdpSend, SocksAddr)> {
    pub(crate) id_counter: Arc<AtomicU16>,
    pub(crate) inner: Arc<RwLock<HashMap<u16, IDStoreVal<T>>>>,
}

impl<T> Default for IDStore<T> {
    fn default() -> Self {
        Self {
            id_counter: Arc::new(AtomicU16::new(0)),
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl<T> IDStore<T>
where
    T: Clone,
{
    async fn get_socket_or_notify(&self, id: u16) -> SResult<SocketLookup<T>> {
        if let Some(r) = self.inner.read().await.get(&id) {
            return Ok(match r {
                Ok(value) => SocketLookup::Ready(value.clone()),
                Err(pending) => SocketLookup::Wait(pending.notify.subscribe()),
            });
        }

        let mut inner = self.inner.write().await;
        if let Some(r) = inner.get(&id) {
            Ok(match r {
                Ok(value) => SocketLookup::Ready(value.clone()),
                Err(pending) => SocketLookup::Wait(pending.notify.subscribe()),
            })
        } else {
            let pending_contexts = inner.values().filter(|value| value.is_err()).count();
            if inner.len() >= MAX_CONTEXT_IDS || pending_contexts >= MAX_PENDING_CONTEXTS {
                return Err(SError::ProtocolViolation);
            }
            let (sender, receiver) = channel(());
            inner.insert(id, Err(NotifyBuffer::new(sender)));
            Ok(SocketLookup::Wait(receiver))
        }
    }
    async fn try_get_socket(&self, id: u16) -> Option<T> {
        if let Some(r) = self.inner.read().await.get(&id) {
            match r {
                Ok(s) => Some(s.clone()),
                Err(_) => None,
            }
        } else {
            None
        }
    }
    async fn get_socket_or_wait(&self, id: u16) -> Result<T, SError> {
        match self.get_socket_or_notify(id).await? {
            SocketLookup::Ready(value) => Ok(value),
            SocketLookup::Wait(mut receiver) => {
                // This may fail is UDP session is closed right at this moment.
                receiver
                    .changed()
                    .await
                    .map_err(|_| SError::UDPSessionClosed("notify sender dropped".to_string()))?;
                //
                let ret = self
                    .try_get_socket(id)
                    .await
                    .ok_or(SError::UDPSessionClosed("UDP session closed".to_string()))?;
                Ok(ret)
            }
        }
    }
    async fn fetch_new_id(&self, val: T) -> SResult<u16> {
        let mut inner = self.inner.write().await;
        trace!("sending side socket number: {}", inner.len());
        if inner.len() >= MAX_CONTEXT_IDS {
            return Err(SError::ProtocolViolation);
        }
        for _ in 0..=u16::MAX {
            let id = self
                .id_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Entry::Vacant(entry) = inner.entry(id) {
                entry.insert(Ok(val));
                return Ok(id);
            }
        }
        Err(SError::ProtocolViolation)
    }
}

impl IDStore {
    async fn feed_datagram(&self, id: u16, packet: Bytes) -> SResult<()> {
        let ready = {
            let inner = self.inner.read().await;
            inner.get(&id).and_then(|value| match value {
                Ok((socket, addr)) => Some((socket.clone(), addr.clone())),
                Err(_) => None,
            })
        };
        if let Some((socket, addr)) = ready {
            socket.send_to(packet, addr.clone()).await?;
            return Ok(());
        }

        let ready = {
            let mut inner = self.inner.write().await;
            if let Some(value) = inner.get_mut(&id) {
                match value {
                    Ok((socket, addr)) => Some((socket.clone(), addr.clone())),
                    Err(pending) => {
                        pending.push(packet.clone())?;
                        None
                    }
                }
            } else {
                let pending_contexts = inner.values().filter(|value| value.is_err()).count();
                if inner.len() >= MAX_CONTEXT_IDS || pending_contexts >= MAX_PENDING_CONTEXTS {
                    return Err(SError::ProtocolViolation);
                }
                let (sender, _receiver) = channel(());
                let mut pending = NotifyBuffer::new(sender);
                pending.push(packet.clone())?;
                inner.insert(id, Err(pending));
                None
            }
        };
        if let Some((socket, addr)) = ready {
            socket.send_to(packet, addr).await?;
        }
        Ok(())
    }
    async fn store_socket_with_prelude(
        &self,
        id: u16,
        val: (Arc<dyn UdpSend>, SocksAddr),
    ) -> SResult<()> {
        let pending = {
            let mut inner = self.inner.write().await;
            trace!("receiving side alive socket number: {}", inner.len());
            if let Some(value) = inner.get_mut(&id) {
                if value.is_ok() {
                    return Err(SError::ProtocolViolation);
                }
                let previous = std::mem::replace(value, Ok(val.clone()));
                previous.err().ok_or(SError::ProtocolViolation)?
            } else {
                if inner.len() >= MAX_CONTEXT_IDS {
                    return Err(SError::ProtocolViolation);
                }
                inner.insert(id, Ok(val));
                return Ok(());
            }
        };

        pending
            .notify
            .send(())
            .unwrap_or_else(|_| debug!("id:{} notifier without subscriber", id));
        event!(Level::TRACE, "notify socket id:{}", id);
        let (socket, addr) = val;
        for bytes in pending.buffer {
            socket.send_to(bytes, addr.clone()).await?;
        }
        Ok(())
    }
}

/// AssociateSendSession is a session for sending UDP packets.
/// It is created for each association task
/// The local dst_map works as a inverse map from destination to id
/// When session ended, the ids created by this session will be removed from the IDStore.
struct AssociateSendSession<W: AsyncWrite> {
    id_store: IDStore<()>,
    dst_map: HashMap<SocksAddr, u16>,
    unistream_map: HashMap<SocksAddr, W>,
}
impl<W: AsyncWrite> AssociateSendSession<W> {
    pub async fn get_id_or_insert(&mut self, addr: &SocksAddr) -> SResult<(u16, bool)> {
        if let Some(id) = self.dst_map.get(addr) {
            Ok((*id, false))
        } else {
            let id = self.id_store.fetch_new_id(()).await?;
            self.dst_map.insert(addr.clone(), id);
            debug!(context_id = id, dst = %addr, "send session insert");
            Ok((id, true))
        }
    }
}

impl<W: AsyncWrite> Drop for AssociateSendSession<W> {
    fn drop(&mut self) {
        let id_store = self.id_store.inner.clone();
        let id_remove = self.dst_map.clone();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(
            async move {
                let mut id_store = id_store.write().await;
                let len = id_store.len();
                id_remove.values().for_each(|k| {
                    id_store.remove(k);
                });
                let decrease = len - id_store.len();
                event!(
                    Level::TRACE,
                    "AssociateSendSession dropped, session id size:{}, {} ids cleaned",
                    id_remove.len(),
                    decrease
                );
            }
            .in_current_span(),
        );
    }
}
/// AssociateRecvSession is a session for receiving UDP ctrl stream.
/// It is created for each association task
/// There are two usages for id_map
/// First, it works as local cache avoiding using global store repeatedly which is more expensive
/// Second. it records ids created by this session and clean those ids when session ended.
struct AssociateRecvSession {
    id_store: IDStore<(AnyUdpSend, SocksAddr)>,
    id_map: HashMap<u16, SocksAddr>,
}
impl AssociateRecvSession {
    pub async fn store_socket(
        &mut self,
        id: u16,
        dst: SocksAddr,
        socks: AnyUdpSend,
    ) -> SResult<()> {
        let hash_map::Entry::Vacant(entry) = self.id_map.entry(id) else {
            return Err(SError::ProtocolViolation);
        };
        self.id_store
            .store_socket_with_prelude(id, (socks, dst.clone()))
            .await?;
        debug!(context_id = id, dst = %dst, "recv session insert");
        entry.insert(dst);
        Ok(())
    }
}

impl Drop for AssociateRecvSession {
    fn drop(&mut self) {
        let id_store = self.id_store.inner.clone();
        let id_remove = self.id_map.clone();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(
            async move {
                let mut id_store = id_store.write().await;
                let len = id_store.len();

                id_remove.keys().for_each(|k| {
                    id_store.remove(k);
                });
                let decrease = len - id_store.len();
                event!(
                    Level::TRACE,
                    "AssociateRecvSession dropped, session id size:{}, {} ids cleaned",
                    id_remove.len(),
                    decrease
                );
            }
            .in_current_span(),
        );
    }
}

/// Handle udp packets send
/// It watches the udp socket and sends the packets to the quic connection.
/// This function is symetrical for both clients and servers.
pub async fn handle_udp_send<C: QuicConnection>(
    mut send: C::SendStream,
    udp_recv: AnyUdpRecv,
    conn: SQConn<C>,
    over_stream: bool,
) -> Result<(), SError> {
    let mut down_stream = udp_recv;
    let mut session = AssociateSendSession {
        id_store: conn.send_id_store.clone(),
        dst_map: Default::default(),
        unistream_map: Default::default(),
    };
    let quic_conn = conn.conn.clone();
    loop {
        let (bytes, dst) = down_stream.recv_from().await?;
        let (id, is_new) = session.get_id_or_insert(&dst).await?;
        //let span = trace_span!("udp", id = id);
        let ctl_header = SQUdpControlHeader {
            dst: dst.clone(),
            id,
        };
        let dg_header = SQPacketDatagramHeader { id };
        if over_stream && !session.unistream_map.contains_key(&dst) {
            let (uni, _id) = conn.open_uni().await?;
            session.unistream_map.insert(dst.clone(), uni);
        }

        let fut1 = async {
            if is_new {
                ctl_header.encode(&mut send).await?;
            }
            //trace!("udp control header sent");
            Ok(()) as Result<(), SError>
        };
        let fut2 = async {
            let mut content = BytesMut::with_capacity(2000);
            let mut head = Vec::<u8>::new();
            dg_header.clone().encode(&mut head).await?;

            if over_stream {
                // Must be opened and inserted.
                let conn = session
                    .unistream_map
                    .get_mut(&dst)
                    .ok_or(SError::ProtocolViolation)?;
                let mut head = Vec::<u8>::new();
                if is_new {
                    dg_header.encode(&mut head).await?
                }
                (bytes.len() as u16).encode(&mut head).await?;
                conn.write_all(&head).await?;
                conn.write_all(&bytes).await?;
            } else {
                content.put(Bytes::from(head));
                content.put(bytes);
                let content = content.freeze();
                quic_conn.send_datagram(content).await?;
            }
            Ok(())
        };
        tokio::try_join!(fut1, fut2)?;
    }
    #[allow(unreachable_code)]
    Ok(())
}

/// Handle udp ctrl stream receive task
/// it retrieves the dst id pair from the bistream and records related socket and address
/// This function is symetrical for both clients and servers.
pub async fn handle_udp_recv_ctrl<C: QuicConnection>(
    mut recv: C::RecvStream,
    udp_socket: AnyUdpSend,
    conn: SQConn<C>,
) -> Result<(), SError> {
    let mut session = AssociateRecvSession {
        id_store: conn.recv_id_store.clone(),
        id_map: Default::default(),
    };
    loop {
        let SQUdpControlHeader { id, dst } = SQUdpControlHeader::decode(&mut recv).await?;
        info!(context_id = id, dst = %dst, "udp control header received");
        session.store_socket(id, dst, udp_socket.clone()).await?;
    }
    #[allow(unreachable_code)]
    Ok(())
}

/// Handle udp packet receive task
/// It watches udp packets from quic connection and sends them to the udp socket.
/// The udp socket could be downstream(inbound) or upstream(outbound)
/// This function is symetrical for both clients and servers.
pub async fn handle_udp_packet_recv<C: QuicConnection>(conn: SQConn<C>) -> Result<(), SError> {
    let id_store = conn.recv_id_store.clone();
    wait_sunny_auth(&conn).await?;
    loop {
        tokio::select! {
            b = conn.read_datagram() => {
                let b = b?;
                let b = BytesMut::from(b);
                let mut cur = Cursor::new(b);
                let SQPacketDatagramHeader{id} = SQPacketDatagramHeader::decode(&mut cur).await?;
                let pos = cur.position() as usize;
                id_store.feed_datagram(id, cur.into_inner().split_off(pos).freeze()).await?;
            }

            r = async {
                let (mut uni_stream, _id) = conn.accept_uni().await?;
                trace!("unistream accepted");
                let SQPacketDatagramHeader{id} = SQPacketDatagramHeader::decode(&mut uni_stream).await?;
                trace!(context_id = id, "resolving datagram id");

                let (udp,addr) = id_store.get_socket_or_wait(id).await?;

                info!(context_id = id, peer_addr = %conn.remote_address(), dst = %addr, "udp over stream");
                Ok((uni_stream,udp.clone(),addr.clone())) as Result<(C::RecvStream,AnyUdpSend,SocksAddr),SError>
            } => {

                let  (mut uni_stream,udp,addr) = match r {
                    Ok(r) => r,
                    Err(SError::UDPSessionClosed(_)) => {
                        continue;
                    }
                    Err(e) => {
                        return Err(e);
                    }
                };

                tokio::spawn(async move {
                    loop {
                        let l: usize = u16::decode(&mut uni_stream).await? as usize;
                        let mut b = BytesMut::with_capacity(l);
                        b.resize(l,0);
                        uni_stream.read_exact(&mut b).await?;
                        udp.send_to(b.freeze(), addr.clone()).await?;
                    }
                    #[allow(unreachable_code)]
                    (Ok(()) as Result<(), SError>)
                }.in_current_span());
            }
        }
    }
    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Mutex};

    use async_trait::async_trait;

    use super::{
        IDStore, MAX_CONTEXT_IDS, MAX_PENDING_BYTES_PER_CONTEXT, MAX_PENDING_CONTEXTS,
        MAX_PENDING_PACKETS_PER_CONTEXT,
    };
    use crate::{UdpSend, error::SError, msgs::socks5::SocksAddr};
    use bytes::Bytes;

    #[derive(Default)]
    struct RecordingUdpSend {
        packets: Mutex<Vec<Bytes>>,
    }

    #[async_trait]
    impl UdpSend for RecordingUdpSend {
        async fn send_to(&self, buf: Bytes, _addr: SocksAddr) -> Result<usize, SError> {
            let len = buf.len();
            self.packets.lock().unwrap().push(buf);
            Ok(len)
        }
    }

    fn target() -> SocksAddr {
        SocksAddr::from("127.0.0.1:53".parse::<SocketAddr>().unwrap())
    }

    #[tokio::test]
    async fn pending_datagrams_are_bounded() {
        let store = IDStore::default();
        for _ in 0..MAX_PENDING_PACKETS_PER_CONTEXT {
            store
                .feed_datagram(1, Bytes::from_static(b"x"))
                .await
                .unwrap();
        }
        assert!(matches!(
            store.feed_datagram(1, Bytes::from_static(b"x")).await,
            Err(SError::ProtocolViolation)
        ));

        let store = IDStore::default();
        assert!(matches!(
            store
                .feed_datagram(1, Bytes::from(vec![0; MAX_PENDING_BYTES_PER_CONTEXT + 1]),)
                .await,
            Err(SError::ProtocolViolation)
        ));
    }

    #[tokio::test]
    async fn pending_contexts_are_bounded() {
        let store = IDStore::default();
        for id in 0..MAX_PENDING_CONTEXTS as u16 {
            store
                .feed_datagram(id, Bytes::from_static(b"x"))
                .await
                .unwrap();
        }
        assert!(matches!(
            store
                .feed_datagram(MAX_PENDING_CONTEXTS as u16, Bytes::from_static(b"x"))
                .await,
            Err(SError::ProtocolViolation)
        ));
    }

    #[tokio::test]
    async fn installing_socket_releases_lock_before_io_and_rejects_duplicates() {
        let store = IDStore::default();
        store
            .feed_datagram(7, Bytes::from_static(b"buffered"))
            .await
            .unwrap();
        let sender = std::sync::Arc::new(RecordingUdpSend::default());
        store
            .store_socket_with_prelude(7, (sender.clone(), target()))
            .await
            .unwrap();

        assert!(store.inner.try_write().is_ok());
        assert_eq!(
            sender.packets.lock().unwrap().as_slice(),
            [Bytes::from_static(b"buffered")]
        );
        assert!(matches!(
            store.store_socket_with_prelude(7, (sender, target())).await,
            Err(SError::ProtocolViolation)
        ));
    }

    #[tokio::test]
    async fn context_id_exhaustion_returns_an_error() {
        let store = IDStore::<()>::default();
        {
            let mut inner = store.inner.write().await;
            for id in 0..MAX_CONTEXT_IDS as u16 {
                inner.insert(id, Ok(()));
            }
        }
        assert!(matches!(
            store.fetch_new_id(()).await,
            Err(SError::ProtocolViolation)
        ));
    }
}
