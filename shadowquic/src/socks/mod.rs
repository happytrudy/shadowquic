use std::{
    io::{self, Cursor},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::{net::UdpSocket, sync::OnceCell};
use tracing::warn;

use crate::utils::dual_socket::to_ipv4_mapped;
use crate::{
    UdpRecv, UdpSend,
    error::SError,
    msgs::socks5::{self, SocksAddr, UdpReqHeader},
};

use crate::msgs::{SDecode, SEncode};
pub mod inbound;
pub mod outbound;

#[derive(Clone)]
pub struct UdpSocksWrap {
    socket: Arc<UdpSocket>,
    remote: OnceCell<SocketAddr>,
    allowed_peer_ip: Option<IpAddr>,
}

impl UdpSocksWrap {
    fn inbound(socket: Arc<UdpSocket>, peer_ip: Option<IpAddr>) -> Self {
        Self {
            socket,
            remote: OnceCell::new(),
            allowed_peer_ip: peer_ip.map(|ip| to_ipv4_mapped(SocketAddr::new(ip, 0)).ip()),
        }
    }

    fn connected(socket: Arc<UdpSocket>, remote: SocketAddr) -> Self {
        Self {
            socket,
            remote: OnceCell::new_with(Some(remote)),
            allowed_peer_ip: None,
        }
    }
}

#[async_trait]
impl UdpRecv for UdpSocksWrap {
    async fn recv_from(&mut self) -> Result<(Bytes, SocksAddr), SError> {
        loop {
            let mut buf = BytesMut::zeroed(usize::from(u16::MAX));
            let (len, peer) = self.socket.recv_from(&mut buf).await?;
            let peer = to_ipv4_mapped(peer);
            if self
                .allowed_peer_ip
                .is_some_and(|allowed| allowed != peer.ip())
            {
                warn!(%peer, "dropping SOCKS UDP packet from unauthenticated peer");
                continue;
            }
            buf.truncate(len);

            let mut cur = Cursor::new(buf);
            let req = socks5::UdpReqHeader::decode(&mut cur).await?;
            if req.frag != 0 {
                warn!("dropping fragmented UDP datagram");
                continue;
            }
            let header_size =
                usize::try_from(cur.position()).map_err(|_| SError::ProtocolViolation)?;
            if header_size > len {
                return Err(SError::ProtocolViolation);
            }
            self.remote
                .get_or_try_init(|| async {
                    self.socket.connect(peer).await?;
                    Ok::<SocketAddr, io::Error>(peer)
                })
                .await?;
            let buf = cur.into_inner().freeze();
            return Ok((buf.slice(header_size..), req.dst));
        }
    }
}
#[async_trait]
impl UdpSend for UdpSocksWrap {
    async fn send_to(&self, buf: Bytes, addr: SocksAddr) -> Result<usize, SError> {
        let reply = UdpReqHeader {
            rsv: 0,
            frag: 0,
            dst: addr,
        };
        let mut buf_new = BytesMut::with_capacity(1600);
        let header = Vec::new();
        let mut cur = Cursor::new(header);
        reply.encode(&mut cur).await?;
        let header = cur.into_inner();
        buf_new.put(Bytes::from(header));
        buf_new.put(buf);

        Ok(self.socket.send(&buf_new).await?)
    }
}
