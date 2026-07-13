use arc_swap::ArcSwap;
use bytes::Bytes;
use std::{collections::HashMap, pin::Pin, sync::Arc};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    select,
    sync::{
        Mutex, SetOnce,
        mpsc::{Sender, channel},
    },
};
use tracing::{Instrument, info, info_span, trace};

use crate::{
    ProxyRequest, Stoppable, TcpSession, TcpTrait, UdpSession, UserContext,
    config::AuthUser,
    error::{SError, SResult},
    msgs::{
        SDecode, SEncode,
        socks5::SocksAddr,
        squic::{
            ExtOpcodeConn, ExtOpcodeUser, SQExtError, SQExtOpcode, SQReq, SunnyCredential,
            UserStats,
        },
    },
    quic::QuicConnection,
    squic::wait_sunny_auth,
};

use super::{SQConn, handle_udp_packet_recv, handle_udp_recv_ctrl, handle_udp_send};

pub type SunnyQuicUserMap = HashMap<SunnyCredential, String>;
pub type SunnyQuicUsers = Arc<ArcSwap<SunnyQuicUserMap>>;

#[derive(Default)]
pub(crate) struct ConnectionRegistry {
    connections: Mutex<HashMap<u64, UserContext>>,
}

impl ConnectionRegistry {
    pub(crate) async fn register(&self, context: UserContext) {
        let mut connections = self.connections.lock().await;
        connections.retain(|_, existing| existing.conn_handle.upgrade().is_some());
        connections.insert(context.conn_id, context);
    }

    pub(crate) async fn close_user(&self, username: &str) {
        let to_close = {
            let mut connections = self.connections.lock().await;
            let mut to_close = Vec::new();
            connections.retain(|_, context| {
                let live = context.conn_handle.upgrade().is_some();
                if live && context.username == username {
                    to_close.push(context.conn_handle.clone());
                    false
                } else {
                    live
                }
            });
            to_close
        };
        for connection in to_close {
            if let Some(connection) = connection.upgrade() {
                connection.stop();
            }
        }
    }
}

#[async_trait::async_trait]
pub trait UserManager: Send + Sync {
    async fn add_user(&self, user: AuthUser) -> Result<(), SQExtError>;
    async fn remove_user(&self, username: &str) -> Result<(), SQExtError>;
    async fn list_users(&self) -> Result<Vec<String>, SQExtError>;
    async fn get_user_stats(&self, username: &str) -> Result<UserStats, SQExtError>;
    async fn get_all_stats(&self) -> Result<Vec<UserStats>, SQExtError>;
    async fn kill_user_conns(&self, username: &str) -> Result<(), SQExtError>;
}

#[derive(Clone)]
pub struct SQServerConn<C: QuicConnection> {
    pub inner: SQConn<C>,
    pub users: Option<SunnyQuicUsers>,
    pub sunny_credential: Option<Arc<SetOnce<SunnyCredential>>>,
    pub user_manager: Option<Arc<dyn UserManager>>,
    pub(crate) connections: Arc<ConnectionRegistry>,
}
impl<C: QuicConnection> SQServerConn<C> {
    fn user_context(self: &Arc<Self>, username: String) -> UserContext {
        UserContext {
            username,
            conn_handle: Arc::downgrade(&(self.clone() as Arc<dyn Stoppable>)),
            conn_id: self.inner.conn.peer_id(),
        }
    }

    async fn current_user(self: &Arc<Self>) -> SResult<String> {
        let username = wait_sunny_auth(&self.inner).await?;
        if let Some(users) = &self.users {
            let credential = self
                .sunny_credential
                .as_ref()
                .and_then(|credential| credential.get())
                .ok_or(SError::ProtocolViolation)?;
            if users.load().get(credential.as_ref()) != Some(&username) {
                self.inner.close(0, b"user revoked");
                return Err(SError::SunnyAuthError("User revoked".into()));
            }
        }
        Ok(username)
    }

    pub async fn handle_connection(
        self: Arc<Self>,
        req_send: Sender<ProxyRequest>,
    ) -> Result<(), SError> {
        let conn = &self.inner;
        info!(peer_address = %conn.remote_address(), "incoming connection accepted");
        let conn_clone = self.inner.clone();
        tokio::spawn(async move {
            let _ = handle_udp_packet_recv(conn_clone).in_current_span().await;
        });

        while conn.close_reason().is_none() {
            select! {
                bi = conn.accept_bi() => {
                    let (send, recv, id) = bi?;
                    let span = info_span!("bistream", id = id);
                    trace!("bistream accepted");
                    tokio::spawn(self.clone().handle_bistream(send, recv, req_send.clone()).instrument(span).in_current_span());
                },
            }
        }
        Ok(())
    }
    async fn handle_bistream(
        self: Arc<Self>,
        send: C::SendStream,
        mut recv: C::RecvStream,
        req_send: Sender<ProxyRequest>,
    ) -> Result<(), SError> {
        let req = SQReq::decode(&mut recv).await?;

        // let rate: f32 = (self.0.conn.stats().path.lost_packets as f32)
        //     / ((self.0.conn.stats().path.sent_packets + 1) as f32);
        // info!(
        //     "packet_loss_rate:{:.2}%, rtt:{:?}, mtu:{}",
        //     rate * 100.0,
        //     self.0.conn.rtt(),
        //     self.0.conn.stats().path.current_mtu,
        // );
        match req {
            SQReq::SQConnect(dst) => {
                let user = self.current_user().await?;
                info!(dst = %dst, "tcp connect request accepted");
                let tcp: TcpSession = TcpSession {
                    stream: Box::new(Unsplit { s: send, r: recv }),
                    dst,
                    user_context: Some(self.user_context(user)),
                };
                req_send
                    .send(ProxyRequest::Tcp(tcp))
                    .await
                    .map_err(|_| SError::OutboundUnavailable)?;
            }
            ref req @ (SQReq::SQAssociatOverDatagram(ref dst)
            | SQReq::SQAssociatOverStream(ref dst)) => {
                let user = self.current_user().await?;
                info!(bind_addr = %dst, "udp associate request accepted");
                let (local_send, udp_recv) = channel::<(Bytes, SocksAddr)>(10);
                let (udp_send, local_recv) = channel::<(Bytes, SocksAddr)>(10);
                let udp: UdpSession = UdpSession {
                    send: Arc::new(udp_send),
                    recv: Box::new(udp_recv),
                    stream: None,
                    bind_addr: dst.clone(),
                    user_context: Some(self.user_context(user)),
                };
                let local_send = Arc::new(local_send);
                req_send
                    .send(ProxyRequest::Udp(udp))
                    .await
                    .map_err(|_| SError::OutboundUnavailable)?;
                let fut1 = handle_udp_send(
                    send,
                    Box::new(local_recv),
                    self.inner.clone(),
                    req == &SQReq::SQAssociatOverStream(dst.clone()),
                );
                let fut2 = handle_udp_recv_ctrl(recv, local_send, self.inner.clone());
                tokio::try_join!(fut1, fut2)?;
            }
            SQReq::SQAuthenticate(passwd_hash) => {
                if self.inner.authed.get().is_some() {
                    self.inner.close(0, b"repeated authentication");
                    return Err(SError::ProtocolViolation);
                }
                let Some(users) = &self.users else {
                    return Err(SError::ProtocolViolation);
                };
                let name = users.load().get(passwd_hash.as_ref()).cloned();
                if let Some(name) = name {
                    tracing::info!("user authenticated:{}", name);
                    self.sunny_credential
                        .as_ref()
                        .ok_or(SError::ProtocolViolation)?
                        .set(passwd_hash)
                        .map_err(|_| SError::ProtocolViolation)?;
                    self.inner
                        .authed
                        .set(Ok(name.clone()))
                        .map_err(|_| SError::ProtocolViolation)?;
                    self.connections.register(self.user_context(name)).await;
                } else {
                    tracing::error!("authentication failed");
                    // 263 is tested result by connecting with sunnyquic client to
                    // cloudflare.com:443
                    self.inner.close(263, &[]);
                    return Err(SError::SunnyAuthError("Wrong password/username".into()));
                }
            }
            SQReq::SQExtension(ext_opcode) => {
                self.handle_extension(ext_opcode, send, recv).await?;
            }
            SQReq::SQBind(_) => return Err(SError::ProtocolUnimpl),
        }
        Ok(())
    }
    pub(crate) async fn handle_extension(
        self: &Arc<Self>,
        ext_opcode: SQExtOpcode,
        mut send: C::SendStream,
        mut _recv: C::RecvStream,
    ) -> SResult<()> {
        let authed_user = self.current_user().await?;
        match ext_opcode {
            SQExtOpcode::Conn(conn_opcode) => match conn_opcode {
                ExtOpcodeConn::GetConnStats => {
                    let stats = self.inner.get_conn_stats().ok_or(SQExtError::NotAvailable);
                    stats.encode(&mut send).await?;
                }
            },
            SQExtOpcode::User(user_opcode) => {
                self.handle_user_extension(&authed_user, user_opcode, &mut send)
                    .await?;
            }
        }
        Ok(())
    }

    async fn handle_user_extension(
        self: &Arc<Self>,
        authed_user: &str,
        user_opcode: ExtOpcodeUser,
        send: &mut C::SendStream,
    ) -> SResult<()> {
        if !authed_user.starts_with("admin") {
            (Err::<(), SQExtError>(SQExtError::PermissionDenied))
                .encode(send)
                .await?;
            return Ok(());
        }

        let user_manager = match self.user_manager.as_ref() {
            Some(user_manager) => user_manager,
            None => {
                (Err::<(), SQExtError>(SQExtError::NotAvailable))
                    .encode(send)
                    .await?;
                return Ok(());
            }
        };
        match user_opcode {
            ExtOpcodeUser::AddUser(user) => {
                info!(username = %user.username, "adding user");
                user_manager.add_user(user).await.encode(send).await?;
            }
            ExtOpcodeUser::RemoveUser(username) => {
                info!(username = %username, "removing user");
                user_manager
                    .remove_user(&username)
                    .await
                    .encode(send)
                    .await?;
            }
            ExtOpcodeUser::ListUsers => {
                user_manager.list_users().await.encode(send).await?;
            }
            ExtOpcodeUser::GetUserStats(username) => {
                info!(username = %username, "getting user stats");
                user_manager
                    .get_user_stats(&username)
                    .await
                    .encode(send)
                    .await?;
            }
            ExtOpcodeUser::GetAllStats => {
                info!("getting all user stats");
                user_manager.get_all_stats().await.encode(send).await?;
            }
            ExtOpcodeUser::KillUserConn(username) => {
                info!(username = %username, "killing user connections");
                user_manager
                    .kill_user_conns(&username)
                    .await
                    .encode(send)
                    .await?;
            }
        }
        Ok(())
    }
}

impl<C: QuicConnection> Stoppable for SQServerConn<C> {
    fn stop(&self) {
        self.inner.conn.close(0, &[]);
    }

    fn remote_address(&self) -> Option<std::net::SocketAddr> {
        Some(crate::utils::dual_socket::to_ipv4_mapped(
            self.inner.conn.remote_address(),
        ))
    }
}
#[derive(Debug)]
pub struct Unsplit<S, R> {
    pub s: S,
    pub r: R,
}
impl<S: AsyncWrite + Unpin + Sync + Send, R: AsyncRead + Unpin + Sync + Send> TcpTrait
    for Unsplit<S, R>
{
}

impl<S: AsyncWrite + Unpin, R: AsyncRead + Unpin> AsyncRead for Unsplit<S, R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.as_mut().r).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin, R: AsyncRead + Unpin> AsyncWrite for Unsplit<S, R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.as_mut().s).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.as_mut().s).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.as_mut().s).poll_shutdown(cx)
    }
}
