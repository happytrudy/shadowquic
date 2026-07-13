use std::{
    net::SocketAddr,
    sync::{Arc, Weak},
};

use bytes::Bytes;
use error::SError;
use msgs::socks5::SocksAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::error;

pub mod config;
pub mod direct;
pub mod error;
#[cfg(feature = "mixed")]
pub mod http;
#[cfg(feature = "mixed")]
pub mod mixed;
pub mod msgs;
mod observe;
pub mod quic;
pub mod shadowquic;
pub mod socks;
pub mod squic;
pub mod sunnyquic;
#[cfg(all(feature = "tproxy", target_os = "linux"))]
pub mod tproxy;
pub mod utils;

pub use msgs::SDecode;
pub use msgs::SEncode;
pub enum ProxyRequest<T = AnyTcp, I = AnyUdpRecv, O = AnyUdpSend> {
    Tcp(TcpSession<T>),
    Udp(UdpSession<I, O>),
}

impl<T, I, O> ProxyRequest<T, I, O> {
    pub fn remote_address(&self) -> Option<SocketAddr> {
        match self {
            Self::Tcp(session) => session.remote_address(),
            Self::Udp(session) => session.remote_address(),
        }
    }

    pub fn username(&self) -> Option<&str> {
        match self {
            Self::Tcp(session) => session.username(),
            Self::Udp(session) => session.username(),
        }
    }
}
/// Udp socket only use immutable reference to self
/// So it can be safely wrapped by Arc and cloned to work in duplex way.
#[async_trait]
pub trait UdpSend: Send + Sync + Unpin {
    async fn send_to(&self, buf: Bytes, addr: SocksAddr) -> Result<usize, SError>; // addr is proxy addr
}
#[async_trait]
pub trait UdpRecv: Send + Sync + Unpin {
    async fn recv_from(&mut self) -> Result<(Bytes, SocksAddr), SError>; // socksaddr is proxy addr
}
pub trait Stoppable: Send + Sync {
    fn stop(&self);

    fn remote_address(&self) -> Option<SocketAddr> {
        None
    }
}
pub type UserName = String;
pub struct TcpSession<IO = AnyTcp> {
    pub stream: IO,
    pub dst: SocksAddr,
    #[allow(dead_code)]
    user_context: Option<UserContext>,
}

pub struct UdpSession<I = AnyUdpRecv, O = AnyUdpSend> {
    pub recv: I,
    pub send: O,
    /// Control stream, should be kept alive during session.
    stream: Option<AnyTcp>,
    bind_addr: SocksAddr,
    #[allow(dead_code)]
    user_context: Option<UserContext>,
}
#[derive(Clone)]
pub struct UserContext {
    pub username: UserName,
    pub conn_handle: Weak<dyn Stoppable>,
    pub conn_id: u64,
}

impl UserContext {
    pub fn remote_address(&self) -> Option<SocketAddr> {
        self.conn_handle
            .upgrade()
            .and_then(|connection| connection.remote_address())
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}

impl<IO> TcpSession<IO> {
    pub fn remote_address(&self) -> Option<SocketAddr> {
        self.user_context
            .as_ref()
            .and_then(UserContext::remote_address)
    }

    pub fn username(&self) -> Option<&str> {
        self.user_context.as_ref().map(UserContext::username)
    }
}

impl<I, O> UdpSession<I, O> {
    pub fn remote_address(&self) -> Option<SocketAddr> {
        self.user_context
            .as_ref()
            .and_then(UserContext::remote_address)
    }

    pub fn username(&self) -> Option<&str> {
        self.user_context.as_ref().map(UserContext::username)
    }
}

pub type AnyTcp = Box<dyn TcpTrait>;
pub type AnyUdpSend = Arc<dyn UdpSend>;
pub type AnyUdpRecv = Box<dyn UdpRecv>;
pub trait TcpTrait: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl TcpTrait for TcpStream {}

#[async_trait]
pub trait Inbound<T = AnyTcp, I = AnyUdpRecv, O = AnyUdpSend>: Send + Sync + Unpin {
    async fn accept(&mut self) -> Result<ProxyRequest<T, I, O>, SError>;
    async fn init(&self) -> Result<(), SError> {
        Ok(())
    }
}

#[async_trait]
pub trait Outbound<T = AnyTcp, I = AnyUdpRecv, O = AnyUdpSend>: Send + Sync + Unpin {
    async fn handle(&mut self, req: ProxyRequest<T, I, O>) -> Result<(), SError>;
}

#[async_trait]
impl UdpSend for Sender<(Bytes, SocksAddr)> {
    async fn send_to(&self, buf: Bytes, addr: SocksAddr) -> Result<usize, SError> {
        let siz = buf.len();
        self.send((buf, addr))
            .await
            .map_err(|_| SError::InboundUnavailable)?;
        Ok(siz)
    }
}
#[async_trait]
impl UdpRecv for Receiver<(Bytes, SocksAddr)> {
    async fn recv_from(&mut self) -> Result<(Bytes, SocksAddr), SError> {
        let r = self.recv().await.ok_or(SError::OutboundUnavailable)?;
        Ok(r)
    }
}
pub struct Manager {
    pub inbound: Box<dyn Inbound>,
    pub outbound: Box<dyn Outbound>,
}

impl Manager {
    pub async fn run(self) -> Result<(), SError> {
        self.inbound.init().await?;
        let mut inbound = self.inbound;
        let mut outbound = self.outbound;
        loop {
            match inbound.accept().await {
                Ok(req) => match outbound.handle(req).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!("error during handling request: {}", e)
                    }
                },
                Err(e) => {
                    error!("error during accepting request: {}", e)
                }
            }
        }
        #[allow(unreachable_code)]
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use super::{Stoppable, UserContext};

    struct TestConnection(SocketAddr);

    impl Stoppable for TestConnection {
        fn stop(&self) {}

        fn remote_address(&self) -> Option<SocketAddr> {
            Some(self.0)
        }
    }

    #[test]
    fn user_context_exposes_live_connection_remote_address() {
        let expected = "203.0.113.8:443".parse().unwrap();
        let connection: Arc<dyn Stoppable> = Arc::new(TestConnection(expected));
        let context = UserContext {
            username: "test".to_owned(),
            conn_handle: Arc::downgrade(&connection),
            conn_id: 1,
        };

        assert_eq!(context.remote_address(), Some(expected));
        assert_eq!(context.username(), "test");
        drop(connection);
        assert_eq!(context.remote_address(), None);
    }
}
