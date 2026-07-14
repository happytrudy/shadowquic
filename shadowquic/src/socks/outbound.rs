use std::{net::SocketAddr, sync::Arc};

use crate::{
    TcpSession, UdpRecv, UdpSend, UdpSession,
    msgs::socks5::{
        AddrOrDomain, CmdReply, PasswordAuthReply, PasswordAuthReq, SOCKS5_AUTH_METHOD_PASSWORD,
        SOCKS5_CMD_TCP_CONNECT, SOCKS5_CMD_UDP_ASSOCIATE, SOCKS5_REPLY_SUCCEEDED, SOCKS5_RESERVE,
        SOCKS5_VERSION,
    },
    socks::UdpSocksWrap,
    utils::socket_opt::{SocketFactory, TcpSocketFactory, UdpSocketFactory},
};
use tokio::{
    io::{AsyncReadExt, copy_bidirectional_with_sizes},
    net::{TcpStream, UdpSocket},
};

use async_trait::async_trait;
use tracing::{Instrument, error, info_span};

use crate::{
    Outbound, ProxyRequest,
    config::SocksClientCfg,
    error::SError,
    msgs::socks5::{AuthReply, AuthReq, CmdReq, SOCKS5_AUTH_METHOD_NONE, VarVec},
    msgs::{SDecode, SEncode},
};

#[derive(Clone)]
pub struct SocksClient {
    pub cfg: SocksClientCfg,
    pub(crate) tcp_socket_factory: Arc<dyn SocketFactory>,
}

impl std::fmt::Debug for SocksClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocksClient")
            .field("cfg", &self.cfg)
            .finish()
    }
}

#[async_trait]
impl Outbound for SocksClient {
    async fn handle(&mut self, req: ProxyRequest) -> Result<(), SError> {
        let span = info_span!("socks", server = self.cfg.addr);
        let client = self.clone();
        let fut = async move {
            match req {
                ProxyRequest::Tcp(tcp_session) => client.handle_tcp(tcp_session).await,
                ProxyRequest::Udp(udp_session) => client.handle_udp(udp_session).await,
            }
        };

        tokio::spawn(
            async {
                fut.await
                    .map_err(|x| error!("error due to handle socks request:{}", x))
            }
            .instrument(span),
        );
        Ok(())
    }
}

impl SocksClient {
    pub fn new(cfg: SocksClientCfg) -> Self {
        let tcp_socket_factory = Arc::new(TcpSocketFactory {
            addr: cfg.addr.clone(),
            interface: cfg.socket_opt.bind_interface.clone(),
            fw_mark: cfg.socket_opt.fw_mark,
            protect_path: None,
        });
        Self {
            cfg,
            tcp_socket_factory,
        }
    }
    async fn authenticate(&self, mut tcp: TcpStream) -> Result<TcpStream, SError> {
        let method = if self.cfg.username.is_some() {
            SOCKS5_AUTH_METHOD_PASSWORD
        } else {
            SOCKS5_AUTH_METHOD_NONE
        };
        let auth = AuthReq {
            version: SOCKS5_VERSION,
            methods: VarVec {
                len: 1,
                contents: vec![method],
            },
        };

        auth.encode(&mut tcp).await?;
        let rep = AuthReply::decode(&mut tcp).await?;
        if rep.version != SOCKS5_VERSION {
            return Err(SError::SocksError("version not supported".into()));
        }
        if rep.method != method {
            return Err(SError::SocksError(
                "authenticate method not supported".into(),
            ));
        }
        if let Some(username) = &self.cfg.username {
            let password = self
                .cfg
                .password
                .as_ref()
                .ok_or(SError::SocksError("password not provided".into()))?;
            let username_len = u8::try_from(username.len())
                .map_err(|_| SError::SocksError("username exceeds 255 bytes".into()))?;
            let password_len = u8::try_from(password.len())
                .map_err(|_| SError::SocksError("password exceeds 255 bytes".into()))?;
            let auth = PasswordAuthReq {
                version: 0x01, // This is password auth version not socks version
                username: VarVec {
                    len: username_len,
                    contents: username.as_bytes().to_vec(),
                },
                password: VarVec {
                    len: password_len,
                    contents: password.as_bytes().to_vec(),
                },
            };
            auth.encode(&mut tcp).await?;
            let rep = PasswordAuthReply::decode(&mut tcp).await?;
            if rep.status != SOCKS5_REPLY_SUCCEEDED {
                return Err(SError::SocksError("authenticate failed".into()));
            }
        }
        Ok(tcp)
    }

    async fn handle_tcp(&self, mut tcp_session: TcpSession) -> Result<(), SError> {
        tracing::info!(server = %self.cfg.addr, "connect to socks server");
        let socket = self.tcp_socket_factory.create_socket().await?;
        let std_stream: std::net::TcpStream = socket.into();
        let tokio_socket = tokio::net::TcpSocket::from_std_stream(std_stream);
        let addr = resolve_address(&self.cfg.addr).await?;
        let tcp = tokio_socket.connect(addr).await?;
        tcp.set_nodelay(true)?;
        let mut tcp = self.authenticate(tcp).await?;
        let socksreq = CmdReq {
            version: SOCKS5_VERSION,
            cmd: SOCKS5_CMD_TCP_CONNECT,
            rsv: SOCKS5_RESERVE,
            dst: tcp_session.dst,
        };
        socksreq.encode(&mut tcp).await?;
        let rep = CmdReply::decode(&mut tcp).await?;
        validate_command_reply(&rep)?;
        tracing::trace!("socks tcp connection established");
        copy_bidirectional_with_sizes(&mut tcp, &mut tcp_session.stream, 16 * 1024, 16 * 1024)
            .await?;
        Ok(())
    }

    async fn handle_udp(&self, mut udp_session: UdpSession) -> Result<(), SError> {
        tracing::info!("connect to socks server: {}", self.cfg.addr);
        let socket = self.tcp_socket_factory.create_socket().await?;
        let std_stream: std::net::TcpStream = socket.into();
        let tokio_socket = tokio::net::TcpSocket::from_std_stream(std_stream);
        let addr = resolve_address(&self.cfg.addr).await?;
        let tcp = tokio_socket.connect(addr).await?;
        tcp.set_nodelay(true)?;

        let mut tcp = self.authenticate(tcp).await?;

        let socksreq = CmdReq {
            version: SOCKS5_VERSION,
            cmd: SOCKS5_CMD_UDP_ASSOCIATE,
            rsv: SOCKS5_RESERVE,
            dst: udp_session.bind_addr.clone(),
        };
        socksreq.encode(&mut tcp).await?;
        let rep = CmdReply::decode(&mut tcp).await?;
        validate_command_reply(&rep)?;
        tracing::trace!("socks udp association established");
        let mut peer_addr = resolve_socks_address(&rep.bind_addr).await?;
        if peer_addr.ip().is_unspecified() {
            peer_addr.set_ip(addr.ip());
        }

        let udp_socket_factory = UdpSocketFactory {
            addr: peer_addr.to_string(),
            interface: self.cfg.socket_opt.bind_interface.clone(),
            fw_mark: self.cfg.socket_opt.fw_mark,
            protect_path: None,
            try_dual_stack: false,
        };
        let socket = udp_socket_factory.create_socket().await?;
        socket.set_nonblocking(true)?;
        let std_socket: std::net::UdpSocket = socket.into();
        let socket = UdpSocket::from_std(std_socket)?;
        socket.connect(peer_addr).await?;
        let mut upstream = UdpSocksWrap::connected(Arc::new(socket), peer_addr);

        let upstream_clone = upstream.clone();
        let fut1 = async move {
            loop {
                let (buf, dst) = upstream.recv_from().await?;

                let _ = udp_session.send.send_to(buf, dst).await?;
            }
            #[allow(unreachable_code)]
            (Ok(()) as Result<(), SError>)
        };
        let fut2 = async move {
            loop {
                let (buf, dst) = udp_session.recv.recv_from().await?;

                let _ = upstream_clone.send_to(buf, dst).await?;
            }
            #[allow(unreachable_code)]
            (Ok(()) as Result<(), SError>)
        };
        // control stream, in socks5 inbound, end of control stream
        // means end of udp association.
        let fut3 = async {
            let Some(mut stream) = udp_session.stream else {
                return Ok(());
            };
            let mut buf = [0u8];
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|x| SError::UDPSessionClosed(x.to_string()))?;
            error!("unexpected data received from socks control stream");
            Err(SError::UDPSessionClosed(
                "unexpected data received from socks control stream".into(),
            )) as Result<(), SError>
        };
        // We can use spawn, but it requires communication to shut down the other
        // Flatten spawn handle using try_join! doesn't work. Don't know why
        tokio::try_join!(fut1, fut2, fut3)?;

        Ok(())
    }
}

async fn resolve_address(address: &str) -> Result<SocketAddr, SError> {
    tokio::net::lookup_host(address)
        .await?
        .next()
        .ok_or_else(|| SError::DomainResolveFailed(address.to_owned()))
}

async fn resolve_socks_address(
    address: &crate::msgs::socks5::SocksAddr,
) -> Result<SocketAddr, SError> {
    match &address.addr {
        AddrOrDomain::V4(ip) => Ok(SocketAddr::from((*ip, address.port))),
        AddrOrDomain::V6(ip) => Ok(SocketAddr::from((*ip, address.port))),
        AddrOrDomain::Domain(domain) => {
            let domain = std::str::from_utf8(&domain.contents)
                .map_err(|error| SError::SocksError(error.to_string()))?;
            resolve_address(&format!("{domain}:{}", address.port)).await
        }
    }
}

fn validate_command_reply(reply: &CmdReply) -> Result<(), SError> {
    if reply.version != SOCKS5_VERSION || reply.rep != SOCKS5_REPLY_SUCCEEDED {
        return Err(SError::SocksError(format!(
            "SOCKS command failed with reply code {}",
            reply.rep
        )));
    }
    Ok(())
}
