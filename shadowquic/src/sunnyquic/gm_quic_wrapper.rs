#![allow(deprecated)]

use std::future::poll_fn;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use gm_quic::prelude::handy::{ToCertificate, client_parameters, server_parameters};

use gm_quic::prelude::StreamReader;
use gm_quic::prelude::StreamWriter;
use rustls::RootCertStore;

use crate::config::{SunnyQuicClientCfg, SunnyQuicServerCfg};
use crate::error::SError;
use crate::quic::{QuicClient, QuicServer};
use crate::quic::{QuicConnection, QuicErrorRepr};

pub use gm_quic::prelude::QuicClient as EndClient;
pub type EndServer = Arc<gm_quic::prelude::QuicListeners>;
/// 202601, gm-quic unreliable datagram is broken
/// BBR is still not supported

/// Right now(202506), gm-quic doesn't provide BBR support.
/// So we stopped here.
#[deprecated(note = "Use quinn instead")]
#[derive(Clone)]
pub struct Connection {
    inner: Arc<gm_quic::prelude::Connection>,
    datagram_reader: gm_quic::prelude::DatagramReader,
    datagram_writer: gm_quic::prelude::DatagramWriter,
    remote_address: SocketAddr,
    peer_id: u64,
}

#[async_trait]
impl QuicClient for gm_quic::prelude::QuicClient {
    type C = Connection;
    type SC = SunnyQuicClientCfg;

    async fn new(cfg: &SunnyQuicClientCfg) -> crate::error::SResult<Self> {
        let mut roots = RootCertStore::empty();
        //roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        if let Some(path) = &cfg.cert_path {
            roots.add_parsable_certificates(path.to_certificate());
        }

        let mut cli_para = client_parameters();
        cli_para
            .set(
                gm_quic::qbase::param::ParameterId::InitialMaxData,
                32 * 1024 * 1024,
            )
            .map_err(parameter_error)?;
        cli_para
            .set(
                gm_quic::qbase::param::ParameterId::InitialMaxStreamDataBidiLocal,
                16 * 1024 * 1024,
            )
            .map_err(parameter_error)?;
        cli_para
            .set(
                gm_quic::qbase::param::ParameterId::InitialMaxStreamDataBidiRemote,
                16 * 1024 * 1024,
            )
            .map_err(parameter_error)?;

        cli_para
            .set(gm_quic::prelude::ParameterId::MaxDatagramFrameSize, 2000)
            .map_err(parameter_error)?;

        let mut client = gm_quic::prelude::QuicClient::builder()
            .with_root_certificates(roots)
            //.without_verifier()
            .without_cert()
            .with_parameters(cli_para)
            .with_alpns(cfg.alpn.iter().map(|alpn| alpn.clone().into_bytes()));

        if cfg.zero_rtt {
            client = client.enable_0rtt();
        }
        Ok(client.build())
    }

    async fn new_with_socket_factory(
        cfg: &Self::SC,
        _socket_factory: Arc<dyn crate::utils::socket_opt::SocketFactory>,
    ) -> crate::error::SResult<Self> {
        Self::new(cfg).await
    }

    async fn connect(
        &self,
        addr: std::net::SocketAddr,
        server_name: &str,
    ) -> Result<Self::C, QuicErrorRepr> {
        let conn = self
            .connected_to(server_name, [addr])
            .map_err(|error| QuicErrorRepr::QuicConnect(error.to_string()))?;
        let peer_id = connection_id(&conn);
        Ok(Connection {
            datagram_reader: conn.unreliable_reader()??,
            datagram_writer: conn.unreliable_writer().await??,
            inner: conn.into(),
            remote_address: addr,
            peer_id,
        })
    }
}

#[async_trait]
impl QuicConnection for Connection {
    type SendStream = StreamWriter;
    type RecvStream = StreamReader;
    async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr> {
        let (id, (r, w)) = self
            .inner
            .open_bi_stream()
            .await?
            .ok_or(QuicErrorRepr::EndpointClosed)?;
        Ok((w, r, id.id()))
    }
    async fn accept_bi(&self) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr> {
        let (id, (r, w)) = self.inner.accept_bi_stream().await?;
        Ok((w, r, id.id()))
    }
    async fn open_uni(&self) -> Result<(Self::SendStream, u64), QuicErrorRepr> {
        let (id, w) = self
            .inner
            .open_uni_stream()
            .await?
            .ok_or(QuicErrorRepr::EndpointClosed)?;
        Ok((w, id.id()))
    }
    async fn accept_uni(&self) -> Result<(Self::RecvStream, u64), QuicErrorRepr> {
        let (id, r) = self.inner.accept_uni_stream().await?;
        Ok((r, id.id()))
    }
    async fn read_datagram(&self) -> Result<Bytes, QuicErrorRepr> {
        let bytes = poll_fn(|cx| self.datagram_reader.poll_recv(cx)).await?;
        tracing::info!("Received datagram");
        Ok(bytes)
    }
    async fn send_datagram(&self, bytes: Bytes) -> Result<(), QuicErrorRepr> {
        self.datagram_writer.send_bytes(bytes)?;
        Ok(())
    }
    fn close_reason(&self) -> Option<QuicErrorRepr> {
        None
    }
    fn remote_address(&self) -> SocketAddr {
        self.remote_address
    }
    fn peer_id(&self) -> u64 {
        self.peer_id
    }
    fn close(&self, error_code: u64, reason: &[u8]) {
        let reason = String::from_utf8_lossy(reason).into_owned();
        let _ = self.inner.close(reason, error_code);
    }
}

#[async_trait]
impl QuicServer for EndServer {
    type C = Connection;
    type SC = SunnyQuicServerCfg;

    async fn new(cfg: &SunnyQuicServerCfg) -> crate::error::SResult<Self> {
        let mut server_para = server_parameters();
        server_para
            .set(
                gm_quic::qbase::param::ParameterId::InitialMaxData,
                16 * 1024 * 1024,
            )
            .map_err(parameter_error)?;
        server_para
            .set(
                gm_quic::qbase::param::ParameterId::InitialMaxStreamDataBidiLocal,
                8 * 1024 * 1024,
            )
            .map_err(parameter_error)?;
        server_para
            .set(
                gm_quic::qbase::param::ParameterId::InitialMaxStreamDataBidiRemote,
                8 * 1024 * 1024,
            )
            .map_err(parameter_error)?;

        server_para
            .set(gm_quic::prelude::ParameterId::MaxDatagramFrameSize, 2000)
            .map_err(parameter_error)?;

        let builder = gm_quic::prelude::QuicListeners::builder()
            .map_err(|x| SError::QuicError(x.into()))?
            .with_parameters(server_para)
            .without_client_cert_verifier();
        let builder = if cfg.zero_rtt {
            builder.enable_0rtt()
        } else {
            builder
        };
        let listeners = builder
            .with_alpns(cfg.alpn.iter().map(|alpn| alpn.clone().into_bytes()))
            .listen(128);
        listeners
            .add_server(
                cfg.server_name.as_str(),
                cfg.cert_path.as_path(),
                cfg.key_path.as_path(),
                [cfg.bind_addr],
                None,
            )
            .map_err(|error| {
                SError::QuicError(QuicErrorRepr::QuicListenerBuilderError(error.to_string()))
            })?;
        Ok(listeners)
    }

    async fn accept(&self) -> Result<Self::C, QuicErrorRepr> {
        let (conn, sni, _path, link) = self
            .deref()
            .accept()
            .await
            .map_err(|_| QuicErrorRepr::EndpointClosed)?;
        let remote_address = match link.src() {
            gm_quic::qbase::net::addr::RealAddr::Internet(address) => address,
            _ => return Err(QuicErrorRepr::ProtocolUnsupportedAddress),
        };
        let peer_id = connection_id(&conn);
        tracing::info!(
            "Accepted new connection from {}, sni: {:?}",
            link.src(),
            sni
        );
        Ok(Connection {
            datagram_reader: conn.unreliable_reader()??,
            datagram_writer: conn.unreliable_writer().await??,
            inner: conn.into(),
            remote_address,
            peer_id,
        })
    }

    async fn update_config(&self, _cfg: &Self::SC) -> crate::error::SResult<()> {
        Err(SError::ProtocolUnimpl)
    }
}

fn connection_id(connection: &gm_quic::prelude::Connection) -> u64 {
    let mut hasher = DefaultHasher::new();
    if let Ok(connection_id) = connection.origin_dcid() {
        connection_id.as_ref().hash(&mut hasher);
    }
    hasher.finish()
}

impl From<std::io::Error> for QuicErrorRepr {
    fn from(err: std::io::Error) -> Self {
        QuicErrorRepr::QuicIoError(err.to_string())
    }
}
impl From<gm_quic::qbase::error::Error> for QuicErrorRepr {
    fn from(err: gm_quic::qbase::error::Error) -> Self {
        QuicErrorRepr::QuicBaseError(err.to_string())
    }
}

fn parameter_error(error: gm_quic::qbase::param::error::Error) -> SError {
    SError::QuicError(QuicErrorRepr::QuicBaseError(error.to_string()))
}
impl From<gm_quic::prelude::BuildListenersError> for QuicErrorRepr {
    fn from(err: gm_quic::prelude::BuildListenersError) -> Self {
        QuicErrorRepr::QuicListenerBuilderError(err.to_string())
    }
}

impl From<rustls::Error> for SError {
    fn from(err: rustls::Error) -> Self {
        SError::RustlsError(err.to_string())
    }
}
