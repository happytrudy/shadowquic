use std::{net::SocketAddr, time::Duration};

use fast_socks5::client::{Config, Socks5Stream};
use shadowquic::{
    Inbound, Manager,
    config::{
        AuthUser, CongestionControl, JlsUpstream, ShadowQuicClientCfg, ShadowQuicServerCfg,
        SunnyQuicClientCfg, SunnyQuicServerCfg, default_initial_mtu,
    },
    shadowquic::{inbound::ShadowQuicServer, outbound::ShadowQuicClient},
    socks::inbound::SocksServer,
    squic::outbound::get_peer_conn_stats,
    sunnyquic::{inbound::SunnyQuicServer, outbound::SunnyQuicClient},
};
use tokio::net::{TcpListener, UdpSocket};

#[tokio::test]
async fn shadowquic_client_sqconn_records_authenticated_username() {
    let username = "authed-shadowquic-user";
    let password = "authed-shadowquic-password";
    let bind_addr = "127.0.0.1:4491".parse().unwrap();

    let server = ShadowQuicServer::new(ShadowQuicServerCfg {
        bind_addr,
        users: vec![AuthUser {
            username: username.into(),
            password: password.into(),
        }],
        jls_upstream: JlsUpstream {
            addr: "localhost:443".into(),
            ..Default::default()
        },
        alpn: vec!["h3".into()],
        zero_rtt: true,
        initial_mtu: default_initial_mtu(),
        congestion_control: CongestionControl::Bbr,
        ..Default::default()
    })
    .await
    .unwrap();
    server.init().await.unwrap();

    let client = ShadowQuicClient::new(ShadowQuicClientCfg {
        addr: bind_addr.to_string(),
        username: username.into(),
        password: password.into(),
        server_name: "localhost".into(),
        alpn: vec!["h3".into()],
        zero_rtt: true,
        initial_mtu: 1200,
        congestion_control: CongestionControl::Bbr,
        ..Default::default()
    });

    let conn = client.get_conn().await.unwrap();

    assert_eq!(conn.authed.wait().await.as_ref().unwrap(), username);
}

#[tokio::test]
async fn sunnyquic_client_sqconn_records_authenticated_username() {
    let username = "authed-sunnyquic-user";
    let password = "authed-sunnyquic-password";
    let bind_addr = "127.0.0.1:4492".parse().unwrap();

    let server = SunnyQuicServer::new(SunnyQuicServerCfg {
        bind_addr,
        users: vec![AuthUser {
            username: username.into(),
            password: password.into(),
        }],
        alpn: vec!["h3".into()],
        zero_rtt: true,
        initial_mtu: default_initial_mtu(),
        congestion_control: CongestionControl::Bbr3,
        server_name: "localhost".into(),
        cert_path: "../assets/certs/localhost.crt".into(),
        key_path: "../assets/certs/localhost.key".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    server.init().await.unwrap();

    let client = SunnyQuicClient::new(SunnyQuicClientCfg {
        addr: bind_addr.to_string(),
        username: username.into(),
        password: password.into(),
        server_name: "localhost".into(),
        alpn: vec!["h3".into()],
        zero_rtt: true,
        initial_mtu: 1200,
        congestion_control: CongestionControl::Bbr3,
        cert_path: Some("../assets/certs/MyCA.pem".into()),
        ..Default::default()
    });

    let conn = client.get_conn().await.unwrap();
    let authed = tokio::time::timeout(Duration::from_secs(3), conn.authed.wait())
        .await
        .unwrap();

    assert_eq!(authed.as_ref().unwrap(), username);
}

#[tokio::test]
async fn sunnyquic_request_exposes_remote_address() {
    let username = "remote-address-user";
    let password = "remote-address-password";
    let server_addr = available_udp_addr().await;
    let socks_addr = available_tcp_addr().await;

    let mut server = SunnyQuicServer::new(SunnyQuicServerCfg {
        bind_addr: server_addr,
        users: vec![AuthUser {
            username: username.into(),
            password: password.into(),
        }],
        alpn: vec!["h3".into()],
        zero_rtt: true,
        initial_mtu: default_initial_mtu(),
        congestion_control: CongestionControl::Bbr,
        server_name: "localhost".into(),
        cert_path: "../assets/certs/localhost.crt".into(),
        key_path: "../assets/certs/localhost.key".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    server.init().await.unwrap();

    let socks_server = SocksServer::new(shadowquic::config::SocksServerCfg {
        bind_addr: socks_addr,
        users: vec![],
    })
    .await
    .unwrap();
    let sunnyquic_client = SunnyQuicClient::new(SunnyQuicClientCfg {
        addr: server_addr.to_string(),
        username: username.into(),
        password: password.into(),
        server_name: "localhost".into(),
        alpn: vec!["h3".into()],
        zero_rtt: true,
        initial_mtu: 1200,
        congestion_control: CongestionControl::Bbr,
        cert_path: Some("../assets/certs/MyCA.pem".into()),
        ..Default::default()
    });
    tokio::spawn(
        Manager {
            inbound: Box::new(socks_server),
            outbound: Box::new(sunnyquic_client),
        }
        .run(),
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut config = Config::default();
    config.set_skip_auth(false);
    let socks_addr = socks_addr.to_string();
    let _stream = Socks5Stream::connect(socks_addr.as_str(), "example.com".into(), 443, config)
        .await
        .unwrap();

    let request = tokio::time::timeout(Duration::from_secs(3), server.accept())
        .await
        .unwrap()
        .unwrap();
    let remote = request.remote_address().unwrap();
    assert!(remote.ip().is_loopback());
    assert_ne!(remote.port(), 0);
    assert_eq!(request.username(), Some(username));
}

#[tokio::test]
async fn sunnyquic_bind_failure_is_returned() {
    let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bind_addr = occupied.local_addr().unwrap();
    let result = SunnyQuicServer::new(SunnyQuicServerCfg {
        bind_addr,
        users: vec![AuthUser {
            username: "test".into(),
            password: "test-password".into(),
        }],
        alpn: vec!["h3".into()],
        server_name: "localhost".into(),
        cert_path: "../assets/certs/localhost.crt".into(),
        key_path: "../assets/certs/localhost.key".into(),
        ..Default::default()
    })
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn sunnyquic_config_update_revokes_changed_password_connections() {
    let bind_addr = available_udp_addr().await;
    let mut server_config = SunnyQuicServerCfg {
        bind_addr,
        users: vec![AuthUser {
            username: "alice".into(),
            password: "old-password".into(),
        }],
        alpn: vec!["h3".into()],
        zero_rtt: false,
        gso: false,
        server_name: "localhost".into(),
        cert_path: "../assets/certs/localhost.crt".into(),
        key_path: "../assets/certs/localhost.key".into(),
        ..Default::default()
    };
    let server = SunnyQuicServer::new(server_config.clone()).await.unwrap();
    server.init().await.unwrap();

    let client = SunnyQuicClient::new(SunnyQuicClientCfg {
        addr: bind_addr.to_string(),
        username: "alice".into(),
        password: "old-password".into(),
        server_name: "localhost".into(),
        alpn: vec!["h3".into()],
        cert_path: Some("../assets/certs/MyCA.pem".into()),
        zero_rtt: false,
        gso: false,
        ..Default::default()
    });
    let connection = client.get_conn().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), get_peer_conn_stats(&connection))
        .await
        .expect("authentication should complete")
        .expect("stats request should complete");

    server_config.users[0].password = "new-password".into();
    server.update_config(&server_config).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while connection.close_reason().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("password change should close the old connection");
}

async fn available_tcp_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn available_udp_addr() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}
