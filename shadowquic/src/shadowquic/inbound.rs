use async_trait::async_trait;
use std::sync::Arc;

use tokio::sync::{
    RwLock, SetOnce,
    mpsc::{Receiver, Sender, channel},
};
use tracing::{Instrument, error, info_span};

use crate::{
    Inbound, ProxyRequest, Stoppable, UserContext,
    config::{AuthUser, ShadowQuicServerCfg},
    error::SError,
    msgs::squic::{SQExtError, UserStats},
    observe::Observer,
    quic::{AuthedConn, QuicConnection, QuicErrorRepr},
    squic::inbound::{ConnectionRegistry, SQServerConn, UserManager},
};

use crate::squic::{IDStore, SQConn};

use super::quinn_wrapper::EndServer;
use crate::quic::QuicServer;
pub struct ShadowQuicServer {
    pub endpoint: EndServer,
    user_manager: Arc<ShadowQuicUserManager>,
    request_sender: Sender<ProxyRequest>,
    request: Receiver<ProxyRequest>,
    observer: Arc<Observer>,
    connections: Arc<ConnectionRegistry>,
}

struct ShadowQuicUserManager {
    endpoint: EndServer,
    config: RwLock<ShadowQuicServerCfg>,
    observer: Arc<Observer>,
    connections: Arc<ConnectionRegistry>,
}

#[async_trait]
impl UserManager for ShadowQuicUserManager {
    async fn add_user(&self, user: AuthUser) -> Result<(), SQExtError> {
        let username = user.username.clone();
        let mut config = self.config.write().await;
        let old_config = config.clone();
        let mut password_changed = false;
        if let Some(existing_user) = config
            .users
            .iter_mut()
            .find(|existing_user| existing_user.username == user.username)
        {
            password_changed = existing_user.password != user.password;
            existing_user.password = user.password;
        } else {
            config.users.push(user);
        }

        if let Err(error) = QuicServer::update_config(&self.endpoint, &config).await {
            *config = old_config;
            tracing::error!("failed to add user: {}", error);
            return Err(SQExtError::Other(error.to_string()));
        }
        drop(config);
        if password_changed {
            self.connections.close_user(&username).await;
            self.observer.close_conn(&username).await;
        }
        Ok(())
    }

    async fn remove_user(&self, username: &str) -> Result<(), SQExtError> {
        let mut config = self.config.write().await;
        let old_config = config.clone();
        let old_len = config.users.len();
        config.users.retain(|user| user.username != username);
        if config.users.len() == old_len {
            return Err(SQExtError::NotFound);
        }

        if let Err(error) = QuicServer::update_config(&self.endpoint, &config).await {
            *config = old_config;
            tracing::error!("failed to remove user: {}", error);
            return Err(SQExtError::Other(error.to_string()));
        }
        drop(config);
        self.connections.close_user(username).await;
        self.observer.remove_user(username).await;
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<String>, SQExtError> {
        let config = self.config.read().await;
        Ok(config
            .users
            .iter()
            .map(|user| user.username.clone())
            .collect())
    }

    async fn get_user_stats(&self, username: &str) -> Result<UserStats, SQExtError> {
        let config = self.config.read().await;
        if !config.users.iter().any(|user| user.username == username) {
            return Err(SQExtError::NotFound);
        }
        drop(config);
        Ok(self.observer.get_user_stats(username).await)
    }

    async fn get_all_stats(&self) -> Result<Vec<UserStats>, SQExtError> {
        let config = self.config.read().await;
        let usernames = config
            .users
            .iter()
            .map(|user| user.username.clone())
            .collect::<Vec<_>>();
        drop(config);
        Ok(self.observer.get_all_stats(&usernames).await)
    }

    async fn kill_user_conns(&self, username: &str) -> Result<(), SQExtError> {
        let config = self.config.read().await;
        if !config.users.iter().any(|user| user.username == username) {
            return Err(SQExtError::NotFound);
        }
        drop(config);
        self.connections.close_user(username).await;
        self.observer.close_conn(username).await;
        Ok(())
    }
}

impl ShadowQuicServer {
    pub async fn new(cfg: ShadowQuicServerCfg) -> Result<Self, SError> {
        let (send, recv) = channel::<ProxyRequest>(10);

        let endpoint: EndServer = QuicServer::new(&cfg).await?;
        let observer = Arc::new(Observer::new());
        let connections = Arc::new(ConnectionRegistry::default());
        let user_manager = Arc::new(ShadowQuicUserManager {
            endpoint: endpoint.clone(),
            config: RwLock::new(cfg),
            observer: observer.clone(),
            connections: connections.clone(),
        });

        Ok(Self {
            endpoint,
            user_manager,
            request_sender: send,
            request: recv,
            observer,
            connections,
        })
    }

    async fn handle_incoming<C: QuicConnection + AuthedConn>(
        incom: C,
        req_sender: Sender<ProxyRequest>,
        user_manager: Arc<dyn UserManager>,
        connections: Arc<ConnectionRegistry>,
    ) -> Result<(), SError> {
        let user = incom
            .authed_user()
            .ok_or(SError::SunnyAuthError("User not authenticated".into()))?;
        let sq_conn = SQServerConn {
            inner: SQConn {
                conn: incom,
                authed: Arc::new(SetOnce::new_with(Some(Ok(user.clone())))),
                send_id_store: Default::default(),
                recv_id_store: IDStore {
                    id_counter: Default::default(),
                    inner: Default::default(),
                },
            },
            users: None,
            sunny_credential: None,
            user_manager: Some(user_manager),
            connections: connections.clone(),
        };
        let span = info_span!("quic", id = sq_conn.inner.peer_id(), user = %user);
        let sq_conn = Arc::new(sq_conn);
        connections
            .register(UserContext {
                username: user,
                conn_handle: Arc::downgrade(&(sq_conn.clone() as Arc<dyn Stoppable>)),
                conn_id: sq_conn.inner.peer_id(),
            })
            .await;
        sq_conn
            .handle_connection(req_sender)
            .instrument(span)
            .await?;

        Ok(())
    }
}

#[async_trait]
impl Inbound for ShadowQuicServer {
    async fn accept(&mut self) -> Result<crate::ProxyRequest, SError> {
        let req = self
            .request
            .recv()
            .await
            .ok_or(SError::InboundUnavailable)?;
        Ok(self.observer.wrap_request(req).await)
    }
    /// Init background job for accepting connection
    async fn init(&self) -> Result<(), SError> {
        let request_sender = self.request_sender.clone();
        let endpoint = self.endpoint.clone();
        let user_manager = self.user_manager.clone();
        let connections = self.connections.clone();
        let fut = async move {
            let mut error_backoff = std::time::Duration::from_millis(10);
            loop {
                match QuicServer::accept(&endpoint).await {
                    Ok(conn) => {
                        error_backoff = std::time::Duration::from_millis(10);
                        let request_sender = request_sender.clone();
                        let user_manager = user_manager.clone();
                        let connections = connections.clone();
                        tokio::spawn(async move {
                            Self::handle_incoming(conn, request_sender, user_manager, connections)
                                .await
                                .map_err(|x| error!("{}", x))
                        });
                    }
                    Err(QuicErrorRepr::EndpointClosed) => {
                        tracing::info!("ShadowQUIC endpoint closed");
                        break;
                    }
                    Err(e) => {
                        error!("Error accepting quic connection: {}", e);
                        tokio::time::sleep(error_backoff).await;
                        error_backoff = (error_backoff * 2).min(std::time::Duration::from_secs(1));
                    }
                }
            }
        };
        tokio::spawn(fut);
        Ok(())
    }
}
