use std::{
    env,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};

use arc_swap::ArcSwap;

use crate::Stoppable;

mod rules;
mod watcher;

use rules::Rules;

const FILE_NAME: &str = "source-whitelist.yaml";

static SOURCE_WHITELIST: OnceLock<Arc<SourceWhitelist>> = OnceLock::new();

struct TrackedConnection {
    source: IpAddr,
    connection: Weak<dyn Stoppable>,
}

pub(super) fn authorize(source: IpAddr, connection: Weak<dyn Stoppable>) -> bool {
    let whitelist = SOURCE_WHITELIST.get_or_init(|| {
        let whitelist = Arc::new(SourceWhitelist::new(resolve_path()));
        watcher::spawn(whitelist.clone());
        whitelist
    });

    if whitelist.authorize(source, connection.clone()) {
        return true;
    }

    tracing::trace!(source_ip = %source, "source IP rejected by whitelist");
    if let Some(connection) = connection.upgrade() {
        connection.stop();
    }
    false
}

struct SourceWhitelist {
    path: PathBuf,
    policy: ArcSwap<Policy>,
    connections: Mutex<Vec<TrackedConnection>>,
}

struct Policy {
    enabled: bool,
    rules: Rules,
}

impl Policy {
    fn disabled() -> Self {
        Self {
            enabled: false,
            rules: Rules::default(),
        }
    }

    fn deny_all() -> Self {
        Self {
            enabled: true,
            rules: Rules::default(),
        }
    }

    fn enabled(rules: Rules) -> Self {
        Self {
            enabled: true,
            rules,
        }
    }

    fn allows(&self, source: IpAddr) -> bool {
        !self.enabled || self.rules.allows(source)
    }
}

impl SourceWhitelist {
    fn new(path: PathBuf) -> Self {
        let policy = load_policy(&path);
        log_policy(&path, &policy, "loaded");
        Self {
            path,
            policy: ArcSwap::from_pointee(policy),
            connections: Mutex::new(Vec::new()),
        }
    }

    fn authorize(&self, source: IpAddr, connection: Weak<dyn Stoppable>) -> bool {
        if !self.is_allowed(source) {
            return false;
        }

        let mut connections = self
            .connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        connections.retain(|tracked| tracked.connection.strong_count() > 0);
        connections.push(TrackedConnection { source, connection });
        drop(connections);

        // Recheck after registration so a concurrent reload cannot leave a removed
        // source connected between the first check and insertion.
        self.is_allowed(source)
    }

    fn is_allowed(&self, source: IpAddr) -> bool {
        self.policy.load().allows(source)
    }

    fn reload(&self) {
        let policy = load_policy(&self.path);
        self.policy.store(Arc::new(policy));

        let current_policy = self.policy.load();
        let mut connections = self
            .connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        connections.retain(|tracked| {
            let Some(connection) = tracked.connection.upgrade() else {
                return false;
            };
            if current_policy.allows(tracked.source) {
                true
            } else {
                tracing::trace!(
                    source_ip = %tracked.source,
                    "closing connection removed from source whitelist"
                );
                connection.stop();
                false
            }
        });

        log_policy(&self.path, &current_policy, "reloaded");
    }
}

fn load_policy(path: &Path) -> Policy {
    match std::fs::read_to_string(path) {
        Ok(content) => match Rules::parse(&content) {
            Ok(rules) => Policy::enabled(rules),
            Err(error) => {
                tracing::error!(
                    path = %path.display(),
                    %error,
                    "invalid source whitelist; denying all sources"
                );
                Policy::deny_all()
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Policy::disabled(),
        Err(error) => {
            tracing::error!(
                path = %path.display(),
                %error,
                "cannot read source whitelist; denying all sources"
            );
            Policy::deny_all()
        }
    }
}

fn log_policy(path: &Path, policy: &Policy, action: &str) {
    if policy.enabled {
        tracing::info!(
            path = %path.display(),
            entries = policy.rules.len(),
            action,
            "source whitelist active"
        );
    } else {
        tracing::info!(
            path = %path.display(),
            "source whitelist file not found; filtering disabled"
        );
    }
}

fn resolve_path() -> PathBuf {
    if let Some(path) = env::var_os("SHADOWQUIC_SOURCE_WHITELIST").filter(|path| !path.is_empty()) {
        return absolute_path(PathBuf::from(path));
    }

    absolute_path(PathBuf::from(FILE_NAME))
}

fn absolute_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use super::*;

    struct TestConnection(AtomicBool);

    impl Stoppable for TestConnection {
        fn stop(&self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn missing_file_disables_filtering() {
        let path = temporary_path();
        let whitelist = SourceWhitelist::new(path);

        assert!(whitelist.is_allowed("192.0.2.10".parse().unwrap()));
        assert!(whitelist.is_allowed("2001:db8::10".parse().unwrap()));
    }

    #[test]
    fn existing_empty_file_denies_every_source() {
        let path = temporary_path();
        std::fs::write(&path, "payload:\n").unwrap();
        let whitelist = SourceWhitelist::new(path.clone());

        assert!(!whitelist.is_allowed("192.0.2.10".parse().unwrap()));
        assert!(!whitelist.is_allowed("2001:db8::10".parse().unwrap()));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn deleting_file_disables_filtering() {
        let path = temporary_path();
        std::fs::write(&path, "payload:\n  - SRC-IP-CIDR,192.0.2.10/32\n").unwrap();
        let whitelist = SourceWhitelist::new(path.clone());
        let other_source = "198.51.100.10".parse().unwrap();
        assert!(!whitelist.is_allowed(other_source));

        std::fs::remove_file(&path).unwrap();
        whitelist.reload();

        assert!(whitelist.is_allowed(other_source));
    }

    #[test]
    fn removing_source_closes_existing_connection() {
        let path = temporary_path();
        std::fs::write(&path, "payload:\n  - SRC-IP-CIDR,192.0.2.10/32\n").unwrap();
        let whitelist = SourceWhitelist::new(path.clone());
        let connection = Arc::new(TestConnection(AtomicBool::new(false)));
        let stoppable: Arc<dyn Stoppable> = connection.clone();

        assert!(whitelist.authorize("192.0.2.10".parse().unwrap(), Arc::downgrade(&stoppable),));
        std::fs::write(&path, "payload:\n").unwrap();
        whitelist.reload();

        assert!(connection.0.load(Ordering::SeqCst));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn watcher_reloads_changes_without_restart() {
        let path = temporary_path();
        std::fs::write(&path, "payload:\n  - SRC-IP-CIDR,198.51.100.7/32\n").unwrap();
        let whitelist = Arc::new(SourceWhitelist::new(path.clone()));
        watcher::spawn(whitelist.clone());

        tokio::time::sleep(Duration::from_millis(50)).await;
        std::fs::write(&path, "payload:\n").unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            while whitelist.is_allowed("198.51.100.7".parse().unwrap()) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("source whitelist was not reloaded");

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn watcher_tracks_file_creation_and_deletion() {
        let path = temporary_path();
        let whitelist = Arc::new(SourceWhitelist::new(path.clone()));
        let source = "198.51.100.7".parse().unwrap();
        watcher::spawn(whitelist.clone());
        assert!(whitelist.is_allowed(source));

        tokio::time::sleep(Duration::from_millis(50)).await;
        std::fs::write(&path, "payload:\n  - SRC-IP-CIDR,192.0.2.1/32\n").unwrap();
        wait_until(|| !whitelist.is_allowed(source)).await;

        std::fs::remove_file(&path).unwrap();
        wait_until(|| whitelist.is_allowed(source)).await;
    }

    async fn wait_until(mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("source whitelist state was not reloaded");
    }

    fn temporary_path() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!(
            "shadowquic-whitelist-{}-{unique}.yaml",
            std::process::id()
        ))
    }
}
