use std::{sync::Arc, time::Duration};

#[cfg(any(feature = "sunnyquic-gm-quic", feature = "sunnyquic-noq"))]
use std::path::Path;

use super::SourceWhitelist;

const POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) fn spawn(whitelist: Arc<SourceWhitelist>) {
    tokio::spawn(async move {
        #[cfg(any(feature = "sunnyquic-gm-quic", feature = "sunnyquic-noq"))]
        {
            if let Err(error) = watch_events(whitelist.clone()).await {
                tracing::error!(%error, "source whitelist watcher failed; using 10ms polling");
            } else {
                return;
            }
        }

        poll(whitelist).await;
    });
}

#[cfg(any(feature = "sunnyquic-gm-quic", feature = "sunnyquic-noq"))]
async fn watch_events(whitelist: Arc<SourceWhitelist>) -> Result<(), notify::Error> {
    use notify::{Event, RecursiveMode, Watcher};

    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let mut watcher = notify::recommended_watcher(move |event: Result<Event, notify::Error>| {
        let _ = send.send(event);
    })?;
    let parent = whitelist.path.parent().unwrap_or_else(|| Path::new("."));
    watcher.watch(parent, RecursiveMode::NonRecursive)?;

    // Reload after the watcher is active to close the initialization race window.
    whitelist.reload();
    while let Some(event) = receive.recv().await {
        match event {
            Ok(event) if affects_file(&event, &whitelist.path) => whitelist.reload(),
            Ok(_) => {}
            Err(error) => tracing::error!(%error, "source whitelist watch event failed"),
        }
    }
    Ok(())
}

#[cfg(any(feature = "sunnyquic-gm-quic", feature = "sunnyquic-noq"))]
fn affects_file(event: &notify::Event, target: &Path) -> bool {
    use notify::EventKind;

    matches!(
        event.kind,
        EventKind::Any
            | EventKind::Create(_)
            | EventKind::Modify(_)
            | EventKind::Remove(_)
            | EventKind::Other
    ) && (event.paths.is_empty()
        || event
            .paths
            .iter()
            .any(|path| path.file_name() == target.file_name()))
}

async fn poll(whitelist: Arc<SourceWhitelist>) {
    let mut previous = std::fs::read(&whitelist.path).ok();
    whitelist.reload();

    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        let current = std::fs::read(&whitelist.path).ok();
        if current != previous {
            previous = current;
            whitelist.reload();
        }
    }
}

#[cfg(all(test, any(feature = "sunnyquic-gm-quic", feature = "sunnyquic-noq")))]
mod tests {
    use notify::{Event, EventKind, event::AccessKind};

    use super::*;

    #[test]
    fn file_access_events_do_not_trigger_reload() {
        let target = Path::new("/tmp/source-whitelist.yaml");
        let event = Event::new(EventKind::Access(AccessKind::Read)).add_path(target.into());

        assert!(!affects_file(&event, target));
    }
}
