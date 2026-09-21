use std::{path::{Path, PathBuf}, sync::Arc};

use anyhow::{Context, Result};
use rvpn_config::ClientConfig;
use rvpn_ipc::{ControlRequest, ControlResponse, StatusSnapshot};
use tokio::{
    sync::{Mutex, watch},
    task::JoinHandle,
};

use crate::run_client;
use rvpn_core::{GuiState, GuiStateHandle};

struct Session {
    shutdown_tx: watch::Sender<bool>,
    handle: JoinHandle<Result<()>>,
    gui_state: GuiStateHandle,
}

/// Holds at most one active client session and answers control requests
/// against it. Shared across every accepted control connection.
pub struct Daemon {
    session: Mutex<Option<Session>>,
}

impl Daemon {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            session: Mutex::new(None),
        })
    }

    async fn connect(&self, config_path: String) -> Result<()> {
        let mut guard = self.session.lock().await;
        if guard.is_some() {
            anyhow::bail!("already connected; disconnect first");
        }
        let config_path = allowed_config_path(&config_path)?;
        let config = ClientConfig::from_toml(
            &rvpn_config::read_config_file(&config_path)
                .with_context(|| format!("reading {}", config_path.display()))?,
        )?;
        let gui_state = GuiState::handle();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let shutdown_fut: std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> =
            Box::pin(wait_for_shutdown(shutdown_rx));
        let handle = tokio::spawn(run_client(
            config,
            Some(Arc::clone(&gui_state)),
            Some(shutdown_fut),
        ));
        *guard = Some(Session {
            shutdown_tx,
            handle,
            gui_state,
        });
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        let session = self.session.lock().await.take();
        let Some(session) = session else {
            anyhow::bail!("not connected");
        };
        let _ = session.shutdown_tx.send(true);
        let _ = session.handle.await;
        Ok(())
    }

    async fn status(&self) -> StatusSnapshot {
        let guard = self.session.lock().await;
        let Some(session) = guard.as_ref() else {
            return StatusSnapshot::disconnected();
        };
        let snap = session
            .gui_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot();
        StatusSnapshot {
            connected: snap.connected,
            server: snap.server,
            session_id: snap.session_id,
            uptime_secs: snap.uptime.as_secs(),
            key_phase: snap.key_phase,
            bytes_tx: snap.bytes_tx,
            bytes_rx: snap.bytes_rx,
            packets_tx: snap.packets_tx,
            packets_rx: snap.packets_rx,
            effective_mtu: snap.effective_mtu as u64,
            mtu_state: snap.mtu_state,
            mtu_changes: snap.mtu_changes,
            send_errors: snap.send_errors,
            dropped_oversized: snap.dropped_oversized,
            dropped_backpressure: snap.dropped_backpressure,
            keepalives_sent: snap.keepalives_sent,
        }
    }
}

fn allowed_config_path(raw: &str) -> Result<PathBuf> {
    let config_dir = rvpn_config::default_config_dir();
    let config_dir = std::fs::canonicalize(&config_dir)
        .with_context(|| format!("resolving config directory {}", config_dir.display()))?;
    let path = Path::new(raw);
    let path = std::fs::canonicalize(path)
        .with_context(|| format!("resolving config path {raw}"))?;
    if !path.starts_with(&config_dir) {
        anyhow::bail!(
            "IPC config path {} is outside the RVPN config directory {}",
            path.display(),
            config_dir.display()
        );
    }
    Ok(path)
}

async fn wait_for_shutdown(mut rx: watch::Receiver<bool>) -> Result<()> {
    loop {
        if *rx.borrow() {
            return Ok(());
        }
        if rx.changed().await.is_err() {
            return Ok(());
        }
    }
}

/// Runs the control socket forever, dispatching each connection's
/// requests against `daemon`.
pub async fn run_ipc_server(daemon: Arc<Daemon>) -> Result<()> {
    tracing::info!(socket = %rvpn_ipc::socket_path().display(), "RVPN control socket starting");
    rvpn_ipc::serve(move |conn| {
        let daemon = Arc::clone(&daemon);
        async move {
            if let Err(error) = handle_connection(daemon, conn).await {
                tracing::debug!(%error, "control connection ended");
            }
        }
    })
    .await?;
    Ok(())
}

async fn handle_connection(daemon: Arc<Daemon>, mut conn: rvpn_ipc::Connection) -> Result<()> {
    loop {
        let Some(request) = conn.read_request().await? else {
            return Ok(());
        };
        let response = match request {
            ControlRequest::Connect { config_path } => match daemon.connect(config_path).await {
                Ok(()) => ControlResponse::Ok,
                Err(error) => ControlResponse::Err(error.to_string()),
            },
            ControlRequest::Disconnect => match daemon.disconnect().await {
                Ok(()) => ControlResponse::Ok,
                Err(error) => ControlResponse::Err(error.to_string()),
            },
            ControlRequest::Status => ControlResponse::Status(daemon.status().await),
            ControlRequest::Ping => ControlResponse::Pong,
        };
        conn.write_response(&response).await?;
    }
}
