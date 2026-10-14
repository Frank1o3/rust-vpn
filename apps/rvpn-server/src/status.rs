//! Local, read-only server peer status socket.
//!
//! The Unix socket is protected by owner-only filesystem permissions. Its
//! response contains operational counters only; key material is never exposed.

use anyhow::{Context, Result};
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::path::PathBuf;
use tokio::sync::watch;
#[cfg(unix)]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

#[cfg(unix)]
pub fn socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("RVPN_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("server-status.sock")
    } else if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir)
            .join("rvpn")
            .join("server-status.sock")
    } else {
        let uid = unsafe { libc::getuid() };
        PathBuf::from(format!("/tmp/rvpn-{uid}")).join("server-status.sock")
    }
}

#[cfg(unix)]
pub async fn serve(mut status: watch::Receiver<String>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let path = socket_path();
    let parent = path.parent().context("status socket path has no parent")?;
    tokio::fs::create_dir_all(parent).await?;
    tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("binding server status socket at {}", path.display()))?;
    tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
    tracing::info!(path = %path.display(), "local server status socket ready");

    let result = async {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let snapshot = (*status.borrow_and_update()).clone();
                    tokio::spawn(async move {
                        if let Err(error) = handle_connection(stream, snapshot).await {
                            tracing::debug!(%error, "server status request failed");
                        }
                    });
                }
                changed = status.changed() => {
                    if changed.is_err() { return Ok(()); }
                }
            }
        }
    }
    .await;
    let _ = tokio::fs::remove_file(path).await;
    result
}

#[cfg(unix)]
async fn handle_connection(mut stream: UnixStream, snapshot: String) -> io::Result<()> {
    let mut request = [0u8; 32];
    let length = stream.read(&mut request).await?;
    let response = match std::str::from_utf8(&request[..length])
        .unwrap_or_default()
        .trim()
    {
        "PING" => "PONG\n".to_string(),
        "STATUS" => snapshot,
        _ => "ERR\tunsupported request (use STATUS or PING)\n".to_string(),
    };
    stream.write_all(response.as_bytes()).await
}

#[cfg(not(unix))]
pub async fn serve(_status: watch::Receiver<String>) -> Result<()> {
    tracing::warn!("local server status socket is currently supported on Unix platforms only");
    let mut status = _status;
    let _ = status.changed().await;
    Ok(())
}

/// Converts peer names to a single-line, tab-separated safe field.
pub fn field(value: &str) -> String {
    value.replace(['\n', '\r', '\t'], " ")
}
