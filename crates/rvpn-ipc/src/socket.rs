use std::{io, path::PathBuf};

use interprocess::local_socket::{
    GenericFilePath, GenericNamespaced, ListenerOptions, ToFsName, ToNsName,
    tokio::{Listener, Stream},
    traits::tokio::{Listener as _, Stream as _},
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::{ControlRequest, ControlResponse};

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("malformed control message")]
    Malformed,
    #[error("control connection closed")]
    Closed,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Filesystem path backing the control socket on Unix (unused on Windows,
/// which uses a named pipe under a fixed name instead). Honors
/// `$XDG_RUNTIME_DIR` — set by systemd/logind per-session, mode 0700 so
/// only this user can reach it — and falls back to a per-uid path under
/// `/tmp` outside a login session.
pub fn socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("rvpn").join("control.sock");
    }
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        return PathBuf::from(format!("/tmp/rvpn-{uid}")).join("control.sock");
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir().join("rvpn").join("control.sock")
    }
}

const WINDOWS_PIPE_NAME: &str = "rvpn-control";

async fn create_listener() -> Result<Listener, IpcError> {
    if cfg!(windows) {
        let name = WINDOWS_PIPE_NAME.to_ns_name::<GenericNamespaced>()?;
        return Ok(ListenerOptions::new().name(name).create_tokio()?);
    }

    let path = socket_path();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;
        }
    }
    let path_str = path.to_string_lossy().into_owned();
    let name = path_str.as_str().to_fs_name::<GenericFilePath>()?;
    match ListenerOptions::new().name(name).create_tokio() {
        Ok(listener) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
            }
            Ok(listener)
        }
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            tokio::fs::remove_file(&path).await.ok();
            let name = path_str.as_str().to_fs_name::<GenericFilePath>()?;
            let listener = ListenerOptions::new().name(name).create_tokio()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
            }
            Ok(listener)
        }
        Err(e) => Err(e.into()),
    }
}

async fn connect_stream() -> Result<Stream, IpcError> {
    if cfg!(windows) {
        let name = WINDOWS_PIPE_NAME.to_ns_name::<GenericNamespaced>()?;
        return Ok(Stream::connect(name).await?);
    }
    let path_str = socket_path().to_string_lossy().into_owned();
    let name = path_str.as_str().to_fs_name::<GenericFilePath>()?;
    Ok(Stream::connect(name).await?)
}

/// A control connection, framed as one `\n`-terminated line per message.
/// The daemon reads requests and writes responses; a controller
/// (`rvpn-tray`, or `socat`/`nc -U` for poking at it by hand) does the
/// reverse via [`Connection::call`].
pub struct Connection {
    stream: Stream,
    buf: Vec<u8>,
}

impl Connection {
    fn new(stream: Stream) -> Self {
        Self {
            stream,
            buf: Vec::new(),
        }
    }

    pub async fn connect() -> Result<Self, IpcError> {
        Ok(Self::new(connect_stream().await?))
    }

    async fn read_line(&mut self) -> Result<Option<String>, IpcError> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let rest = self.buf.split_off(pos + 1);
                let mut line = std::mem::replace(&mut self.buf, rest);
                line.pop(); // drop the trailing '\n'
                return String::from_utf8(line)
                    .map(Some)
                    .map_err(|_| IpcError::Malformed);
            }
            let mut chunk = [0u8; 512];
            let mut reader = &self.stream;
            let read = reader.read(&mut chunk).await?;
            if read == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(IpcError::Malformed)
                };
            }
            self.buf.extend_from_slice(&chunk[..read]);
        }
    }

    async fn write_line(&mut self, line: String) -> Result<(), IpcError> {
        let mut bytes = line.into_bytes();
        bytes.push(b'\n');
        let mut writer = &self.stream;
        writer.write_all(&bytes).await?;
        Ok(())
    }

    pub async fn read_request(&mut self) -> Result<Option<ControlRequest>, IpcError> {
        let Some(line) = self.read_line().await? else {
            return Ok(None);
        };
        ControlRequest::decode(&line).map(Some)
    }

    pub async fn write_response(&mut self, response: &ControlResponse) -> Result<(), IpcError> {
        self.write_line(response.encode()).await
    }

    pub async fn write_request(&mut self, request: &ControlRequest) -> Result<(), IpcError> {
        self.write_line(request.encode()).await
    }

    pub async fn read_response(&mut self) -> Result<ControlResponse, IpcError> {
        let Some(line) = self.read_line().await? else {
            return Err(IpcError::Closed);
        };
        ControlResponse::decode(&line)
    }

    /// One-shot request/response exchange — what `rvpn-tray` uses.
    pub async fn call(&mut self, request: &ControlRequest) -> Result<ControlResponse, IpcError> {
        self.write_request(request).await?;
        self.read_response().await
    }
}

/// Binds the control socket and runs forever, spawning `on_connection` for
/// each accepted connection. `on_connection` gets one [`Connection`] and
/// decides how many requests to read off it — the daemon side loops until
/// the peer disconnects.
pub async fn serve<F, Fut>(on_connection: F) -> Result<(), IpcError>
where
    F: Fn(Connection) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = create_listener().await?;
    let on_connection = std::sync::Arc::new(on_connection);
    loop {
        let stream = listener.accept().await?;
        let conn = Connection::new(stream);
        let handler = std::sync::Arc::clone(&on_connection);
        tokio::spawn(async move { handler(conn).await });
    }
}
