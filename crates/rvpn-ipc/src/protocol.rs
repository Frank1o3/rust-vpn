use std::time::Duration;

use crate::IpcError;

/// A command sent from a controller (systemd, `rvpn-tray`, or anything else
/// speaking the protocol) to the `rvpn-client` daemon.
#[derive(Clone, Debug)]
pub enum ControlRequest {
    /// Connect using the client TOML at `config_path`. Fails if a session
    /// is already active — send `Disconnect` first.
    Connect { config_path: String },
    /// Tear down the currently active session, if any.
    Disconnect,
    /// Report the current connection status and tunnel stats.
    Status,
    /// Liveness check.
    Ping,
}

#[derive(Clone, Debug)]
pub enum ControlResponse {
    Ok,
    Err(String),
    Status(StatusSnapshot),
    Pong,
}

/// Wire-friendly snapshot of one client session's state. Mirrors what the
/// old in-process tray tooltip used to read directly off `GuiState`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StatusSnapshot {
    pub connected: bool,
    pub server: String,
    pub session_id: String,
    pub uptime_secs: u64,
    pub key_phase: u32,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub packets_tx: u64,
    pub packets_rx: u64,
    pub effective_mtu: u64,
    pub mtu_state: String,
    pub mtu_changes: u64,
    pub send_errors: u64,
    pub dropped_oversized: u64,
    pub dropped_backpressure: u64,
    pub keepalives_sent: u64,
}

impl StatusSnapshot {
    pub fn disconnected() -> Self {
        Self::default()
    }

    pub fn tooltip_text(&self) -> String {
        if !self.connected {
            return "RVPN — Disconnected".to_string();
        }
        format!(
            "RVPN — Connected\n{server}\nUp {uptime} · phase {phase}\n↓ {rx}  ↑ {tx}\nMTU {mtu} ({state})",
            server = self.server,
            uptime = format_duration(Duration::from_secs(self.uptime_secs)),
            phase = self.key_phase,
            rx = format_bytes(self.bytes_rx),
            tx = format_bytes(self.bytes_tx),
            mtu = self.effective_mtu,
            state = self.mtu_state,
        )
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

pub fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

// --- wire format: one line per message, tab-separated fields ---------

impl ControlRequest {
    pub(crate) fn encode(&self) -> String {
        match self {
            Self::Connect { config_path } => format!("CONNECT\t{config_path}"),
            Self::Disconnect => "DISCONNECT".to_string(),
            Self::Status => "STATUS".to_string(),
            Self::Ping => "PING".to_string(),
        }
    }

    pub(crate) fn decode(line: &str) -> Result<Self, IpcError> {
        let mut parts = line.splitn(2, '\t');
        match parts.next().unwrap_or_default() {
            "CONNECT" => Ok(Self::Connect {
                config_path: parts.next().ok_or(IpcError::Malformed)?.to_string(),
            }),
            "DISCONNECT" => Ok(Self::Disconnect),
            "STATUS" => Ok(Self::Status),
            "PING" => Ok(Self::Ping),
            _ => Err(IpcError::Malformed),
        }
    }
}

impl ControlResponse {
    pub(crate) fn encode(&self) -> String {
        match self {
            Self::Ok => "OK".to_string(),
            Self::Pong => "PONG".to_string(),
            Self::Err(message) => {
                format!("ERR\t{}", message.replace('\n', " ").replace('\t', " "))
            }
            Self::Status(s) => format!(
                "STATUS\t{connected}\t{server}\t{session_id}\t{uptime}\t{phase}\t{btx}\t{brx}\t{ptx}\t{prx}\t{mtu}\t{mtu_state}\t{mtu_changes}\t{send_errors}\t{dropped_oversized}\t{dropped_backpressure}\t{keepalives}",
                connected = s.connected,
                server = non_empty(&s.server),
                session_id = non_empty(&s.session_id),
                uptime = s.uptime_secs,
                phase = s.key_phase,
                btx = s.bytes_tx,
                brx = s.bytes_rx,
                ptx = s.packets_tx,
                prx = s.packets_rx,
                mtu = s.effective_mtu,
                mtu_state = non_empty(&s.mtu_state),
                mtu_changes = s.mtu_changes,
                send_errors = s.send_errors,
                dropped_oversized = s.dropped_oversized,
                dropped_backpressure = s.dropped_backpressure,
                keepalives = s.keepalives_sent,
            ),
        }
    }

    pub(crate) fn decode(line: &str) -> Result<Self, IpcError> {
        let mut parts = line.split('\t');
        match parts.next().unwrap_or_default() {
            "OK" => Ok(Self::Ok),
            "PONG" => Ok(Self::Pong),
            "ERR" => Ok(Self::Err(parts.next().unwrap_or_default().to_string())),
            "STATUS" => {
                let mut next = || parts.next().ok_or(IpcError::Malformed);
                let connected = next()?.parse().map_err(|_| IpcError::Malformed)?;
                let server = opt(next()?);
                let session_id = opt(next()?);
                let uptime_secs = next()?.parse().map_err(|_| IpcError::Malformed)?;
                let key_phase = next()?.parse().map_err(|_| IpcError::Malformed)?;
                let bytes_tx = next()?.parse().map_err(|_| IpcError::Malformed)?;
                let bytes_rx = next()?.parse().map_err(|_| IpcError::Malformed)?;
                let packets_tx = next()?.parse().map_err(|_| IpcError::Malformed)?;
                let packets_rx = next()?.parse().map_err(|_| IpcError::Malformed)?;
                let effective_mtu = next()?.parse().map_err(|_| IpcError::Malformed)?;
                let mtu_state = opt(next()?);
                let mtu_changes = next()?.parse().map_err(|_| IpcError::Malformed)?;
                let send_errors = next()?.parse().map_err(|_| IpcError::Malformed)?;
                let dropped_oversized = next()?.parse().map_err(|_| IpcError::Malformed)?;
                let dropped_backpressure = next()?.parse().map_err(|_| IpcError::Malformed)?;
                let keepalives_sent = next()?.parse().map_err(|_| IpcError::Malformed)?;
                Ok(Self::Status(StatusSnapshot {
                    connected,
                    server,
                    session_id,
                    uptime_secs,
                    key_phase,
                    bytes_tx,
                    bytes_rx,
                    packets_tx,
                    packets_rx,
                    effective_mtu,
                    mtu_state,
                    mtu_changes,
                    send_errors,
                    dropped_oversized,
                    dropped_backpressure,
                    keepalives_sent,
                }))
            }
            _ => Err(IpcError::Malformed),
        }
    }
}

fn non_empty(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

fn opt(value: &str) -> String {
    if value == "-" {
        String::new()
    } else {
        value.to_string()
    }
}
