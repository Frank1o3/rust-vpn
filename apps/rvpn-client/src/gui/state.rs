use std::sync::{Arc, Mutex};
use std::time::Duration;

use rvpn_transport::{MetricsSnapshot, MtuChangeReason, MtuSnapshot};

#[derive(Clone, Debug)]
pub struct GuiState {
    pub connected: bool,
    pub server: String,
    pub uptime: Duration,
    pub session_id: String,
    pub key_phase: u32,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub packets_tx: u64,
    pub packets_rx: u64,
    pub configured_mtu: usize,
    pub effective_mtu: usize,
    pub mtu_state: String,
    pub last_mtu_change: Option<String>,
    pub mtu_changes: u64,
    pub send_errors: u64,
    pub dropped_oversized: u64,
    pub dropped_backpressure: u64,
    pub keepalives_sent: u64,
}

impl Default for GuiState {
    fn default() -> Self {
        Self {
            connected: false,
            server: String::new(),
            uptime: Duration::ZERO,
            session_id: "—".into(),
            key_phase: 0,
            bytes_tx: 0,
            bytes_rx: 0,
            packets_tx: 0,
            packets_rx: 0,
            configured_mtu: 0,
            effective_mtu: 0,
            mtu_state: "Unknown".into(),
            last_mtu_change: None,
            mtu_changes: 0,
            send_errors: 0,
            dropped_oversized: 0,
            dropped_backpressure: 0,
            keepalives_sent: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GuiSnapshot {
    pub connected: bool,
    pub server: String,
    pub uptime: u64,
    pub session_id: String,
    pub key_phase: String,

    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub packets_tx: u64,
    pub packets_rx: u64,

    pub configured_mtu: usize,
    pub effective_mtu: usize,
    pub mtu_state: String,
    pub last_mtu_change: Option<String>,

    pub mtu_changes: u64,
    pub send_errors: u64,
    pub dropped_oversized: u64,
    pub dropped_backpressure: u64,
    pub keepalives_sent: u64,
}

pub type GuiStateHandle = Arc<Mutex<GuiState>>;

impl GuiState {
    pub fn snapshot(&self) -> GuiSnapshot {
        GuiSnapshot {
            connected: self.connected,
            server: self.server.clone(),
            uptime: self.uptime,
            session_id: self.session_id.clone(),
            key_phase: self.key_phase.clone(),

            bytes_tx: self.bytes_tx,
            bytes_rx: self.bytes_rx,
            packets_tx: self.packets_tx,
            packets_rx: self.packets_rx,

            configured_mtu: self.configured_mtu,
            effective_mtu: self.effective_mtu,
            mtu_state: self.mtu_state.clone(),
            last_mtu_change: self.last_mtu_change.clone(),

            mtu_changes: self.mtu_changes,
            send_errors: self.send_errors,
            dropped_oversized: self.dropped_oversized,
            dropped_backpressure: self.dropped_backpressure,
            keepalives_sent: self.keepalives_sent,
        }
    }

    pub fn handle() -> GuiStateHandle {
        Arc::new(Mutex::new(Self::default()))
    }

    pub fn set_server(&mut self, server: impl Into<String>) {
        self.server = server.into();
    }

    pub fn connected(&mut self, session_id: impl Into<String>, configured_mtu: usize) {
        self.connected = true;
        self.session_id = session_id.into();
        self.configured_mtu = configured_mtu;
    }

    pub fn disconnected(&mut self) {
        self.connected = false;
    }

    pub fn set_uptime(&mut self, uptime: Duration) {
        self.uptime = uptime;
    }

    pub fn set_key_phase(&mut self, key_phase: u32) {
        self.key_phase = key_phase;
    }

    pub fn record_tx(&mut self, bytes: usize) {
        self.bytes_tx = self.bytes_tx.saturating_add(bytes as u64);
        self.packets_tx = self.packets_tx.saturating_add(1);
    }

    pub fn record_rx(&mut self, bytes: usize) {
        self.bytes_rx = self.bytes_rx.saturating_add(bytes as u64);
        self.packets_rx = self.packets_rx.saturating_add(1);
    }

    pub fn update_transport(&mut self, metrics: MetricsSnapshot, mtu: MtuSnapshot) {
        self.effective_mtu = mtu.effective_mtu;
        self.mtu_state = if mtu.probing {
            "Probing".into()
        } else if mtu.effective_mtu < mtu.maximum_mtu {
            "Reduced".into()
        } else {
            "Stable".into()
        };
        self.mtu_changes = metrics.mtu_changes;
        self.send_errors = metrics.send_errors;
        self.dropped_oversized = metrics.packets_dropped_oversized;
        self.dropped_backpressure = metrics.packets_dropped_backpressure;
        self.keepalives_sent = metrics.keepalives_sent;
    }

    pub fn set_mtu_change_reason(&mut self, reason: MtuChangeReason) {
        self.last_mtu_change = Some(match reason {
            MtuChangeReason::PathMtuExceeded => "Path MTU exceeded".into(),
            MtuChangeReason::SustainedInstability => "Sustained instability".into(),
            MtuChangeReason::ProbeUp => "MTU probe succeeded".into(),
            MtuChangeReason::ProbeReverted => "MTU probe reverted".into(),
        });
    }
}
