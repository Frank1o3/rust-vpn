use anyhow::{Context, Result, bail};
use rvpn_core::SessionId;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::state::{ActivePeer, PeerStats};

const FILE_VERSION: u32 = 1;
const MAX_HISTORY_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
struct UsageTotals {
    rx_packets: u64,
    rx_payload_bytes: u64,
    tx_packets: u64,
    tx_payload_bytes: u64,
    dropped_packets: u64,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct HistoryFile {
    version: u32,
    days: BTreeMap<String, BTreeMap<String, UsageTotals>>,
}

pub struct UsageHistory {
    path: PathBuf,
    retention_days: u16,
    file: HistoryFile,
    previous: HashMap<SessionId, (String, PeerStats)>,
    dirty: bool,
}

impl UsageHistory {
    pub fn open(path: impl Into<PathBuf>, retention_days: u16) -> Result<Self> {
        let path = path.into();
        let file = if path.exists() {
            let metadata = fs::metadata(&path)
                .with_context(|| format!("reading usage history metadata at {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if metadata.permissions().mode() & 0o077 != 0
                    || metadata.uid() != unsafe { libc::geteuid() } as u32
                {
                    bail!(
                        "usage history must be owned by the server user and mode 0600: {}",
                        path.display()
                    );
                }
            }
            if metadata.len() > MAX_HISTORY_FILE_BYTES {
                bail!("usage history file exceeds 64 MiB: {}", path.display());
            }
            let bytes = fs::read(&path)
                .with_context(|| format!("reading usage history at {}", path.display()))?;
            let file: HistoryFile = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing usage history at {}", path.display()))?;
            if file.version != FILE_VERSION {
                bail!("unsupported usage history version {}", file.version);
            }
            file
        } else {
            HistoryFile {
                version: FILE_VERSION,
                ..HistoryFile::default()
            }
        };
        Ok(Self {
            path,
            retention_days,
            file,
            previous: HashMap::new(),
            dirty: false,
        })
    }

    pub fn record<'a>(&mut self, peers: impl Iterator<Item = (&'a SessionId, &'a ActivePeer)>) {
        let day = utc_day();
        let mut current = HashMap::new();
        for (session_id, peer) in peers {
            let name = peer.identity.name.clone();
            let stats = peer.stats;
            let previous = self
                .previous
                .get(session_id)
                .map(|(_, stats)| *stats)
                .unwrap_or_default();
            let delta = UsageTotals {
                rx_packets: stats.rx_packets.saturating_sub(previous.rx_packets),
                rx_payload_bytes: stats
                    .rx_payload_bytes
                    .saturating_sub(previous.rx_payload_bytes),
                tx_packets: stats.tx_packets.saturating_sub(previous.tx_packets),
                tx_payload_bytes: stats
                    .tx_payload_bytes
                    .saturating_sub(previous.tx_payload_bytes),
                dropped_packets: stats
                    .dropped_packets
                    .saturating_sub(previous.dropped_packets),
            };
            if delta.rx_packets != 0
                || delta.rx_payload_bytes != 0
                || delta.tx_packets != 0
                || delta.tx_payload_bytes != 0
                || delta.dropped_packets != 0
            {
                let totals = self
                    .file
                    .days
                    .entry(day.clone())
                    .or_default()
                    .entry(name.clone())
                    .or_default();
                add(totals, delta);
                self.dirty = true;
            }
            current.insert(*session_id, (name, stats));
        }
        self.previous = current;
        self.prune();
    }

    pub fn flush(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            create_private_directories(parent).with_context(|| {
                format!("creating usage history directory {}", parent.display())
            })?;
        }
        self.file.version = FILE_VERSION;
        let encoded = serde_json::to_vec_pretty(&self.file).context("encoding usage history")?;
        if encoded.len() as u64 > MAX_HISTORY_FILE_BYTES {
            bail!("usage history would exceed 64 MiB; reduce retention or reset the history");
        }
        let mut temporary = self.path.as_os_str().to_owned();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        temporary.push(format!(".{}-{nonce}.tmp", std::process::id()));
        let temporary = PathBuf::from(temporary);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(&temporary)
            .with_context(|| format!("creating temporary usage history {}", temporary.display()))?;
        output
            .write_all(&encoded)
            .with_context(|| format!("writing temporary usage history {}", temporary.display()))?;
        output.sync_all().context("syncing usage history file")?;
        drop(output);
        fs::rename(&temporary, &self.path).with_context(|| {
            format!(
                "atomically replacing usage history at {}",
                self.path.display()
            )
        })?;
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            && let Ok(directory) = OpenOptions::new().read(true).open(parent)
        {
            let _ = directory.sync_all();
        }
        self.dirty = false;
        Ok(())
    }

    fn prune(&mut self) {
        let today = utc_day_number();
        let retention = u64::from(self.retention_days);
        let before = self.file.days.len();
        self.file.days.retain(|day, _| {
            parse_day_number(day)
                .is_some_and(|day_number| day_number <= today && today - day_number < retention)
        });
        self.dirty |= self.file.days.len() != before;
    }
}

#[cfg(unix)]
fn create_private_directories(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directories(path: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

fn add(target: &mut UsageTotals, delta: UsageTotals) {
    target.rx_packets = target.rx_packets.saturating_add(delta.rx_packets);
    target.rx_payload_bytes = target
        .rx_payload_bytes
        .saturating_add(delta.rx_payload_bytes);
    target.tx_packets = target.tx_packets.saturating_add(delta.tx_packets);
    target.tx_payload_bytes = target
        .tx_payload_bytes
        .saturating_add(delta.tx_payload_bytes);
    target.dropped_packets = target.dropped_packets.saturating_add(delta.dropped_packets);
}

fn utc_day_number() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400
}

fn utc_day() -> String {
    let days = utc_day_number() as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    format!("{year:04}-{month:02}-{day:02}")
}

fn parse_day_number(day: &str) -> Option<u64> {
    let mut fields = day.split('-');
    let year: i64 = fields.next()?.parse().ok()?;
    let month: i64 = fields.next()?.parse().ok()?;
    let day: i64 = fields.next()?.parse().ok()?;
    if fields.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    u64::try_from(era * 146_097 + doe - 719_468).ok()
}
