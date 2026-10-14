//! Loopback-only metrics portal with a bearer token stored in a private runtime file.

use anyhow::{Context, Result};
use rand::{TryRng, rngs::SysRng};
use serde_json::{Value, json};
use std::{collections::VecDeque, io, net::SocketAddr, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    time::{interval, timeout},
};

const PORTAL_ADDRESS: &str = "127.0.0.1:9842";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const HISTORY_SAMPLES: usize = 180;

fn runtime_dir() -> PathBuf {
    if let Ok(path) = std::env::var("RVPN_RUNTIME_DIR") {
        PathBuf::from(path)
    } else if let Ok(path) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(path).join("rvpn")
    } else {
        let uid = unsafe { libc::getuid() };
        PathBuf::from(format!("/tmp/rvpn-{uid}"))
    }
}

fn token_file() -> PathBuf {
    runtime_dir().join("portal.token")
}

async fn create_token() -> Result<String> {
    use std::os::unix::fs::PermissionsExt;

    let dir = runtime_dir();
    tokio::fs::create_dir_all(&dir).await?;
    tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).await?;
    let mut random = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut random)
        .map_err(|error| anyhow::anyhow!("generating portal token: {error}"))?;
    let token = hex::encode(random);
    let mut token_handle = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(token_file())
        .await?;
    token_handle
        .write_all(format!("{token}\n").as_bytes())
        .await?;
    token_handle.flush().await?;
    tokio::fs::set_permissions(token_file(), std::fs::Permissions::from_mode(0o600)).await?;
    Ok(token)
}

pub async fn serve(mut status: watch::Receiver<String>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let token = create_token().await?;
    let listener = match TcpListener::bind(PORTAL_ADDRESS).await {
        Ok(listener) => listener,
        Err(error) => {
            let _ = tokio::fs::remove_file(token_file()).await;
            return Err(error)
                .with_context(|| format!("binding local metrics portal at {PORTAL_ADDRESS}"));
        }
    };
    let local_address = listener.local_addr()?;
    tracing::info!(
        address = %local_address,
        token_file = %token_file().display(),
        "local metrics portal ready"
    );

    let mut sample_tick = interval(Duration::from_secs(5));
    let mut history: VecDeque<Value> = VecDeque::with_capacity(HISTORY_SAMPLES);
    let request_slots = std::sync::Arc::new(Semaphore::new(32));
    let result = async {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, remote) = accepted?;
                    if !remote.ip().is_loopback() {
                        continue;
                    }
                    let Ok(slot) = std::sync::Arc::clone(&request_slots).try_acquire_owned() else {
                        continue;
                    };
                    let snapshot = (*status.borrow()).clone();
                    let recent: Vec<Value> = history.iter().cloned().collect();
                    let token = token.clone();
                    tokio::spawn(async move {
                        let _slot = slot;
                        if let Err(error) = handle_request(stream, snapshot, recent, token).await {
                            tracing::debug!(%error, "metrics portal request failed");
                        }
                    });
                }
                _ = sample_tick.tick() => {
                    let snapshot = (*status.borrow_and_update()).clone();
                    let peers = parse_snapshot(&snapshot).0;
                    let rx: f64 = peers.iter().map(|peer| number(peer, "rx_rate")).sum();
                    let tx: f64 = peers.iter().map(|peer| number(peer, "tx_rate")).sum();
                    history.push_back(json!({
                        "time": unix_time(),
                        "rx": rx,
                        "tx": tx,
                    }));
                    if history.len() > HISTORY_SAMPLES {
                        history.pop_front();
                    }
                }
                changed = status.changed() => {
                    if changed.is_err() { return Ok(()); }
                }
            }
        }
    }
    .await;
    let _ = tokio::fs::remove_file(token_file()).await;
    let _ = tokio::fs::set_permissions(runtime_dir(), std::fs::Permissions::from_mode(0o700)).await;
    result
}

async fn handle_request(
    mut stream: TcpStream,
    snapshot: String,
    history: Vec<Value>,
    token: String,
) -> io::Result<()> {
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    timeout(Duration::from_secs(5), async {
        loop {
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                return Ok::<(), io::Error>(());
            }
            if request.len() >= MAX_REQUEST_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP headers too large",
                ));
            }
            let count = stream.read(&mut chunk).await?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "HTTP request closed",
                ));
            }
            request.extend_from_slice(&chunk[..count]);
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP request timed out"))??;

    let text = String::from_utf8_lossy(&request);
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or_default();
    let mut request_parts = first.split_whitespace();
    let method = request_parts.next().unwrap_or_default();
    let path = request_parts.next().unwrap_or_default();
    let auth = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("authorization")
            .then(|| value.trim())
    });

    let (status, content_type, body) = if method != "GET" {
        (
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "GET only".to_string(),
        )
    } else if path == "/" || path == "/index.html" {
        (
            "200 OK",
            "text/html; charset=utf-8",
            include_str!("portal.html").to_string(),
        )
    } else if path == "/api/metrics" {
        if !auth.is_some_and(|value| bearer_matches(value, &token)) {
            (
                "401 Unauthorized",
                "application/json",
                "{\"error\":\"unauthorized\"}".to_string(),
            )
        } else {
            let body = portal_json(&snapshot, history);
            ("200 OK", "application/json; charset=utf-8", body)
        }
    } else if path == "/metrics" {
        if !auth.is_some_and(|value| bearer_matches(value, &token)) {
            (
                "401 Unauthorized",
                "text/plain; charset=utf-8",
                "unauthorized\n".to_string(),
            )
        } else {
            (
                "200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                prometheus_metrics(&snapshot),
            )
        }
    } else {
        (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "Not found".to_string(),
        )
    };

    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await
}

fn bearer_matches(header: &str, expected: &str) -> bool {
    let Some(supplied) = header.strip_prefix("Bearer ") else {
        return false;
    };
    if supplied.len() != expected.len() {
        return false;
    }
    supplied
        .bytes()
        .zip(expected.bytes())
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn portal_json(snapshot: &str, history: Vec<Value>) -> String {
    let (peers, transport) = parse_snapshot(snapshot);
    json!({
        "updated_at": unix_time(),
        "peers": peers,
        "transport": transport,
        "history": history,
    })
    .to_string()
}

fn prometheus_metrics(snapshot: &str) -> String {
    use std::fmt::Write as _;

    let (peers, transport) = parse_snapshot(snapshot);
    let mut output = String::from(
        "# HELP rvpn_peer_connected Whether the authenticated peer has an active session.\n# TYPE rvpn_peer_connected gauge\n# HELP rvpn_peer_payload_bytes_total Authenticated inner payload bytes.\n# TYPE rvpn_peer_payload_bytes_total counter\n# HELP rvpn_peer_wire_bytes_total Encrypted tunnel datagram bytes.\n# TYPE rvpn_peer_wire_bytes_total counter\n# HELP rvpn_peer_packets_total Authenticated data packets.\n# TYPE rvpn_peer_packets_total counter\n# HELP rvpn_peer_dropped_packets_total Packets dropped for the peer.\n# TYPE rvpn_peer_dropped_packets_total counter\n# HELP rvpn_peer_payload_rate_bytes_per_second Current payload rate.\n# TYPE rvpn_peer_payload_rate_bytes_per_second gauge\n# HELP rvpn_peer_queue_delay_seconds Average and maximum outbound queue delay.\n# TYPE rvpn_peer_queue_delay_seconds gauge\n",
    );
    for peer in &peers {
        let name = prometheus_label(peer["name"].as_str().unwrap_or_default());
        let _ = writeln!(output, "rvpn_peer_connected{{peer=\"{name}\"}} 1");
        for (direction, payload, wire, packets, rate) in [
            (
                "rx",
                peer["rx_payload_bytes"].as_u64().unwrap_or_default(),
                peer["rx_wire_bytes"].as_u64().unwrap_or_default(),
                peer["rx_packets"].as_u64().unwrap_or_default(),
                peer["rx_rate"].as_f64().unwrap_or_default(),
            ),
            (
                "tx",
                peer["tx_payload_bytes"].as_u64().unwrap_or_default(),
                peer["tx_wire_bytes"].as_u64().unwrap_or_default(),
                peer["tx_packets"].as_u64().unwrap_or_default(),
                peer["tx_rate"].as_f64().unwrap_or_default(),
            ),
        ] {
            let _ = writeln!(
                output,
                "rvpn_peer_payload_bytes_total{{peer=\"{name}\",direction=\"{direction}\"}} {payload}"
            );
            let _ = writeln!(
                output,
                "rvpn_peer_wire_bytes_total{{peer=\"{name}\",direction=\"{direction}\"}} {wire}"
            );
            let _ = writeln!(
                output,
                "rvpn_peer_packets_total{{peer=\"{name}\",direction=\"{direction}\"}} {packets}"
            );
            let _ = writeln!(
                output,
                "rvpn_peer_payload_rate_bytes_per_second{{peer=\"{name}\",direction=\"{direction}\"}} {:.3}",
                rate * 1_048_576.0
            );
        }
        let drops = peer["dropped_packets"].as_u64().unwrap_or_default();
        let rx_drops = peer["rx_limited_drops"].as_u64().unwrap_or_default();
        let tx_drops = peer["tx_queue_drops"].as_u64().unwrap_or_default();
        let _ = writeln!(
            output,
            "rvpn_peer_dropped_packets_total{{peer=\"{name}\",reason=\"all\"}} {drops}"
        );
        let _ = writeln!(
            output,
            "rvpn_peer_dropped_packets_total{{peer=\"{name}\",reason=\"rx_limit\"}} {rx_drops}"
        );
        let _ = writeln!(
            output,
            "rvpn_peer_dropped_packets_total{{peer=\"{name}\",reason=\"tx_queue\"}} {tx_drops}"
        );
        let average = peer["avg_queue_delay_ms"].as_f64().unwrap_or_default() / 1000.0;
        let maximum = peer["max_queue_delay_ms"].as_f64().unwrap_or_default() / 1000.0;
        let _ = writeln!(
            output,
            "rvpn_peer_queue_delay_seconds{{peer=\"{name}\",statistic=\"average\"}} {average:.6}"
        );
        let _ = writeln!(
            output,
            "rvpn_peer_queue_delay_seconds{{peer=\"{name}\",statistic=\"maximum\"}} {maximum:.6}"
        );
        let _ = writeln!(
            output,
            "rvpn_peer_rekeys_total{{peer=\"{name}\"}} {}",
            peer["rekeys"].as_u64().unwrap_or_default()
        );
        let _ = writeln!(
            output,
            "rvpn_peer_key_phase{{peer=\"{name}\"}} {}",
            peer["key_phase"].as_u64().unwrap_or_default()
        );
        let _ = writeln!(
            output,
            "rvpn_peer_last_activity_seconds{{peer=\"{name}\"}} {}",
            peer["last_activity_secs"].as_u64().unwrap_or_default()
        );
        for (direction, field) in [
            ("rx", "rx_limit_mib_per_sec"),
            ("tx", "tx_limit_mib_per_sec"),
        ] {
            let limit = peer[field].as_u64().unwrap_or_default();
            let _ = writeln!(
                output,
                "rvpn_peer_rate_limit_bytes_per_second{{peer=\"{name}\",direction=\"{direction}\"}} {}",
                limit.saturating_mul(1_048_576)
            );
        }
    }
    for (name, field) in [
        ("rvpn_transport_bytes_sent_total", "bytes_sent"),
        ("rvpn_transport_bytes_received_total", "bytes_received"),
        ("rvpn_transport_packets_sent_total", "packets_sent"),
        ("rvpn_transport_packets_received_total", "packets_received"),
        (
            "rvpn_transport_dropped_oversized_total",
            "dropped_oversized",
        ),
        (
            "rvpn_transport_dropped_backpressure_total",
            "dropped_backpressure",
        ),
        ("rvpn_transport_send_errors_total", "send_errors"),
        (
            "rvpn_transport_congestion_events_total",
            "congestion_events",
        ),
        ("rvpn_transport_mtu_changes_total", "mtu_changes"),
    ] {
        let _ = writeln!(
            output,
            "{name} {}",
            transport[field].as_u64().unwrap_or_default()
        );
    }
    output
}

fn prometheus_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn parse_snapshot(snapshot: &str) -> (Vec<Value>, Value) {
    let mut peers = Vec::new();
    let mut transport = json!({});
    for line in snapshot.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.first().copied() {
            Some("PEER") if fields.len() >= 21 => peers.push(json!({
                "name": fields[1],
                "connected": fields[2] == "connected",
                "rx_packets": parse_u64(fields[3]),
                "rx_payload_bytes": parse_u64(fields[4]),
                "rx_wire_bytes": parse_u64(fields[5]),
                "tx_packets": parse_u64(fields[6]),
                "tx_payload_bytes": parse_u64(fields[7]),
                "tx_wire_bytes": parse_u64(fields[8]),
                "rx_rate": parse_f64(fields[9]),
                "tx_rate": parse_f64(fields[10]),
                "rx_limit_mib_per_sec": parse_u64(fields[11]),
                "tx_limit_mib_per_sec": parse_u64(fields[12]),
                "rx_limited_drops": parse_u64(fields[13]),
                "tx_queue_drops": parse_u64(fields[14]),
                "dropped_packets": parse_u64(fields[15]),
                "rekeys": parse_u64(fields[16]),
                "key_phase": parse_u64(fields[17]),
                "last_activity_secs": parse_u64(fields[18]),
                "avg_queue_delay_ms": parse_f64(fields[19]),
                "max_queue_delay_ms": parse_f64(fields[20]),
            })),
            Some("TRANSPORT") if fields.len() >= 12 => {
                transport = json!({
                    "bytes_sent": parse_u64(fields[1]),
                    "bytes_received": parse_u64(fields[2]),
                    "packets_sent": parse_u64(fields[3]),
                    "packets_received": parse_u64(fields[4]),
                    "dropped_oversized": parse_u64(fields[5]),
                    "dropped_backpressure": parse_u64(fields[6]),
                    "send_errors": parse_u64(fields[7]),
                    "congestion_events": parse_u64(fields[8]),
                    "keepalives_sent": parse_u64(fields[9]),
                    "keepalives_skipped": parse_u64(fields[10]),
                    "mtu_changes": parse_u64(fields[11]),
                });
            }
            _ => {}
        }
    }
    (peers, transport)
}

fn number(value: &Value, key: &str) -> f64 {
    value.get(key).and_then(Value::as_f64).unwrap_or_default()
}

fn parse_u64(value: &str) -> u64 {
    value.parse().unwrap_or_default()
}

fn parse_f64(value: &str) -> f64 {
    value.parse().unwrap_or_default()
}

fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
