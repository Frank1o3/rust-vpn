use anyhow::{Context, Result, bail};
use rvpn_config::{ForwardingConfig, HandshakeConfig, ServerConfig};
use rvpn_core::SessionId;
use rvpn_crypto::{AEAD_TAG_LEN, HandshakePsk};
use rvpn_interface::{DEFAULT_MTU, TunConfig, TunDevice};
use rvpn_protocol::{
    HEADER_LEN, HandshakeMessage, Header, Packet, PacketKind, ProtectedSession, ResponderHandshake,
};
use rvpn_transport::{SendOptions, TransportConfig, UdpTransport};
use std::{env, fs, net::SocketAddr, time::Duration};
use tokio::{process::Command, time::timeout};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let path = env::args()
        .nth(1)
        .context("usage: rvpn-server <server.toml>")?;
    let config = ServerConfig::from_toml(&fs::read_to_string(path)?)?;
    let tun_config = TunConfig {
        name: config.interface.name.clone(),
        mtu: config.interface.mtu.unwrap_or(DEFAULT_MTU),
    };
    let transport = UdpTransport::open(TransportConfig {
        local_address: config.bind,
        remote_address: None,
        max_datagram_size: usize::from(tun_config.mtu) + HEADER_LEN + AEAD_TAG_LEN,
    })
    .await?;
    tracing::info!(bind = %transport.local_addr()?, "rvpn server waiting for one handshake");
    let psk = config.pre_shared_key_bytes()?;
    let (mut session, mut peer) = accept_initial(&transport, psk, &config.handshake).await?;
    let tun = TunDevice::create(tun_config).await?;
    configure_server_interface(&tun, &config).await?;
    let forwarding = ForwardingGuard::install(&config.forwarding, tun.name()).await?;
    tracing::info!(session_id = ?session.session_id(), %peer, interface = %tun.name(), mtu = tun.mtu(), "authenticated RVPN server data plane started for one peer");
    loop {
        tokio::select! {
            signal = shutdown_signal() => {
                signal?;
                let close = session.seal(PacketKind::Close, b"")?;
                let _ = transport.send_to(peer, close.encode(), SendOptions::default()).await;
                forwarding.cleanup().await;
                tracing::info!("sent authenticated close packet");
                return Ok(());
            }
            packet = tun.recv() => {
                if config.rekey.packet_limit != 0 && session.should_rekey(config.rekey.packet_limit) {
                    // Only the client originates the PSK handshake. This authenticated
                    // request asks it to do so before the server's counter gets large.
                    let request = session.seal(PacketKind::Rekey, b"")?;
                    transport.send_to(peer, request.encode(), SendOptions::default()).await?;
                }
                let packet = session.seal(PacketKind::Data, &packet?)?;
                transport.send_to(peer, packet.encode(), SendOptions::default()).await?;
            }
            datagram = transport.receive() => {
                let datagram = datagram?;
                let packet = match Packet::decode(datagram.payload) { Ok(packet) => packet, Err(error) => { tracing::warn!(%error, "discarding malformed RVPN packet"); continue; } };
                if packet.header.kind == PacketKind::Rekey && packet.header.session_id == session.session_id() && packet.header.key_phase == session.key_phase() {
                    if let Ok(HandshakeMessage::Initiation { .. }) = HandshakeMessage::decode(packet.payload.clone()) {
                        match accept_rekey(&transport, datagram.peer, psk, &config.handshake, &session, packet).await {
                            Ok(next) => { session = next; peer = datagram.peer; tracing::info!(%peer, key_phase = session.key_phase(), "rotated RVPN session keys"); }
                            Err(error) => tracing::warn!(%error, "rekey failed"),
                        }
                    }
                    continue;
                }
                match packet.header.kind {
                    PacketKind::Data => match session.open(packet) {
                        Ok(packet) => {
                            if datagram.peer != peer { tracing::info!(old_peer = %peer, new_peer = %datagram.peer, "authenticated peer roamed"); peer = datagram.peer; }
                            tun.send(&packet).await?;
                        }
                        Err(error) => tracing::warn!(%error, "discarding unauthenticated or replayed RVPN packet"),
                    },
                    PacketKind::Close => if session.open(packet).is_ok() { forwarding.cleanup().await; tracing::info!(%peer, "peer closed session"); return Ok(()); },
                    _ => {}
                }
            }
        }
    }
}

async fn accept_initial(
    transport: &UdpTransport,
    psk: [u8; 32],
    policy: &HandshakeConfig,
) -> Result<(ProtectedSession, SocketAddr)> {
    loop {
        let datagram = transport.receive().await?;
        let packet = match Packet::decode(datagram.payload) {
            Ok(packet) => packet,
            Err(_) => continue,
        };
        if packet.header.kind != PacketKind::Handshake
            || packet.header.key_phase != 0
            || packet.header.sequence != 0
            || packet.header.session_id != SessionId::new([0; 16])
        {
            continue;
        }
        let initiation = match HandshakeMessage::decode(packet.payload) {
            Ok(message @ HandshakeMessage::Initiation { .. }) => message,
            _ => continue,
        };
        let (handshake, response) =
            ResponderHandshake::accept(HandshakePsk::from_bytes(psk), initiation)?;
        let session_id = match response {
            HandshakeMessage::Response { session_id, .. } => session_id,
            _ => unreachable!(),
        };
        let response_packet = Packet {
            header: Header {
                kind: PacketKind::Handshake,
                key_phase: 0,
                sequence: 0,
                session_id,
            },
            payload: response.encode(),
        };
        for attempt in 1..=policy.retry_limit {
            transport
                .send_to(
                    datagram.peer,
                    response_packet.encode(),
                    SendOptions::default(),
                )
                .await?;
            match timeout(
                Duration::from_millis(policy.retry_interval_ms),
                transport.receive(),
            )
            .await
            {
                Ok(Ok(finish)) if finish.peer == datagram.peer => {
                    if let Ok(packet) = Packet::decode(finish.payload) {
                        if packet.header.kind == PacketKind::Handshake
                            && packet.header.session_id == session_id
                            && packet.header.sequence == 1
                        {
                            if let Ok(finish @ HandshakeMessage::Finish { .. }) =
                                HandshakeMessage::decode(packet.payload)
                            {
                                return Ok((handshake.finish(finish)?, datagram.peer));
                            }
                        }
                        // A duplicate initiation means the response was lost; retransmit immediately.
                        if packet.header.kind == PacketKind::Handshake
                            && packet.header.sequence == 0
                        {
                            continue;
                        }
                    }
                }
                Ok(Err(error)) => return Err(error.into()),
                _ => tracing::debug!(
                    attempt,
                    "handshake finish timed out; retransmitting response"
                ),
            }
        }
        tracing::warn!(peer = %datagram.peer, "handshake did not finish; awaiting a new initiation");
    }
}

async fn accept_rekey(
    transport: &UdpTransport,
    peer: SocketAddr,
    psk: [u8; 32],
    policy: &HandshakeConfig,
    current: &ProtectedSession,
    packet: Packet,
) -> Result<ProtectedSession> {
    let initiation = HandshakeMessage::decode(packet.payload)?;
    let phase = current
        .key_phase()
        .checked_add(1)
        .context("key phase exhausted")?;
    let (handshake, response) = ResponderHandshake::accept_for_session(
        HandshakePsk::from_bytes(psk),
        initiation,
        current.session_id(),
        phase,
    )?;
    let response_packet = Packet {
        header: Header {
            kind: PacketKind::Rekey,
            key_phase: current.key_phase(),
            sequence: 0,
            session_id: current.session_id(),
        },
        payload: response.encode(),
    };
    for attempt in 1..=policy.retry_limit {
        transport
            .send_to(peer, response_packet.encode(), SendOptions::default())
            .await?;
        match timeout(
            Duration::from_millis(policy.retry_interval_ms),
            transport.receive(),
        )
        .await
        {
            Ok(Ok(finish)) if finish.peer == peer => {
                if let Ok(packet) = Packet::decode(finish.payload) {
                    if packet.header.kind == PacketKind::Rekey
                        && packet.header.session_id == current.session_id()
                        && packet.header.key_phase == current.key_phase()
                        && packet.header.sequence == 1
                    {
                        if let Ok(finish @ HandshakeMessage::Finish { .. }) =
                            HandshakeMessage::decode(packet.payload)
                        {
                            return Ok(handshake.finish(finish)?);
                        }
                    }
                }
            }
            Ok(Err(error)) => return Err(error.into()),
            _ => tracing::debug!(attempt, "rekey finish timed out; retransmitting response"),
        }
    }
    bail!("rekey timed out after {} attempts", policy.retry_limit)
}

async fn configure_server_interface(tun: &TunDevice, config: &ServerConfig) -> Result<()> {
    if let Some(address) = &config.interface.address {
        run("ip", ["address", "replace", address, "dev", tun.name()]).await?;
        run("ip", ["link", "set", "dev", tun.name(), "up"]).await?;
    }
    Ok(())
}

struct ForwardingGuard {
    previous_ip_forward: Option<String>,
}
impl ForwardingGuard {
    async fn install(config: &ForwardingConfig, tunnel: &str) -> Result<Self> {
        if !config.enabled {
            return Ok(Self {
                previous_ip_forward: None,
            });
        }
        let previous = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .context("reading IPv4 forwarding state")?;
        fs::write("/proc/sys/net/ipv4/ip_forward", "1\n").context("enabling IPv4 forwarding")?;
        let external = config
            .external_interface
            .as_deref()
            .expect("validated external interface");
        let cidr = config
            .tunnel_cidr
            .as_deref()
            .expect("validated tunnel CIDR");
        run("nft", ["add", "table", "inet", "rvpn"]).await?;
        run(
            "nft",
            [
                "add", "chain", "inet", "rvpn", "forward", "{", "type", "filter", "hook",
                "forward", "priority", "filter;", "policy", "drop;", "}",
            ],
        )
        .await?;
        run(
            "nft",
            [
                "add", "rule", "inet", "rvpn", "forward", "iifname", tunnel, "oifname", external,
                "accept",
            ],
        )
        .await?;
        run(
            "nft",
            [
                "add",
                "rule",
                "inet",
                "rvpn",
                "forward",
                "iifname",
                external,
                "oifname",
                tunnel,
                "ct",
                "state",
                "established,related",
                "accept",
            ],
        )
        .await?;
        run(
            "nft",
            [
                "add",
                "chain",
                "inet",
                "rvpn",
                "postrouting",
                "{",
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "srcnat;",
                "}",
            ],
        )
        .await?;
        run(
            "nft",
            [
                "add",
                "rule",
                "inet",
                "rvpn",
                "postrouting",
                "ip",
                "saddr",
                cidr,
                "oifname",
                external,
                "masquerade",
            ],
        )
        .await?;
        tracing::info!(%tunnel, %external, %cidr, "enabled IPv4 forwarding and RVPN NAT");
        Ok(Self {
            previous_ip_forward: Some(previous),
        })
    }
    async fn cleanup(&self) {
        if let Some(previous) = &self.previous_ip_forward {
            let _ = run("nft", ["delete", "table", "inet", "rvpn"]).await;
            let _ = fs::write("/proc/sys/net/ipv4/ip_forward", previous);
        }
    }
}

async fn run<'a>(program: &str, args: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .context("running network command")?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "{} failed: {}",
            program,
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}
async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        tokio::select! { result = tokio::signal::ctrl_c() => result.context("waiting for SIGINT"), result = async { tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?.recv().await; Ok::<(), std::io::Error>(()) } => result.context("waiting for SIGTERM") }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("waiting for shutdown signal")
    }
}
