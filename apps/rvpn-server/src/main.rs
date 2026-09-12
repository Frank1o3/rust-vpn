use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use rvpn_config::{ForwardingConfig, HandshakeConfig, PeerIdentity, ServerConfig};
use rvpn_core::SessionId;
use rvpn_crypto::{AEAD_TAG_LEN, HandshakePsk};
use rvpn_interface::{DEFAULT_MTU, TunConfig, TunDevice};
use rvpn_protocol::{
    HEADER_LEN, HandshakeMessage, Header, Packet, PacketKind, ProtectedSession, ResponderHandshake,
};
use rvpn_transport::{SendOptions, TransportConfig, UdpTransport};
use std::{
    collections::HashMap,
    env, fs,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    process::Command,
    time::{MissedTickBehavior, interval},
};

struct ActivePeer {
    identity: PeerIdentity,
    session: ProtectedSession,
    endpoint: SocketAddr,
}
struct PendingHandshake {
    identity: PeerIdentity,
    handshake: ResponderHandshake,
    endpoint: SocketAddr,
    packet: Packet,
    kind: PacketKind,
    attempts: u32,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let path = env::args()
        .nth(1)
        .context("usage: rvpn-server <server.toml>")?;
    let config = ServerConfig::from_toml(&fs::read_to_string(path)?)?;
    let identities = config.peer_identities()?;
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
    let tun = TunDevice::create(tun_config).await?;
    configure_server_interface(&tun, &config).await?;
    let forwarding = ForwardingGuard::install(&config.forwarding, tun.name()).await?;
    let mut active: HashMap<SessionId, ActivePeer> = HashMap::new();
    let mut pending: HashMap<SessionId, PendingHandshake> = HashMap::new();
    let mut retry_tick = interval(Duration::from_millis(config.handshake.retry_interval_ms));
    retry_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tracing::info!(bind = %transport.local_addr()?, peers = identities.len(), interface = %tun.name(), "RVPN multi-client server started");
    loop {
        tokio::select! {
            signal = shutdown_signal() => { signal?; close_all(&transport, &mut active).await; forwarding.cleanup().await; return Ok(()); }
            _ = retry_tick.tick() => { retransmit_pending(&transport, &mut pending, &config.handshake).await?; }
            outbound = tun.recv() => {
                let outbound = outbound?;
                let Some(destination) = packet_destination(&outbound) else { continue; };
                if let Some((_, peer)) = active.iter_mut().find(|(_, peer)| routes_to(&peer.identity.allowed_ips, destination)) {
                    if config.rekey.packet_limit != 0 && peer.session.should_rekey(config.rekey.packet_limit) {
                        let request = peer.session.seal(PacketKind::Rekey, b"")?;
                        transport.send_to(peer.endpoint, request.encode(), SendOptions::default()).await?;
                    }
                    let packet = peer.session.seal(PacketKind::Data, &outbound)?;
                    transport.send_to(peer.endpoint, packet.encode(), SendOptions::default()).await?;
                } else { tracing::debug!(%destination, "no RVPN peer owns outbound destination"); }
            }
            datagram = transport.receive() => {
                let datagram = datagram?;
                let packet = match Packet::decode(datagram.payload) { Ok(packet) => packet, Err(error) => { tracing::warn!(%error, "discarding malformed RVPN packet"); continue; } };
                match packet.header.kind {
                    PacketKind::Handshake if packet.header.sequence == 0 && packet.header.session_id == SessionId::new([0; 16]) => {
                        if let Ok(initiation @ HandshakeMessage::Initiation { .. }) = HandshakeMessage::decode(packet.payload) {
                            begin_initial(&transport, &identities, &mut pending, datagram.peer, initiation).await?;
                        }
                    }
                    PacketKind::Handshake | PacketKind::Rekey if packet.header.sequence == 1 => {
                        finish_pending(&mut pending, &mut active, datagram.peer, packet)?;
                    }
                    PacketKind::Rekey => {
                        if let Some(current) = active.get(&packet.header.session_id) {
                            if current.session.key_phase() == packet.header.key_phase {
                                if let Ok(initiation @ HandshakeMessage::Initiation { .. }) = HandshakeMessage::decode(packet.payload.clone()) {
                                    begin_rekey(&transport, &mut pending, datagram.peer, current, initiation).await?;
                                }
                            }
                        }
                    }
                    PacketKind::Data | PacketKind::Close => {
                        let Some(peer) = active.get_mut(&packet.header.session_id) else { continue; };
                        let packet_kind = packet.header.kind;
                        let session_id = packet.header.session_id;
                        match peer.session.open(packet) {
                            Ok(plaintext) if packet_kind == PacketKind::Data => {
                                let Some(source) = packet_source(&plaintext) else { continue; };
                                if !permits(&peer.identity.allowed_ips, source) { tracing::warn!(peer = %peer.identity.name, %source, "discarding packet with unauthorized source address"); continue; }
                                if peer.endpoint != datagram.peer { tracing::info!(peer = %peer.identity.name, old = %peer.endpoint, new = %datagram.peer, "authenticated peer roamed"); peer.endpoint = datagram.peer; }
                                tun.send(&plaintext).await?;
                            }
                            Ok(_) if packet_kind == PacketKind::Close => { let name = peer.identity.name.clone(); active.remove(&session_id); tracing::info!(%name, "peer closed session"); }
                            Ok(_) => {}
                            Err(error) => tracing::warn!(%error, "discarding unauthenticated or replayed packet"),
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn begin_initial(
    transport: &UdpTransport,
    identities: &[PeerIdentity],
    pending: &mut HashMap<SessionId, PendingHandshake>,
    endpoint: SocketAddr,
    initiation: HandshakeMessage,
) -> Result<()> {
    // Send one PSK-authenticated response for each provisioned identity. Only
    // the client holding the matching PSK can verify a response and finish it.
    for identity in identities {
        let (handshake, response) = ResponderHandshake::accept(
            HandshakePsk::from_bytes(identity.pre_shared_key),
            initiation,
        )?;
        let session_id = match response {
            HandshakeMessage::Response { session_id, .. } => session_id,
            _ => unreachable!(),
        };
        let packet = Packet {
            header: Header {
                kind: PacketKind::Handshake,
                key_phase: 0,
                sequence: 0,
                session_id,
            },
            payload: response.encode(),
        };
        transport
            .send_to(endpoint, packet.encode(), SendOptions::default())
            .await?;
        pending.insert(
            session_id,
            PendingHandshake {
                identity: identity.clone(),
                handshake,
                endpoint,
                packet,
                kind: PacketKind::Handshake,
                attempts: 1,
            },
        );
    }
    Ok(())
}

async fn begin_rekey(
    transport: &UdpTransport,
    pending: &mut HashMap<SessionId, PendingHandshake>,
    endpoint: SocketAddr,
    current: &ActivePeer,
    initiation: HandshakeMessage,
) -> Result<()> {
    if pending.contains_key(&current.session.session_id()) {
        return Ok(());
    }
    let phase = current
        .session
        .key_phase()
        .checked_add(1)
        .context("key phase exhausted")?;
    let (handshake, response) = ResponderHandshake::accept_for_session(
        HandshakePsk::from_bytes(current.identity.pre_shared_key),
        initiation,
        current.session.session_id(),
        phase,
    )?;
    let packet = Packet {
        header: Header {
            kind: PacketKind::Rekey,
            key_phase: current.session.key_phase(),
            sequence: 0,
            session_id: current.session.session_id(),
        },
        payload: response.encode(),
    };
    transport
        .send_to(endpoint, packet.encode(), SendOptions::default())
        .await?;
    pending.insert(
        current.session.session_id(),
        PendingHandshake {
            identity: current.identity.clone(),
            handshake,
            endpoint,
            packet,
            kind: PacketKind::Rekey,
            attempts: 1,
        },
    );
    Ok(())
}

fn finish_pending(
    pending: &mut HashMap<SessionId, PendingHandshake>,
    active: &mut HashMap<SessionId, ActivePeer>,
    endpoint: SocketAddr,
    packet: Packet,
) -> Result<()> {
    let Some(pending_handshake) = pending.remove(&packet.header.session_id) else {
        return Ok(());
    };
    if pending_handshake.endpoint != endpoint || pending_handshake.kind != packet.header.kind {
        return Ok(());
    }
    let finish = HandshakeMessage::decode(packet.payload)?;
    let session = pending_handshake.handshake.finish(finish)?;
    let id = session.session_id();
    let name = pending_handshake.identity.name.clone();
    active.insert(
        id,
        ActivePeer {
            identity: pending_handshake.identity,
            session,
            endpoint,
        },
    );
    tracing::info!(%name, session_id = ?id, %endpoint, "authenticated RVPN peer established");
    Ok(())
}

async fn retransmit_pending(
    transport: &UdpTransport,
    pending: &mut HashMap<SessionId, PendingHandshake>,
    policy: &HandshakeConfig,
) -> Result<()> {
    pending.retain(|_, state| state.attempts < policy.retry_limit);
    for state in pending.values_mut() {
        transport
            .send_to(
                state.endpoint,
                state.packet.encode(),
                SendOptions::default(),
            )
            .await?;
        state.attempts += 1;
    }
    Ok(())
}

fn permits(prefixes: &[IpNet], address: IpAddr) -> bool {
    prefixes.is_empty() || prefixes.iter().any(|prefix| prefix.contains(&address))
}
fn routes_to(prefixes: &[IpNet], address: IpAddr) -> bool {
    prefixes.is_empty() || prefixes.iter().any(|prefix| prefix.contains(&address))
}
fn packet_source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?)),
        6 if packet.len() >= 40 => Some(IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?)),
        _ => None,
    }
}
fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?)),
        6 if packet.len() >= 40 => Some(IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?)),
        _ => None,
    }
}
async fn close_all(transport: &UdpTransport, active: &mut HashMap<SessionId, ActivePeer>) {
    for peer in active.values_mut() {
        if let Ok(close) = peer.session.seal(PacketKind::Close, b"") {
            let _ = transport
                .send_to(peer.endpoint, close.encode(), SendOptions::default())
                .await;
        }
    }
}

async fn configure_server_interface(tun: &TunDevice, config: &ServerConfig) -> Result<()> {
    if config.interface.address.is_some() || !config.interface.addresses.is_empty() {
        for address in config
            .interface
            .address
            .iter()
            .chain(&config.interface.addresses)
        {
            run("ip", ["address", "replace", address, "dev", tun.name()]).await?;
        }
        run("ip", ["link", "set", "dev", tun.name(), "up"]).await?;
    }
    Ok(())
}
struct ForwardingGuard {
    previous_ipv4_forward: Option<String>,
    previous_ipv6_forward: Option<String>,
}
impl ForwardingGuard {
    async fn install(config: &ForwardingConfig, tunnel: &str) -> Result<Self> {
        if !config.enabled {
            return Ok(Self {
                previous_ipv4_forward: None,
                previous_ipv6_forward: None,
            });
        }
        let previous_ipv4_forward = if config.tunnel_cidr.is_some() {
            let previous = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
                .context("reading IPv4 forwarding state")?;
            fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")
                .context("enabling IPv4 forwarding")?;
            Some(previous)
        } else {
            None
        };
        let previous_ipv6_forward = if config.tunnel_cidr_v6.is_some() {
            let previous = fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
                .context("reading IPv6 forwarding state")?;
            fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1\n")
                .context("enabling IPv6 forwarding")?;
            Some(previous)
        } else {
            None
        };
        let external = config.external_interface.as_deref().expect("validated");
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
        if let Some(cidr) = &config.tunnel_cidr {
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
        }
        if let Some(cidr) = &config.tunnel_cidr_v6 {
            run(
                "nft",
                [
                    "add",
                    "rule",
                    "inet",
                    "rvpn",
                    "postrouting",
                    "ip6",
                    "saddr",
                    cidr,
                    "oifname",
                    external,
                    "masquerade",
                ],
            )
            .await?;
        }
        Ok(Self {
            previous_ipv4_forward,
            previous_ipv6_forward,
        })
    }
    async fn cleanup(&self) {
        if self.previous_ipv4_forward.is_some() || self.previous_ipv6_forward.is_some() {
            let _ = run("nft", ["delete", "table", "inet", "rvpn"]).await;
        }
        if let Some(previous) = &self.previous_ipv4_forward {
            let _ = fs::write("/proc/sys/net/ipv4/ip_forward", previous);
        }
        if let Some(previous) = &self.previous_ipv6_forward {
            let _ = fs::write("/proc/sys/net/ipv6/conf/all/forwarding", previous);
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
