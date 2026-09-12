use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use rvpn_config::{
    DeviceMode, FirewallBackend, ForwardingConfig, HandshakeConfig, PeerIdentity, ServerConfig,
};
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
    let mode = config.interface.mode();
    let mtu = config.interface.mtu.unwrap_or(DEFAULT_MTU);
    let frame_overhead = match mode {
        DeviceMode::Tun => 0,
        DeviceMode::Tap | DeviceMode::Both => 18,
    };
    let transport = UdpTransport::open(TransportConfig {
        local_address: config.bind,
        remote_address: None,
        max_datagram_size: usize::from(mtu) + frame_overhead + HEADER_LEN + AEAD_TAG_LEN,
    })
    .await?;

    let (tun, tap) = match mode {
        DeviceMode::Tun => {
            let dev = TunDevice::create(TunConfig {
                name: config.interface.name.clone(),
                mtu,
                mode: DeviceMode::Tun,
            })
            .await?;
            (Some(dev), None)
        }
        DeviceMode::Tap => {
            let dev = TunDevice::create(TunConfig {
                name: config.interface.name.clone(),
                mtu,
                mode: DeviceMode::Tap,
            })
            .await?;
            (None, Some(dev))
        }
        DeviceMode::Both => {
            let tun_name = config.interface.name.clone();
            let tap_name = config.interface.tap_name.clone().or_else(|| {
                config
                    .interface
                    .name
                    .as_ref()
                    .map(|n| format!("{}-tap", n.chars().take(11).collect::<String>()))
            });
            let tun_dev = TunDevice::create(TunConfig {
                name: tun_name,
                mtu,
                mode: DeviceMode::Tun,
            })
            .await?;
            let tap_dev = TunDevice::create(TunConfig {
                name: tap_name,
                mtu,
                mode: DeviceMode::Tap,
            })
            .await?;
            (Some(tun_dev), Some(tap_dev))
        }
    };

    let primary_dev = tun.as_ref().or(tap.as_ref()).expect("at least one device");
    configure_server_interface(primary_dev, &config).await?;
    let forwarding = ForwardingGuard::install(&config.forwarding, primary_dev.name()).await?;

    let mut active: HashMap<SessionId, ActivePeer> = HashMap::new();
    let mut pending: HashMap<SessionId, PendingHandshake> = HashMap::new();
    let mut mac_table: HashMap<[u8; 6], SessionId> = HashMap::new();
    let mut retry_tick = interval(Duration::from_millis(config.handshake.retry_interval_ms));
    retry_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tracing::info!(
        bind = %transport.local_addr()?,
        peers = identities.len(),
        primary_interface = %primary_dev.name(),
        mode = ?mode,
        "RVPN multi-client server started"
    );
    loop {
        tokio::select! {
            signal = shutdown_signal() => {
                signal?;
                close_all(&transport, &mut active).await;
                forwarding.cleanup().await;
                return Ok(());
            }
            _ = retry_tick.tick() => {
                retransmit_pending(&transport, &mut pending, &config.handshake).await?;
            }
            outbound_tun = async {
                if let Some(t) = &tun {
                    t.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                let outbound = outbound_tun?;
                let Some(destination) = packet_destination(&outbound) else { continue; };
                if let Some((_, peer)) = active.iter_mut().find(|(_, peer)| routes_to(&peer.identity.allowed_ips, destination)) {
                    if config.rekey.packet_limit != 0 && peer.session.should_rekey(config.rekey.packet_limit) {
                        let request = peer.session.seal(PacketKind::Rekey, b"")?;
                        transport.send_to(peer.endpoint, request.encode(), SendOptions::default()).await?;
                    }
                    let packet = peer.session.seal(PacketKind::Data, &outbound)?;
                    transport.send_to(peer.endpoint, packet.encode(), SendOptions::default()).await?;
                } else {
                    tracing::debug!(%destination, "no RVPN peer owns outbound TUN destination");
                }
            }
            outbound_tap = async {
                if let Some(t) = &tap {
                    t.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                let outbound = outbound_tap?;
                if outbound.len() < 14 { continue; }
                let dst_mac: [u8; 6] = outbound[0..6].try_into().unwrap();
                if is_broadcast_or_multicast_mac(&dst_mac) {
                    for peer in active.values_mut() {
                        if config.rekey.packet_limit != 0 && peer.session.should_rekey(config.rekey.packet_limit) {
                            let request = peer.session.seal(PacketKind::Rekey, b"")?;
                            let _ = transport.send_to(peer.endpoint, request.encode(), SendOptions::default()).await;
                        }
                        if let Ok(packet) = peer.session.seal(PacketKind::DataTap, &outbound) {
                            let _ = transport.send_to(peer.endpoint, packet.encode(), SendOptions::default()).await;
                        }
                    }
                } else if let Some(target_session) = mac_table.get(&dst_mac) {
                    if let Some(peer) = active.get_mut(target_session) {
                        if config.rekey.packet_limit != 0 && peer.session.should_rekey(config.rekey.packet_limit) {
                            let request = peer.session.seal(PacketKind::Rekey, b"")?;
                            let _ = transport.send_to(peer.endpoint, request.encode(), SendOptions::default()).await;
                        }
                        let packet = peer.session.seal(PacketKind::DataTap, &outbound)?;
                        transport.send_to(peer.endpoint, packet.encode(), SendOptions::default()).await?;
                    }
                } else {
                    let dest_ip = ethernet_payload_ip(&outbound, true);
                    let mut sent = false;
                    if let Some(destination) = dest_ip {
                        if let Some((_, peer)) = active.iter_mut().find(|(_, peer)| routes_to(&peer.identity.allowed_ips, destination)) {
                            if config.rekey.packet_limit != 0 && peer.session.should_rekey(config.rekey.packet_limit) {
                                let request = peer.session.seal(PacketKind::Rekey, b"")?;
                                let _ = transport.send_to(peer.endpoint, request.encode(), SendOptions::default()).await;
                            }
                            let packet = peer.session.seal(PacketKind::DataTap, &outbound)?;
                            transport.send_to(peer.endpoint, packet.encode(), SendOptions::default()).await?;
                            sent = true;
                        }
                    }
                    if !sent {
                        for peer in active.values_mut() {
                            if let Ok(packet) = peer.session.seal(PacketKind::DataTap, &outbound) {
                                let _ = transport.send_to(peer.endpoint, packet.encode(), SendOptions::default()).await;
                            }
                        }
                    }
                }
            }
            datagram = transport.receive() => {
                let datagram = datagram?;
                let packet = match Packet::decode(datagram.payload) {
                    Ok(packet) => packet,
                    Err(error) => {
                        tracing::warn!(%error, "discarding malformed RVPN packet");
                        continue;
                    }
                };
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
                    PacketKind::Data | PacketKind::DataTap | PacketKind::Close => {
                        let Some(peer) = active.get_mut(&packet.header.session_id) else { continue; };
                        let packet_kind = packet.header.kind;
                        let session_id = packet.header.session_id;
                        match peer.session.open(packet) {
                            Ok(plaintext) if packet_kind == PacketKind::DataTap => {
                                if let Some(src_mac) = ethernet_src_mac(&plaintext) {
                                    mac_table.insert(src_mac, session_id);
                                }
                                if let Some(source) = ethernet_payload_ip(&plaintext, false) {
                                    if !permits(&peer.identity.allowed_ips, source) {
                                        tracing::warn!(peer = %peer.identity.name, %source, "discarding TAP packet with unauthorized source address");
                                        continue;
                                    }
                                }
                                if peer.endpoint != datagram.peer {
                                    tracing::info!(peer = %peer.identity.name, old = %peer.endpoint, new = %datagram.peer, "authenticated peer roamed");
                                    peer.endpoint = datagram.peer;
                                }
                                if let Some(t) = &tap {
                                    t.send(&plaintext).await?;
                                } else if let Some(t) = &tun {
                                    t.send(&plaintext).await?;
                                }
                            }
                            Ok(plaintext) if packet_kind == PacketKind::Data => {
                                if mode == DeviceMode::Tap && tap.is_some() && tun.is_none() {
                                    if let Some(t) = &tap {
                                        t.send(&plaintext).await?;
                                    }
                                } else {
                                    let Some(source) = packet_source(&plaintext) else { continue; };
                                    if !permits(&peer.identity.allowed_ips, source) {
                                        tracing::warn!(peer = %peer.identity.name, %source, "discarding packet with unauthorized source address");
                                        continue;
                                    }
                                    if peer.endpoint != datagram.peer {
                                        tracing::info!(peer = %peer.identity.name, old = %peer.endpoint, new = %datagram.peer, "authenticated peer roamed");
                                        peer.endpoint = datagram.peer;
                                    }
                                    if let Some(t) = &tun {
                                        t.send(&plaintext).await?;
                                    }
                                }
                            }
                            Ok(_) if packet_kind == PacketKind::Close => {
                                let name = peer.identity.name.clone();
                                active.remove(&session_id);
                                mac_table.retain(|_, s_id| *s_id != session_id);
                                tracing::info!(%name, "peer closed session");
                            }
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

fn ethernet_src_mac(frame: &[u8]) -> Option<[u8; 6]> {
    if frame.len() >= 12 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&frame[6..12]);
        Some(mac)
    } else {
        None
    }
}

fn is_broadcast_or_multicast_mac(mac: &[u8; 6]) -> bool {
    mac[0] & 1 == 1
}

fn ethernet_payload_ip(frame: &[u8], is_dest: bool) -> Option<IpAddr> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        0x0800 => {
            let ip_packet = &frame[14..];
            if is_dest {
                packet_destination(ip_packet)
            } else {
                packet_source(ip_packet)
            }
        }
        0x86DD => {
            let ip_packet = &frame[14..];
            if is_dest {
                packet_destination(ip_packet)
            } else {
                packet_source(ip_packet)
            }
        }
        0x0806 => {
            let arp_packet = &frame[14..];
            if arp_packet.len() >= 28 {
                let offset = if is_dest { 24 } else { 14 };
                let ip_bytes: [u8; 4] = arp_packet[offset..offset + 4].try_into().ok()?;
                Some(IpAddr::from(ip_bytes))
            } else {
                None
            }
        }
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

async fn configure_server_interface(dev: &TunDevice, config: &ServerConfig) -> Result<()> {
    if config.interface.address.is_some() || !config.interface.addresses.is_empty() {
        for address in config
            .interface
            .address
            .iter()
            .chain(&config.interface.addresses)
        {
            run("ip", ["address", "replace", address, "dev", dev.name()]).await?;
        }
        run("ip", ["link", "set", "dev", dev.name(), "up"]).await?;
    }
    Ok(())
}

enum FirewallMethod {
    Nftables,
    Iptables {
        rules: Vec<(&'static str, Vec<String>)>,
    },
}

struct ForwardingGuard {
    previous_ipv4_forward: Option<String>,
    previous_ipv6_forward: Option<String>,
    method: Option<FirewallMethod>,
}

impl ForwardingGuard {
    async fn install(config: &ForwardingConfig, tunnel: &str) -> Result<Self> {
        if !config.enabled {
            return Ok(Self {
                previous_ipv4_forward: None,
                previous_ipv6_forward: None,
                method: None,
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
        let use_nft = match config.backend {
            FirewallBackend::Nftables => true,
            FirewallBackend::Iptables => false,
            FirewallBackend::Auto => Command::new("nft")
                .arg("--version")
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false),
        };

        if use_nft {
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
                    "add", "rule", "inet", "rvpn", "forward", "iifname", tunnel, "oifname",
                    external, "accept",
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
            tracing::info!(backend = "nftables", "installed RVPN firewall rules");
            Ok(Self {
                previous_ipv4_forward,
                previous_ipv6_forward,
                method: Some(FirewallMethod::Nftables),
            })
        } else {
            let mut cleanup_rules = Vec::new();
            if config.tunnel_cidr.is_some() {
                run(
                    "iptables",
                    [
                        "-I", "FORWARD", "1", "-i", tunnel, "-o", external, "-j", "ACCEPT",
                    ],
                )
                .await?;
                cleanup_rules.push((
                    "iptables",
                    vec![
                        "-D".into(),
                        "FORWARD".into(),
                        "-i".into(),
                        tunnel.into(),
                        "-o".into(),
                        external.into(),
                        "-j".into(),
                        "ACCEPT".into(),
                    ],
                ));

                run(
                    "iptables",
                    [
                        "-I",
                        "FORWARD",
                        "1",
                        "-i",
                        external,
                        "-o",
                        tunnel,
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "ESTABLISHED,RELATED",
                        "-j",
                        "ACCEPT",
                    ],
                )
                .await?;
                cleanup_rules.push((
                    "iptables",
                    vec![
                        "-D".into(),
                        "FORWARD".into(),
                        "-i".into(),
                        external.into(),
                        "-o".into(),
                        tunnel.into(),
                        "-m".into(),
                        "conntrack".into(),
                        "--ctstate".into(),
                        "ESTABLISHED,RELATED".into(),
                        "-j".into(),
                        "ACCEPT".into(),
                    ],
                ));

                if let Some(cidr) = &config.tunnel_cidr {
                    run(
                        "iptables",
                        [
                            "-t",
                            "nat",
                            "-I",
                            "POSTROUTING",
                            "1",
                            "-s",
                            cidr,
                            "-o",
                            external,
                            "-j",
                            "MASQUERADE",
                        ],
                    )
                    .await?;
                    cleanup_rules.push((
                        "iptables",
                        vec![
                            "-t".into(),
                            "nat".into(),
                            "-D".into(),
                            "POSTROUTING".into(),
                            "-s".into(),
                            cidr.clone(),
                            "-o".into(),
                            external.into(),
                            "-j".into(),
                            "MASQUERADE".into(),
                        ],
                    ));
                }
            }
            if config.tunnel_cidr_v6.is_some() {
                run(
                    "ip6tables",
                    [
                        "-I", "FORWARD", "1", "-i", tunnel, "-o", external, "-j", "ACCEPT",
                    ],
                )
                .await?;
                cleanup_rules.push((
                    "ip6tables",
                    vec![
                        "-D".into(),
                        "FORWARD".into(),
                        "-i".into(),
                        tunnel.into(),
                        "-o".into(),
                        external.into(),
                        "-j".into(),
                        "ACCEPT".into(),
                    ],
                ));

                run(
                    "ip6tables",
                    [
                        "-I",
                        "FORWARD",
                        "1",
                        "-i",
                        external,
                        "-o",
                        tunnel,
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "ESTABLISHED,RELATED",
                        "-j",
                        "ACCEPT",
                    ],
                )
                .await?;
                cleanup_rules.push((
                    "ip6tables",
                    vec![
                        "-D".into(),
                        "FORWARD".into(),
                        "-i".into(),
                        external.into(),
                        "-o".into(),
                        tunnel.into(),
                        "-m".into(),
                        "conntrack".into(),
                        "--ctstate".into(),
                        "ESTABLISHED,RELATED".into(),
                        "-j".into(),
                        "ACCEPT".into(),
                    ],
                ));

                if let Some(cidr) = &config.tunnel_cidr_v6 {
                    run(
                        "ip6tables",
                        [
                            "-t",
                            "nat",
                            "-I",
                            "POSTROUTING",
                            "1",
                            "-s",
                            cidr,
                            "-o",
                            external,
                            "-j",
                            "MASQUERADE",
                        ],
                    )
                    .await?;
                    cleanup_rules.push((
                        "ip6tables",
                        vec![
                            "-t".into(),
                            "nat".into(),
                            "-D".into(),
                            "POSTROUTING".into(),
                            "-s".into(),
                            cidr.clone(),
                            "-o".into(),
                            external.into(),
                            "-j".into(),
                            "MASQUERADE".into(),
                        ],
                    ));
                }
            }
            tracing::info!(backend = "iptables", "installed RVPN firewall rules");
            Ok(Self {
                previous_ipv4_forward,
                previous_ipv6_forward,
                method: Some(FirewallMethod::Iptables {
                    rules: cleanup_rules,
                }),
            })
        }
    }

    async fn cleanup(&self) {
        match &self.method {
            Some(FirewallMethod::Nftables) => {
                let _ = run("nft", ["delete", "table", "inet", "rvpn"]).await;
            }
            Some(FirewallMethod::Iptables { rules }) => {
                for (cmd, args) in rules {
                    let _ = run(cmd, args.iter().map(String::as_str)).await;
                }
            }
            None => {}
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
