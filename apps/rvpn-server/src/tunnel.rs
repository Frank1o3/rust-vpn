use anyhow::Result;
use rvpn_config::{CertificateAuthorityConfig, DeviceMode, PeerIdentity, ServerConfig};
use rvpn_core::SessionId;
use rvpn_crypto::ObfuscationKey;
use rvpn_interface::{InterfaceError, VirtualInterface};
use rvpn_protocol::{HandshakeMessage, Packet, PacketKind};
use rvpn_transport::{OutboundQueue, SendOptions, TransportError, UdpTransport};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::{Instant, interval, sleep};

use crate::firewall::ForwardingGuard;
use crate::handshake::{
    begin_initial, begin_rekey, challenge_or_admit, finish_pending, maybe_send_rekey,
    retransmit_pending,
};
use crate::network::{
    ethernet_payload_ip, ethernet_src_mac, is_broadcast_or_multicast_mac, packet_destination,
    packet_source,
};
use crate::state::{ActivePeer, PendingHandshake, close_all, ip_in_prefixes};

const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 50;

fn wrap(encoded: bytes::Bytes, obfuscation: Option<&ObfuscationKey>) -> Result<bytes::Bytes> {
    Ok(match obfuscation {
        Some(key) => key.wrap(&encoded)?,
        None => encoded,
    })
}

async fn send_wire(
    transport: &UdpTransport,
    peer: SocketAddr,
    wire: bytes::Bytes,
) -> Result<usize, TransportError> {
    match transport.send_to(peer, wire, SendOptions::default()).await {
        Ok(n) => Ok(n),
        Err(e @ TransportError::PathMtuExceeded { .. }) => {
            transport.report_path_failure();
            Err(e)
        }
        Err(e) => Err(e),
    }
}

fn seal_and_queue(
    peer: &mut ActivePeer,
    kind: PacketKind,
    plaintext: &[u8],
    obfuscation: Option<&ObfuscationKey>,
    outbound: &OutboundQueue,
    transport: &UdpTransport,
) {
    let packet = match peer.session.seal(kind, plaintext) {
        Ok(packet) => packet,
        Err(error) => {
            tracing::warn!(peer = %peer.identity.name, %error, "failed to seal packet; dropping it");
            return;
        }
    };
    let wire = match wrap(packet.encode(), obfuscation) {
        Ok(wire) => wire,
        Err(error) => {
            tracing::warn!(peer = %peer.identity.name, %error, "failed to obfuscate packet; dropping it");
            return;
        }
    };
    if let Err(error) = outbound.try_enqueue(peer.endpoint, wire) {
        transport.record_dropped_backpressure();
        tracing::debug!(peer = %peer.identity.name, %error, "outbound queue full; dropping packet");
    }
}

async fn maybe_rekey(
    transport: &UdpTransport,
    obfuscation: Option<&ObfuscationKey>,
    peer: &mut ActivePeer,
    packet_limit: u64,
) {
    if let Err(error) = maybe_send_rekey(transport, obfuscation, peer, packet_limit).await {
        tracing::warn!(peer = %peer.identity.name, %error, "could not send rekey request");
    }
}

async fn inject(device: &VirtualInterface, frame: &[u8], peer: &str) {
    if let Err(error) = device.send(frame).await {
        match error {
            InterfaceError::PacketTooLarge { .. }
            | InterfaceError::InvalidIpPacket
            | InterfaceError::InvalidEthernetFrame => {
                tracing::debug!(%peer, %error, "dropping packet the local interface rejected");
            }
            other => tracing::warn!(%peer, error = %other, "failed to write packet to interface"),
        }
    }
}

pub async fn run_server_loop(
    transport: UdpTransport,
    config: ServerConfig,
    identities: Vec<PeerIdentity>,
    certificate_authority: Option<CertificateAuthorityConfig>,
    obfuscation: Option<ObfuscationKey>,
    mode: DeviceMode,
    cookie_key: rvpn_crypto::CookieKey,
    tun: Option<VirtualInterface>,
    tap: Option<VirtualInterface>,
    mut forwarding: ForwardingGuard,
    mut shutdown_signal: impl std::future::Future<Output = Result<()>> + Unpin,
) -> Result<()> {
    let obfuscation = obfuscation.as_ref();
    let mut active: HashMap<SessionId, ActivePeer> = HashMap::new();
    let mut pending: HashMap<SessionId, PendingHandshake> = HashMap::new();
    let mut mac_table: HashMap<[u8; 6], SessionId> = HashMap::new();
    let mut retry_sleep = Box::pin(sleep(rvpn_config::jittered_retry_interval(
        config.handshake.retry_interval_ms,
        config.handshake.retry_jitter_ms,
    )));
    let keepalive = transport.keepalive();
    let (outbound, mut outbound_rx) = OutboundQueue::new(1024);
    let mut sweep = interval(Duration::from_secs(10));
    let idle_timeout = config.liveness.timeout();
    let mut recv_errors = 0u32;

    let result: Result<()> = async {
        loop {
            tokio::select! {
                signal = &mut shutdown_signal => {
                    if let Err(error) = signal {
                        return Err(error);
                    }
                    return Ok::<(), anyhow::Error>(());
                }
                () = &mut retry_sleep => {
                    if let Err(error) = retransmit_pending(&transport, obfuscation, &mut pending, &config.handshake).await {
                        tracing::warn!(%error, "handshake retransmission failed");
                    }
                    retry_sleep.as_mut().reset(Instant::now() + rvpn_config::jittered_retry_interval(
                        config.handshake.retry_interval_ms,
                        config.handshake.retry_jitter_ms,
                    ));
                }
                _ = sweep.tick() => {
                    if let Some(timeout) = idle_timeout {
                        let stale: Vec<SessionId> = active
                            .iter()
                            .filter(|(_, peer)| peer.last_rx.elapsed() > timeout)
                            .map(|(id, _)| *id)
                            .collect();
                        for id in stale {
                            if let Some(peer) = active.remove(&id) {
                                tracing::info!(peer = %peer.identity.name, session_id = ?id, idle_secs = timeout.as_secs(), "peer timed out; dropping session");
                            }
                            mac_table.retain(|_, session| *session != id);
                        }
                    }
                }
                () = keepalive.wait_for_due() => {
                    for peer in active.values_mut() {
                        match peer.session.seal(PacketKind::Keepalive, b"") {
                            Ok(sealed) => {
                                match wrap(sealed.encode(), obfuscation) {
                                    Ok(wire) => {
                                        if let Err(e) = send_wire(&transport, peer.endpoint, wire).await {
                                            tracing::debug!(peer = %peer.identity.name, %e, "keepalive send failed");
                                        }
                                    }
                                    Err(e) => tracing::debug!(peer = %peer.identity.name, %e, "keepalive wrap failed"),
                                }
                            }
                            Err(e) => tracing::debug!(peer = %peer.identity.name, %e, "keepalive seal failed"),
                        }
                    }
                    keepalive.record_keepalive_sent();
                }
                queued = outbound_rx.recv() => {
                    if let Some(datagram) = queued {
                        if let Err(e) = send_wire(&transport, datagram.peer, datagram.payload).await {
                            tracing::debug!(%e, "queued datagram send failed");
                        }
                    }
                }
                outbound_tun = async {
                    if let Some(t) = &tun {
                        t.recv().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    let outbound_pkt = match outbound_tun {
                        Ok(packet) => packet,
                        Err(InterfaceError::Io(error)) => return Err(anyhow::Error::from(error)),
                        Err(error) => {
                            tracing::debug!(%error, "ignoring invalid packet read from TUN");
                            continue;
                        }
                    };
                    let Some(destination) = packet_destination(&outbound_pkt) else { continue; };
                    if let Some((_, peer)) = active.iter_mut().find(|(_, peer)| ip_in_prefixes(&peer.identity.allowed_ips, destination)) {
                        maybe_rekey(&transport, obfuscation, peer, config.rekey.packet_limit).await;
                        seal_and_queue(peer, PacketKind::Data, &outbound_pkt, obfuscation, &outbound, &transport);
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
                    let outbound_frame = match outbound_tap {
                        Ok(frame) => frame,
                        Err(InterfaceError::Io(error)) => return Err(anyhow::Error::from(error)),
                        Err(error) => {
                            tracing::debug!(%error, "ignoring invalid frame read from TAP");
                            continue;
                        }
                    };
                    if outbound_frame.len() < 14 { continue; }
                    let dst_mac: [u8; 6] = outbound_frame[0..6].try_into().unwrap();
                    if is_broadcast_or_multicast_mac(&dst_mac) {
                        for peer in active.values_mut() {
                            maybe_rekey(&transport, obfuscation, peer, config.rekey.packet_limit).await;
                            seal_and_queue(peer, PacketKind::DataTap, &outbound_frame, obfuscation, &outbound, &transport);
                        }
                    } else if let Some(target_session) = mac_table.get(&dst_mac) {
                        if let Some(peer) = active.get_mut(target_session) {
                            maybe_rekey(&transport, obfuscation, peer, config.rekey.packet_limit).await;
                            seal_and_queue(peer, PacketKind::DataTap, &outbound_frame, obfuscation, &outbound, &transport);
                        }
                    } else {
                        let dest_ip = ethernet_payload_ip(&outbound_frame, true);
                        let mut sent = false;
                        if let Some(destination) = dest_ip {
                            if let Some((_, peer)) = active.iter_mut().find(|(_, peer)| ip_in_prefixes(&peer.identity.allowed_ips, destination)) {
                                maybe_rekey(&transport, obfuscation, peer, config.rekey.packet_limit).await;
                                seal_and_queue(peer, PacketKind::DataTap, &outbound_frame, obfuscation, &outbound, &transport);
                                sent = true;
                            }
                        }
                        if !sent {
                            for peer in active.values_mut() {
                                seal_and_queue(peer, PacketKind::DataTap, &outbound_frame, obfuscation, &outbound, &transport);
                            }
                        }
                    }
                }

                datagram = transport.receive() => {
                    let datagram = match datagram {
                        Ok(datagram) => {
                            recv_errors = 0;
                            datagram
                        }
                        Err(error) => {
                            recv_errors += 1;
                            if recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                                return Err(anyhow::Error::from(error));
                            }
                            tracing::warn!(%error, recv_errors, "UDP receive failed; retrying");
                            sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };
                    let payload = match obfuscation {
                        Some(key) => match key.unwrap(&datagram.payload) {
                            Ok(payload) => payload,
                            Err(error) => {
                                tracing::warn!(%error, "discarding malformed obfuscated datagram");
                                continue;
                            }
                        },
                        None => datagram.payload,
                    };
                    let packet = match Packet::decode(payload) {
                        Ok(packet) => packet,
                        Err(error) => {
                            tracing::warn!(%error, "discarding malformed RVPN packet");
                            continue;
                        }
                    };
                    match packet.header.kind {
                        PacketKind::Handshake if packet.header.sequence == 0 && packet.header.session_id == SessionId::ZERO => {
                            if let Ok(initiation @ HandshakeMessage::Initiation { .. }) = HandshakeMessage::decode(packet.payload) {
                                match challenge_or_admit(&transport, &cookie_key, obfuscation, datagram.peer, &initiation).await {
                                    Ok(true) => {
                                        if let Err(error) = begin_initial(&transport, &identities, certificate_authority.as_ref(), obfuscation, &mut pending, datagram.peer, initiation).await {
                                            tracing::warn!(%error, peer = %datagram.peer, "could not start handshake");
                                        }
                                    }
                                    Ok(false) => {}
                                    Err(error) => tracing::warn!(%error, peer = %datagram.peer, "cookie challenge failed"),
                                }
                            }
                        }
                        PacketKind::Handshake | PacketKind::Rekey if packet.header.sequence == 1 => {
                            for evicted in finish_pending(&mut pending, &mut active, datagram.peer, packet) {
                                mac_table.retain(|_, session| *session != evicted);
                            }
                        }
                        PacketKind::Rekey => {
                            if let Some(current) = active.get(&packet.header.session_id) {
                                if current.session.key_phase() == packet.header.key_phase {
                                    if let Ok(initiation @ HandshakeMessage::Initiation { .. }) = HandshakeMessage::decode(packet.payload.clone()) {
                                        if let Err(error) = begin_rekey(&transport, obfuscation, &mut pending, datagram.peer, current, initiation).await {
                                            tracing::warn!(%error, peer = %current.identity.name, "could not start rekey");
                                        }
                                    }
                                }
                            }
                        }
                        PacketKind::Keepalive => {
                            let session_id = packet.header.session_id;
                            if let Some(peer) = active.get_mut(&session_id) {
                                if peer.session.open(packet).is_ok() {
                                    peer.last_rx = std::time::Instant::now();
                                    if peer.endpoint != datagram.peer {
                                        tracing::info!(peer = %peer.identity.name, old = %peer.endpoint, new = %datagram.peer, "authenticated peer roamed");
                                        peer.endpoint = datagram.peer;
                                    }
                                    seal_and_queue(peer, PacketKind::Keepalive, b"", obfuscation, &outbound, &transport);
                                }
                            }
                        }
                        PacketKind::Data | PacketKind::DataTap | PacketKind::Close => {
                            let session_id = packet.header.session_id;
                            let packet_kind = packet.header.kind;
                            let Some(peer) = active.get_mut(&session_id) else { continue; };
                            match peer.session.open(packet) {
                                Ok(plaintext) => {
                                    peer.last_rx = std::time::Instant::now();
                                    match packet_kind {
                                        PacketKind::DataTap => {
                                            if let Some(source) = ethernet_payload_ip(&plaintext, false) {
                                                if !ip_in_prefixes(&peer.identity.allowed_ips, source) {
                                                    tracing::warn!(peer = %peer.identity.name, %source, "discarding TAP packet with unauthorized source address");
                                                    continue;
                                                }
                                            }
                                            if let Some(src_mac) = ethernet_src_mac(&plaintext) {
                                                mac_table.insert(src_mac, session_id);
                                            }
                                            if peer.endpoint != datagram.peer {
                                                tracing::info!(peer = %peer.identity.name, old = %peer.endpoint, new = %datagram.peer, "authenticated peer roamed");
                                                peer.endpoint = datagram.peer;
                                            }
                                            if let Some(t) = &tap {
                                                inject(t, &plaintext, &peer.identity.name).await;
                                            } else if let Some(t) = &tun {
                                                inject(t, &plaintext, &peer.identity.name).await;
                                            }
                                        }
                                        PacketKind::Data => {
                                            if plaintext.is_empty() {
                                                continue;
                                            }
                                            if mode == DeviceMode::Tap && tap.is_some() && tun.is_none() {
                                                if let Some(t) = &tap {
                                                    inject(t, &plaintext, &peer.identity.name).await;
                                                }
                                            } else {
                                                let Some(source) = packet_source(&plaintext) else { continue; };
                                                if !ip_in_prefixes(&peer.identity.allowed_ips, source) {
                                                    tracing::warn!(peer = %peer.identity.name, %source, "discarding packet with unauthorized source address");
                                                    continue;
                                                }
                                                if peer.endpoint != datagram.peer {
                                                    tracing::info!(peer = %peer.identity.name, old = %peer.endpoint, new = %datagram.peer, "authenticated peer roamed");
                                                    peer.endpoint = datagram.peer;
                                                }
                                                if let Some(t) = &tun {
                                                    inject(t, &plaintext, &peer.identity.name).await;
                                                }
                                            }
                                        }
                                        PacketKind::Close => {
                                            let name = peer.identity.name.clone();
                                            active.remove(&session_id);
                                            mac_table.retain(|_, s_id| *s_id != session_id);
                                            tracing::info!(%name, "peer closed session");
                                        }
                                        _ => {}
                                    }
                                }
                                Err(error) => tracing::warn!(%error, "discarding unauthenticated or replayed packet"),
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    .await;

    close_all(&transport, &mut active, obfuscation).await;
    forwarding.cleanup();
    result
}
