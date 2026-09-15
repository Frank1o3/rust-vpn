use anyhow::Result;
use rvpn_config::{CertificateAuthorityConfig, DeviceMode, PeerIdentity, ServerConfig};
use rvpn_core::SessionId;
use rvpn_crypto::ObfuscationKey;
use rvpn_interface::VirtualInterface;
use rvpn_protocol::{HandshakeMessage, Packet, PacketKind};
use rvpn_transport::{OutboundQueue, SendOptions, TransportError, UdpTransport};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::time::{Instant, sleep};

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

fn wrap(encoded: bytes::Bytes, obfuscation: Option<&ObfuscationKey>) -> Result<bytes::Bytes> {
    Ok(match obfuscation {
        Some(key) => key.wrap(&encoded)?,
        None => encoded,
    })
}

/// Send `wire` bytes to `peer`, reporting oversized-datagram path failures to
/// the adaptive MTU so the effective MTU is reduced appropriately.
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
    forwarding: ForwardingGuard,
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
    // Sealed TUN/TAP datagrams for any active peer are queued here instead
    // of being sent inline, decoupling a slow/congested send to one peer
    // from servicing handshakes, rekeys, and other peers' traffic in the
    // same select! iteration. Shared across peers since sealing (which
    // needs &mut peer.session) still happens synchronously per-peer below.
    let (outbound, mut outbound_rx) = OutboundQueue::new(1024);

    loop {
        tokio::select! {
            signal = &mut shutdown_signal => {
                signal?;
                close_all(&transport, &mut active, obfuscation).await;
                forwarding.cleanup().await;
                return Ok(());
            }
            () = &mut retry_sleep => {
                retransmit_pending(&transport, obfuscation, &mut pending, &config.handshake).await?;
                retry_sleep.as_mut().reset(Instant::now() + rvpn_config::jittered_retry_interval(
                    config.handshake.retry_interval_ms,
                    config.handshake.retry_jitter_ms,
                ));
            }
            // Keepalive: send a sealed empty Keepalive packet to every active
            // peer to keep NAT mappings alive and let the client detect
            // liveness.
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
            // Drains sealed datagrams queued by the TUN/TAP outbound arms below.
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
                let outbound_pkt = outbound_tun?;
                let Some(destination) = packet_destination(&outbound_pkt) else { continue; };
                if let Some((_, peer)) = active.iter_mut().find(|(_, peer)| ip_in_prefixes(&peer.identity.allowed_ips, destination)) {
                    maybe_send_rekey(&transport, obfuscation, peer, config.rekey.packet_limit).await?;
                    let packet = peer.session.seal(PacketKind::Data, &outbound_pkt)?;
                    let wire = wrap(packet.encode(), obfuscation)?;
                    if let Err(e) = outbound.try_enqueue(peer.endpoint, wire) {
                        transport.record_dropped_backpressure();
                        tracing::debug!(peer = %peer.identity.name, %e, "outbound queue full; dropping TUN packet");
                    }
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
                let outbound_frame = outbound_tap?;
                if outbound_frame.len() < 14 { continue; }
                let dst_mac: [u8; 6] = outbound_frame[0..6].try_into().unwrap();
                if is_broadcast_or_multicast_mac(&dst_mac) {
                    for peer in active.values_mut() {
                        maybe_send_rekey(&transport, obfuscation, peer, config.rekey.packet_limit).await?;
                        if let Ok(packet) = peer.session.seal(PacketKind::DataTap, &outbound_frame) {
                            if let Ok(wire) = wrap(packet.encode(), obfuscation) {
                                if let Err(e) = outbound.try_enqueue(peer.endpoint, wire) {
                                    transport.record_dropped_backpressure();
                                    tracing::debug!(peer = %peer.identity.name, %e, "outbound queue full; dropping broadcast TAP frame");
                                }
                            }
                        }
                    }
                } else if let Some(target_session) = mac_table.get(&dst_mac) {
                    if let Some(peer) = active.get_mut(target_session) {
                        maybe_send_rekey(&transport, obfuscation, peer, config.rekey.packet_limit).await?;
                        let packet = peer.session.seal(PacketKind::DataTap, &outbound_frame)?;
                        let wire = wrap(packet.encode(), obfuscation)?;
                        if let Err(e) = outbound.try_enqueue(peer.endpoint, wire) {
                            transport.record_dropped_backpressure();
                            tracing::debug!(peer = %peer.identity.name, %e, "outbound queue full; dropping TAP frame");
                        }
                    }
                } else {
                    let dest_ip = ethernet_payload_ip(&outbound_frame, true);
                    let mut sent = false;
                    if let Some(destination) = dest_ip {
                        if let Some((_, peer)) = active.iter_mut().find(|(_, peer)| ip_in_prefixes(&peer.identity.allowed_ips, destination)) {
                            maybe_send_rekey(&transport, obfuscation, peer, config.rekey.packet_limit).await?;
                            let packet = peer.session.seal(PacketKind::DataTap, &outbound_frame)?;
                            let wire = wrap(packet.encode(), obfuscation)?;
                            if let Err(e) = outbound.try_enqueue(peer.endpoint, wire) {
                                transport.record_dropped_backpressure();
                                tracing::debug!(peer = %peer.identity.name, %e, "outbound queue full; dropping TAP frame via IP lookup");
                            } else {
                                sent = true;
                            }
                        }
                    }
                    if !sent {
                        for peer in active.values_mut() {
                            if let Ok(packet) = peer.session.seal(PacketKind::DataTap, &outbound_frame) {
                                if let Ok(wire) = wrap(packet.encode(), obfuscation) {
                                    if let Err(e) = outbound.try_enqueue(peer.endpoint, wire) {
                                        transport.record_dropped_backpressure();
                                        tracing::debug!(peer = %peer.identity.name, %e, "outbound queue full; dropping flooded TAP frame");
                                    }
                                }
                            }
                        }
                    }
                }
            }

            datagram = transport.receive() => {
                let datagram = datagram?;
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
                            if challenge_or_admit(&transport, &cookie_key, obfuscation, datagram.peer, &initiation).await? {
                                begin_initial(&transport, &identities, certificate_authority.as_ref(), obfuscation, &mut pending, datagram.peer, initiation).await?;
                            }
                        }
                    }
                    PacketKind::Handshake | PacketKind::Rekey if packet.header.sequence == 1 => {
                        finish_pending(&mut pending, &mut active, datagram.peer, packet)?;
                    }
                    PacketKind::Rekey => {
                        if let Some(current) = active.get(&packet.header.session_id) {
                            if current.session.key_phase() == packet.header.key_phase {
                                if let Ok(initiation @ HandshakeMessage::Initiation { .. }) = HandshakeMessage::decode(packet.payload.clone()) {
                                    begin_rekey(&transport, obfuscation, &mut pending, datagram.peer, current, initiation).await?;
                                }
                            }
                        }
                    }
                    PacketKind::Keepalive => {
                        if let Some(peer) = active.get_mut(&packet.header.session_id) {
                            // Authenticates the sender and advances the
                            // replay window; nothing more to do.
                            let _ = peer.session.open(packet);
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
                                    if !ip_in_prefixes(&peer.identity.allowed_ips, source) {
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
                                // Discard any legacy empty-Data keepalives from
                                // clients still on an older packet format.
                                if plaintext.is_empty() {
                                    continue;
                                }
                                if mode == DeviceMode::Tap && tap.is_some() && tun.is_none() {
                                    if let Some(t) = &tap {
                                        t.send(&plaintext).await?;
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
