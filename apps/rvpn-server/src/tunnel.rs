use anyhow::Result;
use rvpn_config::{CertificateAuthorityConfig, PeerIdentity, ServerConfig};
use rvpn_core::SessionId;
use rvpn_crypto::ObfuscationKey;
use rvpn_interface::{InterfaceError, VirtualInterface};
use rvpn_protocol::{HandshakeMessage, Packet, PacketKind};
use rvpn_routing::{
    DropReason, Links, Router, Verdict,
    packet::{ethernet_payload_ip, packet_destination, packet_source, prepare_forward},
};
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
use crate::state::{ActivePeer, PendingHandshake, close_all};

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
    time_limit: Option<Duration>,
) {
    if let Err(error) =
        maybe_send_rekey(transport, obfuscation, peer, packet_limit, time_limit).await
    {
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

/// Registers every active session the router does not know about yet.
///
/// Rekeys reuse the session id, so an already-registered session is left
/// alone; re-registering would throw away the MAC addresses it has learned.
fn register_new_peers(router: &mut Router, active: &HashMap<SessionId, ActivePeer>) {
    for (id, peer) in active {
        if !router.contains(*id) {
            router.register(
                *id,
                peer.identity.name.clone(),
                peer.identity.allowed_ips.clone(),
            );
            tracing::debug!(peer = %peer.identity.name, session_id = ?id, "registered peer with router");
        }
    }
}

/// A peer with no `allowed_ips` (the legacy single-PSK setup) owns no prefix
/// in the router, so it receives every packet the router cannot place.
fn catch_all_peer(active: &HashMap<SessionId, ActivePeer>) -> Option<SessionId> {
    active
        .iter()
        .find(|(_, peer)| peer.identity.allowed_ips.is_empty())
        .map(|(id, _)| *id)
}

fn log_drop(peer: &str, kind: PacketKind, payload: &[u8], reason: DropReason) {
    match reason {
        DropReason::SourceNotAllowed => {
            let source = if kind == PacketKind::DataTap {
                ethernet_payload_ip(payload, false)
            } else {
                packet_source(payload)
            };
            tracing::warn!(%peer, ?source, "discarding packet with unauthorized source address");
        }
        DropReason::MacConflict | DropReason::InvalidSourceMac | DropReason::TooManyMacs => {
            tracing::warn!(%peer, reason = reason.as_str(), "discarding suspicious Ethernet frame");
        }
        _ => tracing::debug!(%peer, reason = reason.as_str(), "dropping packet"),
    }
}

/// Everything needed to put a decrypted packet on the wire or a local device.
struct DataPlane<'a> {
    transport: &'a UdpTransport,
    obfuscation: Option<&'a ObfuscationKey>,
    outbound: &'a OutboundQueue,
    tun: Option<&'a VirtualInterface>,
    tap: Option<&'a VirtualInterface>,
    rekey_packet_limit: u64,
    rekey_time_limit: Option<Duration>,
}

impl DataPlane<'_> {
    async fn send_to(
        &self,
        active: &mut HashMap<SessionId, ActivePeer>,
        session_id: SessionId,
        kind: PacketKind,
        payload: &[u8],
    ) {
        let Some(peer) = active.get_mut(&session_id) else {
            tracing::debug!(
                ?session_id,
                "routing target is no longer active; dropping packet"
            );
            return;
        };
        maybe_rekey(
            self.transport,
            self.obfuscation,
            peer,
            self.rekey_packet_limit,
            self.rekey_time_limit,
        )
        .await;
        seal_and_queue(
            peer,
            kind,
            payload,
            self.obfuscation,
            self.outbound,
            self.transport,
        );
    }

    async fn inject_ip(&self, packet: &[u8], peer: &str) {
        match self.tun {
            Some(device) => inject(device, packet, peer).await,
            None => {
                tracing::debug!(%peer, "no TUN device; dropping IP packet addressed to the server")
            }
        }
    }

    async fn inject_frame(&self, frame: &[u8], peer: &str) {
        if let Some(device) = self.tap.or(self.tun) {
            inject(device, frame, peer).await;
        }
    }
}

/// Routes one authenticated, decrypted packet from `session_id`: to other
/// peers this peer is linked with, to the server's own device, or nowhere.
async fn route_inbound(
    plane: &DataPlane<'_>,
    router: &mut Router,
    active: &mut HashMap<SessionId, ActivePeer>,
    session_id: SessionId,
    kind: PacketKind,
    payload: &[u8],
) {
    let verdict = if kind == PacketKind::DataTap {
        router.route_frame(session_id, payload)
    } else {
        router.route_ip(session_id, payload)
    };
    let peer_name = router.name(session_id).unwrap_or("unknown");

    let delivery = match verdict {
        Verdict::Forward(delivery) => delivery,
        Verdict::Drop(reason) => {
            log_drop(peer_name, kind, payload, reason);
            return;
        }
    };

    for target in delivery.peers {
        if kind == PacketKind::DataTap {
            plane
                .send_to(active, target, PacketKind::DataTap, payload)
                .await;
        } else {
            // Layer 3 forwarding: this hop consumes one TTL / hop limit.
            let Some(forwarded) = prepare_forward(payload) else {
                tracing::debug!(peer = %peer_name, "TTL expired while forwarding peer-to-peer; dropping");
                continue;
            };
            plane
                .send_to(active, target, PacketKind::Data, &forwarded)
                .await;
        }
    }

    if delivery.local {
        if kind == PacketKind::DataTap {
            plane.inject_frame(payload, peer_name).await;
        } else {
            plane.inject_ip(payload, peer_name).await;
        }
    }
}

pub async fn run_server_loop(
    transport: UdpTransport,
    config: ServerConfig,
    identities: Vec<PeerIdentity>,
    certificate_authority: Option<CertificateAuthorityConfig>,
    obfuscation: Option<ObfuscationKey>,
    cookie_key: rvpn_crypto::CookieKey,
    tun: Option<VirtualInterface>,
    tap: Option<VirtualInterface>,
    mut forwarding: ForwardingGuard,
    mut shutdown_signal: impl std::future::Future<Output = Result<()>> + Unpin,
) -> Result<()> {
    let obfuscation = obfuscation.as_ref();
    let mut active: HashMap<SessionId, ActivePeer> = HashMap::new();
    let mut pending: HashMap<SessionId, PendingHandshake> = HashMap::new();
    let mut router = Router::new(Links::from_groups(
        config.links.iter().map(|link| link.between.as_slice()),
    ));
    if config.links.is_empty() {
        tracing::info!("no [[links]] configured; peers cannot reach each other");
    } else {
        tracing::info!(groups = config.links.len(), "peer-to-peer links loaded");
    }
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
        let plane = DataPlane {
            transport: &transport,
            obfuscation,
            outbound: &outbound,
            tun: tun.as_ref(),
            tap: tap.as_ref(),
            rekey_packet_limit: config.rekey.packet_limit,
            rekey_time_limit: config.rekey.time_limit(),
        };

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
                            router.unregister(id);
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
                    match router.route_from_local_ip(&outbound_pkt).or_else(|| catch_all_peer(&active)) {
                        Some(target) => {
                            plane.send_to(&mut active, target, PacketKind::Data, &outbound_pkt).await;
                        }
                        None => {
                            tracing::debug!(destination = ?packet_destination(&outbound_pkt), "no RVPN peer owns outbound TUN destination");
                        }
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
                    for target in router.route_from_local_frame(&outbound_frame) {
                        plane.send_to(&mut active, target, PacketKind::DataTap, &outbound_frame).await;
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
                                router.unregister(evicted);
                            }
                            register_new_peers(&mut router, &active);
                        }
                        PacketKind::Rekey => {
                            if let Some(current) = active.get(&packet.header.session_id) {
                                if datagram.peer != current.endpoint {
                                    tracing::warn!(
                                        peer = %current.identity.name,
                                        current_endpoint = %current.endpoint,
                                        unauthenticated_endpoint = %datagram.peer,
                                        "ignoring rekey initiation from unauthenticated endpoint"
                                    );
                                    continue;
                                }
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
                                    if packet_kind == PacketKind::Close {
                                        let name = peer.identity.name.clone();
                                        active.remove(&session_id);
                                        router.unregister(session_id);
                                        tracing::info!(%name, "peer closed session");
                                        continue;
                                    }
                                    // Legacy empty-Data keepalives from an older packet format.
                                    if packet_kind == PacketKind::Data && plaintext.is_empty() {
                                        continue;
                                    }
                                    // The packet authenticated, so this is a valid roam.
                                    if peer.endpoint != datagram.peer {
                                        tracing::info!(peer = %peer.identity.name, old = %peer.endpoint, new = %datagram.peer, "authenticated peer roamed");
                                        peer.endpoint = datagram.peer;
                                    }
                                    route_inbound(&plane, &mut router, &mut active, session_id, packet_kind, &plaintext).await;
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
