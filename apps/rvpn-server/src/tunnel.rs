//! Multi-client server event pump connecting TUN/TAP virtual interfaces and UDP transport.

use anyhow::Result;
use rvpn_config::{DeviceMode, PeerIdentity, ServerConfig};
use rvpn_core::SessionId;
use rvpn_interface::TunDevice;
use rvpn_protocol::{HandshakeMessage, Packet, PacketKind};
use rvpn_transport::{SendOptions, UdpTransport};
use std::{collections::HashMap, time::Duration};
use tokio::time::{MissedTickBehavior, interval};

use crate::firewall::ForwardingGuard;
use crate::handshake::{begin_initial, begin_rekey, finish_pending, maybe_send_rekey, retransmit_pending};
use crate::network::{
    ethernet_payload_ip, ethernet_src_mac, is_broadcast_or_multicast_mac, packet_destination,
    packet_source,
};
use crate::state::{ActivePeer, PendingHandshake, close_all, ip_in_prefixes};

/// Runs the multi-client server routing and processing loop.
pub async fn run_server_loop(
    transport: UdpTransport,
    config: ServerConfig,
    identities: Vec<PeerIdentity>,
    mode: DeviceMode,
    tun: Option<TunDevice>,
    tap: Option<TunDevice>,
    forwarding: ForwardingGuard,
    mut shutdown_signal: impl std::future::Future<Output = Result<()>> + Unpin,
) -> Result<()> {
    let mut active: HashMap<SessionId, ActivePeer> = HashMap::new();
    let mut pending: HashMap<SessionId, PendingHandshake> = HashMap::new();
    let mut mac_table: HashMap<[u8; 6], SessionId> = HashMap::new();
    let mut retry_tick = interval(Duration::from_millis(config.handshake.retry_interval_ms));
    retry_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            signal = &mut shutdown_signal => {
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
                if let Some((_, peer)) = active.iter_mut().find(|(_, peer)| ip_in_prefixes(&peer.identity.allowed_ips, destination)) {
                    maybe_send_rekey(&transport, peer, config.rekey.packet_limit).await?;
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
                        maybe_send_rekey(&transport, peer, config.rekey.packet_limit).await?;
                        if let Ok(packet) = peer.session.seal(PacketKind::DataTap, &outbound) {
                            let _ = transport.send_to(peer.endpoint, packet.encode(), SendOptions::default()).await;
                        }
                    }
                } else if let Some(target_session) = mac_table.get(&dst_mac) {
                    if let Some(peer) = active.get_mut(target_session) {
                        maybe_send_rekey(&transport, peer, config.rekey.packet_limit).await?;
                        let packet = peer.session.seal(PacketKind::DataTap, &outbound)?;
                        transport.send_to(peer.endpoint, packet.encode(), SendOptions::default()).await?;
                    }
                } else {
                    let dest_ip = ethernet_payload_ip(&outbound, true);
                    let mut sent = false;
                    if let Some(destination) = dest_ip {
                        if let Some((_, peer)) = active.iter_mut().find(|(_, peer)| ip_in_prefixes(&peer.identity.allowed_ips, destination)) {
                            maybe_send_rekey(&transport, peer, config.rekey.packet_limit).await?;
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
                    PacketKind::Handshake if packet.header.sequence == 0 && packet.header.session_id == SessionId::ZERO => {
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
