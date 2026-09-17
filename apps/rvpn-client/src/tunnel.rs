use anyhow::Result;
use rvpn_config::ClientConfig;
use rvpn_crypto::{AuthConfig, ObfuscationKey};
use rvpn_interface::VirtualInterface;
use rvpn_protocol::{Packet, PacketKind, ProtectedSession};
use rvpn_transport::{OutboundQueue, SendOptions, TransportError, UdpTransport};
use std::net::SocketAddr;
use std::time::Duration;

use rvpn_core::GuiStateHandle;
use crate::handshake::{establish, maybe_rekey};

fn wrap(encoded: bytes::Bytes, obfuscation: Option<&ObfuscationKey>) -> Result<bytes::Bytes> {
    Ok(match obfuscation {
        Some(key) => key.wrap(&encoded)?,
        None => encoded,
    })
}

/// Send `wire` bytes to `peer`, reporting path failures to the adaptive MTU.
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

pub async fn run_data_plane(
    mut session: ProtectedSession,
    transport: &UdpTransport,
    config: &ClientConfig,
    server: SocketAddr,
    auth: &AuthConfig,
    obfuscation: Option<&ObfuscationKey>,
    tun: Option<&VirtualInterface>,
    tap: Option<&VirtualInterface>,
    mut shutdown_signal: impl std::future::Future<Output = Result<()>> + Unpin,
    gui_state: Option<GuiStateHandle>,
) -> Result<()> {
    let keepalive = transport.keepalive();
    let started = std::time::Instant::now();
    let (outbound, mut outbound_rx) = OutboundQueue::new(256);
    let mut telemetry = tokio::time::interval(Duration::from_millis(250));

    loop {
        tokio::select! {
            signal = &mut shutdown_signal => {
                signal?;

                let close = session.seal(PacketKind::Close, b"")?;
                let wire = wrap(close.encode(), obfuscation)?;

                match send_wire(transport, server, wire).await {
                    Ok(bytes) => {
                        tracing::info!(
                            bytes,
                            server = %server,
                            "sent authenticated close packet"
                        );
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            server = %server,
                            "failed to send authenticated close packet"
                        );
                    }
                }

                if let Some(state) = &gui_state {
                    state.lock().unwrap_or_else(|e| e.into_inner()).disconnected();
                }
                return Ok(());
            }
            _ = telemetry.tick() => {
                if let Some(state) = &gui_state {
                    let metrics = transport.metrics_snapshot();
                    let mtu = transport.mtu_snapshot();
                    let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                    state.set_uptime(started.elapsed());
                    if metrics.mtu_changes > state.mtu_changes {
                        state.set_mtu_change_reason(rvpn_transport::MtuChangeReason::PathMtuExceeded);
                    }
                    state.update_transport(metrics, mtu);
                    state.set_key_phase(session.key_phase());
                }
            }
            () = keepalive.wait_for_due() => {
                match session.seal(PacketKind::Keepalive, b"") {
                    Ok(sealed) => {
                        match wrap(sealed.encode(), obfuscation) {
                            Ok(wire) => {
                                if let Err(e) = send_wire(transport, server, wire).await {
                                    tracing::debug!(%e, "keepalive send failed");
                                } else {
                                    keepalive.record_keepalive_sent();
                                    tracing::debug!("sent keepalive to server");
                                }
                            }
                            Err(e) => tracing::debug!(%e, "keepalive wrap failed"),
                        }
                    }
                    Err(e) => tracing::debug!(%e, "keepalive seal failed; session may need rekey"),
                }
            }
            queued = outbound_rx.recv() => {
                if let Some(datagram) = queued {
                    if let Err(e) = send_wire(transport, datagram.peer, datagram.payload).await {
                        tracing::debug!(%e, "queued datagram send failed");
                    }
                }
            }
            packet = async {
                if let Some(dev) = tun {
                    dev.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                let packet = packet?;
                if let Some(state) = &gui_state {
                    state.lock().unwrap_or_else(|e| e.into_inner()).record_tx(packet.len());
                }
                maybe_rekey(&mut session, transport, server, auth, obfuscation, &config.handshake, config.rekey.packet_limit).await?;
                let sealed = session.seal(PacketKind::Data, &packet)?;
                let wire = wrap(sealed.encode(), obfuscation)?;
                if let Err(e) = outbound.try_enqueue(server, wire) {
                    transport.record_dropped_backpressure();
                    tracing::debug!(%e, "outbound queue full; dropping TUN packet under backpressure");
                }
            }
            frame = async {
                if let Some(dev) = tap {
                    dev.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                let frame = frame?;
                if let Some(state) = &gui_state {
                    state.lock().unwrap_or_else(|e| e.into_inner()).record_tx(frame.len());
                }
                maybe_rekey(&mut session, transport, server, auth, obfuscation, &config.handshake, config.rekey.packet_limit).await?;
                let sealed = session.seal(PacketKind::DataTap, &frame)?;
                let wire = wrap(sealed.encode(), obfuscation)?;
                if let Err(e) = outbound.try_enqueue(server, wire) {
                    transport.record_dropped_backpressure();
                    tracing::debug!(%e, "outbound queue full; dropping TAP frame under backpressure");
                }
            }
            datagram = transport.receive() => {
                let datagram = datagram?;
                if datagram.peer != server { continue; }
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
                    Ok(packet) if packet.header.kind == PacketKind::Data || packet.header.kind == PacketKind::DataTap => packet,
                    Ok(packet) if packet.header.kind == PacketKind::Keepalive => {
                        let _ = session.open(packet);
                        continue;
                    }
                    Ok(packet) if packet.header.kind == PacketKind::Close => {
                        if session.open(packet).is_ok() {
                            tracing::info!("server closed the session");
                            if let Some(state) = &gui_state {
                                state.lock().unwrap_or_else(|e| e.into_inner()).disconnected();
                            }
                            return Ok(());
                        }
                        continue;
                    }
                    Ok(packet) if packet.header.kind == PacketKind::Rekey => {
                        if session.open(packet).is_ok() {
                            session = establish(transport, server, auth, obfuscation, &config.handshake, Some(&session)).await?;
                            tracing::info!(key_phase = session.key_phase(), "rotated RVPN session keys at server request");
                            if let Some(state) = &gui_state {
                                state.lock().unwrap_or_else(|e| e.into_inner()).set_key_phase(session.key_phase());
                            }
                        }
                        continue;
                    }
                    Ok(_) => continue,
                    Err(error) => {
                        tracing::warn!(%error, "discarding malformed RVPN packet");
                        continue;
                    }
                };
                let kind = packet.header.kind;
                match session.open(packet) {
                    Ok(plaintext) => {
                        if kind == PacketKind::DataTap {
                            if let Some(dev) = tap {
                                dev.send(&plaintext).await?;
                                if let Some(state) = &gui_state {
                                    state.lock().unwrap_or_else(|e| e.into_inner()).record_rx(plaintext.len());
                                }
                            } else if let Some(dev) = tun {
                                dev.send(&plaintext).await?;
                                if let Some(state) = &gui_state {
                                    state.lock().unwrap_or_else(|e| e.into_inner()).record_rx(plaintext.len());
                                }
                            }
                        } else if let Some(dev) = tun {
                            dev.send(&plaintext).await?;
                            if let Some(state) = &gui_state {
                                state.lock().unwrap_or_else(|e| e.into_inner()).record_rx(plaintext.len());
                            }
                        } else if let Some(dev) = tap {
                            dev.send(&plaintext).await?;
                            if let Some(state) = &gui_state {
                                state.lock().unwrap_or_else(|e| e.into_inner()).record_rx(plaintext.len());
                            }
                        }
                    }
                    Err(error) => tracing::warn!(%error, "discarding unauthenticated or replayed RVPN packet"),
                }
            }
        }
    }
}
