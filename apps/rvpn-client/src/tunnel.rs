use anyhow::Result;
use rvpn_config::ClientConfig;
use rvpn_core::GuiStateHandle;
use rvpn_crypto::{AuthConfig, ObfuscationKey};
use rvpn_interface::VirtualInterface;
use rvpn_protocol::{Packet, PacketKind, ProtectedSession};
use rvpn_transport::{OutboundQueue, SendOptions, TransportError, UdpTransport};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::handshake::{establish, maybe_rekey};

/// Why the data plane returned. Everything except `Shutdown` means the
/// session is gone but the local TUN device and routes are still up, so the
/// caller should re-handshake instead of tearing the client down.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataPlaneExit {
    /// The user/daemon asked us to stop.
    Shutdown,
    /// The server sent an authenticated Close.
    ServerClosed,
    /// No authenticated packet within `liveness.timeout_secs`, or a rekey failed.
    LinkLost,
}

fn wrap(encoded: bytes::Bytes, obfuscation: Option<&ObfuscationKey>) -> Result<bytes::Bytes> {
    Ok(match obfuscation {
        Some(key) => key.wrap(&encoded)?,
        None => encoded,
    })
}

fn mark_disconnected(gui_state: &Option<GuiStateHandle>) {
    if let Some(state) = gui_state {
        state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .disconnected();
    }
}

fn record_tx(gui_state: &Option<GuiStateHandle>, bytes: usize) {
    if let Some(state) = gui_state {
        state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_tx(bytes);
    }
}

fn record_rx(gui_state: &Option<GuiStateHandle>, bytes: usize) {
    if let Some(state) = gui_state {
        state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_rx(bytes);
    }
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

#[allow(clippy::too_many_arguments)]
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
) -> Result<DataPlaneExit> {
    let keepalive = transport.keepalive();
    let started = Instant::now();
    let (outbound, mut outbound_rx) = OutboundQueue::new(256);
    let mut telemetry = tokio::time::interval(Duration::from_millis(250));

    // Dead-link detection: `last_rx` moves only on *authenticated* packets, so
    // spoofed or replayed datagrams cannot keep a dead session alive.
    let liveness_timeout = config.liveness.timeout();
    let mut liveness_check = tokio::time::interval(Duration::from_secs(5));
    let mut last_rx = Instant::now();

    // Time-based rekey must not depend on outbound traffic, so it gets its own timer.
    let mut rekey_check = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            signal = &mut shutdown_signal => {
                signal?;

                let close = session.seal(PacketKind::Close, b"")?;
                let wire = wrap(close.encode(), obfuscation)?;

                match send_wire(transport, server, wire).await {
                    Ok(bytes) => {
                        tracing::info!(bytes, server = %server, "sent authenticated close packet");
                    }
                    Err(error) => {
                        tracing::error!(%error, server = %server, "failed to send authenticated close packet");
                    }
                }

                mark_disconnected(&gui_state);
                return Ok(DataPlaneExit::Shutdown);
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
            _ = liveness_check.tick() => {
                if let Some(limit) = liveness_timeout {
                    let silent_for = last_rx.elapsed();
                    if silent_for > limit {
                        tracing::warn!(
                            silent_secs = silent_for.as_secs(),
                            limit_secs = limit.as_secs(),
                            "no authenticated packet from server; treating link as dead"
                        );
                        mark_disconnected(&gui_state);
                        return Ok(DataPlaneExit::LinkLost);
                    }
                }
            }
            _ = rekey_check.tick() => {
                match maybe_rekey(&mut session, transport, server, auth, obfuscation, &config.handshake, &config.rekey).await {
                    Ok(true) => {
                        last_rx = Instant::now();
                        if let Some(state) = &gui_state {
                            state.lock().unwrap_or_else(|e| e.into_inner()).set_key_phase(session.key_phase());
                        }
                    }
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(%error, "scheduled rekey failed; reconnecting");
                        mark_disconnected(&gui_state);
                        return Ok(DataPlaneExit::LinkLost);
                    }
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
                if let Some(datagram) = queued
                    && let Err(e) = send_wire(transport, datagram.peer, datagram.payload).await
                {
                    tracing::debug!(%e, "queued datagram send failed");
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
                record_tx(&gui_state, packet.len());
                match maybe_rekey(&mut session, transport, server, auth, obfuscation, &config.handshake, &config.rekey).await {
                    Ok(true) => last_rx = Instant::now(),
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(%error, "rekey failed; reconnecting");
                        mark_disconnected(&gui_state);
                        return Ok(DataPlaneExit::LinkLost);
                    }
                }
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
                record_tx(&gui_state, frame.len());
                match maybe_rekey(&mut session, transport, server, auth, obfuscation, &config.handshake, &config.rekey).await {
                    Ok(true) => last_rx = Instant::now(),
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(%error, "rekey failed; reconnecting");
                        mark_disconnected(&gui_state);
                        return Ok(DataPlaneExit::LinkLost);
                    }
                }
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
                        if session.open(packet).is_ok() {
                            last_rx = Instant::now();
                        }
                        continue;
                    }
                    Ok(packet) if packet.header.kind == PacketKind::Close => {
                        if session.open(packet).is_ok() {
                            tracing::info!("server closed the session");
                            mark_disconnected(&gui_state);
                            return Ok(DataPlaneExit::ServerClosed);
                        }
                        continue;
                    }
                    Ok(packet) if packet.header.kind == PacketKind::Rekey => {
                        if session.open(packet).is_ok() {
                            match establish(transport, server, auth, obfuscation, &config.handshake, Some(&session)).await {
                                Ok(new_session) => {
                                    session = new_session;
                                    last_rx = Instant::now();
                                    tracing::info!(key_phase = session.key_phase(), "rotated RVPN session keys at server request");
                                    if let Some(state) = &gui_state {
                                        state.lock().unwrap_or_else(|e| e.into_inner()).set_key_phase(session.key_phase());
                                    }
                                }
                                Err(error) => {
                                    tracing::warn!(%error, "server-requested rekey failed; reconnecting");
                                    mark_disconnected(&gui_state);
                                    return Ok(DataPlaneExit::LinkLost);
                                }
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
                        last_rx = Instant::now();
                        if plaintext.is_empty() {
                            continue;
                        }
                        let target = if kind == PacketKind::DataTap { tap.or(tun) } else { tun.or(tap) };
                        if let Some(dev) = target {
                            dev.send(&plaintext).await?;
                            record_rx(&gui_state, plaintext.len());
                        }
                    }
                    Err(error) => tracing::warn!(%error, "discarding unauthenticated or replayed RVPN packet"),
                }
            }
        }
    }
}
