use anyhow::Result;
use rvpn_config::ClientConfig;
use rvpn_crypto::{AuthConfig, ObfuscationKey};
use rvpn_interface::VirtualInterface;
use rvpn_protocol::{Packet, PacketKind, ProtectedSession};
use rvpn_transport::{SendOptions, TransportError, UdpTransport};
use std::net::SocketAddr;

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
) -> Result<()> {
    let keepalive = transport.keepalive();
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

                return Ok(());
            }
            // Keepalive: fire a sealed empty Data packet to keep NAT mappings
            // alive. Uses the KeepaliveScheduler from the transport so any
            // real send/receive automatically resets the deadline.
            () = keepalive.wait_for_due() => {
                match session.seal(PacketKind::Data, b"") {
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
            packet = async {
                if let Some(dev) = tun {
                    dev.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                let packet = packet?;
                maybe_rekey(&mut session, transport, server, auth, obfuscation, &config.handshake, config.rekey.packet_limit).await?;
                let sealed = session.seal(PacketKind::Data, &packet)?;
                let wire = wrap(sealed.encode(), obfuscation)?;
                if let Err(e) = send_wire(transport, server, wire).await {
                    tracing::warn!(%e, "failed to send TUN packet to server");
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
                maybe_rekey(&mut session, transport, server, auth, obfuscation, &config.handshake, config.rekey.packet_limit).await?;
                let sealed = session.seal(PacketKind::DataTap, &frame)?;
                let wire = wrap(sealed.encode(), obfuscation)?;
                if let Err(e) = send_wire(transport, server, wire).await {
                    tracing::warn!(%e, "failed to send TAP frame to server");
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
                    Ok(packet) if packet.header.kind == PacketKind::Close => {
                        if session.open(packet).is_ok() {
                            tracing::info!("server closed the session");
                            return Ok(());
                        }
                        continue;
                    }
                    Ok(packet) if packet.header.kind == PacketKind::Rekey => {
                        if session.open(packet).is_ok() {
                            session = establish(transport, server, auth, obfuscation, &config.handshake, Some(&session)).await?;
                            tracing::info!(key_phase = session.key_phase(), "rotated RVPN session keys at server request");
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
                            } else if let Some(dev) = tun {
                                dev.send(&plaintext).await?;
                            }
                        } else {
                            if let Some(dev) = tun {
                                dev.send(&plaintext).await?;
                            } else if let Some(dev) = tap {
                                dev.send(&plaintext).await?;
                            }
                        }
                    }
                    Err(error) => tracing::warn!(%error, "discarding unauthenticated or replayed RVPN packet"),
                }
            }
        }
    }
}
