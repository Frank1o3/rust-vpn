//! Bidirectional packet forwarding loop between virtual devices and UDP transport.

use anyhow::Result;
use rvpn_config::ClientConfig;
use rvpn_interface::TunDevice;
use rvpn_protocol::{Packet, PacketKind, ProtectedSession};
use rvpn_transport::{SendOptions, UdpTransport};

use crate::handshake::{establish, maybe_rekey};

/// Runs the active data plane loop until a shutdown signal or session termination.
pub async fn run_data_plane(
    mut session: ProtectedSession,
    transport: &UdpTransport,
    config: &ClientConfig,
    psk: [u8; 32],
    tun: Option<&TunDevice>,
    tap: Option<&TunDevice>,
    mut shutdown_signal: impl std::future::Future<Output = Result<()>> + Unpin,
) -> Result<()> {
    loop {
        tokio::select! {
            signal = &mut shutdown_signal => {
                signal?;
                let close = session.seal(PacketKind::Close, b"")?;
                let _ = transport.send_to(config.server, close.encode(), SendOptions::default()).await;
                tracing::info!("sent authenticated close packet");
                return Ok(());
            }
            packet = async {
                if let Some(dev) = tun {
                    dev.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                let packet = packet?;
                maybe_rekey(&mut session, transport, config.server, psk, &config.handshake, config.rekey.packet_limit).await?;
                let packet = session.seal(PacketKind::Data, &packet)?;
                transport.send_to(config.server, packet.encode(), SendOptions::default()).await?;
            }
            frame = async {
                if let Some(dev) = tap {
                    dev.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                let frame = frame?;
                maybe_rekey(&mut session, transport, config.server, psk, &config.handshake, config.rekey.packet_limit).await?;
                let packet = session.seal(PacketKind::DataTap, &frame)?;
                transport.send_to(config.server, packet.encode(), SendOptions::default()).await?;
            }
            datagram = transport.receive() => {
                let datagram = datagram?;
                if datagram.peer != config.server { continue; }
                let packet = match Packet::decode(datagram.payload) {
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
                            session = establish(transport, config.server, psk, &config.handshake, Some(&session)).await?;
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
