use anyhow::{Context, Result, bail};
use rvpn_config::{DeviceMode, HandshakeConfig};
use rvpn_core::SessionId;
use rvpn_crypto::{AEAD_TAG_LEN, HandshakePsk};
use rvpn_interface::TunDevice;
use rvpn_protocol::{
    HEADER_LEN, HandshakeMessage, Header, InitiatorHandshake, Packet, PacketKind, ProtectedSession,
};
use rvpn_transport::{SendOptions, TransportConfig, UdpTransport};
use std::{
    net::SocketAddr,
    os::fd::RawFd,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::watch,
    time::{sleep, timeout},
};

/// Configuration for the Android RVPN tunnel.
pub struct AndroidTunnelConfig {
    /// Established TUN file descriptor provided by Android's `VpnService`.
    pub tun_fd: RawFd,
    /// VPN server endpoint.
    pub server: SocketAddr,
    /// 32-byte pre-shared key.
    pub psk: [u8; 32],
    /// Configured MTU.
    pub mtu: u16,
    /// Packet limit before rotating session keys (0 to disable).
    pub rekey_packet_limit: u64,
    /// Handshake retransmission interval in milliseconds.
    pub retry_interval_ms: u64,
    /// Handshake retransmission limit.
    pub retry_limit: u32,
    /// Callback to protect the UDP transport socket from VPN loopback routing.
    /// Android's `VpnService.protect(socketFd)` must be invoked on the socket descriptor.
    pub socket_protector: Option<Arc<dyn Fn(RawFd) -> bool + Send + Sync + 'static>>,
    /// Shared tunnel telemetry and statistics counter.
    pub stats: Option<Arc<crate::stats::TunnelStats>>,
}


/// Runs the Android VPN tunnel to completion or until shutdown is signaled.
pub async fn run_tunnel(
    config: AndroidTunnelConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let local_bind: SocketAddr = if config.server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    let transport = UdpTransport::open(TransportConfig {
        local_address: local_bind,
        remote_address: None,
        max_datagram_size: usize::from(config.mtu) + HEADER_LEN + AEAD_TAG_LEN,
    })
    .await
    .context("opening UDP transport")?;

    // Protect the UDP socket from VPN routing loop on Android
    if let Some(protector) = &config.socket_protector {
        let fd = transport.raw_fd();
        if !protector(fd) {
            bail!("failed to protect UDP transport socket (fd: {}) via VpnService", fd);
        }
        tracing::info!(socket_fd = fd, "protected UDP transport socket from VPN routing");
    }

    let handshake_policy = HandshakeConfig {
        retry_interval_ms: config.retry_interval_ms,
        retry_limit: config.retry_limit,
    };

    tracing::info!(server = %config.server, "initiating RVPN handshake from Android client");
    let mut session = establish(
        &transport,
        config.server,
        config.psk,
        &handshake_policy,
        None,
        &mut shutdown,
    )
    .await?;

    let tun = TunDevice::from_raw_fd(
        config.tun_fd,
        "rvpn-android".into(),
        config.mtu,
        DeviceMode::Tun,
    )?;

    tracing::info!(
        session_id = ?session.session_id(),
        server = %config.server,
        mtu = config.mtu,
        "RVPN Android tunnel data plane started"
    );

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    tracing::info!("shutdown requested; closing Android RVPN session");
                    if let Ok(close) = session.seal(PacketKind::Close, b"") {
                        let _ = transport.send_to(config.server, close.encode(), SendOptions::default()).await;
                    }
                    return Ok(());
                }
            }
            packet = tun.recv() => {
                let packet = packet.context("reading packet from Android TUN interface")?;
                if let Some(stats) = &config.stats {
                    stats.record_tx(packet.len());
                }
                maybe_rekey(
                    &mut session,
                    &transport,
                    config.server,
                    config.psk,
                    &handshake_policy,
                    config.rekey_packet_limit,
                    &mut shutdown,
                ).await?;
                let sealed = session.seal(PacketKind::Data, &packet)?;
                transport.send_to(config.server, sealed.encode(), SendOptions::default()).await?;
            }
            datagram = transport.receive() => {
                let datagram = datagram.context("receiving UDP datagram")?;
                if datagram.peer != config.server {
                    continue;
                }
                let packet = match Packet::decode(datagram.payload) {
                    Ok(packet) if packet.header.kind == PacketKind::Data => packet,
                    Ok(packet) if packet.header.kind == PacketKind::Close => {
                        if session.open(packet).is_ok() {
                            tracing::info!("server closed the RVPN session");
                            return Ok(());
                        }
                        continue;
                    }
                    Ok(packet) if packet.header.kind == PacketKind::Rekey => {
                        if session.open(packet).is_ok() {
                            session = establish(
                                &transport,
                                config.server,
                                config.psk,
                                &handshake_policy,
                                Some(&session),
                                &mut shutdown,
                            ).await?;
                            tracing::info!(key_phase = session.key_phase(), "rotated session keys at server request");
                        }
                        continue;
                    }
                    Ok(_) => continue,
                    Err(error) => {
                        tracing::warn!(%error, "discarding malformed RVPN packet");
                        continue;
                    }
                };

                match session.open(packet) {
                    Ok(plaintext) => {
                        let len = plaintext.len();
                        if let Err(error) = tun.send(&plaintext).await {
                            tracing::warn!(%error, "failed to inject packet into Android TUN interface");
                        } else if let Some(stats) = &config.stats {
                            stats.record_rx(len);
                        }
                    }
                    Err(error) => tracing::warn!(%error, "discarding unauthenticated or replayed packet"),
                }
            }

        }
    }
}

async fn maybe_rekey(
    session: &mut ProtectedSession,
    transport: &UdpTransport,
    server: SocketAddr,
    psk: [u8; 32],
    handshake: &HandshakeConfig,
    packet_limit: u64,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    if packet_limit != 0 && session.should_rekey(packet_limit) {
        *session = establish(transport, server, psk, handshake, Some(session), shutdown).await?;
        tracing::info!(key_phase = session.key_phase(), "rotated RVPN session keys");
    }
    Ok(())
}

async fn establish(
    transport: &UdpTransport,
    server: SocketAddr,
    psk: [u8; 32],
    policy: &HandshakeConfig,
    old: Option<&ProtectedSession>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<ProtectedSession> {
    let (handshake, initiation) = InitiatorHandshake::start(HandshakePsk::from_bytes(psk))?;
    let (kind, session_id, key_phase) = match old {
        Some(session) => (
            PacketKind::Rekey,
            session.session_id(),
            session
                .key_phase()
                .checked_add(1)
                .context("key phase exhausted")?,
        ),
        None => (PacketKind::Handshake, SessionId::ZERO, 0),
    };
    let old_phase = old.map_or(0, ProtectedSession::key_phase);
    let initiation_packet = Packet {
        header: Header {
            kind,
            key_phase: old_phase,
            sequence: 0,
            session_id,
        },
        payload: initiation.encode(),
    };

    let response = 'retry: loop {
        for attempt in 1..=policy.retry_limit {
            if *shutdown.borrow() {
                bail!("handshake cancelled by shutdown");
            }
            transport
                .send_to(server, initiation_packet.encode(), SendOptions::default())
                .await?;
            let deadline = Instant::now() + Duration::from_millis(policy.retry_interval_ms);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            bail!("handshake cancelled by shutdown");
                        }
                    }
                    res = timeout(remaining, transport.receive()) => {
                        match res {
                            Ok(Ok(datagram)) if datagram.peer == server => {
                                if let Ok(packet) = Packet::decode(datagram.payload) {
                                    if packet.header.kind == kind
                                        && (old.is_none() || packet.header.session_id == session_id)
                                    {
                                        if let Ok(response @ HandshakeMessage::Response { .. }) =
                                            HandshakeMessage::decode(packet.payload)
                                        {
                                            let advertised_session = match response {
                                                HandshakeMessage::Response { session_id, .. } => session_id,
                                                _ => unreachable!(),
                                            };
                                            if packet.header.session_id == advertised_session
                                                && handshake.authenticates_response(response)?
                                            {
                                                break 'retry response;
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(Ok(_)) => continue,
                            Ok(Err(error)) => return Err(error.into()),
                            Err(_) => break,
                        }
                    }
                }
            }
            tracing::debug!(attempt, %server, "handshake response timed out; retransmitting");
        }
        bail!(
            "RVPN handshake timed out after {} attempts to {}",
            policy.retry_limit,
            server
        );
    };

    let finish_session_id = match response {
        HandshakeMessage::Response { session_id, .. } => session_id,
        _ => unreachable!(),
    };
    let (finish, new_session) = match old {
        Some(_) => handshake.finish_for_session(response, session_id, key_phase)?,
        None => handshake.finish(response)?,
    };
    let finish_packet = Packet {
        header: Header {
            kind,
            key_phase: old_phase,
            sequence: 1,
            session_id: finish_session_id,
        },
        payload: finish.encode(),
    };
    for attempt in 1..=policy.retry_limit {
        transport
            .send_to(server, finish_packet.encode(), SendOptions::default())
            .await?;
        if attempt != policy.retry_limit {
            sleep(Duration::from_millis(policy.retry_interval_ms)).await;
        }
    }
    Ok(new_session)
}
