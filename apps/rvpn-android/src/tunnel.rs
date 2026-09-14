use anyhow::{Context, Result, bail};
use rvpn_config::{DeviceMode, HandshakeConfig};
use rvpn_core::SessionId;
use rvpn_crypto::{AEAD_TAG_LEN, AuthConfig, ObfuscationKey};
use rvpn_interface::VirtualInterface;
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
    /// VPN server endpoint as `host:port` or `ip:port`; resolved via DNS
    /// once at tunnel startup (see [`rvpn_config::resolve_endpoint`]).
    pub server: String,
    /// 32-byte pre-shared key. The Android UI currently only exposes PSK
    /// authentication; pinned-key/certificate modes are available at the
    /// Rust API level (`rvpn_crypto::AuthConfig`) but not yet wired into the
    /// Kotlin settings screens.
    pub auth: rvpn_crypto::AuthConfig,
    /// Optional wire obfuscation key. When set, every datagram is wrapped in
    /// a stream-cipher shell to defeat passive DPI fingerprinting. Not yet
    /// exposed in the Kotlin settings UI.
    pub obfuscation_key: Option<[u8; 32]>,
    /// Configured MTU.
    pub mtu: u16,
    /// Packet limit before rotating session keys (0 to disable).
    pub rekey_packet_limit: u64,
    /// Handshake retransmission interval in milliseconds.
    pub retry_interval_ms: u64,
    /// Handshake retransmission limit.
    pub retry_limit: u32,
    /// Callback to protect the UDP transport socket from VPN loopback routing.
    pub socket_protector: Option<Arc<dyn Fn(RawFd) -> bool + Send + Sync + 'static>>,
    /// Shared tunnel telemetry and statistics counter.
    pub stats: Option<Arc<crate::stats::TunnelStats>>,
    /// Called exactly once after the initial handshake succeeds.
    pub on_connected: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
}

/// Runs the Android VPN tunnel to completion or until shutdown is signaled.
pub async fn run_tunnel(
    config: AndroidTunnelConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    // Take ownership of the Android TUN fd immediately. This guarantees that
    // every error path after this point drops the fd and tears down the VPN
    // interface instead of leaving Android's VPN interface orphaned.
    let tun = VirtualInterface::from_raw_fd(
        config.tun_fd,
        "rvpn-android".into(),
        config.mtu,
        DeviceMode::Tun,
    )
    .context("opening Android TUN device")?;

    let server = rvpn_config::resolve_endpoint(&config.server)
        .await
        .context("resolving RVPN server endpoint")?;
    tracing::info!(endpoint = %config.server, %server, "resolved RVPN server endpoint");

    let local_bind: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    let obfuscation = config.obfuscation_key.map(ObfuscationKey::from_bytes);

    let transport = UdpTransport::open(TransportConfig {
        local_address: local_bind,
        remote_address: None,
        max_datagram_size: usize::from(config.mtu)
            + HEADER_LEN
            + AEAD_TAG_LEN
            + rvpn_crypto::OBFUSCATION_OVERHEAD,
    })
    .await
    .context("opening UDP transport")?;

    if let Some(protector) = &config.socket_protector {
        let fd = transport.raw_fd();
        if !protector(fd) {
            bail!(
                "failed to protect UDP transport socket (fd: {}) via VpnService",
                fd
            );
        }
        tracing::info!(
            socket_fd = fd,
            "protected UDP transport socket from VPN routing"
        );
    }

    let handshake_policy = HandshakeConfig {
        retry_interval_ms: config.retry_interval_ms,
        retry_limit: config.retry_limit,
        retry_jitter_ms: config.retry_interval_ms,
    };
    let auth = config.auth.clone();

    tracing::info!(%server, "initiating RVPN handshake from Android client");
    let mut session = establish(
        &transport,
        server,
        &auth,
        obfuscation.as_ref(),
        &handshake_policy,
        None,
        &mut shutdown,
    )
    .await?;

    if let Some(on_connected) = &config.on_connected {
        on_connected();
    }

    tracing::info!(
        session_id = ?session.session_id(),
        %server,
        mtu = config.mtu,
        "RVPN Android tunnel data plane started"
    );

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    tracing::info!("shutdown requested; closing Android RVPN session");
                    if let Ok(close) = session.seal(PacketKind::Close, b"") {
                        let encoded = close.encode();
                        let wire = match &obfuscation {
                            Some(key) => key.wrap(&encoded).unwrap_or(encoded),
                            None => encoded,
                        };
                        let _ = transport.send_to(server, wire, SendOptions::default()).await;
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
                    server,
                    &auth,
                    obfuscation.as_ref(),
                    &handshake_policy,
                    config.rekey_packet_limit,
                    &mut shutdown,
                ).await?;
                let sealed = session.seal(PacketKind::Data, &packet)?;
                let encoded = sealed.encode();
                let wire = match &obfuscation { Some(key) => key.wrap(&encoded)?, None => encoded };
                transport.send_to(server, wire, SendOptions::default()).await?;
            }
            datagram = transport.receive() => {
                let datagram = datagram.context("receiving UDP datagram")?;
                if datagram.peer != server {
                    continue;
                }
                let payload = match &obfuscation {
                    Some(key) => match key.unwrap(&datagram.payload) {
                        Ok(payload) => payload,
                        Err(_) => continue,
                    },
                    None => datagram.payload,
                };
                let packet = match Packet::decode(payload) {
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
                                server,
                                &auth,
                                obfuscation.as_ref(),
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
    auth: &AuthConfig,
    obfuscation: Option<&ObfuscationKey>,
    handshake: &HandshakeConfig,
    packet_limit: u64,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    if packet_limit != 0 && session.should_rekey(packet_limit) {
        *session = establish(
            transport,
            server,
            auth,
            obfuscation,
            handshake,
            Some(session),
            shutdown,
        )
        .await?;
        tracing::info!(key_phase = session.key_phase(), "rotated RVPN session keys");
    }
    Ok(())
}

async fn establish(
    transport: &UdpTransport,
    server: SocketAddr,
    auth: &AuthConfig,
    obfuscation: Option<&ObfuscationKey>,
    policy: &HandshakeConfig,
    old: Option<&ProtectedSession>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<ProtectedSession> {
    let (handshake, initiation) = InitiatorHandshake::start(auth.identity(), auth.verifier())?;
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
            let encoded = initiation_packet.encode();
            let wire = match obfuscation {
                Some(key) => key.wrap(&encoded)?,
                None => encoded,
            };
            transport
                .send_to(server, wire, SendOptions::default())
                .await?;
            let deadline = Instant::now() + Duration::from_millis(policy.retry_jitter_ms);
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
                                let payload = match obfuscation {
                                    Some(key) => match key.unwrap(&datagram.payload) { Ok(p) => p, Err(_) => continue },
                                    None => datagram.payload,
                                };
                                if let Ok(packet) = Packet::decode(payload) {
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
    let (finish, new_session, _remote_identity) = match old {
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
        let encoded = finish_packet.encode();
        let wire = match obfuscation {
            Some(key) => key.wrap(&encoded)?,
            None => encoded,
        };
        transport
            .send_to(server, wire, SendOptions::default())
            .await?;
        if attempt != policy.retry_limit {
            sleep(Duration::from_millis(policy.retry_jitter_ms)).await;
        }
    }
    Ok(new_session)
}
