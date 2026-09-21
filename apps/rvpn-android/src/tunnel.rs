use anyhow::{Context, Result, bail};
use rvpn_config::{DeviceMode, HandshakeConfig};
use rvpn_core::SessionId;
use rvpn_crypto::{AEAD_TAG_LEN, AuthConfig, ObfuscationKey};
use rvpn_interface::VirtualInterface;
use rvpn_protocol::{
    HEADER_LEN, HandshakeMessage, Header, InitiatorHandshake, Packet, PacketKind, ProtectedSession,
};
use rvpn_transport::{OutboundQueue, SendOptions, TransportConfig, TransportError, UdpTransport};
use std::time::Duration;
use std::{net::SocketAddr, os::fd::RawFd, sync::Arc, time::Instant};
use tokio::{
    sync::watch,
    time::{sleep, timeout},
};

pub struct AndroidTunnelConfig {
    pub tun_fd: RawFd,
    pub server: String,
    pub auth: rvpn_crypto::AuthConfig,
    pub obfuscation_key: Option<[u8; 32]>,
    pub mtu: u16,
    pub rekey_packet_limit: u64,
    pub retry_interval_ms: u64,
    pub retry_limit: u32,
    pub socket_protector: Option<Arc<dyn Fn(RawFd) -> bool + Send + Sync + 'static>>,
    pub stats: Option<Arc<crate::stats::TunnelStats>>,
    pub on_connected: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
}

/// Send `wire` to `peer`, logging and reporting path failures to the adaptive MTU.
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

pub async fn run_tunnel(
    config: AndroidTunnelConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let tun = VirtualInterface::from_raw_fd(
        config.tun_fd,
        "rvpn-android".into(),
        config.mtu,
        DeviceMode::Tun,
    )
    .context("opening Android TUN device")?;

    // `server` is reassigned on every authenticated endpoint change below
    // and read again on later loop iterations (passed into `establish`,
    // `maybe_rekey`, and `send_wire`); rustc's per-branch liveness check
    // doesn't see that far across `tokio::select!` loop iterations and
    // flags some of those writes as unread, so the lint is suppressed here
    // rather than restructuring otherwise-correct code.
    #[allow(unused_assignments)]
    let mut server = rvpn_config::resolve_endpoint(&config.server)
        .await
        .context("resolving RVPN server endpoint")?;
    tracing::info!(endpoint = %config.server, %server, "resolved RVPN server endpoint");

    let local_bind: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    let obfuscation = config.obfuscation_key.map(ObfuscationKey::from_bytes);
    let wire_overhead = HEADER_LEN
        + AEAD_TAG_LEN
        + if obfuscation.is_some() {
            rvpn_crypto::OBFUSCATION_OVERHEAD
        } else {
            0
        };

    let transport = UdpTransport::open(TransportConfig {
        local_address: local_bind,
        remote_address: None,
        max_datagram_size: usize::from(config.mtu) + wire_overhead,
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
        ..Default::default()
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

    let keepalive = transport.keepalive();
    // Sealed TUN datagrams are queued here instead of sent inline, so a
    // slow/congested socket send never blocks this select! loop from
    // servicing shutdown, rekeys, or inbound decrypt in the same iteration.
    let (outbound, mut outbound_rx) = OutboundQueue::new(256);

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
                        let _ = send_wire(&transport, server, wire).await;
                    }
                    return Ok(());
                }
            }
            // Keepalive: keep NAT mappings alive with a sealed, empty Keepalive packet.
            () = keepalive.wait_for_due() => {
                match session.seal(PacketKind::Keepalive, b"") {
                    Ok(sealed) => {
                        let encoded = sealed.encode();
                        let wire = match &obfuscation {
                            Some(key) => match key.wrap(&encoded) {
                                Ok(w) => w,
                                Err(e) => {
                                    tracing::debug!(%e, "keepalive wrap failed");
                                    continue;
                                }
                            },
                            None => encoded,
                        };
                        if let Err(e) = send_wire(&transport, server, wire).await {
                            tracing::debug!(%e, "Android keepalive send failed");
                        } else {
                            keepalive.record_keepalive_sent();
                            tracing::debug!("sent Android keepalive to server");
                        }
                    }
                    Err(e) => tracing::debug!(%e, "Android keepalive seal failed; session may need rekey"),
                }
            }
            // Drains sealed datagrams queued by the TUN read arm below.
            queued = outbound_rx.recv() => {
                if let Some(datagram) = queued {
                    if let Err(e) = send_wire(&transport, datagram.peer, datagram.payload).await {
                        tracing::debug!(%e, "queued datagram send failed");
                    }
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
                if let Err(e) = outbound.try_enqueue(server, wire) {
                    transport.record_dropped_backpressure();
                    tracing::debug!(%e, "outbound queue full; dropping Android TUN packet under backpressure");
                }
            }
            datagram = transport.receive() => {
                let datagram = datagram.context("receiving UDP datagram")?;
                let peer = datagram.peer;
                let payload = match &obfuscation {
                    Some(key) => match key.unwrap(&datagram.payload) {
                        Ok(payload) => payload,
                        Err(_) => continue,
                    },
                    None => datagram.payload,
                };
                let packet = match Packet::decode(payload) {
                    Ok(packet) if packet.header.kind == PacketKind::Data => packet,
                    Ok(packet) if packet.header.kind == PacketKind::Keepalive => {
                        match session.open(packet) {
                            Ok(_) => {
                                if peer != server {
                                    tracing::debug!(old = %server, new = %peer, "accepted authenticated Android server endpoint change");
                                    server = peer;
                                }
                            }
                            Err(_) => {}
                        }
                        continue;
                    }
                    Ok(packet) if packet.header.kind == PacketKind::Close => {
                        match session.open(packet) {
                            Ok(_) => {
                                if peer != server {
                                    tracing::debug!(old = %server, new = %peer, "accepted authenticated Android server endpoint change");
                                    server = peer;
                                }
                                tracing::info!("server closed the RVPN session");
                                return Ok(());
                            }
                            Err(_) => continue,
                        }
                    }
                    Ok(packet) if packet.header.kind == PacketKind::Rekey => {
                        match session.open(packet) {
                            Ok(_) => {
                                if peer != server {
                                    tracing::debug!(old = %server, new = %peer, "accepted authenticated Android server endpoint change");
                                    server = peer;
                                }
                                session = establish(
                                    &transport,
                                    server,
                                    &auth,
                                    obfuscation.as_ref(),
                                    &handshake_policy,
                                    Some(&session),
                                    &mut shutdown,
                                ).await?;
                            }
                            Err(_) => continue,
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
                        // Discard any legacy empty-Data keepalives from an
                        // older packet format.
                        if plaintext.is_empty() {
                            continue;
                        }
                        if peer != server {
                            tracing::debug!(old = %server, new = %peer, "accepted authenticated Android server endpoint change");
                            server = peer;
                        }
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
    if session.should_rekey_with_policy(packet_limit, Some(Duration::from_secs(120))) {
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
    let (mut handshake, initiation) = InitiatorHandshake::start(auth.identity(), auth.verifier())?;
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
    let mut initiation_packet = Packet {
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
            let deadline = Instant::now()
                + rvpn_config::jittered_retry_interval(
                    policy.retry_interval_ms,
                    policy.retry_jitter_ms,
                );
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
                                        match HandshakeMessage::decode(packet.payload) {
                                            Ok(response @ HandshakeMessage::Response { .. }) => {
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
                                            Ok(HandshakeMessage::CookieReply { cookie }) => {
                                                // Cheap, immediate resend with the proven
                                                // cookie attached; doesn't consume a retry
                                                // attempt or wait out the deadline.
                                                handshake.attach_cookie(cookie);
                                                initiation_packet.payload = handshake.initiation().encode();
                                                let encoded = initiation_packet.encode();
                                                let wire = match obfuscation {
                                                    Some(key) => key.wrap(&encoded)?,
                                                    None => encoded,
                                                };
                                                transport.send_to(server, wire, SendOptions::default()).await?;
                                            }
                                            _ => {}
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
            sleep(rvpn_config::jittered_retry_interval(
                policy.retry_interval_ms,
                policy.retry_jitter_ms,
            ))
            .await;
        }
    }
    Ok(new_session)
}
