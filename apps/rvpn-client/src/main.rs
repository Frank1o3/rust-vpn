use anyhow::{Context, Result, bail};
use rvpn_config::{ClientConfig, HandshakeConfig};
use rvpn_core::SessionId;
use rvpn_crypto::{AEAD_TAG_LEN, HandshakePsk};
use rvpn_interface::{DEFAULT_MTU, TunConfig, TunDevice};
use rvpn_protocol::{
    HEADER_LEN, HandshakeMessage, Header, InitiatorHandshake, Packet, PacketKind, ProtectedSession,
};
use rvpn_transport::{SendOptions, TransportConfig, UdpTransport};
use std::{
    env, fs,
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{
    process::Command,
    time::{sleep, timeout},
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let path = env::args()
        .nth(1)
        .context("usage: rvpn-client <client.toml>")?;
    let config = ClientConfig::from_toml(&fs::read_to_string(path)?)?;
    let tun_config = TunConfig {
        name: config.interface.name.clone(),
        mtu: config.interface.mtu.unwrap_or(DEFAULT_MTU),
    };
    // Do not UDP-connect: send_to keeps the client usable after its local path is recreated.
    let transport = UdpTransport::open(TransportConfig {
        local_address: "0.0.0.0:0".parse::<SocketAddr>()?,
        remote_address: None,
        max_datagram_size: usize::from(tun_config.mtu) + HEADER_LEN + AEAD_TAG_LEN,
    })
    .await?;
    let psk = config.pre_shared_key_bytes()?;
    let mut session = establish(&transport, config.server, psk, &config.handshake, None).await?;
    let tun = TunDevice::create(tun_config).await?;
    configure_client_network(&tun, &config).await?;
    tracing::info!(session_id = ?session.session_id(), server = %config.server, interface = %tun.name(), mtu = tun.mtu(), "authenticated RVPN client data plane started");
    loop {
        tokio::select! {
            signal = shutdown_signal() => {
                signal?;
                let close = session.seal(PacketKind::Close, b"")?;
                let _ = transport.send_to(config.server, close.encode(), SendOptions::default()).await;
                tracing::info!("sent authenticated close packet");
                return Ok(());
            }
            packet = tun.recv() => {
                let packet = packet?;
                if config.rekey.packet_limit != 0 && session.should_rekey(config.rekey.packet_limit) {
                    session = establish(&transport, config.server, psk, &config.handshake, Some(&session)).await?;
                    tracing::info!(key_phase = session.key_phase(), "rotated RVPN session keys");
                }
                let packet = session.seal(PacketKind::Data, &packet)?;
                transport.send_to(config.server, packet.encode(), SendOptions::default()).await?;
            }
            datagram = transport.receive() => {
                let datagram = datagram?;
                if datagram.peer != config.server { continue; }
                let packet = match Packet::decode(datagram.payload) {
                    Ok(packet) if packet.header.kind == PacketKind::Data => packet,
                    Ok(packet) if packet.header.kind == PacketKind::Close => { if session.open(packet).is_ok() { tracing::info!("server closed the session"); return Ok(()); } continue; }
                    Ok(packet) if packet.header.kind == PacketKind::Rekey => {
                        // A valid protected request lets the responder rotate before its
                        // own outbound counter reaches the configured threshold.
                        if session.open(packet).is_ok() {
                            session = establish(&transport, config.server, psk, &config.handshake, Some(&session)).await?;
                            tracing::info!(key_phase = session.key_phase(), "rotated RVPN session keys at server request");
                        }
                        continue;
                    }
                    Ok(_) => continue,
                    Err(error) => { tracing::warn!(%error, "discarding malformed RVPN packet"); continue; }
                };
                match session.open(packet) { Ok(packet) => tun.send(&packet).await?, Err(error) => tracing::warn!(%error, "discarding unauthenticated or replayed RVPN packet"), }
            }
        }
    }
}

/// Retransmits each handshake flight. Rekeys retain the established session ID.
async fn establish(
    transport: &UdpTransport,
    server: SocketAddr,
    psk: [u8; 32],
    policy: &HandshakeConfig,
    old: Option<&ProtectedSession>,
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
        None => (PacketKind::Handshake, SessionId::new([0; 16]), 0),
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
            transport
                .send_to(server, initiation_packet.encode(), SendOptions::default())
                .await?;
            let deadline = Instant::now() + Duration::from_millis(policy.retry_interval_ms);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match timeout(remaining, transport.receive()).await {
                    Ok(Ok(datagram)) if datagram.peer == server => {
                        if let Ok(packet) = Packet::decode(datagram.payload) {
                            if packet.header.kind == kind
                                && (old.is_none() || packet.header.session_id == session_id)
                            {
                                if let Ok(response @ HandshakeMessage::Response { .. }) =
                                    HandshakeMessage::decode(packet.payload)
                                {
                                    // The first response introduces its newly assigned session ID;
                                    // rekey responses must remain bound to the existing one.
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
            tracing::debug!(attempt, "handshake response timed out; retransmitting");
        }
        bail!(
            "RVPN handshake timed out after {} attempts",
            policy.retry_limit
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

async fn configure_client_network(tun: &TunDevice, config: &ClientConfig) -> Result<()> {
    if let Some(address) = &config.interface.address {
        run("ip", ["address", "replace", address, "dev", tun.name()]).await?;
        run("ip", ["link", "set", "dev", tun.name(), "up"]).await?;
    }
    for route in &config.routing.routes {
        run("ip", ["route", "replace", route, "dev", tun.name()]).await?;
    }
    if config.routing.default_route {
        let gateway = config
            .routing
            .gateway
            .as_deref()
            .expect("validated gateway");
        // Without this exception the server UDP endpoint would itself follow
        // the new default route into the tunnel and recursively black-hole.
        let endpoint_gateway = config
            .routing
            .endpoint_gateway
            .as_deref()
            .expect("validated endpoint gateway");
        let endpoint = format!("{}/32", config.server.ip());
        run(
            "ip",
            ["route", "replace", &endpoint, "via", endpoint_gateway],
        )
        .await?;
        run(
            "ip",
            [
                "route",
                "replace",
                "default",
                "via",
                gateway,
                "dev",
                tun.name(),
            ],
        )
        .await?;
    }
    Ok(())
}

async fn run<'a>(program: &str, args: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .context("running network command")?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "{} failed: {}",
            program,
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        tokio::select! { result = tokio::signal::ctrl_c() => result.context("waiting for SIGINT"), result = async { tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?.recv().await; Ok::<(), std::io::Error>(()) } => result.context("waiting for SIGTERM") }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("waiting for shutdown signal")
    }
}
