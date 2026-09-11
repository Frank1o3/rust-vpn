use anyhow::{Context, Result, bail};
use rvpn_config::ClientConfig;
use rvpn_core::SessionId;
use rvpn_crypto::{AEAD_TAG_LEN, HandshakePsk};
use rvpn_interface::{DEFAULT_MTU, TunConfig, TunDevice};
use rvpn_protocol::{HEADER_LEN, HandshakeMessage, Header, InitiatorHandshake, Packet, PacketKind};
use rvpn_transport::{SendOptions, TransportConfig, UdpTransport};
use std::{env, fs, net::SocketAddr};

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
    let transport = UdpTransport::open(TransportConfig {
        local_address: "0.0.0.0:0".parse::<SocketAddr>()?,
        remote_address: Some(config.server),
        // TUN IP bytes plus authenticated RVPN header and AEAD tag. No VPN
        // fragmentation is implemented, so this bound must be explicit.
        max_datagram_size: usize::from(tun_config.mtu) + HEADER_LEN + AEAD_TAG_LEN,
    })
    .await?;
    let (handshake, initiation) =
        InitiatorHandshake::start(HandshakePsk::from_bytes(config.pre_shared_key_bytes()?))?;
    let initial_packet = Packet {
        header: Header {
            kind: PacketKind::Handshake,
            key_phase: 0,
            sequence: 0,
            session_id: SessionId::new([0; 16]),
        },
        payload: initiation.encode(),
    };
    transport
        .send(initial_packet.encode(), SendOptions::default())
        .await?;
    let response_packet = Packet::decode(transport.receive().await?.payload)?;
    if response_packet.header.kind != PacketKind::Handshake {
        bail!("expected an RVPN handshake response");
    }
    let response = HandshakeMessage::decode(response_packet.payload)?;
    let response_session_id = match response {
        HandshakeMessage::Response { session_id, .. } => session_id,
        _ => bail!("expected an RVPN handshake response message"),
    };
    if response_packet.header.session_id != response_session_id {
        bail!("RVPN handshake response has inconsistent session identifiers");
    }
    let (finish, mut session) = handshake.finish(response)?;
    let finish_packet = Packet {
        header: Header {
            kind: PacketKind::Handshake,
            key_phase: 0,
            sequence: 1,
            session_id: session.session_id(),
        },
        payload: finish.encode(),
    };
    transport
        .send(finish_packet.encode(), SendOptions::default())
        .await?;
    let tun = TunDevice::create(tun_config).await?;
    tracing::info!(session_id = ?session.session_id(), server = %config.server, interface = %tun.name(), mtu = tun.mtu(), "authenticated RVPN client data plane started");

    loop {
        tokio::select! {
            packet = tun.recv() => {
                let packet = packet?;
                tracing::debug!(bytes = packet.len(), "received IP packet from TUN");
                let packet = session.seal(PacketKind::Data, &packet)?;
                tracing::debug!(bytes = packet.payload.len(), sequence = packet.header.sequence, "sending protected packet over UDP");
                transport.send(packet.encode(), SendOptions::default()).await?;
            }
            datagram = transport.receive() => {
                let datagram = datagram?;
                tracing::debug!(peer = %datagram.peer, bytes = datagram.payload.len(), "received UDP datagram");
                if datagram.peer != config.server {
                    tracing::warn!(peer = %datagram.peer, "discarding packet from an unexpected peer");
                    continue;
                }
                let packet = match Packet::decode(datagram.payload) {
                    Ok(packet) if packet.header.kind == PacketKind::Data => packet,
                    Ok(_) => { tracing::warn!("discarding non-data packet after handshake"); continue; }
                    Err(error) => { tracing::warn!(%error, "discarding malformed RVPN packet"); continue; }
                };
                match session.open(packet) {
                    Ok(packet) => {
                        tracing::debug!(bytes = packet.len(), "writing authenticated IP packet to TUN");
                        tun.send(&packet).await?
                    }
                    Err(error) => tracing::warn!(%error, "discarding unauthenticated or replayed RVPN packet"),
                }
            }
        }
    }
}
