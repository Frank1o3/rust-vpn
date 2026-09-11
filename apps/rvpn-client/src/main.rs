use anyhow::{Context, Result, bail};
use rvpn_config::ClientConfig;
use rvpn_core::SessionId;
use rvpn_crypto::HandshakePsk;
use rvpn_protocol::{HandshakeMessage, Header, InitiatorHandshake, Packet, PacketKind};
use rvpn_transport::{SendOptions, TransportConfig, UdpTransport};
use std::{env, fs, net::SocketAddr};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let path = env::args()
        .nth(1)
        .context("usage: rvpn-client <client.toml>")?;
    let config = ClientConfig::from_toml(&fs::read_to_string(path)?)?;
    let transport = UdpTransport::open(TransportConfig {
        local_address: "0.0.0.0:0".parse::<SocketAddr>()?,
        remote_address: Some(config.server),
        max_datagram_size: 1200,
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
    let (finish, session) = handshake.finish(response)?;
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
    tracing::info!(session_id = ?session.session_id(), server = %config.server, "authenticated RVPN session established; packet forwarding is not implemented yet");
    Ok(())
}
