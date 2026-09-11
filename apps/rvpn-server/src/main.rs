use anyhow::{Context, Result, bail};
use rvpn_config::ServerConfig;
use rvpn_crypto::HandshakePsk;
use rvpn_protocol::{HandshakeMessage, Header, Packet, PacketKind, ResponderHandshake};
use rvpn_transport::{SendOptions, TransportConfig, UdpTransport};
use std::{env, fs};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let path = env::args()
        .nth(1)
        .context("usage: rvpn-server <server.toml>")?;
    let config = ServerConfig::from_toml(&fs::read_to_string(path)?)?;
    let transport = UdpTransport::open(TransportConfig::new(config.bind)).await?;
    tracing::info!(bind = %transport.local_addr()?, "rvpn server waiting for one handshake");
    let initiation_datagram = transport.receive().await?;
    let initiation_packet = Packet::decode(initiation_datagram.payload)?;
    if initiation_packet.header.kind != PacketKind::Handshake
        || initiation_packet.header.key_phase != 0
        || initiation_packet.header.sequence != 0
        || initiation_packet.header.session_id != rvpn_core::SessionId::new([0; 16])
    {
        bail!("expected an RVPN handshake initiation");
    }
    let initiation = HandshakeMessage::decode(initiation_packet.payload)?;
    let (handshake, response) = ResponderHandshake::accept(
        HandshakePsk::from_bytes(config.pre_shared_key_bytes()?),
        initiation,
    )?;
    let session_id = match response {
        HandshakeMessage::Response { session_id, .. } => session_id,
        _ => unreachable!(),
    };
    let response_packet = Packet {
        header: Header {
            kind: PacketKind::Handshake,
            key_phase: 0,
            sequence: 0,
            session_id,
        },
        payload: response.encode(),
    };
    transport
        .send_to(
            initiation_datagram.peer,
            response_packet.encode(),
            SendOptions::default(),
        )
        .await?;
    let finish_datagram = transport.receive().await?;
    if finish_datagram.peer != initiation_datagram.peer {
        bail!("received handshake finish from a different peer");
    }
    let finish_packet = Packet::decode(finish_datagram.payload)?;
    if finish_packet.header.kind != PacketKind::Handshake
        || finish_packet.header.session_id != session_id
    {
        bail!("invalid RVPN handshake finish");
    }
    let session = handshake.finish(HandshakeMessage::decode(finish_packet.payload)?)?;
    tracing::info!(session_id = ?session.session_id(), peer = %finish_datagram.peer, "authenticated RVPN session established; packet forwarding is not implemented yet");
    Ok(())
}
