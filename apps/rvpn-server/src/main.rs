use anyhow::{Context, Result, bail};
use rvpn_config::ServerConfig;
use rvpn_crypto::{AEAD_TAG_LEN, HandshakePsk};
use rvpn_interface::{DEFAULT_MTU, TunConfig, TunDevice};
use rvpn_protocol::{HEADER_LEN, HandshakeMessage, Header, Packet, PacketKind, ResponderHandshake};
use rvpn_transport::{SendOptions, TransportConfig, UdpTransport};
use std::{env, fs};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let path = env::args()
        .nth(1)
        .context("usage: rvpn-server <server.toml>")?;
    let config = ServerConfig::from_toml(&fs::read_to_string(path)?)?;
    let tun_config = TunConfig {
        name: config.interface.name.clone(),
        mtu: config.interface.mtu.unwrap_or(DEFAULT_MTU),
    };
    let transport = UdpTransport::open(TransportConfig {
        local_address: config.bind,
        remote_address: None,
        max_datagram_size: usize::from(tun_config.mtu) + HEADER_LEN + AEAD_TAG_LEN,
    })
    .await?;
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
    let mut session = handshake.finish(HandshakeMessage::decode(finish_packet.payload)?)?;
    let peer = finish_datagram.peer;
    let tun = TunDevice::create(tun_config).await?;
    tracing::info!(session_id = ?session.session_id(), %peer, interface = %tun.name(), mtu = tun.mtu(), "authenticated RVPN server data plane started for one peer");

    loop {
        tokio::select! {
            packet = tun.recv() => {
                let packet = packet?;
                tracing::debug!(bytes = packet.len(), "received IP packet from TUN");
                let packet = session.seal(PacketKind::Data, &packet)?;
                tracing::debug!(bytes = packet.payload.len(), sequence = packet.header.sequence, "sending protected packet over UDP");
                transport.send_to(peer, packet.encode(), SendOptions::default()).await?;
            }
            datagram = transport.receive() => {
                let datagram = datagram?;
                tracing::debug!(peer = %datagram.peer, bytes = datagram.payload.len(), "received UDP datagram");
                if datagram.peer != peer {
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
