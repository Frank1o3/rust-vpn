//! RVPN packet framing and protocol-level validation.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use rvpn_core::SessionId;
use thiserror::Error;

/// The current on-wire protocol version.
pub const VERSION: u8 = 1;
const HEADER_LEN: usize = 1 + 1 + 8 + SessionId::LENGTH;

/// The class of an RVPN packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PacketKind {
    Handshake = 1,
    Data = 2,
    Rekey = 3,
    Close = 4,
}

impl TryFrom<u8> for PacketKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Handshake),
            2 => Ok(Self::Data),
            3 => Ok(Self::Rekey),
            4 => Ok(Self::Close),
            _ => Err(ProtocolError::UnknownPacketKind(value)),
        }
    }
}

/// Metadata that remains available to the protocol before packet protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    /// How the packet payload is interpreted by the protocol state machine.
    pub kind: PacketKind,
    /// Per-session packet sequence number, reserved for replay and ordering policy.
    pub sequence: u64,
    /// Session to which this packet belongs.
    pub session_id: SessionId,
}

/// A framed RVPN packet. Payload protection is intentionally outside this crate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    /// Packet routing and sequencing metadata.
    pub header: Header,
    /// Protocol payload; its protection is selected by the session layer.
    pub payload: Bytes,
}

impl Packet {
    /// Serializes the packet to its RVPN wire format.
    pub fn encode(&self) -> Bytes {
        let mut output = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        output.put_u8(VERSION);
        output.put_u8(self.header.kind as u8);
        output.put_u64(self.header.sequence);
        output.extend_from_slice(&self.header.session_id.into_bytes());
        output.extend_from_slice(&self.payload);
        output.freeze()
    }

    /// Parses one complete RVPN packet.
    pub fn decode(mut input: Bytes) -> Result<Self, ProtocolError> {
        if input.remaining() < HEADER_LEN {
            return Err(ProtocolError::TruncatedHeader);
        }
        let version = input.get_u8();
        if version != VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let kind = PacketKind::try_from(input.get_u8())?;
        let sequence = input.get_u64();
        let mut session_id = [0; SessionId::LENGTH];
        input.copy_to_slice(&mut session_id);
        Ok(Self {
            header: Header {
                kind,
                sequence,
                session_id: SessionId::new(session_id),
            },
            payload: input,
        })
    }
}

/// Protocol framing and validation failures.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProtocolError {
    #[error("packet header is truncated")]
    TruncatedHeader,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown packet kind {0}")]
    UnknownPacketKind(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_round_trip() {
        let packet = Packet {
            header: Header {
                kind: PacketKind::Data,
                sequence: 7,
                session_id: SessionId::new([9; 16]),
            },
            payload: Bytes::from_static(b"payload"),
        };
        assert_eq!(Packet::decode(packet.encode()).unwrap(), packet);
    }
}
