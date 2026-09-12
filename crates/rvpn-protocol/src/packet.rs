use bytes::{Buf, Bytes, BytesMut};
use rvpn_core::SessionId;
use thiserror::Error;

/// Current on-wire RVPN version.
pub const VERSION: u8 = 1;
/// Header bytes, which are intended to become AEAD additional authenticated data.
pub const HEADER_LEN: usize = 1 + 1 + 4 + 8 + SessionId::LENGTH;

/// Semantic class of an RVPN packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PacketKind {
    Handshake = 1,
    Data = 2,
    Rekey = 3,
    Close = 4,
    DataTap = 5,
}

impl TryFrom<u8> for PacketKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Handshake),
            2 => Ok(Self::Data),
            3 => Ok(Self::Rekey),
            4 => Ok(Self::Close),
            5 => Ok(Self::DataTap),
            _ => Err(ProtocolError::UnknownPacketKind(value)),
        }
    }
}

/// Metadata used for routing, nonce construction, and authenticated binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    /// Packet interpretation for the protocol state machine.
    pub kind: PacketKind,
    /// Key generation used to derive the packet nonce.
    pub key_phase: u32,
    /// Per-key-phase packet sequence number.
    pub sequence: u64,
    /// Session to which this packet belongs.
    pub session_id: SessionId,
}

impl Header {
    /// Serializes this header for use as the exact AEAD additional data.
    pub fn encode(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0; HEADER_LEN];
        bytes[0] = VERSION;
        bytes[1] = self.kind as u8;
        bytes[2..6].copy_from_slice(&self.key_phase.to_be_bytes());
        bytes[6..14].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[14..].copy_from_slice(&self.session_id.into_bytes());
        bytes
    }
}

/// One complete RVPN datagram. Data payloads are normally AEAD ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    /// Authenticated metadata.
    pub header: Header,
    /// Opaque protocol payload.
    pub payload: Bytes,
}

impl Packet {
    /// Serializes one packet without inspecting its opaque payload.
    pub fn encode(&self) -> Bytes {
        let mut output = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        output.extend_from_slice(&self.header.encode());
        output.extend_from_slice(&self.payload);
        output.freeze()
    }

    /// Parses a complete packet datagram.
    pub fn decode(mut input: Bytes) -> Result<Self, ProtocolError> {
        if input.remaining() < HEADER_LEN {
            return Err(ProtocolError::TruncatedHeader);
        }
        let version = input.get_u8();
        if version != VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let kind = PacketKind::try_from(input.get_u8())?;
        let key_phase = input.get_u32();
        let sequence = input.get_u64();
        let mut session_id = [0; SessionId::LENGTH];
        input.copy_to_slice(&mut session_id);
        Ok(Self {
            header: Header {
                kind,
                key_phase,
                sequence,
                session_id: SessionId::new(session_id),
            },
            payload: input,
        })
    }
}

/// Framing and validation failures.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProtocolError {
    #[error("packet header is truncated")]
    TruncatedHeader,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown packet kind {0}")]
    UnknownPacketKind(u8),
    #[error("invalid handshake message")]
    InvalidHandshake,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_round_trip_and_header_aad_are_stable() {
        let packet = Packet {
            header: Header {
                kind: PacketKind::Data,
                key_phase: 3,
                sequence: 7,
                session_id: SessionId::new([9; 16]),
            },
            payload: Bytes::from_static(b"payload"),
        };
        assert_eq!(Packet::decode(packet.encode()).unwrap(), packet);
        assert_eq!(packet.header.encode().len(), HEADER_LEN);
    }

    #[test]
    fn rejects_malformed_packet_kind() {
        let mut bytes = Header {
            kind: PacketKind::Data,
            key_phase: 0,
            sequence: 0,
            session_id: SessionId::new([0; 16]),
        }
        .encode();
        bytes[1] = 99;
        assert_eq!(
            Packet::decode(Bytes::copy_from_slice(&bytes)),
            Err(ProtocolError::UnknownPacketKind(99))
        );
    }

    #[test]
    fn datatap_round_trip() {
        let packet = Packet {
            header: Header {
                kind: PacketKind::DataTap,
                key_phase: 1,
                sequence: 42,
                session_id: SessionId::new([7; 16]),
            },
            payload: Bytes::from_static(b"ethernet-frame"),
        };
        assert_eq!(Packet::decode(packet.encode()).unwrap(), packet);
    }
}
