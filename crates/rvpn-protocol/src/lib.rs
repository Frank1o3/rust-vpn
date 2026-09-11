//! RVPN framing, handshake messages, and replay metadata.
//!
//! Protocol headers are serialized as AEAD additional authenticated data by the
//! session coordinator. This crate does not implement encryption itself.

mod handshake;
mod packet;
mod replay;

pub use handshake::{HandshakeMessage, HandshakeRole, HandshakeState};
pub use packet::{Header, Packet, PacketKind, ProtocolError, VERSION};
pub use replay::{ReplayError, ReplayWindow};
