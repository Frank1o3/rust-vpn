//! RVPN framing, handshake messages, and replay metadata.
//!
//! Protocol headers are serialized as AEAD additional authenticated data by the
//! session coordinator. This crate does not implement encryption itself.

mod authenticated_handshake;
mod handshake;
mod packet;
mod replay;
mod session;

pub use authenticated_handshake::{HandshakeError, InitiatorHandshake, ResponderHandshake};
pub use handshake::{HandshakeMessage, HandshakeRole, HandshakeState, HandshakeTranscript};
pub use packet::{HEADER_LEN, Header, Packet, PacketKind, ProtocolError, VERSION};
pub use replay::{ReplayError, ReplayWindow};
pub use session::{ProtectedSession, SessionError};
