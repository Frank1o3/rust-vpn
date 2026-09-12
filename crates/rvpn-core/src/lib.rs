//! Shared, protocol-agnostic RVPN foundations.

use thiserror::Error;

/// Identifier assigned to an RVPN session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId([u8; Self::LENGTH]);

impl SessionId {
    /// Number of bytes in an RVPN session identifier.
    pub const LENGTH: usize = 16;

    /// The all-zero session identifier, used as the unestablished-session sentinel
    /// in initial handshake packets before a real session has been assigned.
    pub const ZERO: Self = Self([0; Self::LENGTH]);

    /// Creates an identifier from its wire representation.
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the identifier's wire representation.
    pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }
}

/// Errors shared by RVPN's lower-level crates.
#[derive(Debug, Error)]
pub enum Error {
    /// Input did not satisfy a required invariant.
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
}
