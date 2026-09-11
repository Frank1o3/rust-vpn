//! Cryptographic boundaries for RVPN.
//!
//! This crate intentionally defines no custom cipher or handshake construction.
//! Concrete, reviewed primitives will be selected after the protocol threat model
//! and handshake are specified.

use rand::{TryRng, rngs::SysRng};
use thiserror::Error;
use zeroize::Zeroize;

/// A secret value whose memory is cleared when it is dropped.
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    /// Obtains secret bytes from the operating system's cryptographic RNG.
    pub fn random() -> Result<Self, CryptoError> {
        let mut bytes = [0; N];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(CryptoError::Randomness)?;
        Ok(Self(bytes))
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> core::fmt::Debug for Secret<N> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("Secret")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// Failures while handling RVPN cryptographic material.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("secure randomness is unavailable: {0}")]
    Randomness(#[source] rand::rngs::SysError),
}
