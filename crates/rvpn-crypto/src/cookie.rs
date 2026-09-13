//! Stateless anti-DoS cookies for RVPN's initial handshake.
//!
//! A cookie proves that the peer can receive traffic at the claimed UDP
//! endpoint before the server performs expensive asymmetric handshake work.

use crate::{CryptoError, Secret};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::SocketAddr;

const COOKIE_LEN: usize = 32;
const COOKIE_BUCKET_SECONDS: u64 = 60;
const DOMAIN: &[u8] = b"rvpn-v1/handshake/cookie";

/// Stateless server-side cookie signer.
///
/// The secret lives only for the lifetime of the server process. A restart
/// invalidates outstanding cookies, which is intentional.
pub struct CookieKey {
    secret: Secret<32>,
}

impl CookieKey {
    /// Generates a fresh cookie signing key.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            secret: Secret::random()?,
        })
    }

    /// Creates a cookie bound to the peer endpoint and exact initiation.
    pub fn mint(
        &self,
        endpoint: SocketAddr,
        public_key: &[u8; 32],
        random: &[u8; 32],
        now_unix_seconds: u64,
    ) -> [u8; COOKIE_LEN] {
        self.compute(
            endpoint,
            public_key,
            random,
            now_unix_seconds / COOKIE_BUCKET_SECONDS,
        )
    }

    /// Verifies a cookie against the current or immediately previous bucket.
    pub fn verify(
        &self,
        endpoint: SocketAddr,
        public_key: &[u8; 32],
        random: &[u8; 32],
        cookie: &[u8; COOKIE_LEN],
        now_unix_seconds: u64,
    ) -> bool {
        let bucket = now_unix_seconds / COOKIE_BUCKET_SECONDS;

        let current = self.compute(endpoint, public_key, random, bucket);
        if constant_time_eq(&current, cookie) {
            return true;
        }

        if bucket == 0 {
            return false;
        }

        let previous = self.compute(endpoint, public_key, random, bucket - 1);
        constant_time_eq(&previous, cookie)
    }

    fn compute(
        &self,
        endpoint: SocketAddr,
        public_key: &[u8; 32],
        random: &[u8; 32],
        bucket: u64,
    ) -> [u8; COOKIE_LEN] {
        let mut input = Vec::with_capacity(128);
        input.extend_from_slice(DOMAIN);
        input.extend_from_slice(&bucket.to_be_bytes());

        match endpoint {
            SocketAddr::V4(addr) => {
                input.push(4);
                input.extend_from_slice(&addr.ip().octets());
                input.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                input.push(6);
                input.extend_from_slice(&addr.ip().octets());
                input.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        input.extend_from_slice(public_key);
        input.extend_from_slice(random);

        let mut mac = Hmac::<Sha256>::new_from_slice(self.secret.as_bytes())
            .expect("fixed-size HMAC key is always valid");
        mac.update(&input);
        mac.finalize().into_bytes().into()
    }
}

fn constant_time_eq(a: &[u8; COOKIE_LEN], b: &[u8; COOKIE_LEN]) -> bool {
    let mut difference = 0u8;

    for index in 0..COOKIE_LEN {
        difference |= a[index] ^ b[index];
    }

    difference == 0
}