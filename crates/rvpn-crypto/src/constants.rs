pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const PSK_LEN: usize = 32;

pub const AEAD_TAG_LEN: usize = 16;

pub(crate) const INFO_C2S: &[u8] = b"rvpn-v1/session/client-to-server";
pub(crate) const INFO_S2C: &[u8] = b"rvpn-v1/session/server-to-client";
