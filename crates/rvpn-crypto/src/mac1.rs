use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const MAC1_LEN: usize = 16;
pub const MAC1_KEY_LEN: usize = 32;

#[derive(Clone)]
pub struct Mac1Key([u8; MAC1_KEY_LEN]);

impl Mac1Key {
    pub fn from_key_material(key_material: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"rvpn-v3/mac1-key");
        hasher.update(key_material);
        Self(hasher.finalize().into())
    }

    pub fn compute(&self, data: &[u8]) -> [u8; MAC1_LEN] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0)
            .expect("fixed-length HMAC keys are always accepted");
        mac.update(b"rvpn-v3/mac1");
        mac.update(data);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; MAC1_LEN];
        out.copy_from_slice(&tag[..MAC1_LEN]);
        out
    }

    pub fn verify(&self, data: &[u8], tag: &[u8; MAC1_LEN]) -> bool {
        let expected = self.compute(data);
        let mut diff = 0u8;
        for i in 0..MAC1_LEN {
            diff |= expected[i] ^ tag[i];
        }
        diff == 0
    }

    pub fn as_bytes(&self) -> &[u8; MAC1_KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Mac1Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Mac1Key([REDACTED])")
    }
}

impl Zeroize for Mac1Key {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Mac1Key {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PartialEq for Mac1Key {
    fn eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for i in 0..MAC1_KEY_LEN {
            diff |= self.0[i] ^ other.0[i];
        }
        diff == 0
    }
}

impl Eq for Mac1Key {}
