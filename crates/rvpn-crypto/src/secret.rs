use rand::{TryRng, rngs::SysRng};
use zeroize::Zeroize;

use crate::CryptoError;

pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    pub fn random() -> Result<Self, CryptoError> {
        let mut bytes = [0; N];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(CryptoError::Randomness)?;
        Ok(Self(bytes))
    }

    fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    Ok(Secret::<N>::random()?.0)
}


