use thiserror::Error;
mod state;

pub use state::{GuiSnapshot, GuiState, GuiStateHandle, format_bytes, format_duration};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId([u8; Self::LENGTH]);

impl SessionId {
    pub const LENGTH: usize = 16;
    pub const ZERO: Self = Self([0; Self::LENGTH]);

    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
}
