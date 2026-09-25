use thiserror::Error;
mod state;

pub use state::{GuiSnapshot, GuiState, GuiStateHandle, format_bytes, format_duration};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId([u8; Self::LENGTH]);

pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(31, 1);

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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProtocolVersion {
    encoded: u8,
    minor_digits: u8,
    pub major: u8,
    pub minor: u8,
}

impl ProtocolVersion {
    pub const fn new(encoded: u8, minor_digits: u8) -> Self {
        assert!(
            minor_digits > 0 && minor_digits <= 2,
            "minor_digits must be between 1 and 2 for u8 encoding"
        );

        let scale = Self::scale(minor_digits);
        let major = encoded / scale;
        let minor = encoded % scale;

        Self {
            encoded,
            minor_digits,
            major,
            minor,
        }
    }

    const fn scale(digits: u8) -> u8 {
        let mut scale = 1;
        let mut i = 0;

        while i < digits {
            scale *= 10;
            i += 1;
        }

        scale
    }

    pub const fn encoded(self) -> u8 {
        self.encoded
    }

    pub const fn minor_digits(self) -> u8 {
        self.minor_digits
    }

    fn append_domain_version(self, output: &mut Vec<u8>) {
        output.extend_from_slice(b"rvpn-v");

        output.extend_from_slice(self.major.to_string().as_bytes());

        output.push(b'.');

        let width = self.minor_digits as usize;
        output.extend(format!("{:0width$}", self.minor, width = width).as_bytes());
    }
}

pub fn domain(suffix: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(32);

    PROTOCOL_VERSION.append_domain_version(&mut output);
    output.extend_from_slice(suffix);

    output
}

#[test]
fn protocol_version_decodes_encoded_value() {
    let version = ProtocolVersion::new(30, 1);

    assert_eq!(version.encoded(), 30);
    assert_eq!(version.major, 3);
    assert_eq!(version.minor, 0);
    assert_eq!(version.minor_digits(), 1);
}

#[test]
fn protocol_version_handles_minor_revision() {
    let version = ProtocolVersion::new(37, 1);

    assert_eq!(version.major, 3);
    assert_eq!(version.minor, 7);
}

#[test]
fn domain_uses_current_protocol_version() {
    assert_eq!(domain(b"/handshake/cookie"), b"rvpn-v3.0/handshake/cookie");
}

#[test]
fn domain_changes_when_protocol_version_changes() {
    let version = ProtocolVersion::new(37, 1);
    let mut output = Vec::new();

    version.append_domain_version(&mut output);
    output.extend_from_slice(b"/test");

    assert_eq!(output, b"rvpn-v3.7/test");
}
