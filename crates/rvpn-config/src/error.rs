use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid TOML configuration: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
    #[error(
        "pre_shared_key, identity seeds, and public keys must be exactly 32 bytes encoded as hexadecimal"
    )]
    InvalidPreSharedKey,
    #[error("certificate values must be exactly 112 bytes encoded as hexadecimal")]
    InvalidCertificateEncoding,
    #[error("failed to resolve server endpoint '{host}': {source}")]
    Resolution {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("server endpoint '{0}' did not resolve to any address")]
    NoResolvedAddress(String),
    #[error("[[links]] references unknown peer '{0}'")]
    UnknownLinkPeer(String),
    #[error("duplicate peer name '{0}'; peer names must be unique so links are unambiguous")]
    DuplicatePeerName(String),
}
