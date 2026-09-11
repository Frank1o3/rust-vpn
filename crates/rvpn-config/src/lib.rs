//! TOML configuration parsing and validation for RVPN applications.

use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};
use thiserror::Error;

/// Common configuration accepted by RVPN applications.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    /// UDP address to bind or contact, depending on the application.
    pub endpoint: SocketAddr,
    /// Optional path to a future persistent identity or key configuration.
    pub identity_file: Option<PathBuf>,
}

impl Config {
    /// Parses and validates TOML configuration.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Validates configuration invariants independent of parsing.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.endpoint.port() == 0 {
            return Err(ConfigError::Invalid("endpoint port must not be zero"));
        }
        Ok(())
    }
}

/// Configuration parsing and validation errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid TOML configuration: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_toml() {
        let config = Config::from_toml("endpoint = '127.0.0.1:9000'").unwrap();
        assert_eq!(config.endpoint.port(), 9000);
    }
}
