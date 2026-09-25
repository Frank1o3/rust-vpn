use std::{net::SocketAddr, path::PathBuf, time::Duration};

use crate::ConfigError;

pub(crate) fn validate_endpoint(endpoint: SocketAddr) -> Result<(), ConfigError> {
    if endpoint.port() == 0 {
        return Err(ConfigError::Invalid("endpoint port must not be zero"));
    }
    Ok(())
}

pub(crate) fn decode_psk(value: &str) -> Result<[u8; 32], ConfigError> {
    if value.len() != 64 {
        return Err(ConfigError::InvalidPreSharedKey);
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| ConfigError::InvalidPreSharedKey)?;
    Ok(bytes)
}

pub(crate) fn decode_certificate(value: &str) -> Result<[u8; 112], ConfigError> {
    if value.len() != 224 {
        return Err(ConfigError::InvalidCertificateEncoding);
    }
    let mut bytes = [0; 112];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| ConfigError::InvalidCertificateEncoding)?;
    Ok(bytes)
}

pub async fn resolve_endpoint(value: &str) -> Result<SocketAddr, ConfigError> {
    let mut addrs =
        tokio::net::lookup_host(value)
            .await
            .map_err(|source| ConfigError::Resolution {
                host: value.to_string(),
                source,
            })?;
    addrs
        .next()
        .ok_or_else(|| ConfigError::NoResolvedAddress(value.to_string()))
}

pub fn validate_endpoint_syntax(value: &str) -> Result<(), ConfigError> {
    let (_, port_str) = value.rsplit_once(':').ok_or(ConfigError::Invalid(
        "server endpoint must be in host:port or ip:port form",
    ))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| ConfigError::Invalid("server endpoint port must be a valid number"))?;
    if port == 0 {
        return Err(ConfigError::Invalid(
            "server endpoint port must not be zero",
        ));
    }
    Ok(())
}

pub fn jittered_retry_interval(base_ms: u64, jitter_ms: u64) -> Duration {
    if jitter_ms == 0 {
        return Duration::from_millis(base_ms.max(1));
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as u64;
    let span = 2 * jitter_ms + 1;
    let offset = (nanos % span) as i64 - jitter_ms as i64;
    let millis = (base_ms as i64 + offset).max(1) as u64;
    Duration::from_millis(millis)
}

pub fn default_config_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("rvpn");
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("rvpn");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("rvpn");
    }
    PathBuf::from("rvpn")
}

pub fn default_client_config_path() -> PathBuf {
    default_config_dir().join("client.toml")
}

pub fn default_server_config_path() -> PathBuf {
    default_config_dir().join("server.toml")
}

pub fn read_config_file(path: impl AsRef<std::path::Path>) -> Result<String, ConfigError> {
    let path = path.as_ref();
    let metadata = std::fs::metadata(path).map_err(ConfigError::Io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::InsecurePermissions(path.to_path_buf()));
        }
    }

    std::fs::read_to_string(path).map_err(ConfigError::Io)
}