use crate::InterfaceError;
use serde::{Deserialize, Serialize};

/// Default L3 payload limit exposed by a newly created device.
pub const DEFAULT_MTU: u16 = 1400;
const MIN_MTU: u16 = 576;
const LINUX_IF_NAME_MAX: usize = 15;

/// Operating mode for the virtual interface.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceMode {
    /// Layer-3 virtual interface (raw IPv4 / IPv6 packets).
    #[default]
    Tun,
    /// Layer-2 virtual interface (Ethernet frames).
    Tap,
    /// Dual-stack virtual interfaces (both TUN and TAP running concurrently).
    Both,
}

/// Creation and I/O limits for a virtual TUN/TAP device.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct TunConfig {
    /// Requested name; omit it to let Linux assign a name such as `tun0` or `tap0`.
    pub name: Option<String>,
    /// Kernel MTU and maximum accepted packet length.
    pub mtu: u16,
    /// Virtual interface operating mode.
    #[serde(default)]
    pub mode: DeviceMode,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            mtu: DEFAULT_MTU,
            mode: DeviceMode::default(),
        }
    }
}

impl TunConfig {
    /// Validates values before any privileged OS operation is attempted.
    pub fn validate(&self) -> Result<(), InterfaceError> {
        if self.mtu < MIN_MTU {
            return Err(InterfaceError::InvalidMtu(self.mtu));
        }
        if let Some(name) = &self.name {
            if name.is_empty() || name.len() > LINUX_IF_NAME_MAX || name.as_bytes().contains(&0) {
                return Err(InterfaceError::InvalidInterfaceName);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_name_and_mtu() {
        assert!(
            TunConfig {
                name: Some("".into()),
                ..TunConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            TunConfig {
                mtu: 575,
                ..TunConfig::default()
            }
            .validate()
            .is_err()
        );
    }
}
