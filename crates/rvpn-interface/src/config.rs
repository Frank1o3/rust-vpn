use crate::InterfaceError;
use serde::{Deserialize, Serialize};

pub const DEFAULT_MTU: u16 = 1400;
const MIN_MTU: u16 = 576;
const LINUX_IF_NAME_MAX: usize = 15;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceMode {
    #[default]
    Tun,
    Tap,
    Both,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct TunConfig {
    pub name: Option<String>,
    pub mtu: u16,
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
