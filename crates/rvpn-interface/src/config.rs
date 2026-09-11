use crate::InterfaceError;

/// Default L3 payload limit exposed by a newly created device.
pub const DEFAULT_MTU: u16 = 1400;
const MIN_MTU: u16 = 576;
const LINUX_IF_NAME_MAX: usize = 15;

/// Creation and I/O limits for a TUN device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunConfig {
    /// Requested name; omit it to let Linux assign a name such as `tun0`.
    pub name: Option<String>,
    /// Kernel MTU and maximum accepted packet length.
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            mtu: DEFAULT_MTU,
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
