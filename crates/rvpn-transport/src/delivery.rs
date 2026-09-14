use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Reliability {
    #[default]
    Unreliable,
    Reliable,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Ordering {
    #[default]
    Unordered,
    Ordered,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeliveryMode {
    pub reliability: Reliability,
    pub ordering: Ordering,
}

impl DeliveryMode {
    pub const UNRELIABLE: Self = Self {
        reliability: Reliability::Unreliable,
        ordering: Ordering::Unordered,
    };
    pub const RELIABLE: Self = Self {
        reliability: Reliability::Reliable,
        ordering: Ordering::Unordered,
    };
    pub const ORDERED: Self = Self {
        reliability: Reliability::Unreliable,
        ordering: Ordering::Ordered,
    };
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum Priority {
    Low,
    #[default]
    Normal,
    High,
    Critical,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SendOptions {
    pub delivery: DeliveryMode,
    pub priority: Priority,
    pub timeout: Option<Duration>,
    pub max_retries: Option<u8>,
}
