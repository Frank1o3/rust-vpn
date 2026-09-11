use std::time::Duration;

/// Whether transport-level acknowledgement and retry are required.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Reliability {
    /// Send once; UDP loss is not reported or retried.
    #[default]
    Unreliable,
    /// Future transport implementations must acknowledge and retry this packet.
    Reliable,
}

/// Whether receive delivery must preserve submission order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Ordering {
    /// The receiver may expose packets in arrival order.
    #[default]
    Unordered,
    /// A future implementation must buffer packets until ordering can be honored.
    Ordered,
}

/// Delivery requirements, deliberately modeled as independent dimensions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeliveryMode {
    /// Reliability requirement.
    pub reliability: Reliability,
    /// Ordering requirement.
    pub ordering: Ordering,
}

impl DeliveryMode {
    /// A one-shot UDP send with no delivery acknowledgement.
    pub const UNRELIABLE: Self = Self {
        reliability: Reliability::Unreliable,
        ordering: Ordering::Unordered,
    };
    /// An acknowledged but unordered delivery requirement.
    pub const RELIABLE: Self = Self {
        reliability: Reliability::Reliable,
        ordering: Ordering::Unordered,
    };
    /// An ordered but not implicitly reliable delivery requirement.
    pub const ORDERED: Self = Self {
        reliability: Reliability::Unreliable,
        ordering: Ordering::Ordered,
    };
}

/// Scheduling importance. Priority never changes delivery guarantees.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum Priority {
    Low,
    #[default]
    Normal,
    High,
    Critical,
}

/// Explicit requirements attached to an outbound opaque payload.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SendOptions {
    /// Requested delivery behavior.
    pub delivery: DeliveryMode,
    /// Requested scheduling priority.
    pub priority: Priority,
    /// Future upper bound for transport-level delivery.
    pub timeout: Option<Duration>,
    /// Future upper bound for reliable retransmissions.
    pub max_retries: Option<u8>,
}
