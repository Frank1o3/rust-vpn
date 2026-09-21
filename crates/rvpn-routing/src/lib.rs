pub mod packet;

mod router;

pub use router::{Delivery, DropReason, Links, MAX_MACS_PER_PEER, Router, Verdict};

#[cfg(test)]
mod tests;
