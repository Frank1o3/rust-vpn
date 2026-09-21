pub mod packet;

mod router;

pub use router::{
    Delivery, DropReason, Links, Router, Verdict, MAX_MACS_PER_PEER,
};

#[cfg(test)]
mod tests;
