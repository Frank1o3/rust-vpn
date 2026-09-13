//! Generates a CA identity, a peer identity, and a certificate binding the
//! peer to the CA, printing hex-encoded values ready to paste into RVPN
//! TOML configuration.
//!
//! Run with: cargo run -p rvpn-crypto --example gen_ca_and_cert

use rvpn_crypto::IdentityKeyPair;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ten_years = 10 * 365 * 24 * 60 * 60;

    let ca = IdentityKeyPair::generate().expect("secure randomness available");
    let peer = IdentityKeyPair::generate().expect("secure randomness available");
    let certificate = ca.issue_certificate(peer.public_key(), now, now + ten_years);

    println!("# --- Certificate Authority ---");
    println!("# Keep ca_seed offline; only ca_public_key goes in server config.");
    println!("ca_seed = \"{}\"", hex::encode(ca.to_seed_bytes()));
    println!(
        "ca_public_key = \"{}\"",
        hex::encode(ca.public_key().to_bytes())
    );
    println!();
    println!("# --- Issued peer identity (paste into that peer's config) ---");
    println!(
        "local_identity_seed = \"{}\"",
        hex::encode(peer.to_seed_bytes())
    );
    println!(
        "local_certificate = \"{}\"",
        hex::encode(certificate.encode())
    );
    println!("# subject public key (server certificate_authority.peer_overrides key):");
    println!("# {}", hex::encode(peer.public_key().to_bytes()));
}
