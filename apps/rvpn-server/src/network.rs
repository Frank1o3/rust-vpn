//! Packet inspection, Ethernet decoding, and server interface configuration.

use anyhow::{Context, Result, bail};
use rvpn_config::ServerConfig;
use rvpn_interface::TunDevice;
use std::net::IpAddr;
use tokio::process::Command;

/// Extracts the IPv4 or IPv6 source address from a raw packet.
pub fn packet_source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?)),
        6 if packet.len() >= 40 => Some(IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?)),
        _ => None,
    }
}

/// Extracts the IPv4 or IPv6 destination address from a raw packet.
pub fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?)),
        6 if packet.len() >= 40 => Some(IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?)),
        _ => None,
    }
}

/// Extracts the 6-byte source MAC address from an Ethernet frame.
pub fn ethernet_src_mac(frame: &[u8]) -> Option<[u8; 6]> {
    if frame.len() >= 12 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&frame[6..12]);
        Some(mac)
    } else {
        None
    }
}

/// Checks whether a MAC address is broadcast (FF:FF:FF:FF:FF:FF) or multicast.
pub fn is_broadcast_or_multicast_mac(mac: &[u8; 6]) -> bool {
    mac[0] & 1 == 1
}

/// Extracts IP addresses (IPv4, IPv6, or ARP) encapsulated within an Ethernet frame.
pub fn ethernet_payload_ip(frame: &[u8], is_dest: bool) -> Option<IpAddr> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        0x0800 => {
            let ip_packet = &frame[14..];
            if is_dest {
                packet_destination(ip_packet)
            } else {
                packet_source(ip_packet)
            }
        }
        0x86DD => {
            let ip_packet = &frame[14..];
            if is_dest {
                packet_destination(ip_packet)
            } else {
                packet_source(ip_packet)
            }
        }
        0x0806 => {
            let arp_packet = &frame[14..];
            if arp_packet.len() >= 28 {
                let offset = if is_dest { 24 } else { 14 };
                let ip_bytes: [u8; 4] = arp_packet[offset..offset + 4].try_into().ok()?;
                Some(IpAddr::from(ip_bytes))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Assigns IP addresses and activates the server's virtual interface.
pub async fn configure_server_interface(dev: &TunDevice, config: &ServerConfig) -> Result<()> {
    if config.interface.address.is_some() || !config.interface.addresses.is_empty() {
        for address in config
            .interface
            .address
            .iter()
            .chain(&config.interface.addresses)
        {
            run("ip", ["address", "replace", address, "dev", dev.name()]).await?;
        }
        run("ip", ["link", "set", "dev", dev.name(), "up"]).await?;
    }
    Ok(())
}

/// Executes a system network command, capturing error output on failure.
pub async fn run<'a>(program: &str, args: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .context("running network command")?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "{} failed: {}",
            program,
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}
