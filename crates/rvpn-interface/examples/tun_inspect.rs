use rvpn_interface::{TunConfig, TunDevice};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tun = TunDevice::create(TunConfig::default()).await?;
    println!("created {} with MTU {}", tun.name(), tun.mtu());
    loop {
        println!("received {} IP bytes", tun.recv().await?.len());
    }
}
