//! Embedded DNS forwarding service for RVPN tunnel addresses.

use anyhow::{Context, Result, bail};
use hickory_server::{
    Server,
    proto::rr::Name,
    resolver::config::{NameServerConfig, ResolverOpts},
    store::blocklist::{BlocklistConfig, BlocklistZoneHandler},
    store::forwarder::{ForwardConfig, ForwardZoneHandler},
    zone_handler::{Catalog, ZoneHandler},
};
use ipnet::IpNet;
use std::{
    io::Cursor,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

/// Runs the DNS proxy on each supplied tunnel address using standard DNS port 53.
///
/// Both UDP and TCP DNS are available. Access is restricted to the configured
/// tunnel networks, and queries are forwarded to the configured upstreams.
pub async fn start(
    listen_addresses: &[IpAddr],
    allowed_networks: &[IpNet],
    upstreams: &[SocketAddr],
) -> Result<RunningServer> {
    start_with_options(
        listen_addresses,
        allowed_networks,
        upstreams,
        DnsOptions::default(),
    )
    .await
}

/// Resolver controls for the embedded DNS forwarder.
#[derive(Clone, Debug)]
pub struct DnsOptions {
    /// Maximum time to wait for an upstream response.
    pub timeout: Duration,
    /// Number of retries after an upstream request fails.
    pub attempts: usize,
    /// Maximum number of DNS responses kept in the TTL-aware cache. Zero disables caching.
    pub cache_entries: u64,
    /// Domains to block, including subdomains.
    pub blocked_domains: Vec<String>,
}

impl Default for DnsOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            attempts: 2,
            cache_entries: 1024,
            blocked_domains: Vec::new(),
        }
    }
}

pub async fn start_with_options(
    listen_addresses: &[IpAddr],
    allowed_networks: &[IpNet],
    upstreams: &[SocketAddr],
    options: DnsOptions,
) -> Result<RunningServer> {
    start_on_port_with_options(listen_addresses, allowed_networks, upstreams, 53, options)
        .await
        .map(|(server, _)| server)
}

#[cfg(test)]
async fn start_on_port(
    listen_addresses: &[IpAddr],
    allowed_networks: &[IpNet],
    upstreams: &[SocketAddr],
    port: u16,
) -> Result<(RunningServer, Vec<SocketAddr>)> {
    start_on_port_with_options(
        listen_addresses,
        allowed_networks,
        upstreams,
        port,
        DnsOptions::default(),
    )
    .await
}

async fn start_on_port_with_options(
    listen_addresses: &[IpAddr],
    allowed_networks: &[IpNet],
    upstreams: &[SocketAddr],
    port: u16,
    options: DnsOptions,
) -> Result<(RunningServer, Vec<SocketAddr>)> {
    if listen_addresses.is_empty() {
        bail!("DNS forwarding requires at least one tunnel address");
    }
    if upstreams.is_empty() {
        bail!("DNS forwarding requires at least one upstream server");
    }
    if !(Duration::from_millis(100)..=Duration::from_secs(30)).contains(&options.timeout) {
        bail!("DNS upstream timeout must be between 100 ms and 30 seconds");
    }
    if !(1..=5).contains(&options.attempts) {
        bail!("DNS upstream attempts must be between 1 and 5");
    }
    if options.cache_entries > 65_536 {
        bail!("DNS cache capacity must not exceed 65536 responses");
    }

    let mut name_servers = Vec::with_capacity(upstreams.len());
    for upstream in upstreams {
        let mut config = NameServerConfig::udp_and_tcp(upstream.ip());
        for connection in &mut config.connections {
            connection.port = upstream.port();
        }
        name_servers.push(config);
    }

    let mut resolver_options = ResolverOpts::default();
    resolver_options.timeout = options.timeout;
    resolver_options.attempts = options.attempts;
    resolver_options.cache_size = options.cache_entries;

    let forwarder = ForwardZoneHandler::builder_tokio(ForwardConfig {
        name_servers,
        options: Some(resolver_options),
    })
    .with_origin(Name::root())
    .build()
    .map_err(|error| anyhow::anyhow!("building DNS forwarder: {error}"))?;

    let mut handlers: Vec<Arc<dyn ZoneHandler>> = Vec::new();
    if !options.blocked_domains.is_empty() {
        let mut blocklist = BlocklistZoneHandler::try_from_config(
            Name::root(),
            BlocklistConfig {
                wildcard_match: true,
                min_wildcard_depth: 2,
                ..BlocklistConfig::default()
            },
            None,
        )
        .map_err(|error| anyhow::anyhow!("creating DNS blocklist: {error}"))?;
        blocklist
            .add(Cursor::new(options.blocked_domains.join("\n")))
            .context("loading configured DNS blocked domains")?;
        handlers.push(Arc::new(blocklist));
    }
    handlers.push(Arc::new(forwarder));

    let mut catalog = Catalog::new();
    catalog.upsert(Name::root().into(), handlers);
    let mut server = Server::with_access(catalog, [], allowed_networks.iter().copied());

    let mut bound_addresses = Vec::with_capacity(listen_addresses.len());
    for address in listen_addresses {
        let bind = SocketAddr::new(*address, port);
        let udp = UdpSocket::bind(bind)
            .await
            .with_context(|| format!("binding DNS UDP listener to {bind}"))?;
        let bound = udp.local_addr()?;
        let tcp = TcpListener::bind(bound)
            .await
            .with_context(|| format!("binding DNS TCP listener to {bound}"))?;
        bound_addresses.push(bound);
        server.register_socket(udp);
        server.register_listener(tcp, Duration::from_secs(5), 65535);
    }

    tracing::info!(?listen_addresses, ?upstreams, "RVPN DNS forwarder started");
    let shutdown = server.shutdown_token().clone();
    let task = tokio::spawn(async move { server.block_until_done().await });
    Ok((RunningServer { shutdown, task }, bound_addresses))
}

/// Handle for gracefully stopping the DNS listeners.
pub struct RunningServer {
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), hickory_server::net::NetError>>,
}

impl RunningServer {
    /// Stops the listeners and waits for the server tasks to finish.
    pub async fn shutdown(self) -> Result<()> {
        self.shutdown.cancel();
        self.task
            .await
            .context("joining DNS server task")?
            .map_err(|error| anyhow::anyhow!("DNS server stopped with an error: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UdpSocket},
        time::timeout,
    };

    fn query() -> Vec<u8> {
        let mut message = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(&[
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        ]);
        message.extend_from_slice(&[3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        message
    }

    fn upstream_response(mut request: Vec<u8>) -> Vec<u8> {
        request[2] |= 0x80; // response
        request[3] |= 0x80; // recursion available
        request
    }

    #[tokio::test]
    async fn forwards_udp_and_tcp_queries_to_configured_upstream() {
        let upstream = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            for _ in 0..2 {
                let mut buffer = [0; 4096];
                let (length, peer) = upstream.recv_from(&mut buffer).await.unwrap();
                let response = upstream_response(buffer[..length].to_vec());
                upstream.send_to(&response, peer).await.unwrap();
            }
        });

        let tunnel_address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let allowed: IpNet = "127.0.0.0/8".parse().unwrap();
        let (server, listeners) =
            start_on_port(&[tunnel_address], &[allowed], &[upstream_address], 0)
                .await
                .unwrap();
        let listener = listeners[0];

        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let question = query();
        udp.send_to(&question, listener).await.unwrap();
        let mut response = [0; 4096];
        let (response_length, _) = timeout(Duration::from_secs(3), udp.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..2], &[0x12, 0x34]);
        assert_ne!(response[2] & 0x80, 0);
        assert!(response_length >= 12);

        let mut tcp = timeout(Duration::from_secs(3), TcpStream::connect(listener))
            .await
            .unwrap()
            .unwrap();
        tcp.write_u16(question.len() as u16).await.unwrap();
        tcp.write_all(&question).await.unwrap();
        let response_length = timeout(Duration::from_secs(3), tcp.read_u16())
            .await
            .unwrap()
            .unwrap() as usize;
        let mut response = vec![0; response_length];
        timeout(Duration::from_secs(3), tcp.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..2], &[0x12, 0x34]);
        assert_ne!(response[2] & 0x80, 0);

        server.shutdown().await.unwrap();
        upstream_task.await.unwrap();
    }
}
