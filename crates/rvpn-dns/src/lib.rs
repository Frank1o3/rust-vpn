//! Embedded DNS forwarding service for RVPN tunnel addresses.

use anyhow::{Context, Result, bail};
use hickory_server::{
    Server,
    proto::rr::Name,
    resolver::config::NameServerConfig,
    store::forwarder::{ForwardConfig, ForwardZoneHandler},
    zone_handler::{Catalog, ZoneHandler},
};
use ipnet::IpNet;
use std::{
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
    start_on_port(listen_addresses, allowed_networks, upstreams, 53)
        .await
        .map(|(server, _)| server)
}

async fn start_on_port(
    listen_addresses: &[IpAddr],
    allowed_networks: &[IpNet],
    upstreams: &[SocketAddr],
    port: u16,
) -> Result<(RunningServer, Vec<SocketAddr>)> {
    if listen_addresses.is_empty() {
        bail!("DNS forwarding requires at least one tunnel address");
    }
    if upstreams.is_empty() {
        bail!("DNS forwarding requires at least one upstream server");
    }

    let mut name_servers = Vec::with_capacity(upstreams.len());
    for upstream in upstreams {
        let mut config = NameServerConfig::udp_and_tcp(upstream.ip());
        for connection in &mut config.connections {
            connection.port = upstream.port();
        }
        name_servers.push(config);
    }

    let forwarder = ForwardZoneHandler::builder_tokio(ForwardConfig {
        name_servers,
        options: None,
    })
    .with_origin(Name::root())
    .build()
    .map_err(|error| anyhow::anyhow!("building DNS forwarder: {error}"))?;

    let mut catalog = Catalog::new();
    catalog.upsert(
        Name::root().into(),
        vec![Arc::new(forwarder) as Arc<dyn ZoneHandler>],
    );
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
