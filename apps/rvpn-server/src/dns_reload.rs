use anyhow::{Context, Result};
use ipnet::IpNet;
use rvpn_config::DnsConfig;
use rvpn_dns::{DnsOptions, RunningServer};
use std::{net::IpAddr, time::Duration};
use tokio::sync::{mpsc, oneshot};

enum Command {
    Replace(DnsConfig, oneshot::Sender<Result<()>>),
    Shutdown(oneshot::Sender<Result<()>>),
}

#[derive(Clone)]
pub struct DnsReloader {
    commands: mpsc::Sender<Command>,
}

impl DnsReloader {
    pub async fn start(
        listen_addresses: Vec<IpAddr>,
        allowed_networks: Vec<IpNet>,
        initial: DnsConfig,
    ) -> Result<Self> {
        let running = start_forwarder(&listen_addresses, &allowed_networks, &initial)
            .await
            .context("starting embedded DNS forwarder")?;
        let (commands, mut receiver) = mpsc::channel(4);
        tokio::spawn(async move {
            let mut config = initial;
            let mut running = running;
            while let Some(command) = receiver.recv().await {
                match command {
                    Command::Replace(next, response) => {
                        let result = replace_forwarder(
                            &listen_addresses,
                            &allowed_networks,
                            &mut running,
                            &mut config,
                            next,
                        )
                        .await;
                        let _ = response.send(result);
                    }
                    Command::Shutdown(response) => {
                        let result = stop_forwarder(&mut running).await;
                        let _ = response.send(result);
                        return;
                    }
                }
            }
            let _ = stop_forwarder(&mut running).await;
        });
        Ok(Self { commands })
    }

    pub async fn replace(&self, config: DnsConfig) -> Result<()> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(Command::Replace(config, response))
            .await
            .context("DNS reload service is unavailable")?;
        result.await.context("DNS reload service stopped")?
    }

    pub async fn shutdown(self) -> Result<()> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(Command::Shutdown(response))
            .await
            .context("DNS reload service is unavailable during shutdown")?;
        result.await.context("DNS reload service stopped")?
    }
}

async fn start_forwarder(
    listen_addresses: &[IpAddr],
    allowed_networks: &[IpNet],
    config: &DnsConfig,
) -> Result<Option<RunningServer>> {
    if config.upstreams.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        rvpn_dns::start_with_options(
            listen_addresses,
            allowed_networks,
            &config.upstreams,
            DnsOptions {
                timeout: Duration::from_millis(config.timeout_ms),
                attempts: config.attempts,
                cache_entries: config.cache_entries,
            },
        )
        .await?,
    ))
}

async fn stop_forwarder(running: &mut Option<RunningServer>) -> Result<()> {
    if let Some(server) = running.take() {
        server.shutdown().await?;
    }
    Ok(())
}

async fn replace_forwarder(
    listen_addresses: &[IpAddr],
    allowed_networks: &[IpNet],
    running: &mut Option<RunningServer>,
    current: &mut DnsConfig,
    next: DnsConfig,
) -> Result<()> {
    if *current == next {
        return Ok(());
    }
    stop_forwarder(running).await?;
    match start_forwarder(listen_addresses, allowed_networks, &next).await {
        Ok(replacement) => {
            *running = replacement;
            *current = next;
            tracing::info!(
                upstreams = ?current.upstreams,
                enabled = !current.upstreams.is_empty(),
                "applied live DNS configuration"
            );
            Ok(())
        }
        Err(error) => {
            match start_forwarder(listen_addresses, allowed_networks, current).await {
                Ok(restored) => {
                    *running = restored;
                    Err(error).context("new DNS configuration failed; previous configuration restored")
                }
                Err(restore_error) => Err(error).context(format!(
                    "new DNS configuration failed and restoring the previous configuration also failed: {restore_error:#}"
                )),
            }
        }
    }
}
