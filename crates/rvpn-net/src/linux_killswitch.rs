use crate::{KillSwitchSpec, NetError};
use nftnl::{
    Batch, Chain, ChainType, Policy, ProtoFamily, Rule, Table, nft_expr,
};
use std::{
    ffi::CStr,
    net::SocketAddr,
};

const CHAIN_NAME: &CStr = c"output";
const OUTPUT_HOOK_PRIORITY: i32 = -100;

fn table_name(uid: u32) -> String {
    format!("rvpn_ks_{uid}")
}

pub fn install(spec: &KillSwitchSpec) -> Result<(), NetError> {
    delete_table(spec.uid)?;

    let table_name = table_name(spec.uid);
    let table_c = std::ffi::CString::new(table_name.clone())
        .map_err(|_| NetError::Operation("invalid nftables table name".into()))?;
    let tunnel_c = std::ffi::CString::new(spec.tunnel_interface.clone())
        .map_err(|_| NetError::Operation("invalid tunnel interface name".into()))?;

    let mut batch = Batch::new();
    let table = Table::new(table_c.as_c_str(), ProtoFamily::Inet);
    batch.add(&table, nftnl::MsgType::Add);

    let mut chain = Chain::new(CHAIN_NAME, &table);
    chain.set_type(ChainType::Filter);
    chain.set_hook(nftnl::Hook::Out, OUTPUT_HOOK_PRIORITY);
    chain.set_policy(Policy::Accept);
    batch.add(&chain, nftnl::MsgType::Add);

    add_interface_accept(&mut batch, &chain, spec.uid, b"lo")?;
    add_interface_accept(&mut batch, &chain, spec.uid, tunnel_c.as_bytes())?;
    add_endpoint_accept(&mut batch, &chain, spec.uid, spec.endpoint)?;
    add_uid_drop(&mut batch, &chain, spec.uid);

    send_batch(&batch)?;
    tracing::info!(uid = spec.uid, endpoint = %spec.endpoint, tunnel = %spec.tunnel_interface, "installed persistent RVPN kill switch");
    Ok(())
}

pub fn remove(uid: u32) -> Result<(), NetError> {
    delete_table(uid)
}

fn add_interface_accept(
    batch: &mut Batch,
    chain: &Chain,
    uid: u32,
    interface: &[u8],
) -> Result<(), NetError> {
    let mut rule = Rule::new(chain);
    rule.add_expr(&nft_expr!(meta skuid));
    rule.add_expr(&nft_expr!(cmp == uid));
    rule.add_expr(&nft_expr!(meta oifname));
    rule.add_expr(&nft_expr!(cmp == interface));
    rule.add_expr(&nft_expr!(verdict accept));
    batch.add(&rule, nftnl::MsgType::Add);
    Ok(())
}

fn add_endpoint_accept(
    batch: &mut Batch<'_>,
    chain: &Chain<'_>,
    uid: u32,
    endpoint: SocketAddr,
) -> Result<(), NetError> {
    let mut rule = Rule::new(chain);
    rule.add_expr(&nft_expr!(meta skuid));
    rule.add_expr(&nft_expr!(cmp == uid));
    rule.add_expr(&nft_expr!(meta l4proto));
    rule.add_expr(&nft_expr!(cmp == 17_u8));

    match endpoint.ip() {
        std::net::IpAddr::V4(ip) => {
            rule.add_expr(&nft_expr!(meta nfproto));
            rule.add_expr(&nft_expr!(cmp == 2_u8));
            rule.add_expr(&nft_expr!(payload ipv4 daddr));
            rule.add_expr(&nft_expr!(cmp == ip));
        }
        std::net::IpAddr::V6(ip) => {
            rule.add_expr(&nft_expr!(meta nfproto));
            rule.add_expr(&nft_expr!(cmp == 10_u8));
            rule.add_expr(&nft_expr!(payload ipv6 daddr));
            rule.add_expr(&nft_expr!(cmp == ip));
        }
    }

    rule.add_expr(&nft_expr!(payload udp dport));
    rule.add_expr(&nft_expr!(cmp == endpoint.port().to_be()));
    rule.add_expr(&nft_expr!(verdict accept));
    batch.add(&rule, nftnl::MsgType::Add);
    Ok(())
}

fn add_uid_drop(batch: &mut Batch<'_>, chain: &Chain<'_>, uid: u32) {
    let mut rule = Rule::new(chain);
    rule.add_expr(&nft_expr!(meta skuid));
    rule.add_expr(&nft_expr!(cmp == uid));
    rule.add_expr(&nft_expr!(verdict drop));
    batch.add(&rule, nftnl::MsgType::Add);
}

fn delete_table(uid: u32) -> Result<(), NetError> {
    let table_name = table_name(uid);
    let table_c = std::ffi::CString::new(table_name)
        .map_err(|_| NetError::Operation("invalid nftables table name".into()))?;
    let mut batch = Batch::new();
    let table = Table::new(table_c.as_c_str(), ProtoFamily::Inet);
    batch.add(&table, nftnl::MsgType::Del);
    match send_batch(&batch) {
        Ok(()) => Ok(()),
        Err(error) => {
            // The table not existing is safe during startup/teardown. Preserve other errors.
            let message = error.to_string();
            if message.contains("No such file")
                || message.contains("No such file or directory")
                || message.contains("ENOENT")
            {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

fn send_batch(batch: &Batch<'_>) -> Result<(), NetError> {
    let finalized = batch.finalize();
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)
        .map_err(|e| NetError::Operation(e.to_string()))?;
    let portid = socket.portid();

    socket
        .send_all(&finalized)
        .map_err(|e| NetError::Operation(e.to_string()))?;

    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut expected = finalized.sequence_numbers();

    while !expected.is_empty() {
        for message in socket
            .recv(&mut buffer)
            .map_err(|e| NetError::Operation(e.to_string()))?
        {
            let message =
                message.map_err(|e| NetError::Operation(e.to_string()))?;
            let seq = expected
                .next()
                .ok_or_else(|| NetError::Operation("unexpected nftables ACK".into()))?;
            mnl::cb_run(message, seq, portid)
                .map_err(|e| NetError::Operation(e.to_string()))?;
        }
    }
    Ok(())
}
