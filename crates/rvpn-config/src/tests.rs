use std::time::Duration;

use crate::*;

fn seed() -> String {
    "a".repeat(64)
}

fn pubkey() -> String {
    "b".repeat(64)
}

fn pinned_auth_toml(seed_hex: &str, pub_hex: &str) -> String {
    format!("[auth]\nmode = 'pinned-key'\nlocal_identity_seed = '{seed_hex}'\npeer_public_key = '{pub_hex}'\n")
}

#[test]
fn parses_toml() {
    let config = Config::from_toml("endpoint = '127.0.0.1:9000'").unwrap();
    assert_eq!(config.endpoint.port(), 9000);
}

#[test]
fn validates_client_pinned_key_auth() {
    let toml = format!("server = '127.0.0.1:9000'\n{}", pinned_auth_toml(&seed(), &pubkey()));
    let config = ClientConfig::from_toml(&toml).unwrap();
    assert!(config.auth_config().is_ok());
}

#[test]
fn client_without_auth_is_rejected() {
    assert!(ClientConfig::from_toml("server = '127.0.0.1:9000'").is_err());
}

#[test]
fn legacy_pre_shared_key_configuration_is_rejected() {
    let client_toml = format!(
        "server = '127.0.0.1:9000'\npre_shared_key = '{}'",
        "a".repeat(64)
    );
    assert!(ClientConfig::from_toml(&client_toml).is_err());

    let server_toml = format!("bind = '0.0.0.0:9000'\npre_shared_key = '{}'", "a".repeat(64));
    assert!(ServerConfig::from_toml(&server_toml).is_err());

    let peer_psk_toml = format!(
        "bind = '0.0.0.0:9000'\n[[peers]]\nname = 'laptop'\nallowed_ips = ['10.42.0.2/32']\npre_shared_key = '{}'",
        "a".repeat(64)
    );
    assert!(ServerConfig::from_toml(&peer_psk_toml).is_err());
}

#[test]
fn accepts_hostname_shaped_server_syntax() {
    let config = ClientConfig::from_toml(&format!(
        "server = 'main-pc.lan:9000'\n{}",
        pinned_auth_toml(&seed(), &pubkey())
    ))
    .unwrap();
    assert_eq!(config.server, "main-pc.lan:9000");
    assert!(
        ClientConfig::from_toml(&format!(
            "server = 'main-pc.lan'\n{}",
            pinned_auth_toml(&seed(), &pubkey())
        ))
        .is_err()
    );
}

#[tokio::test]
async fn resolves_literal_ip_endpoint() {
    let resolved = resolve_endpoint("127.0.0.1:9000").await.unwrap();
    assert_eq!(resolved.port(), 9000);
    assert!(resolved.is_ipv4());
}

#[test]
fn parses_provisioned_server_peers() {
    let config = ServerConfig::from_toml(&format!(
        "bind = '127.0.0.1:9000'\n[[peers]]\nname = 'laptop'\nallowed_ips = ['10.42.0.2/32']\n[peers.auth]\nmode = 'pinned-key'\nlocal_identity_seed = '{}'\npeer_public_key = '{}'\n",
        seed(), pubkey()
    ))
    .unwrap();
    let peers = config.peer_identities().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].name, "laptop");
}

#[test]
fn parses_per_peer_pinned_key_auth() {
    let toml = format!(
        r#"
bind = '0.0.0.0:9000'
[[peers]]
name = 'phone'
allowed_ips = ['10.42.0.3/32']
[peers.auth]
mode = 'pinned-key'
local_identity_seed = '{}'
peer_public_key = '{}'
"#,
        seed(),
        pubkey()
    );
    let config = ServerConfig::from_toml(&toml).unwrap();
    let peers = config.peer_identities().unwrap();
    assert_eq!(peers.len(), 1);
    assert!(matches!(
        peers[0].auth,
        rvpn_crypto::AuthConfig::PinnedKey { .. }
    ));
}

#[test]
fn server_requires_peers_or_certificate_authority() {
    assert!(ServerConfig::from_toml("bind = '0.0.0.0:9000'").is_err());
}

#[test]
fn parses_tap_and_both_mode_and_firewall() {
    let server_toml = format!(
        r#"
bind = '0.0.0.0:9000'

[[peers]]
name = 'laptop'
allowed_ips = ['10.42.0.2/32']
[peers.auth]
mode = 'pinned-key'
local_identity_seed = '{seed}'
peer_public_key = '{pubkey}'

[interface]
name = 'rvpn-srv'
tap_name = 'rvpn-tap'
mode = 'both'

[forwarding]
enabled = true
backend = 'iptables'
external_interface = 'eth0'
tunnel_cidr = '10.42.0.0/24'
tunnel_cidr_v6 = 'fd42::/64'
"#,
        seed = seed(),
        pubkey = pubkey()
    );
    let config = ServerConfig::from_toml(&server_toml).unwrap();
    assert_eq!(config.interface.mode(), DeviceMode::Both);
    assert_eq!(config.forwarding.backend, FirewallBackend::Iptables);

    let client_toml = format!(
        r#"
server = '10.0.0.91:9000'
[auth]
mode = 'pinned-key'
local_identity_seed = '{seed}'
peer_public_key = '{pubkey}'

[interface]
mode = 'tap'

[routing]
default_route = true
gateway = '10.42.0.1'
endpoint_gateway = '192.168.88.1'
default_route_v6 = true
gateway_v6 = 'fd42::1'
"#,
        seed = seed(),
        pubkey = pubkey()
    );
    let client_cfg = ClientConfig::from_toml(&client_toml).unwrap();
    assert_eq!(client_cfg.interface.mode(), DeviceMode::Tap);
    assert!(client_cfg.routing.default_route_v6);
}

#[test]
fn parses_dns_server_lists_and_rejects_garbage() {
    let good = format!(
        "server = '127.0.0.1:9000'\n{}[interface]\ndns_servers = '1.1.1.1, 2606:4700:4700::1111'",
        pinned_auth_toml(&seed(), &pubkey())
    );
    let config = ClientConfig::from_toml(&good).unwrap();
    assert_eq!(config.interface.dns_server_list().unwrap().len(), 2);

    let bad = format!(
        "server = '127.0.0.1:9000'\n{}[interface]\ndns_servers = 'not-an-ip'",
        pinned_auth_toml(&seed(), &pubkey())
    );
    assert!(ClientConfig::from_toml(&bad).is_err());
}

#[test]
fn liveness_defaults_and_bounds() {
    let base = format!("server = '127.0.0.1:9000'\n{}", pinned_auth_toml(&seed(), &pubkey()));
    let default = ClientConfig::from_toml(&base).unwrap();
    assert_eq!(default.liveness.timeout(), Some(Duration::from_secs(90)));

    let disabled = ClientConfig::from_toml(&format!("{base}[liveness]\ntimeout_secs = 0")).unwrap();
    assert_eq!(disabled.liveness.timeout(), None);

    assert!(ClientConfig::from_toml(&format!("{base}[liveness]\ntimeout_secs = 10")).is_err());
}

#[test]
fn rekey_grace_period_defaults_and_is_configurable() {
    let base = format!("server = '127.0.0.1:9000'\n{}", pinned_auth_toml(&seed(), &pubkey()));

    let default = ClientConfig::from_toml(&base).unwrap();
    assert_eq!(default.rekey.grace_period(), Duration::from_secs(15));

    let configured =
        ClientConfig::from_toml(&format!("{base}[rekey]\ngrace_period_secs = 5")).unwrap();
    assert_eq!(configured.rekey.grace_period(), Duration::from_secs(5));

    let disabled =
        ClientConfig::from_toml(&format!("{base}[rekey]\ngrace_period_secs = 0")).unwrap();
    assert_eq!(disabled.rekey.grace_period(), Duration::ZERO);

    assert_eq!(default.rekey.packet_limit, 1 << 20);
    assert_eq!(default.rekey.time_limit_secs, 120);
}

#[test]
fn default_route_no_longer_requires_endpoint_gateway() {
    let toml = format!(
        "server = '127.0.0.1:9000'\n{}[routing]\ndefault_route = true\ngateway = '10.42.0.1'",
        pinned_auth_toml(&seed(), &pubkey())
    );
    let config = ClientConfig::from_toml(&toml).unwrap();
    config
        .validate_resolved("127.0.0.1:9000".parse().unwrap())
        .unwrap();
}

fn two_peer_toml(links: &str) -> String {
    format!(
        "bind = '0.0.0.0:9000'\n\
         [[peers]]\nname = 'laptop'\nallowed_ips = ['10.42.0.2/32']\n[peers.auth]\nmode = 'pinned-key'\nlocal_identity_seed = '{s1}'\npeer_public_key = '{p1}'\n\
         [[peers]]\nname = 'phone'\nallowed_ips = ['10.42.0.3/32']\n[peers.auth]\nmode = 'pinned-key'\nlocal_identity_seed = '{s2}'\npeer_public_key = '{p2}'\n{links}",
        s1 = "a".repeat(64),
        p1 = "b".repeat(64),
        s2 = "c".repeat(64),
        p2 = "d".repeat(64),
    )
}

#[test]
fn parses_links_between_peers() {
    let config =
        ServerConfig::from_toml(&two_peer_toml("[[links]]\nbetween = ['laptop', 'phone']"))
            .unwrap();
    assert_eq!(config.links.len(), 1);
    assert_eq!(config.links[0].between, ["laptop", "phone"]);
    assert!(
        ServerConfig::from_toml(&two_peer_toml(""))
            .unwrap()
            .links
            .is_empty()
    );
}

#[test]
fn rejects_bad_links_and_duplicate_peer_names() {
    assert!(matches!(
        ServerConfig::from_toml(&two_peer_toml("[[links]]\nbetween = ['laptop', 'nobody']")),
        Err(ConfigError::UnknownLinkPeer(name)) if name == "nobody"
    ));
    assert!(ServerConfig::from_toml(&two_peer_toml("[[links]]\nbetween = ['laptop']")).is_err());
    assert!(
        ServerConfig::from_toml(&two_peer_toml("[[links]]\nbetween = ['laptop', 'laptop']"))
            .is_err()
    );

    let dup = format!(
        "bind = '0.0.0.0:9000'\n[[peers]]\nname = 'a'\nallowed_ips = ['10.42.0.2/32']\n[peers.auth]\nmode = 'pinned-key'\nlocal_identity_seed = '{s}'\npeer_public_key = '{p}'\n[[peers]]\nname = 'a'\nallowed_ips = ['10.42.0.3/32']\n[peers.auth]\nmode = 'pinned-key'\nlocal_identity_seed = '{s2}'\npeer_public_key = '{p2}'\n",
        s = "a".repeat(64),
        p = "b".repeat(64),
        s2 = "c".repeat(64),
        p2 = "d".repeat(64),
    );
    assert!(matches!(
        ServerConfig::from_toml(&dup),
        Err(ConfigError::DuplicatePeerName(_))
    ));
}

#[test]
fn certificate_authority_only_server_needs_no_static_peers() {
    let toml = format!(
        r#"
bind = '0.0.0.0:9000'
[certificate_authority]
name = 'rvpn-ca'
ca_public_key = '{ca_pub}'
local_identity_seed = '{srv_seed}'
local_certificate = '{cert}'
"#,
        ca_pub = "e".repeat(64),
        srv_seed = "f".repeat(64),
        cert = "0".repeat(224),
    );
    let config = ServerConfig::from_toml(&toml).unwrap();
    assert!(config.peer_identities().unwrap().is_empty());
}