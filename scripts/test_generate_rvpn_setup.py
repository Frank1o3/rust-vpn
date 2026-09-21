from __future__ import annotations

import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from rvpn_setup.crypto import (  # noqa: E402
    generate_keypair,
    generate_hex_secret,
    issue_certificate,
)
from rvpn_setup.models import (  # noqa: E402
    ClientOptions,
    PeerSetup,
    SecurityPolicy,
    SetupConfig,
)
from rvpn_setup.render import (  # noqa: E402
    render_client_toml,
    render_server_toml,
)


class GeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        ca = generate_keypair()
        server_identity = generate_keypair()
        client_identity = generate_keypair()
        self.setup = SetupConfig(
            bind_address="0.0.0.0",
            bind_port=9000,
            client_server_address="vpn.example.test:9000",
            endpoint_external="vpn.example.test",
            server_interface_name="rvpn-server0",
            server_mode="tun",
            server_mtu=1400,
            server_tap_name=None,
            server_v4="10.42.0.1/24",
            ipv6_enabled=True,
            server_v6="fd42::1/64",
            forwarding_enabled=True,
            forwarding_backend="auto",
            external_interface="eth0",
            tunnel_cidr="10.42.0.0/24",
            tunnel_cidr_v6="fd42::/64",
            obfuscation_enabled=True,
            obfuscation_key=generate_hex_secret(),
            auth_mode="certificate",
            security=SecurityPolicy(),
            ca_name="rvpn-ca",
            ca=ca,
            server_identity=server_identity,
            cert_valid_days=3650,
            ca_default_allowed_ips=[],
            revoked_subjects=[],
        )
        self.peer = PeerSetup(
            name="phone",
            platform="android",
            tunnel_v4="10.42.0.2",
            tunnel_v6="fd42::2",
            client=ClientOptions(
                interface_name="rvpn-android",
                mode="tun",
                mtu=1400,
                tap_name=None,
                dns_servers="1.1.1.1",
                default_route=True,
                gateway="10.42.0.1",
                endpoint_gateway=None,
                default_route_v6=True,
                gateway_v6="fd42::1",
                endpoint_gateway_v6=None,
                routes=["192.168.0.0/16"],
            ),
            client_seed_hex=client_identity.seed,
            client_pub_hex=client_identity.public_key,
            client_certificate_hex=issue_certificate(
                ca.seed,
                client_identity.public_key,
                3650,
            ),
        )

    def test_server_is_valid_toml(self) -> None:
        text = render_server_toml(
            self.setup,
            [self.peer],
            [],
        )
        tomllib.loads(text)
        self.assertIn("[certificate_authority]", text)
        self.assertIn("[certificate_authority.peer_overrides]", text)
        self.assertIn("[handshake]", text)
        self.assertIn("[rekey]", text)
        self.assertIn("[liveness]", text)

    def test_client_is_valid_toml(self) -> None:
        text = render_client_toml(
            self.setup,
            self.peer,
        )
        data = tomllib.loads(text)
        self.assertEqual(
            data["server"],
            "vpn.example.test:9000",
        )
        self.assertEqual(
            data["auth"]["mode"],
            "certificate",
        )
        self.assertEqual(
            data["routing"]["routes"],
            ["192.168.0.0/16"],
        )
        self.assertEqual(
            data["handshake"]["retry_jitter_ms"],
            150,
        )
        self.assertEqual(
            data["rekey"]["packet_limit"],
            1 << 20,
        )
        self.assertEqual(
            data["liveness"]["timeout_secs"],
            90,
        )

    def test_files_can_be_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.toml"
            path.write_text(
                render_server_toml(
                    self.setup,
                    [self.peer],
                    [],
                ),
                encoding="utf-8",
            )
            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
