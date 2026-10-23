"""Single-NIC mode (HV_SINGLE_NIC=1).

The WAN interface is also the client-facing interface: the portal is reached
by source-IP matching and every LAN-only template line is rendered as a
comment. The core grants, fail2ban, container guards, IPv6 drop and host
rules stay active.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402

ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"
TEMPLATE = ROOT / "deploy" / "dropjak.nft"


def _function(source: str, name: str) -> str:
    start = source.index(f"\n{name}() {{\n") + 1
    return source[start:source.index("\n}\n", start) + 3]


def render(env: dict[str, str]) -> str:
    """Run entrypoint.sh's render_ruleset() with the given environment."""
    source = ENTRYPOINT.read_text(encoding="utf-8")
    functions = "\n".join(
        _function(source, name)
        for name in (
            "env_bool", "valid_ifname", "valid_network", "valid_port",
            "require_env", "no_forward_elements", "render_ruleset",
        )
    )
    with tempfile.TemporaryDirectory() as tmp:
        rendered = Path(tmp) / "dropjak.nft"
        script = f"""
set -eu
PYTHON={sys.executable}
TEMPLATE={TEMPLATE}
HV_NFT_FILE={rendered}
log() {{ printf '[dropjak] %s\\n' "$*" >&2; }}
die() {{ printf '[dropjak] ERROR: %s\\n' "$*" >&2; exit 1; }}
{functions}
render_ruleset
"""
        result = subprocess.run(
            ["sh", "-c", script],
            env={**os.environ, **env},
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr[-4000:])
        return rendered.read_text(encoding="utf-8")


def active_lines(rendered: str) -> list[str]:
    lines = []
    for raw in rendered.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


SINGLE = {
    "HV_SINGLE_NIC": "1",
    "HV_WAN_IF": "eth0",
    "HV_LAN_IF": "eth1",
    "HV_LAN_NET": "192.168.10.0/24",
    "HV_PORTAL_NET": "0.0.0.0/0",
    "PORT": "8100",
}

TWO = {
    "HV_SINGLE_NIC": "0",
    "HV_WAN_IF": "eth0",
    "HV_LAN_IF": "eth1",
    "HV_LAN_NET": "192.168.10.0/24",
    "HV_PORTAL_NET": "0.0.0.0/0",
    "PORT": "8100",
}


class RenderSingleNicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.single = render(SINGLE)
        cls.single_active = active_lines(cls.single)
        cls.two = render(TWO)
        cls.two_active = active_lines(cls.two)

    def test_no_active_lan_rule(self) -> None:
        for line in self.single_active:
            self.assertNotIn('iifname "eth1"', line)
            self.assertNotIn("__LAN_IF__", line)
            self.assertNotIn("__LAN_NET__", line)
            self.assertNotIn("@client_mac", line)
            self.assertNotIn("masquerade", line)
            self.assertNotIn("redirect to :", line)
            self.assertNotRegex(line, r"\budp (sport 68 )?dport 67\b")
            if "172.30.0.2" not in line:
                # The container guard's own DNS accept stays; a LAN DNS rule
                # would have the client interface and is already excluded.
                self.assertNotRegex(line, r"\budp dport 53\b")
            self.assertNotIn('iifname "eth1" jump block', line)

    def test_no_marker_or_placeholder_remains(self) -> None:
        self.assertNotIn("__LANONLY__", self.single)
        self.assertNotRegex(self.single, r"__[A-Z0-9_]+__")

    def test_retained_core_rules_are_active(self) -> None:
        text = "\n".join(self.single_active)
        self.assertIn('iifname "eth0"', text)
        self.assertIn("ip saddr 0.0.0.0/0 tcp dport 8100 accept", text)
        self.assertIn("@allowed_tcp", text)
        self.assertIn("reason=fail2ban", text)
        self.assertIn("ip daddr @no_forward_v4 drop", text)
        self.assertIn("meta nfproto ipv6 drop", text)
        self.assertIn("jump breakglass", text)
        self.assertIn("jump preauth", text)
        self.assertIn("jump preauth_input", text)
        self.assertIn("jump tunnel_input", text)
        self.assertIn("@allowed_input_tcp", text)

    def test_two_nic_mode_keeps_the_lan_rules(self) -> None:
        text = "\n".join(self.two_active)
        self.assertIn('iifname "eth1" udp sport 68 udp dport 67 accept', text)
        self.assertIn("@client_mac", text)
        self.assertIn("masquerade", text)
        self.assertIn("redirect to :8100", text)
        self.assertIn('iifname "eth1" ct direction original jump block', text)
        self.assertNotIn("__LANONLY__", self.two)

    def test_single_nic_ignores_stale_lan_values(self) -> None:
        # The LAN values are still required to be rendered away, not to
        # produce a rule; the WAN is the only client-facing interface.
        self.assertNotIn("192.168.10.0/24", "\n".join(self.single_active))
        self.assertNotIn("eth1", "\n".join(self.single_active))

    def test_missing_wan_fails_closed(self) -> None:
        with self.assertRaises(AssertionError) as caught:
            render({**SINGLE, "HV_WAN_IF": ""})
        self.assertIn("HV_WAN_IF", str(caught.exception))

    def test_two_nic_still_requires_lan_values(self) -> None:
        with self.assertRaises(AssertionError) as caught:
            render({**TWO, "HV_LAN_IF": "", "HV_LAN_NET": ""})
        self.assertIn("HV_LAN_IF", str(caught.exception))


class FirewallSingleNicTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lan = ipaddress.ip_network("192.168.10.0/24")
        self.fw = gateway.Firewall(
            lan_if="eth1",
            wan_if="eth0",
            lan_network=self.lan,
            arp_path="/nonexistent/arp",
            binary="/nonexistent/nft",
            dry_run=True,
            single_nic=True,
            logger=lambda *_: None,
        )

    def test_mac_binding_is_off_even_with_stale_lan_values(self) -> None:
        self.assertFalse(self.fw.mac_binding)
        self.assertFalse(self.fw.binds_mac("192.168.10.5"))
        self.assertFalse(self.fw.binds_mac("203.0.113.5"))

    def test_grant_does_not_bind_a_mac(self) -> None:
        with mock.patch.object(
            self.fw, "_bind_mac_locked",
            side_effect=AssertionError("MAC binding must not run"),
        ), mock.patch.object(self.fw, "_unbind_mac_locked"):
            self.fw.grant(
                "203.0.113.5", gateway.Ports(full=True), 60
            )

    def test_forward_preauth_uses_the_wan_with_dnat_only(self) -> None:
        rules = self.fw._custom_rules(
            preauth=[{"proto": "tcp", "ports": [80]}]
        )
        text = "\n".join(rules)
        self.assertNotIn('iifname "eth1"', text)
        self.assertIn(
            'add rule inet hatarvedelem preauth iifname "eth0" '
            "ct status dnat meta l4proto tcp",
            text,
        )

    def test_input_preauth_scope_uses_the_wan(self) -> None:
        rules = self.fw._custom_rules(
            preauth=[{"direction": "input", "proto": "tcp", "ports": [8081]}]
        )
        text = "\n".join(rules)
        self.assertNotIn('iifname "eth1"', text)
        self.assertIn(
            'add rule inet hatarvedelem preauth_input iifname "eth0"',
            text,
        )

    def test_portproxy_sides_all_map_to_the_wan(self) -> None:
        for side in ("lan", "wan", "both"):
            self.assertEqual(self.fw._portproxy_ifaces(side), ["eth0"])

    def test_portproxy_without_wan_fails(self) -> None:
        fw = gateway.Firewall(
            lan_if="eth1", wan_if="", binary="/nonexistent/nft",
            dry_run=True, single_nic=True, logger=lambda *_: None,
        )
        with self.assertRaises(gateway.FirewallError):
            fw._portproxy_ifaces("both")


class InstallerSingleNicTests(unittest.TestCase):
    def test_setup_host_accepts_single_nic_without_lan(self) -> None:
        setup = (ROOT / "docker" / "setup-host.sh").read_text(encoding="utf-8")
        start = setup.index("LAN_IF=${HV_LAN_IF:-}")
        end = setup.index('chmod 0644 "$SYSCTL_FILE"')
        snippet = setup[start:end]
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text(
                "HV_SINGLE_NIC=1\nHV_WAN_IF=eth0\n", encoding="utf-8"
            )
            sysctl = os.path.join(tmp, "90-dropjak.conf")
            result = subprocess.run(
                ["bash", "-c",
                 "set -euo pipefail\n"
                 'die() { echo "ERROR: $*" >&2; exit 1; }\n'
                 'info() { echo "[dropjak] $*"; }\n'
                 + snippet + '\ncat "$SYSCTL_FILE"\n'],
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                     "REPO_DIR": tmp, "SYSCTL_FILE": sysctl},
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("net.ipv4.ip_forward = 1", result.stdout)
            self.assertNotIn("disable_ipv6", result.stdout)

    def test_native_installer_has_single_nic_switch(self) -> None:
        text = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("--single-nic)", text)
        self.assertIn("s|__LANONLY__|$LAN_PREFIX|g", text)
        self.assertIn("Environment=HV_SINGLE_NIC=$SINGLE_NIC", text)


if __name__ == "__main__":
    unittest.main()
