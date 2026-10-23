#!/usr/bin/env python3
"""Tests for the firewall/deploy fixes of the 2026-10 security review.

DJ-02  link-local (cloud metadata) destinations are never forwarded
DJ-03  grants do not reach Docker bridges or the LAN (from the WAN) without
       DNAT; DOCKER-USER no longer accepts marked packets toward a bridge
DJ-04  a lost and reloaded table is detected and resynchronized; no grant
       is issued until then
DJ-09  input pre-auth cannot open SSH, DNS, DHCP, Caddy admin or the portal
DJ-16  established UDP 53 flows are cut after revocation
DJ-17  a LAN source is accepted only on the LAN interface
DJ-18  native install passes the interface env; the portal port is rendered
DJ-19  the boot table drops host input
DJ-20  the portal's bounding set holds only NET_ADMIN and NET_BIND_SERVICE
DJ-21  the admin password file is wired in; the variable leaves the env
DJ-33  the input block jump spares replies to the host's own connections
DJ-34  the host_service guard checks only the original direction
DJ-36  destinations with host bits are rejected
Side note: entrypoint.sh exports HV_PORTAL_NET after the fallback.

The tests read repository files, render rules into memory and run small
shell snippets. They never run nft against the system firewall.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
for path in (str(ROOT), str(TESTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

import gateway  # noqa: E402
import settings_store  # noqa: E402
from test_block_precedence import chain_rules  # noqa: E402

NFT = (ROOT / "deploy" / "dropjak.nft").read_text(encoding="utf-8")
BOOT = (ROOT / "deploy" / "dropjak-boot.nft").read_text(encoding="utf-8")
ENTRYPOINT = (ROOT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
FIREWALL_UNIT = (ROOT / "deploy" / "dropjak-firewall.service").read_text(
    encoding="utf-8"
)
IP = "192.168.50.23"


def first(rules: list[str], needle: str) -> int:
    hits = [index for index, rule in enumerate(rules) if needle in rule]
    if not hits:
        raise AssertionError(f"rule not found: {needle}")
    return hits[0]


def first_accept(rules: list[str]) -> int:
    return next(
        index for index, rule in enumerate(rules) if rule.endswith(" accept")
    )


# ------------------------------------------------------------------ template


class ForwardTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.forward = chain_rules(NFT, "forward")

    def test_link_local_set_holds_metadata_range(self) -> None:
        self.assertRegex(
            NFT,
            r"add set inet hatarvedelem no_forward_v4 \{\s*type ipv4_addr\s*"
            r"flags interval\s*\}",
        )
        self.assertIn(
            "add element inet hatarvedelem no_forward_v4 { 169.254.0.0/16 }",
            NFT,
        )

    def test_no_forward_drop_precedes_every_accept(self) -> None:
        drop = self.forward.index("ip daddr @no_forward_v4 drop")
        self.assertLess(drop, first_accept(self.forward))
        self.assertLess(drop, self.forward.index("jump preauth"))
        # The container exception cannot reach it either.
        container = first(self.forward, "ip saddr 172.30.0.2 udp dport 53")
        self.assertLess(drop, container)

    def test_bridges_and_wan_to_lan_need_dnat(self) -> None:
        for rule in (
            'oifname "docker*" ct direction original ct status != dnat drop',
            'oifname "br-*" ct direction original ct status != dnat drop',
            'iifname "__WAN_IF__" oifname "__LAN_IF__" ct direction original '
            "ct status != dnat drop",
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, self.forward)
                self.assertLess(
                    self.forward.index(rule), first_accept(self.forward)
                )

    def test_lan_source_only_on_lan_interface(self) -> None:
        rule = 'iifname != "__LAN_IF__" ip saddr __LAN_NET__ drop'
        self.assertLess(
            self.forward.index(rule), first_accept(self.forward)
        )
        input_rules = chain_rules(NFT, "input")
        index = input_rules.index(rule)
        # Loopback is accepted before it; every grant comes after it.
        self.assertLess(input_rules.index("iif lo accept"), index)
        self.assertLess(index, first(input_rules, "@allowed_input_tcp"))
        self.assertLess(index, first(input_rules, "jump preauth_input"))


class InputTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.input = chain_rules(NFT, "input")

    def test_udp_dns_established_guard_precedes_generic_accept(self) -> None:
        guard = (
            'iifname "__LAN_IF__" udp dport 53 ct state established,related '
            "ip saddr != @allowed_v4 ip saddr . udp dport != @allowed_udp "
            "ip saddr . udp dport != @allowed_input_udp drop"
        )
        self.assertIn(guard, self.input)
        generic = self.input.index("ct state established,related accept")
        self.assertLess(self.input.index(guard), generic)
        # It also runs before the UDP 53 established accepts.
        self.assertLess(
            self.input.index(guard),
            first(self.input, "udp dport 53 ct state established,related ip saddr @allowed_v4 accept"),
        )

    def test_host_service_guard_checks_original_direction_only(self) -> None:
        guards = [
            rule for rule in self.input
            if "@host_service_" in rule and rule.endswith(" drop")
        ]
        self.assertEqual(len(guards), 2, guards)
        for rule in guards:
            self.assertIn("ct direction original", rule)

    def test_input_block_jump_spares_reply_direction(self) -> None:
        self.assertIn("ct direction original jump block", self.input)
        self.assertNotIn("jump block", self.input)

    def test_host_accept_excludes_rendered_portal_port(self) -> None:
        self.assertIn(
            "ip saddr . tcp dport @allowed_input_tcp tcp dport != __PORT__ accept",
            self.input,
        )
        self.assertIn(
            "ip saddr . udp dport @allowed_input_udp udp dport != __PORT__ accept",
            self.input,
        )
        self.assertFalse(any("8100" in rule for rule in self.input))


class BootTableTests(unittest.TestCase):
    def test_boot_input_drops_by_default(self) -> None:
        self.assertIn(
            "type filter hook input priority filter; policy drop;", BOOT
        )
        self.assertNotIn(
            "type filter hook input priority filter; policy accept;", BOOT
        )
        rules = chain_rules(BOOT, "input")
        self.assertEqual(
            rules,
            [
                'iifname "lo" accept',
                "tcp dport 22 drop",
                "ct state established,related accept",
                "udp sport 68 udp dport 67 accept",
            ],
        )


# ------------------------------------------------------------------ renderer


class InputPreauthReservedPortTests(unittest.TestCase):
    def setUp(self) -> None:
        self.logs: list[str] = []
        self.firewall = gateway.Firewall(
            dry_run=True, logger=self.logs.append,
            lan_if="eth1", wan_if="eth0",
        )
        self.scripts: list[str] = []
        self.firewall._run_script = self.scripts.append  # type: ignore[method-assign]

    def input_lines(self) -> list[str]:
        self.assertEqual(len(self.scripts), 1)
        return [
            line for line in self.scripts[0].splitlines()
            if line.startswith("add rule inet hatarvedelem preauth_input ")
            and "@banned_v4" not in line
        ]

    def test_reserved_ports_are_never_rendered(self) -> None:
        reserved = settings_store.preauth_reserved_input_ports()
        for port in (22, 53, 67, 2019, settings_store.PORTAL_PORT):
            self.assertIn(port, reserved)
        self.firewall.apply_custom(preauth=[
            {"id": "a", "proto": "tcp", "ports": [22, 8443], "direction": "input"},
            {"id": "b", "proto": "udp", "ports": [53], "direction": "input"},
            {"id": "c", "proto": "tcp", "ports": [settings_store.PORTAL_PORT],
             "direction": "input"},
        ])
        lines = self.input_lines()
        self.assertTrue(lines)
        for line in lines:
            self.assertIn("proto-dst 8443", line)
        self.assertTrue(any("skips reserved host ports: 22" in m for m in self.logs))

    def test_forward_preauth_keeps_port_53(self) -> None:
        self.firewall.apply_custom(preauth=[
            {"proto": "udp", "ports": [53], "dst": "192.0.2.53"},
        ])
        self.assertIn(
            "ct original proto-dst 53 meta mark set", self.scripts[0]
        )


class SettingsValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = settings_store.SettingsStore(
            os.path.join(self.tmp.name, "settings.json"),
            logger=lambda *_: None,
        )

    def test_input_preauth_rejects_reserved_ports(self) -> None:
        for proto, port in (
            ("tcp", 22), ("udp", 53), ("tcp", 53), ("udp", 67),
            ("tcp", 2019), ("tcp", settings_store.PORTAL_PORT),
        ):
            with self.subTest(proto=proto, port=port):
                with self.assertRaisesRegex(
                    settings_store.SettingsError, "cannot open these host ports"
                ):
                    self.store.prepare("create", "preauth", entry={
                        "label": "t", "proto": proto, "ports": [port], "direction": "input",
                    })

    def test_input_preauth_update_is_checked_too(self) -> None:
        data = self.store.prepare("create", "preauth", entry={
            "label": "t", "proto": "tcp", "ports": [8443], "direction": "input",
        })
        self.store.commit(data)
        entry_id = data["preauth"][0]["id"]
        with self.assertRaises(settings_store.SettingsError):
            self.store.prepare("update", "preauth", entry_id, entry={
                "label": "t", "proto": "tcp", "ports": [22], "direction": "input",
            })

    def test_forward_preauth_and_ordinary_input_ports_still_allowed(self) -> None:
        self.store.prepare("create", "preauth", entry={
            "label": "t", "proto": "udp", "ports": [53], "dst": "192.0.2.53",
        })
        self.store.prepare("create", "preauth", entry={
            "label": "t", "proto": "tcp", "ports": [8443], "direction": "input",
        })

    def test_stored_legacy_entry_does_not_invalidate_the_file(self) -> None:
        # An older version could store such an entry; loading must keep the
        # block entries (the renderer skips the reserved port).
        state = settings_store.validate_state({
            "preauth": [{"id": "abcd1234", "label": "t", "proto": "tcp", "ports": [22],
                         "direction": "input"}],
            "block": [{"id": "bcde2345", "label": "t", "proto": "tcp", "ports": [443],
                       "dst": "203.0.113.0/24"}],
        })
        self.assertEqual(len(state["block"]), 1)

    def test_destination_with_host_bits_is_rejected(self) -> None:
        for dst in ("10.0.0.5/8", "192.168.1.1/24"):
            with self.subTest(dst=dst):
                with self.assertRaisesRegex(
                    settings_store.SettingsError, "host bits"
                ):
                    settings_store.normalize_entry(
                        "block", {"label": "t", "proto": "tcp", "ports": [443], "dst": dst}
                    )
        entry = settings_store.normalize_entry(
            "block", {"label": "t", "proto": "tcp", "ports": [443], "dst": "10.0.0.0/8"}
        )
        self.assertEqual(entry["dst"], "10.0.0.0/8")

    def test_gateway_rejects_host_bits(self) -> None:
        with self.assertRaises(gateway.FirewallError):
            gateway.Firewall._custom_dst({"dst": "10.0.0.5/8"}, "block")
        self.assertEqual(
            gateway.Firewall._custom_dst({"dst": "10.0.0.5"}, "block"),
            "10.0.0.5/32",
        )


class HostRulePortalPortTests(unittest.TestCase):
    def test_effective_portal_port_is_reserved(self) -> None:
        with mock.patch.object(gateway, "PORT", 80):
            with self.assertRaisesRegex(ValueError, "port 80 \\(portal\\)"):
                gateway._validate_host_ports(
                    "input", gateway.Ports(tcp=(80,))
                )
            gateway._validate_host_ports(
                "input", gateway.Ports(tcp=(8100,))
            )


# ------------------------------------------------------------------ DJ-04


class TokenFirewall:
    """Fake firewall: a table generation plus the calls a resync makes."""

    def __init__(self) -> None:
        self.token: int | None = 7
        self.table_exists = True
        self.calls: list[str] = []
        self.grant_calls: list[tuple] = []

    def state_token(self):
        return self.token

    def healthy(self):
        return (True, "ok") if self.table_exists else (False, "no table")

    def sync_host_ports(self, tcp_ports, udp_ports) -> None:
        self.calls.append("sync_host_ports")
        if not self.table_exists:
            raise gateway.FirewallError("no table")

    def prune_host_service_ports(self, tcp, udp, audit=None) -> dict:
        return {}

    def replace_custom(self, preauth=(), block=(), **kwargs) -> None:
        self.calls.append("replace_custom")
        # Re-applying the chains puts the marker back.
        self.token = 8

    def grant_all(self, ip, grants, ttl) -> None:
        self.grant_calls.append((ip, tuple(grants), ttl))

    def revoke_all(self, ip, grants=(), discover=False, only_grants=False):
        pass


class RecordingAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def write(self, event: str, **fields) -> None:
        self.events.append((event, fields))

    def names(self) -> list[str]:
        return [event for event, _fields in self.events]


def build_gateway(firewall):
    from test_host_service_guard import FakeGroups, FakeRules, FakeUsers, make_rule

    rule = make_rule("web", tcp=(80,))
    audit = RecordingAudit()
    fail2ban = types.SimpleNamespace(
        audit=None, _on_ban=lambda record: None, synced=0,
    )

    def sync():
        fail2ban.synced += 1
        return True

    fail2ban.sync = sync
    settings = types.SimpleNamespace(snapshot=lambda: {
        "preauth": [], "block": [
            {"id": "b1", "proto": "tcp", "ports": [80], "dst": "203.0.113.10"}
        ], "port_proxies": [], "tunnels": {}, "error": "",
    })
    gw = gateway.Gateway(
        users=FakeUsers(), firewall=firewall, sessions=None,
        rate_limiter=gateway.RateLimiter(window=60, maximum=1000),
        catalog=types.SimpleNamespace(), rules=FakeRules([rule]),
        groups=FakeGroups(), audit=audit, settings=settings,
        drops=types.SimpleNamespace(), fail2ban=fail2ban,
    )
    return gw, rule, audit, fail2ban


class TableResyncTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.object(gateway, "CONNTRACK_BIN", "")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.fw = TokenFirewall()
        self.gw, self.rule, self.audit, self.f2b = build_gateway(self.fw)
        # What prepare() records after the startup sync.
        self.gw._fw_token = 7

    def test_in_sync_table_needs_no_resync(self) -> None:
        self.assertFalse(self.gw.check_firewall_state())
        self.assertEqual(self.fw.calls, [])

    def test_new_table_generation_blocks_grants_until_resync(self) -> None:
        self.fw.token = 99  # the table was deleted and reloaded bare
        session = self.gw.sessions.login("alice", IP)
        with self.assertRaisesRegex(gateway.FirewallError, "resynchronized"):
            self.gw.sessions.authorize(session.token, IP, self.rule, 60)
        self.assertEqual(self.fw.grant_calls, [])

        self.assertTrue(self.gw.check_firewall_state())
        # Host guards, bans and the custom chains are all pushed again.
        self.assertIn("sync_host_ports", self.fw.calls)
        self.assertIn("replace_custom", self.fw.calls)
        self.assertEqual(self.f2b.synced, 1)
        self.assertTrue(self.gw._host_ports_ok)
        self.assertEqual(self.gw._fw_token, 8)
        self.assertIn("firewall_resync", self.audit.names())

        authorized = self.gw.sessions.authorize(session.token, IP, self.rule, 60)
        self.assertTrue(authorized.authorized)
        self.assertEqual(len(self.fw.grant_calls), 1)

    def test_flushed_chains_trigger_resync(self) -> None:
        self.fw.token = None  # table present, portal's marker rule gone
        self.assertTrue(self.gw.check_firewall_state())
        self.assertIn("replace_custom", self.fw.calls)

    def test_missing_table_waits_and_audits_once(self) -> None:
        self.fw.token = None
        self.fw.table_exists = False
        self.assertFalse(self.gw.check_firewall_state())
        self.assertFalse(self.gw.check_firewall_state())
        self.assertEqual(self.fw.calls, [])
        self.assertFalse(self.gw._host_ports_ok)
        lost = [
            fields for event, fields in self.audit.events
            if event == "firewall_error" and fields.get("operation") == "table_lost"
        ]
        self.assertEqual(len(lost), 1)

    def test_before_prepare_grants_are_not_blocked(self) -> None:
        self.gw._fw_token = None
        self.fw.token = 99
        self.assertTrue(self.gw._firewall_in_sync())
        self.assertFalse(self.gw.check_firewall_state())


class StateTokenTests(unittest.TestCase):
    def make(self, tables: bytes, chain: bytes):
        fw = gateway.Firewall(dry_run=False, logger=lambda *_: None,
                              lan_if="eth1", wan_if="eth0")
        outputs = {"tables": tables, "chain": chain}

        def run(args, check=True):
            key = "tables" if "tables" in args else "chain"
            return subprocess.CompletedProcess(args, 0, outputs[key], b"")

        fw._run = run  # type: ignore[method-assign]
        return fw

    TABLES = (
        b'{"nftables": [{"metainfo": {}}, {"table": {"family": "inet", '
        b'"name": "hatarvedelem", "handle": 42}}]}'
    )
    CHAIN = b"table inet hatarvedelem {\n chain preauth {\n  ip saddr @banned_v4 ct direction original drop\n }\n}\n"

    def test_handle_is_the_generation(self) -> None:
        self.assertEqual(self.make(self.TABLES, self.CHAIN).state_token(), 42)

    def test_missing_table_or_marker_means_resync(self) -> None:
        self.assertIsNone(
            self.make(b'{"nftables": [{"metainfo": {}}]}', self.CHAIN).state_token()
        )
        self.assertIsNone(
            self.make(self.TABLES, b"chain preauth {\n}\n").state_token()
        )
        self.assertIsNone(self.make(b"not json", self.CHAIN).state_token())

    def test_marker_matches_the_rendered_ban_rule(self) -> None:
        """The marker is the direction-aware ban rule that _custom_rules emits."""
        fw = gateway.Firewall(dry_run=True, logger=lambda *_: None)
        rendered = "\n".join(fw._custom_rules([], []))
        self.assertIn("ip saddr @banned_v4 ct direction original drop", rendered)
        self.assertEqual(self.make(self.TABLES, self.CHAIN).state_token(), 42)

    def test_dry_run_is_constant(self) -> None:
        fw = gateway.Firewall(dry_run=True, logger=lambda *_: None)
        self.assertEqual(fw.state_token(), 0)


# ------------------------------------------------------------------ deploy


class EntrypointTests(unittest.TestCase):
    def test_setpriv_limits_bounding_set(self) -> None:
        self.assertIn(
            "--bounding-set=-all,+net_admin,+net_bind_service", ENTRYPOINT
        )
        cap_add = re.search(r"cap_add:\n((?:\s+- \w+\n)+)", COMPOSE).group(1)
        self.assertIn("- SETPCAP", cap_add)

    def test_docker_user_does_not_accept_toward_bridges(self) -> None:
        start = ENTRYPOINT.index("insert rule ip filter DOCKER-USER \\\n            meta mark \"$HV_FWD_MARK\"")
        rule = ENTRYPOINT[start:ENTRYPOINT.index("hv-docker-fwd-mark", start)]
        self.assertIn("oifname != '\"docker*\"'", rule)
        self.assertIn("oifname != '\"br-*\"'", rule)
        # The drop guard for unmarked packets is unchanged.
        self.assertIn('meta mark != "$HV_FWD_MARK" drop', ENTRYPOINT)

    def test_portal_net_fallback_is_exported(self) -> None:
        """Run render_ruleset with HV_PORTAL_NET absent and HV_MGMT_NET set."""
        functions = ENTRYPOINT.split("# ------------------------------------------------------------------------ main")[0]
        with tempfile.TemporaryDirectory() as tmp:
            rendered = os.path.join(tmp, "dropjak.nft")
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HV_APP_DIR": str(ROOT),
                "HV_PYTHON": sys.executable,
                "HV_NFT_FILE": rendered,
                "HV_LAN_IF": "eth1",
                "HV_WAN_IF": "eth0",
                "HV_LAN_NET": "192.168.50.0/24",
                "HV_MGMT_NET": "10.9.0.0/16",
            }
            result = subprocess.run(
                ["sh", "-c", functions + "\nrender_ruleset\n"],
                env=env, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            text = Path(rendered).read_text(encoding="utf-8")
        self.assertIn("ip saddr 10.9.0.0/16 tcp dport 8100 accept", text)
        self.assertNotRegex(text, r"__[A-Z0-9_]+__")

    def test_admin_secret_is_staged_before_any_command(self) -> None:
        main = ENTRYPOINT.split("# ------------------------------------------------------------------------ main")[1]
        self.assertLess(main.index("stage_admin_secret"), main.index('run_as_app "$@"'))
        self.assertIn(
            "HV_ADMIN_PASSWORD_FILE: ${HV_ADMIN_PASSWORD_FILE:-/run/secrets/dropjak_admin_password}",
            COMPOSE,
        )
        self.assertIn("- ./secrets:/run/secrets:ro", COMPOSE)


class NativeInstallTests(unittest.TestCase):
    def test_env_dropin_carries_interfaces(self) -> None:
        dropin = INSTALL[INSTALL.index('cat > "$ENV_DROPIN_DIR/10-dropjak-env.conf"'):]
        dropin = dropin[:dropin.index("\nEOF")]
        for line in (
            "Environment=HV_LAN_IF=$LAN_IF",
            "Environment=HV_WAN_IF=$WAN_IF",
            "Environment=HV_LAN_NET=$LAN_NET",
        ):
            self.assertIn(line, dropin)

    def test_firewall_unit_follows_nftables_service(self) -> None:
        self.assertIn("PartOf=nftables.service", FIREWALL_UNIT)
        self.assertIn("ReloadPropagatedFrom=nftables.service", FIREWALL_UNIT)


class AdminPasswordEnvTests(unittest.TestCase):
    def test_password_leaves_the_process_environment(self) -> None:
        code = (
            "import os, sys; sys.path.insert(0, sys.argv[1]); import gateway; "
            "print('HV_ADMIN_PASSWORD' in os.environ, "
            "gateway.ADMIN_PASSWORD == 'test-only-value')"
        )
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, HV_ADMIN_PASSWORD="test-only-value",
                       HV_STATE_DIR=tmp)
            result = subprocess.run(
                [sys.executable, "-I", "-c", code, str(ROOT)],
                env=env, capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split()[-2:], ["False", "True"])


if __name__ == "__main__":
    unittest.main()
