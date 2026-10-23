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

import json
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
            "add element inet hatarvedelem no_forward_v4 "
            "{ 169.254.0.0/16__NO_FORWARD_NETS__ }",
            NFT,
        )
        # Refilled in the same transaction: a network removed from
        # HV_NO_FORWARD_NETS leaves the set on the next load.
        self.assertLess(
            NFT.index("flush set inet hatarvedelem no_forward_v4"),
            NFT.index("add element inet hatarvedelem no_forward_v4"),
        )

    def test_no_forward_drop_precedes_every_accept(self) -> None:
        drop = self.forward.index("ip daddr @no_forward_v4 drop")
        self.assertLess(drop, first_accept(self.forward))
        self.assertLess(drop, self.forward.index("jump preauth"))
        # The container egress exceptions cannot reach it either.
        self.assertLess(drop, self.forward.index("jump container_egress"))

    def test_bridges_and_wan_to_lan_need_dnat(self) -> None:
        for rule in (
            'oifname "docker*" ct direction original ct status != dnat drop',
            'oifname "br-*" ct direction original ct status != dnat drop',
            "oifname @docker_bridges ct direction original ct status != dnat drop",
            'iifname "__WAN_IF__" oifname "__LAN_IF__" ct direction original '
            "ct status != dnat drop",
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, self.forward)
                self.assertLess(
                    self.forward.index(rule), first_accept(self.forward)
                )

    def test_custom_bridge_set_is_declared_and_logged(self) -> None:
        """DJ-03: bridges not named docker*/br-* come from a set."""
        self.assertRegex(
            NFT, r"add set inet hatarvedelem docker_bridges \{\s*type ifname\s*\}"
        )
        # The template never flushes it: a reload keeps the detected names.
        self.assertNotIn("flush set inet hatarvedelem docker_bridges", NFT)
        drop = self.forward.index(
            "oifname @docker_bridges ct direction original ct status != dnat drop"
        )
        self.assertIn("reason=container-direct", self.forward[drop - 1])

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
        self.assertIn(
            'iifname "__LAN_IF__" ct direction original jump block', self.input
        )
        self.assertNotIn("jump block", self.input)

    def test_input_block_applies_to_lan_traffic_only(self) -> None:
        """DJ-33: a destination-less block must not stop WAN traffic to Caddy."""
        jumps = [rule for rule in self.input if rule.endswith("jump block")]
        self.assertEqual(
            jumps, ['iifname "__LAN_IF__" ct direction original jump block']
        )
        # The WAN proxy accept is not preceded by any WAN-reachable block jump.
        wan_proxy = first(self.input, 'iifname "__WAN_IF__" tcp dport { 80, 443 } accept')
        for rule in self.input[:wan_proxy]:
            if "jump block" in rule:
                self.assertIn('iifname "__LAN_IF__"', rule)
        # Forward behaviour is unchanged: one unconditional jump.
        forward = chain_rules(NFT, "forward")
        self.assertEqual(
            [rule for rule in forward if rule.endswith("jump block")],
            ["jump block"],
        )

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
                "meta nfproto ipv6 drop",
                "tcp dport 22 drop",
                "ct state established,related accept",
                "udp sport 68 udp dport 67 accept",
            ],
        )


class Ipv6DropTests(unittest.TestCase):
    """Owner's rule: IPv6 is always dropped, in every case (DJ-35)."""

    DROP = "meta nfproto ipv6 drop"

    @staticmethod
    def hook_chains(template: str) -> dict[str, str]:
        """chain name -> its hook declaration line."""
        return dict(re.findall(
            r"add chain inet \S+ (\w+) \{\s*\n\s*(type \w+ hook [^\n]+)",
            template,
        ))

    def test_forward_drops_ipv6_before_anything_else(self) -> None:
        rules = chain_rules(NFT, "forward")
        self.assertTrue(rules[0].startswith("meta nfproto ipv6 "), rules[0])
        self.assertEqual(rules[1], self.DROP)

    def test_input_drops_ipv6_before_any_accept_or_jump(self) -> None:
        rules = chain_rules(NFT, "input")
        drop = rules.index(self.DROP)
        # Only loopback (::1 on lo, never from the network) precedes it; the
        # breakglass chain comes after, so it cannot open IPv6 either.
        self.assertEqual(
            [rule for rule in rules[:drop] if "reason=ipv6" not in rule],
            ["iif lo accept"],
        )
        self.assertLess(drop, rules.index("jump breakglass"))

    def test_every_accepting_filter_hook_drops_ipv6(self) -> None:
        for name, template in (("dropjak.nft", NFT), ("dropjak-boot.nft", BOOT)):
            hooks = self.hook_chains(template)
            if name == "dropjak.nft":
                # The forward chain is declared in the transaction body.
                hooks["forward"] = "type filter hook forward priority -10; policy drop;"
            for chain, declaration in hooks.items():
                if not declaration.startswith("type filter"):
                    continue  # nat chains: the raw prerouting drop runs first
                try:
                    rules = chain_rules(template, chain)
                except AssertionError:
                    rules = []  # declared without a rule body
                with self.subTest(template=name, chain=chain):
                    if "policy drop" in declaration and not rules:
                        continue  # nothing accepts: the policy drops IPv6
                    first_accept_or_jump = next(
                        (index for index, rule in enumerate(rules)
                         if (rule.endswith(" accept") or " jump " in f" {rule}")
                         and rule not in ("iif lo accept", 'iifname "lo" accept')),
                        len(rules),
                    )
                    drops = [
                        index for index, rule in enumerate(rules)
                        if rule in (self.DROP, 'iifname != "lo" meta nfproto ipv6 drop')
                    ]
                    self.assertTrue(drops, rules)
                    self.assertLess(drops[0], first_accept_or_jump, rules)

    def test_prerouting_guard_drops_ipv6_first(self) -> None:
        for template in (NFT, BOOT):
            rules = chain_rules(template, "loopback_guard")
            self.assertEqual(rules[0], 'iifname != "lo" meta nfproto ipv6 drop')

    def test_no_rule_accepts_ipv6(self) -> None:
        for template in (NFT, BOOT):
            self.assertNotRegex(template, r"(?m)^[^#\n]*(nfproto ipv6|ip6 )[^#\n]*accept")

    def test_installers_disable_ipv6_on_the_lan_interface(self) -> None:
        setup = (ROOT / "docker" / "setup-host.sh").read_text(encoding="utf-8")
        for script in (setup, INSTALL):
            with self.subTest(script=script[:40]):
                self.assertIn('"net.ipv6.conf.${LAN_IF}.disable_ipv6"', script)
                self.assertIn('"net/ipv6/conf/${LAN_IF}/disable_ipv6"'
                              if script is INSTALL else
                              '"net/ipv6/conf/$LAN_IF/disable_ipv6"', script)
                # The key goes into the dropjak sysctl.d file, unconditionally.
                if script is INSTALL:
                    block = script[re.search(r'cat ?> ?"\$SYSCTL_FILE"', script).start():]
                    block = block[:block.index("EOF\n", block.index("\n") + 1)]
                else:
                    # setup-host.sh writes the file from a { ... } group.
                    end = script.index('} >"$SYSCTL_FILE"')
                    block = script[script.rindex("\n{\n", 0, end):end]
                self.assertIn("$LAN_IPV6_KEY = 1", block)
                # No opt-out variable.
                self.assertNotRegex(script, r"HV_\w*IPV6")
        # No IPv6 SSH exception is inserted into the boot table any more.
        self.assertNotIn("ip6 saddr", setup)

    def test_setup_host_reads_the_lan_interface_from_env(self) -> None:
        setup = (ROOT / "docker" / "setup-host.sh").read_text(encoding="utf-8")
        start = setup.index("LAN_IF=${HV_LAN_IF:-}")
        end = setup.index('chmod 0644 "$SYSCTL_FILE"')
        snippet = setup[start:end]
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text(
                "HV_WAN_IF=eth0\n# HV_LAN_IF=old0\nHV_LAN_IF=\"eth1.10\"  \n",
                encoding="utf-8",
            )
            sysctl = os.path.join(tmp, "90-dropjak.conf")
            result = subprocess.run(
                ["bash", "-c",
                 "set -euo pipefail\ndie() { echo \"ERROR: $*\" >&2; exit 1; }\n"
                 + snippet + '\ncat "$SYSCTL_FILE"\n'],
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                     "REPO_DIR": tmp, "SYSCTL_FILE": sysctl},
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("net/ipv6/conf/eth1.10/disable_ipv6 = 1", result.stdout)
            self.assertIn("net.ipv4.ip_forward = 1", result.stdout)
            # Without HV_LAN_IF anywhere it refuses (no silent opt-out).
            Path(tmp, ".env").write_text("HV_WAN_IF=eth0\n", encoding="utf-8")
            result = subprocess.run(
                ["bash", "-c",
                 "set -euo pipefail\ndie() { echo \"ERROR: $*\" >&2; exit 1; }\n"
                 + snippet],
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                     "REPO_DIR": tmp, "SYSCTL_FILE": sysctl},
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("HV_LAN_IF is not set", result.stderr)


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

    def test_saving_with_host_bits_stays_strict(self) -> None:
        """DJ-36: the UI/API path and the import keep rejecting host bits."""
        with self.assertRaisesRegex(settings_store.SettingsError, "host bits must be zero"):
            self.store.prepare("create", "block", entry={
                "label": "t", "proto": "tcp", "ports": [443], "dst": "10.0.0.5/8",
            })
        with self.assertRaisesRegex(settings_store.SettingsError, "host bits must be zero"):
            settings_store.validate_state({"block": [{
                "id": "bcde2345", "label": "t", "proto": "tcp", "ports": [443],
                "dst": "10.0.0.5/8",
            }]})

    def test_stored_file_with_host_bits_is_normalized_on_load(self) -> None:
        """DJ-36: a hand-edited file loads; the network goes to the kernel."""
        logged: list[str] = []
        path = os.path.join(self.tmp.name, "hand.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "preauth": [{"id": "abcd1234", "label": "p", "proto": "tcp",
                             "ports": [443], "dst": "192.168.1.7/24"}],
                "block": [{"id": "bcde2345", "label": "b", "proto": "udp",
                           "ports": [53], "dst": "10.0.0.5/8"}],
            }, fh)
        store = settings_store.SettingsStore(path, logger=logged.append)
        logged.clear()
        store.load()
        snapshot = store.snapshot()
        self.assertEqual(snapshot["error"], "")
        self.assertEqual(snapshot["preauth"][0]["dst"], "192.168.1.0/24")
        self.assertEqual(snapshot["block"][0]["dst"], "10.0.0.0/8")
        self.assertEqual(len([line for line in logged if "host bits" in line]), 2)
        # What reaches the kernel is the network, never the host-bit form.
        fw = gateway.Firewall(dry_run=True, logger=lambda *_: None,
                              lan_if="eth1", wan_if="eth0")
        rendered = "\n".join(fw._custom_rules(snapshot["preauth"], snapshot["block"]))
        self.assertIn("ip daddr 10.0.0.0/8 ", rendered)
        self.assertIn("ip daddr 192.168.1.0/24 ", rendered)
        self.assertNotIn("10.0.0.5", rendered)
        self.assertNotIn("192.168.1.7", rendered)


class PreauthScopeTests(unittest.TestCase):
    """DJ-09: input pre-auth entries carry a scope, lan (default) or any."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = settings_store.SettingsStore(
            os.path.join(self.tmp.name, "settings.json"),
            logger=lambda *_: None,
        )

    def entry(self, **extra):
        return {"label": "t", "proto": "tcp", "ports": [8443],
                "direction": "input", **extra}

    def test_scope_defaults_to_lan_and_is_validated(self) -> None:
        self.assertEqual(
            settings_store.normalize_entry("preauth", self.entry())["scope"], "lan"
        )
        self.assertEqual(
            settings_store.normalize_entry(
                "preauth", self.entry(scope=" ANY ")
            )["scope"],
            "any",
        )
        for bad in ("wan", 1, True):
            with self.subTest(scope=bad):
                with self.assertRaisesRegex(settings_store.SettingsError, "scope"):
                    settings_store.normalize_entry("preauth", self.entry(scope=bad))
        # A forward entry has no scope field.
        forward = settings_store.normalize_entry(
            "preauth", {"label": "t", "proto": "tcp", "ports": [80]}
        )
        self.assertNotIn("scope", forward)

    def test_stored_entry_without_scope_loads_as_lan(self) -> None:
        path = os.path.join(self.tmp.name, "old.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"preauth": [{"id": "abcd1234", "label": "t",
                                    "proto": "tcp", "ports": [8443],
                                    "direction": "input"}]}, fh)
        store = settings_store.SettingsStore(path, logger=lambda *_: None)
        store.load()
        self.assertEqual(store.snapshot()["preauth"][0]["scope"], "lan")

    def test_scope_is_saved_and_survives_export_import(self) -> None:
        data = self.store.prepare("create", "preauth", entry=self.entry(scope="any"))
        self.store.commit(data)
        entry_id = data["preauth"][0]["id"]
        self.assertEqual(self.store.snapshot()["preauth"][0]["scope"], "any")
        # The bundle's settings section is validate_state() of the snapshot.
        snapshot = self.store.snapshot()
        snapshot.pop("error")
        exported = json.loads(json.dumps(settings_store.validate_state(snapshot)))
        self.assertEqual(exported["preauth"][0]["scope"], "any")
        self.assertEqual(
            settings_store.validate_state(exported)["preauth"][0]["scope"], "any"
        )
        data = self.store.prepare(
            "update", "preauth", entry_id, entry=self.entry(scope="lan")
        )
        self.assertEqual(data["preauth"][0]["scope"], "lan")

    def test_ui_has_a_translated_scope_select(self) -> None:
        index = (ROOT / "index.html").read_text(encoding="utf-8")
        form = index[index.index("function renderSettingForm("):]
        form = form[:form.index("\nfunction ")]
        self.assertIn("el('select', { name: 'scope' }", form)
        self.assertIn("value: 'lan'", form)
        self.assertIn("value: 'any'", form)
        self.assertIn("payload.entry.scope", form)
        en = index[index.index("  en: {"):index.index("  de: {")]
        de = index[index.index("  de: {"):index.index("const I18N_PATTERNS")]
        for text in ("Hatókör", "Csak LAN", "Bármely interfész (LAN + WAN)"):
            with self.subTest(text=text):
                self.assertIn(f"tr('{text}')", index)
                self.assertIn(f"    '{text}': '", en)
                self.assertIn(f"    '{text}': '", de)

    def test_reserved_ports_still_rejected_with_any_scope(self) -> None:
        with self.assertRaisesRegex(
            settings_store.SettingsError, "cannot open these host ports"
        ):
            self.store.prepare(
                "create", "preauth", entry=self.entry(ports=[22], scope="any")
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

    def test_resync_ends_authorized_sessions(self) -> None:
        """Decision (a): sessions whose kernel elements were lost end."""
        session = self.gw.sessions.login("alice", IP)
        self.gw.sessions.authorize(session.token, IP, self.rule, 60)
        waiting = self.gw.sessions.login("bob", "192.168.50.24")
        revoked: list[str] = []
        self.fw.revoke_all = lambda ip, *args, **kwargs: revoked.append(ip)

        self.fw.token = 99
        self.assertTrue(self.gw.check_firewall_state())
        self.assertEqual(self.gw.sessions.count(authorized_only=True), 0)
        self.assertIsNone(self.gw.sessions.validate(session.token, IP))
        # A login still waiting for authorization holds no grant and stays.
        self.assertIsNotNone(self.gw.sessions.validate(waiting.token, "192.168.50.24"))
        self.assertEqual(revoked, [IP])
        self.assertEqual(self.gw.sessions.last_end(IP)["reason"], "firewall_reset")
        ended = [
            fields for event, fields in self.audit.events
            if event == "session_ended"
        ]
        self.assertEqual(len(ended), 1)
        self.assertEqual(ended[0]["reason"], "firewall_reset")
        self.assertEqual(ended[0]["user"], "alice")
        resync = [
            fields for event, fields in self.audit.events
            if event == "firewall_resync"
        ]
        self.assertEqual(resync[0]["sessions_revoked"], 1)
        self.assertIn("firewall_reset", gateway.END_REASONS)

    def test_partial_resync_keeps_sessions_until_it_succeeds(self) -> None:
        session = self.gw.sessions.login("alice", IP)
        self.gw.sessions.authorize(session.token, IP, self.rule, 60)
        self.f2b.sync = lambda: False
        self.fw.token = 99
        self.assertFalse(self.gw.check_firewall_state())
        self.assertNotIn("session_ended", self.audit.names())

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
        start = ENTRYPOINT.index('set -- meta mark "$HV_FWD_MARK"')
        rule = ENTRYPOINT[start:ENTRYPOINT.index("hv-docker-fwd-mark", start)]
        self.assertIn("oifname != '\"docker*\"'", rule)
        self.assertIn("oifname != '\"br-*\"'", rule)
        # Detected custom bridges are excluded from the accept too.
        self.assertIn('for _br in $DOCKER_BRIDGES; do', rule)
        self.assertIn('"$@" accept', rule)
        # The drop guard for unmarked packets is unchanged.
        self.assertIn('meta mark != "$HV_FWD_MARK" drop', ENTRYPOINT)

    def test_missing_docker_guard_is_never_fatal(self) -> None:
        """DJ-03: a crash loop would lock the host out; log loudly instead."""
        self.assertNotRegex(ENTRYPOINT, r"docker_forward_guard[^\n]*\n?[^\n]*\|\|\s*die")
        self.assertIn("docker_forward_guard || log_guard_error", ENTRYPOINT)
        watchdog = ENTRYPOINT[ENTRYPOINT.index("start_firewall_watchdog() {"):]
        self.assertIn("if ! docker_forward_guard; then", watchdog)
        self.assertIn("-ge 60 ]", watchdog)
        self.assertIn("log_guard_error", watchdog)
        self.assertIn("sync_docker_bridges", watchdog)

    def run_entrypoint(self, script: str, tmp: str, **extra: str):
        """Runs entrypoint functions with fake ip and nft tools on PATH."""
        functions = ENTRYPOINT.split("# ------------------------------------------------------------------------ main")[0]
        env = {
            "PATH": tmp + ":" + os.environ.get("PATH", "/usr/bin:/bin"),
            "NFT_LOG": os.path.join(tmp, "nft.log"),
            **extra,
        }
        return subprocess.run(
            ["sh", "-c", functions + "\nset +e\n" + script],
            env=env, capture_output=True, text=True, timeout=30,
        )

    def fake_tools(self, tmp: str, nft_body: str) -> None:
        ip = Path(tmp, "ip")
        ip.write_text(
            "#!/bin/sh\n"
            "cat <<'OUT'\n"
            "3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN\n"
            "4: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP\n"
            "5: mynet0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP\n"
            "6: virbr0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN\n"
            "OUT\n",
            encoding="utf-8",
        )
        nft = Path(tmp, "nft")
        nft.write_text("#!/bin/sh\n" + nft_body, encoding="utf-8")
        for tool in (ip, nft):
            tool.chmod(0o755)

    def test_bridges_are_detected_without_the_lan_interface(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.fake_tools(
                tmp, 'printf "%s\\n" "$*" >>"$NFT_LOG"\ncat >>"$NFT_LOG"\n'
            )
            result = self.run_entrypoint(
                'NFT_BIN=nft\necho "[$(detect_bridges)]"\n'
                "sync_docker_bridges force\n"
                'echo "applied=[$DOCKER_BRIDGES_APPLIED]"\n',
                tmp, HV_LAN_IF="eth1", HV_WAN_IF="virbr0",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            nft_input = Path(tmp, "nft.log").read_text(encoding="utf-8")
        # The LAN (and here the WAN) interface is never a container bridge.
        self.assertIn("[docker0 mynet0]", result.stdout)
        self.assertIn("applied=[docker0 mynet0]", result.stdout)
        self.assertIn("-f -", nft_input)
        self.assertIn("flush set inet hatarvedelem docker_bridges", nft_input)
        self.assertIn(
            'add element inet hatarvedelem docker_bridges { "docker0", "mynet0" }',
            nft_input,
        )

    def test_missing_docker_user_chain_reports_the_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # No ip filter DOCKER-USER chain; Docker's nftables backend table
            # exists.
            self.fake_tools(
                tmp,
                'case "$*" in\n'
                '  *DOCKER-USER*) exit 1 ;;\n'
                '  *docker-bridges*) exit 0 ;;\n'
                "esac\nexit 0\n",
            )
            result = self.run_entrypoint(
                "NFT_BIN=nft\nHV_FWD_MARK=0x1\n"
                "if docker_forward_guard; then echo GUARD-OK; "
                "else log_guard_error; fi\necho continued\n",
                tmp,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("GUARD-OK", result.stdout)
        self.assertIn("ERROR: Docker forward protection is NOT installed", result.stdout)
        self.assertIn("nftables firewall backend", result.stdout)
        self.assertIn("continued", result.stdout)

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

    def run_proxy_key_check(self, **extra: str) -> subprocess.CompletedProcess:
        functions = ENTRYPOINT.split("# ------------------------------------------------------------------------ main")[0]
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **extra}
        return subprocess.run(
            ["sh", "-c", functions + "\ncheck_proxy_key\necho passed\n"],
            env=env, capture_output=True, text=True, timeout=30,
        )

    def test_proxy_requires_a_long_key(self) -> None:
        """DJ-10: HV_PROXY=1 without a 32+ character key refuses to start."""
        for key in ("", "short", "k" * 31):
            with self.subTest(length=len(key)):
                result = self.run_proxy_key_check(HV_PROXY="1", HV_PROXY_KEY=key)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("passed", result.stdout)
                self.assertIn("HV_PROXY_KEY", result.stderr)
                self.assertIn("openssl rand -hex 32", result.stderr)
        result = self.run_proxy_key_check(HV_PROXY="yes", HV_PROXY_KEY="k" * 32)
        self.assertEqual(result.returncode, 0, result.stderr)
        # Without the proxy no key is needed.
        result = self.run_proxy_key_check(HV_PROXY="0")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_proxy_key_is_checked_before_the_firewall(self) -> None:
        main = ENTRYPOINT.split("# ------------------------------------------------------------------------ main")[1]
        self.assertLess(main.index("check_proxy_key"), main.index("load_firewall"))
        # A custom command (CLI user management) is not refused.
        self.assertLess(main.index('run_as_app "$@"'), main.index("check_proxy_key"))

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
