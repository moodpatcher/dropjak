#!/usr/bin/env python3
"""The port proxy (3.11.0): settings validation, nft generation, template order.

The tests do not touch the system firewall: script execution is intercepted,
the template is rendered with the entrypoint's render_ruleset function, and
only ``unshare -rn nft -c`` validates it (if available).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import gateway  # noqa: E402
import settings_store  # noqa: E402
import test_proxy as tp  # noqa: E402

T = "inet hatarvedelem"


def forward(**over) -> dict:
    entry = {
        "id": "mc", "label": "Minecraft", "proto": "tcp", "type": "forward",
        "listen_port": 25565, "target_ip": "192.168.10.20",
        "target_port": 25565, "ifaces": "wan", "snat": False, "enabled": True,
    }
    entry.update(over)
    return entry


def input_entry(**over) -> dict:
    entry = {
        "id": "vc", "label": "Voice", "proto": "udp", "type": "input",
        "listen_port": 24455, "target_ip": "", "target_port": 24454,
        "ifaces": "lan", "snat": False, "enabled": True,
    }
    entry.update(over)
    return entry


def render_template() -> str:
    return tp.ProxyFirewallTemplateTests.render(
        tp.ProxyFirewallTemplateTests("test_proxy_off_keeps_ports_closed"), "1"
    )


class StoreValidationTests(unittest.TestCase):
    def check(self, *entries):
        return settings_store._port_proxies(list(entries))

    def test_valid_entries_are_normalized(self) -> None:
        out = self.check(
            {k: v for k, v in forward().items() if k != "id"},
            input_entry(snat=True, target_ip="10.0.0.1"),
        )
        self.assertRegex(out[0]["id"], r"^[0-9a-f]{8}$")
        self.assertEqual(out[0]["target_ip"], "192.168.10.20")
        # For an input entry there is no target IP and no SNAT.
        self.assertEqual(out[1]["target_ip"], "")
        self.assertIs(out[1]["snat"], False)
        # A Docker bridge (172.16/12) target is allowed too.
        self.check(forward(target_ip="172.30.0.2"))

    def test_reserved_listen_ports(self) -> None:
        for port in (22, 53, 67, 80, 443, 2019, settings_store.PORTAL_PORT):
            with self.subTest(port=port), self.assertRaisesRegex(
                settings_store.SettingsError, "reserved"
            ):
                self.check(forward(listen_port=port))

    def test_duplicate_listen_ports(self) -> None:
        cases = (
            (forward(), forward(id="b")),
            (forward(proto="both"), forward(id="b", proto="udp")),
            (forward(proto="udp"), forward(id="b", proto="both")),
            # A disabled entry also reserves the port.
            (forward(enabled=False), forward(id="b")),
        )
        for first, second in cases:
            with self.subTest(first=first["proto"], second=second["proto"]), \
                    self.assertRaisesRegex(settings_store.SettingsError, "already in use"):
                self.check(first, second)
        # TCP and UDP on the same port do not collide.
        self.check(forward(), forward(id="b", proto="udp"))
        with self.assertRaisesRegex(settings_store.SettingsError, "duplicate"):
            self.check(forward(), forward(proto="udp"))

    def test_forward_target_must_be_private(self) -> None:
        for ip in ("8.8.8.8", "127.0.0.1", "169.254.1.1", "", None, "10.0.0"):
            with self.subTest(ip=ip), self.assertRaisesRegex(
                settings_store.SettingsError, "private-network"
            ):
                self.check(forward(target_ip=ip))

    def test_input_target_restrictions(self) -> None:
        for port in (22, 2019, settings_store.PORTAL_PORT):
            with self.subTest(port=port), self.assertRaisesRegex(
                settings_store.SettingsError, "input target port"
            ):
                self.check(input_entry(target_port=port))
        with self.assertRaisesRegex(settings_store.SettingsError, "host rule"):
            self.check(input_entry(target_port=24455))
        # For forward, the same port is the usual case.
        self.check(forward(target_port=25565))

    def test_field_types(self) -> None:
        bad = (
            {"proto": "icmp"}, {"type": "nat"}, {"ifaces": "eth0"},
            {"listen_port": "25565"}, {"listen_port": True},
            {"target_port": 0}, {"target_port": 70000}, {"snat": "yes"},
            {"enabled": 1}, {"label": ""}, {"id": "Rossz ID"},
        )
        for over in bad:
            with self.subTest(over=over), self.assertRaises(
                settings_store.SettingsError
            ):
                self.check(forward(**over))
        with self.assertRaises(settings_store.SettingsError):
            settings_store._port_proxies({})
        with self.assertRaisesRegex(settings_store.SettingsError, "at most"):
            settings_store._port_proxies(
                [forward(id=f"e{i}", listen_port=10000 + i) for i in range(65)]
            )

    def test_legacy_file_and_prepare_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "s.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"preauth": [], "block": []}, fh)
            store = settings_store.SettingsStore(path, logger=lambda *_: None)
            self.assertEqual(store.snapshot()["port_proxies"], [])
            self.assertEqual(store.snapshot()["error"], "")
            data = store.prepare_port_proxies([forward()])
            self.assertEqual(len(data["port_proxies"]), 1)
            with open(path, encoding="utf-8") as fh:
                self.assertNotIn("port_proxies", json.load(fh))
            store.commit(data)
            reloaded = settings_store.SettingsStore(path, logger=lambda *_: None)
            self.assertEqual(reloaded.snapshot()["port_proxies"], data["port_proxies"])


class RuleGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fw = gateway.Firewall(
            dry_run=True, logger=lambda *_: None, lan_if="eth1", wan_if="eth0",
            lan_network=gateway._parse_lan_network("192.168.10.0/24"),
        )
        self.scripts: list[str] = []
        self.fw._run_script = self.scripts.append  # type: ignore[method-assign]
        # Deterministic: there is no listening socket, hence the input redirect.
        empty = tempfile.TemporaryDirectory()
        self.addCleanup(empty.cleanup)
        self.fw.proc_net = self.fw.sysctl_conf = empty.name

    def test_forward_wan_tcp(self) -> None:
        self.assertEqual(self.fw._portproxy_rules([forward()]), [
            f'add rule {T} portproxy_nat iifname "eth0" fib daddr type local '
            "tcp dport 25565 dnat ip to 192.168.10.20:25565",
        ])

    def test_forward_both_snat(self) -> None:
        rules = self.fw._portproxy_rules([forward(
            proto="both", ifaces="both", snat=True, listen_port=24454,
            target_port=24454,
        )])
        self.assertEqual(rules, [
            f'add rule {T} portproxy_nat iifname {{ "eth1", "eth0" }} '
            "fib daddr type local tcp dport 24454 "
            "dnat ip to 192.168.10.20:24454",
            f"add rule {T} portproxy_snat meta l4proto tcp ct status dnat "
            "ct original proto-dst 24454 ip daddr 192.168.10.20 "
            "tcp dport 24454 masquerade",
            f'add rule {T} portproxy_nat iifname {{ "eth1", "eth0" }} '
            "fib daddr type local udp dport 24454 "
            "dnat ip to 192.168.10.20:24454",
            f"add rule {T} portproxy_snat meta l4proto udp ct status dnat "
            "ct original proto-dst 24454 ip daddr 192.168.10.20 "
            "udp dport 24454 masquerade",
        ])

    def test_input_lan_with_mac_binding(self) -> None:
        match = "meta l4proto udp ct status dnat ct original proto-dst 24455"
        grant = "ip saddr . ct original proto-dst @allowed_input_udp"
        mac = (f'iifname "eth1" {match} {grant} '
               "ip saddr . ether saddr != @client_mac")
        self.assertEqual(self.fw._portproxy_rules([input_entry()]), [
            f'add rule {T} portproxy_nat iifname "eth1" fib daddr type local '
            "udp dport 24455 redirect to :24454",
            f"add rule {T} portproxy_input {mac} limit rate 30/minute burst 60 "
            'packets log prefix "dropjak-drop reason=mac " group 5',
            f"add rule {T} portproxy_input {mac} drop",
            f"add rule {T} portproxy_input {match} {grant} accept",
            f"add rule {T} portproxy_input {match} limit rate 30/minute "
            'burst 60 packets log prefix "dropjak-drop reason=portproxy " group 5',
            f"add rule {T} portproxy_input {match} drop",
        ])

    def test_input_wan_has_no_mac_rule(self) -> None:
        rules = self.fw._portproxy_rules([input_entry(ifaces="wan", proto="tcp")])
        self.assertFalse(any("client_mac" in rule for rule in rules))
        self.assertIn(
            f"add rule {T} portproxy_input meta l4proto tcp ct status dnat "
            "ct original proto-dst 24455 "
            "ip saddr . ct original proto-dst @allowed_input_tcp accept",
            rules,
        )

    def test_disabled_and_errors(self) -> None:
        self.assertEqual(self.fw._portproxy_rules([forward(enabled=False)]), [])
        no_wan = gateway.Firewall(dry_run=True, logger=lambda *_: None, lan_if="eth1")
        for fw, entry in (
            (no_wan, forward()),
            (self.fw, forward(target_ip="8.8.8.8")),
            (self.fw, forward(listen_port="1")),
            (self.fw, forward(proto="sctp")),
        ):
            with self.subTest(entry=entry), self.assertRaises(gateway.FirewallError):
                fw._portproxy_rules([entry])
        # With an invalid entry replace_custom runs nothing.
        with self.assertRaises(gateway.FirewallError):
            self.fw.replace_custom(port_proxies=[forward(target_ip="8.8.8.8")])
        self.assertEqual(self.scripts, [])

    def test_replace_custom_flushes_proxy_chains_in_same_transaction(self) -> None:
        self.fw.replace_custom(port_proxies=[forward()])
        lines = self.scripts[0].splitlines()
        for chain in gateway.PORTPROXY_CHAINS:
            self.assertIn(f"flush chain {T} {chain}", lines)
        self.assertLess(
            lines.index(f"flush chain {T} portproxy_nat"),
            next(i for i, l in enumerate(lines) if "dnat ip to" in l),
        )
        # Invalid settings file (keep_block): the proxy chains remain empty.
        self.scripts.clear()
        self.fw.replace_custom((), (), keep_block=True)
        self.assertIn(f"flush chain {T} portproxy_nat", self.scripts[0])
        self.assertNotIn("dnat", self.scripts[0])

    @unittest.skipUnless(shutil.which("nft") and shutil.which("unshare"), "no nft/unshare")
    def test_nft_check_template_with_rules(self) -> None:
        rules = self.fw._portproxy_rules([
            forward(),
            forward(id="vc", proto="both", ifaces="both", snat=True,
                    listen_port=24454, target_port=24454),
            input_entry(proto="both", ifaces="both"),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.nft")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(render_template() + "\n" + "\n".join(rules) + "\n")
            result = subprocess.run(
                ["unshare", "-rn", "nft", "-c", "-f", path],
                capture_output=True, text=True, timeout=20,
            )
        if result.returncode != 0 and "Operation not permitted" in result.stderr:
            self.skipTest("the user namespace is not available")
        self.assertEqual(result.returncode, 0, result.stderr)


HEAD = "  sl  local_address rem_address   st\n"
V6_ZERO = "00000000000000000000000000000000"


def write_proc(root: str, files: dict[str, list[tuple[str, int, str]]],
               localnet: dict[str, str] | None = None) -> None:
    """Fake /proc/net (address hex, port, state) and route_localnet files."""
    for name, rows in files.items():
        with open(os.path.join(root, name), "w", encoding="ascii") as fh:
            fh.write(HEAD + "".join(
                f"   {i}: {addr}:{port:04X} {V6_ZERO if len(addr) > 8 else '00000000'}:0000 {st}\n"
                for i, (addr, port, st) in enumerate(rows)
            ))
    for iface, value in (localnet or {}).items():
        os.makedirs(os.path.join(root, "conf", iface), exist_ok=True)
        with open(os.path.join(root, "conf", iface, "route_localnet"), "w") as fh:
            fh.write(value + "\n")


# 127.0.0.1 / 0.0.0.0 / 127.0.0.53 in the kernel's native (little-endian) output.
LO, ANY, STUB = "0100007F", "00000000", "3500007F"
MAPPED_LO = "0000000000000000FFFF00000100007F"
V6_LOOP = "00000000000000000000000001000000"


class LoopbackTargetTests(unittest.TestCase):
    """3.11.1: an input target listening only on 127.0.0.1 needs DNAT, not redirect.

    Live bug: the redirect rewrote to the WAN address, the Docker publication
    on 127.0.0.1:8081 did not respond there, and the kernel sent an RST.
    """

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.fw = gateway.Firewall(
            dry_run=True, logger=lambda *_: None, lan_if="eth1", wan_if="eth0",
            lan_network=gateway._parse_lan_network("192.168.10.0/24"),
        )
        self.fw.proc_net = self.root
        self.fw.sysctl_conf = os.path.join(self.root, "conf")

    def test_loopback_target_detection(self) -> None:
        cases = [
            ({"tcp": [(LO, 8081, "0A")]}, "tcp", "127.0.0.1"),
            ({"tcp": [(LO, 8081, "01")]}, "tcp", None),  # not LISTEN
            ({"tcp": [(LO, 8081, "0A"), (ANY, 8081, "0A")]}, "tcp", None),
            ({"tcp": [(ANY, 8081, "0A")]}, "tcp", None),
            ({"tcp6": [(MAPPED_LO, 8081, "0A")]}, "tcp", "127.0.0.1"),
            ({"tcp": [(LO, 8081, "0A")], "tcp6": [(V6_ZERO, 8081, "0A")]}, "tcp", None),
            ({"tcp": [(LO, 8081, "0A")], "tcp6": [(V6_LOOP, 8081, "0A")]}, "tcp", "127.0.0.1"),
            ({"udp": [(STUB, 8081, "07")]}, "udp", "127.0.0.53"),
            ({"udp": [(LO, 8081, "07")]}, "tcp", None),  # other protocol
            ({"udp": [(LO, 8082, "07")]}, "udp", None),  # other port
            ({}, "udp", None),
        ]
        for files, proto, expected in cases:
            with self.subTest(files=files, proto=proto):
                for name in ("tcp", "tcp6", "udp", "udp6"):
                    path = os.path.join(self.root, name)
                    if os.path.exists(path):
                        os.remove(path)
                write_proc(self.root, files)
                self.assertEqual(gateway.loopback_target(proto, 8081, self.root), expected)

    def test_route_localnet_all_or_every_iface(self) -> None:
        conf = os.path.join(self.root, "conf")
        self.assertFalse(gateway.route_localnet(["eth0"], conf))
        write_proc(self.root, {}, {"all": "0", "eth0": "1", "eth1": "0"})
        self.assertTrue(gateway.route_localnet(["eth0"], conf))
        self.assertFalse(gateway.route_localnet(["eth1", "eth0"], conf))
        write_proc(self.root, {}, {"all": "1"})
        self.assertTrue(gateway.route_localnet(["eth1", "eth0"], conf))

    def test_input_to_loopback_only_target_uses_dnat(self) -> None:
        write_proc(self.root, {"tcp": [(LO, 8081, "0A")], "udp": [(LO, 9001, "07")]},
                   {"all": "1"})
        rules = self.fw._portproxy_rules([
            input_entry(id="w", proto="tcp", ifaces="wan", listen_port=8084,
                        target_port=8081),
            input_entry(id="v", proto="udp", ifaces="both", listen_port=18086,
                        target_port=9001),
        ])
        nat = [r for r in rules if " portproxy_nat " in r]
        self.assertEqual(nat, [
            f'add rule {T} portproxy_nat iifname "eth0" fib daddr type local '
            "tcp dport 8084 dnat ip to 127.0.0.1:8081",
            f'add rule {T} portproxy_nat iifname {{ "eth1", "eth0" }} '
            "fib daddr type local udp dport 18086 dnat ip to 127.0.0.1:9001",
        ])
        # Authorization still applies to the original listening port.
        self.assertIn(
            f"add rule {T} portproxy_input meta l4proto tcp ct status dnat "
            "ct original proto-dst 8084 "
            "ip saddr . ct original proto-dst @allowed_input_tcp accept", rules,
        )
        self.assertEqual(self.fw.portproxy_localnet_blocked([input_entry(
            proto="tcp", ifaces="wan", listen_port=8084, target_port=8081)]), [])

    def test_wildcard_or_localnet_off_keeps_redirect(self) -> None:
        entry = input_entry(proto="both", ifaces="wan", listen_port=8084, target_port=8081)
        # Wildcard UDP: the response source is the interface address, hence redirect.
        write_proc(self.root, {"tcp": [(LO, 8081, "0A")], "udp": [(ANY, 8081, "07")]},
                   {"all": "1"})
        nat = [r for r in self.fw._portproxy_rules([entry]) if " portproxy_nat " in r]
        self.assertEqual([r.rsplit(" dport ", 1)[1] for r in nat], [
            "8084 dnat ip to 127.0.0.1:8081", "8084 redirect to :8081",
        ])
        # Without route_localnet the kernel would drop the 127.0.0.1 target:
        # redirect and a warning.
        write_proc(self.root, {}, {"all": "0", "eth0": "0"})
        nat = [r for r in self.fw._portproxy_rules([entry]) if " portproxy_nat " in r]
        self.assertTrue(all(r.endswith("redirect to :8081") for r in nat))
        self.assertEqual(self.fw.portproxy_localnet_blocked([entry]), [("tcp", 8084)])
        warnings = gateway.port_proxy_warnings([entry], set(), set(), {("tcp", 8084)})
        self.assertEqual([(w["proto"], w["localnet"]) for w in warnings], [("tcp", True)])
        # The forward entry is not affected.
        self.assertEqual(self.fw.portproxy_localnet_blocked([forward()]), [])

    def test_refresh_reapplies_when_target_binding_changes(self) -> None:
        store = settings_store.SettingsStore(
            os.path.join(self.root, "s.json"), logger=lambda *_: None
        )
        store.commit(store.prepare_port_proxies([input_entry(
            proto="tcp", ifaces="wan", listen_port=8084, target_port=8081)]))
        scripts: list[str] = []
        self.fw._run_script = scripts.append  # type: ignore[method-assign]
        gw = types.SimpleNamespace(settings=store, firewall=self.fw, audit=None)
        gw._write_audit = lambda *_a, **_k: None
        gw._apply_custom_settings = (
            lambda snap=None: gateway.Gateway._apply_custom_settings(gw, snap)
        )
        flushed: list[tuple[str, int]] = []
        old_flush = gateway.conntrack_flush_port
        gateway.conntrack_flush_port = lambda p, n, audit=None: flushed.append((p, n)) or True
        self.addCleanup(setattr, gateway, "conntrack_flush_port", old_flush)
        # Nothing is installed yet: the refresher does not touch the kernel.
        self.assertEqual(gateway.Gateway.refresh_port_proxies(gw), [])
        gw._apply_custom_settings()
        self.assertIn("redirect to :8081", scripts[-1])
        self.assertEqual(gateway.Gateway.refresh_port_proxies(gw), [])
        self.assertEqual(len(scripts), 1)
        # The target starts later, bound only to loopback (boot-time order).
        write_proc(self.root, {"tcp": [(LO, 8081, "0A")]}, {"all": "1"})
        self.assertEqual(gateway.Gateway.refresh_port_proxies(gw), [("tcp", 8084)])
        self.assertIn("dnat ip to 127.0.0.1:8081", scripts[-1])
        self.assertEqual(flushed, [("tcp", 8084)])
        self.assertEqual(gateway.Gateway.refresh_port_proxies(gw), [])
        self.assertEqual(len(scripts), 2)


class TemplateOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = render_template()

    def chain(self, name: str) -> list[str]:
        start = self.text.index(f"    chain {name} {{")
        end = self.text.index("\n    }", start)
        return [
            line.strip() for line in self.text[start:end].splitlines()[1:]
            if line.strip() and not line.strip().startswith("#")
        ]

    def index(self, lines, needle: str) -> int:
        return next(i for i, line in enumerate(lines) if needle in line)

    def test_input_jump_after_ban_block_mac_before_accepts(self) -> None:
        lines = self.chain("input")
        jump = lines.index("jump portproxy_input")
        for before in (
            "ip saddr @banned_v4 drop", "jump block",
            "ip saddr . udp dport @allowed_input_udp ip saddr . ether saddr != @client_mac drop",
            "ip saddr @proxy_banned_v4 tcp dport { 80, 443 } drop",
        ):
            self.assertLess(self.index(lines, before), jump, before)
        for after in (
            "tcp dport { 80, 443 } accept", "reason=host-revoked",
            "ct state established,related accept",
            "ip saddr . tcp dport @allowed_input_tcp tcp dport != 8100 accept",
        ):
            self.assertGreater(self.index(lines, after), jump, after)

    def test_forward_authorizes_original_port_with_mark(self) -> None:
        lines = self.chain("forward")
        self.assertIn(
            "meta l4proto tcp ct original ip saddr . ct original proto-dst "
            "@allowed_tcp meta mark set 0x44524a4b accept", lines,
        )
        self.assertIn(
            "meta l4proto udp ct original ip saddr . ct original proto-dst "
            "@allowed_udp meta mark set 0x44524a4b accept", lines,
        )
        # The response of a DNAT target on the LAN does not fall under the client MAC check.
        for proto in ("tcp", "udp"):
            self.assertIn(
                f'iifname "eth1" meta l4proto {proto} ct direction original '
                f"ct original ip saddr . ct original proto-dst @allowed_{proto} "
                "ip saddr . ether saddr != @client_mac drop", lines,
            )

    def test_nat_chains(self) -> None:
        self.assertIn(
            "add chain inet hatarvedelem portproxy_prerouting {\n"
            "    type nat hook prerouting priority -101; policy accept;",
            self.text,
        )
        self.assertEqual(self.chain("portproxy_prerouting"), ["jump portproxy_nat"])
        post = self.chain("postrouting")
        self.assertEqual(post[0], "jump portproxy_snat")
        flushed = [
            line for line in self.text.splitlines()
            if line.startswith("flush chain")
        ]
        self.assertIn("flush chain inet hatarvedelem portproxy_prerouting", flushed)
        # The template reload does not flush the runtime chains.
        for chain in gateway.PORTPROXY_CHAINS:
            self.assertIn(f"add chain inet hatarvedelem {chain}\n", self.text)
            self.assertNotIn(f"flush chain inet hatarvedelem {chain}", flushed)
        for chain in ("portproxy_prerouting",) + gateway.PORTPROXY_CHAINS:
            self.assertIn(chain, gateway.RULESET_CHAINS)

    def test_loopback_guard_before_nat(self) -> None:
        """With route_localnet, a 127/8 packet arriving from outside is dropped."""
        guard = [
            'iifname != "lo" ip daddr 127.0.0.0/8 drop',
            'iifname != "lo" ip saddr 127.0.0.0/8 drop',
        ]
        self.assertIn(
            "add chain inet hatarvedelem loopback_guard {\n"
            "    type filter hook prerouting priority raw; policy accept;",
            self.text,
        )
        self.assertIn("flush chain inet hatarvedelem loopback_guard", self.text)
        self.assertEqual(self.chain("loopback_guard"), guard)
        self.assertIn("loopback_guard", gateway.RULESET_CHAINS)
        boot = (ROOT / "deploy" / "hatarvedelem-boot.nft").read_text()
        self.assertIn("type filter hook prerouting priority raw; policy accept;", boot)
        for rule in guard:
            self.assertIn(rule, boot)
        setup = (ROOT / "docker" / "setup-host.sh").read_text()
        self.assertIn("net.ipv4.conf.all.route_localnet = 1", setup)


class ApplyRollbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = settings_store.SettingsStore(
            os.path.join(self.tmp.name, "s.json"), logger=lambda *_: None
        )
        self.fw = gateway.Firewall(
            dry_run=True, logger=lambda *_: None, lan_if="eth1", wan_if="eth0"
        )
        self.scripts: list[str] = []
        self.fail = []
        self.fw._run_script = self.run_script  # type: ignore[method-assign]
        self.audit: list[str] = []
        gw = types.SimpleNamespace(settings=self.store, firewall=self.fw)
        gw._write_audit = lambda event, **_: self.audit.append(event)
        gw._restore_custom_settings = (
            lambda old: gateway.Gateway._restore_custom_settings(gw, old)
        )
        self.gw = gw
        self.store.commit(self.store.prepare_port_proxies([forward()]))

    def run_script(self, script: str) -> None:
        self.scripts.append(script)
        if self.fail and self.fail.pop(0):
            raise gateway.FirewallError("simulated nft error")

    def apply(self, entries) -> None:
        gateway.Gateway.apply_settings(
            self.gw, self.store.prepare_port_proxies(entries)
        )

    def test_apply_then_commit(self) -> None:
        self.apply([forward(target_port=25566)])
        self.assertIn("192.168.10.20:25566", self.scripts[-1])
        self.assertEqual(self.store.snapshot()["port_proxies"][0]["target_port"], 25566)

    def test_nft_failure_rolls_back_and_keeps_file(self) -> None:
        self.fail = [True, False]
        with self.assertRaises(gateway.FirewallError):
            self.apply([forward(target_port=25566)])
        self.assertIn("192.168.10.20:25565", self.scripts[-1])
        self.assertEqual(self.store.snapshot()["port_proxies"][0]["target_port"], 25565)

    def test_commit_failure_restores_old_rules(self) -> None:
        def broken(_data):
            raise OSError("disk full")
        self.store.commit = broken  # type: ignore[method-assign]
        with self.assertRaises(OSError):
            self.apply([forward(target_port=25566)])
        self.assertIn("192.168.10.20:25566", self.scripts[-2])
        self.assertIn("192.168.10.20:25565", self.scripts[-1])

    def test_startup_and_invalid_snapshot(self) -> None:
        gateway.Gateway._apply_custom_settings(self.gw)
        self.assertIn("dnat ip to 192.168.10.20:25565", self.scripts[-1])
        gateway.Gateway._apply_custom_settings(
            self.gw, {"error": "invalid", "port_proxies": [forward()]}
        )
        self.assertNotIn("dnat", self.scripts[-1])
        self.assertIn("flush chain inet hatarvedelem portproxy_nat", self.scripts[-1])
        self.assertEqual(self.audit, ["settings_invalid"])


class HelperTests(unittest.TestCase):
    def test_changes(self) -> None:
        old = [forward(), forward(id="v", proto="both", listen_port=24454,
                                  target_port=24454)]
        self.assertEqual(gateway.port_proxy_changes(old, old), [])
        new = [forward(target_port=25566), forward(
            id="v", proto="both", listen_port=24454, target_port=24454,
            enabled=False)]
        self.assertEqual(
            gateway.port_proxy_changes(old, new),
            [("tcp", 24454), ("tcp", 25565), ("udp", 24454)],
        )
        self.assertEqual(gateway.port_proxy_changes([], [forward()]), [("tcp", 25565)])

    def test_conntrack_flush_port(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "log")
            tool = os.path.join(tmp, "conntrack")
            with open(tool, "w", encoding="utf-8") as fh:
                fh.write(f'#!/bin/sh\necho "$*" >> "{log}"\nexit 0\n')
            os.chmod(tool, 0o755)
            old = gateway.CONNTRACK_BIN
            gateway.CONNTRACK_BIN = tool
            try:
                self.assertTrue(gateway.conntrack_flush_port("udp", 24454))
            finally:
                gateway.CONNTRACK_BIN = old
            with open(log, encoding="utf-8") as fh:
                self.assertEqual(fh.read().split(), ["-D", "-p", "udp", "--orig-port-dst", "24454"])

    def test_listening_ports_and_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            head = "  sl  local_address rem_address   st\n"
            with open(os.path.join(tmp, "tcp"), "w", encoding="ascii") as fh:
                fh.write(head + "   0: 00000000:63DD 00000000:0000 0A\n"
                         "   1: 0100007F:1F90 0100007F:9C40 01\n")
            with open(os.path.join(tmp, "udp6"), "w", encoding="ascii") as fh:
                fh.write(head + "   0: 00000000000000000000000000000000:5F66 "
                         "00000000000000000000000000000000:0000 07\n")
            ports = gateway.listening_ports(tmp)
        self.assertEqual(ports, {("tcp", 25565), ("udp", 24422)})
        warnings = gateway.port_proxy_warnings(
            [forward(proto="both"), forward(id="x", listen_port=30000, enabled=False)],
            ports, {("udp", 25565)},
        )
        self.assertEqual(warnings, [
            {"proto": "tcp", "port": 25565, "docker": False, "listen": True,
             "localnet": False},
            {"proto": "udp", "port": 25565, "docker": True, "listen": False,
             "localnet": False},
        ])

    def test_docker_published_ports_parse(self) -> None:
        fw = gateway.Firewall(dry_run=True, logger=lambda *_: None)
        out = (b'table ip nat {\n\tchain DOCKER {\n\t\tiifname != "br-1" '
               b"meta l4proto tcp tcp dport 25565 counter dnat to 172.30.0.2:25565\n"
               b"\t}\n}\n")
        fw._run = lambda args, check=True: subprocess.CompletedProcess(args, 0, out, b"")  # type: ignore[method-assign]
        self.assertEqual(fw.docker_published_ports(), {("tcp", 25565)})
        fw._run = lambda args, check=True: subprocess.CompletedProcess(args, 1, b"", b"x")  # type: ignore[method-assign]
        self.assertEqual(fw.docker_published_ports(), set())

    def test_portproxy_drop_counts_for_drop_ban(self) -> None:
        self.assertIn("portproxy", gateway.DROP_BAN_REASONS)


if __name__ == "__main__":
    unittest.main()
