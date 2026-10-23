#!/usr/bin/env python3
"""Dropjak home tunnel agent: unit and package-level tests.

The unit tests load ``deploy/tunnel-agent/agent.py`` (with importlib because
of the directory name) and mock subprocess/socket/urllib calls. The
package-level test runs ``tests/tunnel_agent_netns.py`` under ``unshare -rn``;
if the namespace or nft/ip is not available, the test is skipped.
"""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
import pty
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
AGENT_PATH = ROOT / "deploy" / "tunnel-agent" / "agent.py"
HELPER = Path(__file__).resolve().with_name("tunnel_agent_netns.py")

_spec = importlib.util.spec_from_file_location("dropjak_tunnel_agent", AGENT_PATH)
agent = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(agent)

KEY = base64.b64encode(b"k" * 32).decode()

# The agent name comes from the packaged agent.json label and id:
# dropjak-tunnel-agent-<label-slug>-<id>.
DEFAULT_AGENT = {"id": "home-1", "label": "Home"}
DEFAULT_AGENT_NAME = "dropjak-tunnel-agent-home-home-1"


def base_config() -> dict:
    return {
        "format": "dropjak-agent",
        "version": 1,
        "agent": {"id": "home-1", "label": "Home", "address": "10.77.0.2"},
        "wireguard": {
            "private_key": KEY,
            "address": "10.77.0.2/24",
            "peer_public_key": KEY,
            "preshared_key": KEY,
            "endpoint": "198.51.100.7:51820",
            "allowed_ips": ["10.77.0.1/32"],
            "persistent_keepalive": 25,
        },
        "sync": {
            "url": "http://10.77.0.1:8100/api/tunnel/config",
            "token": "test-token",
            "interval_seconds": 30,
        },
        "services": [{
            "id": "mc", "label": "Minecraft", "proto": "both",
            "tunnel_port": 41001, "target": "mc:25565", "enabled": True,
        }],
    }


def completed(stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], 0, stdout=stdout, stderr="")


class FakeRunner:
    """Stand-in for ip/wg/nft; records calls and interface addresses."""

    def __init__(self, routes: dict[str, str] | None = None,
                 default_dev: str = "eth0",
                 subnets: dict[str, tuple[str, int]] | None = None,
                 route_table: str = ""):
        self.routes = routes or {}
        self.route_table = route_table
        self.default_dev = default_dev
        self.subnets = subnets or {"eth1": ("172.30.0.2", 24)}
        self.calls: list[tuple[tuple[str, ...], str | None]] = []

    def __call__(self, argv, *, stdin=None, check=True):
        argv = tuple(argv)
        self.calls.append((argv, stdin))
        if argv == ("ip", "-4", "route", "show", "table", "all"):
            return completed(self.route_table)
        if argv[:3] == ("ip", "route", "show"):
            out = f"default via 192.0.2.1 dev {self.default_dev}\n"
            return completed(out)
        if argv[:3] == ("ip", "route", "get"):
            dev = self.routes[argv[3]]
            return completed(f"{argv[3]} dev {dev} src 172.30.0.1\n")
        if argv == ("ip", "-4", "-o", "addr", "show"):
            lines = []
            for index, (dev, (addr, prefix)) in enumerate(
                    sorted(self.subnets.items()), 1):
                lines.append(
                    f"{index}: {dev}    inet {addr}/{prefix} brd + "
                    f"scope global {dev}")
            return completed("\n".join(lines) + ("\n" if lines else ""))
        if argv[:6] == ("ip", "-4", "-o", "addr", "show", "dev"):
            dev = argv[6]
            addr, prefix = self.subnets[dev]
            return completed(f"2: {dev}    inet {addr}/{prefix} brd +\n")
        return completed()

    @property
    def nft(self) -> list[str]:
        return [stdin for argv, stdin in self.calls
                if argv[:2] == ("nft", "-f")]


class FakeGetaddr:
    def __init__(self, mapping: dict[str, str]):
        self.mapping = mapping

    def __call__(self, host, port, family=0, socktype=0):
        ip = self.mapping.get(host, host)
        return [(socket.AF_INET, socktype, 6, "", (ip, port))]


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200):
        self.body = body
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size: int = -1):
        return self.body

    def getcode(self):
        return self.status


class FakeOpener:
    def __init__(self, responses):
        self.responses = responses
        self.requests = []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make_agent(config: dict, runner: FakeRunner, state_dir: str,
               getaddr: FakeGetaddr | None = None, opener=None, logs=None):
    return agent.Agent(
        agent.validate_config(config), state_dir=state_dir, runner=runner,
        getaddrinfo=getaddr or FakeGetaddr({}), urlopen=opener,
        logger=(lambda level, event, **fields:
                (logs if logs is not None else []).append(
                    (level, event, fields))),
    )


class ConfigValidationTests(unittest.TestCase):
    def test_valid_config_gets_defaults(self) -> None:
        cfg = agent.validate_config(base_config())
        self.assertEqual(cfg["wireguard"]["interface"], "wg0")
        self.assertEqual(cfg["wireguard"]["listen_port"], 0)
        self.assertEqual(cfg["services"][0]["label"], "Minecraft")

    def test_unknown_and_missing_values_are_rejected(self) -> None:
        mutations = {
            "format": lambda c: c.update(format="other"),
            "version": lambda c: c.update(version=2),
            "unknown top key": lambda c: c.update(extra=1),
            "unknown service key": lambda c: c["services"][0].update(extra=1),
            "agent address": lambda c: c["agent"].update(address="10.77.0.9"),
            "wg address mismatch": lambda c: c["wireguard"].update(
                address="10.77.0.3/24"),
            "bad private key": lambda c: c["wireguard"].update(
                private_key="not-a-key"),
            "short key": lambda c: c["wireguard"].update(
                private_key=base64.b64encode(b"short").decode()),
            "allowed outside subnet": lambda c: c["wireguard"].update(
                allowed_ips=["0.0.0.0/0"]),
            "allowed without server": lambda c: c["wireguard"].update(
                allowed_ips=["10.77.0.8/32"]),
            "bad endpoint": lambda c: c["wireguard"].update(
                endpoint="198.51.100.7"),
            "bad interface": lambda c: c["wireguard"].update(
                interface="wg0; rm -rf /"),
            "bad proto": lambda c: c["services"][0].update(proto="icmp"),
            "bad target": lambda c: c["services"][0].update(target="mc"),
            "bad enabled": lambda c: c["services"][0].update(enabled=1),
            "duplicate port": lambda c: c["services"].append(
                dict(c["services"][0], id="mc2")),
            "duplicate id": lambda c: c["services"].append(
                dict(c["services"][0], tunnel_port=41002)),
            "sync scheme": lambda c: c["sync"].update(
                url="ftp://10.77.0.1:8100/x"),
            "sync credentials": lambda c: c["sync"].update(
                url="http://user:pw@10.77.0.1:8100/x"),
            "token whitespace": lambda c: c["sync"].update(token="a b"),
            "bool interval": lambda c: c["sync"].update(interval_seconds=True),
            "short interval": lambda c: c["sync"].update(interval_seconds=1),
        }
        for name, mutate in mutations.items():
            with self.subTest(name):
                config = copy.deepcopy(base_config())
                mutate(config)
                with self.assertRaises(agent.ConfigError):
                    agent.validate_config(config)

    def test_service_label_is_optional_but_defaults_to_id(self) -> None:
        config = base_config()
        del config["services"][0]["label"]
        self.assertEqual(
            agent.validate_config(config)["services"][0]["label"], "mc")


class RulesetTests(unittest.TestCase):
    def rules(self, proto: str = "both") -> str:
        config = agent.validate_config(base_config())
        entries = [{"id": "mc", "proto": proto, "tunnel_port": 41001,
                    "ip": "172.30.0.5", "target_port": 25565,
                    "iface": "eth1"}]
        return agent.render_ruleset(config, entries, ["198.51.100.7"],
                                    ["eth1"], ["10.77.0.1"], ["10.89.1.1"])

    def test_resolver_nameservers_are_allowed(self) -> None:
        # In rootless Podman DNS is the network gateway, not Docker's 127.0.0.11.
        rules = self.rules()
        self.assertIn("ip daddr 10.89.1.1 udp dport 53 accept", rules)
        self.assertIn("ip daddr 10.89.1.1 tcp dport 53 accept", rules)
        self.assertEqual(
            rules.count("ip daddr 127.0.0.11 udp dport 53 accept"), 1)

    def test_resolver_ips_are_read_from_resolv_conf(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(
                "# comment\nnameserver 10.89.1.1\n"
                "nameserver 10.89.3.1\nnameserver fe80::1\n"
                "nameserver not-an-ip\n")
            path = fh.name
        try:
            self.assertEqual(
                agent._resolver_ips(path), ["10.89.1.1", "10.89.3.1"])
        finally:
            Path(path).unlink()

    def test_default_drop_and_key_allows(self) -> None:
        rules = self.rules()
        self.assertEqual(rules.count("policy drop;"), 3)
        self.assertIn("add table inet dropjak_agent", rules)
        self.assertIn("flush table inet dropjak_agent", rules)
        for line in (
            "type filter hook input priority filter; policy drop;",
            "type filter hook forward priority filter; policy drop;",
            "type filter hook output priority filter; policy drop;",
            "ct state established,related accept",
            'iifname "lo" accept',
            'oifname "lo" accept',
            "ip daddr 127.0.0.11 udp dport 53 accept",
            "ip daddr 198.51.100.7 udp dport 51820 accept",
            "ip daddr 10.77.0.1 tcp dport 8100 accept",
            'iifname "eth1" oifname "wg0" ct state established,related accept',
        ):
            self.assertIn(line, rules)

    def test_sync_allow_is_an_exact_rule(self) -> None:
        lines = [line.strip() for line in self.rules().splitlines()]
        self.assertIn("ip daddr 10.77.0.1 tcp dport 8100 accept", lines)

    def test_mapped_forward_and_dnat_rules(self) -> None:
        rules = self.rules()
        for line in (
            'iifname "wg0" oifname "eth1" ip daddr 172.30.0.5 '
            "tcp dport 25565 accept",
            'iifname "wg0" oifname "eth1" ip daddr 172.30.0.5 '
            "udp dport 25565 accept",
            'iifname "wg0" tcp dport 41001 dnat ip to 172.30.0.5:25565',
            'iifname "wg0" udp dport 41001 dnat ip to 172.30.0.5:25565',
            'oifname "eth1" ip saddr 10.77.0.0/24 masquerade',
        ):
            self.assertIn(line, rules)
        self.assertNotIn('iifname "eth1" oifname "wg0" tcp', rules)

    def test_tcp_only_renders_one_protocol(self) -> None:
        rules = self.rules("tcp")
        self.assertIn("tcp dport 41001 dnat", rules)
        self.assertNotIn("udp dport 41001 dnat", rules)

    def test_multiple_interfaces_render_per_service_and_postrouting(
            self) -> None:
        config = agent.validate_config(base_config())
        entries = [
            {"id": "mc", "proto": "tcp", "tunnel_port": 41001,
             "ip": "172.30.0.5", "target_port": 25565, "iface": "eth2"},
            {"id": "web", "proto": "tcp", "tunnel_port": 41002,
             "ip": "172.31.0.5", "target_port": 80, "iface": "eth1"},
        ]
        rules = agent.render_ruleset(
            config, entries, ["198.51.100.7"], ["eth2", "eth1"],
            ["10.77.0.1"], [])
        for line in (
            'iifname "wg0" oifname "eth2" ip daddr 172.30.0.5 '
            "tcp dport 25565 accept",
            'iifname "wg0" oifname "eth1" ip daddr 172.31.0.5 '
            "tcp dport 80 accept",
            'iifname "eth1" oifname "wg0" ct state established,related accept',
            'iifname "eth2" oifname "wg0" ct state established,related accept',
            'oifname "eth1" ip saddr 10.77.0.0/24 masquerade',
            'oifname "eth2" ip saddr 10.77.0.0/24 masquerade',
            'iifname "wg0" tcp dport 41001 dnat ip to 172.30.0.5:25565',
            'iifname "wg0" tcp dport 41002 dnat ip to 172.31.0.5:80',
        ):
            self.assertIn(line, rules)
        # Deterministic order: by network name (postrouting).
        postrouting = rules[rules.index("chain postrouting"):]
        self.assertLess(postrouting.index('oifname "eth1"'),
                        postrouting.index('oifname "eth2"'))

    def test_service_without_iface_and_several_interfaces_is_rejected(
            self) -> None:
        config = agent.validate_config(base_config())
        entries = [{"id": "mc", "proto": "tcp", "tunnel_port": 41001,
                    "ip": "172.30.0.5", "target_port": 25565}]
        with self.assertRaises(ValueError):
            agent.render_ruleset(config, entries, ["198.51.100.7"],
                                 ["eth1", "eth2"], ["10.77.0.1"], [])

    def test_single_interface_string_stays_compatible(self) -> None:
        # Old callers pass a single interface name; without the service's own
        # iface field it still renders for this interface.
        config = agent.validate_config(base_config())
        entries = [{"id": "mc", "proto": "tcp", "tunnel_port": 41001,
                    "ip": "172.30.0.5", "target_port": 25565}]
        rules = agent.render_ruleset(config, entries, ["198.51.100.7"],
                                     "eth1", ["10.77.0.1"], [])
        self.assertIn('iifname "wg0" oifname "eth1"', rules)
        self.assertEqual(rules.count('oifname "eth1" ip saddr'), 1)

    def test_duplicate_interfaces_are_deduplicated(self) -> None:
        config = agent.validate_config(base_config())
        entries = [
            {"id": "a", "proto": "tcp", "tunnel_port": 41001,
             "ip": "172.30.0.5", "target_port": 80, "iface": "eth1"},
            {"id": "b", "proto": "tcp", "tunnel_port": 41002,
             "ip": "172.30.0.6", "target_port": 81, "iface": "eth1"},
        ]
        rules = agent.render_ruleset(
            config, entries, ["198.51.100.7"], ["eth1", "eth1"],
            ["10.77.0.1"], [])
        self.assertEqual(rules.count('oifname "eth1" ip saddr'), 1)
        self.assertEqual(
            rules.count('iifname "eth1" oifname "wg0" '
                        "ct state established,related accept"), 1)

    def test_no_services_has_no_forward_or_nat_rules(self) -> None:
        config = agent.validate_config(base_config())
        rules = agent.render_ruleset(config, [], ["198.51.100.7"], None,
                                     ["10.77.0.1"], [])
        self.assertEqual(rules.count("policy drop;"), 3)
        self.assertNotIn("dnat", rules)
        self.assertNotIn("masquerade", rules)
        self.assertNotIn('oifname "None"', rules)


class ResolutionTests(unittest.TestCase):
    def test_resolves_targets_and_detects_internal_interface(self) -> None:
        runner = FakeRunner(subnets={"eth1": ("172.30.0.2", 24)})
        getaddr = FakeGetaddr({"mc": "172.30.0.5"})
        with tempfile.TemporaryDirectory() as tmp:
            instance = make_agent(base_config(), runner, tmp, getaddr)
            entries, ifaces = instance.resolve_services(
                agent.validate_config(base_config())["services"])
        self.assertEqual(ifaces, ["eth1"])
        self.assertEqual(entries, [{"id": "mc", "proto": "both",
                                    "tunnel_port": 41001,
                                    "ip": "172.30.0.5",
                                    "target_port": 25565,
                                    "iface": "eth1"}])

    def test_services_on_several_networks_resolve_independently(self) -> None:
        config = base_config()
        config["services"].append({
            "id": "web", "label": "Web", "proto": "tcp",
            "tunnel_port": 41002, "target": "web:80", "enabled": True,
        })
        runner = FakeRunner(subnets={
            "eth1": ("172.30.0.2", 24),
            "eth2": ("172.31.0.2", 24),
        })
        getaddr = FakeGetaddr({"mc": "172.30.0.5", "web": "172.31.0.5"})
        with tempfile.TemporaryDirectory() as tmp:
            instance = make_agent(config, runner, tmp, getaddr)
            entries, ifaces = instance.resolve_services(
                agent.validate_config(config)["services"])
        self.assertEqual(ifaces, ["eth1", "eth2"])
        self.assertEqual(
            [(entry["id"], entry["iface"]) for entry in entries],
            [("mc", "eth1"), ("web", "eth2")])

    def test_lo_and_wg_interfaces_are_never_targets(self) -> None:
        for dev in ("lo", "wg0"):
            with self.subTest(dev):
                runner = FakeRunner(subnets={dev: ("172.30.0.2", 24)})
                with tempfile.TemporaryDirectory() as tmp:
                    instance = make_agent(base_config(), runner, tmp,
                                          FakeGetaddr({"mc": "172.30.0.5"}))
                    with self.assertRaises(agent.ApplyError):
                        instance.resolve_services(
                            agent.validate_config(base_config())["services"])

    def test_longest_prefix_wins_for_overlapping_subnets(self) -> None:
        runner = FakeRunner(subnets={
            "eth1": ("172.16.0.2", 12),
            "eth2": ("172.30.0.2", 24),
        })
        with tempfile.TemporaryDirectory() as tmp:
            instance = make_agent(base_config(), runner, tmp,
                                  FakeGetaddr({"mc": "172.30.0.5"}))
            entries, ifaces = instance.resolve_services(
                agent.validate_config(base_config())["services"])
        self.assertEqual(ifaces, ["eth2"])
        self.assertEqual(entries[0]["iface"], "eth2")

    def test_gateway_and_out_of_subnet_targets_are_rejected(self) -> None:
        # 172.30.0.1 is the Docker bridge (the host), .0/.255 are the network/broadcast
        # address, and 10.0.0.5 cannot be found on any attached subnet.
        for target in ("172.30.0.1", "172.30.0.0", "172.30.0.255",
                       "172.30.0.2", "10.0.0.5"):
            with self.subTest(target):
                runner = FakeRunner(subnets={"eth1": ("172.30.0.2", 24)})
                config = base_config()
                config["services"][0]["target"] = f"{target}:25565"
                with tempfile.TemporaryDirectory() as tmp:
                    instance = make_agent(base_config(), runner, tmp,
                                          FakeGetaddr({}))
                    with self.assertRaises(agent.ApplyError):
                        instance.resolve_services(
                            agent.validate_config(config)["services"])

    def test_real_default_gateway_is_rejected_even_if_not_dot_one(
            self) -> None:
        # A custom network whose gateway (the host) is .254, not .1.
        routes = ("default via 172.30.0.254 dev eth1\n"
                  "172.30.0.0/24 dev eth1 proto kernel scope link "
                  "src 172.30.0.2\n")
        for target, allowed in (("172.30.0.254", False),
                                ("172.30.0.5", True)):
            with self.subTest(target):
                runner = FakeRunner(subnets={"eth1": ("172.30.0.2", 24)},
                                    route_table=routes)
                config = base_config()
                config["services"][0]["target"] = f"{target}:25565"
                with tempfile.TemporaryDirectory() as tmp:
                    instance = make_agent(base_config(), runner, tmp,
                                          FakeGetaddr({}))
                    services = agent.validate_config(config)["services"]
                    if allowed:
                        entries, _ = instance.resolve_services(services)
                        self.assertEqual(entries[0]["ip"], target)
                    else:
                        with self.assertRaises(agent.ApplyError):
                            instance.resolve_services(services)

    def test_route_listing_failure_fails_closed(self) -> None:
        def failing(argv, *, stdin=None, check=True):
            if tuple(argv[:3]) == ("ip", "-4", "route"):
                raise agent.CommandError("ip failed")
            return FakeRunner(subnets={"eth1": ("172.30.0.2", 24)})(
                argv, stdin=stdin, check=check)

        with tempfile.TemporaryDirectory() as tmp:
            instance = make_agent(base_config(), failing, tmp,
                                  FakeGetaddr({"mc": "172.30.0.5"}))
            with self.assertRaises(agent.ApplyError):
                instance.resolve_services(
                    agent.validate_config(base_config())["services"])

    def test_target_dns_name_resolving_outside_subnets_is_rejected(
            self) -> None:
        runner = FakeRunner(subnets={"eth1": ("172.30.0.2", 24)})
        with tempfile.TemporaryDirectory() as tmp:
            instance = make_agent(base_config(), runner, tmp,
                                  FakeGetaddr({"mc": "198.51.100.9"}))
            with self.assertRaises(agent.ApplyError):
                instance.resolve_services(
                    agent.validate_config(base_config())["services"])

    def test_unresolvable_target_is_an_error(self) -> None:
        class Broken:
            def __call__(self, *args, **kwargs):
                raise socket.gaierror("nope")

        runner = FakeRunner(subnets={"eth1": ("172.30.0.2", 24)})
        with tempfile.TemporaryDirectory() as tmp:
            instance = make_agent(base_config(), runner, tmp, Broken())
            with self.assertRaises(agent.ApplyError):
                instance.resolve_services(
                    agent.validate_config(base_config())["services"])

    def test_disabled_services_are_not_resolved(self) -> None:
        config = base_config()
        config["services"][0]["enabled"] = False
        runner = FakeRunner({})
        with tempfile.TemporaryDirectory() as tmp:
            instance = make_agent(config, runner, tmp)
            entries, ifaces = instance.resolve_services(
                agent.validate_config(config)["services"])
        self.assertEqual((entries, ifaces), ([], []))


class SyncTests(unittest.TestCase):
    def payload(self, **overrides) -> bytes:
        service = {"id": "web", "label": "Web", "proto": "tcp",
                   "tunnel_port": 41002, "target": "web:8080", "enabled": True}
        service.update(overrides)
        return json.dumps({"services": [service]}).encode()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.runner = FakeRunner({"172.30.0.5": "eth1",
                                  "172.30.0.6": "eth1",
                                  "172.30.0.7": "eth1"})
        self.getaddr = FakeGetaddr({"mc": "172.30.0.5",
                                    "web": "172.30.0.6"})
        self.logs: list = []
        self.opener = FakeOpener([FakeResponse(self.payload())])
        self.agent = make_agent(base_config(), self.runner, self.tmp.name,
                                self.getaddr, self.opener, self.logs)
        self.agent._endpoint_ips = self.agent._resolve_endpoint()
        self.agent._sync_ips = self.agent._resolve_sync()

    def test_sync_sends_bearer_and_applies_ruleset(self) -> None:
        self.assertTrue(self.agent.sync_once())
        request = self.opener.requests[0]
        self.assertEqual(request.get_header("Authorization"),
                         "Bearer test-token")
        self.assertEqual(len(self.runner.nft), 1)
        self.assertIn('iifname "wg0" tcp dport 41002 dnat ip to '
                      "172.30.0.6:8080", self.runner.nft[0])
        self.assertIn(("info", "sync_ok"), [(lvl, ev)
                                            for lvl, ev, _ in self.logs])

    def test_sync_persists_last_good_services_0600(self) -> None:
        self.assertTrue(self.agent.sync_once())
        path = Path(self.tmp.name) / agent.STATE_FILE
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(Path(self.tmp.name).stat().st_mode),
                         0o700)
        state = json.loads(path.read_text())
        self.assertEqual(state["format"], agent.STATE_FORMAT)
        self.assertEqual([s["id"] for s in state["services"]], ["web"])
        self.assertEqual([s["id"] for s in self.agent.load_state()], ["web"])

    def test_network_failure_keeps_previous_rules_and_state(self) -> None:
        self.assertTrue(self.agent.sync_once())
        before = len(self.runner.nft)
        state_before = (Path(self.tmp.name) / agent.STATE_FILE).read_bytes()
        self.opener.responses.append(urllib.error.URLError("cloud down"))
        self.assertFalse(self.agent.sync_once())
        self.assertEqual(len(self.runner.nft), before)
        self.assertEqual(
            (Path(self.tmp.name) / agent.STATE_FILE).read_bytes(), state_before)
        self.assertIn(("warning", "sync_failed"),
                      [(lvl, ev) for lvl, ev, _ in self.logs])

    def test_invalid_payload_keeps_previous_rules(self) -> None:
        self.assertTrue(self.agent.sync_once())
        before = len(self.runner.nft)
        self.opener.responses.append(FakeResponse(self.payload(proto="icmp")))
        self.assertFalse(self.agent.sync_once())
        self.assertEqual(len(self.runner.nft), before)

    def test_each_sync_re_resolves_target_ip(self) -> None:
        self.assertTrue(self.agent.sync_once())
        self.getaddr.mapping["web"] = "172.30.0.7"
        self.opener.responses.append(FakeResponse(self.payload()))
        self.assertTrue(self.agent.sync_once())
        self.assertIn("dnat ip to 172.30.0.7:8080", self.runner.nft[-1])
        self.assertNotIn("dnat ip to 172.30.0.6:8080", self.runner.nft[-1])

    def test_disabled_services_are_filtered(self) -> None:
        self.opener.responses = [FakeResponse(self.payload(enabled=False))]
        self.assertTrue(self.agent.sync_once())
        self.assertNotIn("41002", self.runner.nft[0])
        self.assertEqual(self.agent.load_state(), [])

    def test_list_payload_is_accepted_and_unknown_keys_ignored(self) -> None:
        body = json.loads(self.payload())
        body["services"][0]["cloud_extra"] = "ignored"
        self.opener.responses = [FakeResponse(json.dumps(body["services"])
                                              .encode())]
        self.assertTrue(self.agent.sync_once())
        self.assertIn("41002", self.runner.nft[0])


class WireGuardTests(unittest.TestCase):
    def test_keys_use_0600_temp_files_and_never_argv(self) -> None:
        seen = {}

        def runner(argv, *, stdin=None, check=True):
            argv = tuple(argv)
            if argv[0] == "wg" and "private-key" in argv:
                path = Path(argv[argv.index("private-key") + 1])
                seen["private"] = (path.read_text(),
                                   stat.S_IMODE(path.stat().st_mode),
                                   str(path))
            if argv[0] == "wg" and "preshared-key" in argv:
                path = Path(argv[argv.index("preshared-key") + 1])
                seen["psk"] = (path.read_text(),
                               stat.S_IMODE(path.stat().st_mode),
                               str(path))
            return completed()

        with tempfile.TemporaryDirectory() as tmp:
            instance = make_agent(base_config(), runner, tmp)
            instance._endpoint_ips = ["198.51.100.7"]
            instance.bring_up_tunnel()
        self.assertEqual(seen["private"][:2], (KEY, 0o600))
        self.assertEqual(seen["psk"][:2], (KEY, 0o600))
        self.assertFalse(Path(seen["private"][2]).exists())
        self.assertFalse(Path(seen["psk"][2]).exists())

    def test_shutdown_removes_tunnel_and_rules_together(self) -> None:
        runner = FakeRunner({})
        with tempfile.TemporaryDirectory() as tmp:
            instance = make_agent(base_config(), runner, tmp)
            instance.shutdown()
        commands = [argv for argv, _ in runner.calls]
        self.assertIn(("ip", "link", "del", "wg0"), commands)
        self.assertIn(("nft", "delete", "table", "inet", "dropjak_agent"),
                      commands)

    def test_wireguard_commands_have_no_shell_and_expected_shape(self) -> None:
        runner = FakeRunner({})
        with tempfile.TemporaryDirectory() as tmp:
            instance = make_agent(base_config(), runner, tmp)
            instance._endpoint_ips = ["198.51.100.7"]
            instance.bring_up_tunnel()
        commands = [argv for argv, _ in runner.calls]
        self.assertIn(("ip", "link", "add", "wg0", "type", "wireguard"),
                      commands)
        self.assertIn(("ip", "addr", "add", "10.77.0.2/24", "dev", "wg0"),
                      commands)
        self.assertIn(("ip", "link", "set", "dev", "wg0", "mtu", "1420",
                       "up"), commands)
        peer = [c for c in commands if c[:2] == ("wg", "set")
                and "peer" in c][0]
        self.assertIn("allowed-ips", peer)
        self.assertIn("10.77.0.1/32", peer)
        self.assertIn("persistent-keepalive", peer)
        self.assertIn("endpoint", peer)
        self.assertIn("198.51.100.7:51820", peer)


@unittest.skipUnless(
    all(shutil.which(tool) for tool in ("unshare", "nsenter", "nft", "ip")),
    "missing unshare/nsenter/nft/ip",
)
class TunnelAgentPacketTests(unittest.TestCase):
    def test_ruleset_forwards_mapped_ports_and_contains_the_container(
            self) -> None:
        probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True)
        if probe.returncode != 0:
            self.skipTest("the user namespace is not available")
        result = subprocess.run(
            ["unshare", "-rn", sys.executable, str(HELPER)],
            capture_output=True, text=True, timeout=240,
        )
        if result.returncode != 0 and not result.stdout.strip():
            if "Operation not permitted" in result.stderr:
                self.skipTest("not permitted in the namespace: "
                              + result.stderr[-200:])
            self.fail(result.stderr[-3000:])
        report = json.loads(result.stdout)
        failed = {
            name: check["detail"] for name, check in report["checks"].items()
            if isinstance(check, dict) and not check["ok"]
        }
        self.assertEqual(failed, {},
                         json.dumps(report, indent=1, ensure_ascii=False))
        self.assertTrue(report["ok"])


class IpForwardTests(unittest.TestCase):
    """The sysctl is idempotent: it does not write when the value is already set (rootless EROFS)."""

    def run_with(self, value: str) -> list:
        calls: list = []

        class FakePath:
            def __init__(self, path):
                calls.append(("path", str(path)))

            def read_text(self, encoding=None):
                return value

            def write_text(self, text):
                calls.append(("write", text))

        with mock.patch.object(agent, "Path", FakePath):
            agent.Agent._set_ip_forward(mock.Mock())
        return calls

    def test_already_enabled_is_not_written(self) -> None:
        self.assertEqual(self.run_with("1\n"), [("path", "/proc/sys/net/ipv4/ip_forward")])

    def test_disabled_is_written(self) -> None:
        self.assertIn(("write", "1\n"), self.run_with("0\n"))


FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys

here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "state.json"), encoding="utf-8") as fh:
    state = json.load(fh)
with open(state["log"], "a", encoding="utf-8") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\n")

args = sys.argv[1:]
networks = state["networks"]
containers = state["containers"]


def fail():
    sys.exit(1)


if not args:
    fail()

if args[:2] == ["network", "ls"]:
    for name, driver in networks.items():
        print(f"{name} {driver}")
    sys.exit(0)

if args[:2] == ["network", "inspect"]:
    rest = args[2:]
    fmt = None
    if rest and rest[0] in ("-f", "--format"):
        fmt = rest[1]
        rest = rest[2:]
    if not rest:
        fail()
    name = rest[0]
    if name not in networks:
        fail()
    if fmt and "Driver" in fmt:
        print(networks[name])
    elif fmt and "Name" in fmt:
        print(name)
    else:
        print(json.dumps([{"Name": name, "Driver": networks[name]}]))
    sys.exit(0)

if args[0] == "ps":
    fmt = args[args.index("--format") + 1] if "--format" in args else ""
    for name, container in containers.items():
        if "Image" in fmt:
            print(f"{name} {container['image']}")
        elif "Names" in fmt:
            print(name)
        else:
            print(f"{name} {container['image']}")
    sys.exit(0)

if args[0] == "inspect":
    rest = args[1:]
    fmt = None
    if rest and rest[0] in ("-f", "--format"):
        fmt = rest[1]
        rest = rest[2:]
    if not rest:
        fail()
    name = rest[0]
    if name not in containers:
        fail()
    container = containers[name]
    if not fmt:
        print(json.dumps([{"Name": name}]))
    elif "State.Running" in fmt:
        print("true")
    elif "NetworkSettings.Networks" in fmt:
        print("".join(net + " " for net in container["networks"]))
    elif "Mounts" in fmt:
        print("")
    elif "ReadonlyRootfs" in fmt:
        print("true")
    elif "SecurityOpt" in fmt:
        print("no-new-privileges:true ")
    elif "CapDrop" in fmt:
        print("ALL ")
    elif "CapAdd" in fmt:
        print("NET_ADMIN ")
    else:
        print("")
    sys.exit(0)

if args[:2] == ["compose", "version"]:
    print("Docker Compose version v2.29.0")
    sys.exit(0)

sys.exit(0)
'''


class SelfInstallTests(unittest.TestCase):
    """Interactive, single-network installer: numbered list, prompts on a TTY."""

    DEFAULT_NETWORKS = {
        "bridge": "bridge",
        "host": "host",
        "none": "null",
        "minecraft_default": "bridge",
        "playitgg-net": "bridge",
    }
    DEFAULT_CONTAINERS = {
        "playit": {
            "image": "ghcr.io/playit-cloud/playit-agent:latest",
            "networks": ["playitgg-net"],
        },
    }
    INTERACTIVE_NETWORKS = {
        "bridge": "bridge",
        "host": "host",
        "none": "null",
        "alpha-net": "bridge",
        "games-net": "bridge",
        "playitgg-net": "bridge",
    }

    def make_installer(self, tmp: str, networks=None, containers=None,
                       agent_config=None):
        import io
        import tarfile

        base = ROOT / "deploy" / "tunnel-agent"
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w:gz") as tar:
            for name in ("compose.agent.yml", "Dockerfile", "agent.py",
                         "check-containment.sh"):
                data = (base / name).read_bytes()
                info = tarfile.TarInfo(
                    "compose.yml" if name == "compose.agent.yml" else name)
                info.size = len(data)
                info.mode = 0o755 if name.endswith(".py") else 0o644
                tar.addfile(info, io.BytesIO(data))
            agent = dict(DEFAULT_AGENT if agent_config is None
                         else agent_config)
            config = (json.dumps({
                "format": "dropjak-agent", "version": 1, "agent": agent,
            }, indent=2, ensure_ascii=False) + "\n").encode()
            info = tarfile.TarInfo("agent.json")
            info.size = len(config)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(config))

        home = Path(tmp, "home")
        target = Path(tmp, "target")
        bin_dir = Path(tmp, "bin")
        lib = Path(tmp, "lib")
        units = Path(tmp, "units")
        for directory in (home, target, bin_dir):
            directory.mkdir(exist_ok=True)
        log = Path(tmp, "docker.log")
        systemctl_log = Path(tmp, "systemctl.log")
        state = {
            "log": str(log),
            "networks": dict(
                self.DEFAULT_NETWORKS if networks is None else networks),
            "containers": dict(
                self.DEFAULT_CONTAINERS if containers is None else containers),
        }
        (bin_dir / "state.json").write_text(json.dumps(state))
        fake = bin_dir / "docker"
        fake.write_text(FAKE_DOCKER)
        fake.chmod(0o755)
        systemctl = bin_dir / "systemctl"
        systemctl.write_text(
            "#!/bin/sh\n"
            f'echo "$@" >> "{systemctl_log}"\n'
            "exit 0\n")
        systemctl.chmod(0o755)
        # The real Podman must not influence rootless detection.
        podman = bin_dir / "podman"
        podman.write_text("#!/bin/sh\nexit 1\n")
        podman.chmod(0o755)
        script = Path(tmp, "dropjak-agent-home.sh")
        script.write_bytes(
            (base / "selfinstall.sh").read_bytes() + payload.getvalue())
        return script, target, bin_dir, log, lib, units

    def installer_env(self, tmp, bin_dir, lib, units, **extra_env):
        env = {
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "HOME": str(Path(tmp, "home")),
            "DROPJAK_LIB_DIR": str(lib),
            "DROPJAK_SYSTEMD_UNIT_DIR": str(units),
            "DROPJAK_NO_SYSTEMD": "1",
        }
        env.update(extra_env)
        return env

    def run_installer(self, tmp: str, networks=None, containers=None,
                      args=(), with_compose=False, agent_config=None,
                      **extra_env):
        """Non-interactive run: stdin /dev/null, must never prompt."""
        script, target, bin_dir, log, lib, units = self.make_installer(
            tmp, networks, containers, agent_config)
        if with_compose:
            (target / "compose.yml").write_text("services: {}\n")
        env = self.installer_env(tmp, bin_dir, lib, units, **extra_env)
        result = subprocess.run(
            ["sh", str(script), *args], capture_output=True, text=True,
            timeout=60, stdin=subprocess.DEVNULL, env=env, cwd=target,
        )
        return result, target, log, lib

    def run_installer_tty(self, tmp: str, answers: str, networks=None,
                          containers=None, args=(), with_compose=False,
                          agent_config=None, **extra_env):
        """Run with a TTY stdin so the installer prompts interactively."""
        script, target, bin_dir, log, lib, units = self.make_installer(
            tmp, networks, containers, agent_config)
        if with_compose:
            (target / "compose.yml").write_text("services: {}\n")
        env = self.installer_env(tmp, bin_dir, lib, units, **extra_env)
        master, slave = pty.openpty()
        proc = subprocess.Popen(
            ["sh", str(script), *args], stdin=slave, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env, cwd=target,
            close_fds=True)
        os.close(slave)
        try:
            if answers:
                os.write(master, answers.encode())
            stdout, stderr = proc.communicate(timeout=60)
        finally:
            os.close(master)
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        result = subprocess.CompletedProcess(
            ["sh", str(script), *args], proc.returncode, stdout, stderr)
        return result, target, log, lib

    def assert_single_network(self, compose: str, network: str) -> None:
        self.assertEqual(compose.count("external: true"), 1)
        self.assertEqual(compose.count('name: "'), 1)
        self.assertIn(f'name: "{network}"', compose)
        self.assertIn("      - n1", compose)
        self.assertNotIn("- n2", compose)
        self.assertNotIn("host.docker.internal", compose)
        self.assertNotIn("extra_hosts", compose)

    def test_interactive_numbered_list_and_selection_by_number(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, target, _, _ = self.run_installer_tty(
                tmp, "1\n2\n", networks=self.INTERACTIVE_NETWORKS)
            self.assertEqual(result.returncode, 0, result.stderr)
            out = result.stdout
            self.assertIn(
                "Select a network (the agent will join exactly one network):",
                out)
            # playitgg-net is first; the rest follow sorted.
            self.assertIn("1) playitgg-net (bridge, 1 container)", out)
            self.assertIn("2) alpha-net (bridge, 0 containers)", out)
            self.assertIn("3) bridge (bridge, 0 containers)", out)
            self.assertIn("4) games-net (bridge, 0 containers)", out)
            self.assertIn(
                "Network [1-4] (default: 1 - playitgg-net):", out)
            # host/none are not candidates.
            self.assertNotIn("host (bridge", out)
            self.assertNotIn("none (bridge", out)
            compose = (target / "compose.yml").read_text()
            self.assert_single_network(compose, "alpha-net")
            self.assertNotIn('name: "playitgg-net"', compose)

    def test_interactive_empty_answer_accepts_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # First empty answer = install (menu default), second = network
            # default.
            result, target, _, _ = self.run_installer_tty(
                tmp, "\n\n", networks=self.INTERACTIVE_NETWORKS)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Choose an action:", result.stdout)
            self.assertIn("1) Install/update (default)", result.stdout)
            self.assertIn("2) Delete container", result.stdout)
            self.assertIn("default: 1 - playitgg-net", result.stdout)
            self.assert_single_network(
                (target / "compose.yml").read_text(), "playitgg-net")

    def test_interactive_invalid_answer_reprompts_then_accepts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, target, _, _ = self.run_installer_tty(
                tmp, "1\nabc\n2\n", networks=self.INTERACTIVE_NETWORKS)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("invalid choice", result.stderr)
            self.assertEqual(
                result.stdout.count("Network [1-4]"), 2, result.stdout)
            self.assert_single_network(
                (target / "compose.yml").read_text(), "alpha-net")

    def test_interactive_three_invalid_answers_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, target, _, _ = self.run_installer_tty(
                tmp, "1\nabc\n9\n-1\n", networks=self.INTERACTIVE_NETWORKS)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid choice", result.stderr)
            self.assertIn("3 invalid", result.stderr)
            self.assertEqual(
                result.stdout.count("Network [1-4]"), 3, result.stdout)
            self.assertFalse((target / "compose.yml").exists())

    def test_non_interactive_uses_default_and_installs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, target, log, lib = self.run_installer(tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Network [", result.stdout)
            self.assertNotIn("Choose an action", result.stdout)
            # By default installs into $PWD, not under $HOME.
            self.assertTrue((target / "compose.yml").is_file())
            self.assertTrue((target / "Dockerfile").is_file())
            self.assertTrue((target / "agent.py").is_file())
            config_path = target / "agent.json"
            self.assertEqual(stat.S_IMODE(config_path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(config_path.read_text()), {
                "format": "dropjak-agent", "version": 1,
                "agent": DEFAULT_AGENT,
            })
            compose = (target / "compose.yml").read_text()
            self.assertNotIn("internal: true", compose)
            self.assertNotIn("egress", compose)
            self.assertIn("container_name: dropjak-tunnel-agent", compose)
            self.assertIn(f"container_name: {DEFAULT_AGENT_NAME}", compose)
            name_path = target / "container-name"
            self.assertEqual(name_path.read_text().strip(),
                             DEFAULT_AGENT_NAME)
            self.assertEqual(stat.S_IMODE(name_path.stat().st_mode), 0o644)
            self.assertIn("./agent.json:/etc/dropjak/agent.json:ro,Z",
                          compose)
            self.assert_single_network(compose, "playitgg-net")
            calls = log.read_text()
            self.assertIn("compose up -d --build", calls)
            self.assertIn("compose -f", calls)  # compose config -q check
            self.assertIn("playitgg-net", result.stdout)
            self.assertIn("exactly one network", result.stdout)
            # The exact delete command is printed after a successful install.
            self.assertIn("delete", result.stdout)
            self.assertIn("sudo sh", result.stdout)
            # The multi-network model's helper/timer is not installed.
            self.assertFalse((lib / "reconcile-networks.sh").exists())
            for name in ("dropjak-agent-networks.service",
                         "dropjak-agent-networks.timer"):
                self.assertFalse((Path(tmp, "units") / name).exists())
            self.assertNotIn("timer", result.stdout.lower())
            self.assertNotIn("reconcile", result.stdout.lower())

    def test_container_name_includes_label_and_id(self) -> None:
        agent_config = {"id": "home-7", "label": "Garden Shed"}
        expected = "dropjak-tunnel-agent-garden-shed-home-7"
        with tempfile.TemporaryDirectory() as tmp:
            result, target, _, _ = self.run_installer(
                tmp, agent_config=agent_config)
            self.assertEqual(result.returncode, 0, result.stderr)
            compose = (target / "compose.yml").read_text()
            self.assertIn(f"container_name: {expected}", compose)
            self.assertEqual(
                (target / "container-name").read_text().strip(), expected)
            # The installer messages use the same name, including the check
            # command that hands it to check-containment.sh.
            self.assertIn(expected, result.stdout)
            self.assertIn(f"DROPJAK_CONTAINER={expected}", result.stdout)
            self.assertIn("Agent container name:", result.stdout)

    def test_container_name_transliterates_hungarian_accents(self) -> None:
        agent_config = {"id": "kert-1", "label": "Árvíztűrő Tükörfúrógép"}
        expected = "dropjak-tunnel-agent-arvizturo-tukorfurogep-kert-1"
        with tempfile.TemporaryDirectory() as tmp:
            result, target, _, _ = self.run_installer(
                tmp, agent_config=agent_config)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (target / "container-name").read_text().strip(), expected)
            self.assertIn(f"container_name: {expected}",
                          (target / "compose.yml").read_text())

    def test_container_name_truncates_long_label_to_63_chars(self) -> None:
        agent_config = {"id": "long-1", "label": "A" * 80}
        with tempfile.TemporaryDirectory() as tmp:
            result, target, _, _ = self.run_installer(
                tmp, agent_config=agent_config)
            self.assertEqual(result.returncode, 0, result.stderr)
            name = (target / "container-name").read_text().strip()
            self.assertLessEqual(len(name), 63)
            self.assertEqual(len(name), 63)
            self.assertTrue(name.startswith("dropjak-tunnel-agent-aaaa"))
            self.assertTrue(name.endswith("-long-1"))
            self.assertIn(f"container_name: {name}",
                          (target / "compose.yml").read_text())

    def test_container_name_without_label_is_id_only(self) -> None:
        for label in ("", "!!!"):
            with self.subTest(label=label), \
                    tempfile.TemporaryDirectory() as tmp:
                result, target, _, _ = self.run_installer(
                    tmp, agent_config={"id": "empty-7", "label": label})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    (target / "container-name").read_text().strip(),
                    "dropjak-tunnel-agent-empty-7")

    def test_container_name_falls_back_to_legacy_without_agent(self) -> None:
        # Very old bundles may not contain an agent object at all; the fixed
        # name keeps them installable and deletable.
        with tempfile.TemporaryDirectory() as tmp:
            result, target, _, _ = self.run_installer(tmp, agent_config={})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("container_name: dropjak-tunnel-agent\n",
                          (target / "compose.yml").read_text())
            self.assertEqual(
                (target / "container-name").read_text().strip(),
                "dropjak-tunnel-agent")

    def test_container_name_is_unique_for_different_agents(self) -> None:
        names = []
        for agent_config in (
                {"id": "home-1", "label": "Home"},
                {"id": "home-2", "label": "Home"},
                {"id": "home-1", "label": "Office"}):
            with self.subTest(agent=agent_config), \
                    tempfile.TemporaryDirectory() as tmp:
                result, target, _, _ = self.run_installer(
                    tmp, agent_config=agent_config)
                self.assertEqual(result.returncode, 0, result.stderr)
                names.append(
                    (target / "container-name").read_text().strip())
        self.assertEqual(len(set(names)), len(names))
        self.assertTrue(all(
            name.startswith("dropjak-tunnel-agent-") for name in names))
        self.assertTrue(all(
            name.endswith(("-home-1", "-home-2")) for name in names))


        with tempfile.TemporaryDirectory() as tmp:
            networks = {
                "host": "host",
                "none": "null",
                "minecraft_default": "bridge",
            }
            result, target, _, _ = self.run_installer(
                tmp, networks=networks, containers={})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Network [", result.stdout)
            self.assert_single_network(
                (target / "compose.yml").read_text(), "minecraft_default")

    def test_non_interactive_dropjak_no_prompt_on_tty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, target, _, _ = self.run_installer_tty(
                tmp, "\n", DROPJAK_NO_PROMPT="1")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Network [", result.stdout)
            self.assert_single_network(
                (target / "compose.yml").read_text(), "playitgg-net")

    def test_delete_prefers_compose_down_and_keeps_volumes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            containers = {
                "dropjak-tunnel-agent": {
                    "image": "dropjak-tunnel-agent:1",
                    "networks": ["playitgg-net"],
                },
            }
            result, target, log, _ = self.run_installer(
                tmp, containers=containers, args=("delete",),
                with_compose=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text()
            self.assertIn("compose -f", calls)
            self.assertIn("down --remove-orphans", calls)
            self.assertNotIn("-v", calls)
            self.assertIn("has been removed", result.stdout)
            # Delete never installs or picks a network.
            self.assertNotIn("compose up -d --build", calls)
            self.assertNotIn("Network [", result.stdout)
            self.assertNotIn("Choose an action", result.stdout)

    def test_delete_falls_back_to_docker_rm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            containers = {
                "dropjak-tunnel-agent": {
                    "image": "dropjak-tunnel-agent:1",
                    "networks": ["playitgg-net"],
                },
            }
            result, target, log, _ = self.run_installer(
                tmp, containers=containers, args=("delete",))
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text()
            self.assertIn("rm -f dropjak-tunnel-agent", calls)
            self.assertIn("has been removed", result.stdout)
            self.assertNotIn("compose up -d --build", calls)

    def test_delete_uses_derived_container_name(self) -> None:
        # A previous install left agent.json/container-name (and compose.yml)
        # in the install directory; delete must remove exactly that name.
        for remove_name_file in (False, True):
            with self.subTest(remove_name_file=remove_name_file), \
                    tempfile.TemporaryDirectory() as tmp:
                first, target, _, _ = self.run_installer(tmp)
                self.assertEqual(first.returncode, 0, first.stderr)
                self.assertEqual(
                    (target / "container-name").read_text().strip(),
                    DEFAULT_AGENT_NAME)
                if remove_name_file:
                    # Without the file the name is re-derived from agent.json.
                    (target / "container-name").unlink()
                containers = {
                    DEFAULT_AGENT_NAME: {
                        "image": "dropjak-tunnel-agent:1",
                        "networks": ["playitgg-net"],
                    },
                }
                result, _, log, _ = self.run_installer(
                    tmp, containers=containers, args=("delete",))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"rm -f {DEFAULT_AGENT_NAME}",
                              log.read_text())
                self.assertIn(DEFAULT_AGENT_NAME, result.stdout)
                self.assertIn("has been removed", result.stdout)

    def test_delete_tries_legacy_fixed_name_as_fallback(self) -> None:
        # An old install uses the fixed name; the new install directory even
        # names a different agent. Delete must still find and remove it.
        with tempfile.TemporaryDirectory() as tmp:
            first, target, _, _ = self.run_installer(
                tmp, agent_config={"id": "home-2", "label": "Home"})
            self.assertEqual(first.returncode, 0, first.stderr)
            (target / "container-name").write_text(
                "dropjak-tunnel-agent-home-home-2\n")
            containers = {
                "dropjak-tunnel-agent": {
                    "image": "dropjak-tunnel-agent:1",
                    "networks": ["playitgg-net"],
                },
            }
            result, _, log, _ = self.run_installer(
                tmp, containers=containers, args=("delete",))
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text()
            self.assertIn("rm -f dropjak-tunnel-agent", calls)
            self.assertIn("has been removed", result.stdout)

    def test_delete_is_idempotent_when_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, target, log, _ = self.run_installer(
                tmp, containers={}, args=("delete",))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("nothing to delete", result.stdout)
            self.assertNotIn("rm -f dropjak-tunnel-agent", log.read_text())

    def test_delete_argument_aliases(self) -> None:
        for arg in ("delete", "--delete", "-d"):
            with self.subTest(arg), tempfile.TemporaryDirectory() as tmp:
                result, _, _, _ = self.run_installer(
                    tmp, containers={}, args=(arg,))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("nothing to delete", result.stdout)

    def test_unknown_argument_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, target, _, _ = self.run_installer(
                tmp, args=("bogus",))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown argument", result.stderr)
            self.assertFalse((target / "compose.yml").exists())

    def test_delete_never_prompts_on_tty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            containers = {
                "dropjak-tunnel-agent": {
                    "image": "dropjak-tunnel-agent:1",
                    "networks": ["playitgg-net"],
                },
            }
            result, _, log, _ = self.run_installer_tty(
                tmp, "", containers=containers, args=("delete",))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Choose an action", result.stdout)
            self.assertNotIn("Network [", result.stdout)
            self.assertIn("rm -f dropjak-tunnel-agent", log.read_text())

    def test_tty_action_menu_can_delete_without_network_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            containers = {
                "dropjak-tunnel-agent": {
                    "image": "dropjak-tunnel-agent:1",
                    "networks": ["playitgg-net"],
                },
            }
            result, _, log, _ = self.run_installer_tty(
                tmp, "2\n", containers=containers)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Choose an action:", result.stdout)
            self.assertIn("2) Delete container", result.stdout)
            self.assertIn("has been removed", result.stdout)
            self.assertNotIn("Network [", result.stdout)
            self.assertIn("rm -f dropjak-tunnel-agent", log.read_text())

    def test_autodetects_playit_container_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            networks = {
                "bridge": "bridge",
                "host": "host",
                "none": "null",
                "minecraft_default": "bridge",
            }
            containers = {
                "playit": {
                    "image": "ghcr.io/playit-cloud/playit-agent:latest",
                    "networks": ["minecraft_default"],
                },
            }
            result, target, _, _ = self.run_installer(
                tmp, networks=networks, containers=containers)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_single_network(
                (target / "compose.yml").read_text(), "minecraft_default")

    def test_multiple_playit_networks_prefer_playitgg_net(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            containers = {
                "playit": {
                    "image": "ghcr.io/playit-cloud/playit-agent:latest",
                    "networks": ["minecraft_default", "playitgg-net"],
                },
            }
            result, target, _, _ = self.run_installer(
                tmp, containers=containers)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_single_network(
                (target / "compose.yml").read_text(), "playitgg-net")

    def test_multiple_playit_networks_without_playitgg_use_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            networks = {
                "minecraft_default": "bridge",
                "podman": "bridge",
            }
            containers = {
                "playit": {
                    "image": "ghcr.io/playit-cloud/playit-agent:latest",
                    "networks": ["podman", "minecraft_default"],
                },
            }
            result, target, _, _ = self.run_installer(
                tmp, networks=networks, containers=containers)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_single_network(
                (target / "compose.yml").read_text(), "minecraft_default")

    def test_default_prefers_existing_playitgg_net(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # No playit container runs, but the playitgg-net network exists.
            result, target, _, _ = self.run_installer(tmp, containers={})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_single_network(
                (target / "compose.yml").read_text(), "playitgg-net")

    def test_explicit_dropjak_network_is_used(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            networks = dict(self.DEFAULT_NETWORKS, **{"games-net": "bridge"})
            result, target, _, _ = self.run_installer(
                tmp, networks=networks, DROPJAK_NETWORK="games-net")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Network [", result.stdout)
            compose = (target / "compose.yml").read_text()
            self.assert_single_network(compose, "games-net")
            self.assertNotIn('name: "playitgg-net"', compose)
            self.assertIn("games-net", result.stdout)

    def test_interactive_override_skips_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            networks = dict(self.DEFAULT_NETWORKS, **{"games-net": "bridge"})
            result, target, _, _ = self.run_installer_tty(
                tmp, "\n", networks=networks,
                DROPJAK_NETWORK="games-net")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Network [", result.stdout)
            self.assert_single_network(
                (target / "compose.yml").read_text(), "games-net")

    def test_no_bridge_network_fails_without_compose(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            networks = {
                "host": "host",
                "none": "null",
                "macvlan0": "macvlan",
            }
            result, target, _, _ = self.run_installer(
                tmp, networks=networks, containers={})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bridge network", result.stderr)
            self.assertIn("DROPJAK_NETWORK", result.stderr)
            self.assertFalse((target / "compose.yml").exists())
            self.assertFalse((target / "agent.json").exists())

    def test_explicit_host_network_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, target, _, _ = self.run_installer(
                tmp, DROPJAK_NETWORK="host")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not bridge", result.stderr)
            self.assertFalse((target / "compose.yml").exists())

    def test_explicit_none_network_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, target, _, _ = self.run_installer(
                tmp, DROPJAK_NETWORK="none")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not bridge", result.stderr)
            self.assertFalse((target / "compose.yml").exists())

    def test_explicit_missing_network_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, target, _, _ = self.run_installer(
                tmp, DROPJAK_NETWORK="nincs-ilyen")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not exist", result.stderr)
            self.assertFalse((target / "compose.yml").exists())

    def test_non_bridge_network_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            networks = {"macvlan0": "macvlan"}
            result, target, _, _ = self.run_installer(
                tmp, networks=networks, DROPJAK_NETWORK="macvlan0")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not bridge", result.stderr)
            self.assertFalse((target / "compose.yml").exists())

    def test_upgrade_removes_legacy_timer_and_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            script, target, bin_dir, _, lib, units = self.make_installer(tmp)
            lib.mkdir(parents=True, exist_ok=True)
            units.mkdir(parents=True, exist_ok=True)
            (lib / "reconcile-networks.sh").write_text("#!/bin/sh\n")
            (units / "dropjak-agent-networks.service").write_text("[Unit]\n")
            (units / "dropjak-agent-networks.timer").write_text("[Timer]\n")
            systemctl_log = Path(tmp, "systemctl.log")
            env = self.installer_env(
                tmp, bin_dir, lib, units, DROPJAK_NO_SYSTEMD="0")
            result = subprocess.run(
                ["sh", str(script)], capture_output=True, text=True,
                timeout=60, stdin=subprocess.DEVNULL, env=env, cwd=target,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((lib / "reconcile-networks.sh").exists())
            self.assertFalse(
                (units / "dropjak-agent-networks.service").exists())
            self.assertFalse(
                (units / "dropjak-agent-networks.timer").exists())
            calls = systemctl_log.read_text()
            self.assertIn("disable --now dropjak-agent-networks.timer", calls)
            self.assertIn("daemon-reload", calls)

    def test_reinstall_overwrites_without_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first, target, _, _ = self.run_installer(tmp)
            self.assertEqual(first.returncode, 0, first.stderr)
            second, _, log, _ = self.run_installer(tmp)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertNotIn("Network [", second.stdout)
            self.assertTrue((target / "compose.yml").is_file())
            self.assertEqual(log.read_text().count("compose up -d --build"), 2)

    # -- installer hardening (DJ-08) -----------------------------------------

    def test_prints_sha256_of_the_installer_file(self) -> None:
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            result, _, _, _ = self.run_installer(tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            script = Path(tmp, "dropjak-agent-home.sh")
            digest = hashlib.sha256(script.read_bytes()).hexdigest()
            self.assertIn(f"Installer SHA-256: {digest}", result.stdout)
            self.assertIn("private key", result.stdout)

    def test_refuses_directory_writable_by_others(self) -> None:
        for mode in (0o777, 0o775, 0o1777):
            with self.subTest(mode=oct(mode)), \
                    tempfile.TemporaryDirectory() as tmp:
                script, target, bin_dir, _, lib, units = \
                    self.make_installer(tmp)
                target.chmod(mode)
                env = self.installer_env(tmp, bin_dir, lib, units)
                result = subprocess.run(
                    ["sh", str(script)], capture_output=True, text=True,
                    timeout=60, stdin=subprocess.DEVNULL, env=env,
                    cwd=target)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("other users can write", result.stderr)
                self.assertEqual(list(target.iterdir()), [])

    def test_refuses_symlinked_install_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp, "elsewhere")
            real.mkdir()
            link = Path(tmp, "link")
            link.symlink_to(real)
            result, _, _, _ = self.run_installer(tmp, DROPJAK_DIR=str(link))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symbolic link", result.stderr)
            self.assertEqual(list(real.iterdir()), [])

    def test_planted_symlinks_are_replaced_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            victim = Path(tmp, "victim")
            victim.write_text("keep\n")
            victim.chmod(0o640)
            script, target, bin_dir, _, lib, units = self.make_installer(tmp)
            for name in ("container-name", "compose.yml", "agent.json"):
                (target / name).symlink_to(victim)
            env = self.installer_env(tmp, bin_dir, lib, units)
            result = subprocess.run(
                ["sh", str(script)], capture_output=True, text=True,
                timeout=60, stdin=subprocess.DEVNULL, env=env, cwd=target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(victim.read_text(), "keep\n")
            self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o640)
            for name in ("container-name", "compose.yml", "agent.json"):
                self.assertFalse((target / name).is_symlink(), name)
            self.assertEqual(
                stat.S_IMODE((target / "agent.json").stat().st_mode), 0o600)

    def test_staging_payload_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp, "tmpdir")
            staging.mkdir()
            result, _, _, _ = self.run_installer(tmp, TMPDIR=str(staging))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(staging.iterdir()), [])
            # A failed run cleans up too.
            failed, _, _, _ = self.run_installer(
                tmp, TMPDIR=str(staging), DROPJAK_NETWORK="no-such-net")
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(list(staging.iterdir()), [])

    def test_root_installs_into_fixed_private_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            script, target, bin_dir, _, lib, units = self.make_installer(tmp)
            fake_id = bin_dir / "id"
            fake_id.write_text(
                '#!/bin/sh\n[ "$1" = "-u" ] && { echo 0; exit 0; }\n'
                'exec /usr/bin/id "$@"\n')
            fake_id.chmod(0o755)
            base = Path(tmp, "opt")
            env = self.installer_env(
                tmp, bin_dir, lib, units, DROPJAK_BASE=str(base),
                SUDO_UID=str(os.getuid()))
            result = subprocess.run(
                ["sh", str(script)], capture_output=True, text=True,
                timeout=60, stdin=subprocess.DEVNULL, env=env, cwd=target)
            self.assertEqual(result.returncode, 0, result.stderr)
            installed = base / DEFAULT_AGENT_NAME
            self.assertTrue((installed / "agent.json").is_file())
            self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o700)
            # Nothing lands in the directory the installer was started from.
            self.assertEqual(list(target.iterdir()), [])

    @unittest.skipIf(os.geteuid() == 0, "the system directory is the default as root")
    def test_rootless_install_does_not_create_helper(self) -> None:
        """Rootless Podman/Docker: no network-reconcile helper/timer."""
        with tempfile.TemporaryDirectory() as tmp:
            result, _, _, _ = self.run_installer(
                tmp, DROPJAK_LIB_DIR="", DROPJAK_SYSTEMD_UNIT_DIR="")
            self.assertEqual(result.returncode, 0, result.stderr)
            helper = Path(
                tmp, "home", ".local", "share", "dropjak-agent",
                "reconcile-networks.sh")
            self.assertFalse(helper.exists())
            timer = Path(
                tmp, "home", ".config", "systemd", "user",
                "dropjak-agent-networks.timer")
            self.assertFalse(timer.exists())

    def test_no_timer_or_systemd_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, _, _, _ = self.run_installer(tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = (result.stdout + result.stderr).lower()
            self.assertNotIn("systemd", output)
            self.assertNotIn("timer", output)
            self.assertIn("Done", result.stdout)


class ContainmentCheckTests(unittest.TestCase):
    """check-containment.sh requires exactly one bridge network."""

    NETWORKS = {
        "bridge": "bridge",
        "host": "host",
        "none": "null",
        "playitgg-net": "bridge",
        "macvlan0": "macvlan",
    }

    def run_check(self, attached=(), containers=None, extra_files=None,
                  **extra_env):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp, "bin")
            bin_dir.mkdir()
            if containers is None:
                containers = {"dropjak-tunnel-agent": list(attached)}
            normalized = {}
            for name, value in containers.items():
                if isinstance(value, dict):
                    normalized[name] = value
                else:
                    normalized[name] = {
                        "image": "dropjak-tunnel-agent:1",
                        "networks": list(value),
                    }
            state = {
                "log": str(Path(tmp, "docker.log")),
                "networks": dict(self.NETWORKS),
                "containers": normalized,
            }
            (bin_dir / "state.json").write_text(json.dumps(state))
            (bin_dir / "docker").write_text(FAKE_DOCKER)
            (bin_dir / "docker").chmod(0o755)
            (bin_dir / "podman").write_text("#!/bin/sh\nexit 1\n")
            (bin_dir / "podman").chmod(0o755)
            for name, content in (extra_files or {}).items():
                (Path(tmp) / name).write_text(content)
            env = {
                "PATH": f"{bin_dir}:/usr/bin:/bin",
                "HOME": str(Path(tmp, "home")),
            }
            env.update(extra_env)
            return subprocess.run(
                ["sh", str(ROOT / "deploy" / "tunnel-agent"
                           / "check-containment.sh")],
                capture_output=True, text=True, timeout=30,
                stdin=subprocess.DEVNULL, env=env, cwd=tmp,
            )

    def test_single_bridge_network_passes(self) -> None:
        result = self.run_check(["playitgg-net"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_expected_network_must_match(self) -> None:
        result = self.run_check(
            ["playitgg-net"], DROPJAK_NETWORK="playitgg-net")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_check(
            ["playitgg-net"], DROPJAK_NETWORK="minecraft_default")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("does not match", result.stderr)

    def test_zero_networks_fails(self) -> None:
        result = self.run_check([])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not connected to any network", result.stderr)

    def test_multiple_networks_fail_and_list_extras(self) -> None:
        result = self.run_check(["playitgg-net", "minecraft_default"])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("exactly one network", result.stderr)
        self.assertIn("minecraft_default", result.stderr)

    def test_host_network_is_rejected(self) -> None:
        result = self.run_check(["host"])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("forbidden network", result.stderr)

    def test_non_bridge_network_is_rejected(self) -> None:
        result = self.run_check(["macvlan0"])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("not bridge", result.stderr)

    def test_discovers_the_single_agent_container(self) -> None:
        result = self.run_check(containers={
            DEFAULT_AGENT_NAME: ["playitgg-net"],
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_no_agent_container_fails_with_instruction(self) -> None:
        result = self.run_check(containers={})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dropjak-tunnel-agent", result.stderr)
        self.assertIn("install the agent first", result.stderr)

    def test_ambiguous_agent_containers_are_refused(self) -> None:
        result = self.run_check(containers={
            "dropjak-tunnel-agent-home-home-1": ["playitgg-net"],
            "dropjak-tunnel-agent-home-home-2": ["playitgg-net"],
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("several Dropjak tunnel agent containers", result.stderr)
        self.assertIn("dropjak-tunnel-agent-home-home-1", result.stderr)
        self.assertIn("dropjak-tunnel-agent-home-home-2", result.stderr)
        self.assertIn("DROPJAK_CONTAINER", result.stderr)

    def test_container_name_file_disambiguates(self) -> None:
        result = self.run_check(
            containers={
                "dropjak-tunnel-agent-home-home-1": ["playitgg-net"],
                "dropjak-tunnel-agent-home-home-2": ["playitgg-net"],
            },
            extra_files={
                "container-name": "dropjak-tunnel-agent-home-home-2\n",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_explicit_container_overrides_discovery(self) -> None:
        result = self.run_check(
            containers={
                "dropjak-tunnel-agent-home-home-1": ["playitgg-net"],
                "dropjak-tunnel-agent-home-home-2": ["bridge"],
            },
            DROPJAK_CONTAINER="dropjak-tunnel-agent-home-home-2",
            DROPJAK_NETWORK="bridge",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()

