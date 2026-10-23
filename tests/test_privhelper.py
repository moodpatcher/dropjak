#!/usr/bin/env python3
"""DJ-20: the privileged helper and the portal without CAP_NET_ADMIN.

* the helper's fixed command set: unknown verbs, malformed, oversized and
  wrong-peer requests and injected custom-chain lines are refused before
  anything runs;
* the portal side (RemoteFirewall, RemoteTunnelManager, the NFLOG socket,
  conntrack) issues exactly the nft commands the local Firewall issued:
  only the executing process changed;
* a dead helper makes grants fail closed, a restarted one serves again,
  and the startup waits for it instead of crash-looping;
* the entrypoint starts the helper (root, NET_ADMIN only) in a restart
  loop before the portal, which runs with an empty bounding set; the
  native units do the same; the images are pinned by digest;
* end to end with real nft in a user+net namespace (privhelper_netns.py).
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
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
import privhelper  # noqa: E402
from test_firewall_hardening import RecordingAudit, build_gateway  # noqa: E402

ENTRYPOINT = (ROOT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
AGENT_DOCKERFILE = (ROOT / "deploy" / "tunnel-agent" / "Dockerfile").read_text(
    encoding="utf-8"
)
PORTAL_UNIT = (ROOT / "deploy" / "dropjak.service").read_text(encoding="utf-8")
HELPER_UNIT = (ROOT / "deploy" / "dropjak-helper.service").read_text(
    encoding="utf-8"
)
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
IP = "198.51.100.7"
QUIET = {"logger": lambda *_: None}


def wg_key(seed: int) -> str:
    return base64.b64encode(bytes([seed]) * 32).decode("ascii")


class RecordingFirewall(gateway.Firewall):
    """The real Firewall code; nft calls are recorded instead of run."""

    def __init__(self, **kwargs) -> None:
        kwargs.setdefault("dry_run", False)
        kwargs.setdefault("lan_if", "eth1")
        kwargs.setdefault("wan_if", "eth0")
        kwargs.setdefault("lan_network", None)
        kwargs.setdefault("logger", lambda *_: None)
        super().__init__(**kwargs)
        self.commands: list[tuple] = []
        self.token: int | None = 7

    def _run(self, args, check: bool = True):
        self.commands.append(("run", tuple(args)))
        stdout = b'{"nftables": []}' if args and args[0] == "-j" else b""
        return subprocess.CompletedProcess(args, 0, stdout, b"")

    def _run_script(self, script: str) -> None:
        self.commands.append(("script", script))

    def state_token(self):
        return self.token


class FakeTunnels:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.error = ""

    def reconcile(self, tunnels):
        self.calls.append(("reconcile", tunnels))
        return True

    def remove_all(self):
        self.calls.append(("remove_all",))

    def status(self, tunnels, now=None):
        self.calls.append(("status", tunnels, now))
        return {"error": "", "agents": [
            {"id": agent["id"], "online": True, "last_handshake": 1,
             "rx_bytes": 2, "tx_bytes": 3}
            for agent in tunnels["agents"]
        ]}


class HelperHarness:
    """A helper server on a temporary socket, in a background thread."""

    def __init__(self, test: unittest.TestCase, helper=None, **kwargs) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dropjak-helper-test-")
        test.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = os.path.join(self.tmp, "helper.sock")
        self.firewall = kwargs.pop("firewall", None) or RecordingFirewall()
        self.tunnels = kwargs.pop("tunnels", None) or FakeTunnels()
        self.helper = helper or privhelper.Helper(
            firewall=self.firewall, tunnels=self.tunnels,
            allowed_uids=kwargs.pop("allowed_uids", {os.getuid()}),
            **kwargs,
        )
        self.server = None
        self.client = gateway.PrivHelperClient(self.path, timeout=10)
        test.addCleanup(self.stop)

    def start(self) -> "HelperHarness":
        self.server = privhelper.HelperServer(self.helper, self.path)
        with mock.patch.object(privhelper, "log", lambda *_: None):
            self.server.bind()
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def _serve(self) -> None:
        server = self.server
        try:
            server.serve_forever()
        except OSError:
            pass

    def stop(self) -> None:
        server, self.server = self.server, None
        if server is not None:
            try:
                server.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            server.close()


def request(op: str, args=None) -> bytes:
    return json.dumps({"op": op, "args": {} if args is None else args}).encode()


# ------------------------------------------------------------ the command set


class CommandSetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fw = RecordingFirewall()
        self.tunnels = FakeTunnels()
        self.helper = privhelper.Helper(
            firewall=self.fw, tunnels=self.tunnels, allowed_uids={1000},
        )

    def dispatch(self, raw: bytes, uid: int | None = 1000) -> dict:
        answer, sock = self.helper.dispatch(raw, uid)
        self.assertIsNone(sock)
        return answer

    def assertRefused(self, raw: bytes, kind: str = "invalid", uid=1000):
        answer = self.dispatch(raw, uid)
        self.assertFalse(answer["ok"], answer)
        self.assertEqual(answer["type"], kind, answer)
        return answer

    def test_ping(self) -> None:
        self.assertEqual(self.dispatch(request("ping")), {"ok": True, "result": "pong"})

    def test_unknown_verbs_are_refused(self) -> None:
        for op in ("run", "exec", "nft", "shell", "command", "", "dispatch",
                   "ops", "__init__", "_grant_all", "Ping", "nflog"):
            answer = self.assertRefused(request(op, {"args": ["flush", "ruleset"]}))
            self.assertIn("unknown operation", answer["error"])
        self.assertEqual(self.fw.commands, [])

    def test_there_is_no_generic_command_verb(self) -> None:
        # Every verb names one operation; none takes a command or script.
        for op in self.helper.ops:
            self.assertNotRegex(
                op, r"(^|_)(run|exec|script|command|shell|raw)(_|$)"
            )

    def test_malformed_requests_are_refused(self) -> None:
        for raw in (
            b"", b"not json", b"[]", b'"ping"', b'{"op": "ping"}',
            b'{"args": {}}', b'{"op": 1, "args": {}}',
            b'{"op": "ping", "args": {}, "extra": 1}', b"\xff\xfe",
            b'{"op": "ping", "args": []}', b'{"op": "ping", "args": {"x": 1}}',
        ):
            self.assertRefused(raw)

    def test_oversized_request_is_refused(self) -> None:
        raw = request("ping") + b" " * privhelper.MAX_REQUEST
        self.assertIn("too large", self.assertRefused(raw)["error"])

    def test_read_request_limits_the_size(self) -> None:
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        right.sendall(b"x" * 300)
        with self.assertRaisesRegex(privhelper.RequestError, "too large"):
            privhelper.read_request(left, limit=100)
        left2, right2 = socket.socketpair()
        self.addCleanup(left2.close)
        self.addCleanup(right2.close)
        right2.sendall(b'{"a": 1}\nrest')
        self.assertEqual(privhelper.read_request(left2, limit=100), b'{"a": 1}')
        # A trickling client cannot hold a slot past the request deadline.
        left3, right3 = socket.socketpair()
        self.addCleanup(left3.close)
        self.addCleanup(right3.close)
        right3.sendall(b'{"op": ')
        with self.assertRaises(socket.timeout):
            privhelper.read_request(left3, limit=100, timeout=0.3)

    def test_wrong_peer_uid_is_refused(self) -> None:
        for uid in (0, 999, 1001, None):
            self.assertRefused(request("ping"), "denied", uid=uid)
        # Default: the portal user and root only.
        with mock.patch.object(
            privhelper.pwd, "getpwnam",
            return_value=types.SimpleNamespace(pw_uid=4242),
        ):
            self.assertEqual(privhelper.default_uids(), {0, 4242})

    def test_arguments_are_exact(self) -> None:
        good = {"ip": IP, "ttl": 60, "set": "banned_v4"}
        self.assertTrue(self.dispatch(request("ban", good))["ok"])
        self.fw.commands.clear()
        for args in (
            {**good, "extra": 1},
            {"ip": IP, "ttl": 60},
            {**good, "ip": "2001:db8::1"},
            {**good, "ip": "198.51.100.0/24"},
            {**good, "ip": 3232235777},
            {**good, "ip": "1.2.3.4 } ; flush ruleset"},
            {**good, "ttl": True},
            {**good, "ttl": -1},
            {**good, "ttl": "60"},
            {**good, "ttl": privhelper.MAX_TTL + 1},
            {**good, "set": "allowed_v4"},
            {**good, "set": "banned_v4 { 1.2.3.4 }"},
            {**good, "set": ""},
        ):
            self.assertRefused(request("ban", args))
        self.assertEqual(self.fw.commands, [])

    def test_grants_are_validated(self) -> None:
        good = gateway.ports_to_wire(gateway.Ports(tcp=(80,)))
        for grant in (
            {**good, "direction": "both"},
            {**good, "full": 1},
            {**good, "icmp": "yes"},
            {**good, "tcp": [[0, 10]]},
            {**good, "tcp": [[10, 5]]},
            {**good, "tcp": [[1, 70000]]},
            {**good, "tcp": [80]},
            {**good, "tcp": [[True, 2]]},
            {**good, "label": "x"},
            {"tcp": [[80, 80]]},
        ):
            self.assertRefused(request(
                "grant_all", {"ip": IP, "grants": [grant], "ttl": 60}
            ))
        self.assertRefused(request(
            "grant_all", {"ip": IP, "grants": [good] * (privhelper.MAX_GRANTS + 1),
                          "ttl": 60}
        ))
        self.assertEqual(self.fw.commands, [])

    def test_ports_wire_round_trip(self) -> None:
        for ports in (
            gateway.Ports(tcp=(22, 80, 81, 82, 443), udp=(53,), icmp=True),
            gateway.Ports(full=True),
            gateway.Ports(tcp=tuple(range(8000, 8101)), direction="input"),
            gateway.Ports(),
        ):
            self.assertEqual(
                gateway.ports_from_wire(gateway.ports_to_wire(ports)), ports
            )

    def rules(self, *lines: str, keep_block: bool = False) -> bytes:
        return request(
            "replace_custom", {"rules": list(lines), "keep_block": keep_block}
        )

    def test_custom_rule_injection_is_refused(self) -> None:
        prefix = "add rule inet hatarvedelem preauth "
        for line in (
            prefix + "accept; flush ruleset",
            prefix + "accept\nflush ruleset",
            prefix + "accept\rdelete table inet hatarvedelem",
            prefix + "accept # comment",
            prefix + 'include "/etc/nftables.conf"',
            prefix + "INCLUDE x",
            prefix + "flush ruleset",
            prefix + 'log prefix "a\\" accept',
            prefix + "accept `x`",
            prefix + "accept\x00",
            prefix + "accept é",
            "flush ruleset",
            "delete table inet hatarvedelem",
            "add rule inet filter preauth accept",
            "add rule ip hatarvedelem preauth accept",
            "add rule inet hatarvedelem input accept",
            "add rule inet hatarvedelem forward accept",
            "add rule inet hatarvedelem preauthx accept",
            "add rule inet hatarvedelem preauth",
            "add chain inet hatarvedelem preauth",
            "add element inet hatarvedelem allowed_v4 { 1.2.3.4 }",
            " add rule inet hatarvedelem preauth accept",
            "",
            prefix + "accept " + "x" * privhelper.MAX_RULE_LENGTH,
        ):
            self.assertRefused(self.rules(line), "invalid")
        for value in (None, "x", [1], {"rules": []}):
            self.assertRefused(request(
                "replace_custom", {"rules": value, "keep_block": False}
            ))
        self.assertRefused(request(
            "replace_custom",
            {"rules": [prefix + "accept"] * (privhelper.MAX_RULES + 1),
             "keep_block": False},
        ))
        # keep_block leaves the block chains alone: no rule may target them.
        self.assertRefused(self.rules(
            "add rule inet hatarvedelem block meta l4proto tcp drop",
            keep_block=True,
        ))
        self.assertEqual(self.fw.commands, [])

    def test_rendered_custom_rules_pass_the_check(self) -> None:
        local = RecordingFirewall()
        local.replace_custom(*CUSTOM_ARGS, **CUSTOM_KWARGS)
        script = local.commands[-1][1]
        rules = [
            line for line in script.splitlines()
            if line.startswith("add rule ")
        ]
        self.assertGreater(len(rules), 10)
        checked = privhelper.check_custom_rules(
            rules, "hatarvedelem", gateway.Firewall.replaced_chains(False)
        )
        self.assertEqual(checked, rules)

    def test_tunnel_requests_are_validated(self) -> None:
        good_agent = {
            "id": "home", "address": "10.77.0.2", "public_key": wg_key(1),
            "preshared_key": wg_key(2), "enabled": True,
        }
        good = {"port": 51820, "server_private_key": wg_key(3),
                "agents": [good_agent]}
        self.assertTrue(
            self.dispatch(request("tunnel_reconcile", {"tunnels": good}))["ok"]
        )
        for tunnels in (
            {**good, "server_private_key": "not a key"},
            {**good, "port": 0},
            {**good, "extra": 1},
            {**good, "agents": [{**good_agent, "address": "192.168.1.2"}]},
            {**good, "agents": [{**good_agent, "address": "10.77.0.1"}]},
            {**good, "agents": [{**good_agent, "public_key": "x" * 44}]},
            {**good, "agents": [{**good_agent, "id": "../etc"}]},
            {**good, "agents": [{**good_agent, "enabled": "yes"}]},
            {**good, "agents": [{**good_agent, "private_key": wg_key(4)}]},
            {**good, "agents": [good_agent] * 100},
        ):
            self.assertRefused(request("tunnel_reconcile", {"tunnels": tunnels}))
        self.assertEqual(len(self.tunnels.calls), 1)

    def test_errors_do_not_leak_internals(self) -> None:
        self.fw.flush = mock.Mock(side_effect=KeyError("secret detail"))
        with mock.patch.object(privhelper, "log", lambda *_: None):
            answer = self.assertRefused(request("flush"), "internal")
        self.assertNotIn("secret", answer["error"])
        self.fw.flush = mock.Mock(side_effect=gateway.FirewallError("nft says no"))
        self.assertEqual(
            self.assertRefused(request("flush"), "firewall")["error"],
            "nft says no",
        )


# ------------------------------------------------- same commands, other process

CUSTOM_ARGS = (
    [
        {"id": "p1", "proto": "tcp", "ports": [443], "dst": "203.0.113.0/24"},
        {"id": "p2", "proto": "udp", "ports": [123], "direction": "input",
         "scope": "any"},
    ],
    [{"id": "b1", "proto": "tcp", "ports": [25, 80], "dst": "203.0.113.10"}],
)
CUSTOM_KWARGS = {
    "port_proxies": [
        {"id": "pp", "proto": "both", "type": "forward", "listen_port": 2222,
         "target_ip": "172.19.0.2", "target_port": 22, "ifaces": "both",
         "snat": True},
    ],
    "tunnels": {
        "port": 51820, "server_private_key": wg_key(9),
        "agents": [{
            "id": "home", "enabled": True, "address": "10.77.0.2",
            "public_key": wg_key(1), "preshared_key": wg_key(2),
            "services": [],
        }],
    },
    "container_egress": [
        {"id": "c1", "address": "172.30.0.2", "bridge": "br-mc",
         "tcp": [443], "udp": []},
    ],
}


class SameCommandsTests(unittest.TestCase):
    """The helper runs exactly what the local Firewall ran (DJ-20 step 7)."""

    def setUp(self) -> None:
        patcher = mock.patch.object(gateway, "CONNTRACK_BIN", "")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.local = RecordingFirewall()
        self.harness = HelperHarness(self).start()
        self.inner = self.harness.firewall
        self.remote = gateway.RemoteFirewall(
            self.harness.client, lan_if="eth1", wan_if="eth0",
            lan_network=None, dry_run=False, **QUIET,
        )

    def both(self, name: str, *args, **kwargs):
        local = getattr(self.local, name)(*args, **kwargs)
        remote = getattr(self.remote, name)(*args, **kwargs)
        self.assertEqual(self.inner.commands, self.local.commands, name)
        return local, remote

    def test_grants_revocations_and_bans(self) -> None:
        grants = (
            gateway.Ports(tcp=(80, 443) + tuple(range(8000, 8011))),
            gateway.Ports(tcp=(22,), udp=(53,), direction="input"),
            gateway.Ports(icmp=True),
        )
        self.both("grant_all", IP, grants, 600)
        self.both("grant_all", IP, (gateway.Ports(full=True),), 60)
        self.both("revoke_exact", IP, grants)
        self.both("revoke_all", IP, grants)
        self.both("revoke_all", IP, grants, discover=True)
        self.both("revoke_all", IP, grants, only_grants=True)
        self.both("revoke", IP, grants[0])
        self.both("deny", IP, grants[1])
        self.both("deny", IP)
        self.both("ban", "203.0.113.9", 600)
        self.both("proxy_ban", "203.0.113.9", 600)
        self.both("unban", "203.0.113.9")
        self.both("proxy_unban", "203.0.113.9")
        self.both("sync_bans", [("203.0.113.9", 60), ("::1", 5), ("10.0.0.1", 0)])
        self.both("sync_proxy_bans", [("203.0.113.9", 60)])
        self.both("sync_host_ports", [22, 8000, 8001, True, 70000], [53])
        self.both("flush")
        # Non-IPv4 revocations do nothing on either side.
        self.both("unban", "2001:db8::1")
        self.both("revoke_all", "not an ip")

    def test_custom_chains(self) -> None:
        self.both("replace_custom", *CUSTOM_ARGS, **CUSTOM_KWARGS)
        self.assertEqual(self.remote.portproxy_applied, self.local.portproxy_applied)
        self.both("replace_custom", (), (), keep_block=True)
        self.both("replace_custom", (), ())

    def test_reads(self) -> None:
        for name in ("healthy", "input_chain_consistent", "state_token",
                     "docker_published_ports"):
            local, remote = self.both(name)
            self.assertEqual(remote, local, name)
        local, remote = self.both("snapshot")
        local.pop("generated"), remote.pop("generated")
        self.assertEqual(remote, local)
        local, remote = self.both("ruleset")
        local.pop("generated"), remote.pop("generated")
        self.assertEqual(remote, local)
        local, remote = self.both("prune_host_service_ports", [22], [53])
        self.assertEqual(remote, local)

    def test_single_nic_mode(self) -> None:
        local = RecordingFirewall(single_nic=True, lan_if="")
        harness = HelperHarness(
            self, firewall=RecordingFirewall(single_nic=True, lan_if="")
        ).start()
        remote = gateway.RemoteFirewall(
            harness.client, lan_if="", wan_if="eth0", lan_network=None,
            dry_run=False, single_nic=True, **QUIET,
        )
        for fw in (local, remote):
            fw.replace_custom(*CUSTOM_ARGS, **CUSTOM_KWARGS)
            fw.grant_all(IP, (gateway.Ports(tcp=(80,)),), 60)
            fw.revoke_all(IP, (gateway.Ports(tcp=(80,)),))
        self.assertEqual(harness.firewall.commands, local.commands)
        script = local.commands[0][1]
        self.assertIn('iifname "eth0"', script)
        self.assertNotIn("eth1", script)

    def test_local_validation_errors_are_kept(self) -> None:
        for args in (
            ("not-an-ip", (gateway.Ports(tcp=(80,)),), 60),
            (IP, (gateway.Ports(full=True, direction="input"),), 60),
            (IP, (gateway.Ports(icmp=True, direction="input"),), 60),
        ):
            with self.assertRaises(gateway.FirewallError) as local:
                self.local.grant_all(*args)
            with self.assertRaises(gateway.FirewallError) as remote:
                self.remote.grant_all(*args)
            self.assertEqual(str(remote.exception), str(local.exception))
        self.assertEqual(self.inner.commands, [])

    def test_portal_side_never_runs_nft(self) -> None:
        with self.assertRaisesRegex(gateway.FirewallError, "privileged helper"):
            self.remote._run(["list", "ruleset"])
        with self.assertRaisesRegex(gateway.FirewallError, "privileged helper"):
            self.remote._run_script("flush ruleset\n")


# ----------------------------------------------------------------- the client


class ClientTests(unittest.TestCase):
    def test_missing_helper_is_unavailable(self) -> None:
        client = gateway.PrivHelperClient("/nonexistent/dropjak/helper.sock")
        with self.assertRaises(gateway.HelperUnavailable):
            client.call("ping")
        self.assertTrue(issubclass(gateway.HelperUnavailable, gateway.FirewallError))
        started = time.monotonic()
        self.assertFalse(client.wait_ready(0.3))
        self.assertLess(time.monotonic() - started, 5)

    def test_ping_and_refusals_over_the_socket(self) -> None:
        harness = HelperHarness(self).start()
        self.assertTrue(harness.client.wait_ready(5))
        with self.assertRaisesRegex(gateway.FirewallError, "unknown operation"):
            harness.client.call("nft", {"args": ["flush", "ruleset"]})
        with self.assertRaisesRegex(gateway.FirewallError, "too large"):
            harness.client.call("ping", {"x": "y" * gateway.PRIV_HELPER_MAX_REQUEST})

    def test_oversized_request_over_the_socket(self) -> None:
        harness = HelperHarness(self).start()
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(raw.close)
        raw.settimeout(10)
        raw.connect(harness.path)

        def flood():
            try:
                raw.sendall(b"x" * (privhelper.MAX_REQUEST + 70000))
            except OSError:
                pass

        sender = threading.Thread(target=flood, daemon=True)
        sender.start()
        reader = raw.makefile("rb")
        self.addCleanup(reader.close)
        answer = json.loads(reader.readline())
        sender.join(10)
        self.assertEqual(answer["type"], "invalid")
        self.assertIn("too large", answer["error"])
        self.assertEqual(harness.firewall.commands, [])

    def test_wrong_uid_over_the_socket(self) -> None:
        harness = HelperHarness(self, allowed_uids={os.getuid() + 1}).start()
        with mock.patch.object(privhelper, "log", lambda *_: None):
            with self.assertRaisesRegex(gateway.FirewallError, "peer not allowed"):
                harness.client.call("ping")
        self.assertEqual(harness.firewall.commands, [])

    def test_socket_permissions(self) -> None:
        harness = HelperHarness(self).start()
        mode = os.stat(harness.path).st_mode & 0o777
        self.assertEqual(mode, 0o660)

    def test_nflog_socket_is_passed(self) -> None:
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        harness = HelperHarness(self, nflog_opener=lambda: theirs).start()
        received = harness.client.nflog_socket()
        self.addCleanup(received.close)
        ours.sendall(b"packet")
        received.settimeout(5)
        self.assertEqual(received.recv(100), b"packet")

    def test_nflog_failure_is_an_oserror(self) -> None:
        def fail():
            raise OSError(1, "Operation not permitted")

        harness = HelperHarness(self, nflog_opener=fail).start()
        with self.assertRaisesRegex(OSError, "NFLOG"):
            harness.client.nflog_socket()

    def test_drop_log_listener_uses_the_opener(self) -> None:
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        listener = gateway.droplog.DropLogListener(
            types.SimpleNamespace(path=""), group=5, enabled=True,
            logger=lambda *_: None, socket_opener=lambda: theirs,
        )
        sock = listener._open_socket()
        self.addCleanup(sock.close)
        self.assertIs(sock, theirs)
        self.assertEqual(sock.gettimeout(), 1.0)

    def test_conntrack_audit_is_replayed(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        fake = os.path.join(tmp, "conntrack")
        Path(fake).write_text("#!/bin/sh\necho boom >&2\nexit 2\n")
        os.chmod(fake, 0o755)
        harness = HelperHarness(self).start()
        audit = RecordingAudit()
        with mock.patch.object(gateway, "CONNTRACK_BIN", fake), \
                mock.patch.object(gateway, "DRY_RUN", False), \
                mock.patch.object(gateway, "log", lambda *_: None):
            self.assertFalse(
                harness.client.conntrack("conntrack_flush", {"ip": IP}, audit)
            )
        self.assertEqual(audit.names(), ["conntrack_failed"])
        self.assertEqual(audit.events[0][1]["detail"], "boom")

    def test_conntrack_routes_through_the_helper(self) -> None:
        client = mock.Mock()
        client.conntrack.return_value = True
        with mock.patch.object(gateway, "priv_helper_client", return_value=client):
            self.assertTrue(gateway.conntrack_flush(IP))
            gateway.conntrack_flush_port("udp", 53)
            gateway.conntrack_flush_removed(
                IP, (gateway.Ports(tcp=(80,)),), (gateway.Ports(tcp=(22,)),)
            )
        ops = [call.args[0] for call in client.conntrack.call_args_list]
        self.assertEqual(
            ops, ["conntrack_flush", "conntrack_flush_port", "conntrack_flush_removed"]
        )
        self.assertEqual(
            client.conntrack.call_args_list[2].args[1]["removed"],
            [gateway.ports_to_wire(gateway.Ports(tcp=(80,)))],
        )

    def test_conntrack_without_helper_never_raises(self) -> None:
        client = gateway.PrivHelperClient("/nonexistent/helper.sock")
        audit = RecordingAudit()
        with mock.patch.object(gateway, "log", lambda *_: None):
            self.assertFalse(client.conntrack("conntrack_flush", {"ip": IP}, audit))
        self.assertEqual(audit.names(), ["conntrack_failed"])

    def test_factories(self) -> None:
        with mock.patch.object(gateway, "PRIV_HELPER_SOCKET", ""):
            self.assertIs(type(gateway.make_firewall()), gateway.Firewall)
            self.assertIs(
                type(gateway.make_tunnel_manager()), gateway.tunnel_mod.TunnelManager
            )
            self.assertIsNone(
                gateway.make_drop_log_service().listener.socket_opener
            )
        with mock.patch.object(gateway, "PRIV_HELPER_SOCKET", "/run/x.sock"):
            self.assertIsInstance(gateway.make_firewall(), gateway.RemoteFirewall)
            self.assertIsInstance(
                gateway.make_tunnel_manager(), gateway.RemoteTunnelManager
            )
            self.assertIsNotNone(
                gateway.make_drop_log_service().listener.socket_opener
            )


# ------------------------------------------------------ helper down / restarted


class HelperRestartTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.object(gateway, "CONNTRACK_BIN", "")
        patcher.start()
        self.addCleanup(patcher.stop)
        logs = mock.patch.object(gateway, "log", lambda *_: None)
        logs.start()
        self.addCleanup(logs.stop)
        self.harness = HelperHarness(self).start()
        self.fw = gateway.RemoteFirewall(
            self.harness.client, lan_if="", wan_if="eth0", lan_network=None,
            dry_run=False, **QUIET,
        )
        self.gw, self.rule, self.audit, _f2b = build_gateway(self.fw)
        self.gw._fw_token = 7

    def grants(self) -> list[str]:
        return [
            script for kind, script in self.harness.firewall.commands
            if kind == "script" and "allowed_tcp" in script
        ]

    def test_grants_refused_while_the_helper_is_down(self) -> None:
        first = self.gw.sessions.login("alice", IP)
        self.gw.sessions.authorize(first.token, IP, self.rule, 60)
        self.assertEqual(len(self.grants()), 1)

        self.harness.stop()
        self.assertFalse(self.gw.check_firewall_state())
        self.assertFalse(self.gw.check_firewall_state())
        helper_errors = [
            fields for event, fields in self.audit.events
            if event == "firewall_error" and fields.get("operation") == "helper"
        ]
        self.assertEqual(len(helper_errors), 1)
        self.assertFalse(self.gw._firewall_in_sync())
        second = self.gw.sessions.login("bob", "198.51.100.8")
        with self.assertRaises(gateway.FirewallError):
            self.gw.sessions.authorize(second.token, "198.51.100.8", self.rule, 60)
        self.assertEqual(len(self.grants()), 1)
        # Nothing lost: the session table is not reset by a helper restart.
        self.assertIsNotNone(self.gw.sessions.validate(first.token, IP))

        self.harness.start()
        self.assertFalse(self.gw.check_firewall_state())
        self.assertFalse(self.gw._helper_down_logged)
        self.assertTrue(self.gw._firewall_in_sync())
        self.gw.sessions.authorize(second.token, "198.51.100.8", self.rule, 60)
        self.assertEqual(len(self.grants()), 2)
        self.assertNotIn("firewall_resync", self.audit.names())

    def test_startup_waits_for_the_helper(self) -> None:
        answers = iter([False, False, True])
        firewall = types.SimpleNamespace(
            wait_ready=lambda: next(answers), client=types.SimpleNamespace(path="x"),
        )
        gw = types.SimpleNamespace(firewall=firewall)
        gateway.Gateway._wait_for_helper(gw)
        self.assertIsNone(next(answers, None))
        # Without a helper there is nothing to wait for.
        gateway.Gateway._wait_for_helper(
            types.SimpleNamespace(firewall=RecordingFirewall())
        )

    def test_prepare_waits_before_touching_the_firewall(self) -> None:
        source = (ROOT / "gateway.py").read_text(encoding="utf-8")
        prepare = source[source.index("    def prepare(self) -> None:"):]
        prepare = prepare[:prepare.index("\n    def ", 10)]
        self.assertLess(
            prepare.index("self._wait_for_helper()"),
            prepare.index("self._startup_flush()"),
        )

    def test_tunnel_reconcile_is_retried_after_a_restart(self) -> None:
        tunnels = RemoteTunnelSettings.tunnels()
        manager = gateway.RemoteTunnelManager(self.harness.client)
        self.assertTrue(manager.reconcile(tunnels))
        self.harness.stop()
        self.assertFalse(manager.reconcile(tunnels))
        self.assertIn("unavailable", manager.error)
        status = manager.status(tunnels)
        self.assertIn("unavailable", status["error"])
        self.assertEqual([row["online"] for row in status["agents"]], [False])
        self.harness.start()
        self.assertTrue(manager.retry_pending())
        self.assertFalse(manager.retry_pending())
        self.assertEqual(manager.error, "")
        reconciles = [
            call for call in self.harness.tunnels.calls if call[0] == "reconcile"
        ]
        self.assertEqual(len(reconciles), 2)


class RemoteTunnelSettings:
    @staticmethod
    def tunnels() -> dict:
        return {
            "port": 51820, "server_private_key": wg_key(3),
            "server_public_key": wg_key(4), "endpoint": "gw.example.org",
            "agents": [{
                "id": "home", "address": "10.77.0.2", "public_key": wg_key(1),
                "preshared_key": wg_key(2), "enabled": True,
                "sync_token_hash": "a" * 64, "services": [{"id": "web"}],
            }],
        }


class RemoteTunnelTests(unittest.TestCase):
    def test_only_kernel_fields_leave_the_portal(self) -> None:
        harness = HelperHarness(self).start()
        manager = gateway.RemoteTunnelManager(harness.client)
        tunnels = RemoteTunnelSettings.tunnels()
        self.assertTrue(manager.reconcile(tunnels))
        sent = harness.tunnels.calls[0][1]
        self.assertEqual(set(sent), {"port", "server_private_key", "agents"})
        self.assertEqual(
            set(sent["agents"][0]),
            {"id", "address", "public_key", "preshared_key", "enabled"},
        )
        status = manager.status(tunnels, now=100.0)
        self.assertEqual(status["agents"][0]["id"], "home")
        status_call = harness.tunnels.calls[-1]
        self.assertEqual(status_call[2], 100.0)
        # A status read never carries the keys.
        self.assertEqual(status_call[1]["server_private_key"], "configured")
        self.assertNotIn("preshared_key", status_call[1]["agents"][0])
        manager.remove_all()
        self.assertEqual(harness.tunnels.calls[-1], ("remove_all",))

    def test_helper_runs_the_real_tunnel_manager(self) -> None:
        calls: list[list[str]] = []

        def runner(args, **kwargs):
            calls.append(list(args))
            return subprocess.CompletedProcess(args, 0, "", "")

        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        real = gateway.tunnel_mod.TunnelManager(run_dir=tmp, runner=runner)
        harness = HelperHarness(self, tunnels=real).start()
        manager = gateway.RemoteTunnelManager(harness.client)
        self.assertTrue(manager.reconcile(RemoteTunnelSettings.tunnels()))
        self.assertIn(["ip", "link", "add", "dropjak0", "type", "wireguard"], calls)
        peer = [args for args in calls if "peer" in args and "allowed-ips" in args]
        self.assertEqual(peer[0][peer[0].index("allowed-ips") + 1], "10.77.0.2/32")
        # Unchanged settings: the helper's signature cache skips the kernel.
        self.assertFalse(manager.reconcile(RemoteTunnelSettings.tunnels()))
        self.assertEqual(os.listdir(tmp), [])


# ----------------------------------------------------------- deploy and images


def _function(name: str) -> str:
    start = ENTRYPOINT.index(f"\n{name}() {{\n") + 1
    return ENTRYPOINT[start:ENTRYPOINT.index("\n}\n", start) + 3]


class EntrypointHelperTests(unittest.TestCase):
    def test_portal_has_no_network_admin(self) -> None:
        body = _function("run_as_app")
        self.assertNotIn("net_admin", body)
        self.assertIn("--bounding-set=-all \\", body)
        self.assertIn("--bounding-set=-all,+net_bind_service", body)
        self.assertIn("if needs_low_port; then", body)

    def test_helper_is_root_with_net_admin_only(self) -> None:
        body = _function("run_priv_helper")
        self.assertIn("--bounding-set=-all,+net_admin", body)
        self.assertIn("--inh-caps=-all", body)
        self.assertNotIn("--reuid", body)
        self.assertIn('--regid="$APP_USER"', body)
        for secret in ("HV_ADMIN_PASSWORD", "HV_ADMIN_PASSWORD_FILE",
                       "HV_PROXY_KEY", "TURNSTILE_SECRET"):
            self.assertIn(f"-u {secret} ", body)

    def test_helper_starts_before_the_portal(self) -> None:
        main = ENTRYPOINT[ENTRYPOINT.rindex("\nensure_state_dir\n"):]
        portal = main.index('run_as_app "$PYTHON" "$APP_DIR/server.py"')
        helper = main.rindex("start_priv_helper\n", 0, portal)
        self.assertLess(main.index("    load_firewall\n"), helper)
        self.assertLess(main.index("    start_firewall_watchdog\n"), helper)
        cli = main.index('    run_as_app "$@"')
        self.assertLess(main.index("    start_priv_helper\n"), cli)

    def test_restart_loop_never_stops_the_container(self) -> None:
        body = _function("start_priv_helper")
        loop = body[body.index("    (\n"):body.index("    ) &\n")]
        self.assertIn("while :; do", loop)
        self.assertIn("run_priv_helper || status=$?", loop)
        self.assertNotIn("die ", loop)
        self.assertNotRegex(loop, r"(^|\s)exit(\s|$)")
        self.assertNotIn("die ", _function("wait_priv_helper"))
        self.assertIn("export HV_PRIV_HELPER", body)

    def test_watchdog_stays_root_side(self) -> None:
        self.assertIn("start_firewall_watchdog() {", ENTRYPOINT)
        for name in ("gateway.py", "server.py", "privhelper.py"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotIn("docker_bridges", text.replace("docker_bridges set", ""))
        self.assertIn("sync_docker_bridges", _function("start_firewall_watchdog"))

    def test_run_dir_is_root_owned_and_group_shared(self) -> None:
        body = _function("ensure_tunnel_run_dir")
        self.assertIn('chown "0:$APP_USER" "$_dir"', body)
        self.assertIn('chmod 0750 "$_dir"', body)

    def run_shell(self, script: str, env: dict, timeout: int = 30):
        functions = "\n".join(
            _function(name) for name in (
                "env_bool", "valid_port", "needs_low_port", "ensure_tunnel_run_dir",
                "run_priv_helper", "start_priv_helper", "wait_priv_helper",
            )
        )
        header = (
            "set -eu\nAPP_USER=hatarvedelem\n"
            "log() { printf '[dropjak] %s\\n' \"$*\"; }\n"
            "die() { printf '[dropjak] ERROR: %s\\n' \"$*\"; exit 1; }\n"
            'HELPER_SOCKET=${HV_PRIV_HELPER:-/run/dropjak/helper.sock}\n'
            'HELPER_WAIT=${HV_PRIV_HELPER_WAIT:-20}\n'
        )
        # A file, not a pipe: the background restart loop keeps its stdout
        # open after the script itself has finished.
        with tempfile.TemporaryFile(mode="w+") as out:
            proc = subprocess.Popen(
                ["sh", "-c", header + functions + "\n" + script],
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env},
                stdout=out, stderr=subprocess.STDOUT, text=True,
                start_new_session=True,
            )
            try:
                proc.wait(timeout=timeout)
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            out.seek(0)
            return proc.returncode, out.read()

    def test_needs_low_port(self) -> None:
        for env, expected in (
            ({"PORT": "80"}, 0),
            ({"PORT": "8100"}, 1),
            ({}, 1),
            ({"PORT": "1023"}, 0),
            ({"PORT": "1024"}, 1),
            ({"PORT": "8100", "HV_TUNNEL_SYNC_PORT": "81"}, 0),
            ({"PORT": "8100", "HV_TUNNEL_SYNC_PORT": "8100"}, 1),
            ({"PORT": "65535"}, 1),
            ({"PORT": "junk"}, 1),
        ):
            code, output = self.run_shell("needs_low_port", env)
            self.assertEqual(code, expected, (env, output))

    @unittest.skipIf(os.getuid() == 0, "the supervisor test runs as non-root")
    def test_crashed_helper_is_restarted(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        Path(tmp, "privhelper.py").write_text(
            "import os, socket, sys, time\n"
            "count = os.environ['COUNT']\n"
            "n = len(open(count).read()) + 1 if os.path.exists(count) else 1\n"
            "open(count, 'a').write('x')\n"
            "if n == 1:\n"
            "    sys.exit(3)\n"
            "s = socket.socket(socket.AF_UNIX)\n"
            "s.bind(sys.argv[2])\n"
            "s.listen()\n"
            "time.sleep(30)\n",
            encoding="utf-8",
        )
        sock = os.path.join(tmp, "helper.sock")
        count = os.path.join(tmp, "count")
        code, output = self.run_shell(
            'start_priv_helper; [ -S "$HV_PRIV_HELPER" ] && echo SOCKET_OK; '
            'echo "EXPORTED=$HV_PRIV_HELPER"',
            {"PYTHON": sys.executable, "APP_DIR": tmp, "HV_PRIV_HELPER": sock,
             "COUNT": count},
        )
        self.assertEqual(code, 0, output)
        self.assertIn("SOCKET_OK", output)
        self.assertIn(f"EXPORTED={sock}", output)
        self.assertIn("the privileged helper exited (status 3); restarting in 1 s", output)
        self.assertEqual(Path(count).read_text(), "xx")

    @unittest.skipIf(os.getuid() == 0, "the supervisor test runs as non-root")
    def test_helper_that_never_starts_is_not_fatal(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        Path(tmp, "privhelper.py").write_text("raise SystemExit(1)\n")
        code, output = self.run_shell(
            "start_priv_helper; echo CONTINUED",
            {"PYTHON": sys.executable, "APP_DIR": tmp,
             "HV_PRIV_HELPER": os.path.join(tmp, "helper.sock"),
             "HV_PRIV_HELPER_WAIT": "1"},
        )
        self.assertEqual(code, 0, output)
        self.assertIn("CONTINUED", output)
        self.assertIn("WARNING: the privileged helper socket is not ready", output)


class PackagingTests(unittest.TestCase):
    def test_image_ships_and_points_at_the_helper(self) -> None:
        copy = next(
            line for line in DOCKERFILE.splitlines()
            if line.startswith("COPY ") and "gateway.py" in line
        )
        self.assertIn("privhelper.py", copy.split())
        self.assertIn("HV_PRIV_HELPER=/run/dropjak/helper.sock", DOCKERFILE)
        self.assertEqual(
            gateway.PRIV_HELPER_DEFAULT_SOCKET, "/run/dropjak/helper.sock"
        )

    def test_compose_keeps_net_admin_for_the_helper(self) -> None:
        cap_add = re.search(r"cap_add:\n((?:\s+- \w+\n)+)", COMPOSE).group(1)
        for cap in ("NET_ADMIN", "SETPCAP", "SETUID", "SETGID"):
            self.assertIn(f"- {cap}", cap_add)

    def test_images_are_pinned_by_digest(self) -> None:
        digest = r"@sha256:[0-9a-f]{64}"
        self.assertRegex(DOCKERFILE, r"(?m)^FROM python:3\.12-slim-bookworm" + digest + "$")
        self.assertRegex(AGENT_DOCKERFILE, r"(?m)^FROM python:3\.12-alpine" + digest + "$")
        self.assertRegex(COMPOSE, r"(?m)^\s+image: caddy:2\.10\.2-alpine" + digest + "$")
        example = (ROOT / "deploy" / "tunnel-agent" / "compose.example.yml").read_text()
        self.assertRegex(example, r"image: nginx:alpine" + digest)

    def test_native_portal_unit_has_no_network_admin(self) -> None:
        self.assertNotIn("CAP_NET_ADMIN", PORTAL_UNIT)
        self.assertIn("AmbientCapabilities=__BIND_CAPS__", PORTAL_UNIT)
        self.assertIn("CapabilityBoundingSet=__BIND_CAPS__", PORTAL_UNIT)
        self.assertIn("Environment=HV_PRIV_HELPER=/run/dropjak/helper.sock", PORTAL_UNIT)
        self.assertRegex(PORTAL_UNIT, r"(?m)^After=.*dropjak-helper\.service")
        self.assertRegex(PORTAL_UNIT, r"(?m)^Wants=.*dropjak-helper\.service")
        self.assertNotRegex(PORTAL_UNIT, r"(?m)^Requires=.*dropjak-helper")
        self.assertNotRegex(PORTAL_UNIT, r"(?m)^RuntimeDirectory=")

    def test_native_helper_unit(self) -> None:
        for line in (
            "User=root", "Group=hatarvedelem", "CapabilityBoundingSet=CAP_NET_ADMIN",
            "Restart=always", "RuntimeDirectory=dropjak", "RuntimeDirectoryMode=0750",
            "RuntimeDirectoryPreserve=yes", "NoNewPrivileges=yes",
            "Before=dropjak.service",
        ):
            self.assertRegex(HELPER_UNIT, r"(?m)^" + re.escape(line) + "$")
        self.assertIn("privhelper.py --socket /run/dropjak/helper.sock", HELPER_UNIT)

    def test_installer_renders_and_starts_the_helper(self) -> None:
        self.assertIn('"$SRC_DIR/privhelper.py"', INSTALL)
        self.assertIn("deploy/dropjak-helper.service", INSTALL)
        self.assertIn('-e "s|__BIND_CAPS__|$BIND_CAPS|g"', INSTALL)
        self.assertIn('BIND_CAPS="CAP_NET_BIND_SERVICE"', INSTALL)
        self.assertLess(
            INSTALL.index('systemctl restart "$HELPER_SERVICE"'),
            INSTALL.index('systemctl restart "$SERVICE"'),
        )
        self.assertIn('for unit_name in "$SERVICE" "$HELPER_SERVICE"; do', INSTALL)

    def test_installer_bind_caps(self) -> None:
        start = INSTALL.index('SYNC_PORT="${HV_TUNNEL_SYNC_PORT:-}"')
        snippet = INSTALL[start:INSTALL.index("\nfi\n", INSTALL.index("BIND_CAPS=\"\"", start)) + 4]
        for port, sync, expected in (
            ("80", "", "CAP_NET_BIND_SERVICE"), ("8100", "", ""),
            ("8100", "443", "CAP_NET_BIND_SERVICE"), ("1023", "", "CAP_NET_BIND_SERVICE"),
        ):
            result = subprocess.run(
                ["bash", "-c", f"PORT={port}\n{snippet}\nprintf '%s' \"$BIND_CAPS\""],
                env={"PATH": os.environ.get("PATH", ""), "HV_TUNNEL_SYNC_PORT": sync},
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.stdout, expected, (port, sync, result.stderr))

    def test_uninstall_removes_the_helper_unit(self) -> None:
        text = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn('"dropjak-helper.service"', text)
        self.assertIn("dropjak-helper.service.d", text)


# ------------------------------------------------------------- end to end


@unittest.skipUnless(
    all(shutil.which(tool) for tool in ("unshare", "nft")),
    "unshare/nft not available",
)
class HelperNamespaceTests(unittest.TestCase):
    def test_helper_end_to_end_with_real_nft(self) -> None:
        probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True)
        if probe.returncode != 0:
            self.skipTest("the user namespace is not available")
        result = subprocess.run(
            ["unshare", "-rn", sys.executable,
             str(TESTS / "privhelper_netns.py")],
            capture_output=True, text=True, timeout=240,
        )
        if result.returncode != 0 and not result.stdout.strip():
            if "Operation not permitted" in result.stderr:
                self.skipTest("not permitted in the namespace: " + result.stderr[-200:])
            self.fail(result.stderr[-3000:])
        report = json.loads(result.stdout)
        failed = {
            name: check["detail"] for name, check in report.get("checks", {}).items()
            if not check["ok"]
        }
        self.assertEqual(failed, {}, json.dumps(report, indent=1))
        self.assertTrue(report["ok"], report)


if __name__ == "__main__":
    unittest.main()
