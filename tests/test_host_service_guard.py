#!/usr/bin/env python3
"""Tests for the audit's F5 fix.

F5: the ``host_service_tcp``/``host_service_udp`` add-only guard sets could
previously grow to 4096 elements, and a sync failure was only logged. The fix:

* the set size is 65536, so all up to 65535 valid host ports fit, and a guard
element cannot be lost silently;
* after a sync failure, host (input) authorizations are rejected with 503
  (``FirewallError``), while forward-only authorization keeps working;
* the next host authorization retries the sync once, so a transient nft
error heals by itself;
* after a successful sync a safe cleanup runs: it deletes a port only if no
persisted rule references it and there is no live conntrack entry for it. If
conntrack or the nft listing does not work, no port is deleted.

The tests do not touch real nftables: the health tests use a small fake
firewall, the cleanup tests use the ``test_gateway`` FakeTools helper.
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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import gateway  # noqa: E402
from test_gateway import FakeTools  # noqa: E402

IP = "192.168.50.23"


# ------------------------------------------------------------------ helpers


class RecordingAudit:
    """Replacement that collects audit events in memory."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def write(self, event: str, **fields) -> None:
        self.events.append((event, fields))

    def find(self, name: str) -> list[dict]:
        return [fields for event, fields in self.events if event == name]


class FakeUsers:
    def record(self, name: str):
        return types.SimpleNamespace(enabled=True, pending=False)


class FakeGroups:
    def groups_for(self, name: str):
        return []


class FakeRules:
    """Only the rule store operations used by sync_host_ports()."""

    def __init__(self, rules=()) -> None:
        self._rules = list(rules)

    def persisted_rules(self):
        return list(self._rules)

    def resolve_for(self, record, groups, rule_id):
        for rule in self._rules:
            if rule.id == rule_id:
                return rule
        raise KeyError(rule_id)


class GuardFirewall:
    """Fake firewall for the health/fail-closed tests."""

    def __init__(self) -> None:
        self.fail_sync = False
        self.sync_calls = 0
        self.sync_args: list[tuple[tuple[int, ...], tuple[int, ...]]] = []
        self.grant_calls: list[tuple[str, tuple, int]] = []
        self.revoke_calls: list[tuple] = []
        self.prune_calls: list[tuple] = []

    def sync_host_ports(self, tcp_ports, udp_ports) -> None:
        self.sync_calls += 1
        self.sync_args.append((tuple(tcp_ports), tuple(udp_ports)))
        if self.fail_sync:
            raise gateway.FirewallError("nft sync error")

    def prune_host_service_ports(
        self, referenced_tcp, referenced_udp, audit=None
    ) -> dict:
        self.prune_calls.append(
            (tuple(referenced_tcp), tuple(referenced_udp), audit)
        )
        return {"removed_tcp": [], "removed_udp": []}

    def grant_all(self, ip: str, grants, ttl: int) -> None:
        self.grant_calls.append((ip, tuple(grants), ttl))

    def revoke_all(
        self,
        ip: str,
        grants=(),
        discover: bool = False,
        only_grants: bool = False,
    ) -> None:
        self.revoke_calls.append(
            (ip, tuple(grants), bool(discover), bool(only_grants))
        )


def make_rule(
    rule_id: str,
    tcp=(80,),
    udp=(),
    direction: str = "forward",
    members=(),
    input_tcp=(),
    input_udp=(),
) -> gateway.Rule:
    return gateway.Rule(
        id=rule_id,
        label=rule_id,
        description="",
        tcp=tuple(tcp),
        udp=tuple(udp),
        direction=direction,
        members=tuple(members),
        input_tcp=tuple(input_tcp),
        input_udp=tuple(input_udp),
    )


def build_gateway(rules=(), firewall=None):
    """Gateway with the real SessionManager and fake backend stores."""
    fw = firewall if firewall is not None else GuardFirewall()
    audit = RecordingAudit()
    gw = gateway.Gateway(
        users=FakeUsers(),
        firewall=fw,
        sessions=None,
        rate_limiter=gateway.RateLimiter(window=60, maximum=1000),
        catalog=types.SimpleNamespace(),
        rules=FakeRules(rules),
        groups=FakeGroups(),
        audit=audit,
        settings=types.SimpleNamespace(),
        drops=types.SimpleNamespace(),
        fail2ban=types.SimpleNamespace(
            audit=None, _on_ban=lambda record: None
        ),
    )
    return gw, fw, audit


def login(gw, ip: str = IP):
    return gw.sessions.login("alice", ip)


# ------------------------------------------------------------------ sablon


class TemplateCapacityTests(unittest.TestCase):
    def test_host_service_sets_hold_every_valid_port(self) -> None:
        text = (ROOT / "deploy" / "hatarvedelem.nft").read_text(
            encoding="utf-8"
        )
        for set_name in ("host_service_tcp", "host_service_udp"):
            with self.subTest(set_name=set_name):
                match = re.search(
                    rf"add set inet hatarvedelem {set_name} \{{(.*?)\}}",
                    text,
                    re.S,
                )
                self.assertIsNotNone(match, set_name)
                block = match.group(1)
                self.assertIn("size 65536", block)
                self.assertNotIn("size 4096", block)


# ------------------------------------------------------------------ health


class HostPortHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        # The fake firewall does no conntrack deletion; we disable the global
        # tool so the tests do not call real conntrack.
        patcher = mock.patch.object(gateway, "CONNTRACK_BIN", "")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_sync_failure_marks_unhealthy_and_audits(self) -> None:
        rule = make_rule("host-ssh", tcp=(22,), direction="input")
        gw, fw, audit = build_gateway([rule])
        fw.fail_sync = True

        gw.sync_host_ports()

        self.assertFalse(gw._host_ports_ok)
        self.assertEqual(fw.sync_calls, 1)
        self.assertEqual(fw.prune_calls, [])
        errors = audit.find("firewall_error")
        self.assertTrue(errors)
        self.assertEqual(errors[-1]["operation"], "host_ports")
        self.assertFalse(errors[-1]["healthy"])

    def test_initial_state_without_sync_rejects_host_authorization(self) -> None:
        rule = make_rule("host-ssh", tcp=(22,), direction="input")
        gw, fw, audit = build_gateway([rule])
        fw.fail_sync = True

        # The flag is conservatively false even before any sync runs.
        self.assertFalse(gw._host_ports_ok)
        session = login(gw)
        with self.assertRaises(gateway.FirewallError):
            gw.sessions.authorize(session.token, IP, rule, 60)

        # authorize tried the sync once but did not grant.
        self.assertEqual(fw.sync_calls, 1)
        self.assertEqual(fw.grant_calls, [])
        self.assertFalse(gw._host_ports_ok)

    def test_forward_only_authorization_works_while_unhealthy(self) -> None:
        forward = make_rule("web", tcp=(80,))
        gw, fw, audit = build_gateway([forward])
        fw.fail_sync = True
        gw.sync_host_ports()
        self.assertFalse(gw._host_ports_ok)

        session = login(gw)
        authorized = gw.sessions.authorize(session.token, IP, forward, 60)

        self.assertTrue(authorized.authorized)
        self.assertEqual(len(fw.grant_calls), 1)
        # Forward authorization does not call the port guard callback.
        self.assertEqual(fw.sync_calls, 1)

    def test_next_host_authorization_retries_once_and_heals(self) -> None:
        rule = make_rule("host-ssh", tcp=(22,), direction="input")
        gw, fw, audit = build_gateway([rule])
        fw.fail_sync = True
        gw.sync_host_ports()
        self.assertFalse(gw._host_ports_ok)
        self.assertEqual(fw.sync_calls, 1)

        # The error is gone: the next host authorization starts exactly one
        # retry, and after that grants successfully.
        fw.fail_sync = False
        session = login(gw)
        authorized = gw.sessions.authorize(session.token, IP, rule, 60)

        self.assertTrue(authorized.authorized)
        self.assertTrue(gw._host_ports_ok)
        self.assertEqual(fw.sync_calls, 2)
        self.assertEqual(len(fw.grant_calls), 1)
        self.assertEqual(len(fw.prune_calls), 1)
        self.assertIn(22, fw.prune_calls[0][0])
        self.assertIn(22, fw.sync_args[-1][0])

        # In a healthy state there is no further retry.
        gw.sessions.authorize(session.token, IP, rule, 60)
        self.assertEqual(fw.sync_calls, 2)

    def test_mixed_direction_collection_is_rejected_while_unhealthy(self) -> None:
        mixed = make_rule(
            "mixed",
            tcp=(80,),
            members=("member",),
            input_tcp=(22,),
        )
        self.assertTrue(
            any(part.direction == "input" for part in mixed.grants)
        )
        gw, fw, audit = build_gateway([mixed])
        fw.fail_sync = True

        session = login(gw)
        with self.assertRaises(gateway.FirewallError):
            gw.sessions.authorize(session.token, IP, mixed, 60)

        self.assertEqual(fw.grant_calls, [])
        self.assertFalse(gw._host_ports_ok)

    def test_gateway_wires_guard_callback(self) -> None:
        gw, fw, audit = build_gateway([make_rule("web", tcp=(80,))])
        self.assertIsNotNone(gw.sessions.guard_check)
        self.assertTrue(callable(gw.sessions.guard_check))

    def test_prune_references_every_rule_part(self) -> None:
        collection = make_rule(
            "col",
            tcp=(80,),
            members=("member",),
            input_tcp=(25566,),
            input_udp=(25566,),
        )
        gw, fw, audit = build_gateway([collection])

        gw.sync_host_ports()

        self.assertTrue(gw._host_ports_ok)
        # Only the input member's ports go into the sync...
        self.assertEqual(fw.sync_args[-1], ((25566,), (25566,)))
        # ...but the cleanup's reference list protects every rule part's port:
        # even port 80 of the collection's forward member cannot be deleted.
        self.assertEqual(len(fw.prune_calls), 1)
        referenced_tcp, referenced_udp, _audit = fw.prune_calls[0]
        self.assertEqual(referenced_tcp, (80, 25566))
        self.assertEqual(referenced_udp, (25566,))


# ------------------------------------------------------------------ cleanup


class HostServicePruneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tools = FakeTools(self.tmp.name)
        self._old_conntrack = gateway.CONNTRACK_BIN
        self.addCleanup(
            setattr, gateway, "CONNTRACK_BIN", self._old_conntrack
        )
        # No conntrack by default: in that case cleanup may not delete.
        gateway.CONNTRACK_BIN = ""
        self.fw = gateway.Firewall(
            binary=str(self.tools.nft), logger=lambda *_: None
        )

    def set_conntrack(self, lines=()) -> None:
        """Set up a script imitating the output of conntrack -L."""
        body = "".join(
            f"printf '%s\\n' {self._shell_quote(line)}\n" for line in lines
        )
        path = self.tools.conntrack
        path.write_text("#!/bin/sh\n" + body + "exit 0\n", encoding="utf-8")
        path.chmod(0o755)
        gateway.CONNTRACK_BIN = str(path)

    @staticmethod
    def _shell_quote(text: str) -> str:
        return "'" + text.replace("'", "'\\''") + "'"

    def delete_scripts(self) -> list[str]:
        return [
            line for line in self.tools.script()
            if line.startswith("delete element")
        ]

    def test_unreferenced_and_not_live_ports_are_removed(self) -> None:
        self.tools.set_json("host_service_tcp", [80, 443, 8080])
        self.tools.set_json("host_service_udp", [53, 5353])
        self.set_conntrack()
        self.tools.clear()

        summary = self.fw.prune_host_service_ports({443}, {53})

        self.assertEqual(summary["removed_tcp"], [80, 8080])
        self.assertEqual(summary["removed_udp"], [5353])
        deletes = self.delete_scripts()
        self.assertTrue(
            any(
                "host_service_tcp { 80, 8080 }" in line
                for line in deletes
            ),
            deletes,
        )
        self.assertTrue(
            any("host_service_udp { 5353 }" in line for line in deletes),
            deletes,
        )
        # No deletion touches the referenced port.
        self.assertFalse(any(" 443" in line for line in deletes), deletes)
        self.assertFalse(any(" 53 " in line for line in deletes), deletes)

    def test_referenced_port_is_kept(self) -> None:
        self.tools.set_json("host_service_tcp", [22, 25566])
        self.set_conntrack()
        self.tools.clear()

        summary = self.fw.prune_host_service_ports({22, 25566}, set())

        self.assertEqual(summary["removed_tcp"], [])
        self.assertEqual(self.delete_scripts(), [])

    def test_live_conntrack_port_is_kept(self) -> None:
        self.tools.set_json("host_service_tcp", [22, 80, 8080])
        self.set_conntrack([
            "tcp 6 300 ESTABLISHED src=192.168.50.23 dst=192.168.50.1 "
            "sport=40000 dport=80 src=192.168.50.1 dst=192.168.50.23 "
            "sport=80 dport=40000 [ASSURED] mark=0 use=1"
        ])
        self.tools.clear()

        summary = self.fw.prune_host_service_ports({22}, set())

        # 80 appears in a live connection (dport), so it remains; 8080 is
        # neither referenced nor live, so it is deleted.
        self.assertEqual(summary["removed_tcp"], [8080])
        self.assertEqual(summary["live_kept"], [80])
        self.assertFalse(any(" 80," in line for line in self.delete_scripts()))

    def test_conntrack_unavailable_removes_nothing(self) -> None:
        self.tools.set_json("host_service_tcp", [8080])
        self.tools.clear()
        gateway.CONNTRACK_BIN = ""

        summary = self.fw.prune_host_service_ports(set(), set())

        self.assertEqual(summary["removed_tcp"], [])
        self.assertEqual(self.delete_scripts(), [])

    def test_conntrack_failure_is_logged_once(self) -> None:
        self.tools.set_json("host_service_tcp", [8080])
        messages: list[str] = []
        fw = gateway.Firewall(
            binary=str(self.tools.nft), logger=messages.append
        )
        gateway.CONNTRACK_BIN = ""

        fw.prune_host_service_ports(set(), set())
        fw.prune_host_service_ports(set(), set())

        warnings = [
            message for message in messages
            if "host port pruning skipped" in message
        ]
        self.assertEqual(len(warnings), 1, messages)

    def test_nft_listing_failure_removes_nothing_and_does_not_raise(self) -> None:
        def failing_run(args, check=True, **_kwargs):
            return subprocess.CompletedProcess(
                [str(self.tools.nft), *args],
                1,
                b"",
                b"Operation not permitted",
            )

        self.tools.clear()
        with mock.patch.object(self.fw, "_run", side_effect=failing_run):
            summary = self.fw.prune_host_service_ports({80}, {53})

        self.assertTrue(summary["errors"])
        self.assertEqual(self.delete_scripts(), [])

    def test_nft_binary_failure_does_not_raise(self) -> None:
        self.tools.clear()
        with mock.patch.object(
            self.fw,
            "_run",
            side_effect=gateway.FirewallError("nft not found"),
        ):
            summary = self.fw.prune_host_service_ports({80}, {53})

        self.assertTrue(summary["errors"])
        self.assertEqual(self.delete_scripts(), [])

    def test_missing_set_is_treated_as_empty(self) -> None:
        # FakeTools returns empty nftables JSON by default: nothing to delete.
        self.set_conntrack()
        self.tools.clear()

        summary = self.fw.prune_host_service_ports(set(), set())

        self.assertEqual(summary["removed_tcp"], [])
        self.assertEqual(summary["removed_udp"], [])
        self.assertEqual(self.delete_scripts(), [])

    def test_parse_service_set_json_accepts_plain_and_wrapped_values(self) -> None:
        payload = (
            '{"nftables": [{"set": {"name": "host_service_tcp", '
            '"elem": [22, {"elem": 80}, {"elem": {"val": 443}}, '
            '"not-a-number", 70000, true]}}]}'
        )
        self.assertEqual(
            gateway.Firewall.parse_service_set_json(
                payload, "host_service_tcp"
            ),
            {22, 80, 443},
        )


if __name__ == "__main__":
    unittest.main()
