#!/usr/bin/env python3
"""Drop-signal allowlist and the direction-aware ban rule.

A dropped first packet has an unverified source address. The tests check
that allowlisted infrastructure is never banned on drop signals, that the
allowlist is admin-editable and persisted, and that the ban rules of the
template drop only the original direction, so replies from a banned remote
host still reach the clients that opened the connection.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import fail2ban as fail2ban_mod  # noqa: E402


class FakeFirewall:
    def __init__(self) -> None:
        self.kernel: dict[str, int] = {}

    def ban(self, ip: str, ttl: int) -> None:
        self.kernel[ip] = ttl

    def unban(self, ip: str) -> None:
        self.kernel.pop(ip, None)

    def sync_bans(self, elements) -> None:
        self.kernel = dict(elements)


class DropExemptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "fail2ban.json")
        self.fw = FakeFirewall()
        # The test host's environment must not leak into the built-in list.
        patcher = mock.patch.dict(
            os.environ,
            {"HV_MGMT_NET": "", "HV_FAIL2BAN_DROP_EXEMPT": ""},
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def make_manager(self, **kwargs):
        options = {
            "max_attempts": 3,
            "window_seconds": 60,
            "ban_seconds": 120,
            "drop_count_enabled": True,
            "drop_ports_enabled": True,
            "drop_max": 5,
            "drop_ports": 4,
            "drop_window_seconds": 60,
        }
        options.update(kwargs)
        return fail2ban_mod.Fail2ban(
            self.fw, path=self.path, logger=lambda *_: None, **options
        )

    def scan(self, manager, ip: str, ports: int = 12) -> None:
        for port in range(1, ports + 1):
            manager.record_drop(
                ip, proto="tcp", dport=1000 + port, reason="input-wan"
            )

    def test_drop_signal_never_bans_admin_listed_address(self) -> None:
        manager = self.make_manager()
        manager.configure({"drop_exempt": ["198.51.100.0/24", "203.0.113.9"]})
        self.scan(manager, "198.51.100.77")
        self.scan(manager, "203.0.113.9")
        self.assertEqual(self.fw.kernel, {})
        self.assertIsNone(manager.banned("198.51.100.77"))
        self.assertEqual(manager.snapshot()["drop_pending"], [])
        # A neighbour outside the list is still banned as before.
        self.scan(manager, "203.0.113.10")
        self.assertIn("203.0.113.10", self.fw.kernel)

    def test_builtin_exempt_from_environment_and_caller(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "HV_MGMT_NET": "192.0.2.0/28",
                "HV_FAIL2BAN_DROP_EXEMPT": "198.51.100.53, not-an-ip,",
            },
        ):
            manager = self.make_manager(exempt=["203.0.113.1"])
        for ip in ("192.0.2.5", "198.51.100.53", "203.0.113.1"):
            self.scan(manager, ip)
        self.assertEqual(self.fw.kernel, {})
        builtin = manager.snapshot()["drop_exempt_builtin"]
        self.assertEqual(
            builtin, ["192.0.2.0/28", "198.51.100.53/32", "203.0.113.1/32"]
        )
        # The admin cannot remove the built-in entries.
        manager.configure({"drop_exempt": []})
        self.scan(manager, "192.0.2.5")
        self.assertEqual(self.fw.kernel, {})

    def test_allowlist_covers_drop_signals_only(self) -> None:
        manager = self.make_manager(exempt=["203.0.113.1"])
        # A failed login needs a completed handshake: it still bans.
        for _ in range(3):
            manager.record_failure("203.0.113.1", "admin")
        self.assertIn("203.0.113.1", self.fw.kernel)
        # A manual ban is the admin's decision and is not blocked either.
        manager.ban("203.0.113.2", 600)
        manager.configure({"drop_exempt": ["203.0.113.2"]})
        self.assertIsNotNone(manager.banned("203.0.113.2"))

    def test_new_entry_clears_pending_counter(self) -> None:
        manager = self.make_manager()
        self.scan(manager, "198.51.100.8", ports=3)
        self.assertEqual(len(manager.snapshot()["drop_pending"]), 1)
        manager.configure({"drop_exempt": ["198.51.100.8"]})
        self.assertEqual(manager.snapshot()["drop_pending"], [])
        self.scan(manager, "198.51.100.8", ports=1)
        self.assertEqual(self.fw.kernel, {})

    def test_allowlist_is_validated_canonical_and_persisted(self) -> None:
        manager = self.make_manager()
        for bad in (
            "198.51.100.0/24",
            ["2001:db8::/32"],
            ["300.1.1.1"],
            [7],
            [f"10.0.{n}.0/24" for n in range(65)],
        ):
            with self.subTest(value=bad):
                with self.assertRaises(fail2ban_mod.Fail2banError):
                    manager.configure({"drop_exempt": bad})
        self.assertEqual(manager.snapshot()["drop_exempt"], [])
        snapshot = manager.configure(
            {"drop_exempt": ["198.51.100.7/24", "198.51.100.0/24", "192.0.2.1"]}
        )
        self.assertEqual(
            snapshot["drop_exempt"], ["198.51.100.0/24", "192.0.2.1/32"]
        )
        with open(self.path, encoding="utf-8") as fh:
            saved = json.load(fh)["config"]["drop_exempt"]
        self.assertEqual(saved, ["198.51.100.0/24", "192.0.2.1/32"])
        reloaded = self.make_manager()
        self.scan(reloaded, "198.51.100.200")
        self.assertEqual(self.fw.kernel, {})

    def test_old_state_file_without_allowlist_loads(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(
                {"version": 1, "config": {"drop_max": 7}, "bans": []}, fh
            )
        manager = self.make_manager()
        snapshot = manager.snapshot()
        self.assertEqual(snapshot["drop_max"], 7)
        self.assertEqual(snapshot["drop_exempt"], [])


class InfraExemptAddressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        import gateway

        self.gateway = gateway

    def write(self, name: str, text: str) -> str:
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_resolvers_and_default_gateway_are_exempt(self) -> None:
        resolv = self.write(
            "resolv.conf",
            "# comment\nnameserver 198.51.100.53\nnameserver 127.0.0.53\n"
            "nameserver 2001:db8::53\nsearch example\n",
        )
        gateway_hex = (
            (203 | 0 << 8 | 113 << 16 | 1 << 24)
            if sys.byteorder == "little"
            else (203 << 24 | 0 << 16 | 113 << 8 | 1)
        )
        route = self.write(
            "route",
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            f"eth0\t00000000\t{gateway_hex:08X}\t0003\t0\t0\t0\t00000000\n"
            "eth0\t007100CB\t00000000\t0001\t0\t0\t0\t00FFFFFF\n",
        )
        self.assertEqual(
            self.gateway.infra_exempt_addresses(resolv, route),
            ["198.51.100.53", "203.0.113.1"],
        )

    def test_missing_files_give_empty_list(self) -> None:
        missing = os.path.join(self.tmp.name, "missing")
        self.assertEqual(
            self.gateway.infra_exempt_addresses(missing, missing), []
        )


class DirectionAwareBanRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (ROOT / "deploy" / "dropjak.nft").read_text(
            encoding="utf-8"
        )

    def test_every_ban_rule_matches_original_direction_only(self) -> None:
        rules = [
            line.strip() for line in self.text.splitlines()
            if re.match(r"\s*ip saddr @banned_v4\b", line)
        ]
        # forward and input: one log rule and one drop rule each.
        self.assertEqual(len(rules), 4)
        for rule in rules:
            self.assertTrue(
                rule.startswith("ip saddr @banned_v4 ct direction original "),
                rule,
            )


if __name__ == "__main__":
    unittest.main()
