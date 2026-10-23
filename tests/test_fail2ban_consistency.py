#!/usr/bin/env python3
"""Tests for fail2ban's F9 consistency fixes.

F9 covers three bugs:

* eviction (``MAX_BANS``) previously only removed the oldest ban from memory,
  the kernel element lived until the TTL;
* ``sync()`` raised the remaining time to at least 60 seconds;
* a partial failure of ``configure()`` could leave an intermediate state, and
  the save rollback could lose the in-memory record.

The tests do not touch real nftables: the fake firewall logs the calls and
imitates the ``banned_v4`` set with a dictionary. The audit is replaced by a
tiny recorder, so the test does not depend on the gateway module.

Run from the project root:

    python3 -m unittest discover -s tests -p 'test_fail2ban*.py' -v
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import fail2ban as fail2ban_mod  # noqa: E402


# ------------------------------------------------------------------ helpers


class FakeFail2banFirewall:
    """The fake firewall of the fail2ban tests.

    The ``ban_fail`` and ``unban_fail`` predicates decide on failure by
    address (and, for a ban, by TTL). The ``kernel`` dictionary imitates the
    contents of the ``banned_v4`` set so that the effect of eviction and sync
    can be checked.
    """

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.kernel: dict[str, int] = {}
        self.ban_fail = lambda ip, ttl: False
        self.unban_fail = lambda ip: False
        self.sync_fail = False

    def ban(self, ip: str, ttl: int) -> None:
        self.calls.append(("ban", ip, ttl))
        if self.ban_fail(ip, ttl):
            raise RuntimeError("nft ban error")
        self.kernel[ip] = ttl

    def unban(self, ip: str) -> None:
        self.calls.append(("unban", ip))
        if self.unban_fail(ip):
            raise RuntimeError("nft unban error")
        # Deleting a missing element is not an error, just like with the real Firewall.
        self.kernel.pop(ip, None)

    def sync_bans(self, elements) -> None:
        elements = list(elements)
        self.calls.append(("sync", elements))
        if self.sync_fail:
            raise RuntimeError("nft sync error")
        self.kernel = dict(elements)

    def sync_proxy_bans(self, elements) -> None:
        self.proxy_kernel = dict(elements)


class RecordingAudit:
    """Replacement that collects audit events in memory."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def write(self, event: str, **fields) -> None:
        self.events.append((event, fields))

    def find(self, name: str) -> list[dict]:
        return [fields for event, fields in self.events if event == name]


class Fail2banConsistencyBase(unittest.TestCase):
    LIMIT = 120

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "fail2ban.json")
        self.fw = FakeFail2banFirewall()
        self.audit = RecordingAudit()
        self.manager = self.make_manager()

    def make_manager(self, **kwargs):
        options = {
            "enabled": True,
            "max_attempts": 3,
            "window_seconds": 60,
            "ban_seconds": self.LIMIT,
            "drop_enabled": True,
            "drop_max": 5,
            "drop_ports": 4,
            "drop_window_seconds": 60,
        }
        options.update(kwargs)
        return fail2ban_mod.Fail2ban(
            self.fw,
            path=self.path,
            audit=self.audit,
            logger=lambda *_: None,
            **options,
        )


# -------------------------------------------------------------- eviction


class EvictionTests(Fail2banConsistencyBase):
    def test_eviction_releases_kernel_element_and_audits(self) -> None:
        with mock.patch.object(fail2ban_mod, "MAX_BANS", 2):
            self.manager.ban("192.0.2.1", 600, manual=True)
            self.manager.ban("192.0.2.2", 600, manual=True)
            self.manager.ban("192.0.2.3", 600, manual=True)

        # The oldest kernel element was released too, not just memory.
        self.assertNotIn("192.0.2.1", self.fw.kernel)
        self.assertIn("192.0.2.3", self.fw.kernel)
        self.assertIn(("unban", "192.0.2.1"), self.fw.calls)
        self.assertIsNone(self.manager.banned("192.0.2.1"))
        self.assertIsNotNone(self.manager.banned("192.0.2.3"))

        evicted = self.audit.find("fail2ban_ban_evicted")
        self.assertEqual(len(evicted), 1)
        self.assertEqual(evicted[0]["ip"], "192.0.2.1")
        self.assertEqual(evicted[0]["reason"], "max_bans")
        self.assertTrue(evicted[0]["kernel_released"])
        self.assertEqual(self.audit.find("fail2ban_ban_evict_failed"), [])

    def test_eviction_unban_failure_is_queued_and_retried(self) -> None:
        with mock.patch.object(fail2ban_mod, "MAX_BANS", 2):
            self.manager.ban("192.0.2.11", 600, manual=True)
            self.manager.ban("192.0.2.12", 600, manual=True)
            self.fw.unban_fail = lambda ip: ip == "192.0.2.11"
            view = self.manager.ban("192.0.2.13", 600, manual=True)

        # The new protective ban was created despite the release failure.
        self.assertEqual(view["ip"], "192.0.2.13")
        self.assertIn("192.0.2.13", self.fw.kernel)
        self.assertIn("192.0.2.11", self.fw.kernel)
        self.assertEqual(self.manager._orphan_unbans, ["192.0.2.11"])

        evicted = self.audit.find("fail2ban_ban_evicted")
        self.assertEqual(evicted[-1]["ip"], "192.0.2.11")
        self.assertFalse(evicted[-1]["kernel_released"])
        failed = self.audit.find("fail2ban_ban_evict_failed")
        self.assertEqual(failed[-1]["ip"], "192.0.2.11")
        self.assertTrue(failed[-1]["queued"])

        # Once the error is gone, the next snapshot clears the queue.
        self.fw.unban_fail = lambda ip: False
        self.manager.snapshot()
        self.assertEqual(self.manager._orphan_unbans, [])
        self.assertNotIn("192.0.2.11", self.fw.kernel)
        self.assertIn(("unban", "192.0.2.11"), self.fw.calls)

    def test_orphan_queue_is_bounded(self) -> None:
        with mock.patch.object(fail2ban_mod, "MAX_BANS", 1), \
                mock.patch.object(fail2ban_mod, "MAX_ORPHAN_UNBANS", 2):
            self.fw.unban_fail = lambda ip: True
            self.manager.ban("192.0.2.21", 600, manual=True)
            for last_octet in range(22, 27):
                self.manager.ban(
                    f"192.0.2.{last_octet}", 600, manual=True
                )

        self.assertEqual(len(self.manager._orphan_unbans), 2)
        failed = self.audit.find("fail2ban_ban_evict_failed")
        self.assertTrue(any(row.get("queued") is False for row in failed))


# ------------------------------------------------------------------ sync


class SyncTtlTests(Fail2banConsistencyBase):
    def test_sync_keeps_exact_remaining_ttl_and_drops_expired(self) -> None:
        self.manager.ban("192.0.2.31", 600, manual=True)
        self.manager.ban("192.0.2.32", 600, manual=True)
        self.manager.ban("192.0.2.33", 600, manual=True)
        self.fw.calls.clear()

        with mock.patch.object(
            fail2ban_mod.time, "time", return_value=1000.0
        ):
            self.manager._bans["192.0.2.31"]["until"] = 1005.0
            self.manager._bans["192.0.2.32"]["until"] = 999.0
            self.manager._bans["192.0.2.33"]["until"] = 1000.0
            self.assertTrue(self.manager.sync())

        sync_calls = [call for call in self.fw.calls if call[0] == "sync"]
        self.assertEqual(len(sync_calls), 1)
        # 5 seconds remained: exactly 5 goes into the kernel, not MIN_BAN.
        self.assertEqual(sync_calls[0][1], [("192.0.2.31", 5)])
        self.assertEqual(self.fw.kernel, {"192.0.2.31": 5})
        self.assertNotIn("192.0.2.32", self.manager._bans)
        self.assertNotIn("192.0.2.33", self.manager._bans)

    def test_successful_sync_clears_orphan_queue(self) -> None:
        with mock.patch.object(fail2ban_mod, "MAX_BANS", 1):
            self.manager.ban("192.0.2.71", 600, manual=True)
            self.fw.unban_fail = lambda ip: True
            self.manager.ban("192.0.2.72", 600, manual=True)

        self.assertEqual(self.manager._orphan_unbans, ["192.0.2.71"])
        # sync_bans() empties the whole set, so the orphan element disappears.
        self.assertTrue(self.manager.sync())
        self.assertEqual(self.manager._orphan_unbans, [])
        self.assertEqual(set(self.fw.kernel), {"192.0.2.72"})


# ------------------------------------------------------------- configure


class ConfigureAtomicityTests(Fail2banConsistencyBase):
    def test_partial_unban_failure_restores_released_ban(self) -> None:
        self.manager.ban("192.0.2.41", 600, manual=False)
        self.manager.ban("192.0.2.42", 600, manual=False)
        self.fw.calls.clear()

        with mock.patch.object(
            fail2ban_mod.time, "time", return_value=2000.0
        ):
            self.manager._bans["192.0.2.41"]["until"] = 2007.0
            self.manager._bans["192.0.2.42"]["until"] = 2009.0
            self.fw.unban_fail = lambda ip: ip == "192.0.2.42"
            with self.assertRaises(fail2ban_mod.Fail2banError) as caught:
                self.manager.configure({"enabled": False})

        # The error message names the number of failed addresses.
        self.assertIn("1 addresses", str(caught.exception))
        # The configuration remained unchanged.
        self.assertTrue(self.manager._config["enabled"])
        with open(self.path, encoding="utf-8") as fh:
            self.assertTrue(json.load(fh)["config"]["enabled"])
        # Both records remained in memory.
        self.assertEqual(
            set(self.manager._bans), {"192.0.2.41", "192.0.2.42"}
        )
        # The successfully released ban came back with the exact remaining
        # time (7 s), not with MIN_BAN.
        self.assertIn(("ban", "192.0.2.41", 7), self.fw.calls)
        self.assertNotIn(("ban", "192.0.2.42", 9), self.fw.calls)
        self.assertEqual(self.fw.kernel.get("192.0.2.41"), 7)
        # Because of the release failure the second element remained in the kernel.
        self.assertIn("192.0.2.42", self.fw.kernel)

        failed = self.audit.find("fail2ban_bans_release_failed")
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["count"], 1)

    def test_save_failure_restores_memory_even_if_reban_fails(self) -> None:
        self.manager.ban("192.0.2.51", 600, manual=False)
        self.fw.calls.clear()
        self.fw.ban_fail = lambda ip, ttl: ip == "192.0.2.51"

        def broken_save(raise_errors: bool = False) -> bool:
            if raise_errors:
                raise fail2ban_mod.Fail2banError("save error")
            return True

        with mock.patch.object(
            self.manager, "_save_locked", side_effect=broken_save
        ):
            with mock.patch.object(
                fail2ban_mod.time, "time", return_value=3000.0
            ):
                self.manager._bans["192.0.2.51"]["until"] = 3009.0
                with self.assertRaises(fail2ban_mod.Fail2banError):
                    self.manager.configure({"enabled": False})

        # Despite the kernel restore failure the in-memory record remains.
        self.assertIn("192.0.2.51", self.manager._bans)
        self.assertEqual(
            self.manager._bans["192.0.2.51"]["until"], 3009.0
        )
        self.assertTrue(self.manager._config["enabled"])
        # The rollback tried to put it back with the exact remaining time.
        self.assertIn(("ban", "192.0.2.51", 9), self.fw.calls)
        self.assertTrue(self.manager._error)
        restored = self.audit.find("fail2ban_ban_restore_failed")
        self.assertEqual(restored[-1]["ip"], "192.0.2.51")

    def test_successful_release_keeps_original_behaviour(self) -> None:
        self.manager.ban("192.0.2.61", 600, manual=False)
        self.manager.ban("192.0.2.62", 600, manual=True)
        self.fw.calls.clear()

        snapshot = self.manager.configure({"enabled": False})

        self.assertFalse(snapshot["enabled"])
        self.assertEqual(
            [row["ip"] for row in snapshot["bans"]], ["192.0.2.62"]
        )
        self.assertIn(("unban", "192.0.2.61"), self.fw.calls)
        self.assertNotIn("192.0.2.61", self.fw.kernel)
        released = self.audit.find("fail2ban_bans_released")
        self.assertEqual(released[-1]["count"], 1)
        self.assertEqual(released[-1]["reason"], "disabled")
        with open(self.path, encoding="utf-8") as fh:
            payload = json.load(fh)
        self.assertFalse(payload["config"]["enabled"])
        self.assertEqual(
            [row["ip"] for row in payload["bans"]], ["192.0.2.62"]
        )


if __name__ == "__main__":
    unittest.main()
