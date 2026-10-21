#!/usr/bin/env python3
"""A fail2ban F9 konzisztencia-javításainak tesztjei.

F9 három hibát fed le:

* az eviction (``MAX_BANS``) eddig csak a memóriából dobta ki a legrégebbi
  tiltást, a kernel-elem a TTL-ig élt;
* a ``sync()`` a hátralévő időt legalább 60 másodpercre emelte;
* a ``configure()`` részleges hibája köztes állapotot hagyhatott, és a
  mentési rollback elveszíthette a memóriarekordot.

A tesztek nem nyúlnak valódi nftables-hez: a hamis tűzfal a hívásokat
naplózza, és a ``banned_v4`` halmazt egy szótárral utánozza. Az auditot
egy apró rekorder helyettesíti, így a teszt nem függ a gateway modultól.

Futtatás a projekt gyökeréből:

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


# ------------------------------------------------------------------ segédek


class FakeFail2banFirewall:
    """A fail2ban tesztek hamis tűzfala.

    A ``ban_fail`` és ``unban_fail`` predikátumok cím (és ban esetén TTL)
    alapján döntenek a hibáról. A ``kernel`` szótár a ``banned_v4`` halmaz
    tartalmát utánozza, hogy az eviction és a sync hatása ellenőrizhető
    legyen.
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
            raise RuntimeError("nft ban hiba")
        self.kernel[ip] = ttl

    def unban(self, ip: str) -> None:
        self.calls.append(("unban", ip))
        if self.unban_fail(ip):
            raise RuntimeError("nft unban hiba")
        # A hiányzó elem törlése nem hiba, ahogy a valódi Firewallnál sem.
        self.kernel.pop(ip, None)

    def sync_bans(self, elements) -> None:
        elements = list(elements)
        self.calls.append(("sync", elements))
        if self.sync_fail:
            raise RuntimeError("nft sync hiba")
        self.kernel = dict(elements)


class RecordingAudit:
    """Az audit-eseményeket memóriában gyűjtő helyettesítő."""

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

        # A legrégebbi kernel-elem is felszabadult, nem csak a memória.
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

        # Az új védő tiltás a feloldási hiba ellenére is létrejött.
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

        # A hiba megszűnte után a következő snapshot kitisztítja a sort.
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
        # 5 másodperc maradt: pontosan 5 kerül a kernelbe, nem MIN_BAN.
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
        # A sync_bans() az egész halmazt üríti, ezért az árva elem eltűnik.
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

        # A hibaüzenet a sikertelen címek számát nevezi meg.
        self.assertIn("1 cím", str(caught.exception))
        # A konfiguráció változatlan maradt.
        self.assertTrue(self.manager._config["enabled"])
        with open(self.path, encoding="utf-8") as fh:
            self.assertTrue(json.load(fh)["config"]["enabled"])
        # Mindkét rekord a memóriában maradt.
        self.assertEqual(
            set(self.manager._bans), {"192.0.2.41", "192.0.2.42"}
        )
        # A sikeresen felszabadított tiltás pontos hátralévő idővel jött
        # vissza (7 mp), nem MIN_BAN-nal.
        self.assertIn(("ban", "192.0.2.41", 7), self.fw.calls)
        self.assertNotIn(("ban", "192.0.2.42", 9), self.fw.calls)
        self.assertEqual(self.fw.kernel.get("192.0.2.41"), 7)
        # A feloldási hiba miatt a második elem a kernelben maradt.
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
                raise fail2ban_mod.Fail2banError("mentési hiba")
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

        # A kernel-visszaállítás hibája ellenére a memóriarekord megmarad.
        self.assertIn("192.0.2.51", self.manager._bans)
        self.assertEqual(
            self.manager._bans["192.0.2.51"]["until"], 3009.0
        )
        self.assertTrue(self.manager._config["enabled"])
        # A rollback a pontos hátralévő idővel próbálta visszatenni.
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
