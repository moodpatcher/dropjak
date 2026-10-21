#!/usr/bin/env python3
"""A fail2ban három figyelt jelzésének független kapcsolása.

A tesztek a ``Fail2ban`` osztályt hamis tűzfallal hajtják, így nem nyúlnak
valódi nftables-hez. A fókusz a ``enabled`` / ``drop_count_enabled`` /
``drop_ports_enabled`` kapcsolókon, a küszöbök érvényességén és a
kapcsolókhoz tartozó tiltás-felszabadításon van.
"""

from __future__ import annotations

import importlib
import inspect
import json
import os
import stat
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
        self.calls: list[tuple] = []
        self.kernel: dict[str, int] = {}

    def ban(self, ip: str, ttl: int) -> None:
        self.calls.append(("ban", ip, ttl))
        self.kernel[ip] = ttl

    def unban(self, ip: str) -> None:
        self.calls.append(("unban", ip))
        self.kernel.pop(ip, None)

    def sync_bans(self, elements) -> None:
        elements = list(elements)
        self.calls.append(("sync", elements))
        self.kernel = dict(elements)


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def write(self, event: str, **fields) -> None:
        self.events.append((event, fields))

    def named(self, event: str) -> list[dict]:
        return [fields for name, fields in self.events if name == event]


class DropMetricTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "fail2ban.json")
        self.fw = FakeFirewall()

    def make_manager(self, **kwargs):
        options = {
            "enabled": True,
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

    def write_state(self, config: dict) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "config": config, "bans": []}, fh)

    def ban_calls(self) -> list[tuple]:
        return [call for call in self.fw.calls if call[0] == "ban"]

    def unban_calls(self) -> list[tuple]:
        return [call for call in self.fw.calls if call[0] == "unban"]

    def test_zero_thresholds_are_rejected_and_state_unchanged(self) -> None:
        manager = self.make_manager(drop_max=7, drop_ports=9)
        before = manager.snapshot()
        for payload in (
            {"drop_max": 0},
            {"drop_ports": 0},
            {"drop_max": 0, "drop_count_enabled": False},
            {"drop_ports": 0, "drop_ports_enabled": False},
        ):
            with self.subTest(payload=payload), self.assertRaises(
                fail2ban_mod.Fail2banError
            ):
                manager.configure(payload)
        after = manager.snapshot()
        for key in (
            "enabled", "drop_enabled", "drop_count_enabled",
            "drop_ports_enabled", "drop_max", "drop_ports",
            "drop_window_seconds", "drop_count_active", "drop_ports_active",
        ):
            self.assertEqual(after[key], before[key], key)

    def test_legacy_zero_thresholds_migrate_without_wiping_settings(self) -> None:
        self.write_state({
            "enabled": True,
            "max_attempts": 7,
            "window_seconds": 120,
            "ban_seconds": 300,
            "drop_enabled": True,
            "drop_count_enabled": True,
            "drop_ports_enabled": True,
            "drop_max": 0,
            "drop_ports": 0,
            "drop_window_seconds": 90,
        })
        manager = self.make_manager()
        snapshot = manager.snapshot()
        # A 0 küszöb csak az adott mérőszámot kapcsolja ki, és a küszöb
        # az alapértékre áll vissza; a többi mentett beállítás megmarad.
        self.assertEqual(snapshot["max_attempts"], 7)
        self.assertEqual(snapshot["window_seconds"], 120)
        self.assertEqual(snapshot["ban_seconds"], 300)
        self.assertEqual(snapshot["drop_window_seconds"], 90)
        self.assertEqual(
            snapshot["drop_max"], fail2ban_mod.DEFAULT_DROP_MAX
        )
        self.assertEqual(
            snapshot["drop_ports"], fail2ban_mod.DEFAULT_DROP_PORTS
        )
        self.assertFalse(snapshot["drop_count_enabled"])
        self.assertFalse(snapshot["drop_ports_enabled"])
        self.assertFalse(snapshot["drop_count_active"])
        self.assertFalse(snapshot["drop_ports_active"])
        self.assertFalse(snapshot["drop_enabled"])

    def test_legacy_zero_drop_max_keeps_port_metric(self) -> None:
        self.write_state({
            "enabled": True,
            "drop_count_enabled": True,
            "drop_ports_enabled": True,
            "drop_max": 0,
            "drop_ports": 7,
            "drop_window_seconds": 90,
        })
        manager = self.make_manager()
        snapshot = manager.snapshot()
        # Csak a csomagszám-mérőszám kapcsol ki; a portküszöb megmarad.
        self.assertFalse(snapshot["drop_count_enabled"])
        self.assertEqual(snapshot["drop_max"], fail2ban_mod.DEFAULT_DROP_MAX)
        self.assertTrue(snapshot["drop_ports_enabled"])
        self.assertEqual(snapshot["drop_ports"], 7)
        self.assertFalse(snapshot["drop_count_active"])
        self.assertTrue(snapshot["drop_ports_active"])
        self.assertTrue(snapshot["drop_enabled"])

    def test_legacy_zero_drop_ports_keeps_count_metric(self) -> None:
        self.write_state({
            "enabled": True,
            "drop_count_enabled": True,
            "drop_ports_enabled": True,
            "drop_max": 7,
            "drop_ports": 0,
            "drop_window_seconds": 90,
        })
        manager = self.make_manager()
        snapshot = manager.snapshot()
        # Csak a portmérőszám kapcsol ki; a csomagszám-küszöb megmarad.
        self.assertTrue(snapshot["drop_count_enabled"])
        self.assertEqual(snapshot["drop_max"], 7)
        self.assertFalse(snapshot["drop_ports_enabled"])
        self.assertEqual(
            snapshot["drop_ports"], fail2ban_mod.DEFAULT_DROP_PORTS
        )
        self.assertTrue(snapshot["drop_count_active"])
        self.assertFalse(snapshot["drop_ports_active"])
        self.assertTrue(snapshot["drop_enabled"])

    def test_legacy_drop_enabled_false_keeps_both_metrics_off(self) -> None:
        self.write_state({
            "enabled": True,
            "drop_enabled": False,
            "drop_count_enabled": True,
            "drop_ports_enabled": True,
            "drop_max": 5,
            "drop_ports": 4,
            "drop_window_seconds": 60,
        })
        manager = self.make_manager()
        snapshot = manager.snapshot()
        self.assertFalse(snapshot["drop_count_enabled"])
        self.assertFalse(snapshot["drop_ports_enabled"])
        self.assertFalse(snapshot["drop_enabled"])
        self.assertFalse(snapshot["drop_count_active"])
        self.assertFalse(snapshot["drop_ports_active"])
        # A küszöbök érvényesek maradtak, nem estek vissza alapértékre.
        self.assertEqual(snapshot["drop_max"], 5)
        self.assertEqual(snapshot["drop_ports"], 4)

    def test_constructor_drop_enabled_false_is_first_start_gate(self) -> None:
        manager = self.make_manager(
            drop_enabled=False, drop_max=7, drop_ports=9,
            drop_window_seconds=90,
        )
        snapshot = manager.snapshot()
        self.assertFalse(snapshot["drop_count_enabled"])
        self.assertFalse(snapshot["drop_ports_enabled"])
        self.assertFalse(snapshot["drop_enabled"])
        # A kapu a kapcsolókat zárja, a küszöbök érvényesek maradnak.
        self.assertEqual(snapshot["drop_max"], 7)
        self.assertEqual(snapshot["drop_ports"], 9)
        self.assertEqual(snapshot["drop_window_seconds"], 90)
        self.assertIsNone(manager.record_drop(
            "192.0.2.90", proto="tcp", dport=22, reason="input-wan"
        ))
        self.assertEqual(self.fw.calls, [])

    def test_env_metric_defaults_reach_constructor(self) -> None:
        """A HV_FAIL2BAN_DROP_* env a konstruktor alapértékeit adja."""
        try:
            for variable, attribute, parameter in (
                (
                    "HV_FAIL2BAN_DROP_COUNT_ENABLED",
                    "DEFAULT_DROP_COUNT_ENABLED",
                    "drop_count_enabled",
                ),
                (
                    "HV_FAIL2BAN_DROP_PORTS_ENABLED",
                    "DEFAULT_DROP_PORTS_ENABLED",
                    "drop_ports_enabled",
                ),
            ):
                with self.subTest(variable=variable):
                    with mock.patch.dict(os.environ, {variable: "0"}):
                        module = importlib.reload(fail2ban_mod)
                        self.assertFalse(getattr(module, attribute))
                        default = inspect.signature(
                            module.Fail2ban.__init__
                        ).parameters[parameter].default
                        self.assertIs(default, False)
                    importlib.reload(fail2ban_mod)
        finally:
            # Az env nélküli alapértékek visszaállítása a többi teszthez.
            importlib.reload(fail2ban_mod)

    def test_env_drop_master_off_reaches_constructor(self) -> None:
        """A HV_FAIL2BAN_DROP=0 mindkét metrikát kikapcsolva indul."""
        try:
            with mock.patch.dict(os.environ, {"HV_FAIL2BAN_DROP": "0"}):
                module = importlib.reload(fail2ban_mod)
                self.assertFalse(module.DEFAULT_DROP_ENABLED)
                manager = module.Fail2ban(
                    self.fw,
                    path=self.path,
                    logger=lambda *_: None,
                )
                snapshot = manager.snapshot()
                self.assertFalse(snapshot["drop_count_enabled"])
                self.assertFalse(snapshot["drop_ports_enabled"])
                self.assertFalse(snapshot["drop_enabled"])
                self.assertGreaterEqual(snapshot["drop_max"], 1)
                self.assertGreaterEqual(snapshot["drop_ports"], 1)
        finally:
            importlib.reload(fail2ban_mod)

    def test_both_metrics_off_track_nothing(self) -> None:
        manager = self.make_manager(
            drop_count_enabled=False, drop_ports_enabled=False
        )
        snapshot = manager.snapshot()
        self.assertFalse(snapshot["drop_count_active"])
        self.assertFalse(snapshot["drop_ports_active"])
        self.assertFalse(snapshot["drop_enabled"])

        for index, port in enumerate((22, 80, 443, 8080)):
            self.assertIsNone(manager.record_drop(
                f"192.0.2.{110 + index}",
                proto="tcp",
                dport=port,
                reason="input-wan",
            ))
        self.assertEqual(manager._drop_events, {})
        self.assertEqual(manager.snapshot()["drop_pending"], [])
        self.assertEqual(self.fw.calls, [])

    def test_login_toggle_off_leaves_drop_metrics_working(self) -> None:
        manager = self.make_manager(
            drop_max=2, drop_ports=10, max_attempts=1
        )
        snapshot = manager.configure({"enabled": False})
        self.assertFalse(snapshot["enabled"])
        self.assertTrue(snapshot["drop_count_enabled"])
        self.assertTrue(snapshot["drop_ports_enabled"])
        self.assertTrue(snapshot["drop_count_active"])
        self.assertTrue(snapshot["drop_ports_active"])
        self.assertTrue(snapshot["drop_enabled"])

        # A belépés-figyelés kikapcsolva nem számol és nem tilt.
        self.assertIsNone(manager.record_failure("192.0.2.91", "alice"))

        ip = "192.0.2.92"
        self.assertIsNone(manager.record_drop(
            ip, proto="tcp", dport=22, reason="input-wan"
        ))
        view = manager.record_drop(
            ip, proto="tcp", dport=23, reason="input-wan"
        )
        self.assertIsNotNone(view)
        self.assertEqual(view["source"], "drop")
        self.assertEqual(len(self.ban_calls()), 1)

    def test_count_toggle_off_leaves_port_metric_active(self) -> None:
        manager = self.make_manager(
            drop_max=1, drop_ports=3, drop_count_enabled=False
        )
        snapshot = manager.snapshot()
        self.assertFalse(snapshot["drop_count_active"])
        self.assertTrue(snapshot["drop_ports_active"])
        self.assertTrue(snapshot["drop_enabled"])

        ip = "192.0.2.120"
        # A nagyon alacsony drop_max ellenére sem tilt a csomagszám.
        for _ in range(5):
            self.assertIsNone(manager.record_drop(
                ip, proto="tcp", dport=22, reason="input-wan"
            ))
        self.assertEqual(self.ban_calls(), [])
        self.assertEqual(manager.snapshot()["drop_pending"][0]["count"], 0)

        self.assertIsNone(manager.record_drop(
            ip, proto="tcp", dport=80, reason="input-wan"
        ))
        view = manager.record_drop(
            ip, proto="tcp", dport=443, reason="input-wan"
        )
        self.assertIsNotNone(view)
        self.assertEqual(view["source"], "drop")
        self.assertEqual(len(self.ban_calls()), 1)

    def test_ports_toggle_off_leaves_packet_metric_active(self) -> None:
        manager = self.make_manager(
            drop_max=3, drop_ports=1, drop_ports_enabled=False
        )
        snapshot = manager.snapshot()
        self.assertTrue(snapshot["drop_count_active"])
        self.assertFalse(snapshot["drop_ports_active"])
        self.assertTrue(snapshot["drop_enabled"])

        ip = "192.0.2.121"
        self.assertIsNone(manager.record_drop(
            ip, proto="tcp", dport=22, reason="input-wan"
        ))
        self.assertIsNone(manager.record_drop(
            ip, proto="tcp", dport=80, reason="input-wan"
        ))
        self.assertEqual(self.ban_calls(), [])
        view = manager.record_drop(
            ip, proto="tcp", dport=8080, reason="input-wan"
        )
        self.assertIsNotNone(view)
        self.assertEqual(len(self.ban_calls()), 1)

    def test_lan_events_are_ignored_when_ports_disabled(self) -> None:
        manager = self.make_manager(drop_max=2, drop_ports_enabled=False)
        ip = "192.0.2.122"
        for _ in range(5):
            self.assertIsNone(manager.record_drop(
                ip, proto="tcp", dport=443, reason="no-grant",
                count_total=False,
            ))
        self.assertEqual(manager._drop_events, {})
        self.assertEqual(manager.snapshot()["drop_pending"], [])

        self.assertIsNone(manager.record_drop(
            ip, proto="tcp", dport=443, reason="input-wan"
        ))
        view = manager.record_drop(
            ip, proto="tcp", dport=443, reason="input-wan"
        )
        self.assertIsNotNone(view)
        self.assertEqual(view["attempts"], 2)

    def test_toggles_persist_and_reload(self) -> None:
        manager = self.make_manager()
        manager.configure({
            "drop_count_enabled": False,
            "drop_ports_enabled": False,
        })
        self.assertEqual(
            stat.S_IMODE(os.stat(self.path).st_mode), 0o600
        )
        with open(self.path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        config = payload["config"]
        self.assertFalse(config["drop_count_enabled"])
        self.assertFalse(config["drop_ports_enabled"])
        self.assertFalse(config["drop_enabled"])
        self.assertEqual(config["drop_max"], 5)
        self.assertEqual(config["drop_ports"], 4)

        reloaded = self.make_manager()
        snapshot = reloaded.snapshot()
        self.assertFalse(snapshot["drop_count_enabled"])
        self.assertFalse(snapshot["drop_ports_enabled"])
        self.assertFalse(snapshot["drop_count_active"])
        self.assertFalse(snapshot["drop_ports_active"])

    def test_invalid_config_is_rejected_and_state_unchanged(self) -> None:
        manager = self.make_manager(drop_max=7, drop_ports=9)
        before = manager.snapshot()
        for payload in (
            {"drop_count_enabled": "igen"},
            {"drop_count_enabled": 1},
            {"drop_ports_enabled": None},
            {"drop_ports_enabled": "off"},
            {"drop_enabled": "nem"},
            {"drop_max": 0},
            {"drop_max": -1},
            {"drop_max": 1.5},
            {"drop_max": True},
            {"drop_max": 10001},
            {"drop_ports": 0},
            {"drop_ports": -1},
            {"drop_ports": 2.5},
            {"drop_ports": 4097},
        ):
            with self.subTest(payload=payload), self.assertRaises(
                fail2ban_mod.Fail2banError
            ):
                manager.configure(payload)
        after = manager.snapshot()
        for key in (
            "drop_enabled", "drop_count_enabled", "drop_ports_enabled",
            "drop_max", "drop_ports", "drop_window_seconds",
            "drop_count_active", "drop_ports_active",
        ):
            self.assertEqual(after[key], before[key], key)

    def test_invalid_env_metric_values_fall_back_to_default(self) -> None:
        default_max = 120
        default_ports = 12
        for raw in ("0", "-5", "abc", "1.5", "10001"):
            with self.subTest(raw=raw), mock.patch.dict(
                os.environ, {"HV_FAIL2BAN_DROP_MAX": raw}
            ):
                value = fail2ban_mod._env_int_in_range(
                    "HV_FAIL2BAN_DROP_MAX", default_max, 1, 10000
                )
            self.assertEqual(value, default_max, raw)
        for raw in ("0", "-1", "abc", "2.5", "4097"):
            with self.subTest(raw=raw), mock.patch.dict(
                os.environ, {"HV_FAIL2BAN_DROP_PORTS": raw}
            ):
                value = fail2ban_mod._env_int_in_range(
                    "HV_FAIL2BAN_DROP_PORTS", default_ports, 1, 4096
                )
            self.assertEqual(value, default_ports, raw)

    def test_hot_apply_clears_counters_without_reconstruction(self) -> None:
        manager = self.make_manager(drop_max=5, drop_ports=10)
        ip = "192.0.2.123"
        for _ in range(3):
            self.assertIsNone(manager.record_drop(
                ip, proto="tcp", dport=22, reason="input-wan"
            ))
        self.assertEqual(manager.snapshot()["drop_pending"][0]["count"], 3)

        snapshot = manager.configure({"drop_count_enabled": False})
        self.assertFalse(snapshot["drop_count_active"])
        self.assertEqual(snapshot["drop_pending"], [])
        self.assertIsNone(manager.record_drop(
            ip, proto="tcp", dport=80, reason="input-wan"
        ))
        pending = manager.snapshot()["drop_pending"][0]
        self.assertEqual(pending["count"], 0)
        self.assertEqual(pending["events"], 1)

        manager.configure({"drop_count_enabled": True})
        self.assertEqual(manager.snapshot()["drop_pending"], [])

        manager.record_drop(ip, proto="tcp", dport=80, reason="input-wan")
        self.assertEqual(manager.snapshot()["drop_pending"][0]["count"], 1)
        manager.configure({"drop_max": 6})
        self.assertEqual(manager.snapshot()["drop_pending"], [])
        manager.record_drop(ip, proto="tcp", dport=80, reason="input-wan")
        manager.configure({"drop_ports": 11})
        self.assertEqual(manager.snapshot()["drop_pending"], [])
        self.assertEqual(self.ban_calls(), [])

    def test_login_toggle_off_does_not_clear_drop_counters(self) -> None:
        manager = self.make_manager(drop_max=5, drop_ports=10)
        ip = "192.0.2.127"
        for _ in range(3):
            self.assertIsNone(manager.record_drop(
                ip, proto="tcp", dport=22, reason="input-wan"
            ))
        before = manager.snapshot()["drop_pending"]
        self.assertEqual(len(before), 1)
        self.assertEqual(before[0]["count"], 3)

        manager.configure({"enabled": False})
        after = manager.snapshot()["drop_pending"]
        self.assertEqual(after, before)
        self.assertEqual(len(manager._drop_events[ip]["events"]), 3)

    def test_disabling_both_drop_toggles_releases_only_drop_bans(self) -> None:
        manager = self.make_manager(
            drop_max=1, drop_ports=100, max_attempts=1
        )
        login_ip = "192.0.2.130"
        drop_ip = "192.0.2.131"
        manual_ip = "192.0.2.132"
        self.assertIsNotNone(manager.record_failure(login_ip, "alice"))
        self.assertIsNotNone(manager.record_drop(
            drop_ip, proto="tcp", dport=22, reason="input-wan"
        ))
        manager.ban(manual_ip, 600)
        self.fw.calls.clear()

        manager.configure({
            "drop_count_enabled": False,
            "drop_ports_enabled": False,
        })
        self.assertIsNone(manager.banned(drop_ip))
        self.assertIsNotNone(manager.banned(login_ip))
        self.assertIsNotNone(manager.banned(manual_ip))
        self.assertEqual(self.unban_calls(), [("unban", drop_ip)])

    def test_simultaneous_disable_audits_login_and_drop_counts(self) -> None:
        audit = FakeAudit()
        manager = self.make_manager(
            audit=audit, drop_max=1, drop_ports=100, max_attempts=1
        )
        self.assertIsNotNone(manager.record_failure("192.0.2.150", "alice"))
        self.assertIsNotNone(manager.record_drop(
            "192.0.2.151", proto="tcp", dport=22, reason="input-wan"
        ))

        manager.configure({
            "enabled": False,
            "drop_count_enabled": False,
            "drop_ports_enabled": False,
        })
        events = audit.named("fail2ban_bans_released")
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["count"], 2)
        self.assertEqual(event["reason"], "disabled")
        self.assertEqual(event["login_count"], 1)
        self.assertEqual(event["drop_count"], 1)

    def test_disabling_login_releases_only_login_bans(self) -> None:
        manager = self.make_manager(
            drop_max=1, drop_ports=100, max_attempts=1
        )
        login_ip = "192.0.2.140"
        drop_ip = "192.0.2.141"
        manual_ip = "192.0.2.142"
        self.assertIsNotNone(manager.record_failure(login_ip, "alice"))
        self.assertIsNotNone(manager.record_drop(
            drop_ip, proto="tcp", dport=22, reason="input-wan"
        ))
        manager.ban(manual_ip, 600)
        self.fw.calls.clear()

        manager.configure({"enabled": False})
        self.assertIsNone(manager.banned(login_ip))
        self.assertIsNotNone(manager.banned(drop_ip))
        self.assertIsNotNone(manager.banned(manual_ip))
        self.assertEqual(self.unban_calls(), [("unban", login_ip)])

        # A drop-figyelés továbbra is működik a belépés kikapcsolása után.
        next_ip = "192.0.2.143"
        view = manager.record_drop(
            next_ip, proto="tcp", dport=80, reason="input-wan"
        )
        self.assertIsNotNone(view)
        self.assertEqual(view["source"], "drop")

    def test_simultaneous_crossing_bans_exactly_once(self) -> None:
        manager = self.make_manager(drop_max=2, drop_ports=2)
        ip = "192.0.2.125"
        self.assertIsNone(manager.record_drop(
            ip, proto="tcp", dport=22, reason="input-wan"
        ))
        view = manager.record_drop(
            ip, proto="tcp", dport=80, reason="input-wan"
        )
        self.assertIsNotNone(view)
        self.assertEqual(len(self.ban_calls()), 1)

        self.assertIsNone(manager.record_drop(
            ip, proto="tcp", dport=443, reason="input-wan"
        ))
        self.assertEqual(len(self.ban_calls()), 1)
        self.assertEqual(manager.snapshot()["drop_pending"], [])

    def test_event_cap_accounts_for_large_port_threshold(self) -> None:
        # Kicsi drop_max mellé 512 feletti drop_ports: a korlátot a nagyobb,
        # aktív küszöbhöz kell méretezni, különben a portszkennelés nem
        # érné el a küszöböt.
        manager = self.make_manager(
            drop_max=1,
            drop_ports=600,
            drop_count_enabled=False,
        )
        ip = "192.0.2.126"
        for port in range(1, 600):
            self.assertIsNone(manager.record_drop(
                ip, proto="tcp", dport=port, reason="input-wan"
            ), port)
        self.assertEqual(self.ban_calls(), [])
        view = manager.record_drop(
            ip, proto="tcp", dport=600, reason="input-wan"
        )
        self.assertIsNotNone(view)
        self.assertEqual(len(self.ban_calls()), 1)

    def test_snapshot_status_and_limits_expose_flags_and_min_one(self) -> None:
        manager = self.make_manager()
        snapshot = manager.snapshot()
        self.assertTrue(snapshot["drop_count_enabled"])
        self.assertTrue(snapshot["drop_ports_enabled"])
        self.assertTrue(snapshot["drop_count_active"])
        self.assertTrue(snapshot["drop_ports_active"])
        self.assertTrue(snapshot["drop_enabled"])
        self.assertEqual(snapshot["limits"]["min_drop_max"], 1)
        self.assertEqual(snapshot["limits"]["min_drop_ports"], 1)
        self.assertEqual(snapshot["limits"]["max_drop_max"], 10000)
        self.assertEqual(snapshot["limits"]["max_drop_ports"], 4096)

        status = manager.status()
        self.assertTrue(status["drop_count_enabled"])
        self.assertTrue(status["drop_ports_enabled"])
        self.assertTrue(status["drop_count_active"])
        self.assertTrue(status["drop_ports_active"])
        self.assertTrue(status["drop_enabled"])

        manager.configure({"drop_count_enabled": False})
        status = manager.status()
        self.assertFalse(status["drop_count_enabled"])
        self.assertFalse(status["drop_count_active"])
        self.assertTrue(status["drop_ports_enabled"])
        self.assertTrue(status["drop_ports_active"])
        self.assertTrue(status["drop_enabled"])

    def test_legacy_drop_enabled_false_input_forces_both_metrics_off(self) -> None:
        manager = self.make_manager()
        snapshot = manager.configure({
            "drop_enabled": False,
            "drop_count_enabled": True,
            "drop_ports_enabled": True,
        })
        self.assertFalse(snapshot["drop_count_enabled"])
        self.assertFalse(snapshot["drop_ports_enabled"])
        self.assertFalse(snapshot["drop_enabled"])

        # A drop_enabled=true nem kapcsol be mérőszámot a háttérben.
        manager.configure({"drop_count_enabled": False, "drop_ports_enabled": False})
        snapshot = manager.configure({
            "drop_enabled": True,
            "drop_count_enabled": True,
        })
        self.assertTrue(snapshot["drop_count_enabled"])
        self.assertFalse(snapshot["drop_ports_enabled"])
        self.assertTrue(snapshot["drop_enabled"])


if __name__ == "__main__":
    unittest.main()
