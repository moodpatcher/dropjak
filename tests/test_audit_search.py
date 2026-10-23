#!/usr/bin/env python3
"""Tests for searching the audit log (event and free-text filters).

Run from the project root:

    python3 -m unittest tests.test_audit_search -v

The tests work in an isolated temporary directory; the HTTP test starts its
own server bound to 127.0.0.1 and creates an admin session directly, so no
password/2FA flow is needed.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import droplog  # noqa: E402
import fail2ban as fail2ban_mod  # noqa: E402
import gateway  # noqa: E402
import server  # noqa: E402


def quiet(*_args, **_kwargs) -> None:
    return None


# The rows deliberately contain mixed event codes and values.
# The ts values make the newest-to-oldest ordering and the before=
# paging checkable.
ROWS = (
    {
        "ts": 100.0, "time": "2026-01-01T00:01:40Z",
        "event": "access_granted", "severity": "info",
        "user": "alice", "ip": "10.0.0.5", "rule": "web-only",
        "reason": "successful login",
    },
    {
        "ts": 200.0, "time": "2026-01-01T00:03:20Z",
        "event": "access_granted", "severity": "warn",
        "user": "bob", "ip": "10.0.0.6", "rule": "ssh-only",
        "reason": "ok",
    },
    {
        "ts": 300.0, "time": "2026-01-01T00:05:00Z",
        "event": "login_success", "severity": "info",
        "user": "alice", "ip": "10.0.0.5",
    },
    {
        "ts": 400.0, "time": "2026-01-01T00:06:40Z",
        "event": "admin_rule_deleted", "severity": "warn",
        "user": "root", "ip": "10.0.0.1", "rule": "web-only",
        "reason": "removed",
    },
    # Old entry without severity: "info" by default.
    {
        "ts": 500.0, "time": "2026-01-01T00:08:20Z",
        "event": "login_success", "user": "carol", "ip": "10.0.0.7",
    },
)


def write_rows(path: str, rows) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def events(rows) -> list[str]:
    return [row["event"] for row in rows]


def timestamps(rows) -> list[float]:
    return [row["ts"] for row in rows]


class AuditSearchUnitTests(unittest.TestCase):
    """The event and q filters of AuditLog.read."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "audit.jsonl")
        write_rows(self.path, ROWS)
        self.audit = gateway.AuditLog(self.path, logger=quiet)

    def test_event_filter_accepts_code_case_separators_and_spaces(self) -> None:
        for needle in (
            "access_granted",
            "ACCESS_GRANTED",
            "ACCESS-GRANTED",
            "Access granted",
            "Access Granted",
        ):
            with self.subTest(event=needle):
                rows = self.audit.read(event=needle)
                self.assertEqual(
                    events(rows), ["access_granted", "access_granted"]
                )
                self.assertEqual(timestamps(rows), [200.0, 100.0])

    def test_event_filter_keeps_raw_code_family_search(self) -> None:
        rows = self.audit.read(event="admin_")
        self.assertEqual(events(rows), ["admin_rule_deleted"])

        rows = self.audit.read(event="login")
        self.assertEqual(events(rows), ["login_success", "login_success"])

    def test_events_filter_is_exact_set(self) -> None:
        rows = self.audit.read(events=["login_success", "admin_rule_deleted"])
        self.assertEqual(timestamps(rows), [500.0, 400.0, 300.0])
        # Exact match: the prefix is not a family filter.
        self.assertEqual(self.audit.read(events=["login"]), [])
        # Together with the old single filter, both must hold.
        rows = self.audit.read(events=["login_success"], user="carol")
        self.assertEqual(timestamps(rows), [500.0])

    def test_q_matches_space_and_underscore_forms(self) -> None:
        for needle in ("access granted", "access_granted", "ACCESS-GRANTED"):
            with self.subTest(q=needle):
                rows = self.audit.read(q=needle)
                self.assertEqual(
                    events(rows), ["access_granted", "access_granted"]
                )

    def test_q_ignores_json_key_names(self) -> None:
        # There is no "event"/"user" word among the values, so without
        # counting the key names none of the rows can match.
        self.assertEqual(self.audit.read(q="event"), [])
        self.assertEqual(self.audit.read(q="user"), [])

    def test_q_matches_user_ip_and_rule_values(self) -> None:
        self.assertEqual(
            timestamps(self.audit.read(q="alice")), [300.0, 100.0]
        )
        self.assertEqual(timestamps(self.audit.read(q="10.0.0.6")), [200.0])
        self.assertEqual(
            timestamps(self.audit.read(q="web-only")), [400.0, 100.0]
        )
        self.assertEqual(timestamps(self.audit.read(q="web only")), [400.0, 100.0])

    def test_filters_intersect_with_and_semantics(self) -> None:
        rows = self.audit.read(
            event="Access Granted", user="alice", q="web-only",
            severity="info",
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ts"], 100.0)
        self.assertEqual(rows[0]["user"], "alice")

        # The same with another severity: no intersection.
        self.assertEqual(
            self.audit.read(
                event="Access Granted", user="alice", q="web-only",
                severity="warn",
            ),
            [],
        )

    def test_before_paging_works_with_event_filter(self) -> None:
        rows = self.audit.read(before=300.0, event="Access Granted")
        self.assertEqual(timestamps(rows), [200.0, 100.0])
        rows = self.audit.read(before=150.0, event="Access Granted")
        self.assertEqual(timestamps(rows), [100.0])

    def test_legacy_row_without_severity_is_info(self) -> None:
        info = self.audit.read(severity="info")
        self.assertIn(500.0, timestamps(info))
        legacy = [row for row in info if row["ts"] == 500.0][0]
        self.assertNotIn("severity", legacy)

        warn = timestamps(self.audit.read(severity="warn"))
        self.assertEqual(warn, [400.0, 200.0])
        self.assertNotIn(500.0, warn)

    def test_unknown_filters_return_empty_list(self) -> None:
        self.assertEqual(self.audit.read(event="no_such_event"), [])
        self.assertEqual(self.audit.read(q="no-such-value"), [])

    def test_limit_is_clamped_and_order_is_newest_first(self) -> None:
        self.assertEqual(timestamps(self.audit.read(limit=0)), [500.0])
        self.assertEqual(
            timestamps(self.audit.read(limit=9999)),
            [500.0, 400.0, 300.0, 200.0, 100.0],
        )

    def test_ip_filter_single_cidr_and_combined(self) -> None:
        net = ipaddress.ip_network
        self.assertEqual(
            timestamps(self.audit.read(ip=net("10.0.0.5"))), [300.0, 100.0]
        )
        self.assertEqual(
            timestamps(self.audit.read(ip=net("10.0.0.6/31"))), [500.0, 200.0]
        )
        self.assertEqual(len(self.audit.read(ip=net("10.0.0.0/24"))), 5)
        self.assertEqual(self.audit.read(ip=net("10.0.1.0/24")), [])
        self.assertEqual(self.audit.read(ip=net("::/0")), [])
        self.assertEqual(
            timestamps(self.audit.read(ip=net("10.0.0.5"), event="login")),
            [300.0],
        )

    def test_ip_filter_target_ipv6_and_proxy_host_search(self) -> None:
        extra = os.path.join(self.tmp.name, "extra.jsonl")
        write_rows(extra, (
            {"ts": 1.0, "event": "fail2ban_unban", "ip": "10.9.9.9",
             "target": "203.0.113.7"},
            {"ts": 2.0, "event": "proxy_challenge_shown", "ip": "2001:db8::5",
             "host": "x.z1.example.com", "path": "/", "unknown_host": True},
        ))
        audit = gateway.AuditLog(extra, logger=quiet)
        net = ipaddress.ip_network
        self.assertEqual(timestamps(audit.read(ip=net("203.0.113.0/24"))), [1.0])
        self.assertEqual(timestamps(audit.read(ip=net("2001:db8::/64"))), [2.0])
        self.assertEqual(timestamps(audit.read(q="x.z1.example")), [2.0])

    def test_search_key_normalization(self) -> None:
        self.assertEqual(gateway._search_key(" ACCESS-GRANTED "), "access granted")
        self.assertEqual(gateway._search_key("a__b--c\t d"), "a b c d")


class AuditSearchApiTests(unittest.TestCase):
    """The event and q parameters of GET /api/admin/logs."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        root = cls.tmp.name
        catalog = gateway.ServiceCatalog.load(str(ROOT / "services.json"))
        cls.users = gateway.UserStore(
            os.path.join(root, "users.json"), iterations=10_000
        )
        cls.users.add("root", "root-password-1", role=gateway.ROLE_ADMIN)
        rules = gateway.RuleStore(
            os.path.join(root, "rules.json"), catalog=catalog, logger=quiet
        )
        groups = gateway.GroupStore(
            os.path.join(root, "groups.json"), logger=quiet
        )
        cls.audit = gateway.AuditLog(
            os.path.join(root, "audit.jsonl"), logger=quiet
        )
        write_rows(cls.audit.path, ROWS)
        firewall = gateway.Firewall(
            binary=os.path.join(root, "nft"), logger=quiet
        )
        fail2ban = fail2ban_mod.Fail2ban(
            firewall,
            path=os.path.join(root, "fail2ban.json"),
            audit=cls.audit,
            logger=quiet,
        )
        settings = gateway.settings_store.SettingsStore(
            os.path.join(root, "settings.json"), logger=quiet
        )
        drops = droplog.DropLogService(
            os.path.join(root, "drops.jsonl"), enabled=False, logger=quiet
        )
        cls.gw = gateway.Gateway(
            users=cls.users,
            firewall=firewall,
            catalog=catalog,
            rules=rules,
            groups=groups,
            audit=cls.audit,
            settings=settings,
            drops=drops,
            fail2ban=fail2ban,
            rate_limiter=gateway.RateLimiter(window=60, maximum=1000),
        )
        cls.session = cls.gw.sessions.login(
            "root", "127.0.0.1", role=gateway.ROLE_ADMIN
        )
        cls.server = server.AppServer(("127.0.0.1", 0), cls.gw)
        cls.thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True
        )
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.gw.sessions.terminate(cls.session.sid, reason="test_cleanup")
        cls.tmp.cleanup()

    def get_logs(self, query: str):
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=10,
            source_address=("127.0.0.1", 0),
        )
        try:
            conn.request(
                "GET", f"/api/admin/logs?{query}",
                headers={
                    "Cookie": f"{gateway.COOKIE_NAME}={self.session.token}"
                },
            )
            resp = conn.getresponse()
            body = resp.read()
            return resp.status, json.loads(body)
        finally:
            conn.close()

    def test_api_event_filter_accepts_display_label(self) -> None:
        status, data = self.get_logs(
            "event=" + urllib.parse.quote("Access Granted")
        )
        self.assertEqual(status, 200, data)
        self.assertIs(data["ok"], True)
        self.assertEqual(data["count"], 2)
        self.assertEqual(events(data["logs"]), ["access_granted"] * 2)

    def test_api_q_filter_accepts_space_form(self) -> None:
        status, data = self.get_logs(
            "q=" + urllib.parse.quote("access granted")
        )
        self.assertEqual(status, 200, data)
        self.assertIs(data["ok"], True)
        self.assertEqual(data["count"], 2)
        self.assertEqual(events(data["logs"]), ["access_granted"] * 2)

    def test_api_q_key_name_does_not_match_everything(self) -> None:
        status, data = self.get_logs("q=event")
        self.assertEqual(status, 200, data)
        self.assertIs(data["ok"], True)
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["logs"], [])

    def test_api_ip_filter(self) -> None:
        for query, expected in (
            ("ip=10.0.0.6", [200.0]),
            ("ip=" + urllib.parse.quote("10.0.0.6/31"), [500.0, 200.0]),
            ("ip=10.0.0.5&event=access_granted", [100.0]),
        ):
            with self.subTest(query=query):
                status, data = self.get_logs(query)
                self.assertEqual(status, 200, data)
                self.assertEqual(timestamps(data["logs"]), expected)
        for bad in ("abc", "10.0.0.5/33", "1", "10.0.0.0/24/1"):
            with self.subTest(ip=bad):
                status, data = self.get_logs("ip=" + urllib.parse.quote(bad))
                self.assertEqual(status, 400, data)
                self.assertIs(data["ok"], False)
                self.assertIn("CIDR", data["error"])

    def test_api_multi_event_filter(self) -> None:
        for query, expected in (
            ("events=login_success,admin_rule_deleted", [500.0, 400.0, 300.0]),
            ("events=login_success&events=access_granted",
             [500.0, 300.0, 200.0, 100.0]),
            ("event=login_success&event=admin_rule_deleted",
             [500.0, 400.0, 300.0]),
            ("events=" + urllib.parse.quote(" LOGIN_SUCCESS , ,"), [500.0, 300.0]),
            # A single event= keeps the old partial matching.
            ("event=login", [500.0, 300.0]),
            ("events=login", []),
            ("events=", [500.0, 400.0, 300.0, 200.0, 100.0]),
        ):
            with self.subTest(query=query):
                status, data = self.get_logs(query)
                self.assertEqual(status, 200, data)
                self.assertEqual(timestamps(data["logs"]), expected)
        for bad in ("login success", "admin-rule", "x;y", "a" * 65, "1abc"):
            with self.subTest(events=bad):
                status, data = self.get_logs("events=" + urllib.parse.quote(bad))
                self.assertEqual(status, 400, data)
                self.assertIs(data["ok"], False)
        status, data = self.get_logs(
            "events=" + ",".join(f"e{index}" for index in range(201))
        )
        self.assertEqual(status, 400, data)

    def test_api_unknown_event_is_empty_and_ok(self) -> None:
        status, data = self.get_logs("event=no_such")
        self.assertEqual(status, 200, data)
        self.assertIs(data["ok"], True)
        self.assertEqual(data["logs"], [])


if __name__ == "__main__":
    unittest.main()
