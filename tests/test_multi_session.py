#!/usr/bin/env python3
"""Tests for the optional multi-session-per-source-IP mode.

With the ``multi_session_same_ip`` setting off (the default) a new sign-in
still replaces every earlier session of the source IP. With it on, the
sessions coexist, each with its own TTL and selection; a logout removes only
the departing session's unneeded grants, and the surviving elements are
clamped to the remaining session's TTL.

The tests use a recording fake firewall, so they do not touch nftables.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402
import settings_store  # noqa: E402

IP = "203.0.113.20"
OTHER_IP = "203.0.113.21"
DOMAIN = "app.example.com"


def make_rule(
    rule_id: str = "web",
    tcp: tuple[int, ...] = (80,),
    domains: tuple[str, ...] = (),
    max_ttl: int = 600,
) -> gateway.Rule:
    return gateway.Rule(
        id=rule_id,
        label=rule_id,
        description="",
        tcp=tuple(tcp),
        domains=tuple(domains),
        default_ttl=60,
        max_ttl=max_ttl,
    )


def forward_ports(*tcp: int) -> gateway.Ports:
    return gateway.Ports(tcp=tuple(tcp), direction="forward")


class RecordingFirewall:
    """Records grants, full revocations and exact revocations."""

    def __init__(self) -> None:
        self.grant_calls: list[tuple[str, tuple, int]] = []
        self.revoke_calls: list[tuple[str, tuple, bool, bool]] = []
        self.exact_calls: list[tuple[str, tuple]] = []

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

    def revoke_exact(self, ip: str, grants=()) -> None:
        self.exact_calls.append((ip, tuple(grants)))


class MultiSessionTests(unittest.TestCase):
    def make_manager(self, check, firewall=None) -> gateway.SessionManager:
        return gateway.SessionManager(
            firewall if firewall is not None else RecordingFirewall(),
            ttl=600,
            pending_ttl=60,
            multi_session_check=check,
        )

    def test_off_still_replaces_the_previous_session(self) -> None:
        for label, check in (
            ("no callback", None),
            ("callback false", lambda: False),
        ):
            with self.subTest(label=label):
                firewall = RecordingFirewall()
                manager = self.make_manager(check, firewall)
                first = manager.login("alice", IP)
                second = manager.login("alice", IP)
                self.assertEqual(manager.count(), 1)
                self.assertIsNone(manager.validate(first.token, IP))
                self.assertIsNotNone(manager.validate(second.token, IP))

    def test_on_keeps_both_sessions_and_their_grants(self) -> None:
        firewall = RecordingFirewall()
        manager = self.make_manager(lambda: True, firewall)
        rule = make_rule()
        first = manager.login("alice", IP)
        first = manager.authorize(first.token, IP, rule, 300)
        second = manager.login("bob", IP)
        second = manager.authorize(second.token, IP, rule, 120)
        self.assertEqual(manager.count(), 2)
        self.assertEqual(manager.count(authorized_only=True), 2)
        self.assertIsNotNone(manager.validate(first.token, IP))
        self.assertIsNotNone(manager.validate(second.token, IP))
        # The second sign-in did not revoke the first session's grant.
        self.assertEqual(firewall.revoke_calls, [])
        self.assertEqual(firewall.exact_calls, [])

    def test_logout_or_terminate_keeps_the_other_grants(self) -> None:
        rule = make_rule()
        for action in ("logout", "terminate"):
            with self.subTest(action=action):
                firewall = RecordingFirewall()
                manager = self.make_manager(lambda: True, firewall)
                first = manager.login("alice", IP)
                first = manager.authorize(first.token, IP, rule, 300)
                second = manager.login("bob", IP)
                second = manager.authorize(second.token, IP, rule, 120)
                firewall.revoke_calls.clear()
                firewall.exact_calls.clear()
                firewall.grant_calls.clear()
                if action == "logout":
                    self.assertIsNotNone(
                        manager.logout(first.token, IP)
                    )
                else:
                    self.assertIsNotNone(manager.terminate(first.sid))
                # The remaining session needs every departing element: no
                # deletion happens, only a TTL clamp.
                self.assertEqual(firewall.revoke_calls, [])
                self.assertEqual(firewall.exact_calls, [])
                self.assertEqual(len(firewall.grant_calls), 1)
                _ip, grants, ttl = firewall.grant_calls[0]
                self.assertEqual(grants, second.grants)
                self.assertGreaterEqual(ttl, 1)
                self.assertLessEqual(ttl, 120)
                self.assertIsNotNone(manager.validate(second.token, IP))

    def test_logout_deletes_only_ports_the_other_needs_not(self) -> None:
        firewall = RecordingFirewall()
        manager = self.make_manager(lambda: True, firewall)
        first = manager.login("alice", IP)
        first = manager.authorize(
            first.token, IP, make_rule("wide", tcp=(80, 8080)), 300
        )
        second = manager.login("bob", IP)
        second = manager.authorize(
            second.token, IP, make_rule("web", tcp=(80,)), 120
        )
        firewall.revoke_calls.clear()
        firewall.exact_calls.clear()
        manager.logout(first.token, IP)
        # 8080 belonged only to the departing session; 80 stays.
        self.assertEqual(
            firewall.exact_calls,
            [(IP, (forward_ports(8080),))],
        )
        self.assertEqual(firewall.revoke_calls, [])
        self.assertIsNotNone(manager.validate(second.token, IP))
        self.assertTrue(manager._sessions[second.token].authorized)

        # Logging out the last session revokes everything.
        firewall.revoke_calls.clear()
        firewall.grant_calls.clear()
        manager.logout(second.token, IP)
        self.assertEqual(len(firewall.revoke_calls), 1)
        _ip, grants, discover, only_grants = firewall.revoke_calls[0]
        self.assertEqual(grants, second.grants)
        self.assertFalse(discover)
        self.assertFalse(only_grants)
        self.assertEqual(firewall.grant_calls, [])

    def test_revoke_timeout_is_clamped_to_remaining_session(self) -> None:
        firewall = RecordingFirewall()
        manager = self.make_manager(lambda: True, firewall)
        rule = make_rule()
        first = manager.login("alice", IP)
        first = manager.authorize(first.token, IP, rule, 300)
        second = manager.login("bob", IP)
        second = manager.authorize(second.token, IP, rule, 60)
        # Make the remaining session's expiry unambiguous.
        with manager._lock:
            manager._sessions[second.token] = gateway.replace(
                manager._sessions[second.token],
                expires=time.time() + 42,
            )
        firewall.grant_calls.clear()
        firewall.revoke_calls.clear()
        manager.logout(first.token, IP)
        self.assertEqual(firewall.revoke_calls, [])
        self.assertEqual(len(firewall.grant_calls), 1)
        ip, grants, ttl = firewall.grant_calls[0]
        self.assertEqual(ip, IP)
        self.assertEqual(grants, (forward_ports(80),))
        # The departing session granted 300 s; the surviving element must
        # not outlive the remaining session's 42 s.
        self.assertGreaterEqual(ttl, 40)
        self.assertLessEqual(ttl, 42)

    def test_domain_sessions_and_bind_select_by_sid(self) -> None:
        firewall = RecordingFirewall()
        manager = self.make_manager(lambda: True, firewall)
        rule = make_rule("proxy", tcp=(), domains=(DOMAIN,))
        first = manager.login("alice", IP)
        first = manager.authorize(first.token, IP, rule, 60)
        second = manager.login("bob", IP)
        second = manager.authorize(second.token, IP, rule, 60)

        sessions = manager.domain_sessions(IP, DOMAIN)
        self.assertEqual(
            {session.sid for session in sessions},
            {first.sid, second.sid},
        )
        self.assertEqual(
            manager.domain_bind(IP, DOMAIN, first.sid).user, "alice"
        )
        self.assertEqual(
            manager.domain_bind(IP, DOMAIN, second.sid).user, "bob"
        )
        self.assertIsNone(manager.domain_bind(IP, DOMAIN, "unknown"))
        self.assertIsNone(
            manager.domain_bind(OTHER_IP, DOMAIN, first.sid)
        )
        self.assertIsNone(
            manager.domain_bind(IP, "other.example.com", first.sid)
        )
        # The old helpers still work and return one of the sessions.
        self.assertIn(
            manager.domain_session(IP, DOMAIN), {first.sid, second.sid}
        )
        self.assertIn(manager.domain_user(IP, DOMAIN), {"alice", "bob"})

        # A logged-out session no longer opens the entry.
        manager.logout(first.token, IP)
        remaining = manager.domain_sessions(IP, DOMAIN)
        self.assertEqual([session.sid for session in remaining], [second.sid])
        self.assertIsNone(manager.domain_bind(IP, DOMAIN, first.sid))


class MultiSessionSettingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "firewall-settings.json")

    def store(self) -> settings_store.SettingsStore:
        return settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        )

    def test_default_is_off_and_the_value_persists(self) -> None:
        store = self.store()
        self.assertIs(store.snapshot()["multi_session_same_ip"], False)
        stored = store.set_multi_session_same_ip(True)
        self.assertIs(stored["multi_session_same_ip"], True)
        self.assertIs(store.snapshot()["multi_session_same_ip"], True)
        reloaded = self.store()
        self.assertIs(reloaded.snapshot()["multi_session_same_ip"], True)
        reloaded.set_multi_session_same_ip(False)
        self.assertIs(
            self.store().snapshot()["multi_session_same_ip"], False
        )

    def test_non_bool_is_rejected(self) -> None:
        store = self.store()
        for value in ("yes", 1, 0, None, []):
            with self.subTest(value=value), self.assertRaises(
                settings_store.SettingsError
            ):
                store.set_multi_session_same_ip(value)
            self.assertIs(
                store.snapshot()["multi_session_same_ip"], False
            )
        for value in ("yes", 1, None):
            with self.subTest(state=value), self.assertRaises(
                settings_store.SettingsError
            ):
                settings_store.validate_state(
                    {"multi_session_same_ip": value}
                )
        # A missing key keeps the default and appears in the result.
        validated = settings_store.validate_state({})
        self.assertIs(validated["multi_session_same_ip"], False)


if __name__ == "__main__":
    unittest.main()
