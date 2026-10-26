#!/usr/bin/env python3
"""Tests for the N4 fix: revocation runs under the session lock.

``logout()``, ``terminate()``, ``revoke_user()``, ``revoke_rule()`` and
``reap_once()`` previously called the firewall after removing the session and
after releasing ``self._lock``. A concurrent ``authorize()`` could thus slip
between the two, and the revocation could delete the grant that had just been
issued. The fix performs the firewall mutation under the same lock, and if an
active session remains for the IP, it deletes only the non-overlapping grants
(``only_grants=True``), without a conntrack flush.

The tests are deterministic: no threads, no sleeps. The fake firewall checks
at call time whether ``SessionManager._lock`` is locked and whether the call
runs on the expected thread.
"""

from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402

IP = "203.0.113.9"
OTHER_IP = "203.0.113.10"


def forward_ports(*tcp: int) -> gateway.Ports:
    """A forward-direction grant consisting of TCP ports."""
    return gateway.Ports(tcp=tuple(tcp), direction="forward")


def make_session(
    token: str,
    *,
    ip: str = IP,
    user: str = "alice",
    tcp: tuple[int, ...] = (80,),
    rule: str = "web",
    sid: str | None = None,
    expires: float | None = None,
    authorized: bool = True,
) -> gateway.Session:
    """An authorized (or pending) session from the real dataclass."""
    now = time.time()
    return gateway.Session(
        token=token,
        user=user,
        ip=ip,
        created=now,
        expires=now + 600 if expires is None else expires,
        grant_parts=(forward_ports(*tcp),),
        authorized=authorized,
        role=gateway.ROLE_USER,
        rule=rule,
        rule_label=rule,
        logged_in=now,
        sid=token if sid is None else sid,
    )


class RecordingFirewall:
    """A firewall that records ``revoke_all`` calls and checks the lock state.

    It raises AssertionError at call time if the session lock is not held, or
    if the call does not run on the expected (main) thread. A wrong locking
    order thus fails immediately and deterministically.
    """

    def __init__(self) -> None:
        self.manager: gateway.SessionManager | None = None
        self.expected_thread = threading.get_ident()
        self.calls: list[tuple[str, tuple[gateway.Ports, ...], bool, bool]] = []
        self.grant_calls: list[tuple[str, tuple[gateway.Ports, ...], int]] = []
        self.lock_states: list[bool] = []
        self.thread_ids: list[int] = []
        self.fail_next = False

    def revoke_all(
        self,
        ip: str,
        grants=(),
        discover: bool = False,
        only_grants: bool = False,
    ) -> None:
        locked = self.manager is None or self.manager._lock.locked()
        if not locked:
            raise AssertionError(
                "firewall.revoke_all did not run under SessionManager._lock"
            )
        if threading.get_ident() != self.expected_thread:
            raise AssertionError(
                "firewall.revoke_all did not run on the expected thread"
            )
        self.lock_states.append(locked)
        self.thread_ids.append(threading.get_ident())
        self.calls.append(
            (ip, tuple(grants), bool(discover), bool(only_grants))
        )
        if self.fail_next:
            self.fail_next = False
            raise gateway.FirewallError("simulated nft error")

    def grant_all(self, ip: str, grants, ttl: int) -> None:
        if self.manager is not None and not self.manager._lock.locked():
            raise AssertionError(
                "firewall.grant_all did not run under SessionManager._lock"
            )
        self.grant_calls.append((ip, tuple(grants), ttl))


class LockScopeTestBase(unittest.TestCase):
    """Shared helpers: real SessionManager, fake firewall, observed conntrack."""

    def setUp(self) -> None:
        self.firewall = RecordingFirewall()
        self.manager = gateway.SessionManager(
            self.firewall, ttl=600, pending_ttl=60
        )
        self.firewall.manager = self.manager
        self.flush_calls: list[str] = []
        patcher = mock.patch.object(
            gateway, "conntrack_flush", self._record_flush
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _record_flush(self, ip: str, audit=None) -> bool:
        self.flush_calls.append(ip)
        return True

    def insert_session(self, session: gateway.Session) -> None:
        """Insert a session directly (without login's one-IP rule)."""
        with self.manager._lock:
            self.manager._sessions[session.token] = session

    def assert_locked_sole_call(self, *, only_grants: bool) -> None:
        """Assert exactly one revoke_all call, running under the lock."""
        self.assertEqual(len(self.firewall.calls), 1)
        self.assertTrue(self.firewall.lock_states[0])
        self.assertEqual(
            self.firewall.thread_ids[0], threading.get_ident()
        )
        _ip, _grants, discover, sent_only_grants = self.firewall.calls[0]
        self.assertFalse(discover)
        self.assertEqual(sent_only_grants, only_grants)


class LockScopeTests(LockScopeTestBase):
    """The firewall call runs under _lock for every affected operation."""

    def test_logout_revokes_under_lock(self) -> None:
        session = make_session("token-logout")
        self.insert_session(session)
        self.assertIs(self.manager.logout(session.token, IP), session)
        self.assert_locked_sole_call(only_grants=False)

    def test_terminate_revokes_under_lock(self) -> None:
        session = make_session("token-terminate")
        self.insert_session(session)
        self.assertIs(self.manager.terminate(session.sid), session)
        self.assert_locked_sole_call(only_grants=False)

    def test_revoke_user_revokes_under_lock(self) -> None:
        session = make_session("token-user")
        self.insert_session(session)
        self.assertEqual(self.manager.revoke_user("alice"), 1)
        self.assert_locked_sole_call(only_grants=False)

    def test_revoke_rule_revokes_under_lock(self) -> None:
        session = make_session("token-rule", rule="web")
        self.insert_session(session)
        self.assertEqual(self.manager.revoke_rule("web"), 1)
        self.assert_locked_sole_call(only_grants=False)

    def test_reap_once_revokes_under_lock(self) -> None:
        now = time.time()
        session = make_session("token-reap", expires=now - 1)
        self.insert_session(session)
        self.assertEqual(self.manager.reap_once(now=now), 1)
        self.assert_locked_sole_call(only_grants=False)

    def test_validate_expired_revokes_under_lock(self) -> None:
        session = make_session("token-validate")
        session.expires = time.time() - 1
        self.insert_session(session)

        self.assertIsNone(self.manager.validate(session.token, IP))

        self.assert_locked_sole_call(only_grants=False)


class PartialGrantTests(LockScopeTestBase):
    """With an active session, only the non-overlapping grants are deleted."""

    def test_logout_revokes_only_non_overlapping_grants(self) -> None:
        # The first session got 80 and 8080; the second (for the same
        # IP) got 80 and 443. 80 is shared, so only 8080 must be deleted.
        first = make_session("token-first", tcp=(80, 8080))
        second = make_session("token-second", tcp=(80, 443))
        self.insert_session(first)
        self.insert_session(second)

        self.assertIs(self.manager.logout(first.token, IP), first)

        self.assertEqual(len(self.firewall.calls), 1)
        ip, grants, discover, only_grants = self.firewall.calls[0]
        self.assertEqual(ip, IP)
        self.assertFalse(discover)
        self.assertTrue(only_grants)
        self.assertEqual(grants, (forward_ports(8080),))
        self.assertTrue(self.firewall.lock_states[0])
        # A partial deletion must not touch conntrack.
        self.assertEqual(self.flush_calls, [])
        # The second session remains untouched.
        self.assertIsNotNone(self.manager.validate(second.token, IP))
        self.assertIsNone(self.manager.validate(first.token, IP))

    def test_logout_clamps_remaining_grants_when_covers_all(self) -> None:
        # The first session got only 80, the second 80 and 443: the remaining
        # session covers every element, so nothing is deleted and conntrack
        # is not flushed. The surviving elements are re-issued with the
        # remaining session's TTL, because the departing session may have
        # granted a longer timeout.
        first = make_session("token-covered-first", tcp=(80,))
        second = make_session("token-covered-second", tcp=(80, 443))
        self.insert_session(first)
        self.insert_session(second)

        self.assertIs(self.manager.logout(first.token, IP), first)

        self.assertEqual(self.firewall.calls, [])
        self.assertEqual(len(self.firewall.grant_calls), 1)
        ip, grants, ttl = self.firewall.grant_calls[0]
        self.assertEqual(ip, IP)
        self.assertEqual(
            grants, (forward_ports(80, 443),)
        )
        self.assertGreaterEqual(ttl, 1)
        self.assertLessEqual(ttl, 600)
        self.assertEqual(self.flush_calls, [])
        self.assertIsNotNone(self.manager.validate(second.token, IP))

    def test_partial_revoke_failure_queues_only_remainder(self) -> None:
        # If the partial deletion fails, only the non-overlapping grant goes into
        # the pending queue, and no conntrack flush happens in that case either.
        first = make_session("token-fail-first", tcp=(80, 8080))
        second = make_session("token-fail-second", tcp=(80, 443))
        self.insert_session(first)
        self.insert_session(second)
        self.firewall.fail_next = True

        self.assertIs(self.manager.logout(first.token, IP), first)

        self.assertEqual(self.flush_calls, [])
        pending = self.manager._pending_for_ip(IP)
        self.assertEqual(len(pending), 1)
        _key, entry = pending[0]
        self.assertEqual(entry.grants, (forward_ports(8080),))
        self.assertFalse(entry.discover)
        self.assertEqual(self.manager.pending_count(), 1)
        self.assertEqual(self.firewall.grant_calls, [])
        self.assertIsNotNone(self.manager.validate(second.token, IP))


class FullRevokeTests(LockScopeTestBase):
    """Without an active session both the full revocation and the flush run."""

    def test_logout_without_remaining_session_flushes_conntrack(self) -> None:
        session = make_session("token-only", tcp=(80,))
        self.insert_session(session)

        self.assertIs(self.manager.logout(session.token, IP), session)

        self.assertEqual(len(self.firewall.calls), 1)
        ip, _grants, discover, only_grants = self.firewall.calls[0]
        self.assertEqual(ip, IP)
        self.assertFalse(discover)
        self.assertFalse(only_grants)
        self.assertEqual(self.flush_calls, [IP])

    def test_terminate_without_remaining_session_flushes_conntrack(self) -> None:
        session = make_session("token-term-only", tcp=(443,))
        self.insert_session(session)

        self.assertIs(self.manager.terminate(session.sid), session)

        self.assertEqual(len(self.firewall.calls), 1)
        _ip, _grants, discover, only_grants = self.firewall.calls[0]
        self.assertFalse(discover)
        self.assertFalse(only_grants)
        self.assertEqual(self.flush_calls, [IP])


class RetryOutsideLockTests(LockScopeTestBase):
    """reap_once calls the pending retry after releasing the lock."""

    def test_reap_once_retries_pending_outside_lock(self) -> None:
        observed: dict[str, object] = {}

        def fake_retry(now: float) -> int:
            observed["locked"] = self.manager._lock.locked()
            observed["thread"] = threading.get_ident()
            observed["now"] = now
            return 0

        self.manager._retry_pending_revocations = fake_retry
        now = time.time()
        self.assertEqual(self.manager.reap_once(now=now), 0)
        self.assertEqual(observed["locked"], False)
        self.assertEqual(observed["thread"], threading.get_ident())
        self.assertEqual(observed["now"], now)


if __name__ == "__main__":
    unittest.main()
