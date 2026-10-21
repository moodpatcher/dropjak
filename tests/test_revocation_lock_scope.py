#!/usr/bin/env python3
"""Az N4 hibajavítás tesztjei: a visszavonás a munkamenet-zár alatt fut.

A ``logout()``, ``terminate()``, ``revoke_user()``, ``revoke_rule()`` és
``reap_once()`` korábban a munkamenet eltávolítása után, a ``self._lock``
elengedése után hívta a tűzfalat. Egy párhuzamos ``authorize()`` így a
kettő közé ékelődhetett, és a visszavonás az éppen kiadott engedélyt is
törölhette. A javítás a tűzfal-mutációt ugyanazon zár alatt végzi, és ha az
IP-hez marad aktív munkamenet, csak a nem átfedő grantokat törli
(``only_grants=True``), conntrack-ürítés nélkül.

A tesztek determinisztikusak: nincs szál, nincs alvás. A hamis tűzfal a
hívás pillanatában ellenőrzi, hogy a ``SessionManager._lock`` zarolva van-e
és hogy a várt szálon fut-e a hívás.
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
    """Egy forward irányú, TCP-portokból álló grant."""
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
    """Egy engedélyezett (vagy függő) munkamenet a valódi dataclassból."""
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
    """A ``revoke_all`` hívásokat rögzítő, zárállapotot ellenőrző tűzfal.

    A hívás pillanatában AssertionError-t dob, ha a munkamenet-zár nincs
    tartva, vagy ha a hívás nem a várt (fő) szálon fut. Így a hibás
    zárolási sorrend azonnal, determinisztikusan megbukik.
    """

    def __init__(self) -> None:
        self.manager: gateway.SessionManager | None = None
        self.expected_thread = threading.get_ident()
        self.calls: list[tuple[str, tuple[gateway.Ports, ...], bool, bool]] = []
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
                "a firewall.revoke_all nem a SessionManager._lock alatt futott"
            )
        if threading.get_ident() != self.expected_thread:
            raise AssertionError(
                "a firewall.revoke_all nem a várt szálon futott"
            )
        self.lock_states.append(locked)
        self.thread_ids.append(threading.get_ident())
        self.calls.append(
            (ip, tuple(grants), bool(discover), bool(only_grants))
        )
        if self.fail_next:
            self.fail_next = False
            raise gateway.FirewallError("szimulált nft hiba")

    def grant_all(self, ip: str, grants, ttl: int) -> None:
        raise AssertionError("a teszt nem vár grant_all hívást")


class LockScopeTestBase(unittest.TestCase):
    """Közös segédek: valódi SessionManager, hamis tűzfal, figyelt conntrack."""

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
        """Munkamenet közvetlen beillesztése (a login egy-IP-szabálya nélkül)."""
        with self.manager._lock:
            self.manager._sessions[session.token] = session

    def assert_locked_sole_call(self, *, only_grants: bool) -> None:
        """Pontosan egy, a zár alatt futó revoke_all hívás ellenőrzése."""
        self.assertEqual(len(self.firewall.calls), 1)
        self.assertTrue(self.firewall.lock_states[0])
        self.assertEqual(
            self.firewall.thread_ids[0], threading.get_ident()
        )
        _ip, _grants, discover, sent_only_grants = self.firewall.calls[0]
        self.assertFalse(discover)
        self.assertEqual(sent_only_grants, only_grants)


class LockScopeTests(LockScopeTestBase):
    """A tűzfal-hívás minden érintett műveletnél a _lock alatt fut."""

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
    """Aktív munkamenet mellett csak a nem átfedő grantok törlődnek."""

    def test_logout_revokes_only_non_overlapping_grants(self) -> None:
        # Az első munkamenet 80-at és 8080-at kapott; a második (ugyanarra
        # az IP-re) 80-at és 443-at. A 80 közös, ezért csak a 8080 törlendő.
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
        # Részleges törlésnél a conntrack-hoz nem szabad nyúlni.
        self.assertEqual(self.flush_calls, [])
        # A második munkamenet érintetlen marad.
        self.assertIsNotNone(self.manager.validate(second.token, IP))
        self.assertIsNone(self.manager.validate(first.token, IP))

    def test_logout_skips_firewall_when_remaining_session_covers_all(self) -> None:
        # Az első munkamenet csak 80-at kapott, a második 80-at és 443-at:
        # a maradó munkamenet minden elemet lefed, ezért nincs tűzfal-hívás
        # és nincs conntrack-ürítés sem.
        first = make_session("token-covered-first", tcp=(80,))
        second = make_session("token-covered-second", tcp=(80, 443))
        self.insert_session(first)
        self.insert_session(second)

        self.assertIs(self.manager.logout(first.token, IP), first)

        self.assertEqual(self.firewall.calls, [])
        self.assertEqual(self.flush_calls, [])
        self.assertIsNotNone(self.manager.validate(second.token, IP))

    def test_partial_revoke_failure_queues_only_remainder(self) -> None:
        # Ha a részleges törlés hibázik, csak a nem átfedő grant kerül a
        # függő sorba, és conntrack-ürítés ilyenkor sem történik.
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
        self.assertIsNotNone(self.manager.validate(second.token, IP))


class FullRevokeTests(LockScopeTestBase):
    """Aktív munkamenet nélkül a teljes visszavonás és a flush is lefut."""

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
    """A reap_once a függő újrapróbálkozást a zár elengedése után hívja."""

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
