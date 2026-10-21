#!/usr/bin/env python3
"""Az audit F1/F2 javításainak tesztjei.

F1: a sikertelen tűzfal-visszavonás nem vész el, hanem korlátozott,
növekvő várakozású újrapróbálkozó sorba kerül; a munkamenet azonnal
megszűnik, és a ``revoke_ip`` munkamenet nélkül is felderíti az árva
elemeket.

F2: a ``HV_FLUSH_ON_START`` ugyanazt az igaz/hamis értelmezést használja,
mint a többi logikai változó, és kikapcsolt ürítés esetén alapértelmezésben
mégis egyezteti a dinamikus halmazokat (kivéve a kifejezett, nem biztonságos
``HV_ALLOW_STALE_GRANTS_ON_START=1`` opt-int).

A tesztek nem nyúlnak valódi nftables-hez: a F1 tesztek apró hamis
tűzfalat használnak, a felderítés tesztje pedig a test_gateway FakeTools
segédjét.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# A FakeTools a meglévő tesztekből származik; a discovery a tests
# könyvtárat teszi az importútra, ezért ez közvetlenül elérhető.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import gateway  # noqa: E402
from test_gateway import FakeTools  # noqa: E402

ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"
IP = "192.168.50.23"
OTHER_IP = "192.168.50.24"


def make_rule(
    rule_id: str,
    tcp=(80,),
    direction: str = "forward",
    icmp: bool = False,
) -> gateway.Rule:
    return gateway.Rule(
        id=rule_id,
        label=rule_id,
        description="",
        tcp=tuple(tcp),
        icmp=icmp,
        direction=direction,
    )


class FlakyFirewall:
    """A első N ``revoke_all`` hívást elbukó, egyébként sikeres tűzfal."""

    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.revoke_calls: list[tuple[str, tuple, bool, bool]] = []
        self.exact_calls: list[tuple[str, tuple]] = []
        self.grant_calls: list[tuple[str, tuple, int]] = []

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
        if self.failures > 0:
            self.failures -= 1
            raise gateway.FirewallError("átmeneti nft hiba")

    def revoke_exact(self, ip: str, grants=()) -> None:
        self.exact_calls.append((ip, tuple(grants)))
        if self.failures > 0:
            self.failures -= 1
            raise gateway.FirewallError("átmeneti nft hiba")

    def grant_all(self, ip: str, grants, ttl: int) -> None:
        self.grant_calls.append((ip, tuple(grants), ttl))


class RecordingFlushFirewall:
    def __init__(self, fail: bool = False) -> None:
        self.flush_calls = 0
        self.fail = fail

    def flush(self) -> None:
        self.flush_calls += 1
        if self.fail:
            raise gateway.FirewallError("nft flush hiba")


class LockRaceFirewall:
    """Discovery törlés közben egy authorize() versenyét szimulálja.

    A retry alatt induló authorize() csak akkor tud a discovery elé
    kerülni, ha a retry nem tartja a munkamenet-zárat. A hamis tűzfal a
    nem blokkoló zárszerzéssel észleli ezt, és a hibás esetben megvárja,
    hogy az authorize() engedélyt adjon, majd a discovery törli azt is.
    """

    def __init__(self, manager) -> None:
        self.manager = manager
        self.fail_once = True
        self.elements: dict[str, set[gateway.Ports]] = {}
        self.revoke_entered = threading.Event()
        self.grant_done = threading.Event()
        self.lock_held_during_revoke: bool | None = None
        self.discovery_ran = False

    def revoke_all(
        self,
        ip: str,
        grants=(),
        discover: bool = False,
        only_grants: bool = False,
    ) -> None:
        if self.fail_once:
            self.fail_once = False
            raise gateway.FirewallError("kezdeti nft hiba")
        if not discover:
            bucket = self.elements.setdefault(ip, set())
            if only_grants:
                for part in grants:
                    bucket.discard(part)
            else:
                bucket.clear()
            return
        # Ha a retry a zár alatt fut, a nem blokkoló szerzés False-t ad,
        # mert ugyanaz a szál tartja a zárat. Ha nem, megkapjuk, majd
        # elengedjük, hogy az authorize() beszaladhasson.
        acquired = self.manager._lock.acquire(blocking=False)
        self.lock_held_during_revoke = not acquired
        self.revoke_entered.set()
        if acquired:
            self.manager._lock.release()
            self.grant_done.wait(1.0)
        self.elements.pop(ip, None)
        self.discovery_ran = True

    def grant_all(self, ip: str, grants, ttl: int) -> None:
        bucket = self.elements.setdefault(ip, set())
        for part in grants:
            bucket.add(part)
        self.grant_done.set()


class RevocationTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.audit = gateway.AuditLog(
            os.path.join(self.tmp.name, "audit.jsonl"),
            logger=lambda *_: None,
        )
        self._old_conntrack = gateway.CONNTRACK_BIN
        self._old_dry_run = gateway.DRY_RUN
        gateway.DRY_RUN = False
        self.addCleanup(
            setattr, gateway, "CONNTRACK_BIN", self._old_conntrack
        )
        self.addCleanup(setattr, gateway, "DRY_RUN", self._old_dry_run)
        self.conn_log = os.path.join(self.tmp.name, "conntrack.log")
        self.conntrack = os.path.join(self.tmp.name, "conntrack")
        with open(self.conntrack, "w", encoding="utf-8") as fh:
            fh.write(
                "#!/bin/sh\n"
                f'printf \'%s\\n\' "$*" >> "{self.conn_log}"\n'
                "exit 0\n"
            )
        os.chmod(self.conntrack, 0o755)
        gateway.CONNTRACK_BIN = self.conntrack

    def conntrack_lines(self) -> list[str]:
        try:
            with open(self.conn_log, encoding="utf-8") as fh:
                return fh.read().splitlines()
        except FileNotFoundError:
            return []

    def make_manager(self, firewall) -> gateway.SessionManager:
        return gateway.SessionManager(
            firewall, ttl=3600, pending_ttl=600, audit=self.audit
        )

    def login_and_authorize(
        self,
        manager: gateway.SessionManager,
        rule: gateway.Rule,
        ip: str = IP,
    ) -> gateway.Session:
        session = manager.login("alice", ip)
        return manager.authorize(session.token, ip, rule, 60)

    def firewall_errors(self) -> list[dict]:
        return self.audit.read(event="firewall_error")


class PendingRevocationTests(RevocationTestBase):
    def test_backoff_schedule_is_capped(self) -> None:
        manager = self.make_manager(FlakyFirewall())
        self.assertEqual(
            [manager._pending_delay(i) for i in range(6)],
            [5, 15, 60, 300, 600, 600],
        )

    def _assert_revoked_and_queued(
        self,
        manager: gateway.SessionManager,
        session: gateway.Session,
        ip: str = IP,
    ) -> None:
        self.assertIsNone(manager.validate(session.token, ip))
        self.assertEqual(manager.count(), 0)
        self.assertEqual(manager.pending_count(), 1)
        self.assertTrue(
            any(line.strip() == f"-D -s {ip}" for line in self.conntrack_lines()),
            self.conntrack_lines(),
        )
        errors = self.firewall_errors()
        self.assertTrue(errors)
        self.assertEqual(errors[0]["ip"], ip)
        self.assertEqual(errors[0]["operation"], "revoke_all")

    def _retry_and_assert_cleared(
        self, manager: gateway.SessionManager, firewall: FlakyFirewall
    ) -> None:
        before = len(firewall.revoke_calls)
        # Bőven a lejárat és a hátralévő backoff után járunk.
        manager.reap_once(now=time.time() + 1_000_000)
        self.assertEqual(manager.pending_count(), 0)
        self.assertGreater(len(firewall.revoke_calls), before)

    def test_terminate_failure_is_queued_and_retried(self) -> None:
        firewall = FlakyFirewall(failures=1)
        manager = self.make_manager(firewall)
        session = self.login_and_authorize(manager, make_rule("web"))

        self.assertIsNotNone(manager.terminate(session.sid))
        self._assert_revoked_and_queued(manager, session)
        self._retry_and_assert_cleared(manager, firewall)

    def test_logout_failure_is_queued_and_retried(self) -> None:
        firewall = FlakyFirewall(failures=1)
        manager = self.make_manager(firewall)
        session = self.login_and_authorize(manager, make_rule("web"))

        self.assertIsNotNone(manager.logout(session.token, IP))
        self._assert_revoked_and_queued(manager, session)
        self._retry_and_assert_cleared(manager, firewall)

    def test_revoke_user_failure_is_queued_and_retried(self) -> None:
        firewall = FlakyFirewall(failures=1)
        manager = self.make_manager(firewall)
        session = self.login_and_authorize(manager, make_rule("web"))

        self.assertEqual(manager.revoke_user("alice"), 1)
        self._assert_revoked_and_queued(manager, session)
        self._retry_and_assert_cleared(manager, firewall)

    def test_revoke_rule_failure_is_queued_and_retried(self) -> None:
        firewall = FlakyFirewall(failures=1)
        manager = self.make_manager(firewall)
        session = self.login_and_authorize(manager, make_rule("web"))

        self.assertEqual(manager.revoke_rule("web"), 1)
        self._assert_revoked_and_queued(manager, session)
        self._retry_and_assert_cleared(manager, firewall)

    def test_revoke_ip_failure_is_queued_and_retried(self) -> None:
        firewall = FlakyFirewall(failures=1)
        manager = self.make_manager(firewall)
        session = self.login_and_authorize(manager, make_rule("web"))

        self.assertEqual(manager.revoke_ip(IP, reason="fail2ban"), 1)
        self._assert_revoked_and_queued(manager, session)
        # A revoke_ip munkamenet nélkül is felderít, ezért discover=True.
        self.assertTrue(firewall.revoke_calls[-1][2])
        self._retry_and_assert_cleared(manager, firewall)

    def test_reaper_failure_is_queued_and_retried(self) -> None:
        # Az első hiba a lejáratkori visszavonásé; a reap_once a saját
        # újrapróbálkozását is lefuttatja, ezért két hibát injektálunk.
        firewall = FlakyFirewall(failures=2)
        manager = self.make_manager(firewall)
        session = self.login_and_authorize(manager, make_rule("web"))
        with manager._lock:
            manager._sessions[session.token] = gateway.replace(
                manager._sessions[session.token], expires=time.time() - 1
            )

        self.assertEqual(manager.reap_once(now=time.time() + 7200), 1)
        self.assertIsNone(manager.validate(session.token, IP))
        self.assertEqual(manager.count(), 0)
        self.assertEqual(manager.pending_count(), 1)
        self.assertTrue(self.firewall_errors())
        self.assertTrue(
            any(
                line.strip() == f"-D -s {IP}"
                for line in self.conntrack_lines()
            )
        )

        # A harmadik hívás már sikerül; a sor kiürül.
        self._retry_and_assert_cleared(manager, firewall)

    def test_reauth_failure_drops_session_and_never_grants(self) -> None:
        # Az első hiba a pontos, részleges törlésé, a második a teljes
        # takarításé; ilyenkor a régi+új unió a függő sorba kerül.
        firewall = FlakyFirewall(failures=2)
        manager = self.make_manager(firewall)
        session = self.login_and_authorize(manager, make_rule("web"))
        self.assertEqual(len(firewall.grant_calls), 1)

        # A tűzfalhiba nem klienshiba: a szerver 503-mal válaszol rá.
        with self.assertRaises(gateway.FirewallError):
            manager.authorize(
                session.token, IP, make_rule("icmp", tcp=(), icmp=True), 60
            )

        # A régi munkamenet nem maradhat engedélyre hivatkozva, és új
        # engedély sem került a kernelbe.
        self.assertIsNone(manager.validate(session.token, IP))
        self.assertEqual(manager.count(), 0)
        self.assertEqual(len(firewall.grant_calls), 1)
        self.assertEqual(manager.pending_count(), 1)
        self.assertTrue(
            any(
                line.strip() == f"-D -s {IP}"
                for line in self.conntrack_lines()
            )
        )
        operations = [row["operation"] for row in self.firewall_errors()]
        self.assertIn("authorize_revoke", operations)

        # Az újrapróbálkozás a háttérben letisztítja a régi grantot.
        manager.reap_once(now=time.time() + 3600)
        self.assertEqual(manager.pending_count(), 0)

    def test_login_replacement_failure_drops_old_session(self) -> None:
        firewall = FlakyFirewall(failures=1)
        manager = self.make_manager(firewall)
        self.login_and_authorize(manager, make_rule("web"))

        with self.assertRaises(gateway.FirewallError):
            manager.login("alice", IP)

        self.assertEqual(manager.count(), 0)
        self.assertEqual(manager.pending_count(), 1)
        self.assertTrue(self.firewall_errors())

        manager.reap_once(now=time.time() + 3600)
        self.assertEqual(manager.pending_count(), 0)

    def test_retry_drops_fully_overlapped_entry_without_firewall_call(self) -> None:
        firewall = FlakyFirewall(failures=1)
        manager = self.make_manager(firewall)
        rule = make_rule("web")
        # Kézileg sikertelen visszavonás ugyanarra az IP-re.
        self.assertFalse(manager._revoke_access(IP, (rule.ports,)))
        self.assertEqual(manager.pending_count(), 1)

        session = self.login_and_authorize(manager, rule)
        self.assertIsNotNone(manager.validate(session.token, IP))
        calls_before = len(firewall.revoke_calls)
        conntrack_before = len(self.conntrack_lines())

        # Az új munkamenet grantja teljesen lefedi a régi bejegyzést.
        # Ilyenkor nincs mit törölni: a bejegyzés megszűnik, a tűzfalhoz
        # nem megy újabb hívás, és az új munkamenet conntrack kapcsolatai
        # is érintetlenek maradnak.
        manager._retry_pending_revocations(time.time() + 10)
        self.assertEqual(len(firewall.revoke_calls), calls_before)
        self.assertEqual(manager.pending_count(), 0)
        self.assertEqual(len(self.conntrack_lines()), conntrack_before)
        self.assertIsNotNone(manager.validate(session.token, IP))

    def test_empty_non_discovery_entry_retries_unconditional_cleanup(self) -> None:
        firewall = FlakyFirewall(failures=1)
        manager = self.make_manager(firewall)
        # Üres grantlista mellett is lehet sikertelen a teljes/ICMP/MAC
        # elemek törlése; ezt a retrynak újra kell próbálnia, nem szabad
        # csak azért eldobni a bejegyzést, mert nincs portgrant.
        self.assertFalse(manager._revoke_access(IP, ()))
        self.assertEqual(manager.pending_count(), 1)
        calls_before = len(firewall.revoke_calls)

        manager._retry_pending_revocations(time.time() + 10)
        self.assertEqual(manager.pending_count(), 0)
        self.assertEqual(len(firewall.revoke_calls), calls_before + 1)
        _ip, grants, discover, only_grants = firewall.revoke_calls[-1]
        self.assertEqual(grants, ())
        self.assertFalse(discover)
        self.assertFalse(only_grants)

    def test_retry_deletes_only_old_non_overlapping_grants(self) -> None:
        firewall = FlakyFirewall(failures=1)
        manager = self.make_manager(firewall)
        old_rule = make_rule("old", tcp=(80,))
        old_session = self.login_and_authorize(manager, old_rule)
        self.assertIsNotNone(manager.terminate(old_session.sid))
        self.assertEqual(manager.pending_count(), 1)

        new_session = self.login_and_authorize(
            manager, make_rule("new", tcp=(443,))
        )
        self.assertIsNotNone(manager.validate(new_session.token, IP))
        calls_before = len(firewall.revoke_calls)
        exact_before = len(firewall.exact_calls)
        conntrack_before = len(self.conntrack_lines())

        # Csak a régi TCP 80 törlődik; a TCP 443 az új munkameneté. A
        # részleges törlés pontos, elemszintű művelet (revoke_exact), nem
        # teljes revoke_all.
        manager._retry_pending_revocations(time.time() + 10)
        self.assertEqual(manager.pending_count(), 0)
        self.assertEqual(len(firewall.revoke_calls), calls_before)
        self.assertEqual(len(firewall.exact_calls), exact_before + 1)
        ip, grants = firewall.exact_calls[-1]
        self.assertEqual(ip, IP)
        self.assertEqual(
            grants, (gateway.Ports(tcp=(80,), direction="forward"),)
        )
        self.assertNotIn(
            443, [port for part in grants for port in part.tcp]
        )
        self.assertEqual(len(self.conntrack_lines()), conntrack_before)
        self.assertIsNotNone(manager.validate(new_session.token, IP))

    def test_retry_keeps_overlap_and_deletes_other_old_grants(self) -> None:
        firewall = FlakyFirewall(failures=1)
        manager = self.make_manager(firewall)
        old_rule = make_rule("old", tcp=(80, 8080))
        old_session = self.login_and_authorize(manager, old_rule)
        self.assertIsNotNone(manager.terminate(old_session.sid))
        self.assertEqual(manager.pending_count(), 1)

        new_session = self.login_and_authorize(
            manager, make_rule("new", tcp=(80, 443))
        )
        calls_before = len(firewall.revoke_calls)
        exact_before = len(firewall.exact_calls)
        conntrack_before = len(self.conntrack_lines())

        manager._retry_pending_revocations(time.time() + 10)
        self.assertEqual(manager.pending_count(), 0)
        self.assertEqual(len(firewall.revoke_calls), calls_before)
        self.assertEqual(len(firewall.exact_calls), exact_before + 1)
        _ip, grants = firewall.exact_calls[-1]
        ports = [port for part in grants for port in part.tcp]
        self.assertEqual(ports, [8080])
        self.assertNotIn(80, ports)
        self.assertNotIn(443, ports)
        self.assertEqual(len(self.conntrack_lines()), conntrack_before)
        self.assertIsNotNone(manager.validate(new_session.token, IP))

    def test_discovery_entry_waits_for_active_session(self) -> None:
        firewall = FlakyFirewall(failures=1)
        manager = self.make_manager(firewall)
        rule = make_rule("new", tcp=(443,))
        session = self.login_and_authorize(manager, rule)
        # Fail2ban/pánik esetén a revoke_ip felderítést kér, miközben az
        # IP-hez aktív munkamenet tartozik.
        self.assertFalse(
            manager._revoke_access(IP, (rule.ports,), discover=True)
        )
        self.assertEqual(manager.pending_count(), 1)
        calls_before = len(firewall.revoke_calls)
        conntrack_before = len(self.conntrack_lines())

        # Aktív munkamenet mellett nincs felderítés (az a 443-at is
        # törölné), és a bejegyzés is megmarad.
        manager._retry_pending_revocations(time.time() + 10)
        self.assertEqual(len(firewall.revoke_calls), calls_before)
        self.assertEqual(manager.pending_count(), 1)
        self.assertEqual(len(self.conntrack_lines()), conntrack_before)
        self.assertIsNotNone(manager.validate(session.token, IP))

        # A munkamenet megszűnése után a felderítés lefut és a bejegyzés
        # kiürül.
        manager.terminate(session.sid)
        self.assertEqual(manager.pending_count(), 1)
        calls_after_terminate = len(firewall.revoke_calls)
        self.assertEqual(calls_after_terminate, calls_before + 1)
        manager._retry_pending_revocations(time.time() + 100)
        self.assertEqual(manager.pending_count(), 0)
        self.assertEqual(
            len(firewall.revoke_calls), calls_after_terminate + 1
        )
        _ip, grants, discover, only_grants = firewall.revoke_calls[-1]
        self.assertTrue(discover)
        self.assertFalse(only_grants)
        self.assertEqual(grants, (rule.ports,))

    def test_retry_holds_session_lock_during_discovery_mutation(self) -> None:
        firewall = LockRaceFirewall(None)
        manager = self.make_manager(firewall)
        firewall.manager = manager
        # Kezdeti sikertelen discovery: függő bejegyzés.
        self.assertFalse(manager._revoke_access(IP, (), discover=True))
        self.assertEqual(manager.pending_count(), 1)

        token = manager.login("bob", IP).token
        rule = make_rule("new", tcp=(443,))
        errors: list[BaseException] = []

        def _authorize() -> None:
            # Csak akkor indul, amikor a retry már a tűzfal-hívásban van.
            firewall.revoke_entered.wait(5.0)
            try:
                manager.authorize(token, IP, rule, 60)
            except BaseException as exc:  # a szál hibáját a teszt jelzi
                errors.append(exc)

        thread = threading.Thread(target=_authorize)
        thread.start()
        manager._retry_pending_revocations(time.time() + 10)
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(firewall.discovery_ran)
        self.assertTrue(firewall.lock_held_during_revoke)
        self.assertEqual(manager.pending_count(), 0)
        self.assertIsNotNone(manager.validate(token, IP))
        # A discovery után engedélyezett munkamenet grantja megmaradt.
        self.assertIn(rule.ports, firewall.elements.get(IP, set()))

    def test_retry_audit_is_sampled_not_every_attempt(self) -> None:
        firewall = FlakyFirewall(failures=1000)
        manager = self.make_manager(firewall)
        manager.PENDING_AUDIT_EVERY = 3
        self.assertFalse(manager._revoke_access(IP, (make_rule("web").ports,)))
        initial = len(self.firewall_errors())
        self.assertEqual(initial, 1)

        now = time.time()
        for index in range(1, 6):
            manager._retry_pending_revocations(now + index * 10000)
        # 5 sikertelen újrapróbálkozásból csak a 3. auditált.
        self.assertEqual(len(self.firewall_errors()), initial + 1)
        self.assertEqual(manager.pending_count(), 1)

    def test_ledger_is_bounded_and_logs_loudly(self) -> None:
        firewall = FlakyFirewall(failures=1000)
        manager = self.make_manager(firewall)
        manager.PENDING_LIMIT = 3
        for index in range(5):
            self.assertFalse(
                manager._revoke_access(f"10.0.0.{index + 1}", ())
            )
        self.assertEqual(manager.pending_count(), 3)
        # A tele sor eseménye a meglévő, címkézett firewall_error esemény,
        # ezért az audit-UI nem igényel új címkét.
        rows = [
            row for row in self.audit.read(event="firewall_error")
            if row.get("operation") == "revoke_all_ledger_full"
        ]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["severity"], "alert")


class DiscoveryTests(RevocationTestBase):
    def test_revoke_ip_without_session_removes_orphaned_elements(self) -> None:
        tools = FakeTools(self.tmp.name)
        gateway.CONNTRACK_BIN = str(tools.conntrack)
        tools.set_json("allowed_input_tcp", [
            {"val": {"concat": [IP, 22]}, "timeout": 60, "expires": 60},
            {"val": {"concat": [OTHER_IP, 22]}, "timeout": 60, "expires": 60},
        ])
        tools.set_json("allowed_input_udp", [
            {"val": {"concat": [IP, 5353]}, "timeout": 60, "expires": 60},
        ])
        tools.set_json("allowed_tcp", [
            {"val": {"concat": [IP, 80]}, "timeout": 60, "expires": 60},
            {"val": {"concat": [OTHER_IP, 80]}, "timeout": 60, "expires": 60},
        ])
        tools.set_json("allowed_udp", [
            {"val": {"concat": [IP, 443]}, "timeout": 60, "expires": 60},
        ])
        firewall = gateway.Firewall(
            binary=str(tools.nft), dry_run=False, logger=lambda *_: None
        )
        manager = self.make_manager(firewall)

        # Nincs munkamenet: a grantlista üres, a felderítésnek kell törölnie.
        self.assertEqual(manager.revoke_ip(IP), 0)

        deletes = tools.deletes()
        for expected in (
            f"nft delete element inet hatarvedelem allowed_v4 {{ {IP} }}",
            f"nft delete element inet hatarvedelem allowed_icmp {{ {IP} }}",
            f"nft delete element inet hatarvedelem allowed_input_tcp "
            f"{{ {IP} . 22 }}",
            f"nft delete element inet hatarvedelem allowed_input_udp "
            f"{{ {IP} . 5353 }}",
            f"nft delete element inet hatarvedelem allowed_tcp "
            f"{{ {IP} . 80 }}",
            f"nft delete element inet hatarvedelem allowed_udp "
            f"{{ {IP} . 443 }}",
        ):
            self.assertIn(expected, deletes)
        # Más IP elemét nem törli.
        self.assertFalse(
            any(OTHER_IP in line for line in deletes), deletes
        )
        self.assertEqual(manager.pending_count(), 0)


class StartupFlushTests(unittest.TestCase):
    def _gateway(self, firewall) -> gateway.Gateway:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        instance = object.__new__(gateway.Gateway)
        instance.firewall = firewall
        instance.audit = gateway.AuditLog(
            os.path.join(directory, "audit.jsonl"),
            logger=lambda *_: None,
        )
        return instance

    def test_bool_parsing_matches_gateway_env_bool(self) -> None:
        cases = {
            "1": True, "true": True, "TRUE": True, "yes": True,
            " on ": True, "0": False, "false": False, "off": False,
            "": True, "ismeretlen": True,
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                with mock.patch.dict(
                    os.environ, {"HV_FLUSH_ON_START": raw}, clear=False
                ):
                    self.assertEqual(
                        gateway._env_bool("HV_FLUSH_ON_START", True),
                        expected,
                    )

    def test_startup_decision_matrix(self) -> None:
        self.assertEqual(
            gateway._startup_flush_mode(True, False), "flush"
        )
        self.assertEqual(
            gateway._startup_flush_mode(True, True), "flush"
        )
        self.assertEqual(
            gateway._startup_flush_mode(False, False), "reconcile"
        )
        self.assertEqual(
            gateway._startup_flush_mode(False, True), "stale_allowed"
        )

    def test_disabled_flush_reconciles_by_default(self) -> None:
        firewall = RecordingFlushFirewall()
        instance = self._gateway(firewall)
        with mock.patch.object(gateway, "FLUSH_ON_START", False), \
                mock.patch.object(
                    gateway, "ALLOW_STALE_GRANTS_ON_START", False
                ), \
                mock.patch.object(gateway, "log") as logged:
            instance._startup_flush()
        self.assertEqual(firewall.flush_calls, 1)
        text = "\n".join(str(call) for call in logged.call_args_list)
        self.assertIn("HV_FLUSH_ON_START hatásos értéke: 0", text)
        self.assertIn("memóriabeli", text)
        self.assertEqual(
            instance.audit.read(event="firewall_error"), []
        )

    def test_unsafe_opt_in_skips_flush_and_warns_loudly(self) -> None:
        firewall = RecordingFlushFirewall()
        instance = self._gateway(firewall)
        with mock.patch.object(gateway, "FLUSH_ON_START", False), \
                mock.patch.object(
                    gateway, "ALLOW_STALE_GRANTS_ON_START", True
                ), \
                mock.patch.object(gateway, "log") as logged:
            instance._startup_flush()
        self.assertEqual(firewall.flush_calls, 0)
        text = "\n".join(str(call) for call in logged.call_args_list)
        self.assertIn("FIGYELEM", text)
        self.assertIn("HV_ALLOW_STALE_GRANTS_ON_START=1", text)
        self.assertIn("munkamenet nélkül", text)

    def test_enabled_flush_flushes(self) -> None:
        firewall = RecordingFlushFirewall()
        instance = self._gateway(firewall)
        with mock.patch.object(gateway, "FLUSH_ON_START", True), \
                mock.patch.object(
                    gateway, "ALLOW_STALE_GRANTS_ON_START", False
                ), \
                mock.patch.object(gateway, "log"):
            instance._startup_flush()
        self.assertEqual(firewall.flush_calls, 1)

    def test_flush_failure_stops_startup_and_audits(self) -> None:
        firewall = RecordingFlushFirewall(fail=True)
        instance = self._gateway(firewall)
        with mock.patch.object(gateway, "FLUSH_ON_START", False), \
                mock.patch.object(
                    gateway, "ALLOW_STALE_GRANTS_ON_START", False
                ), \
                mock.patch.object(gateway, "log"):
            with self.assertRaises(gateway.FirewallError):
                instance._startup_flush()
        rows = instance.audit.read(event="firewall_error")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["operation"], "flush")


class EntrypointFlushParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = ENTRYPOINT.read_text(encoding="utf-8")

    def _env_bool_function(self) -> str:
        start = self.text.index("env_bool() {")
        end = self.text.index("\n}", start) + 2
        return self.text[start:end]

    def _run(self, value: str | None) -> str:
        script = self._env_bool_function() + "\nenv_bool HV_FLUSH_ON_START 1\n"
        env = os.environ.copy()
        if value is None:
            env.pop("HV_FLUSH_ON_START", None)
        else:
            env["HV_FLUSH_ON_START"] = value
        result = subprocess.run(
            ["sh", "-c", script],
            env=env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_shell_env_bool_accepts_gateway_spellings(self) -> None:
        for value in ("1", "true", "TRUE", " yes ", "on", "ON"):
            with self.subTest(value=value):
                self.assertEqual(self._run(value), "1")
        for value in ("0", "false", "off", "OFF"):
            with self.subTest(value=value):
                self.assertEqual(self._run(value), "0")
        # Üres/ismeretlen/beállítatlan: az alapértelmezés (itt 1).
        for value in ("", "ismeretlen", None):
            with self.subTest(value=value):
                self.assertEqual(self._run(value), "1")

    def test_startup_uses_safe_reconcile_unless_opt_in(self) -> None:
        self.assertIn(
            'flush_on_start=$(env_bool HV_FLUSH_ON_START 1)', self.text
        )
        self.assertIn(
            "allow_stale_grants=$(env_bool "
            "HV_ALLOW_STALE_GRANTS_ON_START 0)",
            self.text,
        )
        self.assertIn(
            'if [ "$flush_on_start" != "1" ] '
            '&& [ "$allow_stale_grants" = "1" ]',
            self.text,
        )
        # Az ürítő ciklus a biztonságos ágban marad, és a hiba továbbra is
        # leállítja az indulást.
        block_start = self.text.index("flush_on_start=$(env_bool")
        block_end = self.text.index("# A korábbi verziók host_ssh_v4", block_start)
        block = self.text[block_start:block_end]
        self.assertIn('for hv_set in', block)
        self.assertIn('|| die "a(z) $hv_set halmaz ürítése nem sikerült"', block)
        self.assertIn("HV_ALLOW_STALE_GRANTS_ON_START=1", block)


class EntrypointBooleanFlagsTests(unittest.TestCase):
    """N3: minden logikai kapcsoló az env_bool() értelmezését használja.

    A korábbi pontos ``= "1"`` összehasonlítások a ``true``/``yes``/``on``
    értékeket figyelmen kívül hagyták (a watchdog esetében épp fordítva).
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = ENTRYPOINT.read_text(encoding="utf-8")
        cls.compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        cls.env_example = (ROOT / ".env.example").read_text(encoding="utf-8")

    def _env_bool_function(self) -> str:
        start = self.text.index("env_bool() {")
        end = self.text.index("\n}", start) + 2
        return self.text[start:end]

    def _run(self, name: str, default: str, value: str | None) -> str:
        script = (
            self._env_bool_function()
            + f"\nenv_bool {name} {default}\n"
        )
        env = os.environ.copy()
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
        result = subprocess.run(
            ["sh", "-c", script],
            env=env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_env_bool_executes_for_each_flag(self) -> None:
        for name, default in (
            ("HV_RUN_AS_ROOT", "0"),
            ("HV_FIREWALL_WATCHDOG", "1"),
            ("HV_SKIP_FIREWALL", "0"),
        ):
            for value in ("1", "true", "TRUE", " yes ", "on", "ON"):
                with self.subTest(name=name, value=value):
                    self.assertEqual(self._run(name, default, value), "1")
            for value in ("0", "false", "no", "off", "OFF"):
                with self.subTest(name=name, value=value):
                    self.assertEqual(self._run(name, default, value), "0")
            # Üres/ismeretlen/beállítatlan: az alapértelmezés.
            for value in ("", "ismeretlen", None):
                with self.subTest(name=name, value=value):
                    self.assertEqual(self._run(name, default, value), default)

    def test_flags_no_longer_compare_the_raw_value_to_one(self) -> None:
        for expected in (
            '[ "$(env_bool HV_RUN_AS_ROOT 0)" = "1" ]',
            '[ "$(env_bool HV_FIREWALL_WATCHDOG 1)" = "1" ]',
            "skip_firewall=$(env_bool HV_SKIP_FIREWALL 0)",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.text)
        for old in (
            '[ "${HV_RUN_AS_ROOT:-0}" = "1" ]',
            '[ "${HV_FIREWALL_WATCHDOG:-1}" = "1" ]',
            '[ "${HV_SKIP_FIREWALL:-0}" = "1" ]',
        ):
            with self.subTest(old=old):
                self.assertNotIn(old, self.text)

    def test_compose_forwards_boolean_flags(self) -> None:
        # A Compose-whitelist továbbítja a biztonságos alapértelmezésű
        # opt-int és a watchdog kapcsolóját is.
        self.assertIn(
            "HV_ALLOW_STALE_GRANTS_ON_START: "
            "${HV_ALLOW_STALE_GRANTS_ON_START:-0}",
            self.compose,
        )
        self.assertIn(
            "HV_FIREWALL_WATCHDOG: ${HV_FIREWALL_WATCHDOG:-1}",
            self.compose,
        )
        # A mintafájl figyelmeztet a nem biztonságos opt-inra, és leírja a
        # watchdog kikapcsolását.
        self.assertIn("HV_ALLOW_STALE_GRANTS_ON_START=0", self.env_example)
        self.assertIn(
            "1: NEM biztonságos; az újraindítás előtti", self.env_example
        )
        self.assertIn("HV_FIREWALL_WATCHDOG=1", self.env_example)


if __name__ == "__main__":
    unittest.main()
