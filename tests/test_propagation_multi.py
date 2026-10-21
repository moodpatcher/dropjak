#!/usr/bin/env python3
"""Regressziós tesztek a több szabályválasztásos visszavonás terjedésére.

A központi eset: a munkamenet egyszerre választ egy másik szabályt és egy
gyűjtőszabályt (a gyűjtő a második). Amikor az admin a gyűjtő egyik tagját
módosítja, a gyűjtő választása eltűnik a munkamenetből, a másik választás
és annak lejárata megmarad, a tűzfalból csak a távozó gyűjtő pontos elemei
tűnnek el, a conntrack csak a távozó portokra irányul, és az auditösszesítő
``sessions_revoked=1`` értéket, valamint a függő gyűjtőt tartalmazza.

Fontos értelmezés a tűzfal-naplóhoz: részleges eltávolításnál a maradó
választás elemeit a rendszer szándékosan törli és újra kiadja, hogy a
kerneloldali timeout az új munkamenet-TTL-re álljon (ugyanígy jár el a
meglévő ``_remove_selections_locked`` és a hozzá tartozó tesztek is).
Ezért a "csak a távozó elemek törlődtek" állítást a végleges (nem újra
kiadott) elemek halmazán ellenőrizzük: az engedélyezéskor hozzáadott
elemek mínusz a művelet után hozzáadott elemek. A megosztott elemek
conntrack-törlése viszont valóban elmarad, ezt közvetlenül is vizsgáljuk.

A tesztek hamis nft/conntrack szkripteket használnak; valódi tűzfalhoz és
hálózathoz nem nyúlnak. A HTTP-kiszolgáló csak 127.0.0.1-re figyel.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402
import server    # noqa: E402
import fail2ban as fail2ban_mod  # noqa: E402


# --------------------------------------------------------------- segédeszközök


class FakeTools:
    """Ideiglenes nft/conntrack szkriptek naplózással.

    Csak a tesztekhez szükséges műveleteket ismeri: ``nft -f -`` (szkript),
    ``nft -j list set`` (üres kimenet), a törlések naplózása és a
    ``conntrack`` hívások rögzítése.
    """

    def __init__(self, directory: str) -> None:
        self.dir = Path(directory)
        self.log = self.dir / "calls.log"
        self.nft = self.dir / "nft"
        self.conntrack = self.dir / "conntrack"
        self.nft.write_text(
            "#!/bin/sh\n"
            f'echo "nft $*" >> "{self.log}"\n'
            'if [ "$1" = "-f" ] && [ "$2" = "-" ]; then\n'
            "  while IFS= read -r line; do\n"
            f'    printf \'SCRIPT %s\\n\' "$line" >> "{self.log}"\n'
            "  done\n"
            "fi\n"
            'if [ "$1" = "-j" ]; then\n'
            "  printf '{\"nftables\": []}\\n'\n"
            "  exit 0\n"
            "fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        self.conntrack.write_text(
            "#!/bin/sh\n"
            f'echo "conntrack $*" >> "{self.log}"\n'
            "exit 0\n",
            encoding="utf-8",
        )
        self.nft.chmod(0o755)
        self.conntrack.chmod(0o755)

    def lines(self) -> list[str]:
        if not self.log.exists():
            return []
        return self.log.read_text(encoding="utf-8").splitlines()

    def clear(self) -> None:
        self.log.unlink(missing_ok=True)

    def script(self) -> list[str]:
        prefix = "SCRIPT "
        return [line[len(prefix):] for line in self.lines() if line.startswith(prefix)]

    def deletes(self) -> list[str]:
        return [line for line in self.lines() if line.startswith("nft delete element ")]


def solve(challenge: dict) -> dict:
    zeros = "0" * int(challenge["difficulty"])
    number = 0
    while True:
        if hashlib.sha256(
            f'{challenge["salt"]}{number}'.encode()
        ).hexdigest().startswith(zeros):
            return {**challenge, "number": number}
        number += 1


ADD_PREFIX = "add element inet hatarvedelem "
DELETE_PREFIX = "nft delete element inet hatarvedelem "


def added_elements(lines) -> set[str]:
    """A ``nft -f -`` szkriptben hozzáadott (halmaz, elem) kulcsok.

    A timeout utótagot levágjuk, hogy összevethető legyen a törlésnaplóval.
    """
    result: set[str] = set()
    for line in lines:
        if not line.startswith(ADD_PREFIX):
            continue
        body = line[len(ADD_PREFIX):]
        head, separator, _tail = body.partition(" timeout ")
        result.add(head + " }" if separator else head)
    return result


def deleted_elements(lines) -> set[str]:
    """A naplózott ``nft delete element`` hívások (halmaz, elem) kulcsai."""
    return {
        line[len(DELETE_PREFIX):]
        for line in lines
        if line.startswith(DELETE_PREFIX)
    }


def rule(
    rule_id: str,
    *,
    label: str | None = None,
    tcp=(),
    udp=(),
    icmp: bool = False,
    full: bool = False,
    direction: str = "forward",
    max_ttl: int = 3600,
) -> gateway.Rule:
    return gateway.Rule(
        id=rule_id,
        label=label or rule_id,
        description="",
        tcp=tuple(tcp),
        udp=tuple(udp),
        icmp=icmp,
        full=full,
        direction=direction,
        max_ttl=max_ttl,
    )


# ---------------------------------------------------------------- HTTP-réteg


class PropagationHttpTests(unittest.TestCase):
    """A jelentett élő eset a valódi HTTP-végpontokon keresztül."""

    ADMIN_IP = "127.0.0.5"
    ADMIN_USER = "prop-admin"
    ADMIN_PASSWORD = "prop-admin-jelszo-1"

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tools = FakeTools(cls.tmp.name)
        cls._old_conntrack = gateway.CONNTRACK_BIN
        cls._old_difficulty = gateway.POW_DIFFICULTY
        cls._old_portal_url = gateway.PORTAL_URL
        gateway.CONNTRACK_BIN = str(cls.tools.conntrack)
        gateway.POW_DIFFICULTY = 2
        gateway.PORTAL_URL = ""

        cls.users = gateway.UserStore(
            os.path.join(cls.tmp.name, "users.json"), iterations=10_000
        )
        cls.rules = gateway.RuleStore(
            os.path.join(cls.tmp.name, "rules.json"),
            catalog=gateway.ServiceCatalog.load(str(ROOT / "services.json")),
            logger=lambda *_: None,
        )
        cls.groups = gateway.GroupStore(
            os.path.join(cls.tmp.name, "groups.json"), logger=lambda *_: None
        )
        cls.audit = gateway.AuditLog(
            os.path.join(cls.tmp.name, "audit.jsonl"), logger=lambda *_: None
        )
        cls.settings = gateway.settings_store.SettingsStore(
            os.path.join(cls.tmp.name, "firewall-settings.json"),
            logger=lambda *_: None,
        )
        cls.drops = gateway.droplog.DropLogService(
            os.path.join(cls.tmp.name, "drops.jsonl"),
            enabled=False, logger=lambda *_: None,
        )
        cls.users.add(
            cls.ADMIN_USER, cls.ADMIN_PASSWORD, role=gateway.ROLE_ADMIN
        )
        cls.fw = gateway.Firewall(
            binary=str(cls.tools.nft), logger=lambda *_: None
        )
        cls.fail2ban = fail2ban_mod.Fail2ban(
            cls.fw,
            path=os.path.join(cls.tmp.name, "fail2ban.json"),
            audit=cls.audit,
            logger=lambda *_: None,
            on_ban=lambda record: cls.gw._on_fail2ban_ban(record),
        )
        cls.gw = gateway.Gateway(
            users=cls.users,
            firewall=cls.fw,
            catalog=gateway.ServiceCatalog.load(str(ROOT / "services.json")),
            rules=cls.rules,
            groups=cls.groups,
            audit=cls.audit,
            rate_limiter=gateway.RateLimiter(window=60, maximum=1000),
            settings=cls.settings,
            drops=cls.drops,
            fail2ban=cls.fail2ban,
        )
        server.LOGIN_TICKETS.set_audit(cls.audit)
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
        server.LOGIN_TICKETS.revoke_all()
        server.LOGIN_TICKETS.set_audit(None)
        gateway.CONNTRACK_BIN = cls._old_conntrack
        gateway.POW_DIFFICULTY = cls._old_difficulty
        gateway.PORTAL_URL = cls._old_portal_url
        cls.tmp.cleanup()

    def setUp(self) -> None:
        self.tools.clear()

    # -- HTTP-segédek ---------------------------------------------------------

    def conn(self, source: str = "127.0.0.1") -> http.client.HTTPConnection:
        return http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=10, source_address=(source, 0)
        )

    def get(self, path: str, source: str = "127.0.0.1"):
        conn = self.conn(source)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        out = (resp.status, dict(resp.getheaders()), body)
        conn.close()
        return out

    def post(
        self, path: str, obj: dict, cookie: str = "",
        source: str = "127.0.0.1",
    ):
        conn = self.conn(source)
        headers = {"Content-Type": "application/json"}
        if cookie:
            headers["Cookie"] = cookie
        conn.request("POST", path, body=json.dumps(obj), headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        out = (resp.status, dict(resp.getheaders()), body)
        conn.close()
        return out

    def login(self, user: str, password: str, source: str) -> str:
        _, _, body = self.get("/api/challenge", source=source)
        challenge = json.loads(body)
        status, headers, body = self.post(
            "/api/login",
            {"user": user, "pass": password, "captcha": solve(challenge)},
            source=source,
        )
        self.assertEqual(status, 200, body)
        return headers["Set-Cookie"].split(";", 1)[0]

    def admin_cookie(self) -> str:
        return self.login(self.ADMIN_USER, self.ADMIN_PASSWORD, self.ADMIN_IP)

    def create_rule(self, rule_id: str, **fields) -> None:
        payload = {
            "label": fields.pop("label", rule_id),
            "default_ttl": 300,
            "max_ttl": 3600,
        }
        payload.update(fields)
        self.rules.create(rule_id, payload)

    def create_collection(self, rule_id: str, members, **fields) -> None:
        payload = {
            "label": fields.pop("label", rule_id),
            "collection": True,
            "members": list(members),
            "default_ttl": 300,
            "max_ttl": 3600,
        }
        payload.update(fields)
        self.rules.create(rule_id, payload)

    def make_user(self, name: str, assigned) -> str:
        password = f"{name}-jelszo-1"
        self.users.add(name, password, rules=tuple(assigned))
        return password

    def access(self, cookie: str, rule_ids, ttl: int, source: str):
        return self.post(
            "/api/access",
            {"rules": list(rule_ids), "ttl": ttl},
            cookie=cookie,
            source=source,
        )

    def admin_update(self, cookie: str, rule_id: str, **fields):
        payload = {"action": "update", "id": rule_id}
        payload.update(fields)
        return self.post(
            "/api/admin/rules", payload, cookie=cookie, source=self.ADMIN_IP
        )

    @staticmethod
    def cookie_token(cookie: str) -> str:
        return cookie.split("=", 1)[1]

    def current_session(self, cookie: str, source: str):
        return self.gw.sessions.validate(self.cookie_token(cookie), source)

    def conntrack_lines(self) -> list[str]:
        return [
            line for line in self.tools.lines()
            if line.startswith("conntrack ")
        ]

    # -- 1. gyűjtő másodikként: részleges visszavonás ------------------------

    def test_edit_collection_member_keeps_other_selection(self) -> None:
        ip = "127.0.0.21"
        other = "p1-other"
        member = "p1-member"
        collection = "p1-collection"
        self.create_rule(other, tcp=[18000])
        self.create_rule(member, tcp=[18080])
        self.create_collection(collection, [member])
        password = self.make_user(
            "p1-user", (other, collection)
        )
        cookie = self.login("p1-user", password, ip)

        status, _, body = self.access(cookie, [other, collection], 600, ip)
        self.assertEqual(status, 200, body)

        current = self.current_session(cookie, ip)
        self.assertIsNotNone(current)
        self.assertTrue(current.authorized)
        self.assertEqual(current.rules, (other, collection))
        self.assertEqual(
            [part.rule_id for part in current.rule_parts],
            [other, collection],
        )
        self.assertEqual(current.rule, other)
        expires_before = current.expires
        before = added_elements(self.tools.script())
        self.assertEqual(
            before,
            {
                f"allowed_tcp {{ {ip} . 18000 }}",
                f"allowed_tcp {{ {ip} . 18080 }}",
            },
        )
        self.tools.clear()

        admin = self.admin_cookie()
        status, _, body = self.admin_update(
            admin, member, label="Tag", tcp=[18090], direction="forward",
            default_ttl=300, max_ttl=3600,
        )
        self.assertEqual(status, 200, body)

        # A gyűjtő választása eltűnt, a másik választás és a lejárat maradt.
        current = self.current_session(cookie, ip)
        self.assertIsNotNone(current, "a munkamenet nem tűnhet el")
        self.assertTrue(current.authorized)
        self.assertEqual(current.rules, (other,))
        self.assertEqual(
            [part.rule_id for part in current.rule_parts], [other]
        )
        self.assertEqual(current.rule, other)
        self.assertEqual(current.rule_label, other)
        self.assertEqual(
            current.grant_parts,
            (gateway.Ports(tcp=(18000,), direction="forward"),),
        )
        self.assertEqual(current.tcp, (18000,))
        self.assertEqual(
            current.ports, gateway.Ports(tcp=(18000,), direction="forward")
        )
        self.assertEqual(current.expires, expires_before)
        self.assertIsNotNone(
            self.gw.sessions.validate(self.cookie_token(cookie), ip)
        )

        # Csak a gyűjtő pontos eleme tűnt el véglegesen; a maradó elem
        # timeoutjának újraindításához törölt+újra kiadott elem megmarad.
        after = added_elements(self.tools.script())
        self.assertEqual(
            after, {f"allowed_tcp {{ {ip} . 18000 }}"}
        )
        self.assertEqual(
            before - after, {f"allowed_tcp {{ {ip} . 18080 }}"}
        )
        deletes = deleted_elements(self.tools.deletes())
        self.assertIn(f"allowed_tcp {{ {ip} . 18080 }}", deletes)
        self.assertNotIn(f"allowed_input_tcp {{ {ip} . 18080 }}", deletes)
        self.assertNotIn("allowed_v4", {item.split(" ", 1)[0] for item in deletes})

        # A conntrack csak a távozó portra irányul, nem az egész IP-re.
        conntrack = self.conntrack_lines()
        self.assertIn(
            f"conntrack -D -s {ip} -p tcp --dport 18080", conntrack
        )
        self.assertNotIn(f"conntrack -D -s {ip}", conntrack)
        self.assertNotIn(
            f"conntrack -D -s {ip} -p tcp --dport 18000", conntrack
        )

        rows = [
            row for row in self.audit.read(
                limit=2000, event="admin_rule_updated"
            )
            if row.get("target") == member
        ]
        self.assertTrue(rows, "hiányzik az admin_rule_updated audit")
        self.assertEqual(rows[-1].get("sessions_revoked"), 1)
        self.assertIn(
            collection,
            str(rows[-1].get("collections_affected", "")).split(","),
        )

    # -- 3. tag két gyűjtőben, a munkamenet csak az egyiket választotta -----

    def test_member_of_two_collections_only_selected_collection_removed(
        self,
    ) -> None:
        ip = "127.0.0.22"
        other = "p3-other"
        member = "p3-member"
        selected = "p3-collection-a"
        unselected = "p3-collection-b"
        self.create_rule(other, tcp=[16000])
        self.create_rule(member, tcp=[17000])
        self.create_rule("p3-extra-a", tcp=[17100])
        self.create_rule("p3-extra-b", tcp=[17200])
        self.create_collection(selected, [member, "p3-extra-a"])
        self.create_collection(unselected, [member, "p3-extra-b"])
        password = self.make_user("p3-user", (other, selected))
        cookie = self.login("p3-user", password, ip)

        status, _, body = self.access(cookie, [other, selected], 600, ip)
        self.assertEqual(status, 200, body)
        current = self.current_session(cookie, ip)
        self.assertEqual(current.rules, (other, selected))
        expires_before = current.expires
        before = added_elements(self.tools.script())
        self.assertEqual(
            before,
            {
                f"allowed_tcp {{ {ip} . 16000 }}",
                f"allowed_tcp {{ {ip} . 17000 }}",
                f"allowed_tcp {{ {ip} . 17100 }}",
            },
        )
        self.tools.clear()

        admin = self.admin_cookie()
        status, _, body = self.admin_update(
            admin, member, label="Közös tag", tcp=[17010],
            direction="forward", default_ttl=300, max_ttl=3600,
        )
        self.assertEqual(status, 200, body)

        current = self.current_session(cookie, ip)
        self.assertIsNotNone(current)
        self.assertTrue(current.authorized)
        self.assertEqual(current.rules, (other,))
        self.assertEqual(current.rule, other)
        self.assertEqual(current.expires, expires_before)
        self.assertEqual(
            current.grant_parts,
            (gateway.Ports(tcp=(16000,), direction="forward"),),
        )

        after = added_elements(self.tools.script())
        self.assertEqual(after, {f"allowed_tcp {{ {ip} . 16000 }}"})
        # Csak a kiválasztott gyűjtő (és a tag) elemei távoztak; a nem
        # kiválasztott gyűjtő saját portja (17200) érintetlen.
        self.assertEqual(
            before - after,
            {
                f"allowed_tcp {{ {ip} . 17000 }}",
                f"allowed_tcp {{ {ip} . 17100 }}",
            },
        )
        deletes = deleted_elements(self.tools.deletes())
        self.assertNotIn(f"allowed_tcp {{ {ip} . 17200 }}", deletes)
        self.assertFalse(
            any("17200" in line for line in self.conntrack_lines())
        )
        # A nem kiválasztott gyűjtő a szabálytárban változatlanul megvan.
        other_collection = self.rules.get(unselected)
        self.assertIsNotNone(other_collection)
        self.assertEqual(
            set(other_collection.members), {member, "p3-extra-b"}
        )

        rows = [
            row for row in self.audit.read(
                limit=2000, event="admin_rule_updated"
            )
            if row.get("target") == member
        ]
        self.assertTrue(rows)
        self.assertEqual(rows[-1].get("sessions_revoked"), 1)
        dependents = str(
            rows[-1].get("collections_affected", "")
        ).split(",")
        self.assertIn(selected, dependents)
        self.assertIn(unselected, dependents)

    # -- 4. gyűjtő és a tagja is kiválasztva: egy menetben törlés -----------

    def test_edit_member_removes_collection_and_member_selections(self) -> None:
        ip = "127.0.0.23"
        member = "p4-member"
        collection = "p4-collection"
        self.create_rule(member, tcp=[15000])
        self.create_rule("p4-extra", tcp=[15100])
        self.create_collection(collection, [member, "p4-extra"])
        password = self.make_user("p4-user", (collection, member))
        cookie = self.login("p4-user", password, ip)

        status, _, body = self.access(cookie, [collection, member], 600, ip)
        self.assertEqual(status, 200, body)
        current = self.current_session(cookie, ip)
        self.assertEqual(current.rules, (collection, member))
        before = added_elements(self.tools.script())
        self.assertEqual(
            before,
            {
                f"allowed_tcp {{ {ip} . 15000 }}",
                f"allowed_tcp {{ {ip} . 15100 }}",
            },
        )
        self.tools.clear()

        admin = self.admin_cookie()
        status, _, body = self.admin_update(
            admin, member, label="Tag", tcp=[15010], direction="forward",
            default_ttl=300, max_ttl=3600,
        )
        self.assertEqual(status, 200, body)

        # Mindkét választás egy menetben tűnt el: nincs köztes, részleges
        # újrakiadás (az egyenkénti revoke_rule két lépésben újraadta volna
        # a maradó választás elemeit).
        self.assertIsNone(self.current_session(cookie, ip))
        self.assertIsNone(
            self.gw.sessions.validate(self.cookie_token(cookie), ip)
        )
        after = added_elements(self.tools.script())
        self.assertEqual(after, set(), "nem maradhat újra kiadott elem")
        self.assertEqual(
            before - after,
            {
                f"allowed_tcp {{ {ip} . 15000 }}",
                f"allowed_tcp {{ {ip} . 15100 }}",
            },
        )
        deletes = deleted_elements(self.tools.deletes())
        self.assertIn(f"allowed_tcp {{ {ip} . 15000 }}", deletes)
        self.assertIn(f"allowed_tcp {{ {ip} . 15100 }}", deletes)
        self.assertIn(f"allowed_v4 {{ {ip} }}", deletes)
        self.assertIn(f"allowed_icmp {{ {ip} }}", deletes)
        # Teljes eltávolításnál az egész IP kapcsolatai szakadnak meg.
        self.assertIn(
            f"conntrack -D -s {ip}", self.conntrack_lines()
        )

        rows = [
            row for row in self.audit.read(
                limit=2000, event="admin_rule_updated"
            )
            if row.get("target") == member
        ]
        self.assertTrue(rows)
        self.assertEqual(rows[-1].get("sessions_revoked"), 1)

    # -- 7. újbóli engedélyezés bejelentkezés nélkül, az új definícióval ----

    def test_reauth_after_edit_grants_new_definition_without_old_element(
        self,
    ) -> None:
        ip = "127.0.0.24"
        other = "p7-other"
        member = "p7-member"
        collection = "p7-collection"
        self.create_rule(other, tcp=[14000])
        self.create_rule(member, tcp=[14080])
        self.create_collection(collection, [member])
        password = self.make_user("p7-user", (other, collection))
        cookie = self.login("p7-user", password, ip)

        status, _, body = self.access(cookie, [other, collection], 600, ip)
        self.assertEqual(status, 200, body)
        before = added_elements(self.tools.script())
        self.assertEqual(
            before,
            {
                f"allowed_tcp {{ {ip} . 14000 }}",
                f"allowed_tcp {{ {ip} . 14080 }}",
            },
        )
        self.tools.clear()

        admin = self.admin_cookie()
        status, _, body = self.admin_update(
            admin, member, label="Tag", tcp=[14090], direction="forward",
            default_ttl=300, max_ttl=3600,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            added_elements(self.tools.script()),
            {f"allowed_tcp {{ {ip} . 14000 }}"},
        )
        self.assertEqual(
            before - added_elements(self.tools.script()),
            {f"allowed_tcp {{ {ip} . 14080 }}"},
        )

        # Új bejelentkezés nélkül, ugyanazzal a munkamenettel engedélyezzük
        # újra ugyanazt a gyűjtőt: az új tagdefiníció érvényesül.
        self.tools.clear()
        status, _, body = self.access(cookie, [other, collection], 600, ip)
        self.assertEqual(status, 200, body)

        current = self.current_session(cookie, ip)
        self.assertIsNotNone(current)
        self.assertTrue(current.authorized)
        self.assertEqual(current.rules, (other, collection))
        self.assertEqual(current.tcp, (14000, 14090))
        self.assertEqual(
            current.grant_parts,
            (
                gateway.Ports(
                    tcp=(14000, 14090), direction="forward"
                ),
            ),
        )

        adds = added_elements(self.tools.script())
        self.assertEqual(
            adds,
            {
                f"allowed_tcp {{ {ip} . 14000 }}",
                f"allowed_tcp {{ {ip} . 14090 }}",
            },
            "az új definíció portjai kerüljenek kiadásra",
        )
        deletes = deleted_elements(self.tools.deletes())
        # A távozó régi elem (14080) sem hozzáadásban, sem törlésben nem
        # jelenhet meg újra: az már a módosításkor eltűnt.
        self.assertNotIn(f"allowed_tcp {{ {ip} . 14080 }}", adds)
        self.assertNotIn(f"allowed_tcp {{ {ip} . 14080 }}", deletes)


# ---------------------------------------------------------------- magszint


class _DirectSessionTests(unittest.TestCase):
    """Közvetlen SessionManager-tesztek hamis tűzfallal."""

    IP = "192.168.50.23"

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tools = FakeTools(self.tmp.name)
        self._old_conntrack = gateway.CONNTRACK_BIN
        gateway.CONNTRACK_BIN = str(self.tools.conntrack)
        self.addCleanup(
            setattr, gateway, "CONNTRACK_BIN", self._old_conntrack
        )
        self.fw = gateway.Firewall(
            binary=str(self.tools.nft), logger=lambda *_: None
        )
        self.sessions = gateway.SessionManager(
            self.fw, ttl=3600, pending_ttl=600
        )

    def login(self) -> gateway.Session:
        return self.sessions.login("alice", self.IP)

    def conntrack_lines(self) -> list[str]:
        return [
            line for line in self.tools.lines()
            if line.startswith("conntrack ")
        ]


class PartialRevokeUnitTests(_DirectSessionTests):
    """2. eset: a második választás visszavonása, az első megmarad."""

    def test_revoke_second_keeps_first_and_updates_derived_fields(self) -> None:
        first = rule("first", label="Első", tcp=(80,))
        second = rule("second", label="Második", tcp=(443, 8080))
        session = self.login()
        authorized = self.sessions.authorize(
            session.token, self.IP, [first, second], 120
        )
        expires_before = authorized.expires
        before = added_elements(self.tools.script())
        self.tools.clear()

        self.assertEqual(self.sessions.revoke_rule("second"), 1)

        current = self.sessions.validate(session.token, self.IP)
        self.assertIsNotNone(current, "a munkamenet nem tűnhet el")
        self.assertTrue(current.authorized)
        # A megmaradt választás minden származtatott nézetben konzisztens.
        self.assertEqual(current.rules, ("first",))
        self.assertEqual(current.rule, "first")
        self.assertEqual(current.rule_label, "Első")
        self.assertEqual(
            current.rule_parts,
            (gateway.RuleSelection("first", "Első", first.grants),),
        )
        self.assertEqual(
            current.grant_parts,
            (gateway.Ports(tcp=(80,), direction="forward"),),
        )
        self.assertEqual(current.tcp, (80,))
        self.assertEqual(current.udp, ())
        self.assertFalse(current.icmp)
        self.assertFalse(current.full)
        self.assertEqual(
            current.ports, gateway.Ports(tcp=(80,), direction="forward")
        )
        self.assertEqual(current.expires, expires_before)
        self.assertEqual(self.sessions.count(authorized_only=True), 1)
        self.assertIs(
            self.sessions.validate(session.token, self.IP), current
        )

        row = self.sessions.active_sessions()[0]
        self.assertEqual(row["rule"], "first")
        self.assertEqual(row["rule_label"], "Első")
        self.assertEqual(row["selected_rules"], ["first"])
        self.assertEqual(row["selected_rule_labels"], ["Első"])

        after = added_elements(self.tools.script())
        self.assertEqual(after, {f"allowed_tcp {{ {self.IP} . 80 }}"})
        self.assertEqual(
            before - after,
            {
                f"allowed_tcp {{ {self.IP} . 443 }}",
                f"allowed_tcp {{ {self.IP} . 8080 }}",
            },
        )
        conntrack = self.conntrack_lines()
        self.assertIn(
            f"conntrack -D -s {self.IP} -p tcp --dport 443", conntrack
        )
        self.assertIn(
            f"conntrack -D -s {self.IP} -p tcp --dport 8080", conntrack
        )
        self.assertNotIn(
            f"conntrack -D -s {self.IP} -p tcp --dport 80", conntrack
        )
        self.assertNotIn(f"conntrack -D -s {self.IP}", conntrack)
        # A második azonosítóra újabb hívás már nem érinti a munkamenetet.
        self.assertEqual(self.sessions.revoke_rule("second"), 0)


class OverlappingPortUnitTests(_DirectSessionTests):
    """5. eset: két input választás közös 22-es portja nem tűnik el."""

    def test_shared_input_port_not_deleted_or_flushed(self) -> None:
        first = rule("ssh-a", label="SSH A", tcp=(22, 180), direction="input")
        second = rule("ssh-b", label="SSH B", tcp=(22, 443), direction="input")
        session = self.login()
        authorized = self.sessions.authorize(
            session.token, self.IP, [first, second], 120
        )
        expires_before = authorized.expires
        before = added_elements(self.tools.script())
        self.assertEqual(
            before,
            {
                f"allowed_input_tcp {{ {self.IP} . 22 }}",
                f"allowed_input_tcp {{ {self.IP} . 180 }}",
                f"allowed_input_tcp {{ {self.IP} . 443 }}",
            },
        )
        self.tools.clear()

        self.assertEqual(self.sessions.revoke_rule("ssh-b"), 1)

        current = self.sessions.validate(session.token, self.IP)
        self.assertIsNotNone(current)
        self.assertEqual(current.rules, ("ssh-a",))
        self.assertEqual(current.expires, expires_before)
        self.assertEqual(
            current.grant_parts,
            (
                gateway.Ports(
                    tcp=(22, 180), direction="input"
                ),
            ),
        )

        after = added_elements(self.tools.script())
        self.assertEqual(
            after,
            {
                f"allowed_input_tcp {{ {self.IP} . 22 }}",
                f"allowed_input_tcp {{ {self.IP} . 180 }}",
            },
        )
        # Véglegesen csak a 443 tűnt el. A 22-es portot a maradó választás
        # timeoutjának újraindítása miatt a grant_all törli és azonnal
        # vissza is adja; a revoke_exact nem érinti, és a conntrack sem
        # törli a megosztott port élő kapcsolatait.
        self.assertEqual(
            before - after, {f"allowed_input_tcp {{ {self.IP} . 443 }}"}
        )
        deletes = deleted_elements(self.tools.deletes())
        self.assertIn(f"allowed_input_tcp {{ {self.IP} . 443 }}", deletes)
        conntrack = self.conntrack_lines()
        self.assertIn(
            f"conntrack -D -s {self.IP} -p tcp --dport 443", conntrack
        )
        self.assertNotIn(
            f"conntrack -D -s {self.IP} -p tcp --dport 22", conntrack
        )
        self.assertNotIn(
            f"conntrack -D -s {self.IP} -p tcp --dport 180", conntrack
        )
        self.assertNotIn(f"conntrack -D -s {self.IP}", conntrack)


class MixedDirectionCollectionUnitTests(_DirectSessionTests):
    """6. eset: vegyes irányú gyűjtő másodikként, input 22 megmarad."""

    def test_mixed_collection_second_cleans_both_exact_sets(self) -> None:
        ssh = rule("ssh", label="SSH", tcp=(22,), direction="input")
        mixed = gateway.Rule(
            id="mixed",
            label="Vegyes",
            description="",
            # A feloldott gyűjtő nézete: forward 25565 TCP/UDP, input
            # 25566 TCP/UDP. A members mező teszi gyűjtővé.
            tcp=(25565,),
            udp=(25565,),
            input_tcp=(25566,),
            input_udp=(25566,),
            members=("mixed-forward", "mixed-input"),
            direction="mixed",
        )
        self.assertEqual(
            mixed.grants,
            (
                gateway.Ports(
                    tcp=(25565,), udp=(25565,), direction="forward"
                ),
                gateway.Ports(
                    tcp=(25566,), udp=(25566,), direction="input"
                ),
            ),
        )
        session = self.login()
        authorized = self.sessions.authorize(
            session.token, self.IP, [ssh, mixed], 120
        )
        expires_before = authorized.expires
        before = added_elements(self.tools.script())
        self.assertEqual(
            before,
            {
                f"allowed_input_tcp {{ {self.IP} . 22 }}",
                f"allowed_tcp {{ {self.IP} . 25565 }}",
                f"allowed_udp {{ {self.IP} . 25565 }}",
                f"allowed_input_tcp {{ {self.IP} . 25566 }}",
                f"allowed_input_udp {{ {self.IP} . 25566 }}",
            },
        )
        self.tools.clear()

        self.assertEqual(self.sessions.revoke_rule("mixed"), 1)

        current = self.sessions.validate(session.token, self.IP)
        self.assertIsNotNone(current)
        self.assertTrue(current.authorized)
        self.assertEqual(current.rules, ("ssh",))
        self.assertEqual(current.expires, expires_before)
        self.assertEqual(
            current.grant_parts,
            (gateway.Ports(tcp=(22,), direction="input"),),
        )
        self.assertEqual(current.direction, "input")

        after = added_elements(self.tools.script())
        self.assertEqual(
            after, {f"allowed_input_tcp {{ {self.IP} . 22 }}"}
        )
        # Mindkét irány pontos halmaza távozott; a 22-es input elem megmarad.
        self.assertEqual(
            before - after,
            {
                f"allowed_tcp {{ {self.IP} . 25565 }}",
                f"allowed_udp {{ {self.IP} . 25565 }}",
                f"allowed_input_tcp {{ {self.IP} . 25566 }}",
                f"allowed_input_udp {{ {self.IP} . 25566 }}",
            },
        )
        deletes = deleted_elements(self.tools.deletes())
        for element in before - after:
            self.assertIn(element, deletes)
        conntrack = self.conntrack_lines()
        for proto, port in (
            ("tcp", 25565), ("udp", 25565), ("tcp", 25566), ("udp", 25566),
        ):
            self.assertIn(
                f"conntrack -D -s {self.IP} -p {proto} --dport {port}",
                conntrack,
            )
        self.assertNotIn(
            f"conntrack -D -s {self.IP} -p tcp --dport 22", conntrack
        )
        self.assertNotIn(f"conntrack -D -s {self.IP}", conntrack)


if __name__ == "__main__":
    unittest.main()
