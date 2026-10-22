#!/usr/bin/env python3
"""A Dropjak mag és HTTP-réteg automatizált tesztjei.

Futtatás a projekt gyökeréből:

    python3 -m unittest discover -s tests -v

A tesztek nem nyúlnak a valódi nftables-hez: egy hamis nft szkriptet
használnak, és a HTTP-kiszolgálót is csak 127.0.0.1-re indítják.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402
import server    # noqa: E402
import droplog   # noqa: E402
import fail2ban as fail2ban_mod  # noqa: E402


# ------------------------------------------------------------------ segédek

CATALOG = gateway.ServiceCatalog.load(str(ROOT / "services.json"))
FULL = gateway.Ports(full=True)


def ports_for(*service_ids: str) -> gateway.Ports:
    """A katalógus-szolgáltatásokból előállított Ports a tesztekhez."""
    tcp: set[int] = set()
    udp: set[int] = set()
    icmp = False
    full = False
    for service_id in service_ids:
        service = CATALOG.service(service_id)
        if service is None:
            raise KeyError(service_id)
        tcp.update(service.tcp)
        udp.update(service.udp)
        icmp = icmp or service.icmp
        full = full or service.full
    return gateway.Ports(tuple(sorted(tcp)), tuple(sorted(udp)), icmp, full)


def make_rule(
    rule_id: str,
    services: tuple[str, ...],
    default_ttl: int = 3600,
    max_ttl: int = gateway.MAX_TTL,
) -> gateway.Rule:
    ports = ports_for(*services)
    return gateway.Rule(
        id=rule_id,
        label=rule_id,
        description="",
        tcp=ports.tcp,
        udp=ports.udp,
        icmp=ports.icmp,
        full=ports.full,
        default_ttl=default_ttl,
        max_ttl=max_ttl,
    )


class FakeTools:
    """Ideiglenes nft/conntrack szkriptek naplózással."""

    def __init__(self, directory: str) -> None:
        self.dir = Path(directory)
        self.log = self.dir / "calls.log"
        self.fail = self.dir / "fail.txt"
        self.json_dir = self.dir / "json"
        self.json_dir.mkdir(exist_ok=True)
        self.chain_dir = self.dir / "chains"
        self.chain_dir.mkdir(exist_ok=True)
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
            '  last=""\n'
            '  for arg in "$@"; do last="$arg"; done\n'
            f'  if [ -f "{self.json_dir}/$last.json" ]; then\n'
            f'    cat "{self.json_dir}/$last.json"\n'
            "  else\n"
            '    printf \'{"nftables": []}\\n\'\n'
            "  fi\n"
            "  exit 0\n"
            "fi\n"
            f'if [ -f "{self.fail}" ]; then cat "{self.fail}" >&2; exit 1; fi\n'
            'if [ "$1" = "list" ] && [ "$2" = "chain" ]; then\n'
            '  last=""\n'
            '  for arg in "$@"; do last="$arg"; done\n'
            f'  if [ -f "{self.chain_dir}/$last.txt" ]; then\n'
            f'    cat "{self.chain_dir}/$last.txt"\n'
            "    exit 0\n"
            "  fi\n"
            '  echo "Error: No such file or directory" >&2\n'
            "  exit 1\n"
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

    def make_fail(self, text: str = "boom") -> None:
        self.fail.write_text(text, encoding="utf-8")

    def clear_fail(self) -> None:
        self.fail.unlink(missing_ok=True)

    def script(self) -> list[str]:
        """Az nft -f - bemenetére adott sorok."""
        prefix = "SCRIPT "
        return [line[len(prefix):] for line in self.lines() if line.startswith(prefix)]

    def deletes(self) -> list[str]:
        return [line for line in self.lines() if line.startswith("nft delete element")]

    def set_json(self, set_name: str, elements: list[dict]) -> None:
        """A ``nft -j list set`` hamis kimenetének beállítása."""
        item = {
            "set": {
                "family": "inet",
                "name": set_name,
                "table": "hatarvedelem",
                "type": (
                    ["ipv4_addr", "inet_service"]
                    if set_name in (
                        "allowed_tcp", "allowed_udp",
                        "allowed_input_tcp", "allowed_input_udp",
                    )
                    else "ipv4_addr"
                ),
                "flags": ["timeout"],
            }
        }
        if elements:
            item["set"]["elem"] = [
                {"elem": element} for element in elements
            ]
        (self.json_dir / f"{set_name}.json").write_text(
            json.dumps({"nftables": [{"metainfo": {}}, item]}),
            encoding="utf-8",
        )

    def clear_json(self) -> None:
        for path in self.json_dir.glob("*.json"):
            path.unlink()

    def chain_text(self, chain: str, text: str) -> None:
        """A ``nft list chain`` hamis kimenetének beállítása."""
        (self.chain_dir / f"{chain}.txt").write_text(text, encoding="utf-8")

    def clear_chains(self) -> None:
        for path in self.chain_dir.glob("*.txt"):
            path.unlink()


def solve(challenge: dict) -> dict:
    zeros = "0" * int(challenge["difficulty"])
    n = 0
    while True:
        if hashlib.sha256(f'{challenge["salt"]}{n}'.encode()).hexdigest().startswith(zeros):
            return {**challenge, "number": n}
        n += 1


def fresh_totp_code(secret: str, after_step: int | None = None) -> str:
    """Aktuális TOTP-kód, az időlépés határától biztonságos távolságban.

    Ha ``after_step`` meg van adva, a visszaadott kód egy annál későbbi
    időlépéshez tartozik (a beiratkozási kód újrafelhasználásának
    elkerülésére), de az aktuális ellenőrzési ablakon belül marad.
    Ha közel vagyunk a 30 másodperces lépés végéhez, megvárjuk a következő
    lépést, hogy a több kérést igénylő tesztek ne essenek szét határátlépéskor.
    """
    remaining = gateway.TOTP_PERIOD - (time.time() % gateway.TOTP_PERIOD)
    if remaining < 5:
        time.sleep(remaining + 0.2)
    now = time.time()
    if after_step is None:
        return gateway.totp_code(secret, now=now)
    current = int(now // gateway.TOTP_PERIOD)
    for counter in range(
        max(after_step + 1, current - gateway.TOTP_WINDOW),
        current + gateway.TOTP_WINDOW + 1,
    ):
        code = gateway.hotp_code(secret, counter)
        if gateway.totp_match(secret, code, now=now) == counter:
            return code
    raise AssertionError("nincs a megadott lépésnél későbbi érvényes kód")


def wrong_totp_code(secret: str) -> str:
    """Olyan 6 jegyű kód, amely egyik elfogadott időablakban sem érvényes."""
    current = int(time.time() // gateway.TOTP_PERIOD)
    accepted = {
        gateway.hotp_code(secret, counter)
        for counter in range(
            max(0, current - gateway.TOTP_WINDOW),
            current + gateway.TOTP_WINDOW + 1,
        )
    }
    candidate = 0
    while True:
        code = f"{candidate:06d}"
        if code not in accepted:
            return code
        candidate += 1


def audit_since(audit, started: float) -> list[dict]:
    """A ``started`` időpont után írt naplóbejegyzések (legújabb elöl)."""
    rows: list[dict] = []
    for row in audit.read(limit=2000):
        try:
            if float(row.get("ts", 0)) >= started:
                rows.append(row)
        except (TypeError, ValueError):
            continue
    return rows


# ------------------------------------------------------------------ katalógus

class CatalogTests(unittest.TestCase):
    def test_project_catalog_loads(self) -> None:
        web = CATALOG.service("web")
        dns = CATALOG.service("dns")
        self.assertIsNotNone(web)
        self.assertIsNotNone(dns)
        self.assertEqual(web.tcp, (80, 443))
        self.assertEqual(web.udp, (443,))
        self.assertEqual(dns.tcp, (53, 853))
        self.assertEqual(dns.udp, (53, 853))
        self.assertTrue(CATALOG.service("all").full)
        self.assertTrue(CATALOG.service("icmp").icmp)
        self.assertIsNotNone(CATALOG.default_scenario)
        self.assertIn(CATALOG.default_scenario, CATALOG.scenario_order)

        public = CATALOG.public()
        self.assertEqual(
            [svc["id"] for svc in public["services"]],
            list(CATALOG.service_order),
        )
        self.assertTrue(public["scenarios"])
        self.assertIn("default_ttl", public["scenarios"][0])

    def test_resolve(self) -> None:
        self.assertEqual(
            [svc.id for svc in CATALOG.resolve(["dns", "web"])],
            ["dns", "web"],
        )
        # A teljes hozzáférés minden mást magába foglal.
        self.assertEqual(
            [svc.id for svc in CATALOG.resolve(["web", "all", "dns"])],
            ["all"],
        )
        for bad in ([], ["nincs-ilyen"], ["web", 1], "web", None):
            with self.assertRaises(gateway.AccessError):
                CATALOG.resolve(bad)

    def test_validate_ttl_bounds(self) -> None:
        self.assertEqual(gateway.validate_ttl(gateway.MIN_TTL), gateway.MIN_TTL)
        self.assertEqual(gateway.validate_ttl(gateway.MAX_TTL), gateway.MAX_TTL)
        # Az egy hét is választható legyen, ne álljon meg 24 óránál.
        one_week = 7 * 24 * 60 * 60
        self.assertGreaterEqual(gateway.MAX_TTL, one_week)
        self.assertEqual(gateway.validate_ttl(one_week), one_week)
        for bad in (
            gateway.MIN_TTL - 1,
            gateway.MAX_TTL + 1,
            True,
            "60",
            1.5,
            None,
        ):
            with self.assertRaises(gateway.AccessError):
                gateway.validate_ttl(bad)

    def test_format_duration(self) -> None:
        self.assertEqual(gateway.format_duration(3600), "1 óra")
        self.assertEqual(gateway.format_duration(7200), "2 óra")
        self.assertEqual(gateway.format_duration(5400), "90 perc")
        self.assertEqual(gateway.format_duration(90), "90 másodperc")

    def test_invalid_catalogs_rejected(self) -> None:
        bad_catalogs = [
            {},
            {"services": []},
            {"services": [{"id": "x"}]},
            {"services": [{"id": "x", "tcp": [0]}]},
            {"services": [{"id": "x", "tcp": [70000]}]},
            {"services": [{"id": "x", "tcp": [80]}, {"id": "x", "tcp": [81]}]},
            {"services": [{"id": "x", "tcp": [80]}, {"id": "y", "all": True, "tcp": [81]}]},
            {
                "services": [{"id": "x", "tcp": [80]}],
                "scenarios": [{"id": "s", "services": ["nincs"]}],
            },
        ]
        for data in bad_catalogs:
            with self.assertRaises(gateway.CatalogError, msg=data):
                gateway.ServiceCatalog.from_data(data)


# ------------------------------------------------------------------ tűzfal

class FirewallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tools = FakeTools(cls.tmp.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def setUp(self) -> None:
        self.tools.clear()
        self.tools.clear_fail()
        self.tools.clear_json()
        self.tools.clear_chains()
        self.fw = gateway.Firewall(
            table="hatarvedelem", set_name="allowed_v4",
            binary=str(self.tools.nft), dry_run=False,
            logger=lambda *_: None,
        )

    def test_grant_full_access_uses_allowed_v4(self) -> None:
        self.fw.grant("192.168.50.23", FULL, 90)
        self.assertEqual(
            self.tools.script(),
            [
                "add element inet hatarvedelem allowed_v4 "
                "{ 192.168.50.23 timeout 90s }"
            ],
        )
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_v4 { 192.168.50.23 }",
            self.tools.deletes(),
        )

    def test_grant_selected_services_uses_port_sets(self) -> None:
        self.fw.grant("192.168.50.23", ports_for("web", "dns"), 120)

        script = self.tools.script()
        self.assertEqual(len(script), 7, script)
        for line in (
            "add element inet hatarvedelem allowed_tcp "
            "{ 192.168.50.23 . 80 timeout 120s }",
            "add element inet hatarvedelem allowed_tcp "
            "{ 192.168.50.23 . 443 timeout 120s }",
            "add element inet hatarvedelem allowed_udp "
            "{ 192.168.50.23 . 443 timeout 120s }",
            "add element inet hatarvedelem allowed_tcp "
            "{ 192.168.50.23 . 53 timeout 120s }",
            "add element inet hatarvedelem allowed_tcp "
            "{ 192.168.50.23 . 853 timeout 120s }",
            "add element inet hatarvedelem allowed_udp "
            "{ 192.168.50.23 . 53 timeout 120s }",
            "add element inet hatarvedelem allowed_udp "
            "{ 192.168.50.23 . 853 timeout 120s }",
        ):
            self.assertIn(line, script)
        self.assertFalse(any("allowed_v4" in line for line in script), script)

    def test_allow_defaults_to_full_access(self) -> None:
        self.fw.allow("192.168.50.23", 60)
        self.assertEqual(
            self.tools.script(),
            [
                "add element inet hatarvedelem allowed_v4 "
                "{ 192.168.50.23 timeout 60s }"
            ],
        )

    def test_deny_without_services_clears_full_and_icmp(self) -> None:
        self.fw.deny("192.168.50.23")
        self.assertEqual(
            self.tools.deletes(),
            [
                "nft delete element inet hatarvedelem allowed_v4 { 192.168.50.23 }",
                "nft delete element inet hatarvedelem allowed_icmp { 192.168.50.23 }",
            ],
        )

    def test_revoke_all_deletes_every_catalog_port(self) -> None:
        all_ports = gateway.Ports(
            tcp=CATALOG.all_tcp_ports(), udp=CATALOG.all_udp_ports()
        )
        self.fw.revoke_all("192.168.50.23", (all_ports,))
        lines = self.tools.deletes()
        self.assertEqual(len(lines), len(set(lines)))
        self.assertEqual(
            len(lines),
            2 + len(CATALOG.all_tcp_ports()) + len(CATALOG.all_udp_ports()),
        )
        for line in (
            "nft delete element inet hatarvedelem allowed_v4 { 192.168.50.23 }",
            "nft delete element inet hatarvedelem allowed_icmp { 192.168.50.23 }",
            "nft delete element inet hatarvedelem allowed_tcp { 192.168.50.23 . 80 }",
            "nft delete element inet hatarvedelem allowed_udp { 192.168.50.23 . 53 }",
            "nft delete element inet hatarvedelem allowed_udp { 192.168.50.23 . 51820 }",
        ):
            self.assertIn(line, lines)

    def test_grant_host_rule_uses_input_sets(self) -> None:
        host = gateway.Ports(
            tcp=(25566,), udp=(25566,), direction="input"
        )
        self.fw.grant("192.168.50.23", host, 120)
        script = self.tools.script()
        self.assertIn(
            "add element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.23 . 25566 timeout 120s }",
            script,
        )
        self.assertIn(
            "add element inet hatarvedelem allowed_input_udp "
            "{ 192.168.50.23 . 25566 timeout 120s }",
            script,
        )
        # A host port sosem kerülhet a forward halmazokba.
        self.assertFalse(
            any("allowed_tcp" in line or "allowed_udp" in line
                for line in script),
            script,
        )
        self.assertFalse(any("allowed_v4" in line for line in script), script)
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.23 . 25566 }",
            self.tools.deletes(),
        )
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_input_udp "
            "{ 192.168.50.23 . 25566 }",
            self.tools.deletes(),
        )

    def test_grant_all_mixed_directions(self) -> None:
        forward = gateway.Ports(tcp=(80,), udp=(443,))
        host = gateway.Ports(
            tcp=(25566,), udp=(25566,), direction="input"
        )
        self.fw.grant_all("192.168.50.23", (forward, host), 120)
        script = self.tools.script()
        for line in (
            "add element inet hatarvedelem allowed_tcp "
            "{ 192.168.50.23 . 80 timeout 120s }",
            "add element inet hatarvedelem allowed_udp "
            "{ 192.168.50.23 . 443 timeout 120s }",
            "add element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.23 . 25566 timeout 120s }",
            "add element inet hatarvedelem allowed_input_udp "
            "{ 192.168.50.23 . 25566 timeout 120s }",
        ):
            self.assertIn(line, script)
        self.assertFalse(any("allowed_v4" in line for line in script), script)

        # Ismétlődő engedélyrész nem ad ismétlődő nft-elemet.
        self.tools.clear()
        self.fw.grant_all("192.168.50.23", (forward, forward), 60)
        lines = self.tools.script()
        self.assertEqual(len(lines), len(set(lines)), lines)
        self.assertEqual(len(lines), 2, lines)

        # Üres engedélyhalmaz: nincs MAC-kötés és nincs nft-művelet.
        self.tools.clear()
        self.fw.grant_all("192.168.50.23", (), 60)
        self.assertEqual(self.tools.lines(), [])

        # A visszavonás mindkét irány halmazaiból töröl.
        self.fw.revoke_all("192.168.50.23", (forward, host))
        deletes = self.tools.deletes()
        for line in (
            "nft delete element inet hatarvedelem allowed_tcp "
            "{ 192.168.50.23 . 80 }",
            "nft delete element inet hatarvedelem allowed_udp "
            "{ 192.168.50.23 . 443 }",
            "nft delete element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.23 . 25566 }",
            "nft delete element inet hatarvedelem allowed_input_udp "
            "{ 192.168.50.23 . 25566 }",
        ):
            self.assertIn(line, deletes)

    def test_revoke_and_revoke_all_remove_host_elements(self) -> None:
        host = gateway.Ports(tcp=(25566,), direction="input")
        self.fw.revoke("192.168.50.23", host)
        self.assertEqual(
            self.tools.deletes(),
            [
                "nft delete element inet hatarvedelem allowed_input_tcp "
                "{ 192.168.50.23 . 25566 }",
            ],
        )

        self.tools.clear()
        self.fw.revoke_all("192.168.50.23", (host,))
        lines = self.tools.deletes()
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.23 . 25566 }",
            lines,
        )
        self.assertFalse(
            any("allowed_tcp" in line or "allowed_udp" in line
                for line in lines),
            lines,
        )

    def test_input_full_and_icmp_are_rejected_by_firewall(self) -> None:
        with self.assertRaises(gateway.FirewallError):
            self.fw.grant(
                "10.0.0.5",
                gateway.Ports(full=True, direction="input"),
                60,
            )
        with self.assertRaises(gateway.FirewallError):
            self.fw.grant(
                "10.0.0.5",
                gateway.Ports(icmp=True, direction="input"),
                60,
            )
        self.assertEqual(self.tools.lines(), [])

    def test_flush_includes_input_sets(self) -> None:
        self.fw.flush()
        flushed = [
            line for line in self.tools.lines()
            if line.startswith("nft flush set inet hatarvedelem ")
        ]
        for set_name in ("allowed_input_tcp", "allowed_input_udp"):
            self.assertIn(
                f"nft flush set inet hatarvedelem {set_name}", flushed
            )
        # A host_service_* őrhalmazok szándékosan nem ürülnek induláskor.
        for set_name in ("host_service_tcp", "host_service_udp"):
            self.assertNotIn(
                f"nft flush set inet hatarvedelem {set_name}", flushed
            )

    def test_sync_host_ports_adds_ports_without_flushing(self) -> None:
        self.fw.sync_host_ports(
            [25566, 25566, 0, 70000, "25565", True], [25566]
        )
        script = self.tools.script()
        self.assertEqual(
            script,
            [
                "add element inet hatarvedelem host_service_tcp "
                "{ 25566 }",
                "add element inet hatarvedelem host_service_udp "
                "{ 25566 }",
            ],
        )
        self.assertFalse(
            any("flush set" in line for line in self.tools.lines()),
            self.tools.lines(),
        )
        # A portőr nem érinti a tényleges engedélyező halmazokat.
        self.assertFalse(
            any("allowed_input" in line or "allowed_tcp" in line
                for line in script),
            script,
        )

    def test_sync_host_ports_empty_is_noop(self) -> None:
        self.fw.sync_host_ports([], [])
        self.fw.sync_host_ports(None, ())
        self.assertEqual(self.tools.lines(), [])

    def test_sync_host_ports_raises_on_nft_failure(self) -> None:
        self.tools.make_fail("nft: Operation not permitted")
        with self.assertRaises(gateway.FirewallError):
            self.fw.sync_host_ports([25566], [])

    def test_snapshot_and_health_include_input_and_service_sets(self) -> None:
        snapshot = self.fw.snapshot()
        # A host engedélyek a snapshotban is szerepelnek (az admin nézet
        # ezekből rajzolja a csoportokat); a csak bővülő védőhalmazok
        # szándékosan nem részei a megjelenített képnek.
        for set_name in ("allowed_input_tcp", "allowed_input_udp"):
            self.assertIn(set_name, snapshot["sets"])
            self.assertIn(
                f"nft -j list set inet hatarvedelem {set_name}",
                self.tools.lines(),
            )
        for set_name in ("host_service_tcp", "host_service_udp"):
            self.assertNotIn(set_name, snapshot["sets"])

        self.tools.clear()
        ok, why = self.fw.healthy()
        self.assertTrue(ok, why)
        for set_name in (
            "allowed_input_tcp", "allowed_input_udp",
            "host_service_tcp", "host_service_udp",
        ):
            self.assertIn(
                f"nft list set inet hatarvedelem {set_name}",
                self.tools.lines(),
            )

    def test_deny_without_ports_removes_input_set_elements(self) -> None:
        self.tools.set_json("allowed_input_tcp", [
            {"val": {"concat": ["192.168.50.23", 25566]},
             "timeout": 60, "expires": 60},
            {"val": {"concat": ["192.168.50.24", 25566]},
             "timeout": 60, "expires": 60},
        ])
        self.tools.set_json("allowed_input_udp", [
            {"val": {"concat": ["192.168.50.23", 25566]},
             "timeout": 60, "expires": 60},
        ])
        self.fw.deny("192.168.50.23")
        deletes = self.tools.deletes()
        for line in (
            "nft delete element inet hatarvedelem allowed_v4 "
            "{ 192.168.50.23 }",
            "nft delete element inet hatarvedelem allowed_icmp "
            "{ 192.168.50.23 }",
            "nft delete element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.23 . 25566 }",
            "nft delete element inet hatarvedelem allowed_input_udp "
            "{ 192.168.50.23 . 25566 }",
        ):
            self.assertIn(line, deletes)
        # Más IP elemét nem törli.
        self.assertFalse(
            any("192.168.50.24" in line for line in deletes), deletes
        )

    def test_grant_host_rule_tcp22_uses_input_set(self) -> None:
        host_ssh = gateway.Ports(tcp=(22,), direction="input")
        self.fw.grant("192.168.50.23", host_ssh, 120)
        self.assertEqual(
            self.tools.script(),
            [
                "add element inet hatarvedelem allowed_input_tcp "
                "{ 192.168.50.23 . 22 timeout 120s }"
            ],
        )

    def test_revoke_all_deletes_host_22_input_element(self) -> None:
        host_ssh = gateway.Ports(tcp=(22,), direction="input")
        self.fw.revoke_all("192.168.50.23", (host_ssh,))
        self.assertEqual(
            self.tools.deletes(),
            [
                "nft delete element inet hatarvedelem allowed_v4 "
                "{ 192.168.50.23 }",
                "nft delete element inet hatarvedelem allowed_icmp "
                "{ 192.168.50.23 }",
                "nft delete element inet hatarvedelem allowed_input_tcp "
                "{ 192.168.50.23 . 22 }",
            ],
        )
        self.fw.revoke_all("nem-ip")
        self.fw.revoke_all("2001:db8::1")
        self.assertEqual(len(self.tools.deletes()), 3)

    def test_invalid_ip_never_reaches_nft(self) -> None:
        with self.assertRaises(gateway.FirewallError):
            self.fw.allow("not-an-ip", 60)
        with self.assertRaises(gateway.FirewallError):
            self.fw.allow("2001:db8::1", 60)
        self.assertEqual(self.tools.lines(), [])

    def test_missing_element_delete_is_tolerated(self) -> None:
        self.tools.make_fail("Error: Could not process rule: No such file or directory")
        # A grant először töröl (ez tolerált), majd hozzáad (ez hibázik).
        with self.assertRaises(gateway.FirewallError):
            self.fw.allow("10.0.0.5", 60)
        self.fw.deny("10.0.0.5")  # a törlés hibája elfogadható

    def test_nft_failure_is_raised(self) -> None:
        self.tools.make_fail("nft: Operation not permitted")
        with self.assertRaises(gateway.FirewallError):
            self.fw.allow("10.0.0.5", 60)

    def test_healthy(self) -> None:
        ok, _ = self.fw.healthy()
        self.assertTrue(ok)
        self.tools.make_fail("Error: No such file or directory")
        ok, why = self.fw.healthy()
        self.assertFalse(ok)
        self.assertTrue(why)

    def test_dry_run_does_not_execute(self) -> None:
        fw = gateway.Firewall(binary="/nonexistent/nft", dry_run=True, logger=lambda *_: None)
        fw.grant("10.0.0.5", ports_for("web"), 30)
        fw.deny("10.0.0.5")
        self.assertEqual(self.tools.lines(), [])

    def test_snapshot_parses_set_json(self) -> None:
        self.tools.set_json("allowed_v4", [
            {"val": "192.168.50.23", "timeout": 90, "expires": 80},
        ])
        self.tools.set_json("allowed_tcp", [
            {"val": {"concat": ["192.168.50.23", 443]},
             "timeout": 120, "expires": 100},
            {"val": {"concat": ["192.168.50.24", 80]},
             "timeout": 60, "expires": 50},
        ])
        snapshot = self.fw.snapshot()
        self.assertEqual(snapshot["errors"], [])
        self.assertEqual(snapshot["sets"]["allowed_v4"], [{
            "address": "192.168.50.23",
            "port": None,
            "expires_in": 80,
            "timeout": 90,
        }])
        self.assertEqual(
            {(entry["address"], entry["port"])
             for entry in snapshot["sets"]["allowed_tcp"]},
            {("192.168.50.23", 443), ("192.168.50.24", 80)},
        )
        self.assertEqual(snapshot["sets"]["allowed_udp"], [])
        self.assertTrue(
            all(
                line.startswith("nft -j list set inet hatarvedelem ")
                for line in self.tools.lines()
            ),
            self.tools.lines(),
        )

    def test_snapshot_reports_broken_json(self) -> None:
        (self.tools.json_dir / "allowed_tcp.json").write_text(
            "{nem json", encoding="utf-8"
        )
        snapshot = self.fw.snapshot()
        self.assertEqual(snapshot["sets"]["allowed_tcp"], [])
        self.assertEqual(len(snapshot["errors"]), 1)
        self.assertIn("allowed_tcp", snapshot["errors"][0])

    def test_ruleset_lists_chains_without_sets(self) -> None:
        # Az újabb nft a list chain kimenetét table blokkba ágyazza; a
        # preauth ág a régebbi, burkolat nélküli formátumot modellezi.
        self.tools.chain_text(
            "forward",
            "table inet hatarvedelem {\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority -10; policy drop;\n"
            "\t}\n"
            "}",
        )
        self.tools.chain_text(
            "preauth",
            "chain preauth {\n"
            '\tiifname "eth1" meta l4proto tcp '
            "ct original proto-dst 25565 accept\n"
            "}",
        )
        result = self.fw.ruleset()
        self.assertFalse(result["dry_run"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["chains"], ["forward", "preauth"])
        self.assertTrue(result["text"].startswith("chain forward {"), result["text"])
        self.assertIn("chain preauth {", result["text"])
        self.assertNotIn("table inet", result["text"])
        self.assertIn("\ttype filter hook forward priority -10; policy drop;",
                      result["text"])
        self.assertIn("ct original proto-dst 25565 accept", result["text"])
        self.assertNotIn("allowed_tcp", result["text"])
        listed = [
            line for line in self.tools.lines()
            if line.startswith("nft list chain inet hatarvedelem ")
        ]
        self.assertEqual(len(listed), len(gateway.RULESET_CHAINS))
        self.assertIn("preauth_nat", result["missing"])
        self.assertNotIn("preauth_nat", result["chains"])

    def test_ruleset_reports_nft_errors(self) -> None:
        self.tools.make_fail("boom")
        result = self.fw.ruleset()
        self.assertEqual(result["text"], "")
        self.assertTrue(result["errors"])
        self.assertIn("forward", result["errors"][0])

    def test_ruleset_dry_run_does_not_execute(self) -> None:
        fw = gateway.Firewall(
            binary="/nonexistent/nft", dry_run=True, logger=lambda *_: None
        )
        result = fw.ruleset()
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["text"], "")
        self.assertEqual(self.tools.lines(), [])

    def test_group_snapshot_marks_orphans_and_mismatches(self) -> None:
        snapshot = {
            "table": "hatarvedelem",
            "generated": 1,
            "sets": {
                "allowed_v4": [],
                "allowed_icmp": [],
                "allowed_tcp": [
                    {"address": "192.168.50.23", "port": 80,
                     "expires_in": 100, "timeout": 120},
                    {"address": "192.168.50.30", "port": 8080,
                     "expires_in": 60, "timeout": 60},
                ],
                "allowed_udp": [],
            },
            "errors": [],
        }
        sessions = [
            {
                "user": "alice", "ip": "192.168.50.23", "authorized": True,
                "tcp": [80, 443], "udp": [], "icmp": False, "full": False,
                "rule": "web", "rule_label": "Web", "ports_label": "TCP 80, 443",
                "expires_in": 100, "logged_in": 1,
            },
            {
                "user": "bob", "ip": "192.168.50.24", "authorized": True,
                "tcp": [53], "udp": [], "icmp": False, "full": False,
                "rule": "dns", "rule_label": "DNS", "ports_label": "TCP 53",
                "expires_in": 90, "logged_in": 2,
            },
            {
                "user": "pete", "ip": "192.168.50.25", "authorized": False,
                "tcp": [], "udp": [], "icmp": False, "full": False,
                "rule": "", "rule_label": "", "ports_label": "",
                "expires_in": 50, "logged_in": 3,
            },
        ]
        grouped = gateway.group_firewall_snapshot(snapshot, sessions)
        rows = {row["ip"]: row for row in grouped["ips"]}
        self.assertEqual(
            [row["ip"] for row in grouped["ips"]],
            ["192.168.50.23", "192.168.50.24", "192.168.50.30"],
        )
        self.assertNotIn("192.168.50.25", rows)  # függő munkamenet

        alice = rows["192.168.50.23"]
        self.assertFalse(alice["orphan"])
        self.assertFalse(alice["in_sync"])
        self.assertEqual(alice["ports_label"], "TCP 80")
        self.assertIn("hiányzó TCP 443", alice["mismatch"])
        self.assertNotIn("host_ssh", alice)
        self.assertEqual(alice["expires_in"], 100)
        self.assertEqual(alice["users"], ["alice"])

        bob = rows["192.168.50.24"]
        self.assertFalse(bob["orphan"])
        self.assertFalse(bob["in_sync"])
        self.assertEqual(bob["ports_label"], "Nincs port")
        self.assertIn("hiányzó TCP 53", bob["mismatch"])

        orphan = rows["192.168.50.30"]
        self.assertTrue(orphan["orphan"])
        self.assertIn("váratlan TCP 8080", orphan["mismatch"])
        self.assertEqual(grouped["counts"]["orphans"], 1)
        self.assertEqual(grouped["counts"]["mismatched"], 2)

    def test_group_snapshot_full_access_in_sync(self) -> None:
        snapshot = {
            "sets": {
                "allowed_v4": [{"address": "10.0.0.9", "expires_in": 60,
                                "timeout": 60}],
                "allowed_icmp": [{"address": "10.0.0.9", "expires_in": 60,
                                  "timeout": 60}],
                "allowed_tcp": [],
                "allowed_udp": [],
            },
            "errors": [],
        }
        sessions = [{
            "user": "root", "ip": "10.0.0.9", "authorized": True,
            "tcp": [], "udp": [], "icmp": True, "full": True,
            "rule": "custom-full", "rule_label": "Teljes",
            "ports_label": "Minden port", "expires_in": 60, "logged_in": 1,
        }]
        grouped = gateway.group_firewall_snapshot(snapshot, sessions)
        row = grouped["ips"][0]
        self.assertTrue(row["in_sync"], row)
        self.assertEqual(row["mismatch"], [])
        self.assertTrue(row["full"])
        self.assertTrue(row["icmp"])
        self.assertNotIn("host_ssh", row)
        self.assertEqual(row["ports_label"], "Minden port")
        self.assertEqual(grouped["counts"]["mismatched"], 0)

    def test_group_snapshot_input_grant_in_sync_and_marked(self) -> None:
        snapshot = {
            "sets": {
                "allowed_v4": [],
                "allowed_icmp": [],
                "allowed_tcp": [],
                "allowed_udp": [],
                "allowed_input_tcp": [
                    {"address": "192.168.50.23", "port": 25566,
                     "expires_in": 90, "timeout": 120},
                ],
                "allowed_input_udp": [],
            },
            "errors": [],
        }
        sessions = [{
            "user": "alice", "ip": "192.168.50.23", "authorized": True,
            "tcp": [25566], "udp": [], "icmp": False, "full": False,
            "direction": "input", "rule": "host-25566",
            "rule_label": "mpwerks host", "ports_label": "TCP 25566",
            "expires_in": 90, "logged_in": 1,
        }]
        grouped = gateway.group_firewall_snapshot(snapshot, sessions)
        row = grouped["ips"][0]
        self.assertEqual(row["mismatch"], [])
        self.assertTrue(row["in_sync"], row)
        # A host (input) bejegyzés irányjelölést kap, és a felirat jelzi.
        self.assertEqual(row["tcp"], [{
            "port": 25566, "direction": "input",
            "expires_in": 90, "timeout": 120,
        }])
        self.assertEqual(row["ports_label"], "Host TCP 25566")
        self.assertEqual(row["entry_count"], 1)
        self.assertEqual(grouped["counts"]["mismatched"], 0)

    def test_group_snapshot_removed_input_grant_is_mismatch(self) -> None:
        snapshot = {
            "sets": {
                "allowed_v4": [], "allowed_icmp": [],
                "allowed_tcp": [], "allowed_udp": [],
                "allowed_input_tcp": [], "allowed_input_udp": [],
            },
            "errors": [],
        }
        sessions = [{
            "user": "alice", "ip": "192.168.50.23", "authorized": True,
            "tcp": [25566], "udp": [], "icmp": False, "full": False,
            "direction": "input", "rule": "host-25566",
            "rule_label": "mpwerks host", "ports_label": "TCP 25566",
            "expires_in": 90, "logged_in": 1,
        }]
        row = gateway.group_firewall_snapshot(snapshot, sessions)["ips"][0]
        self.assertFalse(row["in_sync"])
        # Nem téves forward „hiányzó TCP” eltérés.
        self.assertEqual(row["mismatch"], ["hiányzó host TCP 25566"])

    def test_group_snapshot_orphan_input_entry_is_visible(self) -> None:
        snapshot = {
            "sets": {
                "allowed_v4": [], "allowed_icmp": [],
                "allowed_tcp": [], "allowed_udp": [],
                "allowed_input_tcp": [
                    {"address": "192.168.50.31", "port": 25566,
                     "expires_in": 40, "timeout": 60},
                ],
                "allowed_input_udp": [],
            },
            "errors": [],
        }
        grouped = gateway.group_firewall_snapshot(snapshot, [])
        row = grouped["ips"][0]
        self.assertTrue(row["orphan"])
        self.assertEqual(row["ports_label"], "Host TCP 25566")
        self.assertEqual(row["mismatch"], ["váratlan host TCP 25566"])
        self.assertEqual(row["tcp"][0]["direction"], "input")
        self.assertEqual(grouped["counts"]["orphans"], 1)

    def test_group_snapshot_mixed_collection_in_sync_and_mismatches(self) -> None:
        def snapshot(input_tcp_ports, input_udp_ports=()):
            return {
                "sets": {
                    "allowed_v4": [],
                    "allowed_icmp": [],
                    "allowed_tcp": [
                        {"address": "192.168.50.23", "port": 80,
                         "expires_in": 90, "timeout": 120},
                    ],
                    "allowed_udp": [],
                    "allowed_input_tcp": [
                        {"address": "192.168.50.23", "port": port,
                         "expires_in": 90, "timeout": 120}
                        for port in input_tcp_ports
                    ],
                    "allowed_input_udp": [
                        {"address": "192.168.50.23", "port": port,
                         "expires_in": 90, "timeout": 120}
                        for port in input_udp_ports
                    ],
                },
                "errors": [],
            }

        sessions = [{
            "user": "alice", "ip": "192.168.50.23", "authorized": True,
            "tcp": [80, 25566], "udp": [25566], "icmp": False, "full": False,
            "direction": "mixed", "rule": "mixed-col",
            "rule_label": "Mixed", "ports_label": "TCP 80, 25566 · UDP 25566",
            "expires_in": 90, "logged_in": 1,
            "grants": [
                {"direction": "forward", "tcp": [80], "udp": [],
                 "icmp": False, "full": False},
                {"direction": "input", "tcp": [25566], "udp": [25566],
                 "icmp": False, "full": False},
            ],
        }]

        matching = gateway.group_firewall_snapshot(
            snapshot([25566], [25566]), sessions
        )
        row = matching["ips"][0]
        self.assertTrue(row["in_sync"], row)
        self.assertEqual(row["mismatch"], [])
        self.assertEqual(row["ports_label"], "TCP 80 · Host TCP 25566 · "
                         "Host UDP 25566")
        self.assertEqual(matching["counts"]["mismatched"], 0)

        missing = gateway.group_firewall_snapshot(
            snapshot([], [25566]), sessions
        )["ips"][0]
        self.assertFalse(missing["in_sync"])
        self.assertEqual(missing["mismatch"], ["hiányzó host TCP 25566"])

        extra = gateway.group_firewall_snapshot(
            snapshot([25566, 25567], [25566]), sessions
        )["ips"][0]
        self.assertFalse(extra["in_sync"])
        self.assertEqual(extra["mismatch"], ["váratlan host TCP 25567"])

    def test_group_snapshot_host_ssh_is_only_a_host_22_entry(self) -> None:
        # A teljes forward szabály nem nyit host SSH-t. A host SSH kizárólag
        # közönséges TCP 22-es input bejegyzésként jelenik meg.
        base_sets = {
            "allowed_v4": [{"address": "10.0.0.9", "expires_in": 60,
                            "timeout": 60}],
            "allowed_icmp": [{"address": "10.0.0.9", "expires_in": 60,
                              "timeout": 60}],
            "allowed_tcp": [],
            "allowed_udp": [],
            "allowed_input_tcp": [],
            "allowed_input_udp": [],
        }

        full_session = {
            "user": "root", "ip": "10.0.0.9", "authorized": True,
            "tcp": [], "udp": [], "icmp": True, "full": True,
            "rule": "custom-full", "rule_label": "Teljes",
            "ports_label": "Minden port", "expires_in": 60, "logged_in": 1,
        }
        custom = gateway.group_firewall_snapshot(
            {"sets": base_sets, "errors": []}, [full_session]
        )
        custom_row = custom["ips"][0]
        self.assertTrue(custom_row["in_sync"], custom_row)
        self.assertNotIn("host_ssh", custom_row)
        self.assertEqual(custom_row["tcp"], [])

        ssh_sets = dict(base_sets)
        ssh_sets["allowed_v4"] = []
        ssh_sets["allowed_icmp"] = []
        ssh_sets["allowed_input_tcp"] = [
            {"address": "10.0.0.9", "port": 22,
             "expires_in": 60, "timeout": 60},
        ]
        ssh_session = {
            "user": "admin", "ip": "10.0.0.9", "authorized": True,
            "tcp": [22], "udp": [], "icmp": False, "full": False,
            "direction": "input", "rule": "host-ssh",
            "rule_label": "Host SSH", "ports_label": "TCP 22",
            "expires_in": 60, "logged_in": 1,
        }
        ssh_row = gateway.group_firewall_snapshot(
            {"sets": ssh_sets, "errors": []}, [ssh_session]
        )["ips"][0]
        self.assertTrue(ssh_row["in_sync"], ssh_row)
        self.assertEqual(ssh_row["mismatch"], [])
        self.assertEqual(ssh_row["tcp"], [{
            "port": 22, "direction": "input",
            "expires_in": 60, "timeout": 60,
        }])
        self.assertEqual(ssh_row["ports_label"], "Host TCP 22")
        self.assertEqual(ssh_row["entry_count"], 1)


    # -- MAC-kötés -----------------------------------------------------------

    def _mac_firewall(self, arp_text: str):
        arp_path = os.path.join(self.tmp.name, "arp")
        with open(arp_path, "w", encoding="utf-8") as fh:
            fh.write(arp_text)
        return gateway.Firewall(
            table="hatarvedelem", set_name="allowed_v4",
            binary=str(self.tools.nft), dry_run=False,
            logger=lambda *_: None,
            lan_if="hv-lan",
            lan_network=ipaddress.ip_network("192.168.10.0/24"),
            arp_path=arp_path,
        )

    @staticmethod
    def _arp(ip: str, mac: str, flags: str = "0x2", device: str = "hv-lan") -> str:
        return (
            "IP address       HW type     Flags       HW address            "
            "Mask     Device\n"
            f"{ip:<16} 0x1         {flags:<11} {mac:<21} *        {device}\n"
        )

    def test_grant_binds_client_mac(self) -> None:
        fw = self._mac_firewall(self._arp("192.168.10.2", "aa:bb:cc:dd:ee:ff"))
        fw.grant("192.168.10.2", ports_for("web"), 60)
        self.assertIn(
            "add element inet hatarvedelem client_mac "
            "{ 192.168.10.2 . aa:bb:cc:dd:ee:ff timeout 60s }",
            self.tools.script(),
        )
        self.assertIn(
            "add element inet hatarvedelem allowed_tcp "
            "{ 192.168.10.2 . 80 timeout 60s }",
            self.tools.script(),
        )

    def test_grant_host_tcp22_binds_client_mac_and_ttl(self) -> None:
        fw = self._mac_firewall(self._arp("192.168.10.2", "aa:bb:cc:dd:ee:ff"))
        fw.grant(
            "192.168.10.2", gateway.Ports(tcp=(22,), direction="input"), 120
        )
        self.assertIn(
            "add element inet hatarvedelem client_mac "
            "{ 192.168.10.2 . aa:bb:cc:dd:ee:ff timeout 120s }",
            self.tools.script(),
        )
        self.assertIn(
            "add element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.10.2 . 22 timeout 120s }",
            self.tools.script(),
        )

    def test_grant_fails_closed_without_arp_entry(self) -> None:
        fw = self._mac_firewall(self._arp("192.168.10.9", "aa:bb:cc:dd:ee:ff"))
        with self.assertRaises(gateway.FirewallError):
            fw.grant("192.168.10.2", ports_for("web"), 60)
        self.assertFalse(
            any("allowed_tcp" in line for line in self.tools.script()),
            self.tools.script(),
        )

    def test_incomplete_arp_entry_is_rejected(self) -> None:
        fw = self._mac_firewall(
            self._arp("192.168.10.2", "aa:bb:cc:dd:ee:ff", flags="0x0")
        )
        with self.assertRaises(gateway.FirewallError):
            fw.grant("192.168.10.2", ports_for("web"), 60)

    def test_arp_entry_on_other_interface_is_rejected(self) -> None:
        fw = self._mac_firewall(
            self._arp("192.168.10.2", "aa:bb:cc:dd:ee:ff", device="eth0")
        )
        with self.assertRaises(gateway.FirewallError):
            fw.grant("192.168.10.2", ports_for("web"), 60)

    def test_non_lan_client_needs_no_mac(self) -> None:
        fw = self._mac_firewall("")
        fw.grant("203.0.113.5", ports_for("web"), 60)
        # Nem-LAN címen nincs MAC-kötés; a maradék elem takarítása viszont
        # ilyenkor is lefut (F8), ezért csak a hozzáadást tiltjuk.
        self.assertFalse(
            any(
                "add element inet hatarvedelem client_mac" in line
                for line in self.tools.script()
            ),
            self.tools.script(),
        )

    def test_revoke_all_removes_mac_binding(self) -> None:
        fw = self._mac_firewall(self._arp("192.168.10.2", "aa:bb:cc:dd:ee:ff"))
        fw.grant("192.168.10.2", ports_for("web"), 60)
        self.tools.clear()
        fw.revoke_all("192.168.10.2", (ports_for("web"),))
        self.assertIn(
            "nft delete element inet hatarvedelem client_mac "
            "{ 192.168.10.2 . aa:bb:cc:dd:ee:ff }",
            self.tools.deletes(),
        )

    def test_revoke_all_removes_mac_for_non_lan_address(self) -> None:
        """Nem-LAN címnél is kitakarítja a maradt MAC-elemet (F8)."""
        fw = self._mac_firewall("")
        self.tools.set_json("client_mac", [
            {"val": {"concat": [
                "203.0.113.5", "aa:bb:cc:dd:ee:ff"
            ]}},
        ])
        fw.revoke_all("203.0.113.5")
        self.assertIn(
            "nft delete element inet hatarvedelem client_mac "
            "{ 203.0.113.5 . aa:bb:cc:dd:ee:ff }",
            self.tools.deletes(),
        )

    def test_mac_listing_failure_blocks_grant(self) -> None:
        """Hibás client_mac kimenet esetén nincs engedélyezés (fail-closed)."""
        fw = self._mac_firewall(self._arp("192.168.10.2", "aa:bb:cc:dd:ee:ff"))
        (self.tools.json_dir / "client_mac.json").write_text(
            "{nem json", encoding="utf-8"
        )
        with self.assertRaises(gateway.FirewallError):
            fw.grant("192.168.10.2", ports_for("web"), 60)
        self.assertFalse(
            any(
                "add element inet hatarvedelem allowed_tcp" in line
                for line in self.tools.script()
            ),
            self.tools.script(),
        )

    def test_parse_mac_json(self) -> None:
        raw = json.dumps({"nftables": [{"set": {"name": "client_mac", "elem": [
            {"elem": {"val": {"concat": [
                "192.168.10.2", "aa:bb:cc:dd:ee:ff"
            ]}}},
            {"elem": {"val": {"concat": [
                "192.168.10.3", "11:22:33:44:55:66"
            ]}}},
        ]}}]})
        self.assertEqual(
            gateway.Firewall.parse_mac_json(raw, "192.168.10.2"),
            ["aa:bb:cc:dd:ee:ff"],
        )
        # A hibás listázás nem jelenthet "nincs kötés" állapotot.
        for raw in ("{nem json", "[]", b"\xff"):
            with self.assertRaises(gateway.FirewallError):
                gateway.Firewall.parse_mac_json(raw, "x")
        self.assertEqual(
            gateway.Firewall.parse_mac_json('{"nftables": []}', "x"), []
        )

    def test_arp_mac_rejects_all_zero_and_bad_mac(self) -> None:
        path = os.path.join(self.tmp.name, "arp-zero")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self._arp("192.168.10.2", "00:00:00:00:00:00"))
        self.assertIsNone(
            gateway.arp_mac("192.168.10.2", "hv-lan", path)
        )


# ------------------------------------------------------------------ felhasználók

class UserStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "users.json")
        self.store = gateway.UserStore(self.path, iterations=10_000)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_add_verify_and_persistence(self) -> None:
        self.store.add("alice", "hosszu-jelszo-1")
        self.assertTrue(self.store.verify("alice", "hosszu-jelszo-1"))
        self.assertFalse(self.store.verify("alice", "rossz-jelszo"))
        self.assertFalse(self.store.verify("bob", "hosszu-jelszo-1"))
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600)
        other = gateway.UserStore(self.path, iterations=10_000)
        self.assertTrue(other.verify("alice", "hosszu-jelszo-1"))
        self.assertEqual(other.names(), ["alice"])

    def test_duplicate_and_validation(self) -> None:
        self.store.add("alice", "hosszu-jelszo-1")
        with self.assertRaises(gateway.UserStoreError):
            self.store.add("alice", "masik-jelszo-2")
        with self.assertRaises(gateway.UserStoreError):
            self.store.add("rossz nev", "hosszu-jelszo-1")
        with self.assertRaises(gateway.UserStoreError):
            self.store.add("bob", "rovid")
        with self.assertRaises(gateway.UserStoreError):
            self.store.add("x" * 33, "hosszu-jelszo-1")

    def test_set_password_and_remove(self) -> None:
        self.store.add("alice", "hosszu-jelszo-1")
        self.store.set_password("alice", "masik-jelszo-2")
        self.assertFalse(self.store.verify("alice", "hosszu-jelszo-1"))
        self.assertTrue(self.store.verify("alice", "masik-jelszo-2"))
        self.assertTrue(self.store.remove("alice"))
        self.assertFalse(self.store.remove("alice"))
        self.assertEqual(self.store.names(), [])

    def test_malformed_file_fails_closed(self) -> None:
        Path(self.path).write_text("{not json", encoding="utf-8")
        self.assertFalse(self.store.verify("alice", "barmi-jelszo"))

    def test_password_reset_preserves_metadata_and_sets_flag(self) -> None:
        self.store.add(
            "alice", "hosszu-jelszo-1", role=gateway.ROLE_ADMIN,
            rules=("web-only",), must_change_password=True,
        )
        before = self.store.record("alice")
        self.assertIsNotNone(before)
        self.assertTrue(before.must_change_password)
        self.assertEqual(before.rules, ("web-only",))
        self.store.set_password("alice", "masik-jelszo-2")
        after = self.store.record("alice")
        self.assertIsNotNone(after)
        self.assertFalse(after.must_change_password)
        self.assertEqual(after.role, gateway.ROLE_ADMIN)
        self.assertEqual(after.rules, ("web-only",))
        self.assertEqual(after.created, before.created)
        self.store.set_metadata("alice", must_change_password=True)
        self.assertTrue(self.store.record("alice").must_change_password)

    def test_provision_marker_survives_password_change(self) -> None:
        self.store.add("admin", "hosszu-jelszo-1", role=gateway.ROLE_ADMIN)
        self.store.set_metadata("admin", provisioned_from="jelolo-1")
        self.store.set_password("admin", "masik-jelszo-2")
        self.assertEqual(self.store.provisioned_from("admin"), "jelolo-1")
        self.assertIsNotNone(self.store.record("admin"))
        self.assertEqual(self.store.record("admin").role, gateway.ROLE_ADMIN)


class UserStoreAccountRequestTests(unittest.TestCase):
    """A fiókkérés (pending) adatmodellje, jóváhagyása és elutasítása."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "users.json")
        self.store = gateway.UserStore(self.path, iterations=10_000)
        self.rules = gateway.RuleStore(
            os.path.join(self.tmp.name, "rules.json"),
            catalog=CATALOG, logger=lambda *_: None,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _raw(self) -> dict:
        return json.loads(Path(self.path).read_text(encoding="utf-8"))

    def _write_raw(self, data: dict) -> None:
        Path(self.path).write_text(json.dumps(data), encoding="utf-8")

    def _fresh(self) -> gateway.UserStore:
        return gateway.UserStore(self.path, iterations=10_000)

    def test_add_defaults_are_active_user_without_email(self) -> None:
        self.store.add("alice", "hosszu-jelszo-1")
        record = self.store.record("alice")
        self.assertIsNotNone(record)
        self.assertFalse(record.pending)
        self.assertEqual(record.email, "")
        self.assertTrue(record.enabled)
        self.assertEqual(record.rules, ())
        self.assertFalse(record.rules_set)
        self.assertFalse(record.must_change_password)
        self.assertEqual(record.role, gateway.ROLE_USER)

    def test_add_pending_normalizes_and_forces_safe_defaults(self) -> None:
        self.store.add(
            "alice", "hosszu-jelszo-1",
            role=gateway.ROLE_ADMIN, enabled=True, rules=("browse",),
            must_change_password=True, pending=True, email="  A@B.CO ",
        )
        record = self.store.record("alice")
        self.assertIsNotNone(record)
        self.assertTrue(record.pending)
        self.assertEqual(record.email, "a@b.co")
        self.assertFalse(record.enabled)
        self.assertEqual(record.rules, ())
        self.assertTrue(record.rules_set)
        self.assertFalse(record.must_change_password)
        self.assertEqual(record.role, gateway.ROLE_USER)
        self.assertEqual(self.rules.effective_for(record, []), [])

    def test_pending_requires_valid_normalized_email(self) -> None:
        for email in (
            "", "   ", "nem-email", "a@b", "@b.co", "a b@c.co", None, 123,
        ):
            with self.subTest(email=email):
                with self.assertRaises(gateway.UserStoreError):
                    self.store.add(
                        "bob", "hosszu-jelszo-1", pending=True, email=email
                    )
        self.assertEqual(self.store.names(), [])
        self.assertFalse(Path(self.path).exists())

    def test_public_and_verify_include_pending(self) -> None:
        self.store.add(
            "alice", "hosszu-jelszo-1", pending=True, email="a@b.co"
        )
        record = self.store.record("alice")
        public = record.public(["staff"])
        self.assertIs(public["pending"], True)
        self.assertEqual(public["email"], "a@b.co")
        self.assertEqual(public["groups"], ["staff"])
        self.assertFalse(public["enabled"])
        self.assertEqual(public["rules"], [])
        self.assertTrue(self.store.verify("alice", "hosszu-jelszo-1"))
        self.assertFalse(self.store.verify("alice", "rossz-jelszo"))

    def test_effective_rules_are_empty_for_pending_without_rules_key(self) -> None:
        # Ellenőrző eset: a rules mező nélküli aktív (örökölt) felhasználó
        # továbbra is megkapja a forward szabályokat, tehát a régi ág él.
        self.store.add("legacy", "hosszu-jelszo-1")
        self.store.add(
            "pending", "hosszu-jelszo-1", pending=True, email="p@e.co"
        )
        data = self._raw()
        self.assertNotIn("rules", data["legacy"])
        self.assertIn("rules", data["pending"])
        del data["pending"]["rules"]
        self._write_raw(data)
        fresh = self._fresh()
        legacy = fresh.record("legacy")
        pending = fresh.record("pending")
        self.assertFalse(legacy.rules_set)
        self.assertTrue(self.rules.effective_for(legacy, []))
        self.assertFalse(pending.rules_set)
        self.assertEqual(self.rules.effective_for(pending, []), [])
        # Admin szerepkörű, de még függő fiók sem kap szabályt.
        data["pending"]["role"] = gateway.ROLE_ADMIN
        data["pending"]["enabled"] = True
        self._write_raw(data)
        admin_pending = self._fresh().record("pending")
        self.assertEqual(admin_pending.role, gateway.ROLE_ADMIN)
        self.assertTrue(admin_pending.pending)
        self.assertEqual(self.rules.effective_for(admin_pending, []), [])

    def test_approve_activates_and_preserves_details(self) -> None:
        self.store.add(
            "alice", "hosszu-jelszo-1", pending=True, email="a@b.co"
        )
        data = self._raw()
        data["alice"]["rules"] = ["browse"]
        self._write_raw(data)
        self.assertTrue(self.store.approve_user("alice"))
        fresh = self._fresh()
        record = fresh.record("alice")
        self.assertIsNotNone(record)
        self.assertFalse(record.pending)
        self.assertTrue(record.enabled)
        self.assertEqual(record.email, "a@b.co")
        self.assertEqual(record.rules, ("browse",))
        self.assertTrue(record.rules_set)
        self.assertTrue(fresh.verify("alice", "hosszu-jelszo-1"))
        self.assertFalse(fresh.verify("alice", "rossz-jelszo"))
        self.assertEqual(fresh.pending_records(), [])
        self.assertFalse(self.store.approve_user("nincs-ilyen"))

    def test_reject_removes_record_and_pending_listing(self) -> None:
        self.store.add(
            "bob", "hosszu-jelszo-1", pending=True, email="b@c.co"
        )
        self.assertEqual(
            [record.name for record in self.store.pending_records()], ["bob"]
        )
        self.assertTrue(self.store.reject_user("bob"))
        fresh = self._fresh()
        self.assertIsNone(fresh.record("bob"))
        self.assertEqual(fresh.names(), [])
        self.assertEqual(fresh.pending_records(), [])
        self.assertFalse(self.store.reject_user("bob"))
        self.assertFalse(self.store.reject_user("nincs-ilyen"))

    def test_malformed_pending_flag_fails_closed(self) -> None:
        self.store.add("alice", "hosszu-jelszo-1")
        base = self._raw()["alice"]
        cases = (
            ("missing", None),
            ("string", "yes"),
            ("number", 1),
            ("null", None),
            ("false-string", "false"),
            ("list", []),
        )
        for label, value in cases:
            with self.subTest(case=label):
                data = self._raw()
                item = dict(base)
                if label == "missing":
                    item.pop("pending", None)
                else:
                    item["pending"] = value
                data["alice"] = item
                self._write_raw(data)
                record = self._fresh().record("alice")
                self.assertIsNotNone(record)
                self.assertIs(record.pending, label != "missing", label)

    def test_admin_count_excludes_pending_admin(self) -> None:
        self.store.add("root", "root-jelszo-1", role=gateway.ROLE_ADMIN)
        self.store.add(
            "alice", "hosszu-jelszo-1", pending=True, email="a@b.co"
        )
        data = self._raw()
        data["alice"]["role"] = gateway.ROLE_ADMIN
        data["alice"]["enabled"] = True
        self._write_raw(data)
        fresh = self._fresh()
        self.assertEqual(fresh.admin_count(), 1)
        self.assertEqual(
            [record.name for record in fresh.pending_records()], ["alice"]
        )


# ------------------------------------------------------------------------ TOTP

RFC_TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class TotpPrimitiveTests(unittest.TestCase):
    def test_rfc6238_vector_and_window(self) -> None:
        self.assertEqual(
            (gateway.TOTP_PERIOD, gateway.TOTP_DIGITS, gateway.TOTP_WINDOW),
            (30, 6, 1),
        )
        self.assertEqual(gateway.totp_code(RFC_TOTP_SECRET, now=59), "287082")
        self.assertEqual(gateway.totp_match(RFC_TOTP_SECRET, "287082", now=59), 1)
        # 90 másodpercnél a számláló 3; a ±1 ablak a 2., 3. és 4. lépést
        # fogadja el, az ezen kívülieket nem.
        for step in (2, 3, 4):
            code = gateway.totp_code(
                RFC_TOTP_SECRET, now=step * gateway.TOTP_PERIOD
            )
            self.assertEqual(
                gateway.totp_match(RFC_TOTP_SECRET, code, now=90), step
            )
        for step in (1, 5):
            code = gateway.totp_code(
                RFC_TOTP_SECRET, now=step * gateway.TOTP_PERIOD
            )
            self.assertIsNone(gateway.totp_match(RFC_TOTP_SECRET, code, now=90))

    def test_hotp_bad_secret_and_invalid_codes(self) -> None:
        for secret in ("", "nem-base32!", "======"):
            with self.subTest(secret=secret):
                with self.assertRaises(ValueError):
                    gateway.hotp_code(secret, 0)
        for code in (
            "", "12345", "1234567", "12345a", " 12345", "12345 ",
            "12345²",
        ):
            with self.subTest(code=code):
                self.assertIsNone(
                    gateway.totp_match(RFC_TOTP_SECRET, code, now=59)
                )
        self.assertIsNone(gateway.totp_match(RFC_TOTP_SECRET, None, now=59))
        self.assertIsNone(gateway.totp_match("", "287082", now=59))
        self.assertIsNone(gateway.totp_match("nem-base32!", "287082", now=59))

    def test_generated_secret(self) -> None:
        secret = gateway.generate_totp_secret()
        self.assertEqual(len(secret), 32)
        self.assertEqual(secret, secret.upper())
        self.assertNotIn("=", secret)
        self.assertTrue(set(secret) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"))
        self.assertNotEqual(secret, gateway.generate_totp_secret())
        code = gateway.totp_code(secret, now=59)
        self.assertEqual(gateway.totp_match(secret, code, now=59), 1)

    def test_recovery_helpers(self) -> None:
        self.assertEqual(
            gateway.normalize_recovery_code(" ab-cd 2efg34\t"), "ABCD2EFG34"
        )
        self.assertEqual(gateway.normalize_recovery_code(None), "")
        self.assertEqual(
            gateway.hash_recovery_code(" ab-cd 2efg34\t"),
            hashlib.sha256(b"ABCD2EFG34").hexdigest(),
        )
        codes = gateway.generate_recovery_codes()
        self.assertEqual(len(codes), 10)
        self.assertEqual(len(set(codes)), 10)
        for code in codes:
            self.assertEqual(len(code), 10)
            self.assertTrue(
                set(code) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
            )
        self.assertEqual(gateway.generate_recovery_codes(0), [])

    def test_otpauth_uri(self) -> None:
        with mock.patch.object(gateway, "TOTP_ISSUER", "Teszt Kupac"):
            uri = gateway.build_otpauth_uri("alice", RFC_TOTP_SECRET)
        parsed = urllib.parse.urlparse(uri)
        self.assertEqual(parsed.scheme, "otpauth")
        self.assertEqual(parsed.netloc, "totp")
        self.assertEqual(parsed.path, "/Teszt%20Kupac%3Aalice")
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(query["secret"], [RFC_TOTP_SECRET])
        self.assertEqual(query["issuer"], ["Teszt Kupac"])
        self.assertEqual(query["algorithm"], ["SHA1"])
        self.assertEqual(query["digits"], ["6"])
        self.assertEqual(query["period"], ["30"])

    def test_otpauth_uri_custom_issuer_and_fallback(self) -> None:
        with mock.patch.object(gateway, "TOTP_ISSUER", "Teszt Kupac"):
            uri = gateway.build_otpauth_uri(
                "alice", RFC_TOTP_SECRET, issuer="Északi Torony"
            )
            fallback = gateway.build_otpauth_uri(
                "alice", RFC_TOTP_SECRET, issuer=None
            )
            empty = gateway.build_otpauth_uri(
                "alice", RFC_TOTP_SECRET, issuer="   "
            )
        parsed = urllib.parse.urlparse(uri)
        self.assertEqual(parsed.path, "/%C3%89szaki%20Torony%3Aalice")
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(query["issuer"], ["Északi Torony"])
        self.assertEqual(query["secret"], [RFC_TOTP_SECRET])
        self.assertEqual(
            urllib.parse.urlparse(fallback).path, "/Teszt%20Kupac%3Aalice"
        )
        self.assertEqual(
            urllib.parse.parse_qs(
                urllib.parse.urlparse(fallback).query
            )["issuer"],
            ["Teszt Kupac"],
        )
        self.assertEqual(
            urllib.parse.urlparse(empty).path, "/Teszt%20Kupac%3Aalice"
        )
        self.assertEqual(
            urllib.parse.parse_qs(urllib.parse.urlparse(empty).query)["issuer"],
            ["Teszt Kupac"],
        )


class TotpUserStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "users.json")
        self.store = gateway.UserStore(self.path, iterations=10_000)
        self.store.add("alice", "hosszu-jelszo-1")
        self.secret = gateway.generate_totp_secret()
        self.base_item = json.loads(
            Path(self.path).read_text(encoding="utf-8")
        )["alice"]

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _enroll(self, recovery_codes=()) -> list[str]:
        hashes = [gateway.hash_recovery_code(code) for code in recovery_codes]
        self.assertTrue(self.store.enroll_totp("alice", self.secret, hashes))
        return hashes

    def _fresh_record(self) -> gateway.UserRecord:
        return gateway.UserStore(self.path, iterations=10_000).record("alice")

    def _write_alice(self, item: dict) -> None:
        data = json.loads(Path(self.path).read_text(encoding="utf-8"))
        data["alice"] = item
        Path(self.path).write_text(json.dumps(data), encoding="utf-8")

    def test_replay_rejected(self) -> None:
        self._enroll()
        now = 1_000_000.0
        code = gateway.totp_code(self.secret, now=now)
        self.assertTrue(self.store.verify_totp("alice", code, now=now))
        self.assertFalse(self.store.verify_totp("alice", code, now=now))
        record = self._fresh_record()
        self.assertEqual(record.totp_last_step, int(now // gateway.TOTP_PERIOD))
        # A kötelező jelző nélkül is működik; azt a szerver kényszeríti ki.
        self.assertFalse(record.totp_required)

    def test_enroll_records_step_and_rejects_replay(self) -> None:
        now = 5_000_000.0
        code = gateway.totp_code(self.secret, now=now)
        matched = gateway.totp_match(self.secret, code, now=now)
        self.assertIsNotNone(matched)
        self.assertTrue(
            self.store.enroll_totp("alice", self.secret, [], last_step=matched)
        )
        # A beiratkozást megerősítő kód ugyanabban az időlépésben már nem
        # használható fel újra.
        self.assertFalse(self.store.verify_totp("alice", code, now=now))
        self.assertEqual(self._fresh_record().totp_last_step, matched)
        # Csak a nem negatív egész (nem bool) érték kerül a számlálóba.
        for value in (None, -1, True, False, "7", 3.5):
            with self.subTest(last_step=value):
                self.assertTrue(
                    self.store.enroll_totp(
                        "alice", self.secret, [], last_step=value
                    )
                )
                self.assertEqual(self._fresh_record().totp_last_step, -1)

    def test_concurrent_verify_single_success(self) -> None:
        self._enroll()
        now = 2_000_000.0
        code = gateway.totp_code(self.secret, now=now)
        barrier = threading.Barrier(2)
        results: list[bool] = []
        errors: list[BaseException] = []
        result_lock = threading.Lock()

        def worker() -> None:
            try:
                barrier.wait(timeout=10)
                ok = self.store.verify_totp("alice", code, now=now)
            except BaseException as exc:
                with result_lock:
                    errors.append(exc)
                return
            with result_lock:
                results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), [False, True])

    def test_recovery_codes_normalized_and_single_use(self) -> None:
        codes = gateway.generate_recovery_codes(3)
        self._enroll(codes)
        first, second, third = codes
        messy = f" {first[:5].lower()} - {first[5:].lower()} "
        # A "0" nem szerepel a kódábécében, ezért biztosan nem egyezik.
        self.assertFalse(self.store.verify_recovery("alice", "0000000000"))
        self.assertTrue(self.store.verify_recovery("alice", messy))
        self.assertFalse(self.store.verify_recovery("alice", messy))
        self.assertEqual(len(self._fresh_record().totp_recovery), 2)
        # A többi kódot a felhasználás nem érinti.
        self.assertTrue(self.store.verify_recovery("alice", second))
        self.assertTrue(self.store.verify_recovery("alice", third))
        self.assertEqual(self._fresh_record().totp_recovery, ())
        self.assertFalse(self.store.verify_recovery("alice", second))

    def test_reset_and_enroll_preserve_required(self) -> None:
        codes = gateway.generate_recovery_codes(2)
        self._enroll(codes)
        self.assertTrue(self.store.set_totp_required("alice", True))
        record = self._fresh_record()
        self.assertTrue(record.totp_required)
        self.assertTrue(record.totp_enrolled)
        self.assertTrue(self.store.reset_totp("alice"))
        record = self._fresh_record()
        self.assertTrue(record.totp_required)
        self.assertFalse(record.totp_enrolled)
        self.assertEqual(record.totp_secret, "")
        self.assertEqual(record.totp_last_step, -1)
        self.assertEqual(record.totp_recovery, ())
        raw = json.loads(Path(self.path).read_text(encoding="utf-8"))["alice"]
        self.assertEqual(raw["totp_last_step"], -1)
        now = 3_000_000.0
        self.assertFalse(
            self.store.verify_totp(
                "alice", gateway.totp_code(self.secret, now=now), now=now
            )
        )
        # Az újrabelépés megőrzi a kötelező jelzőt.
        self._enroll(codes)
        record = self._fresh_record()
        self.assertTrue(record.totp_required)
        self.assertEqual(len(record.totp_recovery), 2)

    def test_set_metadata_does_not_touch_totp_secret(self) -> None:
        self._enroll(gateway.generate_recovery_codes(2))
        before = self._fresh_record()
        self.store.set_metadata("alice", totp_required=True)
        after = self._fresh_record()
        self.assertTrue(after.totp_required)
        self.assertEqual(after.totp_secret, before.totp_secret)
        self.assertEqual(after.totp_recovery, before.totp_recovery)
        self.store.set_metadata("alice", role=gateway.ROLE_ADMIN)
        again = self._fresh_record()
        self.assertTrue(again.totp_required)
        self.assertEqual(again.totp_secret, before.totp_secret)

    def test_parsing_totp_required_fail_closed(self) -> None:
        cases = (
            ({}, False),
            ({"totp_required": False}, False),
            ({"totp_required": True}, True),
            ({"totp_required": "yes"}, True),
            ({"totp_required": 1}, True),
            ({"totp_required": None}, True),
            ({"totp_required": {}}, True),
        )
        for fields, expected in cases:
            with self.subTest(fields=fields):
                item = dict(self.base_item)
                item.update(fields)
                self._write_alice(item)
                record = self._fresh_record()
                self.assertIsNotNone(record)
                self.assertIs(record.totp_required, expected)

    def test_parsing_secret_step_and_recovery(self) -> None:
        record = self._fresh_record()
        self.assertEqual(
            (
                record.totp_secret, record.totp_required,
                record.totp_last_step, record.totp_recovery,
            ),
            ("", False, -1, ()),
        )
        good = "a" * 64
        item = dict(self.base_item)
        item.update({
            "totp_secret": "ABC234",
            "totp_last_step": "7",
            "totp_recovery": [good, "B" * 64, "nem-hash", 5, "C" * 63],
        })
        self._write_alice(item)
        record = self._fresh_record()
        self.assertEqual(record.totp_secret, "ABC234")
        self.assertEqual(record.totp_last_step, 7)
        self.assertEqual(record.totp_recovery, (good, "b" * 64))
        self.assertTrue(record.totp_enrolled)

        item = dict(self.base_item)
        item.update({
            "totp_secret": 123,
            "totp_last_step": "nem-szam",
            "totp_recovery": "nem-lista",
        })
        self._write_alice(item)
        record = self._fresh_record()
        self.assertEqual(record.totp_secret, "")
        self.assertEqual(record.totp_last_step, -1)
        self.assertEqual(record.totp_recovery, ())
        self.assertFalse(record.totp_enrolled)

    def test_public_hides_totp_internals(self) -> None:
        self._enroll(gateway.generate_recovery_codes(2))
        self.store.set_totp_required("alice", True)
        record = self._fresh_record()
        info = record.public()
        self.assertIs(info["totp_required"], True)
        self.assertIs(info["totp_enrolled"], True)
        self.assertEqual(
            {key for key in info if key.startswith("totp")},
            {"totp_required", "totp_enrolled"},
        )
        for key in ("totp_secret", "totp_last_step", "totp_recovery"):
            self.assertNotIn(key, info)
        self.store.reset_totp("alice")
        record = self._fresh_record()
        self.assertFalse(record.totp_enrolled)
        self.assertIs(record.public()["totp_enrolled"], False)

    def test_unknown_and_disabled_users_rejected(self) -> None:
        now = 4_000_000.0
        code = gateway.totp_code(self.secret, now=now)
        self.assertFalse(self.store.verify_totp("nobody", code, now=now))
        self.assertFalse(self.store.verify_recovery("nobody", "ABCDEFGHIJ"))
        self.assertFalse(self.store.set_totp_required("nobody", True))
        self.assertFalse(self.store.enroll_totp("nobody", self.secret, []))
        self.assertFalse(self.store.reset_totp("nobody"))
        self._enroll(["ABCDEFGHIJ"])
        self.store.set_metadata("alice", enabled=False)
        self.assertFalse(self.store.verify_totp("alice", code, now=now))
        self.assertFalse(self.store.verify_recovery("alice", "ABCDEFGHIJ"))

    def test_verify_without_enrollment_rejected(self) -> None:
        now = 5_000_000.0
        code = gateway.totp_code(self.secret, now=now)
        self.assertFalse(self.store.verify_totp("alice", code, now=now))


class LoginTicketStoreTests(unittest.TestCase):
    """A 2FA-belépőjegyek élettartama, IP-kötése és próbaszámlálása."""

    def setUp(self) -> None:
        self.now = 1000.0
        self.store = server.LoginTicketStore(
            ttl=5, max_attempts=3, clock=lambda: self.now
        )
        self.ip = "127.0.0.9"

    def test_issue_fields_and_ip_binding(self) -> None:
        token = self.store.issue(
            "verify", "alice", self.ip, "fingerprint-1"
        )
        ticket = self.store.peek(token, self.ip)
        self.assertIsNotNone(ticket)
        self.assertEqual(ticket.token, token)
        self.assertEqual(ticket.purpose, "verify")
        self.assertEqual(ticket.username, "alice")
        self.assertEqual(ticket.ip, self.ip)
        self.assertEqual(ticket.fingerprint, "fingerprint-1")
        self.assertEqual(ticket.secret, "")
        self.assertEqual(ticket.attempts, 0)
        self.assertEqual(ticket.expires_at, 1005.0)

        # Idegen IP-ről a jegy nem olvasható, nem fogyasztható és nem
        # számolható rá sikertelen próba.
        self.assertIsNone(self.store.peek(token, "127.0.0.10"))
        self.assertIsNone(self.store.consume(token, "127.0.0.10"))
        self.assertEqual(self.store.fail(token, "127.0.0.10"), 0)
        self.assertIsNotNone(self.store.peek(token, self.ip))
        self.assertEqual(self.store.peek(token, self.ip).attempts, 0)

    def test_ttl_expiry_with_injected_clock_and_purge(self) -> None:
        token = self.store.issue("verify", "alice", self.ip, "fp")
        self.now = 1004.0
        self.assertIsNotNone(self.store.peek(token, self.ip))
        self.now = 1005.0
        self.assertIsNone(self.store.peek(token, self.ip))

        # A purge a hozzáférés nélkül is eltakarítja a lejárt jegyeket.
        fresh = self.store.issue("verify", "alice", self.ip, "fp")
        self.assertIn(fresh, self.store._tickets)
        self.now = 1011.0
        self.store.purge()
        self.assertNotIn(fresh, self.store._tickets)
        self.assertIsNone(self.store.peek(fresh, self.ip))

    def test_ticket_is_single_use(self) -> None:
        token = self.store.issue("verify", "alice", self.ip, "fp")
        ticket = self.store.consume(token, self.ip)
        self.assertIsNotNone(ticket)
        self.assertEqual(ticket.username, "alice")
        self.assertIsNone(self.store.consume(token, self.ip))
        self.assertIsNone(self.store.peek(token, self.ip))

    def test_attempt_cap_invalidates_ticket(self) -> None:
        token = self.store.issue("verify", "alice", self.ip, "fp")
        self.assertEqual(self.store.fail(token, self.ip), 2)
        self.assertEqual(self.store.fail(token, self.ip), 1)
        self.assertIsNotNone(self.store.peek(token, self.ip))
        self.assertEqual(self.store.fail(token, self.ip), 0)
        self.assertIsNone(self.store.peek(token, self.ip))
        self.assertIsNone(self.store.consume(token, self.ip))

        # Egy friss jegy ettől függetlenül használható marad.
        fresh = self.store.issue("verify", "alice", self.ip, "fp")
        self.assertEqual(self.store.consume(fresh, self.ip).username, "alice")

    def test_revoke_user_and_revoke_all(self) -> None:
        first = self.store.issue("verify", "alice", self.ip, "fp")
        bob = self.store.issue("verify", "bob", self.ip, "fp")
        second = self.store.issue("enroll", "alice", self.ip, "fp")
        self.assertEqual(self.store.revoke_user("alice"), 2)
        self.assertIsNone(self.store.peek(first, self.ip))
        self.assertIsNone(self.store.peek(second, self.ip))
        self.assertIsNotNone(self.store.peek(bob, self.ip))

        self.store.revoke_all()
        self.assertIsNone(self.store.peek(bob, self.ip))
        self.assertEqual(self.store._tickets, {})

    def test_ticket_username_is_server_chosen(self) -> None:
        token = self.store.issue("verify", "alice", self.ip, "fp")
        ticket = self.store.peek(token, self.ip)
        self.assertEqual(ticket.username, "alice")
        # A kliens nem tud más felhasználót „beírni” a jegybe: a token csak
        # a szerveroldali rekordot azonosítja.
        self.assertNotEqual(ticket.username, "bob")
        self.assertIsNone(self.store.peek("alice", self.ip))


class LoginTicketAuditTests(unittest.TestCase):
    """A 2FA-jegyek kiadás/lejárat/elutasítás naplózása."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.audit = gateway.AuditLog(
            os.path.join(self.tmp.name, "audit.jsonl"),
            logger=lambda *_: None,
        )
        self.now = 1000.0
        self.store = server.LoginTicketStore(
            ttl=5, max_attempts=3, clock=lambda: self.now
        )
        self.store.set_audit(self.audit)
        self.ip = "127.0.0.9"

    def test_abandoned_ticket_expiry_is_audited(self) -> None:
        token = self.store.issue("verify", "alice", self.ip, "fp")
        self.now = 1005.0
        self.store.purge()
        rows = self.audit.read(event="totp_ticket_expired")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["severity"], "info")
        self.assertEqual(row["user"], "alice")
        self.assertEqual(row["ip"], self.ip)
        self.assertEqual(row["purpose"], "verify")
        self.assertEqual(row["attempts"], 0)
        self.assertEqual(row["ttl"], 5)
        self.assertEqual(row["reason"], "expired")
        self.assertEqual(row["ticket_hash"], server._ticket_hash(token))
        self.assertNotIn(token, json.dumps(rows))
        # A megőrzött ok alapján a későbbi kérés pontos indokot kap.
        self.assertEqual(self.store.inspect(token, self.ip)[1], "expired")

    def test_expiry_after_failed_attempt_is_warning(self) -> None:
        token = self.store.issue("verify", "alice", self.ip, "fp")
        self.assertEqual(self.store.fail(token, self.ip), 2)
        self.now = 1006.0
        self.store.purge()
        row = self.audit.read(event="totp_ticket_expired")[0]
        self.assertEqual(row["severity"], "warn")
        self.assertEqual(row["attempts"], 1)

    def test_inspect_reasons_and_revocation_events(self) -> None:
        self.assertEqual(self.store.inspect("", self.ip)[1], "bad_request")
        self.assertEqual(
            self.store.inspect("nem-letezo-jegy", self.ip)[1], "unknown"
        )
        token = self.store.issue("verify", "alice", self.ip, "fp")
        self.assertIsNotNone(self.store.consume(token, self.ip))
        self.assertEqual(
            self.store.inspect(token, self.ip)[1], "already_consumed"
        )
        locked = self.store.issue("verify", "alice", self.ip, "fp")
        for _ in range(3):
            self.store.fail(locked, self.ip)
        self.assertEqual(
            self.store.inspect(locked, self.ip)[1], "too_many_attempts"
        )
        other = self.store.issue("verify", "alice", self.ip, "fp")
        self.assertEqual(
            self.store.inspect(other, "127.0.0.10")[1], "ip_mismatch"
        )
        self.assertEqual(
            self.store.revoke_user("alice", reason="deleted"), 1
        )
        self.assertEqual(
            self.store.inspect(other, self.ip)[1], "user_state_changed"
        )
        revoked = self.audit.read(event="totp_tickets_revoked")
        self.assertEqual(len(revoked), 1)
        self.assertEqual(revoked[0]["target"], "alice")
        self.assertEqual(revoked[0]["count"], 1)
        self.assertEqual(revoked[0]["reason"], "deleted")

        self.store.revoke_all(reason="service_stop")
        discarded = self.audit.read(event="totp_tickets_discarded")
        self.assertEqual(len(discarded), 1)
        self.assertEqual(discarded[0]["reason"], "service_stop")


class AdminProvisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = gateway.UserStore(
            os.path.join(self.tmp.name, "users.json"), iterations=10_000
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _provision(self, enabled: bool, user: str, password: str) -> str:
        with mock.patch.multiple(
            gateway,
            ADMIN_ENABLED=enabled,
            ADMIN_USER=user,
            ADMIN_PASSWORD=password,
        ):
            return gateway.provision_admin(self.store)

    def test_disabled_does_not_touch_users(self) -> None:
        self.assertEqual(self._provision(False, "admin", "hosszu-jelszo-1"), "disabled")
        self.assertEqual(self.store.names(), [])

    def test_enabled_requires_credentials(self) -> None:
        for user, password in (("", "hosszu-jelszo-1"), ("admin", "")):
            with self.subTest(user=user, password=password):
                with self.assertRaises(gateway.UserStoreError):
                    self._provision(True, user, password)
        self.assertEqual(self.store.names(), [])

    def test_creates_then_keeps_unchanged(self) -> None:
        self.assertEqual(self._provision(True, "admin", "hosszu-jelszo-1"), "created")
        self.assertTrue(self.store.verify("admin", "hosszu-jelszo-1"))
        self.assertEqual(self._provision(True, "admin", "hosszu-jelszo-1"), "unchanged")
        self.assertEqual(self.store.names(), ["admin"])

    def test_password_change_updates_existing_user(self) -> None:
        self._provision(True, "admin", "hosszu-jelszo-1")
        self.assertEqual(self._provision(True, "admin", "masik-jelszo-2"), "updated")
        self.assertTrue(self.store.verify("admin", "masik-jelszo-2"))
        self.assertFalse(self.store.verify("admin", "hosszu-jelszo-1"))
        self.assertEqual(self.store.names(), ["admin"])

    def test_invalid_credentials_rejected(self) -> None:
        with self.assertRaises(gateway.UserStoreError):
            self._provision(True, "admin", "rovid")
        with self.assertRaises(gateway.UserStoreError):
            self._provision(True, "rossz nev", "hosszu-jelszo-1")

    def test_created_admin_has_no_implicit_rules_and_keeps_assignments(self) -> None:
        self.assertEqual(self._provision(True, "admin", "hosszu-jelszo-1"), "created")
        record = self.store.record("admin")
        self.assertEqual(record.rules, ())
        self.assertTrue(record.rules_set)
        self.store.set_metadata("admin", rules=("browse",))
        self.assertEqual(
            self._provision(True, "admin", "hosszu-jelszo-1"), "unchanged"
        )
        self.assertEqual(self.store.record("admin").rules, ("browse",))
        self.assertEqual(
            self._provision(True, "admin", "masik-jelszo-2"), "updated"
        )
        self.assertEqual(self.store.record("admin").rules, ("browse",))

    def test_disabling_keeps_existing_user(self) -> None:
        self._provision(True, "admin", "hosszu-jelszo-1")
        self.assertEqual(self._provision(False, "admin", "hosszu-jelszo-1"), "disabled")
        self.assertEqual(self.store.names(), ["admin"])
        self.assertTrue(self.store.verify("admin", "hosszu-jelszo-1"))

    def test_created_admin_must_change_seed_password(self) -> None:
        self.assertEqual(self._provision(True, "admin", "hosszu-jelszo-1"), "created")
        record = self.store.record("admin")
        self.assertIsNotNone(record)
        self.assertTrue(record.must_change_password)
        self.assertTrue(self.store.provisioned_from("admin"))

    def test_ui_password_change_is_not_reset_on_restart(self) -> None:
        self._provision(True, "admin", "hosszu-jelszo-1")
        self.store.set_password("admin", "sajat-jelszo-3")
        self.assertEqual(self._provision(True, "admin", "hosszu-jelszo-1"), "unchanged")
        self.assertFalse(self.store.verify("admin", "hosszu-jelszo-1"))
        self.assertTrue(self.store.verify("admin", "sajat-jelszo-3"))
        self.assertFalse(self.store.record("admin").must_change_password)

    def test_changed_env_password_resets_and_forces_change(self) -> None:
        self._provision(True, "admin", "hosszu-jelszo-1")
        self.store.set_password("admin", "sajat-jelszo-3")
        self.assertEqual(self._provision(True, "admin", "uj-env-jelszo-4"), "updated")
        self.assertTrue(self.store.verify("admin", "uj-env-jelszo-4"))
        self.assertFalse(self.store.verify("admin", "sajat-jelszo-3"))
        self.assertTrue(self.store.record("admin").must_change_password)

    def test_legacy_record_without_marker_gets_one(self) -> None:
        self.store.add("admin", "hosszu-jelszo-1", role=gateway.ROLE_ADMIN)
        self.assertFalse(self.store.record("admin").must_change_password)
        self.assertEqual(self._provision(True, "admin", "hosszu-jelszo-1"), "updated")
        self.assertTrue(self.store.provisioned_from("admin"))
        self.assertTrue(self.store.record("admin").must_change_password)
        self.assertTrue(self.store.verify("admin", "hosszu-jelszo-1"))


# ------------------------------------------------------------------ munkamenet

class SessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tools = FakeTools(self.tmp.name)
        self._old_conntrack = gateway.CONNTRACK_BIN
        gateway.CONNTRACK_BIN = str(self.tools.conntrack)
        self.fw = gateway.Firewall(
            binary=str(self.tools.nft), logger=lambda *_: None
        )
        self.sessions = gateway.SessionManager(
            self.fw, ttl=3600, pending_ttl=600
        )
        self.web_rule = make_rule("web-only", ("web",))
        self.icmp_rule = make_rule("icmp-only", ("icmp",))
        # A host SSH ma már csak egy közönséges, a felhasználóhoz rendelt
        # host (input) szabállyal nyitható, amely kifejezetten a 22-es
        # TCP-portot engedélyezi.
        self.admin_rule = gateway.Rule(
            id="host-ssh",
            label="Host SSH",
            description="",
            tcp=(22,),
            direction="input",
        )

    def tearDown(self) -> None:
        gateway.CONNTRACK_BIN = self._old_conntrack
        self.tmp.cleanup()

    def conntrack_lines(self) -> list[str]:
        return [line for line in self.tools.lines() if line.startswith("conntrack ")]

    def test_login_is_pending_and_grants_nothing(self) -> None:
        session = self.sessions.login("alice", "192.168.50.23")
        self.assertEqual(session.user, "alice")
        self.assertEqual(session.ip, "192.168.50.23")
        self.assertFalse(session.authorized)
        self.assertEqual(session.ports, gateway.Ports())
        self.assertIsNotNone(self.sessions.validate(session.token, "192.168.50.23"))
        # Az IP-hez kötött munkamenet más IP-ről érkező ellenőrzésre
        # megszűnik (és a hozzá tartozó engedély is visszavonódik).
        self.assertIsNone(self.sessions.validate(session.token, "192.168.50.24"))
        self.assertIsNone(self.sessions.validate("hamis", "192.168.50.23"))
        self.assertEqual(self.sessions.count(), 0)
        self.assertEqual(self.sessions.count(authorized_only=True), 0)
        self.assertEqual(self.tools.lines(), [])

    def test_authorize_grants_selected_services(self) -> None:
        session = self.sessions.login("alice", "192.168.50.23")
        web_dns = make_rule("web-dns", ("web", "dns"))
        authorized = self.sessions.authorize(
            session.token, "192.168.50.23", web_dns, 90
        )
        self.assertTrue(authorized.authorized)
        self.assertEqual(authorized.ports, web_dns.ports)
        self.assertEqual(authorized.rule, "web-dns")
        self.assertGreaterEqual(authorized.expires_in, 85)
        self.assertLessEqual(authorized.expires_in, 90)
        self.assertEqual(self.sessions.count(authorized_only=True), 1)

        script = self.tools.script()
        for line in (
            "add element inet hatarvedelem allowed_tcp { 192.168.50.23 . 80 timeout 90s }",
            "add element inet hatarvedelem allowed_tcp { 192.168.50.23 . 443 timeout 90s }",
            "add element inet hatarvedelem allowed_udp { 192.168.50.23 . 443 timeout 90s }",
            "add element inet hatarvedelem allowed_tcp { 192.168.50.23 . 53 timeout 90s }",
            "add element inet hatarvedelem allowed_tcp { 192.168.50.23 . 853 timeout 90s }",
            "add element inet hatarvedelem allowed_udp { 192.168.50.23 . 53 timeout 90s }",
            "add element inet hatarvedelem allowed_udp { 192.168.50.23 . 853 timeout 90s }",
        ):
            self.assertIn(line, script)
        self.assertFalse(
            any("allowed_input_tcp" in line for line in script), script
        )
        self.assertFalse(any("allowed_v4" in line for line in script), script)
        # Előző engedély hiányában nincs conntrack-takarítás.
        self.assertEqual(self.conntrack_lines(), [])

    def test_authorize_validation(self) -> None:
        session = self.sessions.login("alice", "192.168.50.23")
        with self.assertRaises(gateway.AccessError):
            self.sessions.authorize(session.token, "192.168.50.23", None, 60)
        with self.assertRaises(gateway.AccessError):
            self.sessions.authorize(
                session.token, "192.168.50.23", "web-only", 60,
            )
        with self.assertRaises(gateway.AccessError):
            self.sessions.authorize(
                session.token, "192.168.50.23", self.web_rule,
                gateway.MIN_TTL - 1,
            )
        with self.assertRaises(gateway.AccessError):
            self.sessions.authorize(
                session.token, "192.168.50.23", self.web_rule,
                gateway.MAX_TTL + 1,
            )
        with self.assertRaises(gateway.AccessError):
            self.sessions.authorize(
                session.token, "192.168.50.23",
                make_rule("short", ("web",), max_ttl=60), 120,
            )
        with self.assertRaises(gateway.AccessError):
            self.sessions.authorize(session.token, "10.0.0.9", self.web_rule, 60)
        with self.assertRaises(gateway.AccessError):
            self.sessions.authorize("hamis", "192.168.50.23", self.web_rule, 60)
        self.assertEqual(self.sessions.count(authorized_only=True), 0)
        self.assertEqual(self.tools.script(), [])

    def test_logout_pending_does_not_touch_firewall(self) -> None:
        session = self.sessions.login("alice", "192.168.50.23")
        self.tools.clear()
        self.assertTrue(self.sessions.logout(session.token, "192.168.50.23"))
        self.assertIsNone(self.sessions.validate(session.token, "192.168.50.23"))
        self.assertFalse(self.sessions.logout(session.token, "192.168.50.23"))
        self.assertEqual(self.tools.lines(), [])

    def test_logout_authorized_revokes_all_services(self) -> None:
        session = self.sessions.login("alice", "192.168.50.23")
        self.sessions.authorize(session.token, "192.168.50.23", self.web_rule, 60)
        self.tools.clear()

        self.assertTrue(self.sessions.logout(session.token, "192.168.50.23"))
        self.assertIsNone(self.sessions.validate(session.token, "192.168.50.23"))
        self.assertEqual(self.sessions.count(), 0)

        deletes = self.tools.deletes()
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_v4 { 192.168.50.23 }",
            deletes,
        )
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_icmp { 192.168.50.23 }",
            deletes,
        )
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_tcp { 192.168.50.23 . 80 }",
            deletes,
        )
        self.assertTrue(
            any(line.startswith("conntrack -D -s 192.168.50.23") for line in self.tools.lines())
        )

    def test_modify_authorization_revokes_old_grants(self) -> None:
        session = self.sessions.login("alice", "192.168.50.23")
        self.sessions.authorize(session.token, "192.168.50.23", self.web_rule, 300)
        self.tools.clear()

        updated = self.sessions.authorize(
            session.token, "192.168.50.23", self.icmp_rule, 60
        )
        self.assertEqual(updated.ports, self.icmp_rule.ports)
        deletes = self.tools.deletes()
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_tcp { 192.168.50.23 . 80 }",
            deletes,
        )
        script = self.tools.script()
        self.assertIn(
            "add element inet hatarvedelem allowed_icmp { 192.168.50.23 timeout 60s }",
            script,
        )
        self.assertFalse(
            any("allowed_input_tcp" in line for line in script), script
        )
        self.assertTrue(
            any(line.startswith("conntrack -D -s 192.168.50.23") for line in self.tools.lines())
        )

    def test_authorize_failure_resets_to_pending(self) -> None:
        session = self.sessions.login("alice", "192.168.50.23")
        self.tools.make_fail("nft: Operation not permitted")
        with self.assertRaises(gateway.FirewallError):
            self.sessions.authorize(session.token, "192.168.50.23", self.web_rule, 60)

        current = self.sessions.validate(session.token, "192.168.50.23")
        self.assertIsNotNone(current)
        self.assertFalse(current.authorized)
        self.assertEqual(current.ports, gateway.Ports())
        self.assertEqual(self.sessions.count(authorized_only=True), 0)

        self.tools.clear_fail()
        authorized = self.sessions.authorize(
            session.token, "192.168.50.23", self.web_rule, 60
        )
        self.assertTrue(authorized.authorized)

    def test_reaper_revokes_expired_authorized_sessions(self) -> None:
        alice = self.sessions.login("alice", "192.168.50.23")
        self.sessions.authorize(alice.token, "192.168.50.23", self.web_rule, 60)
        bob = self.sessions.login("bob", "192.168.50.24")  # függő, nincs engedély
        self.tools.clear()

        revoked = self.sessions.reap_once(now=time.time() + 7200)
        self.assertEqual(revoked, 1)
        self.assertEqual(self.sessions.count(), 0)
        self.assertIsNone(self.sessions.validate(alice.token, "192.168.50.23"))
        self.assertIsNone(self.sessions.validate(bob.token, "192.168.50.24"))

        lines = self.tools.lines()
        self.assertTrue(
            any("allowed_tcp { 192.168.50.23 . 80 }" in line for line in lines), lines
        )
        self.assertFalse(any("192.168.50.24" in line for line in lines), lines)

    def test_second_login_replaces_authorized_session(self) -> None:
        first = self.sessions.login("alice", "192.168.50.23")
        self.sessions.authorize(first.token, "192.168.50.23", self.web_rule, 300)
        self.tools.clear()

        second = self.sessions.login("alice", "192.168.50.23")
        self.assertIsNone(self.sessions.validate(first.token, "192.168.50.23"))
        self.assertIsNotNone(self.sessions.validate(second.token, "192.168.50.23"))
        self.assertFalse(second.authorized)
        self.assertEqual(self.sessions.count(authorized_only=True), 0)

        deletes = self.tools.deletes()
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_tcp { 192.168.50.23 . 80 }",
            deletes,
        )
        self.assertTrue(
            any(line.startswith("conntrack -D -s 192.168.50.23") for line in self.tools.lines())
        )
        end = self.sessions.last_end("192.168.50.23")
        self.assertIsNotNone(end)
        self.assertEqual(end["reason"], "replaced")
        self.assertIn("IP-címről", end["message"])

    def test_snapshot_contains_ua_and_remaining_time(self) -> None:
        session = self.sessions.login(
            "alice", "192.168.50.23", ua="Mozilla/5.0 teszt"
        )
        self.sessions.authorize(session.token, "192.168.50.23", self.web_rule, 120)
        rows = self.sessions.active_sessions()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["user"], "alice")
        self.assertEqual(row["ua"], "Mozilla/5.0 teszt")
        self.assertTrue(row["authorized"])
        self.assertEqual(row["rule"], "web-only")
        self.assertEqual(row["ttl"], 120)
        self.assertGreater(row["expires_in"], 0)
        self.assertLessEqual(row["expires_in"], 120)
        self.assertGreater(row["logged_in"], 0)
        self.assertTrue(row["id"])
        self.assertEqual(row["id"], session.sid)
        # A forward szabály munkamenete is megkapja az irányt, hogy az
        # adminlista és a csoportos nézet egyértelmű legyen.
        self.assertEqual(row["direction"], "forward")

    def test_snapshot_contains_input_direction_for_host_rule(self) -> None:
        host_rule = gateway.Rule(
            id="host-25566",
            label="mpwerks (host)",
            description="",
            tcp=(25566,),
            default_ttl=300,
            max_ttl=600,
            direction="input",
        )
        session = self.sessions.login("alice", "192.168.50.23")
        self.sessions.authorize(session.token, "192.168.50.23", host_rule, 120)
        row = self.sessions.active_sessions()[0]
        self.assertEqual(row["direction"], "input")
        self.assertEqual(row["rule"], "host-25566")
        self.assertEqual(row["ports_label"], "TCP 25566")
        self.assertEqual(row["tcp"], [25566])

    def test_mixed_collection_grants_and_revocation(self) -> None:
        # Feloldott, vegyes irányú gyűjtő: forward TCP 80 és host
        # TCP/UDP 25566 engedély.
        mixed = gateway.Rule(
            id="mixed-col",
            label="Mixed collection",
            description="",
            tcp=(80,),
            input_tcp=(25566,),
            input_udp=(25566,),
            members=("mix-web", "mix-host"),
            direction="mixed",
            default_ttl=300,
            max_ttl=600,
        )
        self.assertEqual(
            [part.direction for part in mixed.grants], ["forward", "input"]
        )
        session = self.sessions.login("alice", "192.168.50.23")
        authorized = self.sessions.authorize(
            session.token, "192.168.50.23", mixed, 120
        )
        self.assertEqual(authorized.direction, "mixed")
        self.assertEqual(authorized.grant_parts, mixed.grants)
        self.assertEqual(authorized.grants, mixed.grants)
        self.assertEqual(authorized.ports.direction, "forward")
        self.assertEqual(authorized.ports.tcp, (80, 25566))
        self.assertEqual(authorized.ports.udp, (25566,))

        row = self.sessions.active_sessions()[0]
        self.assertEqual(row["direction"], "mixed")
        self.assertEqual(row["grants"], [
            {
                "direction": "forward", "tcp": [80], "udp": [],
                "icmp": False, "full": False,
            },
            {
                "direction": "input", "tcp": [25566], "udp": [25566],
                "icmp": False, "full": False,
            },
        ])
        self.assertEqual(row["tcp"], [80, 25566])
        self.assertEqual(row["udp"], [25566])
        script = self.tools.script()
        self.assertIn(
            "add element inet hatarvedelem allowed_tcp "
            "{ 192.168.50.23 . 80 timeout 120s }",
            script,
        )
        self.assertIn(
            "add element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.23 . 25566 timeout 120s }",
            script,
        )
        self.assertIn(
            "add element inet hatarvedelem allowed_input_udp "
            "{ 192.168.50.23 . 25566 timeout 120s }",
            script,
        )

        # Módosítás: mindkét irány régi engedélye törlődik.
        self.tools.clear()
        self.sessions.authorize(
            session.token, "192.168.50.23", self.web_rule, 60
        )
        deletes = self.tools.deletes()
        for line in (
            "nft delete element inet hatarvedelem allowed_tcp "
            "{ 192.168.50.23 . 80 }",
            "nft delete element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.23 . 25566 }",
            "nft delete element inet hatarvedelem allowed_input_udp "
            "{ 192.168.50.23 . 25566 }",
        ):
            self.assertIn(line, deletes)

        # Lejárat: szintén mindkét irány törlődik.
        self.sessions.authorize(
            session.token, "192.168.50.23", mixed, 60
        )
        self.tools.clear()
        self.assertEqual(self.sessions.reap_once(now=time.time() + 7200), 1)
        deletes = self.tools.deletes()
        for line in (
            "nft delete element inet hatarvedelem allowed_tcp "
            "{ 192.168.50.23 . 80 }",
            "nft delete element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.23 . 25566 }",
            "nft delete element inet hatarvedelem allowed_input_udp "
            "{ 192.168.50.23 . 25566 }",
        ):
            self.assertIn(line, deletes)

        # Kijelentkezés: szintén mindkét irány engedélye törlődik.
        second = self.sessions.login("bob", "192.168.50.24")
        self.sessions.authorize(second.token, "192.168.50.24", mixed, 60)
        self.tools.clear()
        self.assertIsNotNone(
            self.sessions.logout(second.token, "192.168.50.24")
        )
        deletes = self.tools.deletes()
        for line in (
            "nft delete element inet hatarvedelem allowed_tcp "
            "{ 192.168.50.24 . 80 }",
            "nft delete element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.24 . 25566 }",
            "nft delete element inet hatarvedelem allowed_input_udp "
            "{ 192.168.50.24 . 25566 }",
        ):
            self.assertIn(line, deletes)

    def test_terminate_specific_session(self) -> None:
        alice = self.sessions.login("alice", "192.168.50.23")
        bob = self.sessions.login("bob", "192.168.50.24")
        self.sessions.authorize(alice.token, "192.168.50.23", self.web_rule, 120)
        self.tools.clear()

        ended = self.sessions.terminate(alice.sid)
        self.assertIsNotNone(ended)
        self.assertEqual(ended.user, "alice")
        self.assertEqual(ended.sid, alice.sid)
        self.assertIsNone(self.sessions.validate(alice.token, "192.168.50.23"))
        self.assertIsNotNone(self.sessions.validate(bob.token, "192.168.50.24"))
        self.assertEqual(self.sessions.last_end("192.168.50.23")["reason"],
                         "admin_terminated")

        deletes = self.tools.deletes()
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_tcp { 192.168.50.23 . 80 }",
            deletes,
        )
        self.assertTrue(
            any(line.startswith("conntrack -D -s 192.168.50.23")
                for line in self.tools.lines())
        )
        self.assertFalse(
            any("192.168.50.24" in line for line in self.tools.lines()),
            self.tools.lines(),
        )
        self.assertIsNone(self.sessions.terminate("nincs-ilyen-azonosito"))
        self.assertIsNone(self.sessions.terminate(""))

    def test_revoke_user_can_keep_one_session(self) -> None:
        alice = self.sessions.login("alice", "192.168.50.23")
        bob = self.sessions.login("bob", "192.168.50.24")
        self.assertEqual(
            self.sessions.revoke_user("alice", except_token=alice.token), 0
        )
        self.assertIsNotNone(
            self.sessions.validate(alice.token, "192.168.50.23")
        )
        self.assertEqual(
            self.sessions.revoke_user("alice", reason="password_changed"), 1
        )
        self.assertIsNone(self.sessions.validate(alice.token, "192.168.50.23"))
        self.assertIsNotNone(self.sessions.validate(bob.token, "192.168.50.24"))
        self.assertEqual(self.sessions.last_end("192.168.50.23")["reason"],
                         "password_changed")

    def test_logout_records_reason(self) -> None:
        session = self.sessions.login("alice", "192.168.50.23")
        self.assertIsNotNone(self.sessions.logout(session.token, "192.168.50.23"))
        self.assertEqual(self.sessions.last_end("192.168.50.23")["reason"], "logout")
        self.assertEqual(self.sessions.active_sessions(), [])

    # -- host SSH: csak a felhasználóhoz rendelt, 22/TCP host szabály -------

    def _host_ssh_script(
        self, manager: gateway.SessionManager, rule: gateway.Rule
    ) -> list[str]:
        session = manager.login("user", "192.168.50.23")
        manager.authorize(session.token, "192.168.50.23", rule, 60)
        return [
            line for line in self.tools.script()
            if "allowed_input_tcp" in line and ". 22 " in line
        ]

    def test_host_ssh_requires_explicit_host_22_rule(self) -> None:
        manager = gateway.SessionManager(
            self.fw, ttl=3600, pending_ttl=600
        )
        # Szűk szolgáltatási szabály nem nyit SSH-t.
        self.assertEqual(self._host_ssh_script(manager, self.web_rule), [])
        # Egyedi teljes hozzáférésű (forward) szabály sem nyit host SSH-t.
        self.tools.clear()
        custom_full = make_rule("custom-full", ("all",))
        self.assertTrue(custom_full.full)
        self.assertEqual(self._host_ssh_script(manager, custom_full), [])
        # A 22-es TCP-portot kifejezetten engedélyező host szabály viszont
        # igen, a TTL-jével, és a szokásos MAC-kötéssel.
        self.tools.clear()
        self.assertEqual(
            self._host_ssh_script(manager, self.admin_rule),
            [
                "add element inet hatarvedelem allowed_input_tcp "
                "{ 192.168.50.23 . 22 timeout 60s }"
            ],
        )

    def test_switching_away_from_host_22_rule_revokes_ssh(self) -> None:
        session = self.sessions.login("alice", "192.168.50.23")
        self.sessions.authorize(
            session.token, "192.168.50.23", self.admin_rule, 300
        )
        self.assertIn(
            "add element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.23 . 22 timeout 300s }",
            self.tools.script(),
        )
        self.tools.clear()

        self.sessions.authorize(
            session.token, "192.168.50.23", self.web_rule, 60
        )
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.23 . 22 }",
            self.tools.deletes(),
        )
        self.assertFalse(
            any("allowed_input_tcp" in line for line in self.tools.script()),
            self.tools.script(),
        )

    def test_host_ssh_revoked_on_logout_and_shutdown(self) -> None:
        session = self.sessions.login("alice", "192.168.50.23")
        self.sessions.authorize(
            session.token, "192.168.50.23", self.admin_rule, 120
        )
        self.tools.clear()
        self.assertIsNotNone(
            self.sessions.logout(session.token, "192.168.50.23")
        )
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.23 . 22 }",
            self.tools.deletes(),
        )

        second = self.sessions.login("bob", "192.168.50.24")
        self.sessions.authorize(
            second.token, "192.168.50.24", self.admin_rule, 120
        )
        self.tools.clear()
        self.assertEqual(self.sessions.shutdown(), 1)
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_input_tcp "
            "{ 192.168.50.24 . 22 }",
            self.tools.deletes(),
        )

    # -- versenyhelyzetek és leállás ---------------------------------------

    def test_rule_check_rejects_removed_rule(self) -> None:
        manager = gateway.SessionManager(
            self.fw, ttl=3600, pending_ttl=600,
            rule_check=lambda user, rule: False,
        )
        session = manager.login("alice", "192.168.50.23")
        with self.assertRaises(gateway.AccessError):
            manager.authorize(
                session.token, "192.168.50.23", self.web_rule, 60
            )
        self.assertFalse(
            any("allowed_tcp" in line for line in self.tools.script())
        )

    def test_shutdown_revokes_active_grants(self) -> None:
        session = self.sessions.login("alice", "192.168.50.23")
        self.sessions.authorize(
            session.token, "192.168.50.23", self.web_rule, 60
        )
        self.tools.clear()
        self.assertEqual(self.sessions.shutdown(), 1)
        deletes = self.tools.deletes()
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_tcp "
            "{ 192.168.50.23 . 80 }",
            deletes,
        )
        self.assertEqual(self.sessions.count(), 0)
        self.assertGreaterEqual(len(self.conntrack_lines()), 1)

    def test_expiry_revokes_socket_and_firewall(self) -> None:
        session = self.sessions.login("alice", "192.168.50.23")
        self.sessions.authorize(
            session.token, "192.168.50.23", self.web_rule, 60
        )
        # A munkamenet lejártát szimuláljuk: a válasznak hibának kell lennie,
        # és a tűzfalengedélynek azonnal törlődnie kell.
        with self.sessions._lock:
            self.sessions._sessions[session.token] = gateway.replace(
                self.sessions._sessions[session.token], expires=time.time() - 1
            )
        self.tools.clear()
        with self.assertRaises(gateway.AccessError):
            self.sessions.authorize(
                session.token, "192.168.50.23", self.web_rule, 60
            )
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_tcp "
            "{ 192.168.50.23 . 80 }",
            self.tools.deletes(),
        )


class UnionGrantsTests(unittest.TestCase):
    """A ``union_grants`` irányonkénti és determinisztikus uniója."""

    def test_full_absorbs_other_parts_in_the_same_direction(self) -> None:
        union = gateway.union_grants((
            gateway.Ports(tcp=(443,), udp=(53,)),
            gateway.Ports(full=True, direction="forward"),
            gateway.Ports(tcp=(80,), icmp=True),
        ))
        self.assertEqual(
            union, (gateway.Ports(full=True, direction="forward"),)
        )

    def test_ports_are_unioned_sorted_and_ordered_forward_first(self) -> None:
        union = gateway.union_grants((
            gateway.Ports(tcp=(443, 80), udp=(53,), direction="forward"),
            gateway.Ports(tcp=(80,), icmp=True, direction="forward"),
            gateway.Ports(tcp=(22,), direction="input"),
        ))
        self.assertEqual(
            union,
            (
                gateway.Ports(
                    tcp=(80, 443), udp=(53,), icmp=True,
                    direction="forward",
                ),
                gateway.Ports(tcp=(22,), direction="input"),
            ),
        )

    def test_empty_parts_are_omitted(self) -> None:
        self.assertEqual(gateway.union_grants(()), ())
        self.assertEqual(
            gateway.union_grants((gateway.Ports(), gateway.Ports())), ()
        )

    def test_unknown_direction_raises_firewall_error(self) -> None:
        with self.assertRaises(gateway.FirewallError):
            gateway.union_grants((gateway.Ports(direction="bogus"),))


class SubtractGrantsTests(unittest.TestCase):
    """Az aktív teljes hozzáférés csak a távozó teljes részt fedi."""

    def test_active_full_keeps_non_full_parts_for_exact_deletion(self) -> None:
        # A portos/ICMP elemek a kernelben léteznek, és a munkamenet
        # összevont grant_parts-ából eltűntek; ezért a maradéknak
        # tartalmaznia kell őket, hogy a revoke_exact törölhesse. Ha itt
        # kimaradnának, a teljes hozzáférés későbbi visszavonásakor újra
        # előbukkannának.
        forward = gateway.Ports(
            tcp=(80,), icmp=True, direction="forward"
        )
        result = gateway.SessionManager._subtract_grants(
            (
                forward,
                gateway.Ports(tcp=(22,), direction="input"),
            ),
            (gateway.Ports(full=True, direction="forward"),),
        )
        self.assertEqual(
            result,
            (
                forward,
                gateway.Ports(tcp=(22,), direction="input"),
            ),
        )

    def test_removed_full_covered_by_active_full_is_dropped(self) -> None:
        full = gateway.Ports(full=True, direction="forward")
        result = gateway.SessionManager._subtract_grants(
            (full,), (full,)
        )
        self.assertEqual(result, ())

    def test_removed_full_is_kept_without_active_full(self) -> None:
        full = gateway.Ports(full=True, direction="forward")
        result = gateway.SessionManager._subtract_grants(
            (full,), (gateway.Ports(tcp=(80,), direction="forward"),)
        )
        self.assertEqual(result, (full,))


class MultiSelectionTests(unittest.TestCase):
    """Több egyidejű szabályválasztás a valódi tűzfallal."""

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

    def conntrack_lines(self) -> list[str]:
        return [
            line for line in self.tools.lines()
            if line.startswith("conntrack ")
        ]

    @staticmethod
    def rule(
        rule_id: str,
        *,
        label: str | None = None,
        tcp=(),
        udp=(),
        icmp: bool = False,
        full: bool = False,
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
            max_ttl=max_ttl,
        )

    def login(self) -> gateway.Session:
        return self.sessions.login("alice", self.IP)

    def test_authorize_union_grants_overlapping_port_once(self) -> None:
        web = self.rule("web", label="Web", tcp=(80,), udp=(53,))
        secure = self.rule("secure", label="Secure", tcp=(80, 443))
        session = self.login()

        authorized = self.sessions.authorize(
            session.token, self.IP, [web, secure], 120
        )

        self.assertEqual(authorized.rules, ("web", "secure"))
        self.assertEqual(authorized.rule, "web")
        self.assertEqual(authorized.rule_label, "Web")
        self.assertEqual(
            authorized.rule_parts,
            (
                gateway.RuleSelection("web", "Web", web.grants),
                gateway.RuleSelection("secure", "Secure", secure.grants),
            ),
        )
        self.assertEqual(
            authorized.grant_parts,
            (
                gateway.Ports(
                    tcp=(80, 443), udp=(53,), direction="forward"
                ),
            ),
        )
        self.assertEqual(authorized.tcp, (80, 443))
        self.assertEqual(authorized.udp, (53,))
        script = self.tools.script()
        self.assertEqual(
            len([
                line for line in script
                if "allowed_tcp" in line and ". 80 " in line
            ]),
            1,
            script,
        )
        row = self.sessions.active_sessions()[0]
        self.assertEqual(row["rule"], "web")
        self.assertEqual(row["rule_label"], "Web")
        self.assertEqual(row["selected_rules"], ["web", "secure"])
        self.assertEqual(
            row["selected_rule_labels"], ["Web", "Secure"]
        )

    def test_single_rule_and_duplicate_ids_are_compatible(self) -> None:
        web = self.rule("web", tcp=(80,))
        secure = self.rule("secure", tcp=(443,))
        session = self.login()

        single = self.sessions.authorize(
            session.token, self.IP, web, 60
        )
        self.assertEqual(single.rules, ("web",))
        self.assertEqual(single.rule, "web")
        self.assertEqual(single.rule_parts[0].rule_id, "web")

        updated = self.sessions.authorize(
            session.token, self.IP, [web, secure, web], 60
        )
        self.assertEqual(updated.rules, ("web", "secure"))
        self.assertEqual(
            [part.rule_id for part in updated.rule_parts],
            ["web", "secure"],
        )
        self.assertEqual(
            updated.grant_parts,
            (gateway.Ports(tcp=(80, 443), direction="forward"),),
        )

    def test_authorize_rejects_invalid_rule_collections(self) -> None:
        session = self.login()
        empty = self.rule("empty")
        for value in (None, "web", [], [None], [self.rule("ok"), "x"]):
            with self.assertRaises(gateway.AccessError) as ctx:
                self.sessions.authorize(session.token, self.IP, value, 60)
            self.assertEqual(
                str(ctx.exception), "érvénytelen hozzáférési szabály"
            )
        with self.assertRaises(gateway.AccessError) as ctx:
            self.sessions.authorize(
                session.token, self.IP, [empty], 60
            )
        self.assertEqual(
            str(ctx.exception), "ez a szabály nem ad hozzáférést"
        )
        self.assertEqual(self.sessions.count(authorized_only=True), 0)
        self.assertEqual(self.tools.script(), [])

    def test_multi_rule_ttl_uses_strictest_max_ttl(self) -> None:
        long_rule = self.rule("long", label="Hosszú", tcp=(80,), max_ttl=600)
        short_rule = self.rule(
            "short", label="Rövid", tcp=(443,), max_ttl=300
        )
        session = self.login()

        with self.assertRaises(gateway.AccessError) as ctx:
            self.sessions.authorize(
                session.token, self.IP, [long_rule, short_rule], 301
            )
        message = str(ctx.exception)
        self.assertIn("Rövid", message)
        self.assertIn("szabály miatt legfeljebb", message)
        self.assertIn("5 perc", message)
        self.assertEqual(self.sessions.count(authorized_only=True), 0)
        self.assertEqual(self.tools.script(), [])

        # A legszigorúbb szabály max_ttl-je még éppen elfogadható.
        accepted = self.sessions.authorize(
            session.token, self.IP, [long_rule, short_rule], 300
        )
        self.assertTrue(accepted.authorized)

        # Egyetlen szabálynál a régi hibaüzenet marad.
        with self.assertRaises(gateway.AccessError) as ctx:
            self.sessions.authorize(
                session.token, self.IP, short_rule, 301
            )
        self.assertEqual(
            str(ctx.exception),
            "ez a szabály legfeljebb 5 perc időtartamra engedélyez",
        )

    def test_partial_revoke_rule_keeps_session_and_other_grants(self) -> None:
        first = self.rule("first", label="Első", tcp=(80, 8080))
        second = self.rule("second", label="Második", tcp=(80, 443))
        session = self.login()
        authorized = self.sessions.authorize(
            session.token, self.IP, [first, second], 120
        )
        expires = authorized.expires
        self.tools.clear()

        self.assertEqual(self.sessions.revoke_rule("first"), 1)

        current = self.sessions.validate(session.token, self.IP)
        self.assertIsNotNone(current)
        self.assertTrue(current.authorized)
        self.assertEqual(current.rules, ("second",))
        self.assertEqual(current.rule, "second")
        self.assertEqual(current.rule_label, "Második")
        self.assertEqual(
            current.grant_parts,
            (gateway.Ports(tcp=(80, 443), direction="forward"),),
        )
        self.assertEqual(current.expires, expires)

        deletes = self.tools.deletes()
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_tcp "
            f"{{ {self.IP} . 8080 }}",
            deletes,
        )
        # A maradó elemeket a grant_all az időtúllépés újraindításához
        # törölheti, de ezeket ugyanabban a folyamatban vissza is adja, és
        # a revoke_exact nem érintette őket.
        adds = [
            line for line in self.tools.script()
            if line.startswith("add element ")
        ]
        for port in (80, 443):
            self.assertTrue(
                any(
                    line.startswith(
                        "add element inet hatarvedelem allowed_tcp "
                        f"{{ {self.IP} . {port} timeout "
                    )
                    for line in adds
                ),
                adds,
            )
        self.assertFalse(
            any("allowed_v4" in line for line in deletes), deletes
        )
        # Csak a távozó port kapcsolatai szakadnak meg, nem az egész IP.
        lines = self.conntrack_lines()
        self.assertIn(
            f"conntrack -D -s {self.IP} -p tcp --dport 8080", lines
        )
        self.assertNotIn(f"conntrack -D -s {self.IP}", lines)
        # Újabb hívás már nem érinti a munkamenetet.
        self.assertEqual(self.sessions.revoke_rule("first"), 0)
        self.assertIsNotNone(self.sessions.validate(session.token, self.IP))

    def test_revoke_user_rules_keeps_other_users_and_selections(self) -> None:
        first = self.rule("first", tcp=(80,))
        second = self.rule("second", tcp=(443,))
        alice = self.sessions.login("alice", self.IP)
        bob = self.sessions.login("bob", "192.168.50.24")
        self.sessions.authorize(
            alice.token, self.IP, [first, second], 120
        )
        self.sessions.authorize(
            bob.token, "192.168.50.24", [first], 120
        )

        self.assertEqual(
            self.sessions.revoke_user_rules("alice", ["first"]), 1
        )

        alice_current = self.sessions.validate(alice.token, self.IP)
        self.assertIsNotNone(alice_current)
        self.assertEqual(alice_current.rules, ("second",))
        bob_current = self.sessions.validate(
            bob.token, "192.168.50.24"
        )
        self.assertIsNotNone(bob_current)
        self.assertEqual(bob_current.rules, ("first",))

    def test_expired_session_is_not_regranted_by_partial_revoke(self) -> None:
        first = self.rule("first", label="Első", tcp=(80,))
        second = self.rule("second", label="Második", tcp=(443,))
        session = self.login()
        authorized = self.sessions.authorize(
            session.token, self.IP, [first, second], 120
        )
        authorized.expires = time.time() - 1
        self.tools.clear()

        self.assertEqual(self.sessions.revoke_rule("first"), 1)

        # A lejárt munkamenet nem maradhat részlegesen frissítve a
        # nyilvántartásban, és a maradó választás grantjeit sem szabad
        # újra kiadni.
        self.assertNotIn(session.token, self.sessions._sessions)
        self.assertEqual(self.sessions.count(), 0)
        self.assertEqual(
            [
                line for line in self.tools.script()
                if line.startswith("add element ")
            ],
            [],
        )
        self.assertIsNone(self.sessions.validate(session.token, self.IP))

    def test_revoke_rules_removes_rule_and_collection_in_one_pass(self) -> None:
        rule = self.rule("rule", label="Szabály", tcp=(80,))
        collection = gateway.Rule(
            id="collection",
            label="Gyűjtő",
            description="",
            tcp=(80, 443),
            members=("rule",),
            max_ttl=3600,
        )
        session = self.login()
        self.sessions.authorize(
            session.token, self.IP, [rule, collection], 120
        )
        self.tools.clear()

        self.assertEqual(
            self.sessions.revoke_rules((rule.id, collection.id)), 1
        )

        # Egy zárolás alatt a teljes választáshalmaz tűnik el; nincs
        # köztes, részleges újrakiadás.
        self.assertNotIn(session.token, self.sessions._sessions)
        self.assertEqual(self.sessions.count(), 0)
        self.assertEqual(
            [
                line for line in self.tools.script()
                if line.startswith("add element ")
            ],
            [],
        )

    def test_removing_full_selection_deletes_allowed_v4_and_keeps_session(
        self,
    ) -> None:
        full = self.rule("full", label="Teljes", full=True)
        ports = self.rule("ports", label="Portok", tcp=(443,))
        session = self.login()
        authorized = self.sessions.authorize(
            session.token, self.IP, [full, ports], 120
        )
        self.assertEqual(
            authorized.grant_parts,
            (gateway.Ports(full=True, direction="forward"),),
        )
        self.assertIn(
            "add element inet hatarvedelem allowed_v4 "
            f"{{ {self.IP} timeout 120s }}",
            self.tools.script(),
        )
        self.assertFalse(
            any("allowed_tcp" in line for line in self.tools.script())
        )
        self.tools.clear()

        self.assertEqual(self.sessions.revoke_rule("full"), 1)

        current = self.sessions.validate(session.token, self.IP)
        self.assertIsNotNone(current)
        self.assertTrue(current.authorized)
        self.assertEqual(current.rules, ("ports",))
        self.assertEqual(
            current.grant_parts,
            (gateway.Ports(tcp=(443,), direction="forward"),),
        )
        deletes = self.tools.deletes()
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_v4 "
            f"{{ {self.IP} }}",
            deletes,
        )
        self.assertFalse(
            any("allowed_icmp" in line for line in deletes), deletes
        )
        self.assertFalse(
            any("client_mac" in line for line in deletes), deletes
        )
        # A 443-as port a munkamenetben továbbra is engedélyezett, ezért a
        # teljes IP-s ürítés megszakítaná annak élő kapcsolatait. A távozó
        # full elemhez célzott törlés sem indítható, így nincs conntrack-hívás.
        self.assertEqual(self.conntrack_lines(), [])
        # A maradó port eddig az allowed_v4 alatt élt; a törlése után külön
        # kernel-elemként újra ki kell adni, különben a munkamenet papíron
        # élne, de a portja nem lenne engedélyezve.
        adds = [
            line for line in self.tools.script()
            if line.startswith("add element ")
        ]
        self.assertTrue(
            any(
                line.startswith(
                    "add element inet hatarvedelem allowed_tcp "
                    f"{{ {self.IP} . 443 timeout "
                )
                for line in adds
            ),
            adds,
        )


class ConntrackFlushRemovedTests(unittest.TestCase):
    """A célzott conntrack-törlés irányvak és kíméli a maradó engedélyeket."""

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

    def conntrack_lines(self) -> list[str]:
        return [
            line for line in self.tools.lines()
            if line.startswith("conntrack ")
        ]

    def test_removed_full_does_not_flush_remaining_input_ssh(self) -> None:
        # Egy teljes forward hozzáférést input-22 vált fel: a teljes IP-s
        # ürítés megszakítaná a még engedélyezett SSH-kapcsolatot.
        result = gateway.conntrack_flush_removed(
            self.IP,
            (gateway.Ports(full=True, direction="forward"),),
            (gateway.Ports(tcp=(22,), direction="input"),),
        )
        self.assertFalse(result)
        self.assertEqual(self.conntrack_lines(), [])

    def test_removed_port_kept_by_other_direction_is_not_flushed(self) -> None:
        # A conntrack -D -s irányvak: a 80-as portot egy input engedély
        # továbbra is használja, ezért nem szabad célzottan törölni.
        result = gateway.conntrack_flush_removed(
            self.IP,
            (gateway.Ports(tcp=(80,), direction="forward"),),
            (gateway.Ports(tcp=(80,), direction="input"),),
        )
        self.assertFalse(result)
        self.assertEqual(self.conntrack_lines(), [])

    def test_removed_full_without_remaining_flushes_whole_ip(self) -> None:
        result = gateway.conntrack_flush_removed(
            self.IP,
            (gateway.Ports(full=True, direction="forward"),),
            (),
        )
        self.assertTrue(result)
        self.assertEqual(
            self.conntrack_lines(), [f"conntrack -D -s {self.IP}"]
        )

    def test_too_many_commands_with_remaining_skips_flush(self) -> None:
        # 17 célzott parancs > CONNTRACK_REMOVED_LIMIT. Maradó engedély
        # mellett nem szabad teljes IP-s ürítésre váltani.
        removed = gateway.Ports(
            tcp=tuple(range(8000, 8017)), direction="forward"
        )
        result = gateway.conntrack_flush_removed(
            self.IP,
            (removed,),
            (gateway.Ports(tcp=(443,), direction="input"),),
        )
        self.assertFalse(result)
        self.assertEqual(self.conntrack_lines(), [])


# ------------------------------------------------------------------ egyéb mag

class SessionAuditTests(unittest.TestCase):
    """A munkamenet-életciklus audit-eseményei."""

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
        self.audit = gateway.AuditLog(
            os.path.join(self.tmp.name, "audit.jsonl"),
            logger=lambda *_: None,
        )
        self.sessions = gateway.SessionManager(
            self.fw, ttl=3600, pending_ttl=600, audit=self.audit
        )
        self.ip = "192.168.50.23"
        self.web_rule = make_rule("web-only", ("web",))

    def _expire(self, token: str) -> None:
        with self.sessions._lock:
            self.sessions._sessions[token] = gateway.replace(
                self.sessions._sessions[token], expires=time.time() - 1
            )

    def test_session_replaced_includes_pending_and_authorized(self) -> None:
        first = self.sessions.login("alice", self.ip)
        second = self.sessions.login("alice", self.ip)
        rows = self.audit.read(event="session_replaced")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["old_user"], "alice")
        self.assertEqual(row["new_user"], "alice")
        self.assertEqual(row["ip"], self.ip)
        self.assertEqual(row["old_sid"], first.sid)
        self.assertEqual(row["old_authorized"], False)
        self.assertEqual(row["reason"], "new_login_same_ip")
        self.assertEqual(self.sessions.count(), 1)
        self.assertIsNotNone(
            self.sessions.validate(second.token, self.ip)
        )

        # Engedéllyel rendelkező munkamenet cseréjekor az összesített
        # access_revoked esemény is megmarad.
        self.sessions.authorize(second.token, self.ip, self.web_rule, 60)
        self.sessions.login("alice", self.ip)
        rows = self.audit.read(event="session_replaced")
        self.assertEqual(len(rows), 2)
        replaced = [row for row in rows if row["old_authorized"]]
        self.assertEqual(len(replaced), 1)
        self.assertEqual(replaced[0]["old_rule"], "web-only")
        revoked = self.audit.read(event="access_revoked")
        self.assertEqual(len(revoked), 1)

    def test_session_expiry_via_validate_and_authorize(self) -> None:
        pending = self.sessions.login("alice", self.ip)
        self._expire(pending.token)
        self.assertIsNone(self.sessions.validate(pending.token, self.ip))

        authorized = self.sessions.login("bob", self.ip)
        self.sessions.authorize(authorized.token, self.ip, self.web_rule, 60)
        self._expire(authorized.token)
        with self.assertRaises(gateway.AccessError):
            self.sessions.authorize(
                authorized.token, self.ip, self.web_rule, 60
            )

        rows = self.audit.read(event="session_expired")
        self.assertEqual(len(rows), 2)
        by_user = {row["user"]: row for row in rows}
        self.assertEqual(by_user["alice"]["authorized"], False)
        self.assertEqual(by_user["bob"]["authorized"], True)
        self.assertEqual(by_user["bob"]["rule"], "web-only")
        for row in rows:
            self.assertEqual(row["reason"], "expired")
            self.assertEqual(row["ip"], self.ip)
            self.assertIn("sid", row)
            self.assertIn("duration", row)

    def test_session_ip_changed_is_audited(self) -> None:
        session = self.sessions.login("alice", self.ip)
        self.assertIsNone(
            self.sessions.validate(session.token, "192.168.50.24")
        )
        row = self.audit.read(event="session_ip_changed")[0]
        self.assertEqual(row["user"], "alice")
        self.assertEqual(row["sid"], session.sid)
        self.assertEqual(row["session_ip"], self.ip)
        self.assertEqual(row["request_ip"], "192.168.50.24")
        self.assertEqual(row["authorized"], False)

    def test_revoke_user_does_not_emit_per_session_events(self) -> None:
        self.sessions.login("alice", self.ip)
        self.assertEqual(self.sessions.revoke_user("alice"), 1)
        self.assertEqual(self.audit.read(event="session_expired"), [])
        self.assertEqual(self.audit.read(event="session_ended"), [])


class RateLimiterTests(unittest.TestCase):
    def test_window(self) -> None:
        limiter = gateway.RateLimiter(window=60, maximum=2)
        self.assertTrue(limiter.allow("a"))
        self.assertTrue(limiter.allow("a"))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))


class PowTests(unittest.TestCase):
    def test_challenge_solution_and_replay(self) -> None:
        challenge = gateway.issue_challenge(difficulty=2)
        solution = solve(challenge)
        ok, why = gateway.verify_pow(solution)
        self.assertTrue(ok, why)
        ok, why = gateway.verify_pow(solution)
        self.assertFalse(ok)
        self.assertIn("használva", why)

    def test_tampering_rejected(self) -> None:
        challenge = gateway.issue_challenge(difficulty=1)
        solution = solve(challenge)
        bad = dict(solution, difficulty=0)
        ok, why = gateway.verify_pow(bad)
        self.assertFalse(ok)
        self.assertIn("aláírás", why)
        # A szám+1 véletlenül szintén teljesítheti a nehézséget, ezért
        # addig növeljük, amíg biztosan érvénytelen proof-of-worköt kapunk.
        zeros = "0" * int(solution["difficulty"])
        number = int(solution["number"]) + 1
        while hashlib.sha256(f'{solution["salt"]}{number}'.encode()).hexdigest().startswith(zeros):
            number += 1
        bad = dict(solution, number=number)
        ok, _ = gateway.verify_pow(bad)
        self.assertFalse(ok)

    def test_expired_challenge_rejected(self) -> None:
        old = gateway.CHALLENGE_TTL
        gateway.CHALLENGE_TTL = -1
        try:
            challenge = gateway.issue_challenge(difficulty=1)
        finally:
            gateway.CHALLENGE_TTL = old
        ok, why = gateway.verify_pow(solve(challenge))
        self.assertFalse(ok)
        self.assertIn("lejárt", why)


# ------------------------------------------------------------------ HTTP

class AuditLogTests(unittest.TestCase):
    """Az auditnapló központi súlyosság- és érzékenységkezelése."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "audit.jsonl")
        self.audit = gateway.AuditLog(self.path, logger=lambda *_: None)

    def test_write_redacts_sensitive_fields_and_truncates(self) -> None:
        self.audit.write(
            "ismeretlen_esemeny",
            password="Titok-Jelszo-42",
            code="987654",
            ticket="Nyers-Jegy-ABC",
            ticket_hash="abc123def456",
            note="x" * 600,
        )
        rows = self.audit.read()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["severity"], "info")
        for key in ("password", "code", "ticket"):
            self.assertNotIn(key, row)
        self.assertEqual(row["ticket_hash"], "abc123def456")
        self.assertEqual(len(row["note"]), 500)
        raw = open(self.path, encoding="utf-8").read()
        for value in ("Titok-Jelszo-42", "987654", "Nyers-Jegy-ABC"):
            self.assertNotIn(value, raw)

    def test_explicit_severity_wins_and_read_filters(self) -> None:
        self.audit.write("firewall_error", reason="teszt")
        self.audit.write("login_success", user="alice")
        self.audit.write("sajat_esemeny", severity="warn", reason="x")
        alerts = self.audit.read(severity="alert")
        self.assertEqual([row["event"] for row in alerts], ["firewall_error"])
        self.assertEqual(
            [row["event"] for row in self.audit.read(severity="ALERT")],
            ["firewall_error"],
        )
        warns = self.audit.read(severity="warn")
        self.assertEqual([row["event"] for row in warns], ["sajat_esemeny"])
        row = self.audit.read(event="sajat_esemeny")[0]
        self.assertEqual(row["severity"], "warn")
        # A régi, severity nélküli sorok info szintűnek számítanak.
        legacy = os.path.join(self.tmp.name, "legacy.jsonl")
        with open(legacy, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": 1, "event": "login_success"}) + "\n")
        legacy_log = gateway.AuditLog(legacy, logger=lambda *_: None)
        self.assertEqual(len(legacy_log.read(severity="info")), 1)
        self.assertEqual(legacy_log.read(severity="alert"), [])


class HttpTests(unittest.TestCase):
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

        users_path = os.path.join(cls.tmp.name, "users.json")
        rules_path = os.path.join(cls.tmp.name, "rules.json")
        groups_path = os.path.join(cls.tmp.name, "groups.json")
        audit_path = os.path.join(cls.tmp.name, "audit.jsonl")
        cls.users = gateway.UserStore(users_path, iterations=10_000)
        cls.rules = gateway.RuleStore(rules_path, catalog=CATALOG, logger=lambda *_: None)
        cls.rules.create("web-only", {
            "label": "Csak web", "tcp": [80, 443], "udp": [443],
            "default_ttl": 3600, "max_ttl": gateway.MAX_TTL,
        })
        cls.rules.create("icmp-only", {
            "label": "Csak ping", "icmp": True,
            "default_ttl": 3600, "max_ttl": gateway.MAX_TTL,
        })
        cls.groups = gateway.GroupStore(groups_path, logger=lambda *_: None)
        cls.audit = gateway.AuditLog(audit_path, logger=lambda *_: None)
        cls.users.add(
            "alice", "hosszu-jelszo-1", rules=("web-only", "icmp-only")
        )
        cls.users.add("bob", "hosszu-jelszo-2", rules=("web-only",))
        cls.users.add(
            "dora", "dora-seed-jelszo-1", rules=("web-only",),
            must_change_password=True,
        )
        cls.fw = gateway.Firewall(binary=str(cls.tools.nft), logger=lambda *_: None)
        cls.fail2ban = fail2ban_mod.Fail2ban(
            cls.fw,
            path=os.path.join(cls.tmp.name, "fail2ban.json"),
            audit=cls.audit,
            logger=lambda *_: None,
            on_ban=lambda record: cls.gw._on_fail2ban_ban(record),
        )
        cls.gw = gateway.Gateway(
            users=cls.users, firewall=cls.fw, catalog=CATALOG,
            rules=cls.rules, groups=cls.groups, audit=cls.audit,
            rate_limiter=gateway.RateLimiter(window=60, maximum=1000),
            fail2ban=cls.fail2ban,
        )
        # A 2FA-jegyek életciklusa a HTTP-teszt naplójába írjon.
        server.LOGIN_TICKETS.set_audit(cls.audit)
        cls.server = server.AppServer(("127.0.0.1", 0), cls.gw)
        import threading
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
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
        self.tools.clear_fail()
        self.tools.clear_json()
        self.reset_fail2ban()

    def reset_fail2ban(self) -> None:
        """Friss számláló minden HTTP-teszthez (a tiltásnevek ne szivárogjanak)."""
        path = os.path.join(self.tmp.name, "fail2ban.json")
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        self.gw.fail2ban = fail2ban_mod.Fail2ban(
            self.fw,
            path=path,
            audit=self.audit,
            logger=lambda *_: None,
            on_ban=lambda record: self.gw._on_fail2ban_ban(record),
        )

    def conn(self, source: str | None = None) -> http.client.HTTPConnection:
        if source:
            return http.client.HTTPConnection("127.0.0.1", self.port, timeout=10, source_address=(source, 0))
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)

    def get(self, path: str, headers: dict | None = None, source: str | None = None):
        conn = self.conn(source)
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        body = resp.read()
        out = (resp.status, dict(resp.getheaders()), body)
        conn.close()
        return out

    def post_json(
        self, path: str, obj: dict, headers: dict | None = None,
        cookie: str = "", source: str | None = None,
    ):
        conn = self.conn(source)
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        if cookie:
            hdrs["Cookie"] = cookie
        conn.request("POST", path, body=json.dumps(obj), headers=hdrs)
        resp = conn.getresponse()
        body = resp.read()
        out = (resp.status, dict(resp.getheaders()), body)
        conn.close()
        return out

    def challenge(self) -> dict:
        status, _, body = self.get("/api/challenge")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["mode"], "pow")
        return data

    def login(self, user: str, password: str, captcha: dict | None = None, headers: dict | None = None):
        ch = self.challenge()
        return self.post_json(
            "/api/login",
            {"user": user, "pass": password, "captcha": captcha or solve(ch)},
            headers=headers,
        )

    def access(
        self, cookie: str, rule, ttl, headers: dict | None = None,
        source: str | None = None,
    ):
        return self.post_json(
            "/api/access",
            {"rule": rule, "ttl": ttl},
            headers=headers,
            cookie=cookie,
            source=source,
        )

    @staticmethod
    def cookie_from(headers: dict) -> str:
        raw = headers.get("Set-Cookie", "")
        return raw.split(";", 1)[0]

    def login_from(self, user: str, password: str, source: str):
        """Jelszavas belépés megadott forrás-IP-ről (a 2FA-jegyhez kell)."""
        _, _, body = self.get("/api/challenge", source=source)
        challenge = json.loads(body)
        return self.post_json(
            "/api/login",
            {"user": user, "pass": password, "captcha": solve(challenge)},
            source=source,
        )

    def require_totp(self, name: str) -> None:
        """2FA kötelezővé tétele a teszt erejéig, biztos visszaállítással."""
        self.users.reset_totp(name)
        self.users.set_totp_required(name, True)
        self.addCleanup(self._clear_totp, name)

    def _clear_totp(self, name: str) -> None:
        # A HttpTests felhasználói osztályszinten közösek, ezért a 2FA-t és a
        # nyitva maradt jegyeket/munkameneteket minden érintett teszt végén
        # vissza kell állítani.
        server.LOGIN_TICKETS.revoke_all()
        self.users.reset_totp(name)
        self.users.set_totp_required(name, False)
        self.gw.sessions.revoke_user(name)

    def enroll_totp(self, user: str, password: str, source: str | None = None):
        """Teljes első 2FA-beállítás; (secret, ticket, headers, válasz)."""
        status, _, body = self.login_from(user, password, source or "127.0.0.1")
        self.assertEqual(status, 200, body)
        offer = json.loads(body)
        self.assertTrue(offer.get("totp_enroll_required"), offer)
        secret = offer["secret"]
        ticket = offer["ticket"]
        status, headers, body = self.post_json(
            "/api/login/totp/enroll",
            {"ticket": ticket, "code": gateway.totp_code(secret)},
            source=source or "127.0.0.1",
        )
        self.assertEqual(status, 200, body)
        return secret, ticket, headers, json.loads(body)

    def test_page_and_no_source_leak(self) -> None:
        for path in ("/", "/index.html", "/server.py", "/gateway.py", "/users.json"):
            status, headers, body = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn("text/html", headers["Content-Type"])
            self.assertIn("Dropjak".encode(), body)
            self.assertNotIn(b"PBKDF2", body)
            self.assertNotIn(b"import hashlib", body)
        status, _, body = self.get("/")
        self.assertIn(b"/api/access", body)
        self.assertIn(b'id="rules"', body)
        self.assertIn(b'id="admin-panel"', body)
        status, headers, body = self.get("/icon.png")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "image/png")
        self.assertTrue(body.startswith(b"\x89PNG"))
        status, headers, body = self.get("/blocked.png")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "image/png")
        self.assertTrue(body.startswith(b"\x89PNG"))

    def test_page_and_status_expose_version(self) -> None:
        status, _, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(f"v{gateway.APP_VERSION}".encode(), body)
        self.assertNotIn(b"__VERSION__", body)

        # A nyilvános állapotvégpont a verziót is megadja.
        status, _, body = self.get("/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body)["version"], gateway.APP_VERSION
        )

        # Bejelentkezve ugyanaz a verzió szerepel a válaszban.
        status, headers, body = self.login("alice", "hosszu-jelszo-1")
        self.assertEqual(status, 200, body)
        cookie = self.cookie_from(headers)
        status, _, body = self.get("/api/status", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["version"], gateway.APP_VERSION)

    def test_unknown_api_is_404(self) -> None:
        status, _, body = self.get("/api/nincs")
        self.assertEqual(status, 404)
        self.assertFalse(json.loads(body)["ok"])

    def test_login_is_pending_then_access_logout(self) -> None:
        status, headers, body = self.login("alice", "hosszu-jelszo-1")
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertTrue(data["authenticated"])
        self.assertFalse(data["authorized"])
        self.assertTrue(data["pending"])
        self.assertIn("limits", data)
        self.assertIn("web-only", [rule["id"] for rule in data["rules"]])
        cookie = self.cookie_from(headers)
        self.assertTrue(cookie.startswith("hv_session="))
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Lax", headers["Set-Cookie"])
        self.assertFalse(
            any("add element" in line for line in self.tools.lines()),
            self.tools.lines(),
        )

        status, _, body = self.get("/api/status", headers={"Cookie": cookie})
        status_data = json.loads(body)
        self.assertTrue(status_data["authenticated"])
        self.assertFalse(status_data["authorized"])
        self.assertTrue(status_data["pending"])
        self.assertEqual(status_data["user"], "alice")
        self.assertEqual(status_data["limits"]["min_ttl"], gateway.MIN_TTL)
        self.assertEqual(status_data["limits"]["max_ttl"], gateway.MAX_TTL)

        status, headers, body = self.access(cookie, "web-only", 60)
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["authorized"])
        self.assertEqual(data["rule"], "web-only")
        self.assertEqual(data["grant"]["tcp"], [80, 443])
        self.assertEqual(data["grant"]["udp"], [443])
        self.assertGreater(data["expires_in"], 0)
        self.assertIn("Max-Age=", headers["Set-Cookie"])
        self.assertNotIn("Max-Age=0", headers["Set-Cookie"])

        script = self.tools.script()
        for line in (
            "add element inet hatarvedelem allowed_tcp { 127.0.0.1 . 80 timeout 60s }",
            "add element inet hatarvedelem allowed_tcp { 127.0.0.1 . 443 timeout 60s }",
            "add element inet hatarvedelem allowed_udp { 127.0.0.1 . 443 timeout 60s }",
        ):
            self.assertIn(line, script)
        # Az egyedi web szabály nem nyit host SSH-t.
        self.assertFalse(
            any("allowed_input_tcp" in line for line in script), script
        )
        self.assertFalse(
            any(". 53 " in line or ". 853 " in line for line in script), script
        )

        status, _, body = self.get("/api/status", headers={"Cookie": cookie})
        status_data = json.loads(body)
        self.assertTrue(status_data["authorized"])
        self.assertEqual(status_data["rule"], "web-only")
        self.assertEqual(status_data["grant"]["tcp"], [80, 443])
        self.assertEqual(status_data["grant"]["udp"], [443])

        status, headers, body = self.post_json("/api/logout", {}, cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        status, _, body = self.get("/api/status", headers={"Cookie": cookie})
        self.assertFalse(json.loads(body)["authenticated"])
        self.assertTrue(
            any(line.startswith("conntrack -D -s 127.0.0.1") for line in self.tools.lines())
        )

    def test_access_requires_a_session(self) -> None:
        status, _, body = self.post_json(
            "/api/access", {"rule": "web-only", "ttl": 60}
        )
        self.assertEqual(status, 400)
        self.assertFalse(json.loads(body)["ok"])
        self.assertIn("munkamenet", json.loads(body)["error"])

    def test_access_grant_of_host_rule_audits_direction(self) -> None:
        self.rules.create("host-25566", {
            "label": "mpwerks host", "direction": "input",
            "tcp": [25566],
            "default_ttl": 3600, "max_ttl": 3600,
        })
        self.users.add(
            "host-audit-user", "hosszu-jelszo-3", rules=("host-25566",)
        )
        self.addCleanup(lambda: self.rules.delete("host-25566"))
        self.addCleanup(lambda: self.users.remove("host-audit-user"))
        self.addCleanup(
            lambda: self.gw.sessions.revoke_user("host-audit-user")
        )

        started = time.time()
        status, headers, _ = self.login(
            "host-audit-user", "hosszu-jelszo-3"
        )
        self.assertEqual(status, 200)
        cookie = self.cookie_from(headers)
        status, _, body = self.access(cookie, "host-25566", 60)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["grant"]["direction"], "input")

        rows = [
            row for row in audit_since(self.audit, started)
            if row.get("event") == "access_granted"
            and row.get("user") == "host-audit-user"
        ]
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["direction"], "input")
        self.assertEqual(rows[0]["rule"], "host-25566")
        self.assertTrue(
            any(
                "add element inet hatarvedelem allowed_input_tcp "
                "{ 127.0.0.1 . 25566 timeout 60s }" in line
                for line in self.tools.script()
            ),
            self.tools.script(),
        )

    def test_access_multi_rule_union(self) -> None:
        source = "127.0.0.41"
        status, headers, body = self.login_from(
            "alice", "hosszu-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        cookie = self.cookie_from(headers)
        started = time.time()
        status, _, body = self.post_json(
            "/api/access",
            {
                "rules": ["web-only", "icmp-only"],
                "rule": "web-only",
                "ttl": 60,
            },
            cookie=cookie,
            source=source,
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["authorized"])
        self.assertEqual(data["selected_rules"], ["web-only", "icmp-only"])
        self.assertEqual(
            data["selected_rule_labels"], ["Csak web", "Csak ping"]
        )
        # A régi mezők az első választást tükrözik.
        self.assertEqual(data["rule"], "web-only")
        self.assertEqual(data["rule_label"], "Csak web")
        self.assertEqual(data["grant"]["tcp"], [80, 443])
        self.assertTrue(data["grant"]["icmp"])
        self.assertIn("(Csak web, Csak ping)", data["message"])
        self.assertEqual(len(data["grants"]), 1)
        grant = data["grants"][0]
        self.assertEqual(grant["direction"], "forward")
        self.assertEqual(grant["tcp"], [80, 443])
        self.assertEqual(grant["udp"], [443])
        self.assertTrue(grant["icmp"])
        self.assertFalse(grant["full"])

        script = self.tools.script()
        for line in (
            "add element inet hatarvedelem allowed_tcp "
            "{ 127.0.0.41 . 80 timeout 60s }",
            "add element inet hatarvedelem allowed_tcp "
            "{ 127.0.0.41 . 443 timeout 60s }",
            "add element inet hatarvedelem allowed_icmp "
            "{ 127.0.0.41 timeout 60s }",
        ):
            self.assertIn(line, script)

        rows = [
            row for row in audit_since(self.audit, started)
            if row.get("event") == "access_granted"
            and row.get("user") == "alice"
        ]
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["rules"], "web-only,icmp-only")
        self.assertEqual(rows[0]["rule_labels"], "Csak web,Csak ping")
        self.assertEqual(rows[0]["rule_count"], 2)
        self.assertEqual(rows[0]["direction"], "forward")
        self.assertEqual(rows[0]["tcp"], "80,443")
        self.assertTrue(rows[0]["icmp"])
        self.assertNotIn("removed_rules", rows[0])
        self.addCleanup(self.gw.sessions.revoke_user, "alice")

    def test_access_legacy_single_rule_still_works(self) -> None:
        source = "127.0.0.42"
        status, headers, body = self.login_from(
            "alice", "hosszu-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        cookie = self.cookie_from(headers)
        status, _, body = self.access(
            cookie, "web-only", 60, source=source
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertEqual(data["selected_rules"], ["web-only"])
        self.assertEqual(data["selected_rule_labels"], ["Csak web"])
        self.assertEqual(data["rule"], "web-only")
        self.assertEqual(data["rule_label"], "Csak web")
        self.assertEqual(data["grant"]["tcp"], [80, 443])
        self.assertEqual(data["grant"]["udp"], [443])
        self.assertEqual(len(data["grants"]), 1)
        self.assertEqual(data["grants"][0]["direction"], "forward")
        self.assertEqual(data["grants"][0]["tcp"], [80, 443])
        self.assertEqual(data["grants"][0]["udp"], [443])
        self.assertFalse(data["grants"][0]["icmp"])
        self.addCleanup(self.gw.sessions.revoke_user, "alice")

    def test_access_multi_rule_validation(self) -> None:
        source = "127.0.0.43"
        status, headers, body = self.login_from(
            "alice", "hosszu-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        cookie = self.cookie_from(headers)
        started = time.time()
        bad_requests = [
            {"rules": [], "ttl": 60},
            {"rules": "web-only", "ttl": 60},
            {"rules": ["web-only", 5], "ttl": 60},
            {"rules": ["web-only", ""], "ttl": 60},
            {
                "rules": [f"ismeretlen-{index}" for index in range(17)],
                "ttl": 60,
            },
        ]
        for payload in bad_requests:
            status, _, body = self.post_json(
                "/api/access", payload, cookie=cookie, source=source
            )
            self.assertEqual(status, 400, (payload, body))
            self.assertFalse(json.loads(body)["ok"])

        # Ismeretlen, de jól formált azonosító: egyik szabály sem jut be.
        before_unknown = list(self.tools.lines())
        status, _, body = self.post_json(
            "/api/access",
            {"rules": ["web-only", "nincs-ilyen"], "ttl": 60},
            cookie=cookie,
            source=source,
        )
        self.assertEqual(status, 400, body)
        self.assertEqual(self.tools.lines(), before_unknown)
        denied = [
            row for row in audit_since(self.audit, started)
            if row.get("event") == "access_denied"
        ]
        self.assertGreaterEqual(len(denied), len(bad_requests) + 1)

        # Az ismétlődő azonosító nem számít bele a 16-os korlátba.
        status, _, body = self.post_json(
            "/api/access",
            {"rules": ["web-only"] * 17, "ttl": 60},
            cookie=cookie,
            source=source,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["selected_rules"], ["web-only"])
        self.addCleanup(self.gw.sessions.revoke_user, "alice")

    def test_access_multi_rule_modification_revokes_removed(self) -> None:
        source = "127.0.0.44"
        status, headers, body = self.login_from(
            "alice", "hosszu-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        cookie = self.cookie_from(headers)
        status, _, body = self.access(
            cookie, "web-only", 60, source=source
        )
        self.assertEqual(status, 200, body)
        # Csak a módosítás tűzfal-hívásait vizsgáljuk.
        self.tools.clear()
        started = time.time()
        status, _, body = self.post_json(
            "/api/access", {"rules": ["icmp-only"], "ttl": 60},
            cookie=cookie,
            source=source,
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertEqual(data["selected_rules"], ["icmp-only"])
        self.assertEqual(data["selected_rule_labels"], ["Csak ping"])
        self.assertEqual(data["rule"], "icmp-only")
        self.assertEqual(data["rule_label"], "Csak ping")
        self.assertEqual(
            [grant["direction"] for grant in data["grants"]], ["forward"]
        )
        self.assertTrue(data["grants"][0]["icmp"])

        deletes = self.tools.deletes()
        for line in (
            "nft delete element inet hatarvedelem allowed_tcp "
            "{ 127.0.0.44 . 80 }",
            "nft delete element inet hatarvedelem allowed_tcp "
            "{ 127.0.0.44 . 443 }",
            "nft delete element inet hatarvedelem allowed_udp "
            "{ 127.0.0.44 . 443 }",
        ):
            self.assertIn(line, deletes)
        self.assertIn(
            "add element inet hatarvedelem allowed_icmp "
            "{ 127.0.0.44 timeout 60s }",
            self.tools.script(),
        )
        self.assertFalse(
            any(
                "add element" in line and "allowed_tcp" in line
                for line in self.tools.lines()
            ),
            self.tools.lines(),
        )

        rows = [
            row for row in audit_since(self.audit, started)
            if row.get("event") == "access_modified"
            and row.get("user") == "alice"
        ]
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["removed_rules"], "web-only")
        self.assertEqual(rows[0]["rule_count"], 1)
        self.assertEqual(rows[0]["rules"], "icmp-only")
        self.assertEqual(rows[0]["rule_labels"], "Csak ping")
        self.assertEqual(rows[0]["direction"], "forward")
        self.assertEqual(rows[0]["tcp"], "")
        self.assertTrue(rows[0]["icmp"])
        self.addCleanup(self.gw.sessions.revoke_user, "alice")

    def test_status_reports_multi_selection(self) -> None:
        source = "127.0.0.45"
        status, headers, body = self.login_from(
            "alice", "hosszu-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        login_data = json.loads(body)
        self.assertFalse(login_data["authorized"])
        self.assertNotIn("selected_rules", login_data)
        cookie = self.cookie_from(headers)

        status, _, body = self.get(
            "/api/status", headers={"Cookie": cookie}, source=source
        )
        self.assertEqual(status, 200, body)
        pending = json.loads(body)
        self.assertFalse(pending["authorized"])
        self.assertNotIn("selected_rules", pending)
        self.assertNotIn("selected_rule_labels", pending)
        self.assertNotIn("grants", pending)

        status, _, body = self.post_json(
            "/api/access",
            {"rules": ["web-only", "icmp-only"], "ttl": 60},
            cookie=cookie,
            source=source,
        )
        self.assertEqual(status, 200, body)
        status, _, body = self.get(
            "/api/status", headers={"Cookie": cookie}, source=source
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["authorized"])
        self.assertEqual(data["selected_rules"], ["web-only", "icmp-only"])
        self.assertEqual(
            data["selected_rule_labels"], ["Csak web", "Csak ping"]
        )
        self.assertEqual(data["rule"], "web-only")
        self.assertEqual(data["rule_label"], "Csak web")
        self.assertEqual(data["grant"]["tcp"], [80, 443])
        self.assertEqual(len(data["grants"]), 1)
        self.assertEqual(data["grants"][0]["direction"], "forward")
        self.assertEqual(data["grants"][0]["tcp"], [80, 443])
        self.assertTrue(data["grants"][0]["icmp"])
        self.addCleanup(self.gw.sessions.revoke_user, "alice")

    def test_admin_session_listing_shows_multi_selection(self) -> None:
        source = "127.0.0.46"
        admin_source = "127.0.0.47"
        admin_name = "multi-admin"
        self.users.add(
            admin_name, "multi-admin-jelszo-1",
            role=gateway.ROLE_ADMIN, rules=("web-only",),
        )
        self.addCleanup(self.users.remove, admin_name)
        self.addCleanup(self.gw.sessions.revoke_user, admin_name)

        status, headers, body = self.login_from(
            "alice", "hosszu-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        cookie = self.cookie_from(headers)
        status, _, body = self.post_json(
            "/api/access",
            {"rules": ["web-only", "icmp-only"], "ttl": 60},
            cookie=cookie,
            source=source,
        )
        self.assertEqual(status, 200, body)

        status, admin_headers, body = self.login_from(
            admin_name, "multi-admin-jelszo-1", admin_source
        )
        self.assertEqual(status, 200, body)
        admin_cookie = self.cookie_from(admin_headers)
        status, _, body = self.get(
            "/api/admin/sessions",
            headers={"Cookie": admin_cookie},
            source=admin_source,
        )
        self.assertEqual(status, 200, body)
        rows = json.loads(body)["sessions"]
        row = next(
            item for item in rows
            if item["user"] == "alice" and item["ip"] == source
        )
        self.assertEqual(row["selected_rules"], ["web-only", "icmp-only"])
        self.assertEqual(
            row["selected_rule_labels"], ["Csak web", "Csak ping"]
        )
        self.addCleanup(self.gw.sessions.revoke_user, "alice")

    def test_access_validation(self) -> None:
        status, headers, _ = self.login("alice", "hosszu-jelszo-1")
        self.assertEqual(status, 200)
        cookie = self.cookie_from(headers)

        bad_requests = [
            ("", 60),
            ("nincs-ilyen", 60),
            ("web-only", gateway.MIN_TTL - 1),
            ("web-only", gateway.MAX_TTL + 1),
            (["web-only"], 60),
            ("web-only", "60"),
            ("web-only", True),
            ("web-only", None),
            (None, 60),
        ]
        for rule, ttl in bad_requests:
            status, _, body = self.access(cookie, rule, ttl)
            self.assertEqual(status, 400, (rule, ttl, body))
            self.assertFalse(json.loads(body)["ok"])
        self.assertFalse(any("add element" in line for line in self.tools.lines()))

        # A határok elfogadottak; a második kérés újraengedélyez.
        status, _, body = self.access(cookie, "web-only", gateway.MIN_TTL)
        self.assertEqual(status, 200, body)
        self.assertTrue(json.loads(body)["authorized"])
        status, _, body = self.access(cookie, "web-only", gateway.MAX_TTL)
        self.assertEqual(status, 200, body)
        self.assertTrue(json.loads(body)["authorized"])

    def test_access_origin_check(self) -> None:
        _, headers, _ = self.login("alice", "hosszu-jelszo-1")
        cookie = self.cookie_from(headers)
        status, _, _ = self.access(
            cookie, "web-only", 60, headers={"Origin": "http://evil.example"}
        )
        self.assertEqual(status, 403)

    def test_access_is_bound_to_client_ip(self) -> None:
        _, headers, _ = self.login("alice", "hosszu-jelszo-1")
        cookie = self.cookie_from(headers)
        status, _, body = self.access(cookie, "web-only", 60, source="127.0.0.2")
        self.assertEqual(status, 400, body)
        self.assertFalse(json.loads(body)["ok"])

        # A más IP-ről érkező kérés a munkamenetet is megszünteti, ezért a
        # eredeti IP-ről sem használható tovább a régi cookie.
        status, _, body = self.access(cookie, "web-only", 60)
        self.assertEqual(status, 400, body)

        # Új belépéssel viszont működik.
        _, headers, _ = self.login("alice", "hosszu-jelszo-1")
        cookie = self.cookie_from(headers)
        status, _, body = self.access(cookie, "web-only", 60)
        self.assertEqual(status, 200, body)
        self.assertTrue(json.loads(body)["authorized"])

    def test_wrong_password_and_consumed_captcha(self) -> None:
        ch = self.challenge()
        solution = solve(ch)
        status, _, body = self.post_json(
            "/api/login", {"user": "alice", "pass": "rossz", "captcha": solution}
        )
        self.assertEqual(status, 403)
        self.assertIn("Hibás", json.loads(body)["error"])
        self.assertFalse(any("add element" in line for line in self.tools.lines()))

        status, _, body = self.post_json(
            "/api/login", {"user": "alice", "pass": "hosszu-jelszo-1", "captcha": solution}
        )
        self.assertEqual(status, 403)
        self.assertIn("használva", json.loads(body)["error"])

    def test_unknown_user_generic_error(self) -> None:
        status, _, body = self.login("nincs-ilyen", "barmi-jelszo")
        self.assertEqual(status, 403)
        self.assertIn("Hibás", json.loads(body)["error"])

    def test_missing_captcha(self) -> None:
        status, _, _ = self.post_json(
            "/api/login", {"user": "alice", "pass": "hosszu-jelszo-1", "captcha": {}}
        )
        self.assertEqual(status, 403)

    def test_origin_check(self) -> None:
        ch = self.challenge()
        status, _, _ = self.post_json(
            "/api/login",
            {"user": "alice", "pass": "hosszu-jelszo-1", "captcha": solve(ch)},
            headers={"Origin": "http://evil.example"},
        )
        self.assertEqual(status, 403)

    def test_session_is_bound_to_client_ip(self) -> None:
        status, headers, _ = self.login("alice", "hosszu-jelszo-1")
        self.assertEqual(status, 200)
        cookie = self.cookie_from(headers)
        status, _, body = self.get("/api/status", headers={"Cookie": cookie}, source="127.0.0.2")
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["authenticated"])

    def test_must_change_password_blocks_access_until_changed(self) -> None:
        status, headers, body = self.login("dora", "dora-seed-jelszo-1")
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["must_change_password"])
        cookie = self.cookie_from(headers)

        status, _, body = self.access(cookie, "web-only", 60)
        self.assertEqual(status, 403, body)
        self.assertTrue(json.loads(body)["must_change_password"])
        self.assertFalse(
            any("add element" in line for line in self.tools.lines()),
            self.tools.lines(),
        )

        status, _, body = self.post_json(
            "/api/password",
            {"current": "rossz-jelszo", "new": "uj-dora-jelszo-2"},
            cookie=cookie,
        )
        self.assertEqual(status, 403, body)
        status, _, body = self.post_json(
            "/api/password",
            {"current": "dora-seed-jelszo-1", "new": "dora-seed-jelszo-1"},
            cookie=cookie,
        )
        self.assertEqual(status, 400, body)

        status, _, body = self.post_json(
            "/api/password",
            {"current": "dora-seed-jelszo-1", "new": "uj-dora-jelszo-2"},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        self.assertFalse(json.loads(body)["must_change_password"])
        self.assertFalse(self.users.record("dora").must_change_password)

        status, _, body = self.access(cookie, "web-only", 60)
        self.assertEqual(status, 200, body)
        self.assertTrue(json.loads(body)["authorized"])

    def test_password_change_revokes_other_sessions_only(self) -> None:
        if self.users.record("eve") is None:
            self.users.add(
                "eve", "eve-seed-jelszo-1", rules=("web-only",),
                must_change_password=True,
            )
        _, headers, _ = self.login("eve", "eve-seed-jelszo-1")
        first = self.cookie_from(headers)
        _, _, challenge_body = self.get("/api/challenge", source="127.0.0.3")
        status, headers, body = self.post_json(
            "/api/login",
            {
                "user": "eve", "pass": "eve-seed-jelszo-1",
                "captcha": solve(json.loads(challenge_body)),
            },
            source="127.0.0.3",
        )
        self.assertEqual(status, 200, body)
        second = self.cookie_from(headers)

        status, _, body = self.post_json(
            "/api/password",
            {"current": "eve-seed-jelszo-1", "new": "eve-uj-jelszo-2"},
            cookie=first,
        )
        self.assertEqual(status, 200, body)
        status, _, body = self.get(
            "/api/status", headers={"Cookie": second}, source="127.0.0.3"
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertFalse(data["authenticated"])
        self.assertEqual(data["last_end"]["reason"], "password_changed")
        status, _, body = self.get(
            "/api/status", headers={"Cookie": first}
        )
        self.assertTrue(json.loads(body)["authenticated"])
        self.assertFalse(json.loads(body)["must_change_password"])

    def test_recent_replacement_reason_is_reported(self) -> None:
        if self.users.record("frank") is None:
            self.users.add("frank", "frank-jelszo-1", rules=("web-only",))
        _, headers, _ = self.login("frank", "frank-jelszo-1")
        old = self.cookie_from(headers)
        self.login("frank", "frank-jelszo-1")
        status, _, body = self.get("/api/status", headers={"Cookie": old})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertFalse(data["authenticated"])
        self.assertEqual(data["last_end"]["reason"], "replaced")

    def test_portal_redirect_for_foreign_host(self) -> None:
        gateway.PORTAL_URL = "http://192.168.50.1"
        try:
            status, headers, _ = self.get("/", headers={"Host": "example.com"})
            self.assertEqual(status, 302)
            self.assertEqual(headers["Location"], "http://192.168.50.1")
            status, _, body = self.get("/", headers={"Host": "192.168.50.1"})
            self.assertEqual(status, 200)
            self.assertIn("Dropjak".encode(), body)
        finally:
            gateway.PORTAL_URL = ""

    def test_head_request(self) -> None:
        conn = self.conn()
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertGreater(int(resp.getheader("Content-Length")), 0)
        self.assertEqual(resp.read(), b"")
        conn.close()

    def test_body_too_large(self) -> None:
        conn = self.conn()
        conn.request("POST", "/api/login", body=b"{}" * 20000,
                     headers={"Content-Type": "application/json", "Content-Length": "40000"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 400)
        resp.read()
        conn.close()

    # -- kétfaktoros belépés ---------------------------------------------------

    def test_totp_required_enroll_offer_without_session(self) -> None:
        self.require_totp("alice")
        started = time.time()
        status, headers, body = self.login("alice", "hosszu-jelszo-1")
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertTrue(data["totp_required"])
        self.assertTrue(data["totp_enroll_required"])
        self.assertIsInstance(data["ticket"], str)
        self.assertTrue(data["ticket"])
        self.assertRegex(data["secret"], r"^[A-Z2-7]{32}$")
        self.assertEqual(data["issuer"], gateway.TOTP_ISSUER)
        self.assertIn("otpauth://totp/", data["otpauth_uri"])
        self.assertIn(data["secret"], data["otpauth_uri"])
        # A jelszó önmagában nem ad munkamenetet.
        self.assertNotIn("Set-Cookie", headers)
        status, _, status_body = self.get("/api/status")
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(status_body)["authenticated"])

        dump = json.dumps(audit_since(self.audit, started), ensure_ascii=False)
        self.assertNotIn(data["secret"], dump)
        self.assertNotIn(data["ticket"], dump)

    def test_totp_enrollment_returns_codes_and_stores_hashes(self) -> None:
        self.require_totp("alice")
        started = time.time()
        secret, ticket, headers, data = self.enroll_totp(
            "alice", "hosszu-jelszo-1"
        )
        self.assertIn("Set-Cookie", headers)
        cookie = self.cookie_from(headers)
        self.assertTrue(cookie.startswith("hv_session="))
        self.assertEqual(data["user"], "alice")
        codes = data["recovery_codes"]
        self.assertEqual(len(codes), 10)
        self.assertEqual(len(set(codes)), 10)
        for code in codes:
            self.assertEqual(len(code), gateway._RECOVERY_CODE_LENGTH)
            self.assertTrue(set(code) <= set(gateway._BASE32_ALPHABET), code)

        record = self.users.record("alice")
        self.assertEqual(record.totp_secret, secret)
        self.assertTrue(record.totp_required)
        self.assertGreaterEqual(
            record.totp_last_step, int(started // gateway.TOTP_PERIOD)
        )
        self.assertEqual(len(record.totp_recovery), 10)
        self.assertEqual(
            set(record.totp_recovery),
            {gateway.hash_recovery_code(code) for code in codes},
        )
        for digest in record.totp_recovery:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

        # A nyílt kódok és a titok se a naplóba, se a nyilvános állapotba
        # nem szivároghatnak be.
        public_dump = json.dumps(
            [item.public() for item in self.users.details()],
            ensure_ascii=False,
        )
        audit_dump = json.dumps(
            audit_since(self.audit, started), ensure_ascii=False
        )
        self.assertNotIn(secret, public_dump)
        self.assertNotIn(secret, audit_dump)
        self.assertNotIn(ticket, audit_dump)
        for code in codes:
            self.assertNotIn(code, public_dump)
            self.assertNotIn(code, audit_dump)
        for digest in record.totp_recovery:
            self.assertNotIn(digest, public_dump)
            self.assertNotIn(digest, audit_dump)

        # A regisztrációs jegy egyszer használatos.
        status, headers, body = self.post_json(
            "/api/login/totp/enroll",
            {"ticket": ticket, "code": gateway.totp_code(secret)},
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(json.loads(body)["code"], "ticket_invalid")
        self.assertNotIn("Set-Cookie", headers)

    def test_totp_verify_wrong_then_correct_code(self) -> None:
        self.require_totp("alice")
        source = "127.0.0.20"
        secret, _, _, _ = self.enroll_totp(
            "alice", "hosszu-jelszo-1", source
        )
        status, headers, body = self.login_from(
            "alice", "hosszu-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        offer = json.loads(body)
        self.assertEqual(offer["mode"], "verify")
        self.assertTrue(offer["totp_required"])
        self.assertTrue(offer["ticket"])
        self.assertNotIn("Set-Cookie", headers)
        ticket = offer["ticket"]

        status, headers, body = self.post_json(
            "/api/login/totp",
            {"ticket": ticket, "code": wrong_totp_code(secret)},
            source=source,
        )
        self.assertEqual(status, 403, body)
        failure = json.loads(body)
        self.assertEqual(failure["code"], "totp_invalid")
        self.assertNotIn("Set-Cookie", headers)
        pending = {
            row["ip"]: row
            for row in self.gw.fail2ban.snapshot()["pending"]
        }
        self.assertIn(source, pending)
        self.assertEqual(pending[source]["count"], 1)
        self.assertEqual(pending[source]["user"], "alice")

        code = fresh_totp_code(
            secret, after_step=self.users.record("alice").totp_last_step
        )
        status, headers, body = self.post_json(
            "/api/login/totp", {"ticket": ticket, "code": code}, source=source
        )
        self.assertEqual(status, 200, body)
        cookie = self.cookie_from(headers)
        self.assertTrue(cookie.startswith("hv_session="))
        status, _, body = self.get(
            "/api/status", headers={"Cookie": cookie}, source=source
        )
        self.assertTrue(json.loads(body)["authenticated"])
        pending = {
            row["ip"]: row
            for row in self.gw.fail2ban.snapshot()["pending"]
        }
        self.assertNotIn(source, pending)

        # Ugyanaz a jegy nem használható újra.
        status, headers, body = self.post_json(
            "/api/login/totp", {"ticket": ticket, "code": code}, source=source
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(json.loads(body)["code"], "ticket_invalid")
        self.assertNotIn("Set-Cookie", headers)

    def test_totp_code_replay_with_fresh_ticket_rejected(self) -> None:
        self.require_totp("alice")
        source = "127.0.0.21"
        secret, _, _, _ = self.enroll_totp(
            "alice", "hosszu-jelszo-1", source
        )
        code = fresh_totp_code(
            secret, after_step=self.users.record("alice").totp_last_step
        )

        status, _, body = self.login_from("alice", "hosszu-jelszo-1", source)
        self.assertEqual(status, 200, body)
        first_ticket = json.loads(body)["ticket"]
        status, headers, body = self.post_json(
            "/api/login/totp",
            {"ticket": first_ticket, "code": code},
            source=source,
        )
        self.assertEqual(status, 200, body)
        self.assertIn("Set-Cookie", headers)

        # Friss jegy, ugyanaz a még aktuális kód: a last_step replay-védelem
        # miatt el kell utasítani (a jegy egyszer használata nem fedi el).
        status, _, body = self.login_from("alice", "hosszu-jelszo-1", source)
        self.assertEqual(status, 200, body)
        second_ticket = json.loads(body)["ticket"]
        self.assertNotEqual(first_ticket, second_ticket)
        status, headers, body = self.post_json(
            "/api/login/totp",
            {"ticket": second_ticket, "code": code},
            source=source,
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(json.loads(body)["code"], "totp_invalid")
        self.assertNotIn("Set-Cookie", headers)

    def test_totp_recovery_code_login_is_single_use(self) -> None:
        self.require_totp("alice")
        source = "127.0.0.22"
        secret, _, _, enrolled = self.enroll_totp(
            "alice", "hosszu-jelszo-1", source
        )
        self.assertEqual(len(enrolled["recovery_codes"]), 10)
        first_code, second_code = enrolled["recovery_codes"][:2]
        started = time.time()

        status, _, body = self.login_from("alice", "hosszu-jelszo-1", source)
        self.assertEqual(status, 200, body)
        ticket = json.loads(body)["ticket"]
        status, headers, body = self.post_json(
            "/api/login/recovery",
            {"ticket": ticket, "code": first_code},
            source=source,
        )
        self.assertEqual(status, 200, body)
        self.assertIn("Set-Cookie", headers)
        self.assertTrue(json.loads(body)["authenticated"])
        rows = audit_since(self.audit, started)
        self.assertTrue(
            any(
                row.get("event") == "totp_recovery_used"
                and row.get("target") == "alice"
                for row in rows
            ),
            rows,
        )

        # Ugyanaz a recovery kód nem használható újra.
        status, _, body = self.login_from("alice", "hosszu-jelszo-1", source)
        self.assertEqual(status, 200, body)
        ticket = json.loads(body)["ticket"]
        status, headers, body = self.post_json(
            "/api/login/recovery",
            {"ticket": ticket, "code": first_code},
            source=source,
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(json.loads(body)["code"], "recovery_invalid")
        self.assertNotIn("Set-Cookie", headers)

        # Egy másik kód viszont még egyszer működik.
        status, _, body = self.login_from("alice", "hosszu-jelszo-1", source)
        self.assertEqual(status, 200, body)
        ticket = json.loads(body)["ticket"]
        status, headers, body = self.post_json(
            "/api/login/recovery",
            {"ticket": ticket, "code": second_code},
            source=source,
        )
        self.assertEqual(status, 200, body)
        self.assertIn("Set-Cookie", headers)
        self.assertEqual(len(self.users.record("alice").totp_recovery), 8)

    def test_totp_ticket_is_bound_to_issuing_ip(self) -> None:
        self.require_totp("alice")
        secret, _, _, _ = self.enroll_totp("alice", "hosszu-jelszo-1")
        issuer = "127.0.0.9"
        other = "127.0.0.10"
        status, _, body = self.login_from("alice", "hosszu-jelszo-1", issuer)
        self.assertEqual(status, 200, body)
        ticket = json.loads(body)["ticket"]
        status, headers, body = self.post_json(
            "/api/login/totp",
            {"ticket": ticket, "code": gateway.totp_code(secret)},
            source=other,
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(json.loads(body)["code"], "ticket_invalid")
        self.assertNotIn("Set-Cookie", headers)

    def test_totp_ticket_attempt_cap_locks_ticket(self) -> None:
        self.require_totp("alice")
        source = "127.0.0.30"
        store = server.LoginTicketStore(max_attempts=3)
        with mock.patch.object(server, "LOGIN_TICKETS", store):
            # A fail2ban ne zavarja a jegy-próbaszámlálás determinisztikus
            # ellenőrzését.
            with mock.patch.object(
                self.gw.fail2ban, "record_failure", return_value=None
            ):
                secret, _, _, _ = self.enroll_totp(
                    "alice", "hosszu-jelszo-1", source
                )
                status, _, body = self.login_from(
                    "alice", "hosszu-jelszo-1", source
                )
                self.assertEqual(status, 200, body)
                ticket = json.loads(body)["ticket"]

                for remaining in (2, 1, 0):
                    status, headers, body = self.post_json(
                        "/api/login/totp",
                        {"ticket": ticket, "code": wrong_totp_code(secret)},
                        source=source,
                    )
                    self.assertEqual(status, 403, body)
                    failure = json.loads(body)
                    self.assertEqual(failure["remaining"], remaining)
                    if remaining:
                        self.assertEqual(failure["code"], "totp_invalid")
                    else:
                        self.assertEqual(failure["code"], "ticket_locked")
                    self.assertNotIn("Set-Cookie", headers)

                self.assertIsNone(store.peek(ticket, source))
                self.assertIsNone(store.consume(ticket, source))
                status, headers, body = self.post_json(
                    "/api/login/totp",
                    {"ticket": ticket, "code": fresh_totp_code(secret)},
                    source=source,
                )
                self.assertEqual(status, 403, body)
                self.assertIn(
                    json.loads(body).get("code"),
                    {"ticket_invalid", "ticket_locked"},
                )
                self.assertNotIn("Set-Cookie", headers)

    def test_totp_ticket_attempt_cap_with_fail2ban(self) -> None:
        self.require_totp("alice")
        source = "127.0.0.31"
        # A fail2ban-tiltás drop-log bejegyzést ír; azt a teszt könyvtárába
        # irányítjuk, hogy a projekt gyökerébe ne kerüljön szemét.
        drops = gateway.droplog.DropLogService(
            os.path.join(self.tmp.name, "totp-ban-drops.jsonl"),
            enabled=False, logger=lambda *_: None,
        )
        original_drops = self.gw.drops
        self.gw.drops = drops
        self.addCleanup(setattr, self.gw, "drops", original_drops)

        secret, _, _, _ = self.enroll_totp(
            "alice", "hosszu-jelszo-1", source
        )
        status, _, body = self.login_from("alice", "hosszu-jelszo-1", source)
        self.assertEqual(status, 200, body)
        ticket = json.loads(body)["ticket"]

        last: dict = {}
        for _ in range(server.LOGIN_TICKET_MAX_ATTEMPTS):
            status, headers, body = self.post_json(
                "/api/login/totp",
                {"ticket": ticket, "code": wrong_totp_code(secret)},
                source=source,
            )
            self.assertEqual(status, 403, body)
            last = json.loads(body)
            self.assertNotIn("Set-Cookie", headers)
        self.assertTrue(
            last.get("banned") is True or last.get("code") == "ticket_locked",
            last,
        )

        # A kimerült (vagy fail2ban-tiltott) jegy után a helyes kód sem
        # adhat munkamenetet.
        status, headers, body = self.post_json(
            "/api/login/totp",
            {"ticket": ticket, "code": fresh_totp_code(secret)},
            source=source,
        )
        self.assertEqual(status, 403, body)
        self.assertNotIn("Set-Cookie", headers)

    def test_totp_ticket_invalidated_by_direct_secret_reset(self) -> None:
        self.require_totp("alice")
        source = "127.0.0.32"
        secret, _, _, _ = self.enroll_totp(
            "alice", "hosszu-jelszo-1", source
        )
        status, _, body = self.login_from("alice", "hosszu-jelszo-1", source)
        self.assertEqual(status, 200, body)
        ticket = json.loads(body)["ticket"]

        before = server._record_fingerprint(self.users.record("alice"))
        self.assertTrue(self.users.reset_totp("alice"))
        after = server._record_fingerprint(self.users.record("alice"))
        self.assertNotEqual(before, after)

        status, headers, body = self.post_json(
            "/api/login/totp",
            {"ticket": ticket, "code": gateway.totp_code(secret)},
            source=source,
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(json.loads(body)["code"], "ticket_invalid")
        self.assertNotIn("Set-Cookie", headers)

    def test_non_totp_login_still_returns_session(self) -> None:
        self.users.reset_totp("alice")
        self.users.set_totp_required("alice", False)
        status, headers, body = self.login("alice", "hosszu-jelszo-1")
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["authenticated"])
        self.assertNotIn("totp_required", data)
        self.assertNotIn("ticket", data)
        cookie = self.cookie_from(headers)
        status, _, body = self.get(
            "/api/status", headers={"Cookie": cookie}
        )
        self.assertTrue(json.loads(body)["authenticated"])

    def test_wrong_totp_and_wrong_password_count_identically(self) -> None:
        self.require_totp("alice")
        source = "127.0.0.40"
        secret, _, _, _ = self.enroll_totp(
            "alice", "hosszu-jelszo-1", source
        )
        status, _, body = self.login_from("alice", "hosszu-jelszo-1", source)
        self.assertEqual(status, 200, body)
        ticket = json.loads(body)["ticket"]

        status, headers, body = self.post_json(
            "/api/login/totp",
            {"ticket": ticket, "code": wrong_totp_code(secret)},
            source=source,
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(json.loads(body)["code"], "totp_invalid")
        self.assertNotIn("Set-Cookie", headers)
        rows = [
            row for row in self.gw.fail2ban.snapshot()["pending"]
            if row["ip"] == source
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["count"], 1)
        self.assertEqual(rows[0]["user"], "alice")

        # Ugyanaz a számlálás hibás jelszónál is (friss fail2ban-állapotból).
        self.reset_fail2ban()
        status, headers, body = self.login_from(
            "bob", "rossz-jelszo", source
        )
        self.assertEqual(status, 403, body)
        self.assertNotIn("Set-Cookie", headers)
        rows = [
            row for row in self.gw.fail2ban.snapshot()["pending"]
            if row["ip"] == source
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["count"], 1)
        self.assertEqual(rows[0]["user"], "bob")

    def test_totp_ticket_issued_is_audited_without_secrets(self) -> None:
        self.require_totp("alice")
        source = "127.0.0.60"
        started = time.time()
        status, headers, body = self.login_from(
            "alice", "hosszu-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        offer = json.loads(body)
        self.assertTrue(offer["totp_enroll_required"])
        self.assertNotIn("Set-Cookie", headers)
        rows = audit_since(self.audit, started)
        issued = [
            row for row in rows if row.get("event") == "totp_ticket_issued"
        ]
        self.assertEqual(len(issued), 1, rows)
        row = issued[0]
        self.assertEqual(row["user"], "alice")
        self.assertEqual(row["purpose"], "enroll")
        self.assertTrue(row["secret_generated"])
        self.assertEqual(row["ttl"], server.LOGIN_TICKETS.ttl)
        self.assertEqual(
            row["ticket_hash"],
            hashlib.sha256(offer["ticket"].encode("utf-8")).hexdigest()[:12],
        )
        self.assertEqual(row["severity"], "info")
        dump = json.dumps(rows, ensure_ascii=False)
        self.assertNotIn(offer["ticket"], dump)
        self.assertNotIn(offer["secret"], dump)
        self.assertNotIn("otpauth", dump.lower())

    def test_totp_verify_ticket_issued_is_audited(self) -> None:
        self.require_totp("alice")
        source = "127.0.0.61"
        self.enroll_totp("alice", "hosszu-jelszo-1", source)
        started = time.time()
        status, headers, body = self.login_from(
            "alice", "hosszu-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        offer = json.loads(body)
        self.assertEqual(offer["mode"], "verify")
        self.assertNotIn("Set-Cookie", headers)
        rows = audit_since(self.audit, started)
        issued = [
            row for row in rows if row.get("event") == "totp_ticket_issued"
        ]
        self.assertEqual(len(issued), 1, rows)
        row = issued[0]
        self.assertEqual(row["user"], "alice")
        self.assertEqual(row["purpose"], "verify")
        self.assertNotIn("secret_generated", row)
        self.assertEqual(
            row["ticket_hash"],
            hashlib.sha256(offer["ticket"].encode("utf-8")).hexdigest()[:12],
        )
        self.assertNotIn(offer["ticket"], json.dumps(rows, ensure_ascii=False))

    def test_totp_failures_and_lock_are_audited(self) -> None:
        self.require_totp("alice")
        source = "127.0.0.62"
        store = server.LoginTicketStore(max_attempts=3)
        store.set_audit(self.audit)
        with mock.patch.object(server, "LOGIN_TICKETS", store):
            with mock.patch.object(
                self.gw.fail2ban, "record_failure", return_value=None
            ):
                secret, _, _, _ = self.enroll_totp(
                    "alice", "hosszu-jelszo-1", source
                )
                status, _, body = self.login_from(
                    "alice", "hosszu-jelszo-1", source
                )
                self.assertEqual(status, 200, body)
                ticket = json.loads(body)["ticket"]
                started = time.time()
                wrong = wrong_totp_code(secret)
                for remaining in (2, 1, 0):
                    status, headers, body = self.post_json(
                        "/api/login/totp",
                        {"ticket": ticket, "code": wrong},
                        source=source,
                    )
                    self.assertEqual(status, 403, body)
                    self.assertEqual(json.loads(body)["remaining"], remaining)
                    self.assertNotIn("Set-Cookie", headers)

        rows = audit_since(self.audit, started)
        failed = [
            row for row in rows if row.get("event") == "totp_failed"
        ]
        self.assertEqual(len(failed), 3, rows)
        chronological = list(reversed(failed))
        self.assertEqual(
            [row["remaining"] for row in chronological], [2, 1, 0]
        )
        self.assertEqual(
            [row["attempts"] for row in chronological], [1, 2, 3]
        )
        self.assertEqual(
            [row["severity"] for row in chronological], ["warn", "warn", "alert"]
        )
        expected_hash = hashlib.sha256(
            ticket.encode("utf-8")
        ).hexdigest()[:12]
        for row in failed:
            self.assertEqual(row["user"], "alice")
            self.assertEqual(row["method"], "totp")
            self.assertEqual(row["purpose"], "verify")
            self.assertEqual(row["ticket_hash"], expected_hash)
            self.assertFalse(row["banned"])
        locked = [
            row for row in rows if row.get("event") == "totp_ticket_locked"
        ]
        self.assertEqual(len(locked), 1, rows)
        self.assertEqual(locked[0]["attempts"], 3)
        self.assertEqual(locked[0]["reason"], "too_many_attempts")
        self.assertEqual(locked[0]["ticket_hash"], expected_hash)
        self.assertEqual(locked[0]["severity"], "alert")
        self.assertNotIn(wrong, json.dumps(rows, ensure_ascii=False))
        self.assertNotIn(ticket, json.dumps(rows, ensure_ascii=False))

    def test_totp_ticket_rejection_reasons_are_audited(self) -> None:
        self.require_totp("alice")
        source = "127.0.0.63"
        other = "127.0.0.64"
        clock = [time.time()]
        store = server.LoginTicketStore(clock=lambda: clock[0])
        store.set_audit(self.audit)
        unknown = "soha-nem-letezo-jegy"
        with mock.patch.object(server, "LOGIN_TICKETS", store):
            secret, _, _, _ = self.enroll_totp(
                "alice", "hosszu-jelszo-1", source
            )
            started = time.time()

            # Hiányzó jelszó utáni jegy/kód: bad_request.
            status, _, _ = self.post_json(
                "/api/login/totp", {}, source=source
            )
            self.assertEqual(status, 400)

            # Ismeretlen jegy: unknown.
            status, _, _ = self.post_json(
                "/api/login/totp",
                {"ticket": unknown, "code": "123456"},
                source=source,
            )
            self.assertEqual(status, 403)

            status, _, body = self.login_from(
                "alice", "hosszu-jelszo-1", source
            )
            self.assertEqual(status, 200, body)
            ticket = json.loads(body)["ticket"]

            # Jó jegy, rossz végpont: wrong_purpose.
            status, _, _ = self.post_json(
                "/api/login/totp/enroll",
                {"ticket": ticket, "code": "123456"},
                source=source,
            )
            self.assertEqual(status, 403)

            # Jó jegy, idegen forrás-IP: ip_mismatch.
            status, _, _ = self.post_json(
                "/api/login/totp",
                {"ticket": ticket, "code": "123456"},
                source=other,
            )
            self.assertEqual(status, 403)

            # Sikeres felhasználás, majd ugyanaz a jegy: already_consumed.
            code = fresh_totp_code(
                secret,
                after_step=self.users.record("alice").totp_last_step,
            )
            status, _, body = self.post_json(
                "/api/login/totp",
                {"ticket": ticket, "code": code},
                source=source,
            )
            self.assertEqual(status, 200, body)
            status, _, _ = self.post_json(
                "/api/login/totp",
                {"ticket": ticket, "code": code},
                source=source,
            )
            self.assertEqual(status, 403)

            # Lejárt jegy: expired (és közben totp_ticket_expired is).
            status, _, body = self.login_from(
                "alice", "hosszu-jelszo-1", source
            )
            self.assertEqual(status, 200, body)
            expired = json.loads(body)["ticket"]
            clock[0] += store.ttl + 1
            status, _, _ = self.post_json(
                "/api/login/totp",
                {"ticket": expired, "code": "123456"},
                source=source,
            )
            self.assertEqual(status, 403)

        rows = audit_since(self.audit, started)
        rejected = [
            row for row in rows
            if row.get("event") == "totp_ticket_rejected"
        ]
        reasons = [row["reason"] for row in reversed(rejected)]
        self.assertEqual(
            reasons,
            [
                "bad_request", "unknown", "wrong_purpose",
                "ip_mismatch", "already_consumed", "expired",
            ],
            rows,
        )
        for row in rejected:
            self.assertEqual(row["purpose"], "verify")
        by_reason = {row["reason"]: row for row in rejected}
        self.assertNotIn("ticket_hash", by_reason["bad_request"])
        self.assertEqual(
            by_reason["unknown"]["ticket_hash"],
            hashlib.sha256(unknown.encode("utf-8")).hexdigest()[:12],
        )
        self.assertEqual(by_reason["wrong_purpose"]["user"], "alice")
        self.assertNotIn("user", by_reason["ip_mismatch"])
        dump = json.dumps(rows, ensure_ascii=False)
        for token in (unknown, ticket, expired):
            self.assertNotIn(token, dump)
        self.assertTrue(
            any(
                row.get("event") == "totp_ticket_expired"
                and row.get("ticket_hash")
                == hashlib.sha256(expired.encode("utf-8")).hexdigest()[:12]
                for row in rows
            ),
            rows,
        )

    def test_totp_enrollment_audit_has_no_material(self) -> None:
        self.require_totp("alice")
        source = "127.0.0.65"
        started = time.time()
        secret, ticket, _, data = self.enroll_totp(
            "alice", "hosszu-jelszo-1", source
        )
        rows = audit_since(self.audit, started)
        issued = [
            row for row in rows
            if row.get("event") == "totp_ticket_issued"
        ]
        self.assertEqual(len(issued), 1, rows)
        self.assertEqual(issued[0]["purpose"], "enroll")
        self.assertTrue(issued[0]["secret_generated"])
        self.assertEqual(
            issued[0]["ticket_hash"],
            hashlib.sha256(ticket.encode("utf-8")).hexdigest()[:12],
        )
        enrolled = [
            row for row in rows if row.get("event") == "totp_enrolled"
        ]
        self.assertEqual(len(enrolled), 1, rows)
        self.assertEqual(enrolled[0]["user"], "alice")
        self.assertEqual(enrolled[0]["target"], "alice")
        self.assertEqual(enrolled[0]["recovery_codes"], 10)
        dump = json.dumps(rows, ensure_ascii=False)
        self.assertNotIn(secret, dump)
        self.assertNotIn(ticket, dump)
        self.assertNotIn("otpauth", dump.lower())
        for code in data["recovery_codes"]:
            self.assertNotIn(code, dump)
            self.assertNotIn(
                gateway.hash_recovery_code(code), dump
            )

    def test_session_replacement_and_revocation_are_audited(self) -> None:
        source = "127.0.0.66"
        started = time.time()
        status, headers, body = self.login_from(
            "alice", "hosszu-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        first_cookie = self.cookie_from(headers)
        status, _, body = self.access(
            first_cookie, "web-only", 60, source=source
        )
        self.assertEqual(status, 200, body)

        status, _, body = self.login_from(
            "alice", "hosszu-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        rows = audit_since(self.audit, started)
        replaced = [
            row for row in rows if row.get("event") == "session_replaced"
        ]
        self.assertEqual(len(replaced), 1, rows)
        row = replaced[0]
        self.assertEqual(row["old_user"], "alice")
        self.assertEqual(row["new_user"], "alice")
        self.assertEqual(row["ip"], source)
        self.assertTrue(row["old_authorized"])
        self.assertEqual(row["old_rule"], "web-only")
        self.assertEqual(row["reason"], "new_login_same_ip")
        revoked = [
            row for row in rows if row.get("event") == "access_revoked"
        ]
        self.assertEqual(len(revoked), 1, rows)
        token = first_cookie.split("=", 1)[1]
        self.assertNotIn(token, json.dumps(rows, ensure_ascii=False))

    def test_auto_ban_is_audited_without_password(self) -> None:
        source = "127.0.0.67"
        drops = gateway.droplog.DropLogService(
            os.path.join(self.tmp.name, "auto-ban-drops.jsonl"),
            enabled=False, logger=lambda *_: None,
        )
        original_drops = self.gw.drops
        self.gw.drops = drops
        self.addCleanup(setattr, self.gw, "drops", original_drops)
        self.gw.fail2ban = fail2ban_mod.Fail2ban(
            self.fw,
            path=os.path.join(self.tmp.name, "auto-ban.json"),
            audit=self.audit,
            logger=lambda *_: None,
            enabled=True,
            max_attempts=1,
            window_seconds=600,
            ban_seconds=600,
            drop_enabled=False,
            on_ban=lambda record: self.gw._on_fail2ban_ban(record),
        )
        self.addCleanup(self.reset_fail2ban)
        password = "auto-ban-titkos-jelszo-9"
        started = time.time()
        status, headers, body = self.login_from("alice", password, source)
        self.assertEqual(status, 403, body)
        self.assertNotIn("Set-Cookie", headers)
        rows = audit_since(self.audit, started)
        bans = [
            row for row in rows if row.get("event") == "fail2ban_ban"
        ]
        self.assertEqual(len(bans), 1, rows)
        row = bans[0]
        self.assertEqual(row["ip"], source)
        self.assertEqual(row["user"], "alice")
        self.assertFalse(row["manual"])
        self.assertEqual(row["source"], "login")
        self.assertEqual(row["attempts"], 1)
        self.assertGreater(row["until"], time.time())
        self.assertEqual(row["severity"], "alert")
        dump = json.dumps(rows, ensure_ascii=False)
        self.assertNotIn(password, dump)
        self.assertFalse(
            any("password" in key.lower() for key in row for row in rows),
            rows,
        )

    def test_totp_static_markup_present(self) -> None:
        status, _, body = self.get("/")
        self.assertEqual(status, 200)
        for token in (
            b'id="totp-view"',
            b'id="totp-code"',
            b'id="totp-enroll"',
            b'id="totp-recovery"',
            b'id="totp-recovery-codes"',
            b"/api/login/totp",
            b"totp_required",
        ):
            self.assertIn(token, body, token)
        # Titok vagy szerveroldali mező ne legyen a statikus oldalba égetve.
        for hidden in (
            b"totp_secret",
            b"totp_last_step",
            b"totp_recovery",
            RFC_TOTP_SECRET.encode(),
        ):
            self.assertNotIn(hidden, body, hidden)


class RegistrationHttpTests(unittest.TestCase):
    """Nyilvános fiókkérés: külön, izolált alkalmazás saját beállításfájllal."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tools = FakeTools(self.tmp.name)
        self._globals = (
            ("CONNTRACK_BIN", gateway.CONNTRACK_BIN),
            ("POW_DIFFICULTY", gateway.POW_DIFFICULTY),
            ("PORTAL_URL", gateway.PORTAL_URL),
        )
        gateway.CONNTRACK_BIN = str(self.tools.conntrack)
        gateway.POW_DIFFICULTY = 2
        gateway.PORTAL_URL = ""

        self.users = gateway.UserStore(
            os.path.join(self.tmp.name, "users.json"), iterations=10_000
        )
        self.rules = gateway.RuleStore(
            os.path.join(self.tmp.name, "rules.json"),
            catalog=CATALOG, logger=lambda *_: None,
        )
        self.rules.create("web-only", {
            "label": "Csak web", "tcp": [80, 443], "udp": [443],
            "default_ttl": 3600, "max_ttl": gateway.MAX_TTL,
        })
        self.groups = gateway.GroupStore(
            os.path.join(self.tmp.name, "groups.json"),
            logger=lambda *_: None,
        )
        self.audit = gateway.AuditLog(
            os.path.join(self.tmp.name, "audit.jsonl"),
            logger=lambda *_: None,
        )
        self.settings = gateway.settings_store.SettingsStore(
            os.path.join(self.tmp.name, "firewall-settings.json"),
            logger=lambda *_: None,
        )
        self.fw = gateway.Firewall(
            binary=str(self.tools.nft), logger=lambda *_: None
        )
        self.fail2ban = fail2ban_mod.Fail2ban(
            self.fw,
            path=os.path.join(self.tmp.name, "fail2ban.json"),
            audit=self.audit,
            logger=lambda *_: None,
        )
        self.gw = gateway.Gateway(
            users=self.users, firewall=self.fw, catalog=CATALOG,
            rules=self.rules, groups=self.groups, audit=self.audit,
            settings=self.settings,
            rate_limiter=gateway.RateLimiter(window=60, maximum=1000),
            fail2ban=self.fail2ban,
        )
        server.LOGIN_TICKETS.set_audit(self.audit)
        self.server = server.AppServer(("127.0.0.1", 0), self.gw)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        server.LOGIN_TICKETS.revoke_all()
        server.LOGIN_TICKETS.set_audit(None)
        for name, value in self._globals:
            setattr(gateway, name, value)
        self.tmp.cleanup()

    def get(self, path: str, headers: dict | None = None):
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=10
        )
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        body = resp.read()
        out = (resp.status, dict(resp.getheaders()), body)
        conn.close()
        return out

    def post_json(
        self, path: str, obj: dict, cookie: str = "",
        extra_headers: dict | None = None,
    ):
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=10
        )
        headers = {"Content-Type": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        if cookie:
            headers["Cookie"] = cookie
        conn.request("POST", path, body=json.dumps(obj), headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        out = (resp.status, dict(resp.getheaders()), body)
        conn.close()
        return out

    def captcha(self) -> dict:
        status, _, body = self.get("/api/challenge")
        self.assertEqual(status, 200, body)
        return solve(json.loads(body))

    def register(self, user, password, email, captcha=None):
        return self.post_json(
            "/api/register",
            {
                "user": user,
                "pass": password,
                "email": email,
                "captcha": self.captcha() if captcha is None else captcha,
            },
        )

    def register_raw(self, obj: dict):
        return self.post_json("/api/register", obj)

    def login(self, user: str, password: str, captcha: dict | None = None):
        return self.post_json(
            "/api/login",
            {
                "user": user,
                "pass": password,
                "captcha": self.captcha() if captcha is None else captcha,
            },
        )

    def enable(self) -> None:
        self.settings.set_registration_enabled(True)
        self.assertIs(
            self.settings.snapshot()["registration_enabled"], True
        )

    def audit_rows(self, event: str) -> list[dict]:
        return [
            row for row in self.audit.read(limit=2000)
            if row.get("event") == event
        ]

    def audit_text(self) -> str:
        path = os.path.join(self.tmp.name, "audit.jsonl")
        if not os.path.exists(path):
            return ""
        return Path(path).read_text(encoding="utf-8")

    def test_registration_disabled_by_default(self) -> None:
        self.assertIs(
            self.settings.snapshot()["registration_enabled"], False
        )
        status, headers, body = self.register(
            "alice", "hosszu-jelszo-1", "a@b.co", captcha={}
        )
        self.assertEqual(status, 403, body)
        data = json.loads(body)
        self.assertFalse(data["ok"])
        self.assertEqual(data["code"], "registration_disabled")
        self.assertIn("nem engedélyezett", data["error"])
        self.assertNotIn("Set-Cookie", headers)
        self.assertIsNone(self.users.record("alice"))
        self.assertEqual(self.users.pending_records(), [])
        self.assertEqual(
            [row.get("reason") for row in self.audit_rows(
                "registration_failed"
            )],
            ["a fiókkérés ki van kapcsolva"],
        )

    def test_valid_registration_creates_pending_user_without_session(self) -> None:
        self.enable()
        password = "Hosszu-Jelszo-42"
        status, headers, body = self.register(
            "alice", password, "  A@B.CO "
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertIn("jóváhagyás", data["message"])
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn("token", data)

        record = self.users.record("alice")
        self.assertIsNotNone(record)
        self.assertTrue(record.pending)
        self.assertFalse(record.enabled)
        self.assertEqual(record.email, "a@b.co")
        self.assertEqual(record.rules, ())
        self.assertTrue(record.rules_set)
        self.assertFalse(record.totp_required)
        self.assertFalse(record.must_change_password)
        self.assertEqual(record.role, gateway.ROLE_USER)
        self.assertTrue(self.users.verify("alice", password))
        self.assertEqual([item.name for item in self.users.pending_records()], ["alice"])
        self.assertEqual(self.gw.effective_rules("alice"), [])

        rows = self.audit_rows("registration_requested")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("target"), "alice")
        text = self.audit_text()
        self.assertNotIn("a@b.co", text)
        self.assertNotIn("A@B.CO", text)
        self.assertNotIn(password, text)

    def test_registration_rejects_invalid_fields(self) -> None:
        self.enable()
        # A közös üzenetküldő tesztek miatt bő keret kell: a korlát a
        # captcha és a mezőellenőrzés előtt fogy.
        self.gw.register_rate = gateway.RateLimiter(window=600, maximum=1000)
        cases = (
            ({}, "hiányos adatok"),
            ({"user": "dave", "pass": "hosszu-jelszo-1"}, "hiányos adatok"),
            ({"user": "dave", "pass": "hosszu-jelszo-1",
              "email": "nem-email", "captcha": None}, "Érvénytelen e-mail-cím."),
            ({"user": "dave", "pass": "rovid",
              "email": "d@e.co", "captcha": None}, "a jelszó"),
            ({"user": "nincs itt!", "pass": "hosszu-jelszo-1",
              "email": "d@e.co", "captcha": None}, "felhasználónév"),
        )
        for obj, expected in cases:
            with self.subTest(obj=obj):
                body = dict(obj)
                if body.get("captcha", "missing") is None:
                    body["captcha"] = self.captcha()
                status, headers, response = self.register_raw(body)
                self.assertEqual(status, 400, response)
                data = json.loads(response)
                self.assertFalse(data["ok"])
                self.assertIn(expected, data["error"])
                self.assertNotIn("Set-Cookie", headers)
                self.assertIsNone(self.users.record("dave"))
        self.assertEqual(self.users.pending_records(), [])

    def test_registration_rejects_captcha(self) -> None:
        self.enable()
        self.gw.register_rate = gateway.RateLimiter(window=600, maximum=1000)
        wrong = {"challenge": "nem-letezo", "salt": "x"}
        status, headers, body = self.register(
            "dave", "hosszu-jelszo-1", "d@e.co", captcha=wrong
        )
        self.assertEqual(status, 403, body)
        self.assertIn("Captcha", json.loads(body)["error"])
        self.assertNotIn("Set-Cookie", headers)
        # A captcha kulcs hiánya hiányos adatnak számít (400), az üres
        # csomag viszont érvénytelen captcha (403) -- egyik sem hoz létre
        # fiókot.
        status, _, body = self.register_raw(
            {"user": "dave", "pass": "hosszu-jelszo-1", "email": "d@e.co"}
        )
        self.assertEqual(status, 400, body)
        status, _, body = self.register_raw(
            {"user": "dave", "pass": "hosszu-jelszo-1",
             "email": "d@e.co", "captcha": {}}
        )
        self.assertEqual(status, 403, body)
        self.assertIsNone(self.users.record("dave"))
        self.assertEqual(self.users.pending_records(), [])

    def test_registration_duplicate_username_conflicts(self) -> None:
        self.enable()
        self.gw.register_rate = gateway.RateLimiter(window=600, maximum=1000)
        self.users.add("alice", "hosszu-jelszo-1")
        status, _, body = self.register("alice", "uj-jelszo-12", "a@b.co")
        self.assertEqual(status, 409, body)
        self.assertEqual(json.loads(body)["code"], "username_taken")
        self.assertFalse(self.users.record("alice").pending)

        status, _, body = self.register("bob", "hosszu-jelszo-2", "b@c.co")
        self.assertEqual(status, 200, body)
        status, _, body = self.register("bob", "mas-jelszo-34", "b2@c.co")
        self.assertEqual(status, 409, body)
        self.assertEqual(json.loads(body)["code"], "username_taken")
        pending = self.users.pending_records()
        self.assertEqual([item.name for item in pending], ["bob"])
        self.assertEqual(pending[0].email, "b@c.co")

    def test_registration_rejects_foreign_origin(self) -> None:
        self.enable()
        status, headers, body = self.post_json(
            "/api/register",
            {"user": "alice", "pass": "hosszu-jelszo-1",
             "email": "a@b.co", "captcha": {}},
            extra_headers={"Origin": "http://evil.example"},
        )
        self.assertEqual(status, 403, body)
        self.assertIn(
            "érvénytelen kérés-eredet", json.loads(body)["error"]
        )
        self.assertNotIn("Set-Cookie", headers)
        self.assertIsNone(self.users.record("alice"))
        self.assertEqual(self.users.pending_records(), [])

    def test_registration_accepts_alternate_field_names(self) -> None:
        self.enable()
        status, headers, body = self.post_json(
            "/api/register",
            {
                "name": "alice", "password": "hosszu-jelszo-1",
                "email": "  Alt@Example.CO ",
                "captcha": self.captcha(),
            },
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(json.loads(body)["ok"])
        self.assertNotIn("Set-Cookie", headers)
        record = self.users.record("alice")
        self.assertTrue(record.pending)
        self.assertFalse(record.enabled)
        self.assertEqual(record.email, "alt@example.co")
        self.assertEqual(
            [item.name for item in self.users.pending_records()], ["alice"]
        )
        self.assertEqual(
            [row.get("target") for row in
             self.audit_rows("registration_requested")],
            ["alice"],
        )

    def test_registration_requires_ipv4(self) -> None:
        self.enable()
        # A valódi, szigorú IPv4-ellenőrzést csak a kérés idejére cseréljük.
        with mock.patch.object(gateway, "is_ipv4", return_value=False):
            status, _, body = self.post_json(
                "/api/register",
                {"user": "alice", "pass": "hosszu-jelszo-1",
                 "email": "a@b.co", "captcha": {}},
            )
        self.assertEqual(status, 400, body)
        self.assertIn("csak IPv4", json.loads(body)["error"])
        self.assertIsNone(self.users.record("alice"))
        # A mock nem szivárgott ki: a valódi ellenőrzés és a regisztráció él.
        self.assertTrue(gateway.is_ipv4("127.0.0.1"))
        status, _, body = self.register(
            "alice", "hosszu-jelszo-1", "a@b.co"
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(self.users.record("alice").pending)

    def test_duplicate_email_is_allowed_without_oracle(self) -> None:
        self.enable()
        status1, headers1, body1 = self.register(
            "alice", "hosszu-jelszo-1", "Shared@Example.COM"
        )
        status2, headers2, body2 = self.register(
            "bob", "hosszu-jelszo-2", "shared@example.com"
        )
        self.assertEqual(status1, 200, body1)
        self.assertEqual(status2, 200, body2)
        self.assertEqual(body1, body2)
        self.assertNotIn("Set-Cookie", headers1)
        self.assertNotIn("Set-Cookie", headers2)
        records = {item.name: item for item in self.users.pending_records()}
        self.assertEqual(sorted(records), ["alice", "bob"])
        self.assertEqual(records["alice"].email, "shared@example.com")
        self.assertEqual(records["bob"].email, "shared@example.com")
        self.assertNotIn("shared@example.com", self.audit_text())

    def test_registration_rate_limit_is_dedicated(self) -> None:
        self.enable()
        self.assertEqual(self.gw.register_rate.window, 600)
        self.assertEqual(self.gw.register_rate.maximum, 3)
        self.assertIsNot(self.gw.register_rate, self.gw.login_rate)
        for _ in range(3):
            status, _, body = self.register_raw({})
            self.assertEqual(status, 400, body)
        status, headers, body = self.register(
            "alice", "hosszu-jelszo-1", "a@b.co"
        )
        self.assertEqual(status, 429, body)
        self.assertEqual(headers.get("Retry-After"), "600")
        self.assertIn("Túl sok fiókkérés", json.loads(body)["error"])
        self.assertIsNone(self.users.record("alice"))
        self.assertEqual(self.users.pending_records(), [])

    def test_pending_login_is_rejected_until_approved(self) -> None:
        self.enable()
        status, _, body = self.register(
            "alice", "hosszu-jelszo-1", "a@b.co"
        )
        self.assertEqual(status, 200, body)

        status, headers, body = self.login("alice", "hosszu-jelszo-1")
        self.assertEqual(status, 403, body)
        data = json.loads(body)
        self.assertFalse(data["ok"])
        self.assertEqual(data["code"], "pending_approval")
        self.assertIs(data["pending"], True)
        self.assertIn("jóváhagyás", data["error"])
        self.assertIn("vár", data["error"])
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn("token", data)
        self.assertNotIn("ticket", data)
        self.assertEqual(self.gw.effective_rules("alice"), [])
        # A helyes jelszó nem számít hibás belépésnek: nincs fail2ban-tétel.
        pending_bans = [
            row for row in self.gw.fail2ban.snapshot()["pending"]
            if row["ip"] == "127.0.0.1"
        ]
        self.assertEqual(pending_bans, [])
        self.assertEqual(
            [row.get("reason") for row in self.audit_rows("login_failed")
             if row.get("user") == "alice"],
            ["a fiók jóváhagyásra vár"],
        )
        # Munkamenet nélkül a hozzáférés-kérés sem működik.
        status, _, body = self.post_json(
            "/api/access", {"rule": "web-only", "ttl": 60}
        )
        self.assertEqual(status, 400, body)
        self.assertIn("munkamenet", json.loads(body)["error"])

        status, _, body = self.login("alice", "rossz-jelszo-99")
        self.assertEqual(status, 403, body)
        data = json.loads(body)
        self.assertNotIn("code", data)
        self.assertNotIn("pending", data)
        self.assertEqual(
            data["error"], "Hibás felhasználónév vagy jelszó."
        )


class RuleGroupStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.users = gateway.UserStore(
            os.path.join(self.tmp.name, "users.json"), iterations=10_000
        )
        self.rules = gateway.RuleStore(
            os.path.join(self.tmp.name, "rules.json"), catalog=CATALOG,
            logger=lambda *_: None,
        )
        self.groups = gateway.GroupStore(
            os.path.join(self.tmp.name, "groups.json"), logger=lambda *_: None
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_seeded_rules_and_crud(self) -> None:
        ids = [rule.id for rule in self.rules.persisted_rules()]
        for scenario in ("browse", "work", "admin", "full"):
            self.assertIn(scenario, ids)
        rule = self.rules.create("web-only", {
            "label": "Csak web", "description": "teszt",
            "tcp": [80, 443], "udp": [443],
            "default_ttl": 120, "max_ttl": 600,
        })
        self.assertEqual(rule.tcp, (80, 443))
        self.assertEqual(rule.udp, (443,))
        self.assertEqual(self.rules.get("web-only"), rule)
        updated = self.rules.update("web-only", {
            "label": "Web", "tcp": [80, 53, 443], "udp": [53, 443],
            "default_ttl": 60, "max_ttl": 120,
        })
        self.assertEqual(updated.tcp, (53, 80, 443))
        self.assertEqual(updated.udp, (53, 443))
        with self.assertRaises(gateway.RuleStoreError):
            self.rules.create(gateway.LEGACY_ADMIN_RULE_ID, {"tcp": [80]})
        with self.assertRaises(gateway.RuleStoreError):
            self.rules.update(gateway.LEGACY_ADMIN_RULE_ID, {"tcp": [80]})
        with self.assertRaises(gateway.RuleStoreError):
            self.rules.delete(gateway.LEGACY_ADMIN_RULE_ID)
        self.rules.delete("web-only")
        self.assertIsNone(self.rules.get("web-only"))

    def test_empty_rules_file_is_not_reseeded(self) -> None:
        path = os.path.join(self.tmp.name, "empty-rules.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"rules": {}}, fh)
        store = gateway.RuleStore(path, catalog=CATALOG, logger=lambda *_: None)
        self.assertEqual(store.persisted_rules(), [])
        self.assertEqual(store.all_rules(), [])
        self.assertIsNone(store.get(gateway.LEGACY_ADMIN_RULE_ID))

    def test_legacy_services_are_migrated_with_backup(self) -> None:
        path = os.path.join(self.tmp.name, "legacy-rules.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "rules": {
                    "web-only": {
                        "label": "Csak web", "services": ["web"],
                        "default_ttl": 60, "max_ttl": 600,
                    },
                    gateway.LEGACY_ADMIN_RULE_ID: {"services": ["all"]},
                }
            }, fh)
        store = gateway.RuleStore(path, catalog=CATALOG, logger=lambda *_: None)
        rule = store.get("web-only")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.tcp, (80, 443))
        self.assertEqual(rule.udp, (443,))
        self.assertFalse(rule.full)
        self.assertIsNone(store.get(gateway.LEGACY_ADMIN_RULE_ID))
        with open(path, encoding="utf-8") as fh:
            stored_rules = json.load(fh)["rules"]
        self.assertNotIn(gateway.LEGACY_ADMIN_RULE_ID, stored_rules)
        self.assertEqual(stored_rules["web-only"]["tcp"], [80, 443])
        self.assertEqual(stored_rules["web-only"]["udp"], [443])
        self.assertNotIn("services", stored_rules["web-only"])
        backups = list(Path(self.tmp.name).glob(
            "legacy-rules.json.admin-full-backup-*"
        ))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        with open(backups[0], encoding="utf-8") as fh:
            legacy = json.load(fh)["rules"]
        self.assertEqual(legacy["web-only"]["services"], ["web"])
        self.assertIn(gateway.LEGACY_ADMIN_RULE_ID, legacy)

    def test_legacy_admin_full_only_file_becomes_empty_without_reseed(self) -> None:
        path = os.path.join(self.tmp.name, "legacy-admin-only.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "rules": {
                    gateway.LEGACY_ADMIN_RULE_ID: {"services": ["all"]},
                }
            }, fh)
        store = gateway.RuleStore(path, catalog=CATALOG, logger=lambda *_: None)
        self.assertEqual(store.persisted_rules(), [])
        self.assertEqual(store.all_rules(), [])
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["rules"], {})
        backups = list(Path(self.tmp.name).glob(
            "legacy-admin-only.json.admin-full-backup-*"
        ))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)

    def test_whitespace_legacy_rule_ids_are_normalized_and_removed(self) -> None:
        path = os.path.join(self.tmp.name, "whitespace-legacy.json")
        base = {"default_ttl": 60, "max_ttl": 600, "created": 1}
        variants = {
            "admin-full ": {
                "label": "Trailing", "direction": "input",
                "tcp": [22], **base,
            },
            " admin-full": {
                "label": "Leading", "direction": "input",
                "tcp": [22], **base,
            },
            "admin-full\t": {
                "label": "Tab", "direction": "input",
                "tcp": [22], **base,
            },
        }
        raw = dict(variants)
        raw["web-only"] = {"label": "Web", "tcp": [80], **base}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"rules": raw}, fh)

        store = gateway.RuleStore(
            path, catalog=CATALOG, logger=lambda *_: None
        )
        legacy = gateway.LEGACY_ADMIN_RULE_ID
        self.assertIsNone(store.get(legacy))
        for collection in (store.persisted_rules(), store.all_rules()):
            self.assertNotIn(legacy, [rule.id for rule in collection])
        self.users.add("legacy", "hosszu-jelszo-1")
        self.assertNotIn(
            legacy,
            [
                rule.id
                for rule in store.effective_for(
                    self.users.record("legacy"), []
                )
            ],
        )
        self.assertEqual(
            [rule.id for rule in store.persisted_rules()], ["web-only"]
        )

        # A tisztított fájlból a whitespace-es változatok is eltűntek.
        with open(path, encoding="utf-8") as fh:
            stored = json.load(fh)["rules"]
        self.assertEqual(set(stored), {"web-only"})
        for key in variants:
            self.assertNotIn(key, stored)
        backups = list(Path(self.tmp.name).glob(
            "whitespace-legacy.json.admin-full-backup-*"
        ))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        with open(backups[0], encoding="utf-8") as fh:
            backup = json.load(fh)["rules"]
        for key in variants:
            self.assertIn(key, backup)

    def test_whitespace_legacy_only_file_becomes_empty_without_reseed(self) -> None:
        path = os.path.join(self.tmp.name, "whitespace-legacy-only.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "rules": {
                    "admin-full\t": {
                        "label": "Legacy", "direction": "input",
                        "tcp": [22], "default_ttl": 60, "max_ttl": 600,
                    },
                }
            }, fh)
        store = gateway.RuleStore(
            path, catalog=CATALOG, logger=lambda *_: None
        )
        self.assertEqual(store.persisted_rules(), [])
        self.assertEqual(store.all_rules(), [])
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["rules"], {})
        backups = list(Path(self.tmp.name).glob(
            "whitespace-legacy-only.json.admin-full-backup-*"
        ))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)

    def test_normalized_duplicate_id_is_a_parse_error_and_keeps_first(self) -> None:
        path = os.path.join(self.tmp.name, "duplicate-normalized.json")
        base = {"default_ttl": 60, "max_ttl": 600, "created": 1}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "rules": {
                    gateway.LEGACY_ADMIN_RULE_ID: {"services": ["all"]},
                    "dup": {"label": "First", "tcp": [80], **base},
                    " dup ": {"label": "Second", "tcp": [443], **base},
                }
            }, fh)
        logs: list[str] = []
        store = gateway.RuleStore(path, catalog=CATALOG, logger=logs.append)
        # Az első érvényes bejegyzés marad; a második nem írja felül.
        self.assertEqual(store.get("dup").tcp, (80,))
        self.assertEqual(
            [rule.id for rule in store.persisted_rules()], ["dup"]
        )
        self.assertTrue(
            any("ismétlődő szabály-azonosító" in line for line in logs),
            logs,
        )
        # A normalizálási ütközés parse hibának számít: nincs átírás és
        # nincs biztonsági másolat, a fájl nyers tartalma megmarad.
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)["rules"]
        self.assertIn(gateway.LEGACY_ADMIN_RULE_ID, raw)
        self.assertIn("dup", raw)
        self.assertIn(" dup ", raw)
        self.assertFalse(list(Path(self.tmp.name).glob(
            "duplicate-normalized.json.admin-full-backup-*"
        )))
        self.assertTrue(
            any("nem írom át" in line for line in logs), logs
        )

    def test_legacy_admin_id_is_filtered_from_user_and_group_rules(self) -> None:
        self.users.add("alice", "hosszu-jelszo-1", rules=("browse",))
        self.groups.create("staff", {
            "label": "Staff", "rules": ["browse"], "members": ["alice"],
        })
        # Régi fájlokban még szerepelhet a fenntartott azonosító. A betöltés
        # kiszűri, a meglévő többi szabály és a rules_set jelző megmarad.
        with open(self.users.path, encoding="utf-8") as fh:
            users_raw = json.load(fh)
        users_raw["alice"]["rules"].append(gateway.LEGACY_ADMIN_RULE_ID)
        with open(self.users.path, "w", encoding="utf-8") as fh:
            json.dump(users_raw, fh)
        with open(self.groups.path, encoding="utf-8") as fh:
            groups_raw = json.load(fh)
        groups_raw["groups"]["staff"]["rules"].append(
            gateway.LEGACY_ADMIN_RULE_ID
        )
        with open(self.groups.path, "w", encoding="utf-8") as fh:
            json.dump(groups_raw, fh)

        record = self.users.record("alice")
        self.assertEqual(record.rules, ("browse",))
        self.assertTrue(record.rules_set)
        group = gateway.GroupStore(
            self.groups.path, logger=lambda *_: None
        ).get("staff")
        self.assertEqual(group.rules, ("browse",))
        # A szerkesztés nem akad el a kiszűrt azonosítón.
        self.users.set_metadata("alice", rules=("browse",))
        self.groups.update("staff", {
            "label": "Staff", "rules": ["browse"], "members": ["alice"],
        })
        self.assertNotIn(
            gateway.LEGACY_ADMIN_RULE_ID,
            self.users.record("alice").rules,
        )
        self.assertNotIn(
            gateway.LEGACY_ADMIN_RULE_ID,
            self.groups.get("staff").rules,
        )

    def test_whitespace_legacy_id_is_filtered_from_assignments(self) -> None:
        """A users.json/groups.json whitespace-es változata is kiszűrve."""
        self.users.add("alice", "hosszu-jelszo-1", rules=("browse",))
        self.groups.create("staff", {
            "label": "Staff", "rules": ["browse"], "members": ["alice"],
        })
        with open(self.users.path, encoding="utf-8") as fh:
            users_raw = json.load(fh)
        users_raw["alice"]["rules"].append("admin-full ")
        with open(self.users.path, "w", encoding="utf-8") as fh:
            json.dump(users_raw, fh)
        with open(self.groups.path, encoding="utf-8") as fh:
            groups_raw = json.load(fh)
        groups_raw["groups"]["staff"]["rules"].append(" admin-full\t")
        with open(self.groups.path, "w", encoding="utf-8") as fh:
            json.dump(groups_raw, fh)

        record = gateway.UserStore(
            self.users.path, iterations=10_000
        ).record("alice")
        self.assertEqual(record.rules, ("browse",))
        self.assertTrue(record.rules_set)
        group = gateway.GroupStore(
            self.groups.path, logger=lambda *_: None
        ).get("staff")
        self.assertEqual(group.rules, ("browse",))

    def test_legacy_admin_rule_is_reserved_and_invisible(self) -> None:
        legacy = gateway.LEGACY_ADMIN_RULE_ID
        self.assertIsNone(self.rules.get(legacy))
        self.assertNotIn(
            legacy, [rule.id for rule in self.rules.persisted_rules()]
        )
        self.assertNotIn(legacy, [rule.id for rule in self.rules.all_rules()])
        for action in (
            lambda: self.rules.create(legacy, {"tcp": [80]}),
            lambda: self.rules.update(legacy, {"tcp": [80]}),
            lambda: self.rules.delete(legacy),
            lambda: self.rules.duplicate(legacy),
            lambda: self.rules.create("tag", {
                "collection": True, "members": [legacy],
            }),
        ):
            with self.assertRaises(gateway.RuleStoreError) as caught:
                action()
            self.assertIn("fenntartott", str(caught.exception))
            self.assertNotIn("beépített", str(caught.exception))
        # Admin sem kap automatikus szabályt.
        self.users.add("root", "hosszu-jelszo-1", role=gateway.ROLE_ADMIN)
        root = self.users.record("root")
        self.assertEqual(self.rules.effective_for(root, []), [])
        self.assertEqual(root.rules, ())
        self.assertFalse(root.rules_set)

    def test_legacy_migration_is_skipped_on_parse_error(self) -> None:
        path = os.path.join(self.tmp.name, "broken-legacy.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "rules": {
                    "good": {"label": "Jó", "services": ["web"]},
                    "bad": {"label": "Rossz", "services": ["nincs-ilyen"]},
                }
            }, fh)
        logs = []
        store = gateway.RuleStore(
            path, catalog=CATALOG, logger=logs.append
        )
        self.assertIsNotNone(store.get("good"))
        self.assertIsNone(store.get("bad"))
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)["rules"]
        # Hibás bejegyzés esetén nem írjuk át a fájlt.
        self.assertIn("services", raw["good"])
        self.assertFalse(
            list(Path(self.tmp.name).glob("broken-legacy.json.services-backup-*"))
        )
        self.assertTrue(any("nem írom át" in line for line in logs), logs)

    def test_port_rule_validation(self) -> None:
        with self.assertRaises(gateway.RuleStoreError):
            self.rules.create("empty", {"label": "Üres", "tcp": []})
        with self.assertRaises(gateway.RuleStoreError):
            self.rules.create("mixed", {
                "label": "Vegyes", "full": True, "tcp": [80],
            })
        with self.assertRaises(gateway.RuleStoreError):
            self.rules.create("bad-port", {"label": "Rossz", "tcp": [70000]})
        rule = self.rules.create("text-ports", {
            "label": "Szöveges", "tcp": "443, 80 80", "udp": "53",
        })
        self.assertEqual(rule.tcp, (80, 443))
        self.assertEqual(rule.udp, (53,))

    def test_effective_rules_and_group_membership(self) -> None:
        self.users.add("legacy", "hosszu-jelszo-1")
        self.users.add("empty", "hosszu-jelszo-1", rules=())
        self.users.add("alice", "hosszu-jelszo-1", rules=("browse",))
        self.users.add("root", "hosszu-jelszo-1", role=gateway.ROLE_ADMIN)
        self.rules.create("dns-only", {
            "label": "Csak DNS", "tcp": [53, 853], "udp": [53, 853],
            "default_ttl": 60, "max_ttl": 120,
        })
        group = self.groups.create("staff", {
            "label": "Staff", "rules": ["dns-only"], "members": ["alice"],
        })
        self.assertEqual(group.members, ("alice",))
        self.assertEqual(
            [item.id for item in self.groups.groups_for("alice")], ["staff"]
        )

        legacy = self.users.record("legacy")
        empty = self.users.record("empty")
        alice = self.users.record("alice")
        root = self.users.record("root")
        self.assertIn(
            "browse",
            [rule.id for rule in self.rules.effective_for(legacy, [])],
        )
        self.assertEqual(self.rules.effective_for(empty, []), [])
        self.assertEqual(
            [rule.id for rule in self.rules.effective_for(alice, [group])],
            ["browse", "dns-only"],
        )
        root_rules = [rule.id for rule in self.rules.effective_for(root, [])]
        # Az admin sem kap automatikus hozzáférést: csak a kifejezetten
        # kiosztott szabályok érvényesek.
        self.assertEqual(root_rules, [])
        self.users.set_metadata("root", rules=("browse",))
        root = self.users.record("root")
        self.assertEqual(
            [rule.id for rule in self.rules.effective_for(root, [])],
            ["browse"],
        )
        with self.assertRaises(gateway.AccessError):
            self.rules.resolve_for(empty, [], "browse")
        self.assertEqual(
            self.rules.resolve_for(alice, [group], "dns-only").id, "dns-only"
        )

        self.groups.set_memberships("alice", [])
        self.assertEqual(self.groups.groups_for("alice"), [])
        self.assertEqual(
            self.users.record("alice").rules, ("browse",)
        )
        self.groups.remove_rule_everywhere("dns-only")
        self.assertEqual(self.groups.get("staff").rules, ())

    def test_legacy_fallback_is_forward_only(self) -> None:
        """Kiosztás nélküli régi fiók nem örökölhet host (input) szabályt."""
        self.rules.create("host-ssh", {
            "label": "Host SSH", "direction": "input", "tcp": [22],
            "default_ttl": 60, "max_ttl": 600,
        })
        self.rules.create("forward-web", {"label": "Web", "tcp": [80]})
        self.rules.create("forward-full", {"label": "Full", "full": True})
        self.rules.create("mixed-col", {
            "label": "Mixed", "collection": True,
            "members": ["forward-web", "host-ssh"],
        })
        self.rules.create("input-col", {
            "label": "Only input", "collection": True,
            "members": ["host-ssh"],
        })
        # Régi fiók: a users.json-ban nincs rules kulcs.
        self.users.add("legacy", "hosszu-jelszo-1")
        legacy = self.users.record("legacy")
        self.assertEqual(legacy.rules, ())
        self.assertFalse(legacy.rules_set)

        effective = self.rules.effective_for(legacy, [])
        ids = [rule.id for rule in effective]
        # Az ordinary forward szabályok (a forward full is) megmaradnak.
        self.assertIn("forward-web", ids)
        self.assertIn("forward-full", ids)
        # Az input szabály és a input tagot tartalmazó gyűjtők kimaradnak.
        self.assertNotIn("host-ssh", ids)
        self.assertNotIn("mixed-col", ids)
        self.assertNotIn("input-col", ids)
        self.assertFalse(
            any(
                part.direction == "input"
                for rule in effective
                for part in rule.grants
            )
        )

        # A host szabály a fallbacken keresztül nem kérhető/engedélyezhető.
        for rule_id in ("host-ssh", "mixed-col", "input-col"):
            with self.subTest(rule_id=rule_id):
                with self.assertRaises(gateway.AccessError):
                    self.rules.resolve_for(legacy, [], rule_id)

        # Az effektív szabályokból képzett tűzfalelemek között nincs
        # (IP, 22) input pár.
        address = "192.168.50.20"
        firewall = gateway.Firewall(dry_run=True, logger=lambda *_: None)
        elements = [
            element
            for rule in effective
            for element in firewall._elements(address, rule.ports)
        ]
        self.assertNotIn(
            (firewall.input_tcp_set, f"{address} . 22"), elements
        )
        self.assertFalse(
            any(
                set_name == firewall.input_tcp_set
                for set_name, _element in elements
            ),
            elements,
        )

        # Kifejezett kiosztással viszont választható és (IP, 22)-t ad.
        self.users.set_metadata("legacy", rules=("host-ssh",))
        assigned = self.users.record("legacy")
        self.assertTrue(assigned.rules_set)
        self.assertEqual(
            [rule.id for rule in self.rules.effective_for(assigned, [])],
            ["host-ssh"],
        )
        resolved = self.rules.resolve_for(assigned, [], "host-ssh")
        self.assertEqual(
            firewall._elements(address, resolved.ports),
            [(firewall.input_tcp_set, f"{address} . 22")],
        )

        class _RecordingFirewall:
            def __init__(self) -> None:
                self.granted: list[tuple] = []

            def revoke_all(self, ip: str, grants=()) -> None:
                pass

            def grant_all(self, ip, grants, ttl) -> None:
                self.granted.append((ip, tuple(grants), ttl))

        manager = gateway.SessionManager(
            _RecordingFirewall(), ttl=600, pending_ttl=60
        )
        session = manager.login("legacy", address)
        authorized = manager.authorize(
            session.token, address, resolved, resolved.max_ttl
        )
        self.assertEqual(authorized.grant_parts, resolved.grants)
        self.assertEqual(
            resolved.grants,
            (gateway.Ports((22,), (), False, False, "input"),),
        )
        self.assertEqual(
            firewall._elements(address, authorized.grant_parts[0]),
            [(firewall.input_tcp_set, f"{address} . 22")],
        )

        # Csoporton keresztüli kifejezett kiosztás is működik.
        self.users.set_metadata("legacy", rules=())
        group = self.groups.create("ssh-staff", {
            "label": "SSH", "rules": ["host-ssh"], "members": ["legacy"],
        })
        grouped = self.users.record("legacy")
        self.assertEqual(
            [
                rule.id
                for rule in self.rules.effective_for(grouped, [group])
            ],
            ["host-ssh"],
        )
        self.assertEqual(
            self.rules.resolve_for(grouped, [group], "host-ssh").id,
            "host-ssh",
        )

        # Az admin továbbra sem kap automatikus szabályt.
        self.users.add(
            "root", "hosszu-jelszo-1", role=gateway.ROLE_ADMIN
        )
        root = self.users.record("root")
        self.assertEqual(self.rules.effective_for(root, []), [])
        self.assertFalse(root.rules_set)

    def test_collection_union_resolution_and_persistence(self) -> None:
        web = self.rules.create("col-web", {
            "label": "Web", "tcp": [80, 443], "udp": [443],
            "default_ttl": 120, "max_ttl": 600,
        })
        dns = self.rules.create("col-dns", {
            "label": "DNS", "tcp": [53, 853], "udp": [53], "icmp": True,
            "default_ttl": 60, "max_ttl": 300,
        })
        combo = self.rules.create("col-combo", {
            "label": "Web + DNS", "description": "gyűjtő",
            "collection": True, "members": ["col-web", "col-dns"],
            "default_ttl": 120, "max_ttl": 600,
        })
        self.assertTrue(combo.collection)
        self.assertEqual(combo.members, ("col-web", "col-dns"))
        self.assertEqual(combo.tcp, (53, 80, 443, 853))
        self.assertEqual(combo.udp, (53, 443))
        self.assertTrue(combo.icmp)
        self.assertFalse(combo.full)
        self.assertEqual(
            combo.public()["ports_label"], "TCP 53, 80, 443, 853 · UDP 53, 443 · ICMP"
        )
        self.assertIn("members", combo.public())
        self.assertTrue(combo.public()["collection"])

        with open(self.rules.path, encoding="utf-8") as fh:
            stored = json.load(fh)["rules"]["col-combo"]
        self.assertEqual(
            set(stored),
            {"label", "description", "members", "default_ttl",
             "max_ttl", "created"},
        )
        self.assertEqual(stored["members"], ["col-web", "col-dns"])
        # A gyűjtőszabálynak nincs saját iránya a tárolt alakban sem.
        for forbidden in ("direction", "tcp", "udp", "icmp", "full"):
            self.assertNotIn(forbidden, stored)

        reloaded = gateway.RuleStore(
            self.rules.path, catalog=CATALOG, logger=lambda *_: None
        )
        loaded = reloaded.get("col-combo")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.members, ("col-web", "col-dns"))
        self.assertEqual(loaded.tcp, (53, 80, 443, 853))
        self.assertEqual(loaded.udp, (53, 443))
        self.assertTrue(loaded.icmp)
        self.assertFalse(loaded.full)

    def test_host_rule_create_and_persistence(self) -> None:
        rule = self.rules.create("mpwerks-host", {
            "label": "mpwerks host", "direction": "input",
            "tcp": [25566], "udp": [25566],
            "default_ttl": 60, "max_ttl": 600,
        })
        self.assertEqual(rule.direction, "input")
        self.assertEqual(rule.ports.direction, "input")
        self.assertEqual(rule.ports.public()["direction"], "input")
        self.assertEqual(rule.public()["direction"], "input")

        tcp_only = self.rules.create("host-tcp-only", {
            "label": "Host TCP", "direction": "input", "tcp": [25566],
        })
        self.assertEqual(tcp_only.direction, "input")
        self.assertEqual(tcp_only.udp, ())

        with open(self.rules.path, encoding="utf-8") as fh:
            stored = json.load(fh)["rules"]
        self.assertEqual(stored["mpwerks-host"]["direction"], "input")
        self.assertEqual(stored["host-tcp-only"]["direction"], "input")
        # A direction nélküli (régi) szabály továbbra is forward.
        default = self.rules.create("plain-forward", {
            "label": "Plain", "tcp": [25566],
        })
        self.assertEqual(default.direction, "forward")
        with open(self.rules.path, encoding="utf-8") as fh:
            self.assertEqual(
                json.load(fh)["rules"]["plain-forward"]["direction"], "forward"
            )

        reloaded = gateway.RuleStore(
            self.rules.path, catalog=CATALOG, logger=lambda *_: None
        )
        loaded = reloaded.get("mpwerks-host")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.direction, "input")
        self.assertEqual(loaded.ports.direction, "input")
        self.assertEqual(loaded.public()["direction"], "input")

    def test_host_rule_validation_messages(self) -> None:
        cases = (
            (
                {"direction": "input", "full": True},
                "host szabály nem lehet teljes hozzáférésű",
            ),
            (
                {"direction": "input", "icmp": True},
                "host szabály nem tartalmazhat ICMP-t",
            ),
            (
                {"direction": "input", "services": ["web"]},
                "host szabály nem használhat szolgáltatáslistát",
            ),
            (
                {"direction": "input"},
                "host szabályhoz legalább egy TCP vagy UDP port kell",
            ),
            (
                {"direction": "input", "tcp": [8100]},
                "a 8100-as port (portál) nem nyitható meg host szabállyal",
            ),
            (
                {"direction": "input", "udp": [8100]},
                "a 8100-as port (portál) nem nyitható meg host szabállyal",
            ),
            (
                {"direction": "oldalra", "tcp": [25566]},
                "direction: forward vagy input érték kell",
            ),
        )
        for index, (payload, message) in enumerate(cases):
            with self.subTest(payload=payload):
                with self.assertRaises(gateway.RuleStoreError) as caught:
                    self.rules.create(f"host-bad-{index}", payload)
                self.assertEqual(str(caught.exception), message)

        # Forward szabályoknál a teljes hozzáférés, az ICMP és a
        # szolgáltatáslista továbbra is érvényes.
        self.rules.create("forward-full", {"label": "F", "full": True})
        self.rules.create("forward-icmp", {"label": "I", "icmp": True})
        legacy = self.rules.create("forward-legacy", {
            "label": "L", "services": ["web"],
        })
        self.assertEqual(legacy.direction, "forward")
        self.assertEqual(legacy.tcp, (80, 443))

        # A 22-es port admin által létrehozott host szabállyal TCP-n és
        # UDP-n is megnyitható. A szabály nem teljes hozzáférésű, és a
        # tűzfal a külön input halmazokba teszi, soha nem a forward
        # halmazokba.
        fw = gateway.Firewall(dry_run=True, logger=lambda *_: None)
        host_cases = (
            ("host-ssh-tcp", "tcp", fw.input_tcp_set),
            ("host-ssh-udp", "udp", fw.input_udp_set),
        )
        for rule_id, proto, expected_set in host_cases:
            with self.subTest(proto=proto):
                rule = self.rules.create(rule_id, {
                    "label": f"SSH {proto}", "direction": "input",
                    proto: [22],
                })
                self.assertEqual(rule.direction, "input")
                self.assertEqual(rule.ports.direction, "input")
                self.assertFalse(rule.full)
                self.assertIn(22, getattr(rule, proto))
                elements = fw._elements("192.168.50.20", rule.ports)
                self.assertEqual(
                    elements, [(expected_set, "192.168.50.20 . 22")]
                )
                set_names = {name for name, _ in elements}
                for forbidden in (fw.tcp_set, fw.udp_set):
                    self.assertNotIn(forbidden, set_names)

    def test_collection_mixed_directions(self) -> None:
        self.rules.create("host-a", {
            "label": "A", "direction": "input", "tcp": [25566],
        })
        self.rules.create("host-b", {
            "label": "B", "direction": "input", "udp": [25566],
        })
        self.rules.create("forward-member", {"label": "F", "tcp": [80]})
        # A gyűjtő payloadjában szereplő elavult/hibás irányt figyelmen
        # kívül hagyjuk: kizárólag a tagok iránya dönt.
        mixed = self.rules.create("mixed-col", {
            "label": "Mixed", "collection": True,
            "direction": "oldalra",
            "members": ["host-a", "host-b", "forward-member"],
            "default_ttl": 60, "max_ttl": 600,
        })
        self.assertEqual(mixed.direction, "mixed")
        self.assertEqual(mixed.tcp, (80,))
        self.assertEqual(mixed.udp, ())
        self.assertEqual(mixed.input_tcp, (25566,))
        self.assertEqual(mixed.input_udp, (25566,))
        self.assertEqual(
            {part.direction for part in mixed.grants}, {"forward", "input"}
        )
        forward_part = next(
            part for part in mixed.grants if part.direction == "forward"
        )
        input_part = next(
            part for part in mixed.grants if part.direction == "input"
        )
        self.assertEqual(forward_part.tcp, (80,))
        self.assertEqual(forward_part.udp, ())
        self.assertEqual(input_part.tcp, (25566,))
        self.assertEqual(input_part.udp, (25566,))
        self.assertEqual(
            mixed.public()["ports_label"],
            "TCP 80, 25566 · UDP 25566",
        )
        # A gyűjtőnek nincs saját iránya a nyilvános vagy tárolt alakban.
        self.assertNotIn("direction", mixed.public())
        with open(self.rules.path, encoding="utf-8") as fh:
            stored = json.load(fh)["rules"]["mixed-col"]
        self.assertNotIn("direction", stored)
        self.assertNotIn("tcp", stored)
        self.assertNotIn("udp", stored)

        reloaded = gateway.RuleStore(
            self.rules.path, catalog=CATALOG, logger=lambda *_: None
        )
        loaded = reloaded.get("mixed-col")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.direction, "mixed")
        self.assertEqual(loaded.tcp, (80,))
        self.assertEqual(loaded.input_tcp, (25566,))
        self.assertEqual(loaded.input_udp, (25566,))
        self.assertEqual(loaded.grants, mixed.grants)

        # Csak input tagok: a gyűjtő iránya input, engedélye csak input.
        input_col = self.rules.create("input-col", {
            "label": "Input collection", "collection": True,
            "members": ["host-a", "host-b"],
        })
        self.assertEqual(input_col.direction, "input")
        self.assertEqual(input_col.tcp, ())
        self.assertEqual(input_col.input_tcp, (25566,))
        self.assertEqual(
            [part.direction for part in input_col.grants], ["input"]
        )

        # Egy tag is elég, és a csak forward tagok forward gyűjtőt adnak.
        forward_col = self.rules.create("forward-col", {
            "label": "Forward collection", "collection": True,
            "members": ["forward-member"],
        })
        self.assertEqual(forward_col.direction, "forward")
        self.assertEqual(forward_col.tcp, (80,))
        self.assertEqual(forward_col.input_tcp, ())
        self.assertEqual(
            [part.direction for part in forward_col.grants], ["forward"]
        )

        # A tag iránya a gyűjtő alatt is megváltozhat; a függő gyűjtők
        # visszajönnek, hogy a szerver a munkameneteiket visszavonhassa.
        updated, dependents = self.rules.update_with_dependents("host-a", {
            "label": "A", "direction": "forward", "tcp": [25566],
        })
        self.assertEqual(updated.direction, "forward")
        self.assertEqual(set(dependents), {"mixed-col", "input-col"})
        refreshed = self.rules.get("mixed-col")
        # host-a most forward, host-b továbbra is input, a forward tag mellett.
        self.assertEqual(refreshed.direction, "mixed")
        self.assertEqual(refreshed.tcp, (80, 25566))
        self.assertEqual(refreshed.input_tcp, ())
        self.assertEqual(refreshed.input_udp, (25566,))
        refreshed_input = self.rules.get("input-col")
        self.assertEqual(refreshed_input.direction, "mixed")
        self.assertEqual(refreshed_input.tcp, (25566,))
        self.assertEqual(refreshed_input.input_udp, (25566,))

    def test_collection_validation_rejects_bad_members(self) -> None:
        self.rules.create("member-a", {"label": "A", "tcp": [80]})
        self.rules.create("member-b", {"label": "B", "udp": [53]})
        self.rules.create("host-member", {
            "label": "H", "direction": "input", "tcp": [2525],
        })
        self.rules.create("member-full", {"label": "Full", "full": True})
        self.rules.create("nested", {
            "label": "Nested", "collection": True,
            "members": ["member-a", "member-b"],
        })
        # Egyetlen tag is elég, forward és host (input) változatban is.
        single = self.rules.create("single-member", {
            "label": "X", "collection": True, "members": ["member-a"],
        })
        self.assertEqual(single.members, ("member-a",))
        self.assertEqual(single.tcp, (80,))
        self.assertEqual(single.direction, "forward")
        single_host = self.rules.create("single-host-member", {
            "label": "X", "collection": True, "members": ["host-member"],
        })
        self.assertEqual(single_host.direction, "input")
        self.assertEqual(single_host.input_tcp, (2525,))
        self.assertEqual(
            [part.direction for part in single_host.grants], ["input"]
        )
        invalid = {
            "unknown member": (
                {"label": "X", "members": ["member-a", "missing"]},
                "ismeretlen szabály a gyűjtőszabályban: missing",
            ),
            "full member": (
                {"label": "X", "members": ["member-a", "member-full"]},
                "teljes hozzáférésű szabályt: member-full",
            ),
            "nested collection": (
                {"label": "X", "members": ["member-a", "nested"]},
                "másik gyűjtőszabályt: nested",
            ),
            "duplicate members": (
                {"label": "X", "members": ["member-a", "member-a"]},
                "ismétlődő szabály-azonosító",
            ),
            "empty members": (
                {"label": "X", "collection": True},
                "members: 1–64 szabály-azonosítóból álló lista kell",
            ),
            "ports with collection": (
                {
                    "label": "X", "collection": True,
                    "members": ["member-a", "member-b"], "tcp": [80],
                },
                "nem adható meg port",
            ),
            "too many members": (
                {
                    "label": "X", "collection": True,
                    "members": [f"r{index}" for index in range(65)],
                },
                "legfeljebb 64",
            ),
            "self reference": (
                {
                    "label": "X", "collection": True,
                    "members": ["member-a", "selfref"],
                },
                "nem tartalmazhatja önmagát",
            ),
        }
        for index, (name, (payload, expected)) in enumerate(invalid.items()):
            target = "selfref" if name == "self reference" else f"bad-{index}"
            with self.subTest(name=name):
                with self.assertRaises(gateway.RuleStoreError) as caught:
                    self.rules.create(target, payload)
                self.assertIn(expected, str(caught.exception))
        self.assertIsNone(self.rules.get("selfref"))

    def test_collection_assignment_and_authorization(self) -> None:
        self.rules.create("col-web", {
            "label": "Web", "tcp": [80, 443], "udp": [443],
        })
        self.rules.create("col-dns", {
            "label": "DNS", "tcp": [53, 853], "udp": [53], "icmp": True,
        })
        combo = self.rules.create("col-combo", {
            "label": "Combo", "collection": True,
            "members": ["col-web", "col-dns"],
            "default_ttl": 120, "max_ttl": 300,
        })
        self.users.add("alice", "hosszu-jelszo-1", rules=("col-combo",))
        self.users.add("bob", "hosszu-jelszo-2", rules=())
        group = self.groups.create("col-staff", {
            "label": "Staff", "rules": ["col-combo"], "members": ["bob"],
        })
        alice = self.users.record("alice")
        bob = self.users.record("bob")
        alice_effective = self.rules.effective_for(alice, [])
        bob_effective = self.rules.effective_for(bob, [group])
        self.assertEqual([item.id for item in alice_effective], ["col-combo"])
        self.assertEqual([item.id for item in bob_effective], ["col-combo"])
        for current in (alice_effective[0], bob_effective[0]):
            self.assertEqual(current.tcp, (53, 80, 443, 853))
            self.assertEqual(current.udp, (53, 443))
            self.assertTrue(current.icmp)
            self.assertFalse(current.full)
        resolved = self.rules.resolve_for(alice, [], "col-combo")
        self.assertEqual(resolved.ports, combo.ports)
        self.assertEqual(resolved.default_ttl, 120)
        self.assertEqual(resolved.max_ttl, 300)

        class _FakeFirewall:
            def __init__(self) -> None:
                self.granted = []

            def revoke_all(self, ip: str, grants=()) -> None:
                pass

            def grant_all(self, ip, grants, ttl) -> None:
                self.granted.append((ip, tuple(grants), ttl))

        firewall = _FakeFirewall()
        manager = gateway.SessionManager(
            firewall, ttl=3600, pending_ttl=600
        )
        session = manager.login("alice", "192.168.50.10")
        with self.assertRaises(gateway.AccessError):
            manager.authorize(
                session.token, "192.168.50.10", resolved, resolved.max_ttl + 1
            )
        authorized = manager.authorize(
            session.token, "192.168.50.10", resolved, resolved.max_ttl
        )
        self.assertEqual(authorized.rule, "col-combo")
        self.assertEqual(authorized.ports, resolved.ports)
        self.assertEqual(authorized.grant_parts, resolved.grants)
        self.assertEqual(
            firewall.granted[-1],
            ("192.168.50.10", resolved.grants, resolved.max_ttl),
        )

    def test_delete_blocks_collection_member_and_collections_containing(self) -> None:
        self.rules.create("member-a", {"label": "A", "tcp": [80]})
        self.rules.create("member-b", {"label": "B", "udp": [53]})
        self.rules.create("col-a", {
            "label": "Combo A", "collection": True,
            "members": ["member-a", "member-b"],
        })
        self.rules.create("col-b", {
            "label": "Combo B", "collection": True,
            "members": ["member-a", "member-b"],
        })
        self.assertEqual(
            sorted(self.rules.collections_containing("member-a")),
            ["col-a", "col-b"],
        )
        self.assertEqual(self.rules.collections_containing("col-a"), [])
        with self.assertRaises(gateway.RuleStoreError) as caught:
            self.rules.delete("member-a")
        message = str(caught.exception)
        self.assertIn("col-a", message)
        self.assertIn("col-b", message)
        self.assertIn("gyűjtőszabály", message)
        # A gyűjtő törlése csak a gyűjtőt törli, a tagokat nem.
        self.rules.delete("col-a")
        self.assertIsNotNone(self.rules.get("member-a"))
        self.assertIsNotNone(self.rules.get("member-b"))
        self.assertEqual(self.rules.collections_containing("member-a"), ["col-b"])
        self.rules.delete("col-b")
        self.rules.delete("member-a")
        self.assertIsNone(self.rules.get("member-a"))

    def test_collection_member_cannot_become_full_or_collection(self) -> None:
        """Egy tag nem válhat teljes hozzáférésűvé vagy gyűjtővé."""
        self.rules.create("guard-a", {"label": "A", "tcp": [80]})
        self.rules.create("guard-b", {"label": "B", "udp": [53]})
        self.rules.create("guard-c", {"label": "C", "tcp": [8080]})
        self.rules.create("guard-col", {
            "label": "Guard", "collection": True,
            "members": ["guard-a", "guard-b"],
            "default_ttl": 120, "max_ttl": 600,
        })
        with self.assertRaises(gateway.RuleStoreError) as caught:
            self.rules.update("guard-a", {
                "label": "A", "full": True, "collection": False,
            })
        self.assertIn("guard-col", str(caught.exception))
        member = self.rules.get("guard-a")
        self.assertIsNotNone(member)
        self.assertEqual(member.tcp, (80,))
        self.assertFalse(member.full)

        with self.assertRaises(gateway.RuleStoreError) as caught:
            self.rules.update("guard-a", {
                "label": "A", "collection": True,
                "members": ["guard-b", "guard-c"],
            })
        self.assertIn("guard-col", str(caught.exception))
        self.assertIsNotNone(self.rules.get("guard-a"))
        self.assertFalse(self.rules.get("guard-a").collection)

        # A tag portjának módosítása engedélyezett, és az unió követi.
        self.rules.update("guard-a", {
            "label": "A", "tcp": [8080], "collection": False,
        })
        collection = self.rules.get("guard-col")
        self.assertEqual(collection.tcp, (8080,))
        self.assertEqual(collection.udp, (53,))
        self.assertFalse(collection.full)

    def test_duplicate_individual_and_collection(self) -> None:
        original = self.rules.create("dupe-web", {
            "label": "Dupe web", "description": "leírás",
            "tcp": [80, 443], "udp": [443],
            "default_ttl": 120, "max_ttl": 600,
        })
        copied = self.rules.duplicate("dupe-web")
        self.assertEqual(copied.id, "dupe-web-copy")
        self.assertEqual(copied.label, "Dupe web (copy)")
        self.assertEqual(copied.description, original.description)
        self.assertEqual(copied.tcp, original.tcp)
        self.assertEqual(copied.udp, original.udp)
        self.assertEqual(copied.default_ttl, original.default_ttl)
        self.assertEqual(copied.max_ttl, original.max_ttl)
        self.assertFalse(copied.builtin)
        second = self.rules.duplicate("dupe-web")
        self.assertEqual(second.id, "dupe-web-2")
        explicit = self.rules.duplicate(
            "dupe-web", new_id="dupe-explicit", label="Saját másolat"
        )
        self.assertEqual(explicit.id, "dupe-explicit")
        self.assertEqual(explicit.label, "Saját másolat")
        with self.assertRaises(gateway.RuleStoreError):
            self.rules.duplicate("dupe-web", new_id="dupe-web-copy")
        with self.assertRaises(gateway.RuleStoreError):
            self.rules.duplicate(gateway.LEGACY_ADMIN_RULE_ID)
        with self.assertRaises(gateway.RuleStoreError):
            self.rules.duplicate("nincs-ilyen")

        long_id = "a" * 32
        self.rules.create(long_id, {"label": "Hosszú", "tcp": [8080]})
        long_copy = self.rules.duplicate(long_id)
        self.assertLessEqual(len(long_copy.id), 32)
        self.assertTrue(long_copy.id.endswith("-copy"))

        self.rules.create("col-member", {"label": "Member", "tcp": [22]})
        collection = self.rules.create("dupe-collection", {
            "label": "Collection", "collection": True,
            "members": ["dupe-web", "col-member"],
            "default_ttl": 60, "max_ttl": 300,
        })
        collection_copy = self.rules.duplicate("dupe-collection")
        self.assertEqual(collection_copy.id, "dupe-collection-copy")
        self.assertEqual(collection_copy.members, collection.members)
        self.assertEqual(collection_copy.tcp, collection.tcp)
        self.assertTrue(collection_copy.collection)
        with open(self.rules.path, encoding="utf-8") as fh:
            stored = json.load(fh)["rules"]["dupe-collection-copy"]
        self.assertEqual(
            set(stored),
            {"label", "description", "members", "default_ttl",
             "max_ttl", "created"},
        )
        self.assertNotIn("tcp", stored)
        self.assertNotIn("direction", stored)

    def test_load_drops_invalid_persisted_collections(self) -> None:
        """Hibás perzisztált gyűjtők ne jelenjenek meg és ne adjanak jogot."""
        path = os.path.join(self.tmp.name, "invalid-collections.json")
        base = {"default_ttl": 60, "max_ttl": 600, "created": 1}

        def rule(label: str, **extra) -> dict:
            return {"label": label, **base, **extra}

        raw = {
            "ok-a": rule("A", tcp=[80]),
            "ok-b": rule("B", udp=[53]),
            "ok-full": rule("Full", full=True),
            "ok-nested": rule("Nested", members=["ok-a", "ok-b"]),
            "valid-col": rule("Valid", members=["ok-a", "ok-b"]),
            "bad-missing": rule("Missing", members=["ok-a", "ghost"]),
            "bad-full": rule("Bad full", members=["ok-a", "ok-full"]),
            "bad-nested": rule("Bad nested", members=["ok-a", "ok-nested"]),
            "bad-self": rule("Self", members=["ok-a", "bad-self"]),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"rules": raw}, fh)

        logs: list[str] = []
        store = gateway.RuleStore(path, catalog=CATALOG, logger=logs.append)
        invalid = ("bad-missing", "bad-full", "bad-nested", "bad-self")
        for rule_id in invalid:
            with self.subTest(rule_id=rule_id):
                self.assertIsNone(store.get(rule_id))
                self.assertNotIn(
                    rule_id,
                    [item.id for item in store.persisted_rules()],
                )
                self.assertNotIn(
                    rule_id, [item.id for item in store.all_rules()]
                )
        self.assertIsNotNone(store.get("valid-col"))
        self.assertEqual(store.get("valid-col").tcp, (80,))
        self.assertEqual(store.get("valid-col").udp, (53,))
        self.assertTrue(
            any("kihagyott hibás gyűjtőszabály" in line for line in logs),
            logs,
        )

        # Közvetlen és csoporton keresztüli kiosztás sem ad hozzáférést.
        self.users.add(
            "invalid-direct", "hosszu-jelszo-1",
            rules=("bad-missing",),
        )
        self.users.add("invalid-group", "hosszu-jelszo-1", rules=())
        group = self.groups.create("invalid-grant", {
            "label": "Invalid", "rules": ["bad-nested"],
            "members": ["invalid-group"],
        })
        direct = self.users.record("invalid-direct")
        grouped = self.users.record("invalid-group")
        self.assertEqual(store.effective_for(direct, []), [])
        self.assertEqual(store.effective_for(grouped, [group]), [])
        with self.assertRaises(gateway.AccessError) as caught:
            store.resolve_for(direct, [], "bad-missing")
        self.assertIn("nem tartozik hozzád", str(caught.exception))

    def test_load_mixed_collection_and_ignore_stale_direction(self) -> None:
        path = os.path.join(self.tmp.name, "mixed-collections.json")
        base = {"default_ttl": 60, "max_ttl": 600, "created": 1}
        raw = {
            "lm-fwd": {"label": "F", "tcp": [80], **base},
            "lm-host": {
                "label": "H", "direction": "input",
                "tcp": [25566], "udp": [25566], **base,
            },
            # Elavult/hibás direction a gyűjtőn: a tagok döntenek.
            "lm-mixed": {
                "label": "Mixed", "direction": "oldalra",
                "members": ["lm-fwd", "lm-host"], **base,
            },
            "lm-stale": {
                "label": "Stale", "direction": "input",
                "members": ["lm-fwd"], **base,
            },
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"rules": raw}, fh)

        store = gateway.RuleStore(path, catalog=CATALOG, logger=lambda *_: None)
        mixed = store.get("lm-mixed")
        self.assertIsNotNone(mixed)
        self.assertEqual(mixed.direction, "mixed")
        self.assertEqual(mixed.tcp, (80,))
        self.assertEqual(mixed.input_tcp, (25566,))
        self.assertEqual(mixed.input_udp, (25566,))
        self.assertEqual(
            {part.direction for part in mixed.grants}, {"forward", "input"}
        )
        self.assertNotIn("direction", mixed.public())

        # A gyűjtőn tárolt elavult direction nem írja felül a tagokat.
        stale = store.get("lm-stale")
        self.assertEqual(stale.direction, "forward")
        self.assertEqual([part.direction for part in stale.grants], ["forward"])

    def test_unassigned_collection_cannot_be_authorized(self) -> None:
        self.rules.create("neg-a", {"label": "A", "tcp": [80]})
        self.rules.create("neg-b", {"label": "B", "udp": [53]})
        self.rules.create("neg-col", {
            "label": "Negative", "collection": True,
            "members": ["neg-a", "neg-b"],
        })
        self.users.add(
            "outsider", "hosszu-jelszo-1", rules=("neg-a",)
        )
        outsider = self.users.record("outsider")
        self.assertEqual(
            [item.id for item in self.rules.effective_for(outsider, [])],
            ["neg-a"],
        )
        with self.assertRaises(gateway.AccessError) as caught:
            self.rules.resolve_for(outsider, [], "neg-col")
        self.assertIn("nem tartozik hozzád", str(caught.exception))

        # Egy nem hozzá tartozó csoport szabálya sem nyitja meg.
        other_group = self.groups.create("neg-group", {
            "label": "Other", "rules": ["neg-col"], "members": [],
        })
        with self.assertRaises(gateway.AccessError):
            self.rules.resolve_for(outsider, [other_group], "neg-col")

    def test_duplicate_keeps_suffix_for_long_label(self) -> None:
        """80 karakteres név másolata is megkülönböztethető maradjon."""
        label = "H" * 80
        self.rules.create(
            "long-label", {"label": label, "tcp": [8080]}
        )
        copied = self.rules.duplicate("long-label")
        self.assertLessEqual(len(copied.label), 80)
        self.assertNotEqual(copied.label, label)
        self.assertTrue(copied.label.endswith("(copy)"))
        self.assertEqual(
            copied.label.count("H"), 80 - len(" (copy)")
        )
        reloaded = gateway.RuleStore(
            self.rules.path, catalog=CATALOG, logger=lambda *_: None
        )
        self.assertEqual(reloaded.get(copied.id).label, copied.label)

    def test_user_metadata_and_last_admin_helpers(self) -> None:
        self.users.add("root", "hosszu-jelszo-1", role=gateway.ROLE_ADMIN)
        self.users.add("alice", "hosszu-jelszo-1")
        self.users.set_metadata(
            "alice", role=gateway.ROLE_ADMIN, enabled=False, rules=["browse"]
        )
        record = self.users.record("alice")
        self.assertEqual(record.role, gateway.ROLE_ADMIN)
        self.assertFalse(record.enabled)
        self.assertEqual(record.rules, ("browse",))
        self.assertTrue(record.rules_set)
        self.assertFalse(self.users.verify("alice", "hosszu-jelszo-1"))
        self.assertEqual(self.users.admin_count(), 1)
        self.users.set_password("alice", "masik-jelszo-1")
        record = self.users.record("alice")
        self.assertEqual(record.role, gateway.ROLE_ADMIN)
        self.assertFalse(record.enabled)
        self.assertEqual(record.rules, ("browse",))
        self.users.set_metadata("alice", enabled=True)
        self.assertTrue(self.users.verify("alice", "masik-jelszo-1"))


class RuleStoreConcurrencyTests(unittest.TestCase):
    """A szabálytár zárolási versenyhelyzetei."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _store(self, name: str = "rules.json"):
        class RacingStore(gateway.RuleStore):
            race_hook = None

            def _validate_payload(inner, data, rule_id):
                rule = gateway.RuleStore._validate_payload(
                    inner, data, rule_id
                )
                hook, inner.race_hook = inner.race_hook, None
                if hook is not None:
                    hook()
                return rule

        return RacingStore(
            os.path.join(self.tmp.name, name), catalog=CATALOG,
            logger=lambda *_: None,
        )

    def test_nested_locked_and_create_do_not_deadlock(self) -> None:
        """A _locked() újrabeléphető: a beágyazott create() nem akad meg."""
        store = self._store("nested-lock.json")
        done = threading.Event()
        errors = []

        def work() -> None:
            try:
                with store._locked():
                    with store._locked():
                        store.create(
                            "nested-lock-rule",
                            {"label": "Nested", "tcp": [80]},
                        )
            except BaseException as exc:  # a teszt szálából látható legyen
                errors.append(exc)
            finally:
                done.set()

        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        self.assertTrue(
            done.wait(5), "a beágyazott _locked() holtpontot okozott"
        )
        thread.join(1)
        self.assertFalse(errors, errors)
        self.assertIsNotNone(store.get("nested-lock-rule"))

    def test_create_validates_member_change_under_one_lock(self) -> None:
        """A tag módosítása nem csúszhat a validálás és a commit közé.

        A régi kód a validálást a záron kívül végezte, ezért egy párhuzamos
        delete()/update() érvénytelen (hiányzó, teljes vagy beágyazott tagú)
        gyűjtőt hagyhatott a fájlban. A javított kódnak vagy meg kell
        hiúsítania a létrehozást, vagy érvényes gyűjtőt szabad committálnia.
        """
        for action in ("delete", "full", "nested"):
            with self.subTest(action=action):
                store = self._store(f"race-{action}.json")
                store.create("race-a", {"label": "A", "tcp": [80]})
                store.create("race-b", {"label": "B", "udp": [53]})
                if action == "nested":
                    store.create("race-c", {"label": "C", "tcp": [8080]})

                finished = threading.Event()
                errors: list[str] = []
                threads: list[threading.Thread] = []

                def mutate() -> None:
                    try:
                        if action == "delete":
                            store.delete("race-b")
                        elif action == "full":
                            store.update("race-b", {
                                "label": "B", "full": True,
                                "collection": False,
                            })
                        else:
                            store.update("race-b", {
                                "label": "B", "collection": True,
                                "members": ["race-a", "race-c"],
                            })
                    except gateway.RuleStoreError as exc:
                        errors.append(str(exc))
                    finally:
                        finished.set()

                def hook() -> None:
                    thread = threading.Thread(
                        target=mutate, daemon=True
                    )
                    thread.start()
                    threads.append(thread)
                    # A javított kód zárat tart, ezért a szál legfeljebb a
                    # záron várakozhat; a régi kódnál itt befejeződik.
                    finished.wait(0.5)

                store.race_hook = hook
                created = None
                try:
                    created = store.create("race-col", {
                        "label": "Race", "collection": True,
                        "members": ["race-a", "race-b"],
                    })
                except gateway.RuleStoreError:
                    pass

                for thread in threads:
                    thread.join(5)
                    self.assertFalse(
                        thread.is_alive(),
                        "a versenyző szál nem fejeződött be",
                    )

                # A fájlban maradt gyűjtő minden tagja létező, egyedi,
                # nem teljes és nem gyűjtő szabály legyen.
                with open(store.path, encoding="utf-8") as fh:
                    raw = json.load(fh)["rules"]
                for rule_id, item in raw.items():
                    for member_id in item.get("members", []):
                        self.assertIn(
                            member_id, raw,
                            f"{rule_id} hiányzó tagra hivatkozik",
                        )
                        self.assertNotIn(
                            "members", raw[member_id],
                            f"{rule_id} beágyazott gyűjtőt tartalmaz",
                        )
                        self.assertFalse(
                            raw[member_id].get("full", False),
                            f"{rule_id} teljes hozzáférésű tagot tartalmaz",
                        )

                fresh = gateway.RuleStore(
                    store.path, catalog=CATALOG, logger=lambda *_: None
                )
                if created is not None:
                    loaded = fresh.get("race-col")
                    self.assertIsNotNone(loaded)
                    self.assertEqual(
                        loaded.members, ("race-a", "race-b")
                    )
                    self.assertFalse(loaded.full)
                    self.assertTrue(
                        errors,
                        "a versenyző műveletnek a szülővédő miatt kell "
                        "meghiúsulnia",
                    )
                else:
                    self.assertIsNone(fresh.get("race-col"))


class AdminHttpTests(unittest.TestCase):
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
            os.path.join(cls.tmp.name, "rules.json"), catalog=CATALOG,
            logger=lambda *_: None,
        )
        cls.rules.create("web-only", {
            "label": "Csak web", "tcp": [80, 443], "udp": [443],
            "default_ttl": 120, "max_ttl": 600,
        })
        cls.rules.create("host-ssh", {
            "label": "Host SSH", "tcp": [22], "direction": "input",
            "default_ttl": 300, "max_ttl": 900,
        })
        cls.groups = gateway.GroupStore(
            os.path.join(cls.tmp.name, "groups.json"), logger=lambda *_: None
        )
        cls.audit = gateway.AuditLog(
            os.path.join(cls.tmp.name, "audit.jsonl"), logger=lambda *_: None
        )
        cls.users.add(
            "root", "root-jelszo-1", role=gateway.ROLE_ADMIN
        )
        cls.users.set_metadata("root", rules=("host-ssh",))
        cls.users.add("alice", "alice-jelszo-1", rules=("web-only",))
        cls.users.add("resetme", "resetme-jelszo-1", rules=("web-only",))
        cls.fw = gateway.Firewall(
            binary=str(cls.tools.nft), logger=lambda *_: None, lan_if="eth1"
        )
        cls.settings = gateway.settings_store.SettingsStore(
            os.path.join(cls.tmp.name, "firewall-settings.json"),
            logger=lambda *_: None,
        )
        cls.drops = gateway.droplog.DropLogService(
            os.path.join(cls.tmp.name, "drops.jsonl"),
            enabled=False, logger=lambda *_: None,
        )
        cls.fail2ban = fail2ban_mod.Fail2ban(
            cls.fw,
            path=os.path.join(cls.tmp.name, "fail2ban.json"),
            audit=cls.audit,
            logger=lambda *_: None,
            on_ban=lambda record: cls.gw._on_fail2ban_ban(record),
        )
        cls.gw = gateway.Gateway(
            users=cls.users, firewall=cls.fw, catalog=CATALOG,
            rules=cls.rules, groups=cls.groups, audit=cls.audit,
            rate_limiter=gateway.RateLimiter(window=60, maximum=1000),
            settings=cls.settings, drops=cls.drops, fail2ban=cls.fail2ban,
        )
        server.LOGIN_TICKETS.set_audit(cls.audit)
        cls.server = server.AppServer(("127.0.0.1", 0), cls.gw)
        import threading
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
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
        self.tools.clear_fail()
        self.tools.clear_json()
        self.tools.clear_chains()
        # A beállítások és a drop napló közös a tesztek között; minden teszt
        # ismert, üres állapotból induljon.
        self.gw.settings.commit(
            {"preauth": [], "block": []}
        )
        base = self.drops.store.path
        for suffix in ("", ".1", ".2", ".3", ".4", ".5"):
            try:
                os.unlink(base + suffix)
            except FileNotFoundError:
                pass
        self.reset_fail2ban()

    def reset_fail2ban(self) -> None:
        """Friss, izolált fail2ban-állapot minden teszthez."""
        path = os.path.join(self.tmp.name, "fail2ban.json")
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        self.gw.fail2ban = fail2ban_mod.Fail2ban(
            self.fw,
            path=path,
            audit=self.audit,
            logger=lambda *_: None,
            enabled=True,
            max_attempts=3,
            window_seconds=600,
            ban_seconds=600,
            on_ban=lambda record: self.gw._on_fail2ban_ban(record),
        )

    def conn(self, source: str = "127.0.0.1") -> http.client.HTTPConnection:
        return http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=10, source_address=(source, 0)
        )

    def get(self, path: str, cookie: str = "", source: str = "127.0.0.1"):
        conn = self.conn(source)
        headers = {"Cookie": cookie} if cookie else {}
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        out = (resp.status, dict(resp.getheaders()), body)
        conn.close()
        return out

    def post(self, path: str, obj: dict, cookie: str = "", source: str = "127.0.0.1"):
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

    def login(self, user: str, password: str, source: str = "127.0.0.1"):
        _, _, body = self.get("/api/challenge", source=source)
        challenge = json.loads(body)
        status, headers, body = self.post(
            "/api/login",
            {"user": user, "pass": password, "captcha": solve(challenge)},
            source=source,
        )
        self.assertEqual(status, 200, body)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        return cookie, json.loads(body)

    def admin_cookie(self) -> str:
        cookie, data = self.login("root", "root-jelszo-1", source="127.0.0.5")
        self.assertTrue(data["admin"])
        return cookie

    @staticmethod
    def state(cookie: str, source: str = "127.0.0.5") -> dict:
        conn = http.client.HTTPConnection(
            "127.0.0.1", AdminHttpTests.port, timeout=10,
            source_address=(source, 0),
        )
        conn.request("GET", "/api/admin/state", headers={"Cookie": cookie})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return json.loads(body)

    # -- kétfaktoros belépés ---------------------------------------------------

    def password_login(self, user: str, password: str, source: str = "127.0.0.1"):
        """Jelszavas belépés nyers válasszal (a 2FA-jegyhez forrás-IP kell)."""
        _, _, body = self.get("/api/challenge", source=source)
        challenge = json.loads(body)
        return self.post(
            "/api/login",
            {"user": user, "pass": password, "captcha": solve(challenge)},
            source=source,
        )

    def enroll_totp(self, user: str, password: str, source: str = "127.0.0.1"):
        """Első 2FA-beállítás; (secret, ticket, headers, válasz)."""
        status, _, body = self.password_login(user, password, source)
        self.assertEqual(status, 200, body)
        offer = json.loads(body)
        self.assertTrue(offer.get("totp_enroll_required"), offer)
        secret = offer["secret"]
        ticket = offer["ticket"]
        status, headers, body = self.post(
            "/api/login/totp/enroll",
            {"ticket": ticket, "code": gateway.totp_code(secret)},
            source=source,
        )
        self.assertEqual(status, 200, body)
        return secret, ticket, headers, json.loads(body)

    def create_user(self, cookie: str, name: str, password: str, **extra):
        payload = {
            "action": "create", "name": name, "password": password,
            "role": "user", "enabled": True, "rules": [], "groups": [],
        }
        payload.update(extra)
        return self.post(
            "/api/admin/users", payload, cookie=cookie, source="127.0.0.5"
        )

    def drop_totp_user(self, name: str) -> None:
        """A teszt-specifikus felhasználó és a hozzá tartozó állapot törlése."""
        server.LOGIN_TICKETS.revoke_all()
        self.gw.sessions.revoke_user(name)
        self.gw.groups.remove_member_everywhere(name)
        self.users.remove(name)

    def restore_root_totp(self) -> None:
        server.LOGIN_TICKETS.revoke_all()
        self.users.reset_totp("root")
        self.users.set_totp_required("root", False)
        self.gw.sessions.revoke_user("root")

    def test_non_admin_is_rejected(self) -> None:
        cookie, _ = self.login("alice", "alice-jelszo-1")
        status, _, body = self.get("/api/admin/state", cookie=cookie)
        self.assertEqual(status, 403, body)
        status, _, body = self.get("/api/admin/logs", cookie=cookie)
        self.assertEqual(status, 403, body)
        status, _, body = self.get("/api/admin/sessions", cookie=cookie)
        self.assertEqual(status, 403, body)
        status, _, body = self.get("/api/admin/firewall", cookie=cookie)
        self.assertEqual(status, 403, body)
        status, _, body = self.get("/api/admin/firewall-rules", cookie=cookie)
        self.assertEqual(status, 403, body)
        status, _, body = self.post(
            "/api/admin/sessions", {"action": "terminate", "id": "x"},
            cookie=cookie,
        )
        self.assertEqual(status, 403, body)
        status, _, _ = self.post(
            "/api/admin/users", {"action": "delete", "name": "root"}, cookie=cookie
        )
        self.assertEqual(status, 403)

    def test_admin_firewall_view_groups_active_grants(self) -> None:
        cookie = self.admin_cookie()
        alice_cookie, _ = self.login(
            "alice", "alice-jelszo-1", source="127.0.0.2"
        )
        status, _, body = self.post(
            "/api/access", {"rule": "web-only", "ttl": 120},
            cookie=alice_cookie, source="127.0.0.2",
        )
        self.assertEqual(status, 200, body)

        self.tools.set_json("allowed_tcp", [
            {"val": {"concat": ["127.0.0.2", 80]},
             "timeout": 120, "expires": 100},
            {"val": {"concat": ["127.0.0.2", 443]},
             "timeout": 120, "expires": 100},
        ])
        self.tools.set_json("allowed_udp", [
            {"val": {"concat": ["127.0.0.2", 443]},
             "timeout": 120, "expires": 100},
        ])

        status, _, body = self.get(
            "/api/admin/firewall", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["counts"]["ips"], 1)
        self.assertEqual(data["counts"]["entries"], 3)
        self.assertEqual(data["counts"]["orphans"], 0)
        row = data["ips"][0]
        self.assertEqual(row["ip"], "127.0.0.2")
        self.assertEqual(row["users"], ["alice"])
        self.assertEqual(row["ports_label"], "TCP 80, 443 · UDP 443")
        self.assertEqual([entry["port"] for entry in row["tcp"]], [80, 443])
        self.assertEqual([entry["port"] for entry in row["udp"]], [443])
        # Az egyedi web szabály nem vár host SSH-t; a nézetben nincs külön
        # host_ssh mező, a 22-es port csak közönséges input bejegyzésként
        # jelenhet meg.
        self.assertNotIn("host_ssh", row)
        self.assertTrue(row["in_sync"], row)
        self.assertEqual(row["rules"][0]["label"], "Csak web")
        self.assertEqual(row["sessions"][0]["user"], "alice")
        self.assertTrue(row["sessions"][0]["authorized"])

    def test_admin_firewall_rules_endpoint_returns_raw_chains(self) -> None:
        cookie = self.admin_cookie()
        self.tools.chain_text(
            "forward",
            "chain forward {\n"
            "\ttype filter hook forward priority -10; policy drop;\n"
            "}",
        )
        self.tools.chain_text(
            "preauth",
            "chain preauth {\n"
            '\tiifname "eth1" meta l4proto tcp '
            "ct original proto-dst 25565 accept\n"
            "}",
        )
        try:
            status, _, body = self.get(
                "/api/admin/firewall-rules", cookie=cookie, source="127.0.0.5"
            )
            data = json.loads(body)
            self.assertEqual(status, 200, body)
            self.assertTrue(data["ok"])
            self.assertFalse(data["dry_run"])
            self.assertEqual(data["table"], "hatarvedelem")
            self.assertEqual(data["chains"], ["forward", "preauth"])
            self.assertIn("chain forward", data["text"])
            self.assertIn("ct original proto-dst 25565 accept", data["text"])
            self.assertEqual(data["errors"], [])
        finally:
            self.tools.clear_chains()

    def test_admin_sessions_endpoint_lists_open_sessions(self) -> None:
        cookie = self.admin_cookie()
        alice_cookie, _ = self.login(
            "alice", "alice-jelszo-1", source="127.0.0.2"
        )
        status, _, body = self.post(
            "/api/access", {"rule": "web-only", "ttl": 120},
            cookie=alice_cookie, source="127.0.0.2",
        )
        self.assertEqual(status, 200, body)
        status, _, body = self.get(
            "/api/admin/sessions", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        row = next(item for item in data["sessions"] if item["user"] == "alice")
        self.assertEqual(row["ip"], "127.0.0.2")
        self.assertTrue(row["authorized"])
        self.assertEqual(row["rule"], "web-only")
        self.assertEqual(row["ttl"], 120)
        self.assertGreater(row["expires_in"], 0)
        self.assertLessEqual(row["expires_in"], 120)
        self.assertIn("ua", row)

    def test_admin_can_terminate_a_session(self) -> None:
        cookie = self.admin_cookie()
        user_cookie, _ = self.login(
            "alice", "alice-jelszo-1", source="127.0.0.2"
        )
        status, _, body = self.post(
            "/api/access", {"rule": "web-only", "ttl": 120},
            cookie=user_cookie, source="127.0.0.2",
        )
        self.assertEqual(status, 200, body)

        status, _, body = self.get(
            "/api/admin/sessions", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        rows = json.loads(body)["sessions"]
        alice = next(item for item in rows if item["user"] == "alice")
        own = next(item for item in rows if item["current"])
        self.assertTrue(alice["id"])
        self.assertEqual(own["user"], "root")

        # A saját munkamenet lezárása a Kilépés gomb feladata.
        status, _, body = self.post(
            "/api/admin/sessions", {"action": "terminate", "id": own["id"]},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 400, body)
        self.assertIn("Kilépés", json.loads(body)["error"])

        self.tools.clear()
        status, _, body = self.post(
            "/api/admin/sessions", {"action": "terminate", "id": alice["id"]},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertNotIn(
            "alice", [item["user"] for item in payload["sessions"]]
        )
        self.assertIn("lezárva", payload["message"])

        status, _, body = self.get(
            "/api/status", cookie=user_cookie, source="127.0.0.2"
        )
        data = json.loads(body)
        self.assertFalse(data["authenticated"])
        self.assertEqual(data["last_end"]["reason"], "admin_terminated")

        deletes = self.tools.deletes()
        self.assertIn(
            "nft delete element inet hatarvedelem allowed_tcp { 127.0.0.2 . 80 }",
            deletes,
        )
        self.assertTrue(
            any(line.startswith("conntrack -D -s 127.0.0.2")
                for line in self.tools.lines())
        )
        with open(self.audit.path, encoding="utf-8") as fh:
            entries = [json.loads(line) for line in fh if line.strip()]
        terminated = [
            item for item in entries
            if item.get("event") == "admin_session_terminated"
        ]
        self.assertEqual(terminated[-1]["target"], "alice")
        self.assertEqual(terminated[-1]["user"], "root")
        self.assertEqual(terminated[-1]["ip"], "127.0.0.2")
        self.assertTrue(terminated[-1]["authorized"])

        status, _, body = self.post(
            "/api/admin/sessions", {"action": "terminate", "id": alice["id"]},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 404, body)

    def test_admin_created_user_must_change_password(self) -> None:
        cookie = self.admin_cookie()
        status, _, body = self.post(
            "/api/admin/users",
            {
                "action": "create", "name": "newbie",
                "password": "newbie-jelszo-1", "role": "user",
                "enabled": True, "rules": [], "groups": [],
            },
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        newbie = next(
            user for user in json.loads(body)["users"] if user["name"] == "newbie"
        )
        self.assertTrue(newbie["must_change_password"])

        user_cookie, data = self.login(
            "newbie", "newbie-jelszo-1", source="127.0.0.2"
        )
        self.assertTrue(data["must_change_password"])
        status, _, body = self.post(
            "/api/access", {"rule": "web-only", "ttl": 60},
            cookie=user_cookie, source="127.0.0.2",
        )
        self.assertEqual(status, 403, body)
        self.assertTrue(json.loads(body)["must_change_password"])
        self.assertFalse(
            any("add element" in line for line in self.tools.lines()),
            self.tools.lines(),
        )

        status, _, body = self.post(
            "/api/admin/users",
            {
                "action": "create", "name": "tempadmin",
                "password": "tempadmin-jelszo-1", "role": "admin",
                "enabled": True, "rules": [], "groups": [],
            },
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        temp_cookie, temp_data = self.login(
            "tempadmin", "tempadmin-jelszo-1", source="127.0.0.3"
        )
        self.assertTrue(temp_data["admin"])
        status, _, body = self.get(
            "/api/admin/state", cookie=temp_cookie, source="127.0.0.3"
        )
        self.assertEqual(status, 403, body)
        self.assertTrue(json.loads(body)["must_change_password"])

        for name in ("newbie", "tempadmin"):
            status, _, body = self.post(
                "/api/admin/users", {"action": "delete", "name": name},
                cookie=cookie, source="127.0.0.5",
            )
            self.assertEqual(status, 200, body)

    def test_admin_password_reset_forces_change_and_revokes(self) -> None:
        cookie = self.admin_cookie()
        user_cookie, _ = self.login(
            "resetme", "resetme-jelszo-1", source="127.0.0.2"
        )
        status, _, body = self.post(
            "/api/admin/users",
            {
                "action": "update", "name": "resetme",
                "password": "resetme-uj-jelszo-9",
            },
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        resetme = next(
            user for user in json.loads(body)["users"] if user["name"] == "resetme"
        )
        self.assertTrue(resetme["must_change_password"])

        status, _, body = self.get(
            "/api/status", cookie=user_cookie, source="127.0.0.2"
        )
        self.assertFalse(json.loads(body)["authenticated"])
        self.assertEqual(
            json.loads(body)["last_end"]["reason"], "password_changed"
        )

        _, _, challenge = self.get("/api/challenge", source="127.0.0.2")
        status, _, body = self.post(
            "/api/login",
            {
                "user": "resetme", "pass": "resetme-jelszo-1",
                "captcha": solve(json.loads(challenge)),
            },
            source="127.0.0.2",
        )
        self.assertEqual(status, 403, body)

        new_cookie, data = self.login(
            "resetme", "resetme-uj-jelszo-9", source="127.0.0.2"
        )
        self.assertTrue(data["must_change_password"])
        status, _, body = self.post(
            "/api/password",
            {
                "current": "resetme-uj-jelszo-9",
                "new": "resetme-vegleges-10",
            },
            cookie=new_cookie, source="127.0.0.2",
        )
        self.assertEqual(status, 200, body)
        self.assertFalse(self.users.record("resetme").must_change_password)

    def test_admin_disable_revokes_access_and_blocks_login(self) -> None:
        cookie = self.admin_cookie()
        user_cookie, _ = self.login(
            "alice", "alice-jelszo-1", source="127.0.0.2"
        )
        status, _, body = self.post(
            "/api/access", {"rule": "web-only", "ttl": 60},
            cookie=user_cookie, source="127.0.0.2",
        )
        self.assertEqual(status, 200, body)
        status, _, body = self.post(
            "/api/admin/users",
            {"action": "update", "name": "alice", "enabled": False},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        status, _, body = self.get(
            "/api/status", cookie=user_cookie, source="127.0.0.2"
        )
        self.assertFalse(json.loads(body)["authenticated"])
        self.assertEqual(json.loads(body)["last_end"]["reason"], "disabled")

        _, _, challenge = self.get("/api/challenge", source="127.0.0.2")
        status, _, body = self.post(
            "/api/login",
            {
                "user": "alice", "pass": "alice-jelszo-1",
                "captcha": solve(json.loads(challenge)),
            },
            source="127.0.0.2",
        )
        self.assertEqual(status, 403, body)
        self.assertIn("Hibás", json.loads(body)["error"])

        status, _, body = self.post(
            "/api/admin/users",
            {"action": "update", "name": "alice", "enabled": True},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(self.users.record("alice").enabled)

    def test_admin_update_failure_revokes_and_restores_password(self) -> None:
        cookie = self.admin_cookie()
        # Saját, friss felhasználó: a osztályszintű tárban más tesztek
        # módosíthatják a jelszót, ezért a „resetme” használata
        # teszt-sorrendtől függően elbukna.
        name = "updatefail-user"
        self.users.remove(name)
        self.users.add(name, "updatefail-jelszo-1")
        try:
            user_cookie, _ = self.login(
                name, "updatefail-jelszo-1", source="127.0.0.2"
            )
            before = self.users.record(name)
            self.assertIsNotNone(before)
            original_metadata = self.users.set_metadata

            def failing_metadata(target, **kwargs):
                raise gateway.UserStoreError("szimulált íráshiba")

            self.users.set_metadata = failing_metadata
            try:
                status, _, body = self.post(
                    "/api/admin/users",
                    {
                        "action": "update", "name": name,
                        "password": "updatefail-uj-jelszo-9", "enabled": True,
                    },
                    cookie=cookie, source="127.0.0.5",
                )
            finally:
                self.users.set_metadata = original_metadata
            self.assertEqual(status, 400, body)

            # A köztes hiba után a jelszó-hash és a must_change jelző az
            # eredeti állapotra állt vissza, a munkamenet viszont megszűnt.
            after = self.users.record(name)
            self.assertIsNotNone(after)
            self.assertEqual(after.salt, before.salt)
            self.assertEqual(after.digest, before.digest)
            self.assertEqual(after.iterations, before.iterations)
            self.assertEqual(
                after.must_change_password, before.must_change_password
            )
            self.assertTrue(
                self.users.verify(name, "updatefail-jelszo-1")
            )
            self.assertFalse(
                self.users.verify(name, "updatefail-uj-jelszo-9")
            )

            status, _, body = self.get(
                "/api/status", cookie=user_cookie, source="127.0.0.2"
            )
            self.assertFalse(json.loads(body)["authenticated"])

            failures = [
                row for row in self.audit.read(
                    event="admin_user_update_failed"
                )
                if row.get("target") == name
            ]
            self.assertTrue(failures)
            self.assertEqual(failures[-1].get("stage"), "metadata")
            self.assertTrue(failures[-1].get("password_changed"))
            self.assertGreaterEqual(
                int(failures[-1].get("sessions_revoked", 0)), 1
            )
            self.assertFalse(
                any(
                    "updatefail-uj-jelszo-9" in json.dumps(row)
                    for row in failures
                )
            )
        finally:
            self.users.remove(name)
    def test_cli_local_delete_removes_group_membership(self) -> None:
        name = "cli-delete-user"
        self.users.add(name, "cli-delete-jelszo-1", rules=("web-only",))
        self.groups.create(
            "cli-delete-group",
            {"label": "CLI törlés", "rules": ["web-only"], "members": [name]},
        )
        original = (
            server._control_mutation,
            gateway.UserStore,
            gateway.GroupStore,
            gateway.AuditLog,
        )
        server._control_mutation = lambda payload: (False, 0)
        gateway.UserStore = lambda *args, **kwargs: self.users
        gateway.GroupStore = lambda *args, **kwargs: self.groups
        gateway.AuditLog = lambda *args, **kwargs: self.audit
        try:
            code = server._user_cli(["del", name])
        finally:
            (
                server._control_mutation,
                gateway.UserStore,
                gateway.GroupStore,
                gateway.AuditLog,
            ) = original
            if self.groups.groups_for(name):
                self.groups.remove_member_everywhere(name)
            self.groups.delete("cli-delete-group")
        self.assertEqual(code, 0)
        self.assertIsNone(self.users.record(name))
        self.assertEqual(self.groups.groups_for(name), [])

    def test_admin_state_and_host_ssh_access(self) -> None:
        cookie = self.admin_cookie()
        status, _, body = self.get("/api/admin/state", cookie=cookie, source="127.0.0.5")
        self.assertEqual(status, 200, body)
        state = json.loads(body)
        self.assertTrue(state["ok"])
        self.assertNotIn("builtin_rule", state)
        names = [user["name"] for user in state["users"]]
        self.assertIn("alice", names)
        root = next(user for user in state["users"] if user["name"] == "root")
        self.assertEqual(root["effective_rules"], ["host-ssh"])
        alice = next(user for user in state["users"] if user["name"] == "alice")
        self.assertEqual(alice["rules"], ["web-only"])

        status, _, body = self.get(
            "/api/status", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        status_rules = [
            rule.get("id") for rule in json.loads(body).get("rules", [])
        ]
        self.assertNotIn(gateway.LEGACY_ADMIN_RULE_ID, status_rules)
        self.assertEqual(status_rules, ["host-ssh"])

        # A fenntartott régi azonosító nem kérhető, még adminként sem.
        status, _, body = self.post(
            "/api/access", {"rule": gateway.LEGACY_ADMIN_RULE_ID, "ttl": 60},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 400, body)
        self.assertIn("nem tartozik", json.loads(body)["error"])

        # A kifejezetten kiosztott host SSH szabály viszont megnyitja a
        # 22-es TCP-portot az input halmazban, teljes hozzáférés nélkül.
        status, _, body = self.post(
            "/api/access", {"rule": "host-ssh", "ttl": 60},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertEqual(data["rule"], "host-ssh")
        self.assertFalse(data["grant"]["full"])
        self.assertEqual(data["grant"]["direction"], "input")
        script = self.tools.script()
        self.assertIn(
            "add element inet hatarvedelem allowed_input_tcp "
            "{ 127.0.0.5 . 22 timeout 60s }",
            script,
        )
        self.assertFalse(
            any("allowed_v4" in line for line in script), script
        )

    def test_user_cannot_request_legacy_admin_rule(self) -> None:
        cookie, _ = self.login("alice", "alice-jelszo-1")
        status, _, body = self.post(
            "/api/access", {"rule": gateway.LEGACY_ADMIN_RULE_ID, "ttl": 60},
            cookie=cookie,
        )
        self.assertEqual(status, 400, body)
        self.assertIn("nem tartozik", json.loads(body)["error"])

    def test_admin_rule_mutations_audit_input_direction_and_sync_ports(self) -> None:
        cookie = self.admin_cookie()
        source = "127.0.0.5"

        def admin_post(payload: dict):
            return self.post(
                "/api/admin/rules", payload, cookie=cookie, source=source
            )

        try:
            status, _, body = admin_post({
                "action": "create", "id": "host-audit",
                "label": "Host audit", "direction": "input",
                "tcp": [25566], "udp": [25566],
                "default_ttl": 60, "max_ttl": 600,
            })
            self.assertEqual(status, 200, body)
            rules = self.gw.rules.get("host-audit")
            self.assertIsNotNone(rules)
            self.assertEqual(rules.direction, "input")
            # A host portok azonnal a kerneloldali, csak bővülő védőhalmazba
            # kerülnek (a portál nem üríti őket).
            script = self.tools.script()
            self.assertIn(
                "add element inet hatarvedelem host_service_tcp "
                "{ 22, 25566 }",
                script,
            )
            self.assertIn(
                "add element inet hatarvedelem host_service_udp { 25566 }",
                script,
            )

            self.tools.clear()
            status, _, body = admin_post({
                "action": "update", "id": "host-audit",
                "direction": "input", "tcp": [25566, 25568], "udp": [],
            })
            self.assertEqual(status, 200, body)
            script = self.tools.script()
            self.assertIn(
                "add element inet hatarvedelem host_service_tcp "
                "{ 22, 25566, 25568 }",
                script,
            )
            self.assertNotIn("host_service_udp", script)

            status, _, body = admin_post({
                "action": "duplicate", "id": "host-audit",
                "new_id": "host-audit-copy",
            })
            self.assertEqual(status, 200, body)
            copied = self.gw.rules.get("host-audit-copy")
            self.assertIsNotNone(copied)
            self.assertEqual(copied.direction, "input")

            for event, target in (
                ("admin_rule_created", "host-audit"),
                ("admin_rule_updated", "host-audit"),
                ("admin_rule_duplicated", "host-audit-copy"),
            ):
                status, _, body = self.get(
                    f"/api/admin/logs?limit=200&event={event}",
                    cookie=cookie, source=source,
                )
                self.assertEqual(status, 200, body)
                entries = [
                    entry for entry in json.loads(body)["logs"]
                    if entry.get("target") == target
                ]
                self.assertTrue(entries, event)
                self.assertEqual(entries[-1].get("direction"), "input")

            # A törlés auditja is hordozza az irányt, hogy a host és a
            # forward szabály azonos portok mellett is megkülönböztethető
            # legyen a naplóban.
            status, _, body = admin_post({
                "action": "delete", "id": "host-audit-copy",
            })
            self.assertEqual(status, 200, body)
            status, _, body = self.get(
                "/api/admin/logs?limit=200&event=admin_rule_deleted",
                cookie=cookie, source=source,
            )
            self.assertEqual(status, 200, body)
            entries = [
                entry for entry in json.loads(body)["logs"]
                if entry.get("target") == "host-audit-copy"
            ]
            self.assertTrue(entries)
            self.assertEqual(entries[-1].get("direction"), "input")
        finally:
            for rule_id in ("host-audit-copy", "host-audit"):
                admin_post({"action": "delete", "id": rule_id})

    def test_rule_group_user_crud_and_logs(self) -> None:
        cookie = self.admin_cookie()
        source = "127.0.0.5"

        status, _, body = self.post(
            "/api/admin/rules",
            {
                "action": "create", "id": "dns-only", "label": "Csak DNS",
                "tcp": [53, 853], "udp": [53, 853],
                "default_ttl": 60, "max_ttl": 600,
            },
            cookie=cookie, source=source,
        )
        self.assertEqual(status, 200, body)

        status, _, body = self.post(
            "/api/admin/users",
            {
                "action": "create", "name": "bob", "password": "bob-jelszo-1",
                "role": "user", "enabled": True,
                "rules": ["web-only"], "groups": [],
            },
            cookie=cookie, source=source,
        )
        self.assertEqual(status, 200, body)

        status, _, body = self.post(
            "/api/admin/groups",
            {
                "action": "create", "id": "staff", "label": "Staff",
                "description": "teszt", "rules": ["dns-only"],
                "members": ["bob"],
            },
            cookie=cookie, source=source,
        )
        self.assertEqual(status, 200, body)

        # Részleges frissítés ne törölje a tagokat és a szabályokat.
        status, _, body = self.post(
            "/api/admin/groups",
            {"action": "update", "id": "staff", "label": "Munkatársak"},
            cookie=cookie, source=source,
        )
        self.assertEqual(status, 200, body)
        state = json.loads(body)
        staff = next(group for group in state["groups"] if group["id"] == "staff")
        self.assertEqual(staff["label"], "Munkatársak")
        self.assertEqual(staff["rules"], ["dns-only"])
        self.assertEqual(staff["members"], ["bob"])
        bob = next(user for user in state["users"] if user["name"] == "bob")
        self.assertEqual(bob["groups"], ["staff"])
        self.assertIn("dns-only", bob["effective_rules"])

        status, _, body = self.post(
            "/api/admin/users",
            {
                "action": "create", "name": "carol", "password": "carol-jelszo-1",
                "role": "user", "enabled": True,
                "rules": [], "groups": ["staff"],
            },
            cookie=cookie, source=source,
        )
        self.assertEqual(status, 200, body)
        state = json.loads(body)
        carol = next(user for user in state["users"] if user["name"] == "carol")
        self.assertEqual(carol["groups"], ["staff"])
        self.assertEqual(carol["rules"], [])

        status, _, body = self.post(
            "/api/admin/users",
            {"action": "delete", "name": "bob"},
            cookie=cookie, source=source,
        )
        self.assertEqual(status, 200, body)
        state = json.loads(body)
        self.assertNotIn("bob", [user["name"] for user in state["users"]])
        staff = next(group for group in state["groups"] if group["id"] == "staff")
        self.assertEqual(staff["members"], ["carol"])

        status, _, body = self.post(
            "/api/admin/rules",
            {"action": "delete", "id": "dns-only"},
            cookie=cookie, source=source,
        )
        self.assertEqual(status, 200, body)
        state = json.loads(body)
        self.assertNotIn("dns-only", [rule["id"] for rule in state["rules"]])
        staff = next(group for group in state["groups"] if group["id"] == "staff")
        self.assertEqual(staff["rules"], [])
        carol = next(user for user in state["users"] if user["name"] == "carol")
        self.assertEqual(carol["rules"], [])
        self.assertEqual(carol["effective_rules"], [])

        status, _, body = self.get(
            "/api/admin/logs?limit=200&event=admin_", cookie=cookie, source=source
        )
        self.assertEqual(status, 200, body)
        logs = json.loads(body)["logs"]
        events = [entry["event"] for entry in logs]
        for event in (
            "admin_rule_created", "admin_group_created",
            "admin_group_updated", "admin_user_created",
            "admin_user_deleted", "admin_rule_deleted",
        ):
            self.assertIn(event, events)

    def test_collection_admin_api_assignment_and_access(self) -> None:
        cookie = self.admin_cookie()
        source = "127.0.0.5"

        def admin_post(payload: dict):
            return self.post(
                "/api/admin/rules", payload, cookie=cookie, source=source
            )

        def cleanup() -> None:
            self.post(
                "/api/admin/users",
                {"action": "update", "name": "alice", "rules": ["web-only"]},
                cookie=cookie, source=source,
            )
            for rule_id in ("col-combo", "col-web", "col-dns"):
                self.post(
                    "/api/admin/rules",
                    {"action": "delete", "id": rule_id},
                    cookie=cookie, source=source,
                )
            for user_name in ("groupie",):
                self.post(
                    "/api/admin/users",
                    {"action": "delete", "name": user_name},
                    cookie=cookie, source=source,
                )
            self.post(
                "/api/admin/groups",
                {"action": "delete", "id": "col-staff"},
                cookie=cookie, source=source,
            )

        self.addCleanup(cleanup)
        for payload in (
            {"action": "create", "id": "col-web", "label": "Web",
             "tcp": [80, 443], "udp": [443],
             "default_ttl": 120, "max_ttl": 600},
            {"action": "create", "id": "col-dns", "label": "DNS",
             "tcp": [53, 853], "udp": [53], "icmp": True,
             "default_ttl": 60, "max_ttl": 300},
            {"action": "create", "id": "col-combo", "label": "Web + DNS",
             "collection": True, "members": ["col-web", "col-dns"],
             "default_ttl": 120, "max_ttl": 300},
        ):
            status, _, body = admin_post(payload)
            self.assertEqual(status, 200, body)

        status, _, body = self.get(
            "/api/admin/state", cookie=cookie, source=source
        )
        self.assertEqual(status, 200, body)
        state = json.loads(body)
        combo = next(rule for rule in state["rules"] if rule["id"] == "col-combo")
        self.assertTrue(combo["collection"])
        self.assertEqual(combo["members"], ["col-web", "col-dns"])
        self.assertEqual(combo["tcp"], [53, 80, 443, 853])
        self.assertEqual(combo["udp"], [53, 443])
        self.assertTrue(combo["icmp"])
        self.assertFalse(combo["full"])
        self.assertEqual(
            combo["ports_label"], "TCP 53, 80, 443, 853 · UDP 53, 443 · ICMP"
        )

        # Közvetlen felhasználói kiosztás.
        status, _, body = self.post(
            "/api/admin/users",
            {"action": "update", "name": "alice", "rules": ["col-combo"]},
            cookie=cookie, source=source,
        )
        self.assertEqual(status, 200, body)
        # Csoporton keresztüli kiosztás (a csoport szabályai a tagra élnek).
        status, _, body = self.post(
            "/api/admin/users",
            {"action": "create", "name": "groupie",
             "password": "groupie-jelszo-1", "role": "user",
             "enabled": True, "rules": [], "groups": []},
            cookie=cookie, source=source,
        )
        self.assertEqual(status, 200, body)
        status, _, body = self.post(
            "/api/admin/groups",
            {"action": "create", "id": "col-staff", "label": "Staff",
             "rules": ["col-combo"], "members": ["groupie"]},
            cookie=cookie, source=source,
        )
        self.assertEqual(status, 200, body)

        alice_cookie, _ = self.login("alice", "alice-jelszo-1")
        status, _, body = self.get("/api/status", cookie=alice_cookie)
        self.assertEqual(status, 200, body)
        status_data = json.loads(body)
        exposed = next(
            rule for rule in status_data["rules"] if rule["id"] == "col-combo"
        )
        self.assertTrue(exposed["collection"])
        self.assertEqual(exposed["members"], ["col-web", "col-dns"])
        self.assertEqual(exposed["tcp"], [53, 80, 443, 853])
        self.assertEqual(exposed["udp"], [53, 443])
        self.assertTrue(exposed["icmp"])

        status, _, body = self.post(
            "/api/access", {"rule": "col-combo", "ttl": 301},
            cookie=alice_cookie,
        )
        self.assertEqual(status, 400, body)
        self.assertIn("legfeljebb", json.loads(body)["error"])
        status, _, body = self.post(
            "/api/access", {"rule": "col-combo", "ttl": 300},
            cookie=alice_cookie,
        )
        self.assertEqual(status, 200, body)
        granted = json.loads(body)
        self.assertEqual(granted["rule"], "col-combo")
        self.assertEqual(granted["grant"]["tcp"], [53, 80, 443, 853])
        self.assertEqual(granted["grant"]["udp"], [53, 443])
        self.assertTrue(granted["grant"]["icmp"])
        self.assertFalse(granted["grant"]["full"])
        # A gyűjtő uniója pontosan a tagok TCP/UDP portjait és az ICMP-t
        # engedélyezze, a kért 300 másodperces TTL-lel.
        added = {
            line for line in self.tools.script()
            if line.startswith("add element inet hatarvedelem allowed_")
        }
        expected = {
            "add element inet hatarvedelem allowed_tcp "
            "{ 127.0.0.1 . 53 timeout 300s }",
            "add element inet hatarvedelem allowed_tcp "
            "{ 127.0.0.1 . 80 timeout 300s }",
            "add element inet hatarvedelem allowed_tcp "
            "{ 127.0.0.1 . 443 timeout 300s }",
            "add element inet hatarvedelem allowed_tcp "
            "{ 127.0.0.1 . 853 timeout 300s }",
            "add element inet hatarvedelem allowed_udp "
            "{ 127.0.0.1 . 53 timeout 300s }",
            "add element inet hatarvedelem allowed_udp "
            "{ 127.0.0.1 . 443 timeout 300s }",
            "add element inet hatarvedelem allowed_icmp "
            "{ 127.0.0.1 timeout 300s }",
        }
        self.assertEqual(added, expected)

        groupie_cookie, _ = self.login("groupie", "groupie-jelszo-1")
        status, _, body = self.get("/api/status", cookie=groupie_cookie)
        self.assertEqual(status, 200, body)
        groupie_rules = json.loads(body)["rules"]
        self.assertIn("col-combo", [rule["id"] for rule in groupie_rules])
        self.assertTrue(next(
            rule for rule in groupie_rules if rule["id"] == "col-combo"
        )["collection"])

    def test_update_member_revokes_dependent_collection_sessions(self) -> None:
        cookie = self.admin_cookie()
        source = "127.0.0.5"

        def admin_post(payload: dict):
            return self.post(
                "/api/admin/rules", payload, cookie=cookie, source=source
            )

        def cleanup() -> None:
            self.post(
                "/api/admin/users",
                {"action": "update", "name": "alice", "rules": ["web-only"]},
                cookie=cookie, source=source,
            )
            for rule_id in ("col-combo", "col-web", "col-dns"):
                self.post(
                    "/api/admin/rules",
                    {"action": "delete", "id": rule_id},
                    cookie=cookie, source=source,
                )

        self.addCleanup(cleanup)
        for payload in (
            {"action": "create", "id": "col-web", "label": "Web",
             "tcp": [80], "default_ttl": 60, "max_ttl": 600},
            {"action": "create", "id": "col-dns", "label": "DNS",
             "udp": [53], "default_ttl": 60, "max_ttl": 600},
            {"action": "create", "id": "col-combo", "label": "Combo",
             "collection": True, "members": ["col-web", "col-dns"],
             "default_ttl": 60, "max_ttl": 600},
        ):
            status, _, body = admin_post(payload)
            self.assertEqual(status, 200, body)
        status, _, body = self.post(
            "/api/admin/users",
            {"action": "update", "name": "alice", "rules": ["col-combo"]},
            cookie=cookie, source=source,
        )
        self.assertEqual(status, 200, body)

        alice_cookie, _ = self.login("alice", "alice-jelszo-1")
        status, _, body = self.post(
            "/api/access", {"rule": "col-combo", "ttl": 60},
            cookie=alice_cookie,
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(any(
            row["user"] == "alice" and row["authorized"]
            for row in self.gw.sessions.active_sessions()
        ))

        status, _, body = admin_post({
            "action": "update", "id": "col-web", "label": "Web módosítva",
            "tcp": [80, 8080], "default_ttl": 60, "max_ttl": 600,
        })
        self.assertEqual(status, 200, body)
        self.assertFalse(any(
            row["user"] == "alice" and row["authorized"]
            for row in self.gw.sessions.active_sessions()
        ))

        status, _, body = self.get(
            "/api/admin/logs?limit=200&event=admin_rule_updated",
            cookie=cookie, source=source,
        )
        self.assertEqual(status, 200, body)
        entries = [
            entry for entry in json.loads(body)["logs"]
            if entry.get("target") == "col-web"
        ]
        self.assertTrue(entries)
        latest = entries[-1]
        self.assertIn("col-combo", latest.get("collections_affected", ""))
        self.assertGreaterEqual(int(latest.get("sessions_revoked", 0)), 1)

    def test_rule_available_detects_member_direction_change(self) -> None:
        """Ugyanazok a portok, de más irány => más grants, újra kell választani."""
        try:
            self.rules.create("rc-host", {
                "label": "H", "direction": "input", "tcp": [25566],
            })
            self.rules.create("rc-col", {
                "label": "C", "collection": True, "members": ["rc-host"],
            })
            self.users.add(
                "rulecheck", "rulecheck-jelszo-1", rules=("rc-col",)
            )
            record = self.users.record("rulecheck")
            selected = self.rules.resolve_for(record, [], "rc-col")
            self.assertTrue(self.gw._rule_available("rulecheck", selected))

            # A tag iránya azonos port mellett megváltozik: a feloldott
            # engedély már a forward halmazba kerülne, ezért a régi
            # választás érvénytelen.
            self.rules.update("rc-host", {
                "label": "H", "direction": "forward", "tcp": [25566],
            })
            self.assertFalse(self.gw._rule_available("rulecheck", selected))
            current = self.rules.resolve_for(
                self.users.record("rulecheck"), [], "rc-col"
            )
            self.assertTrue(self.gw._rule_available("rulecheck", current))
        finally:
            self.users.remove("rulecheck")
            for rule_id in ("rc-col", "rc-host"):
                try:
                    self.rules.delete(rule_id)
                except gateway.RuleStoreError:
                    pass

    def test_sync_host_ports_collects_mixed_collection_input(self) -> None:
        try:
            self.rules.create("mix-sync-fwd", {
                "label": "F", "tcp": [80],
            })
            self.rules.create("mix-sync-host", {
                "label": "H", "direction": "input",
                "tcp": [25566], "udp": [25566],
            })
            self.rules.create("mix-sync-col", {
                "label": "C", "collection": True,
                "members": ["mix-sync-fwd", "mix-sync-host"],
            })
            self.tools.clear()
            self.gw.sync_host_ports()
            script = self.tools.script()
            self.assertIn(
                "add element inet hatarvedelem host_service_tcp "
                "{ 22, 25566 }",
                script,
            )
            self.assertIn(
                "add element inet hatarvedelem host_service_udp "
                "{ 25566 }",
                script,
            )
            self.assertNotIn(
                "add element inet hatarvedelem host_service_tcp { 80 }",
                script,
            )
        finally:
            for rule_id in ("mix-sync-col", "mix-sync-host", "mix-sync-fwd"):
                try:
                    self.rules.delete(rule_id)
                except gateway.RuleStoreError:
                    pass

    def test_collection_update_and_delete_revoke_its_sessions(self) -> None:
        cookie = self.admin_cookie()
        source = "127.0.0.5"

        def admin_post(payload: dict):
            return self.post(
                "/api/admin/rules", payload, cookie=cookie, source=source
            )

        def cleanup() -> None:
            self.gw.sessions.revoke_user("colrev")
            self.gw.users.remove("colrev")
            for rule_id in ("sess-col", "sess-web", "sess-dns"):
                try:
                    self.gw.rules.delete(rule_id)
                except gateway.RuleStoreError:
                    pass

        self.addCleanup(cleanup)
        for payload in (
            {"action": "create", "id": "sess-web", "label": "Web",
             "tcp": [80], "default_ttl": 60, "max_ttl": 600},
            {"action": "create", "id": "sess-dns", "label": "DNS",
             "udp": [53], "default_ttl": 60, "max_ttl": 600},
            {"action": "create", "id": "sess-col", "label": "Combo",
             "collection": True, "members": ["sess-web", "sess-dns"],
             "default_ttl": 60, "max_ttl": 600},
        ):
            status, _, body = admin_post(payload)
            self.assertEqual(status, 200, body)
        self.users.add(
            "colrev", "colrev-jelszo-1", rules=("sess-col",)
        )

        def authorize() -> None:
            alice_cookie, _ = self.login(
                "colrev", "colrev-jelszo-1", source="127.0.0.9"
            )
            status, _, body = self.post(
                "/api/access", {"rule": "sess-col", "ttl": 120},
                cookie=alice_cookie, source="127.0.0.9",
            )
            self.assertEqual(status, 200, body)
            self.assertTrue(any(
                row["user"] == "colrev" and row["authorized"]
                and row["rule"] == "sess-col"
                for row in self.gw.sessions.active_sessions()
            ))

        authorize()
        status, _, body = admin_post({
            "action": "update", "id": "sess-col", "label": "Combo updated",
            "collection": True, "members": ["sess-web", "sess-dns"],
            "default_ttl": 60, "max_ttl": 600,
        })
        self.assertEqual(status, 200, body)
        self.assertFalse(any(
            row["user"] == "colrev" and row["authorized"]
            and row["rule"] == "sess-col"
            for row in self.gw.sessions.active_sessions()
        ))

        authorize()
        status, _, body = admin_post({
            "action": "delete", "id": "sess-col",
        })
        self.assertEqual(status, 200, body)
        self.assertFalse(any(
            row["user"] == "colrev" and row["authorized"]
            and row["rule"] == "sess-col"
            for row in self.gw.sessions.active_sessions()
        ))

    def test_update_revokes_collection_created_at_commit_point(self) -> None:
        """A commit pontján létrejövő függő gyűjtő se maradjon engedélyezve.

        A régi szerver a függőlistát a módosítás előtt, külön zárral
        olvasta. A hook a snapshot után hozza létre a gyűjtőt és engedélyezi
        a munkamenetét, utánozva a versenyhelyzetet; a javított kód egy
        záron belül látja a commit pontján létező gyűjtőt.
        """
        cookie = self.admin_cookie()
        source = "127.0.0.5"
        store = self.gw.rules

        def admin_post(payload: dict):
            return self.post(
                "/api/admin/rules", payload, cookie=cookie, source=source
            )

        fired: list[bool] = []
        authorized_before: list[bool] = []
        tokens: dict[str, str] = {}

        def fire() -> None:
            if fired:
                return
            fired.append(True)
            store.create("late-col", {
                "label": "Late", "collection": True,
                "members": ["late-web", "late-dns"],
                "default_ttl": 60, "max_ttl": 600,
            })
            record = self.gw.users.record("lateuser")
            rule = store.resolve_for(
                record, self.gw.groups.groups_for("lateuser"), "late-col"
            )
            self.gw.sessions.authorize(
                tokens["value"], "127.0.0.7", rule, 60
            )
            authorized_before.append(True)

        def cleanup() -> None:
            store.__dict__.pop("collections_containing", None)
            store.__dict__.pop("update_with_dependents", None)
            self.gw.sessions.revoke_user("lateuser")
            self.gw.users.remove("lateuser")
            for rule_id in ("late-col", "late-web", "late-dns"):
                try:
                    store.delete(rule_id)
                except gateway.RuleStoreError:
                    pass

        self.addCleanup(cleanup)
        for payload in (
            {"action": "create", "id": "late-web", "label": "Web",
             "tcp": [80, 443], "default_ttl": 60, "max_ttl": 600},
            {"action": "create", "id": "late-dns", "label": "DNS",
             "udp": [53], "default_ttl": 60, "max_ttl": 600},
        ):
            status, _, body = admin_post(payload)
            self.assertEqual(status, 200, body)
        self.users.add(
            "lateuser", "lateuser-jelszo-1", rules=("late-col",)
        )
        late_cookie, _ = self.login(
            "lateuser", "lateuser-jelszo-1", source="127.0.0.7"
        )
        tokens["value"] = late_cookie.split("=", 1)[1]

        original_snapshot = store.collections_containing
        original_atomic = getattr(store, "update_with_dependents", None)

        def hooked_snapshot(rule_id: str) -> list[str]:
            # A régi kód itt már elkészítette a (hiányos) pillanatképet.
            result = original_snapshot(rule_id)
            if rule_id == "late-web":
                fire()
            return result

        def hooked_atomic(rule_id: str, data: dict):
            # Az új kód a zár megszerzése előtt hívja; a létrehozott
            # gyűjtő így már a commit pontján létezik.
            if rule_id == "late-web":
                fire()
            return original_atomic(rule_id, data)

        store.collections_containing = hooked_snapshot
        if original_atomic is not None:
            store.update_with_dependents = hooked_atomic
        try:
            status, _, body = admin_post({
                "action": "update", "id": "late-web", "label": "Web",
                "tcp": [8080], "default_ttl": 60, "max_ttl": 600,
            })
        finally:
            store.__dict__.pop("collections_containing", None)
            if original_atomic is not None:
                store.__dict__.pop("update_with_dependents", None)
        self.assertEqual(status, 200, body)
        self.assertTrue(fired, "a versenyző gyűjtő nem jött létre")
        self.assertTrue(authorized_before)
        self.assertFalse(any(
            row["user"] == "lateuser" and row["authorized"]
            and row["rule"] == "late-col"
            for row in self.gw.sessions.active_sessions()
        ), "a közben létrehozott gyűjtő munkamenete a régi portokkal élt")

    def test_duplicate_action_and_delete_guard(self) -> None:
        cookie = self.admin_cookie()
        source = "127.0.0.5"

        def admin_post(payload: dict):
            return self.post(
                "/api/admin/rules", payload, cookie=cookie, source=source
            )

        def cleanup() -> None:
            for rule_id in (
                "dup-collection-copy", "dup-collection",
                "dup-web-copy", "dup-web", "dup-dns",
            ):
                self.post(
                    "/api/admin/rules",
                    {"action": "delete", "id": rule_id},
                    cookie=cookie, source=source,
                )

        self.addCleanup(cleanup)
        for payload in (
            {"action": "create", "id": "dup-web", "label": "Web",
             "tcp": [80, 443], "default_ttl": 60, "max_ttl": 600},
            {"action": "create", "id": "dup-dns", "label": "DNS",
             "udp": [53], "default_ttl": 60, "max_ttl": 600},
            {"action": "create", "id": "dup-collection", "label": "Combo",
             "collection": True, "members": ["dup-web", "dup-dns"],
             "default_ttl": 60, "max_ttl": 600},
        ):
            status, _, body = admin_post(payload)
            self.assertEqual(status, 200, body)

        status, _, body = admin_post({
            "action": "duplicate", "id": "dup-web", "label": "Web — másolat",
        })
        self.assertEqual(status, 200, body)
        result = json.loads(body)
        self.assertEqual(result["message"], "Szabály duplikálva.")
        copy = next(rule for rule in result["rules"] if rule["id"] == "dup-web-copy")
        self.assertEqual(copy["label"], "Web — másolat")
        self.assertEqual(copy["tcp"], [80, 443])
        self.assertFalse(copy["collection"])

        status, _, body = admin_post({
            "action": "duplicate", "id": "dup-collection",
        })
        self.assertEqual(status, 200, body)
        state = json.loads(body)
        collection_copy = next(
            rule for rule in state["rules"]
            if rule["id"] == "dup-collection-copy"
        )
        self.assertTrue(collection_copy["collection"])
        self.assertEqual(collection_copy["members"], ["dup-web", "dup-dns"])
        self.assertEqual(collection_copy["tcp"], [80, 443])
        self.assertEqual(collection_copy["udp"], [53])

        status, _, body = admin_post({
            "action": "delete", "id": "dup-web",
        })
        self.assertEqual(status, 400, body)
        error = json.loads(body)["error"]
        self.assertIn("dup-collection", error)
        self.assertIn("dup-collection-copy", error)
        self.assertIn("gyűjtőszabály", error)

        # A gyűjtő (és másolata) törölhető; a tagok megmaradnak.
        status, _, body = admin_post({
            "action": "delete", "id": "dup-collection-copy",
        })
        self.assertEqual(status, 200, body)
        self.assertIn(
            "dup-web", [rule["id"] for rule in json.loads(body)["rules"]]
        )
        status, _, body = admin_post({
            "action": "delete", "id": "dup-collection",
        })
        self.assertEqual(status, 200, body)
        status, _, body = admin_post({
            "action": "delete", "id": "dup-web",
        })
        self.assertEqual(status, 200, body)
        self.assertNotIn(
            "dup-web", [rule["id"] for rule in json.loads(body)["rules"]]
        )

    def test_last_admin_cannot_be_removed(self) -> None:
        cookie = self.admin_cookie()
        status, _, body = self.post(
            "/api/admin/users", {"action": "delete", "name": "root"},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 400, body)
        self.assertIn("utolsó admin", json.loads(body)["error"])

    def test_admin_drop_log_filters(self) -> None:
        cookie = self.admin_cookie()
        now = time.time()
        rows = [
            {"ts": now - 30, "src": "10.0.0.1", "dst": "203.0.113.9",
             "proto": "tcp", "sport": 41000, "dport": 443,
             "reason": "no-grant", "if_in": "eth1"},
            {"ts": now - 20, "src": "10.0.0.2", "dst": "203.0.113.9",
             "proto": "udp", "sport": 5353, "dport": 53,
             "reason": "block"},
            {"ts": now - 10, "src": "10.0.0.1", "dst": "198.51.100.7",
             "proto": "tcp", "sport": 41001, "dport": 8443,
             "reason": "block"},
        ]
        for row in rows:
            self.drops.store.write(row)

        status, _, body = self.get(
            "/api/admin/drops?src=10.0.0.1&proto=tcp&port=443&reason=no-grant",
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["drops"][0]["reason"], "no-grant")
        self.assertEqual(data["drops"][0]["dport"], 443)
        self.assertFalse(data["status"]["running"])

        status, _, body = self.get(
            "/api/admin/drops?group=drop", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertEqual(data["count"], 3)
        self.assertTrue(all(row["group"] == "drop" for row in data["drops"]))

        status, _, body = self.get(
            "/api/admin/drops?port=99999", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 400, body)

        status, _, body = self.get(
            "/api/admin/drops?q=198.51.100", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["count"], 1)

        status, _, body = self.get(
            "/api/admin/drops", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        times = [row["ts"] for row in json.loads(body)["drops"]]
        self.assertEqual(times, sorted(times, reverse=True))

    def test_non_admin_cannot_read_drop_log_or_settings(self) -> None:
        cookie, _ = self.login("alice", "alice-jelszo-1")
        for path in ("/api/admin/drops", "/api/admin/settings"):
            status, _, body = self.get(path, cookie=cookie)
            self.assertEqual(status, 403, body)

    def test_admin_settings_crud(self) -> None:
        cookie = self.admin_cookie()

        status, _, body = self.get(
            "/api/admin/settings", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertNotIn("host_ssh", data["settings"])
        self.assertEqual(data["settings"]["preauth"], [])
        self.assertIn("drop_log", data)

        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "create", "kind": "preauth",
             "entry": {"label": "Kiosk web", "dst": "192.168.50.10",
                       "proto": "tcp", "ports": [80, 443]}},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        entry = data["settings"]["preauth"][0]
        self.assertEqual(entry["label"], "Kiosk web")
        self.assertEqual(entry["ports"], [80, 443])
        self.assertTrue(entry["enabled"])
        entry_id = entry["id"]
        script = "\n".join(self.tools.script())
        self.assertIn("flush chain inet hatarvedelem preauth", script)
        self.assertIn("192.168.50.10", script)
        self.assertIn("preauth_nat", script)

        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "update", "kind": "preauth", "id": entry_id,
             "entry": {"label": "Kiosk web 2", "dst": "192.168.50.10",
                       "proto": "tcp", "ports": [8080], "enabled": False}},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        entry = json.loads(body)["settings"]["preauth"][0]
        self.assertEqual(entry["label"], "Kiosk web 2")
        self.assertEqual(entry["ports"], [8080])
        self.assertFalse(entry["enabled"])

        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "toggle", "kind": "preauth", "id": entry_id,
             "entry": {"enabled": True}},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(
            json.loads(body)["settings"]["preauth"][0]["enabled"]
        )

        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "delete", "kind": "preauth", "id": entry_id},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["settings"]["preauth"], [])

        # A mentett állapot újratöltve is megmarad.
        self.gw.settings.load()
        self.assertEqual(self.gw.settings.snapshot()["preauth"], [])

    def test_admin_host_ssh_settings_action_is_rejected(self) -> None:
        cookie = self.admin_cookie()
        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "host_ssh", "host_ssh": "off"},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 400, body)
        self.assertFalse(json.loads(body)["ok"])
        self.assertNotIn("host_ssh", self.gw.settings.snapshot())

    def test_admin_settings_invalid_is_400(self) -> None:
        cookie = self.admin_cookie()
        cases = [
            {"action": "create", "kind": "preauth",
             "entry": {"label": "Rossz proto", "dst": "192.168.50.10",
                       "proto": "icmp", "ports": [80]}},
            {"action": "create", "kind": "block",
             "entry": {"label": "80 cél nélkül", "proto": "tcp",
                       "ports": [80]}},
            {"action": "create", "kind": "block",
             "entry": {"label": "Rossz port", "dst": "192.168.50.10",
                       "proto": "tcp", "ports": [70000]}},
            {"action": "ismeretlen", "kind": "preauth"},
        ]
        for payload in cases:
            status, _, body = self.post(
                "/api/admin/settings", payload,
                cookie=cookie, source="127.0.0.5",
            )
            self.assertEqual(status, 400, (payload, body))
        self.assertEqual(self.gw.settings.snapshot()["preauth"], [])

    def test_admin_settings_apply_failure_is_503_and_unchanged(self) -> None:
        cookie = self.admin_cookie()
        self.tools.make_fail("nft hiba")
        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "create", "kind": "block",
             "entry": {"label": "Blokk", "dst": "198.51.100.0/24",
                       "proto": "tcp", "ports": [443]}},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 503, body)
        self.assertEqual(self.gw.settings.snapshot()["block"], [])
        self.tools.clear_fail()

    def test_settings_ui_block_trigger_removed_but_block_api_persists(
        self,
    ) -> None:
        status, headers, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        page = body.decode("utf-8")
        # A beállítások oldal csak a pre-auth szakaszt rendereli; a blokk
        # felület eltűnt, és a Host SSH szakasz már nem létezik.
        self.assertNotIn("renderSettingSection('block'", page)
        self.assertIn("renderSettingSection('preauth'", page)
        self.assertNotIn("Host SSH", page)
        self.assertNotIn("sshSection", page)
        self.assertNotIn("host_ssh", page)
        self.assertIn(
            "A pre-auth szabályok megkerülik a portált: a megadott cél és port "
            "a bejelentkezés előtt is elérhető minden LAN-kliensnek. Csak olyan "
            "szolgáltatást adj hozzá, amelynek nyilvánosnak kell lennie.",
            page,
        )
        self.assertNotIn("mindig blokkolt célok", page)
        self.assertNotIn("pre-auth és blokk listák üresek", page)

        # A háttér és az API változatlanul kezeli a blokk szabályokat.
        cookie = self.admin_cookie()
        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "create", "kind": "block",
             "entry": {"label": "Blokk", "dst": "198.51.100.0/24",
                       "proto": "tcp", "ports": [443]}},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        block = json.loads(body)["settings"]["block"]
        self.assertEqual(block[0]["dst"], "198.51.100.0/24")
        self.assertEqual(block[0]["ports"], [443])
        self.assertTrue(block[0]["enabled"])
        entry_id = block[0]["id"]
        self.assertTrue(entry_id)

        self.gw.settings.load()
        persisted = self.gw.settings.snapshot()["block"]
        self.assertEqual(persisted[0]["id"], entry_id)
        self.assertEqual(persisted[0]["dst"], "198.51.100.0/24")


    # -- fail2ban ----------------------------------------------------------
    def fail2ban_state(self, cookie: str) -> dict:
        status, _, body = self.get(
            "/api/admin/fail2ban", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        return data["fail2ban"]

    def test_admin_fail2ban_proxy_unban_is_separate(self) -> None:
        cookie = self.admin_cookie()
        ip = "203.0.113.45"
        for _ in range(20):
            self.gw.fail2ban.record_proxy_unauthorized(ip)
        self.gw.fail2ban.ban(ip, 600)
        sources = sorted(
            row["source"] for row in self.fail2ban_state(cookie)["bans"]
        )
        self.assertEqual(sources, ["manual", "proxy"])
        request = {"action": "unban", "ip": ip, "proxy": True}
        status, _, body = self.post(
            "/api/admin/fail2ban", request, cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        self.assertIsNone(self.gw.fail2ban.proxy_banned(ip))
        self.assertIsNotNone(self.gw.fail2ban.banned(ip))
        status, _, _ = self.post(
            "/api/admin/fail2ban", request, cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 404)

    def test_admin_fail2ban_config_and_rejections(self) -> None:
        alice, _ = self.login("alice", "alice-jelszo-1", source="127.0.0.6")
        status, _, _ = self.get(
            "/api/admin/fail2ban", cookie=alice, source="127.0.0.6"
        )
        self.assertEqual(status, 403)
        status, _, _ = self.post(
            "/api/admin/fail2ban", {"action": "config", "enabled": True},
            cookie=alice, source="127.0.0.6",
        )
        self.assertEqual(status, 403)

        cookie = self.admin_cookie()
        snapshot = self.fail2ban_state(cookie)
        self.assertTrue(snapshot["enabled"])
        self.assertEqual(snapshot["max_attempts"], 3)
        self.assertEqual(snapshot["ban_seconds"], 600)

        status, _, body = self.post(
            "/api/admin/fail2ban",
            {"action": "config", "enabled": True, "max_attempts": 4,
             "window_seconds": 120, "ban_seconds": 900},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertEqual(data["message"], "A fail2ban beállításai mentve.")
        self.assertEqual(data["fail2ban"]["max_attempts"], 4)
        self.assertEqual(data["fail2ban"]["window_seconds"], 120)
        self.assertEqual(data["fail2ban"]["ban_seconds"], 900)

        # Nem alapértelmezett küszöbök, hogy a kikapcsolás utáni
        # megőrzés ellenőrzése ne legyen tautologikus.
        status, _, body = self.post(
            "/api/admin/fail2ban",
            {"action": "config", "drop_max": 7, "drop_ports": 9},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        custom = json.loads(body)["fail2ban"]
        self.assertEqual(custom["drop_max"], 7)
        self.assertEqual(custom["drop_ports"], 9)

        status, _, body = self.post(
            "/api/admin/fail2ban",
            {"action": "config",
             "drop_count_enabled": False, "drop_ports_enabled": False},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)["fail2ban"]
        self.assertEqual(data["drop_max"], 7)
        self.assertEqual(data["drop_ports"], 9)
        self.assertFalse(data["drop_count_enabled"])
        self.assertFalse(data["drop_ports_enabled"])
        self.assertFalse(data["drop_count_active"])
        self.assertFalse(data["drop_ports_active"])
        self.assertFalse(data["drop_enabled"])
        self.assertEqual(data["limits"]["min_drop_max"], 1)
        self.assertEqual(data["limits"]["min_drop_ports"], 1)

        for payload in (
            {"action": "config", "max_attempts": 0},
            {"action": "config", "window_seconds": 5},
            {"action": "config", "ban_seconds": 5},
            {"action": "config", "enabled": "igen"},
            {"action": "config", "drop_count_enabled": "igen"},
            {"action": "config", "drop_ports_enabled": 1},
            {"action": "config", "drop_max": 0},
            {"action": "config", "drop_max": -1},
            {"action": "config", "drop_ports": 0},
            {"action": "config", "drop_ports": -1},
            {"action": "config", "drop_max": 10001},
            {"action": "config", "drop_ports": 4097},
            {"action": "ban", "ip": "127.0.0.1"},
            {"action": "ban", "ip": "127.0.0.5"},
            {"action": "ban", "ip": "10.0.0.0/8"},
            {"action": "ismeretlen"},
        ):
            status, _, body = self.post(
                "/api/admin/fail2ban", payload,
                cookie=cookie, source="127.0.0.5",
            )
            self.assertEqual(status, 400, (payload, body))
        status, _, body = self.post(
            "/api/admin/fail2ban", {"action": "unban", "ip": "192.0.2.99"},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 404, body)

    def test_admin_manual_ban_and_unban(self) -> None:
        cookie = self.admin_cookie()
        status, _, body = self.post(
            "/api/admin/fail2ban",
            {"action": "ban", "ip": "192.0.2.50", "seconds": 600},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertEqual(data["message"], "192.0.2.50 letiltva.")
        bans = data["fail2ban"]["bans"]
        self.assertEqual(len(bans), 1)
        self.assertEqual(bans[0]["ip"], "192.0.2.50")
        self.assertTrue(bans[0]["manual"])
        script = "\n".join(self.tools.script())
        self.assertIn(
            "add element inet hatarvedelem banned_v4 "
            "{ 192.0.2.50 timeout 600s }", script
        )
        events = self.drops.store.read(reason="fail2ban")
        self.assertTrue(events)
        self.assertEqual(events[0]["event"], "ban")
        self.assertEqual(events[0]["src"], "192.0.2.50")
        self.assertTrue(events[0]["manual"])

        # A felület 5 másodpercenként GET-tel frissít; a friss listaérésnek is
        # tartalmaznia kell a kézi tiltást, nem csak a POST válaszának.
        status, _, body = self.get(
            "/api/admin/fail2ban", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        listed = json.loads(body)["fail2ban"]["bans"]
        self.assertEqual([row["ip"] for row in listed], ["192.0.2.50"])
        self.assertTrue(listed[0]["manual"])
        self.assertEqual(listed[0]["source"], "manual")

        state = self.state(cookie)
        self.assertEqual(
            [row["ip"] for row in state["fail2ban"]["bans"]],
            ["192.0.2.50"],
        )

        # Újraindítás után a tiltás a fail2ban.json-ból töltődik vissza.
        reloaded = fail2ban_mod.Fail2ban(
            self.fw,
            path=os.path.join(self.tmp.name, "fail2ban.json"),
            logger=lambda *_: None,
        )
        restored = reloaded.banned("192.0.2.50")
        self.assertIsNotNone(restored)
        self.assertTrue(restored["manual"])

        status, _, body = self.post(
            "/api/admin/fail2ban",
            {"action": "ban", "ip": "192.0.2.51", "seconds": 600},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)

        status, _, body = self.post(
            "/api/admin/fail2ban", {"action": "unban", "ip": "192.0.2.50"},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            json.loads(body)["message"], "192.0.2.50 tiltása feloldva."
        )
        self.assertIn(
            "nft delete element inet hatarvedelem banned_v4 { 192.0.2.50 }",
            self.tools.deletes(),
        )

        status, _, body = self.post(
            "/api/admin/fail2ban", {"action": "unban_all"},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertEqual(data["message"], "1 tiltás feloldva.")
        self.assertEqual(data["fail2ban"]["banned_count"], 0)

    def test_early_403_drains_body_on_keepalive(self) -> None:
        """A korai 403 után a keep-alive kapcsolat ne mérgeződjön el."""
        payload = json.dumps(
            {"action": "ban", "ip": "192.0.2.77", "seconds": 600}
        )

        # Nincs admin munkamenet: a guard a body kiolvasása előtt 403-at ad.
        conn = self.conn(source="127.0.0.5")
        try:
            conn.request(
                "POST", "/api/admin/fail2ban", body=payload,
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            body = resp.read()
            self.assertEqual(resp.status, 403, body)
            data = json.loads(body)
            self.assertEqual(data.get("code"), "admin_session")

            conn.request("GET", "/api/status")
            follow = conn.getresponse()
            follow_body = follow.read()
            self.assertEqual(follow.status, 200, follow_body)
            self.assertTrue(json.loads(follow_body).get("ok"))
        finally:
            conn.close()

        # Érvénytelen Origin: a guard átenged, de az origin-ellenőrzés a body
        # kiolvasása előtt 403-at ad.
        cookie = self.admin_cookie()
        conn = self.conn(source="127.0.0.5")
        try:
            conn.request(
                "POST", "/api/admin/fail2ban", body=payload,
                headers={
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "Origin": "http://evil.example",
                },
            )
            resp = conn.getresponse()
            body = resp.read()
            self.assertEqual(resp.status, 403, body)
            data = json.loads(body)
            self.assertEqual(data.get("error"), "érvénytelen kérés-eredet")
            self.assertNotIn("code", data)

            conn.request(
                "GET", "/api/admin/fail2ban", headers={"Cookie": cookie}
            )
            follow = conn.getresponse()
            follow_body = follow.read()
            self.assertEqual(follow.status, 200, follow_body)
            self.assertTrue(json.loads(follow_body).get("ok"))
        finally:
            conn.close()

    def test_fail2ban_auto_ban_blocks_login_and_writes_drop_event(self) -> None:
        source = "127.0.0.9"
        for _ in range(2):
            _, _, challenge_body = self.get("/api/challenge", source=source)
            status, _, body = self.post(
                "/api/login",
                {"user": "alice", "pass": "rossz-jelszo",
                 "captcha": solve(json.loads(challenge_body))},
                source=source,
            )
            self.assertEqual(status, 403, body)
            self.assertFalse(json.loads(body).get("banned", False))

        _, _, challenge_body = self.get("/api/challenge", source=source)
        status, _, body = self.post(
            "/api/login",
            {"user": "alice", "pass": "rossz-jelszo",
             "captcha": solve(json.loads(challenge_body))},
            source=source,
        )
        self.assertEqual(status, 403, body)
        data = json.loads(body)
        self.assertTrue(data.get("banned"))
        self.assertTrue(595 <= data["remaining"] <= 600)
        self.assertIn("Túl sok sikertelen belépés", data["error"])

        script = "\n".join(self.tools.script())
        self.assertIn(
            "add element inet hatarvedelem banned_v4 "
            "{ 127.0.0.9 timeout 600s }", script
        )
        events = self.drops.store.read(reason="fail2ban")
        self.assertTrue(events)
        self.assertEqual(events[0]["event"], "ban")
        self.assertEqual(events[0]["src"], source)
        self.assertEqual(events[0]["attempts"], 3)
        self.assertEqual(events[0]["user"], "alice")
        self.assertFalse(events[0]["manual"])

        # A belépőoldal a tiltott állapotot 403-as, közös tiltásválaszból
        # tudja meg; munkamenet-adat nem szivárog ki.
        status, status_headers, body = self.get(
            "/api/status", source=source
        )
        self.assertEqual(status, 403, body)
        self.assertIn("Retry-After", status_headers)
        status_data = json.loads(body)
        self.assertFalse(status_data["authenticated"])
        self.assertTrue(status_data["banned"])
        self.assertTrue(595 <= status_data["remaining"] <= 600)
        self.assertGreater(status_data["ban_until"], 0)
        self.assertEqual(status_data["ban_source"], "login")
        self.assertEqual(status_data["ban_attempts"], 3)
        self.assertNotIn("user", status_data)

        # A tiltott IP a helyes jelszóval is elutasításra kerül.
        _, _, challenge_body = self.get("/api/challenge", source=source)
        status, headers, body = self.post(
            "/api/login",
            {"user": "alice", "pass": "alice-jelszo-1",
             "captcha": solve(json.loads(challenge_body))},
            source=source,
        )
        self.assertEqual(status, 403, body)
        self.assertTrue(json.loads(body).get("banned"))
        self.assertIn("Retry-After", headers)

        cookie = self.admin_cookie()
        snapshot = self.fail2ban_state(cookie)
        self.assertEqual(snapshot["banned_count"], 1)
        self.assertEqual(snapshot["bans"][0]["ip"], source)
        self.assertEqual(snapshot["bans"][0]["attempts"], 3)

        status, _, body = self.post(
            "/api/admin/fail2ban", {"action": "unban", "ip": source},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)

        status, _, body = self.get("/api/status", source=source)
        self.assertEqual(status, 200, body)
        self.assertNotIn("banned", json.loads(body))

        _, _, challenge_body = self.get("/api/challenge", source=source)
        status, _, body = self.post(
            "/api/login",
            {"user": "alice", "pass": "alice-jelszo-1",
             "captcha": solve(json.loads(challenge_body))},
            source=source,
        )
        self.assertEqual(status, 200, body)

    def test_drop_ban_is_reflected_in_status_and_login(self) -> None:
        source = "127.0.0.10"
        self.gw.fail2ban.configure({
            "drop_max": 2, "drop_ports": 10, "drop_window_seconds": 60,
        })
        self.assertIsNone(self.gw.fail2ban.record_drop(
            source, proto="tcp", dport=22, reason="input-wan"
        ))
        view = self.gw.fail2ban.record_drop(
            source, proto="tcp", dport=23, reason="input-wan"
        )
        self.assertIsNotNone(view)
        self.assertEqual(view["source"], "drop")

        status, status_headers, body = self.get(
            "/api/status", source=source
        )
        self.assertEqual(status, 403, body)
        self.assertIn("Retry-After", status_headers)
        data = json.loads(body)
        self.assertFalse(data["authenticated"])
        self.assertTrue(data["banned"])
        self.assertEqual(data["ban_source"], "drop")
        self.assertEqual(data["ban_detail"], "input-wan")
        self.assertEqual(data["ban_attempts"], 2)

        _, _, challenge_body = self.get("/api/challenge", source=source)
        status, _, body = self.post(
            "/api/login",
            {"user": "alice", "pass": "alice-jelszo-1",
             "captcha": solve(json.loads(challenge_body))},
            source=source,
        )
        self.assertEqual(status, 403, body)
        data = json.loads(body)
        self.assertTrue(data["banned"])
        self.assertEqual(data["ban_source"], "drop")
        self.assertIn("gyanús hálózati forgalmat", data["error"])

        cookie = self.admin_cookie()
        snapshot = self.fail2ban_state(cookie)
        self.assertEqual(snapshot["bans"][0]["source"], "drop")
        self.assertEqual(snapshot["bans"][0]["detail"], "input-wan")
        self.assertEqual(snapshot["drop_pending"], [])
        self.assertIn("drop_enabled", snapshot)
        self.assertIn("drop_max", snapshot)
        self.assertIn("drop_ports", snapshot)
        self.assertIn("drop_window_seconds", snapshot)
        self.assertEqual(snapshot["limits"]["max_drop_max"], 10000)

    # -- kétfaktoros belépés ---------------------------------------------------

    def test_admin_creates_user_with_totp_required(self) -> None:
        admin = self.admin_cookie()
        name = "totpcreated"
        password = "totpcreated-jelszo-1"
        self.addCleanup(self.drop_totp_user, name)
        status, _, body = self.create_user(
            admin, name, password, totp_required=True
        )
        self.assertEqual(status, 200, body)
        user = next(
            item for item in json.loads(body)["users"] if item["name"] == name
        )
        self.assertTrue(user["totp_required"])
        self.assertFalse(user["totp_enrolled"])

        status, headers, body = self.password_login(
            name, password, source="127.0.0.2"
        )
        self.assertEqual(status, 200, body)
        offer = json.loads(body)
        self.assertTrue(offer["totp_required"])
        self.assertTrue(offer["totp_enroll_required"])
        self.assertTrue(offer["ticket"])
        self.assertNotIn("Set-Cookie", headers)

    def test_admin_totp_required_toggle_keeps_enrolled_secret(self) -> None:
        admin = self.admin_cookie()
        name = "totptoggle"
        password = "totptoggle-jelszo-1"
        source = "127.0.0.2"
        self.addCleanup(self.drop_totp_user, name)
        status, _, body = self.create_user(
            admin, name, password, totp_required=True
        )
        self.assertEqual(status, 200, body)
        secret, _, _, _ = self.enroll_totp(name, password, source)
        self.assertTrue(self.users.record(name).totp_enrolled)

        status, _, body = self.post(
            "/api/admin/users",
            {"action": "update", "name": name, "totp_required": False},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        record = self.users.record(name)
        self.assertEqual(record.totp_secret, secret)
        self.assertFalse(record.totp_required)
        status, headers, body = self.password_login(name, password, source)
        self.assertEqual(status, 200, body)
        self.assertNotIn("totp_required", json.loads(body))
        self.assertIn("Set-Cookie", headers)

        status, _, body = self.post(
            "/api/admin/users",
            {"action": "update", "name": name, "totp_required": True},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        record = self.users.record(name)
        self.assertEqual(record.totp_secret, secret)
        self.assertTrue(record.totp_required)
        status, headers, body = self.password_login(name, password, source)
        self.assertEqual(status, 200, body)
        offer = json.loads(body)
        self.assertEqual(offer["mode"], "verify")
        self.assertTrue(offer["ticket"])
        self.assertNotIn("Set-Cookie", headers)

    def test_admin_totp_reset_clears_secret_and_invalidates(self) -> None:
        admin = self.admin_cookie()
        name = "totpreset"
        password = "totpreset-jelszo-1"
        source = "127.0.0.2"
        self.addCleanup(self.drop_totp_user, name)
        status, _, body = self.create_user(
            admin, name, password, totp_required=True
        )
        self.assertEqual(status, 200, body)
        secret, _, enroll_headers, enrolled = self.enroll_totp(
            name, password, source
        )
        user_cookie = enroll_headers["Set-Cookie"].split(";", 1)[0]
        hashes = list(self.users.record(name).totp_recovery)
        self.assertEqual(len(hashes), 10)

        # Nyitott verify-jegy: a resetnek ezt is érvénytelenítenie kell.
        status, _, body = self.password_login(name, password, source)
        self.assertEqual(status, 200, body)
        ticket = json.loads(body)["ticket"]

        started = time.time()
        status, _, body = self.post(
            "/api/admin/users",
            {"action": "totp_reset", "name": name},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        state = json.loads(body)
        self.assertIn("message", state)
        self.assertIn(name, state["message"])
        record = self.users.record(name)
        self.assertEqual(record.totp_secret, "")
        self.assertEqual(record.totp_last_step, -1)
        self.assertEqual(record.totp_recovery, ())
        self.assertTrue(record.totp_required)

        status, _, body = self.get(
            "/api/status", cookie=user_cookie, source=source
        )
        self.assertFalse(json.loads(body)["authenticated"])

        rows = audit_since(self.audit, started)
        resets = [
            row for row in rows if row.get("event") == "admin_totp_reset"
        ]
        self.assertEqual(len(resets), 1)
        self.assertEqual(resets[0]["target"], name)
        dump = json.dumps(rows, ensure_ascii=False)
        self.assertNotIn(secret, dump)
        for digest in hashes:
            self.assertNotIn(digest, dump)
        self.assertNotIn("totp_secret", dump)
        self.assertNotIn("totp_recovery", dump)

        status, headers, body = self.post(
            "/api/login/totp",
            {"ticket": ticket, "code": gateway.totp_code(secret)},
            source=source,
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(json.loads(body)["code"], "ticket_invalid")
        self.assertNotIn("Set-Cookie", headers)

        status, _, body = self.post(
            "/api/admin/users",
            {"action": "totp_reset", "name": "nincs-ilyen-user"},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 400, body)
        self.assertFalse(json.loads(body)["ok"])

    def test_admin_state_hides_totp_internals(self) -> None:
        admin = self.admin_cookie()
        name = "totpstate"
        password = "totpstate-jelszo-1"
        self.addCleanup(self.drop_totp_user, name)
        status, _, body = self.create_user(
            admin, name, password, totp_required=True
        )
        self.assertEqual(status, 200, body)
        secret, _, _, enrolled = self.enroll_totp(
            name, password, "127.0.0.2"
        )
        codes = enrolled["recovery_codes"]

        status, _, body = self.get(
            "/api/admin/state", cookie=admin, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        raw = body.decode("utf-8")
        for token in ("totp_secret", "totp_last_step", "totp_recovery", secret):
            self.assertNotIn(token, raw)
        for code in codes:
            self.assertNotIn(code, raw)
        state = json.loads(body)
        for user in state["users"]:
            self.assertEqual(
                {key for key in user if key.startswith("totp")},
                {"totp_required", "totp_enrolled"},
            )
        record = self.users.record(name)
        self.assertTrue(record.totp_secret)
        for digest in record.totp_recovery:
            self.assertNotIn(digest, raw)

    def test_admin_account_can_use_totp(self) -> None:
        self.addCleanup(self.restore_root_totp)
        self.users.reset_totp("root")
        self.users.set_totp_required("root", True)
        source = "127.0.0.5"

        # Az első jelszavas lépés még nem ad munkamenetet.
        status, headers, body = self.password_login(
            "root", "root-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        offer = json.loads(body)
        self.assertTrue(offer["totp_enroll_required"])
        self.assertTrue(offer["ticket"])
        self.assertNotIn("Set-Cookie", headers)
        secret = offer["secret"]
        status, headers, body = self.post(
            "/api/login/totp/enroll",
            {"ticket": offer["ticket"], "code": gateway.totp_code(secret)},
            source=source,
        )
        self.assertEqual(status, 200, body)
        self.assertIn("Set-Cookie", headers)
        self.assertEqual(len(json.loads(body)["recovery_codes"]), 10)

        # Beállítás után a jelszó csak jegyet ad, munkamenetet nem.
        status, headers, body = self.password_login(
            "root", "root-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        offer = json.loads(body)
        self.assertEqual(offer["mode"], "verify")
        self.assertTrue(offer["ticket"])
        self.assertNotIn("Set-Cookie", headers)

        status, headers, body = self.post(
            "/api/login/totp",
            {
                "ticket": offer["ticket"],
                "code": fresh_totp_code(
                    secret,
                    after_step=self.users.record("root").totp_last_step,
                ),
            },
            source=source,
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["admin"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, _, body = self.get(
            "/api/admin/state", cookie=cookie, source=source
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(json.loads(body)["ok"])

    # -- fiókkérések (pending) -------------------------------------------------

    def test_admin_registration_setting_toggle_without_nft(self) -> None:
        admin = self.admin_cookie()
        before = list(self.tools.lines())
        started = time.time()

        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "registration_enabled", "enabled": True},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertIs(data["settings"]["registration_enabled"], True)
        self.assertEqual(data["message"], "A fiókkérés beállítása mentve.")
        # A beállítás nem megy át az nftables-en.
        self.assertEqual(self.tools.lines(), before)

        reloaded = gateway.settings_store.SettingsStore(
            self.settings.path, logger=lambda *_: None
        )
        snapshot = reloaded.snapshot()
        self.assertIs(snapshot["registration_enabled"], True)
        self.assertNotIn("host_ssh", snapshot)
        self.assertEqual(snapshot["preauth"], [])
        self.assertEqual(snapshot["block"], [])

        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "registration_enabled", "enabled": False},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        self.assertIs(
            json.loads(body)["settings"]["registration_enabled"], False
        )
        reloaded = gateway.settings_store.SettingsStore(
            self.settings.path, logger=lambda *_: None
        )
        self.assertIs(reloaded.snapshot()["registration_enabled"], False)

        for value in ("yes", 1, None):
            with self.subTest(value=value):
                status, _, body = self.post(
                    "/api/admin/settings",
                    {"action": "registration_enabled", "enabled": value},
                    cookie=admin, source="127.0.0.5",
                )
                self.assertEqual(status, 400, body)
                self.assertIn("igaz/hamis", json.loads(body)["error"])
                self.assertIs(
                    self.settings.snapshot()["registration_enabled"], False
                )
        self.assertEqual(self.tools.lines(), before)

        rows = [
            row for row in audit_since(self.audit, started)
            if row.get("event") == "admin_settings_changed"
            and row.get("action") == "registration_enabled"
        ]
        self.assertEqual(len(rows), 2)
        self.assertEqual(
            {row.get("registration_enabled") for row in rows},
            {True, False},
        )
        for row in rows:
            self.assertEqual(row.get("user"), "root")
            self.assertEqual(row.get("target"), "registration_enabled")

    def test_public_status_only_exposes_registration_flag(self) -> None:
        status, _, body = self.get("/api/status")
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertIs(data["registration_enabled"], False)
        for hidden in ("preauth", "block", "host_ssh", "settings", "users",
                       "email"):
            self.assertNotIn(hidden, data)
            self.assertNotIn(hidden.encode(), body)

        self.settings.set_registration_enabled(True)
        status, _, body = self.get("/api/status")
        self.assertEqual(status, 200, body)
        self.assertTrue(json.loads(body)["registration_enabled"])
        for hidden in ("preauth", "block", "host_ssh", "settings", "users",
                       "email"):
            self.assertNotIn(hidden.encode(), body)

    def test_status_exposes_site_name_publicly(self) -> None:
        status, _, body = self.get("/api/status")
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertEqual(data["site_name"], "")
        self.assertNotIn("error", data)

        self.settings.set_site_name("Északi Torony")
        status, _, body = self.get("/api/status")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["site_name"], "Északi Torony")

        cookie, _ = self.login("alice", "alice-jelszo-1")
        status, _, body = self.get("/api/status", cookie=cookie)
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["site_name"], "Északi Torony")
        self.assertNotIn("error", data)

    def test_admin_site_name_setting_saves_without_nft(self) -> None:
        admin = self.admin_cookie()
        before = list(self.tools.lines())
        started = time.time()

        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "site_name", "name": "  Északi Torony  "},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["settings"]["site_name"], "Északi Torony")
        self.assertEqual(data["message"], "A tűzfal neve mentve.")
        # A név mentése nem megy át az nftables-en.
        self.assertEqual(self.tools.lines(), before)

        reloaded = gateway.settings_store.SettingsStore(
            self.settings.path, logger=lambda *_: None
        )
        self.assertEqual(reloaded.snapshot()["site_name"], "Északi Torony")

        status, _, body = self.get("/api/status")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["site_name"], "Északi Torony")

        rows = [
            row for row in audit_since(self.audit, started)
            if row.get("event") == "admin_settings_changed"
            and row.get("action") == "site_name"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("user"), "root")
        self.assertEqual(rows[0].get("target"), "site_name")
        self.assertEqual(rows[0].get("site_name"), "Északi Torony")

        for value in ("x" * 65, "a\x01b", 5, None):
            with self.subTest(value=value):
                status, _, body = self.post(
                    "/api/admin/settings",
                    {"action": "site_name", "name": value},
                    cookie=admin, source="127.0.0.5",
                )
                self.assertEqual(status, 400, body)
                self.assertFalse(json.loads(body)["ok"])
                self.assertEqual(
                    self.settings.snapshot()["site_name"], "Északi Torony"
                )
        self.assertEqual(self.tools.lines(), before)

        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "site_name", "name": ""},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["settings"]["site_name"], "")
        self.assertEqual(self.settings.snapshot()["site_name"], "")
        rows = [
            row for row in audit_since(self.audit, started)
            if row.get("event") == "admin_settings_changed"
            and row.get("action") == "site_name"
        ]
        self.assertEqual(len(rows), 2)
        self.assertIn("", [row.get("site_name") for row in rows])

    def test_admin_proxy_setting_saves_without_nft(self) -> None:
        self.addCleanup(self.settings.set_proxy, [], [])
        admin = self.admin_cookie()
        before = list(self.tools.lines())
        started = time.time()
        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "proxy", "proxy_domains": ["Z1.Example.com"],
             "proxy_routes": [{"name": "owui", "root": "z1.example.com",
                               "port": 3000, "enabled": True}]},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertEqual(data["settings"]["proxy_domains"], ["z1.example.com"])
        self.assertEqual(data["message"], "A proxy beállításai mentve.")
        self.assertEqual(self.tools.lines(), before)
        rows = [
            row for row in audit_since(self.audit, started)
            if row.get("event") == "admin_settings_changed"
            and row.get("action") == "proxy"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("proxy_routes"), "owui.z1.example.com:3000")
        self.assertEqual(rows[0].get("proxy_domains"), "z1.example.com")

        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "proxy", "proxy_domains": ["z1.example.com"],
             "proxy_routes": [{"name": "ssh", "root": "z1.example.com",
                               "port": 22}]},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 400, body)
        self.assertEqual(
            self.settings.snapshot()["proxy_routes"][0]["name"], "owui"
        )

        # Domain szabály csak létező bejegyzésre hivatkozhat, és amíg
        # hivatkozik, a bejegyzés nem törölhető.
        status, _, body = self.post(
            "/api/admin/rules",
            {"action": "create", "id": "dom-x", "label": "X",
             "domains": ["nincs.z1.example.com"]},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 400, body)
        self.assertIn("ismeretlen proxy-bejegyzés", json.loads(body)["error"])
        status, _, body = self.post(
            "/api/admin/rules",
            {"action": "create", "id": "dom-owui", "label": "OWUI",
             "domains": ["owui.z1.example.com"]},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        listed = next(
            rule for rule in json.loads(body)["rules"]
            if rule["id"] == "dom-owui"
        )
        self.assertEqual(listed["hosts"], ["owui.z1.example.com"])
        self.assertEqual(listed["ports_label"], "Domain: owui.z1.example.com")
        created = [
            row for row in audit_since(self.audit, started)
            if row.get("event") == "admin_rule_created"
        ]
        self.assertEqual(created[-1].get("domains"), "owui.z1.example.com")
        before = list(self.tools.lines())
        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "proxy", "proxy_domains": ["z1.example.com"],
             "proxy_routes": []},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 400, body)
        self.assertIn("domain szabály hivatkozik rá", json.loads(body)["error"])
        self.assertEqual(len(self.settings.snapshot()["proxy_routes"]), 1)
        status, _, body = self.post(
            "/api/admin/rules", {"action": "delete", "id": "dom-owui"},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "proxy", "proxy_domains": ["z1.example.com"],
             "proxy_routes": []},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)

    def test_totp_enrollment_issuer_uses_site_name(self) -> None:
        self.addCleanup(self.restore_root_totp)
        self.users.reset_totp("root")
        self.users.set_totp_required("root", True)
        source = "127.0.0.5"

        status, _, body = self.password_login(
            "root", "root-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        offer = json.loads(body)
        self.assertEqual(offer["issuer"], gateway.TOTP_ISSUER)
        expected_label = urllib.parse.quote(
            f"{gateway.TOTP_ISSUER}:root", safe=""
        )
        self.assertEqual(
            urllib.parse.urlparse(offer["otpauth_uri"]).path,
            "/" + expected_label,
        )

        self.settings.set_site_name("Északi Torony")
        status, _, body = self.password_login(
            "root", "root-jelszo-1", source
        )
        self.assertEqual(status, 200, body)
        offer = json.loads(body)
        self.assertTrue(offer["totp_enroll_required"])
        self.assertEqual(offer["issuer"], "Északi Torony")
        parsed = urllib.parse.urlparse(offer["otpauth_uri"])
        self.assertEqual(parsed.path, "/%C3%89szaki%20Torony%3Aroot")
        self.assertEqual(
            urllib.parse.parse_qs(parsed.query)["issuer"],
            ["Északi Torony"],
        )

    def test_admin_state_and_approve_pending_request(self) -> None:
        admin = self.admin_cookie()
        name = "pendingalice"
        password = "pending-jelszo-1"
        email = "pending@example.co"
        self.addCleanup(self.drop_totp_user, name)
        self.users.add(
            name, password, pending=True, email="  Pending@Example.CO "
        )
        record = self.users.record(name)
        self.assertEqual(record.email, email)
        self.assertFalse(record.enabled)
        self.assertTrue(record.rules_set)

        # Nyers pending admin: szerepköre admin és enabled, mégsem aktív admin.
        admin_name = "pendingadmin"
        self.addCleanup(self.drop_totp_user, admin_name)
        self.users.add(
            admin_name, "pendingadmin-jelszo-1",
            pending=True, email="pendingadmin@example.co",
        )
        self.users.set_metadata(
            admin_name, role=gateway.ROLE_ADMIN, enabled=True
        )
        self.assertEqual(self.users.admin_count(), 1)

        status, _, body = self.get(
            "/api/admin/state", cookie=admin, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        state = json.loads(body)
        item = next(u for u in state["users"] if u["name"] == name)
        self.assertTrue(item["pending"])
        self.assertFalse(item["enabled"])
        self.assertEqual(item["email"], email)
        self.assertEqual(item["rules"], [])
        self.assertEqual(item["effective_rules"], [])
        admin_item = next(
            u for u in state["users"] if u["name"] == admin_name
        )
        self.assertEqual(admin_item["role"], gateway.ROLE_ADMIN)
        self.assertTrue(admin_item["enabled"])
        self.assertTrue(admin_item["pending"])
        self.assertEqual(admin_item["effective_rules"], [])
        active_admins = [
            u["name"] for u in state["users"]
            if u["role"] == gateway.ROLE_ADMIN and u["enabled"]
            and not u["pending"]
        ]
        self.assertEqual(active_admins, ["root"])

        # Az e-mail-cím nem szivárog a nyilvános végpontokra.
        for path in ("/api/status", "/api/challenge"):
            status, _, payload = self.get(path)
            self.assertEqual(status, 200, payload)
            self.assertNotIn(email.encode(), payload)
            self.assertNotIn(b"email", payload)

        started = time.time()
        status, _, body = self.post(
            "/api/admin/users",
            {"action": "approve", "name": name},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertEqual(payload["message"], "A fiókkérés jóváhagyva.")
        item = next(u for u in payload["users"] if u["name"] == name)
        self.assertFalse(item["pending"])
        self.assertTrue(item["enabled"])
        self.assertEqual(item["email"], email)
        self.assertEqual(item["rules"], [])
        self.assertEqual(item["effective_rules"], [])

        record = self.users.record(name)
        self.assertFalse(record.pending)
        self.assertTrue(record.enabled)
        self.assertFalse(record.must_change_password)
        self.assertEqual(record.email, email)
        self.assertEqual(record.rules, ())
        self.assertTrue(self.users.verify(name, password))
        self.assertEqual(
            [item.name for item in self.users.pending_records()],
            [admin_name],
        )
        self.assertEqual(self.gw.effective_rules(name), [])

        rows = audit_since(self.audit, started)
        approved = [
            row for row in rows
            if row.get("event") == "registration_approved"
        ]
        self.assertEqual(len(approved), 1)
        self.assertEqual(approved[0]["target"], name)
        self.assertEqual(approved[0]["user"], "root")
        dump = json.dumps(rows, ensure_ascii=False)
        self.assertNotIn(email, dump)
        self.assertNotIn(password, dump)

        # Jóváhagyás után jelszó + captcha munkamenetet ad, szabály nélkül.
        user_cookie, login_data = self.login(
            name, password, source="127.0.0.2"
        )
        self.assertTrue(user_cookie)
        self.assertTrue(login_data["authenticated"])
        self.assertFalse(login_data["admin"])
        self.assertEqual(login_data["role"], gateway.ROLE_USER)
        self.assertEqual(login_data["rules"], [])

        status, _, body = self.post(
            "/api/admin/users",
            {"action": "approve", "name": "alice"},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 400, body)
        self.assertIn("nem jóváhagyásra váró", json.loads(body)["error"])

    def test_reject_pending_request_cleans_up(self) -> None:
        admin = self.admin_cookie()
        name = "pendingreject"
        password = "pendingreject-jelszo-1"
        email = "reject@example.co"
        group_id = "pending-reject-grp"
        self.addCleanup(self.drop_totp_user, name)
        self.addCleanup(
            lambda: self.groups.delete(group_id)
            if self.groups.get(group_id) is not None else None
        )
        self.groups.create(group_id, {
            "label": "Elutasítandó kérelem", "rules": [], "members": [],
        })
        self.users.add(name, password, pending=True, email=email)
        # A csoporttagságot közvetlenül állítjuk be, hogy az elutasítás
        # takarítását vizsgálhassuk (a HTTP-úton ezt a guard tiltja).
        self.groups.set_memberships(name, [group_id])
        self.assertEqual(
            [group.id for group in self.groups.groups_for(name)], [group_id]
        )
        started = time.time()

        status, _, body = self.post(
            "/api/admin/users",
            {"action": "reject", "name": name},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertEqual(payload["message"], "A fiókkérés elutasítva.")
        self.assertIsNone(self.users.record(name))
        self.assertNotIn(name, [u["name"] for u in payload["users"]])
        self.assertEqual(self.groups.groups_for(name), [])
        self.assertEqual(self.users.pending_records(), [])

        rejected = [
            row for row in audit_since(self.audit, started)
            if row.get("event") == "registration_rejected"
        ]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["target"], name)
        self.assertEqual(rejected[0]["user"], "root")
        dump = json.dumps(rejected, ensure_ascii=False)
        self.assertNotIn(email, dump)
        self.assertNotIn(password, dump)

        status, _, body = self.post(
            "/api/admin/users",
            {"action": "reject", "name": "alice"},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 400, body)
        self.assertIn("csak jóváhagyásra váró", json.loads(body)["error"])
        self.assertIsNotNone(self.users.record("alice"))

    def test_pending_request_cannot_be_edited_or_grouped(self) -> None:
        admin = self.admin_cookie()
        name = "pendingedit"
        password = "pendingedit-jelszo-1"
        group_id = "pending-edit-grp"
        self.addCleanup(self.drop_totp_user, name)
        self.addCleanup(
            lambda: self.groups.delete(group_id)
            if self.groups.get(group_id) is not None else None
        )
        self.users.add(
            name, password, pending=True, email="edit@example.co"
        )

        status, _, body = self.post(
            "/api/admin/users",
            {
                "action": "update", "name": name, "role": "admin",
                "enabled": True, "rules": ["web-only"],
            },
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 400, body)
        self.assertIn("nem szerkeszthető", json.loads(body)["error"])
        record = self.users.record(name)
        self.assertTrue(record.pending)
        self.assertFalse(record.enabled)
        self.assertEqual(record.role, gateway.ROLE_USER)
        self.assertEqual(record.rules, ())

        status, _, body = self.post(
            "/api/admin/groups",
            {
                "action": "create", "id": group_id,
                "label": "Függő kérelem csoport", "rules": [], "members": [],
            },
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        status, _, body = self.post(
            "/api/admin/groups",
            {"action": "update", "id": group_id, "members": [name]},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 400, body)
        self.assertIn(
            "nem rendelhető csoporthoz", json.loads(body)["error"]
        )
        self.assertEqual(self.groups.get(group_id).members, ())
        self.assertEqual(self.groups.groups_for(name), [])
        self.assertTrue(self.users.record(name).pending)

    def test_admin_create_and_last_admin_guard_ignore_pending_admin(self) -> None:
        admin = self.admin_cookie()
        name = "aktivuj"
        password = "aktivuj-jelszo-1"
        self.addCleanup(self.drop_totp_user, name)
        status, _, body = self.create_user(admin, name, password)
        self.assertEqual(status, 200, body)
        record = self.users.record(name)
        self.assertFalse(record.pending)
        self.assertEqual(record.email, "")
        self.assertTrue(record.enabled)
        self.assertTrue(record.must_change_password)

        pending_admin = "pendingroot"
        self.addCleanup(self.drop_totp_user, pending_admin)
        self.users.add(
            pending_admin, "pendingroot-jelszo-1",
            pending=True, email="pendingroot@example.co",
        )
        self.users.set_metadata(
            pending_admin, role=gateway.ROLE_ADMIN, enabled=True
        )
        pending_record = self.users.record(pending_admin)
        self.assertTrue(pending_record.is_admin)
        self.assertTrue(pending_record.enabled)
        self.assertTrue(pending_record.pending)
        self.assertEqual(self.users.admin_count(), 1)

        for payload in (
            {"action": "update", "name": "root", "role": "user"},
            {"action": "update", "name": "root", "enabled": False},
        ):
            with self.subTest(payload=payload):
                status, _, body = self.post(
                    "/api/admin/users", payload,
                    cookie=admin, source="127.0.0.5",
                )
                self.assertEqual(status, 400, body)
                self.assertIn(
                    "utolsó aktív admin", json.loads(body)["error"]
                )
        root = self.users.record("root")
        self.assertEqual(root.role, gateway.ROLE_ADMIN)
        self.assertTrue(root.enabled)


    def test_admin_logs_manual_read_is_audited(self) -> None:
        admin = self.admin_cookie()
        started = time.time()
        status, _, body = self.get(
            "/api/admin/logs?manual=1&limit=10&severity=warn",
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        rows = audit_since(self.audit, started)
        reads = [
            row for row in rows if row.get("event") == "admin_logs_read"
        ]
        self.assertEqual(len(reads), 1, rows)
        row = reads[0]
        self.assertEqual(row["user"], "root")
        self.assertEqual(row["limit"], 10)
        self.assertEqual(row["severity_filter"], "warn")
        self.assertEqual(row["event_filter"], "")
        self.assertEqual(row["user_filter"], "")
        self.assertFalse(row["q_present"])
        self.assertFalse(row["before_present"])
        self.assertEqual(row["count"], payload["count"])
        self.assertEqual(row["severity"], "info")

        # Az automatikus (manual nélküli) frissítés nem kerül a naplóba.
        status, _, body = self.get(
            "/api/admin/logs?limit=10", cookie=admin, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        reads = [
            item for item in audit_since(self.audit, started)
            if item.get("event") == "admin_logs_read"
        ]
        self.assertEqual(len(reads), 1, reads)

    def test_admin_invalid_origin_is_audited(self) -> None:
        admin = self.admin_cookie()
        password = "admin-origin-titok-4"
        started = time.time()
        conn = self.conn("127.0.0.5")
        conn.request(
            "POST",
            "/api/admin/users",
            body=json.dumps({
                "action": "create", "name": "ujuser", "password": password,
            }),
            headers={
                "Content-Type": "application/json",
                "Cookie": admin,
                "Origin": "http://evil.example",
            },
        )
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        self.assertEqual(resp.status, 403, body)
        rows = audit_since(self.audit, started)
        rejected = [
            row for row in rows
            if row.get("event") == "admin_request_rejected"
        ]
        self.assertEqual(len(rejected), 1, rows)
        row = rejected[0]
        self.assertEqual(row["reason"], "invalid_origin")
        self.assertEqual(row["path"], "/api/admin/users")
        self.assertEqual(row["user"], "")
        self.assertEqual(row["severity"], "warn")
        self.assertNotIn(password, json.dumps(rows, ensure_ascii=False))

    # -- port proxy (3.11.0) -------------------------------------------------

    PORT_PROXY = {
        "label": "Minecraft", "proto": "tcp", "type": "forward",
        "listen_port": 25565, "target_ip": "192.168.10.20",
        "target_port": 25565, "ifaces": "lan", "snat": False,
        "enabled": True,
    }

    def test_port_proxy_requires_admin_and_same_origin(self) -> None:
        payload = {"action": "port_proxies", "port_proxies": [self.PORT_PROXY]}
        alice, _ = self.login("alice", "alice-jelszo-1", source="127.0.0.7")
        status, _, body = self.post(
            "/api/admin/settings", payload, cookie=alice, source="127.0.0.7"
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(json.loads(body).get("code"), "admin_session")
        admin = self.admin_cookie()
        started = time.time()
        conn = self.conn("127.0.0.5")
        conn.request(
            "POST", "/api/admin/settings", body=json.dumps(payload),
            headers={"Content-Type": "application/json", "Cookie": admin,
                     "Origin": "http://evil.example"},
        )
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        self.assertEqual(resp.status, 403, body)
        self.assertEqual(self.settings.snapshot()["port_proxies"], [])
        self.assertFalse(any("portproxy" in line for line in self.tools.lines()))
        rejected = [
            row for row in audit_since(self.audit, started)
            if row.get("event") == "admin_request_rejected"
        ]
        self.assertEqual(rejected[0]["reason"], "invalid_origin")

    def test_port_proxy_apply_audit_and_conntrack(self) -> None:
        admin = self.admin_cookie()
        started = time.time()
        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "port_proxies", "port_proxies": [self.PORT_PROXY]},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertIsInstance(data["port_proxy_warnings"], list)
        stored = self.settings.snapshot()["port_proxies"]
        self.assertEqual(len(stored), 1)
        self.assertEqual(data["settings"]["port_proxies"], stored)
        script = self.tools.script()
        self.assertIn("flush chain inet hatarvedelem portproxy_nat", script)
        self.assertIn(
            'add rule inet hatarvedelem portproxy_nat iifname "eth1" '
            "fib daddr type local tcp dport 25565 "
            "dnat ip to 192.168.10.20:25565",
            script,
        )
        self.assertIn(
            "conntrack -D -p tcp --orig-port-dst 25565", self.tools.lines()
        )
        rows = [
            row for row in audit_since(self.audit, started)
            if row.get("event") == "admin_portproxy_changed"
        ]
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["user"], "root")
        self.assertEqual(rows[0]["port_proxy_count"], 1)
        self.assertEqual(
            rows[0]["port_proxies"],
            "Minecraft: tcp/25565 -> forward 192.168.10.20:25565 (lan)",
        )
        self.assertEqual(rows[0]["flushed_ports"], "tcp/25565")

        # Változatlan újramentésnél nincs conntrack-törlés.
        self.tools.clear()
        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "port_proxies", "port_proxies": stored},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        self.assertFalse(
            any(line.startswith("conntrack") for line in self.tools.lines())
        )

    def test_port_proxy_invalid_and_nft_failure_keep_state(self) -> None:
        admin = self.admin_cookie()
        started = time.time()
        bad = dict(self.PORT_PROXY, listen_port=22)
        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "port_proxies", "port_proxies": [bad]},
            cookie=admin, source="127.0.0.5",
        )
        self.assertEqual(status, 400, body)
        self.assertIn("fenntartott", json.loads(body)["error"])
        rejected = [
            row for row in audit_since(self.audit, started)
            if row.get("event") == "admin_request_rejected"
        ]
        self.assertEqual(rejected[0]["reason"], "invalid_port_proxy")

        self.tools.make_fail("nft hiba")
        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "port_proxies", "port_proxies": [self.PORT_PROXY]},
            cookie=admin, source="127.0.0.5",
        )
        self.tools.clear_fail()
        self.assertEqual(status, 503, body)
        self.assertEqual(self.settings.snapshot()["port_proxies"], [])
        self.assertFalse(
            any(line.startswith("conntrack") for line in self.tools.lines())
        )


class RateLimitHttpTests(unittest.TestCase):
    def test_second_attempt_is_429(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        try:
            tools = FakeTools(tmp.name)
            users = gateway.UserStore(os.path.join(tmp.name, "users.json"), iterations=10_000)
            users.add("alice", "hosszu-jelszo-1")
            fw = gateway.Firewall(binary=str(tools.nft), logger=lambda *_: None)
            audit = gateway.AuditLog(
                os.path.join(tmp.name, "audit.jsonl"), logger=lambda *_: None
            )
            gw = gateway.Gateway(
                users=users, firewall=fw, catalog=CATALOG,
                rules=gateway.RuleStore(
                    os.path.join(tmp.name, "rules.json"),
                    catalog=CATALOG, logger=lambda *_: None,
                ),
                groups=gateway.GroupStore(
                    os.path.join(tmp.name, "groups.json"), logger=lambda *_: None
                ),
                audit=audit,
                rate_limiter=gateway.RateLimiter(window=60, maximum=1),
            )
            srv = server.AppServer(("127.0.0.1", 0), gw)
            import threading
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
                conn.request("POST", "/api/login", body=b"{}",
                             headers={"Content-Type": "application/json"})
                first = conn.getresponse(); first.read()
                self.assertEqual(first.status, 400)
                conn.request("POST", "/api/login", body=b"{}",
                             headers={"Content-Type": "application/json"})
                second = conn.getresponse(); second.read()
                self.assertEqual(second.status, 429)
                conn.close()
            finally:
                srv.shutdown(); srv.server_close(); th.join(timeout=5)
        finally:
            tmp.cleanup()


class TotpCliTests(unittest.TestCase):
    """A ``server.py user totp-reset`` parancs viselkedése."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.users_path = os.path.join(self.tmp.name, "users.json")
        self.audit_path = os.path.join(self.tmp.name, "audit-cli.jsonl")
        self.users = gateway.UserStore(self.users_path, iterations=10_000)
        self.users.add("cliuser", "cliuser-jelszo-1")
        self.users.set_totp_required("cliuser", True)
        self.secret = gateway.generate_totp_secret()
        self.recovery = gateway.generate_recovery_codes(10)
        self.users.enroll_totp(
            "cliuser",
            self.secret,
            [gateway.hash_recovery_code(code) for code in self.recovery],
        )

    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        env = {
            **os.environ,
            "HV_USERS": self.users_path,
            "HV_AUDIT_LOG": self.audit_path,
        }
        return subprocess.run(
            [sys.executable, str(ROOT / "server.py"), *args],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def assert_no_secrets(self, text: str) -> None:
        self.assertNotIn(self.secret, text)
        for code in self.recovery:
            self.assertNotIn(code, text)

    def test_cli_totp_reset_existing_user(self) -> None:
        result = self.run_cli("user", "totp-reset", "cliuser")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cliuser", result.stdout)
        self.assertIn("2FA alaphelyzetbe állítva", result.stdout)
        self.assert_no_secrets(result.stdout + result.stderr)

        data = json.loads(Path(self.users_path).read_text(encoding="utf-8"))
        item = data["cliuser"]
        self.assertEqual(item.get("totp_secret", ""), "")
        self.assertEqual(item.get("totp_last_step", -1), -1)
        self.assertEqual(item.get("totp_recovery", []), [])
        self.assertIs(item.get("totp_required"), True)
        self.assertEqual(
            stat.S_IMODE(os.stat(self.users_path).st_mode), 0o600
        )
        # A már betöltött példány is látja a változást (mtime-újratöltés).
        record = self.users.record("cliuser")
        self.assertEqual(record.totp_secret, "")
        self.assertEqual(record.totp_last_step, -1)
        self.assertEqual(record.totp_recovery, ())

    def test_cli_totp_reset_unknown_user(self) -> None:
        result = self.run_cli("user", "totp-reset", "nincs-ilyen")
        self.assertEqual(result.returncode, 1)
        output = result.stdout + result.stderr
        self.assertIn("Nincs ilyen felhasználó", output)
        self.assertIn("nincs-ilyen", output)
        self.assert_no_secrets(output)
        # A meglévő felhasználó érintetlen maradt.
        self.assertTrue(self.users.record("cliuser").totp_secret)

    def test_cli_totp_reset_while_server_runs(self) -> None:
        tools = FakeTools(self.tmp.name)
        fw = gateway.Firewall(binary=str(tools.nft), logger=lambda *_: None)
        rules = gateway.RuleStore(
            os.path.join(self.tmp.name, "rules.json"), catalog=CATALOG,
            logger=lambda *_: None,
        )
        groups = gateway.GroupStore(
            os.path.join(self.tmp.name, "groups.json"), logger=lambda *_: None
        )
        audit = gateway.AuditLog(
            os.path.join(self.tmp.name, "audit.jsonl"), logger=lambda *_: None
        )
        settings = gateway.settings_store.SettingsStore(
            os.path.join(self.tmp.name, "firewall-settings.json"),
            logger=lambda *_: None,
        )
        drops = gateway.droplog.DropLogService(
            os.path.join(self.tmp.name, "drops.jsonl"),
            enabled=False, logger=lambda *_: None,
        )
        fail2ban = fail2ban_mod.Fail2ban(
            fw, path=os.path.join(self.tmp.name, "fail2ban.json"),
            audit=audit, logger=lambda *_: None, enabled=False,
        )
        gw = gateway.Gateway(
            users=self.users, firewall=fw, catalog=CATALOG,
            rules=rules, groups=groups, audit=audit, settings=settings,
            drops=drops, fail2ban=fail2ban,
            rate_limiter=gateway.RateLimiter(window=60, maximum=1000),
        )
        srv = server.AppServer(("127.0.0.1", 0), gw)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()

        def stop_server() -> None:
            srv.shutdown()
            srv.server_close()
            thread.join(timeout=5)

        self.addCleanup(stop_server)

        # A futó szerver gyorsítótára már tartalmazza a beállított titkot.
        self.assertTrue(self.users.record("cliuser").totp_secret)

        result = self.run_cli("user", "totp-reset", "cliuser")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_no_secrets(result.stdout + result.stderr)

        # mtime-alapú újratöltés: az élő példány a CLI írása után frissül.
        record = self.users.record("cliuser")
        self.assertEqual(record.totp_secret, "")
        self.assertEqual(record.totp_last_step, -1)
        self.assertEqual(record.totp_recovery, ())
        self.assertTrue(record.totp_required)

        data = json.loads(Path(self.users_path).read_text(encoding="utf-8"))
        self.assertEqual(data["cliuser"]["totp_secret"], "")
        self.assertEqual(data["cliuser"]["totp_recovery"], [])
        self.assertEqual(
            stat.S_IMODE(os.stat(self.users_path).st_mode), 0o600
        )


class CliAuditTests(unittest.TestCase):
    """A parancssori felhasználó- és fail2ban-műveletek auditja."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.users_path = os.path.join(self.tmp.name, "users.json")
        self.audit_path = os.path.join(self.tmp.name, "audit-cli.jsonl")
        self.tools = FakeTools(self.tmp.name)
        self.audit = gateway.AuditLog(
            self.audit_path, logger=lambda *_: None
        )

    def run_cli(
        self, *args: str, input_text: str = ""
    ) -> subprocess.CompletedProcess:
        env = {
            **os.environ,
            "HV_USERS": self.users_path,
            "HV_AUDIT_LOG": self.audit_path,
            "HV_STATE_DIR": self.tmp.name,
            "HV_NFT_BIN": str(self.tools.nft),
        }
        return subprocess.run(
            [sys.executable, str(ROOT / "server.py"), *args],
            cwd=str(ROOT),
            env=env,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def events(self, name: str) -> list[dict]:
        # Az AuditLog.read esemény-szűrője részleges (családokhoz), itt
        # viszont pontos egyezést akarunk: a cli_fail2ban_ban nem azonos a
        # fail2ban_ban eseménnyel.
        return [
            row for row in self.audit.read()
            if row.get("event") == name
        ]

    def test_user_cli_events_have_no_passwords(self) -> None:
        first = "cli-audit-jelszo-1"
        second = "cli-audit-jelszo-2"
        result = self.run_cli(
            "user", "add", "cliuser2", "--password-stdin",
            input_text=first + "\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        created = self.events("cli_user_created")
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0]["target"], "cliuser2")
        self.assertEqual(created[0]["actor"], "cli")
        self.assertEqual(created[0]["role"], "user")

        result = self.run_cli(
            "user", "passwd", "cliuser2", "--password-stdin",
            input_text=second + "\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        changed = self.events("cli_password_changed")
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["target"], "cliuser2")
        self.assertEqual(changed[0]["actor"], "cli")
        self.assertEqual(changed[0]["severity"], "warn")

        result = self.run_cli("user", "del", "cliuser2")
        self.assertEqual(result.returncode, 0, result.stderr)
        deleted = self.events("cli_user_deleted")
        self.assertEqual(len(deleted), 1)
        self.assertEqual(deleted[0]["target"], "cliuser2")
        self.assertEqual(deleted[0]["severity"], "warn")

        result = self.run_cli("user", "del", "cliuser2")
        self.assertEqual(result.returncode, 1)
        failed = self.events("cli_action_failed")
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["action"], "del")
        self.assertEqual(failed[0]["target"], "cliuser2")
        self.assertEqual(failed[0]["reason"], "nincs ilyen felhasználó")

        dump = Path(self.audit_path).read_text(encoding="utf-8")
        self.assertNotIn(first, dump)
        self.assertNotIn(second, dump)
        for row in self.audit.read():
            self.assertNotIn("password", row)

    def test_fail2ban_cli_events(self) -> None:
        ip = "203.0.113.9"
        result = self.run_cli(
            "fail2ban", "ban", ip, "--seconds", "120"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        bans = self.events("fail2ban_ban")
        self.assertEqual(len(bans), 1)
        self.assertEqual(bans[0]["ip"], ip)
        self.assertTrue(bans[0]["manual"])
        self.assertEqual(bans[0]["source"], "cli")
        self.assertEqual(bans[0]["seconds"], 120)
        self.assertEqual(bans[0]["actor"], "cli")
        self.assertEqual(bans[0]["severity"], "alert")
        cli_bans = self.events("cli_fail2ban_ban")
        self.assertEqual(len(cli_bans), 1)
        self.assertEqual(cli_bans[0]["target"], ip)
        self.assertEqual(cli_bans[0]["seconds"], 120)
        self.assertEqual(cli_bans[0]["actor"], "cli")

        result = self.run_cli("fail2ban", "unban", ip)
        self.assertEqual(result.returncode, 0, result.stderr)
        unbans = self.events("fail2ban_unban")
        self.assertEqual(len(unbans), 1)
        self.assertEqual(unbans[0]["ip"], ip)
        self.assertTrue(unbans[0]["removed"])
        self.assertEqual(unbans[0]["actor"], "cli")
        cli_unbans = self.events("cli_fail2ban_unban")
        self.assertEqual(len(cli_unbans), 1)
        self.assertEqual(cli_unbans[0]["target"], ip)
        self.assertTrue(cli_unbans[0]["removed"])

        # Nem tiltott IP feloldása nem hiba, de naplózott művelet.
        result = self.run_cli("fail2ban", "unban", ip)
        self.assertEqual(result.returncode, 0, result.stderr)
        failed = self.events("cli_action_failed")
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["action"], "unban")
        self.assertEqual(failed[0]["target"], ip)
        self.assertEqual(failed[0]["reason"], "not_banned")


class StaticUiTests(unittest.TestCase):
    """A fiókkérés és a QR-beiratkozás statikus frontend-jelölői."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / "index.html").read_text(encoding="utf-8")

    def test_registration_markup_and_text_present(self) -> None:
        for token in (
            'id="register-view"',
            'id="register-link"',
            'id="reg-email"',
            'data-i18n="Fiók kérése"',
        ):
            self.assertIn(token, self.source, token)
        # Az admin beállítás jelölőnégyzete JS-ben épül: id: 'registration-enabled'.
        self.assertRegex(
            self.source,
            r"""id\s*[:=]\s*["']registration-enabled["']""",
        )
        for text in (
            "Fiókkérelmek engedélyezése",
            "Függő fiókkérelmek",
            "Jóváhagyás",
            "Elutasítás",
        ):
            self.assertIn(text, self.source, text)

    def test_access_ttl_defaults_to_hours_and_allows_long_grants(self) -> None:
        # A hozzáférés hosszát mindig egész órában adjuk meg: nincs
        # mértékegység-választó, és a perc-alapú ágak eltűntek.
        self.assertNotIn('id="ttl-unit"', self.source)
        self.assertNotIn('<option value="min"', self.source)
        self.assertNotIn("ttlUnit", self.source)
        self.assertNotIn("ttlUnitFactor", self.source)
        self.assertNotIn("setTtlUnit", self.source)
        # A régi 1440 perces (24 órás) felső korlát eltűnt; az admin űrlap
        # a szerveroldali limitet követi, így egy hét is beállítható.
        self.assertNotIn('max="1440"', self.source)
        self.assertNotIn("1440 perc = 24 óra", self.source)
        self.assertIn("max_ttl: 2592000", self.source)
        # Az admin szabályűrlap egész órában kérdez, a tárolt érték másodperc.
        self.assertIn("max: maxTtlHours", self.source)
        self.assertIn('Alapértelmezett idő (óra)', self.source)
        self.assertIn('Maximális idő (óra)', self.source)
        self.assertNotIn('Alapértelmezett idő (perc)', self.source)
        self.assertNotIn('Maximális idő (perc)', self.source)
        self.assertIn("Math.round(defaultHours * 3600)", self.source)
        self.assertIn("Math.round(maxHours * 3600)", self.source)
        self.assertIn("Math.round(rawTtl * 3600)", self.source)
        self.assertIn("ttlDurationLabel", self.source)
        self.assertIn("ttlHours", self.source)
        self.assertIn("return '< 1 óra'", self.source)
        # A régi, egy óránál rövidebb szabály külön üzenetet ad, kérés nélkül.
        self.assertIn("Number(rule.max_ttl) < 3600", self.source)
        self.assertIn("ttlEl.disabled = unavailable", self.source)
        self.assertIn("grantBtn.disabled = unavailable", self.source)
        # A régi, perces megjelenítés nem maradt a szabályűrlapon.
        self.assertNotIn("Math.round(rule.default_ttl / 60)", self.source)
        self.assertNotIn("Math.round(rule.max_ttl / 60)", self.source)
        # Az óra egész számú: nincs törtszámos lépés, és a beküldés is ellenőrzi.
        self.assertIn("ttlEl.step = '1'", self.source)
        self.assertIn("ttlEl.inputMode = 'numeric'", self.source)
        self.assertIn("!Number.isInteger(rawTtl)", self.source)
        self.assertIn("Az időtartam csak egész óra lehet.", self.source)
        self.assertIn(
            'Ez a szabály legalább 1 órás időtartamot igényel.',
            self.source,
        )
        # Az EN/DE fordítások ismerik az új órás alakokat.
        for token in (
            r"Legfeljebb (< 1|[0-9.,]+) óra",
            r"([0-9.,]+) óra$",
            "'< 1 óra': '< 1 hour'",
            "'< 1 óra': '< 1 Std.'",
        ):
            self.assertIn(token, self.source, token)
        # A szerveroldali üzenetek is a formázott időtartamot használják.
        gateway_source = (ROOT / "gateway.py").read_text(encoding="utf-8")
        server_source = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn("def format_duration(seconds)", gateway_source)
        self.assertIn("format_duration(rule.max_ttl)", gateway_source)
        self.assertIn("format_duration(MIN_TTL)", gateway_source)
        self.assertIn('"Hozzáférés engedélyezve: "', server_source)
        self.assertIn("gateway.format_duration(ttl)", server_source)
        self.assertIn("gateway.format_duration(gateway.MAX_TTL)", server_source)

    def test_site_name_ui_and_no_inner_html(self) -> None:
        for token in (
            'id="login-site-name"',
            'id="topbar-site-name"',
            "function applySiteName(raw)",
            "applySiteName(data.site_name)",
            "applySiteName(settings.site_name)",
            "id: 'site-name-input'",
            "action: 'site_name'",
            "name: siteNameInput.value",
            "A tűzfal neve mentve.",
            "Tűzfal neve",
        ):
            self.assertIn(token, self.source, token)
        # A nevet csak textContent adja a DOM-ba, nem innerHTML.
        start = self.source.index("function applySiteName(raw)")
        end = self.source.index("\n}", start)
        self.assertNotIn("innerHTML", self.source[start:end])
        start = self.source.index("const siteSection")
        end = self.source.index("adminPanel.append(siteSection)", start)
        self.assertNotIn("innerHTML", self.source[start:end])
        en, de, _, _ = self._i18n_sections()
        for text in (
            "Tűzfal neve",
            "A tűzfal neve mentve.",
            "A név a portál fejlécében, a böngésző címében és az új "
            "2FA-beiratkozások hitelesítő-bejegyzésében jelenik meg. "
            "Üresen a Dropjak név érvényes.",
            "Tűzfalnév, bejelentkezés előtt nyitva lévő és blokkolt célok.",
        ):
            with self.subTest(text=text):
                self.assertIn(
                    f"'{text}':", en, f"hiányzó angol fordítás: {text}"
                )
                self.assertIn(
                    f"'{text}':", de, f"hiányzó német fordítás: {text}"
                )

    def test_qr_markup_and_inline_library_present(self) -> None:
        for token in (
            "qrcodegen",
            "Project Nayuki",
            "MIT License",
            "https://www.nayuki.io/page/qr-code-generator-library",
            'id="totp-qr"',
            "renderTotpQr",
            "clearTotpQr",
            "Nem működik a QR? Írd be kézzel",
        ):
            self.assertIn(token, self.source, token)
        # A kézi titok a QR-tartalék egy <details> blokkban van.
        self.assertIsNotNone(
            re.search(
                r"<details\b[^>]*>.*?Nem működik a QR\? Írd be kézzel.*?</details>",
                self.source, re.S,
            )
        )
        # Nincs külső QR-CDN vagy qrcode-ra mutató script-forrás.
        self.assertNotIn("cdn.", self.source.lower())
        self.assertIsNone(
            re.search(
                r"""src\s*=\s*["'][^"']*qrcode""",
                self.source, re.IGNORECASE,
            )
        )

    def _i18n_sections(self) -> tuple[str, str, str, str]:
        i18n_start = self.source.index("const I18N = {")
        patterns_start = self.source.index("const I18N_PATTERNS")
        tr_start = self.source.index("function tr(text)")
        i18n = self.source[i18n_start:patterns_start]
        en_start = i18n.index("en: {")
        de_start = i18n.index("de: {")
        patterns = self.source[patterns_start:tr_start]
        pen_start = patterns.index("en: [")
        pde_start = patterns.index("de: [")
        return (
            i18n[en_start:de_start],
            i18n[de_start:],
            patterns[pen_start:pde_start],
            patterns[pde_start:],
        )

    def test_new_ui_strings_are_translated(self) -> None:
        en, de, pen, pde = self._i18n_sections()
        sources = (
            "Fiók kérése",
            "Kérj fiókot. Az admin jóváhagyása után beléphetsz.",
            "Bejelentkezési név",
            "E-mail-cím",
            "Jelszó újra",
            "Kérelem elküldése",
            "Fiókkérelmek",
            "A jóváhagyásra váró fiók captcha-védett, e-mail-címet tárol "
            "(nem küld e-mailt), és csak admin jóváhagyás után léphet be.",
            "Fiókkérelmek engedélyezése",
            "Függő fiókkérelmek",
            "Jóváhagyás",
            "Elutasítás",
            "Nem működik a QR? Írd be kézzel",
            "2FA QR-kód beolvasása",
        )
        for text in sources:
            with self.subTest(text=text):
                self.assertIn(text, en, f"hiányzó angol fordítás: {text}")
                self.assertIn(text, de, f"hiányzó német fordítás: {text}")
        # Dinamikus darabszám és elutasítás-megerősítés mintája.
        for section in (pen, pde):
            self.assertIn("függő kérelem", section)
            self.assertIn("Elutasítod:", section)


    def test_legacy_rule_fallback_label_is_accurate(self) -> None:
        """A kiosztás nélküli fiók címkéje csak a forward öröklést jelzi."""
        for old in (
            "nincs beállítva (alap: mind)",
            "not set (default: all)",
            "nicht gesetzt (Standard: alle)",
        ):
            with self.subTest(old=old):
                self.assertNotIn(old, self.source, old)
        en, de, _, _ = self._i18n_sections()
        for source_text, english, german in (
            (
                "nincs közvetlen beállítás (a forward szabályok öröklődnek)",
                "no direct assignment (forward rules are inherited)",
                "keine direkte Zuweisung (Forward-Regeln werden geerbt)",
            ),
            (
                "nincs közvetlen beállítás (csoportból örökölve)",
                "no direct assignment (inherited from groups)",
                "keine direkte Zuweisung (von Gruppen geerbt)",
            ),
        ):
            with self.subTest(text=source_text):
                self.assertIn(source_text, self.source, source_text)
                self.assertIn(f"'{source_text}': '{english}'", en, source_text)
                self.assertIn(f"'{source_text}': '{german}'", de, source_text)
        # A régi fallback csak kiosztás nélküli fiókra vonatkozik, ezért a
        # csoportos öröklést külön címke jelzi.
        self.assertIn("(user.groups || []).length", self.source)


    def test_admin_password_generator_markup_and_translations(self) -> None:
        """Az admin felhasználóűrlap jelszó-generátora és a hozzá tartozó UI."""
        for token in (
            "function secureRandomIndex(max)",
            "function generatePassword()",
            "crypto.getRandomValues(buffer)",
            "new Uint32Array(1)",
            "while (chars.length < 20)",
            "setPasswordVisible",
            "aria-pressed",
            "'aria-live': 'polite'",
            "navigator.clipboard",
            "document.execCommand('copy')",
            "class: 'password-field'",
            "Jelszó a vágólapra másolva.",
            "A vágólapra másolás nem sikerült.",
            "A mentéssel a felhasználó jelszava megváltozik.",
        ):
            self.assertIn(token, self.source, token)
        self.assertRegex(self.source, r"name:\s*['\"]password['\"]")
        self.assertNotIn("Math.random", self.source)
        match = re.search(
            r"const lower = '([^']+)';\s*"
            r"const upper = '([^']+)';\s*"
            r"const digits = '([^']+)';\s*"
            r"const symbols = '([^']+)';",
            self.source,
        )
        self.assertIsNotNone(match)
        lower, upper, digits, symbols = match.groups()
        self.assertEqual((len(lower), len(upper), len(digits), len(symbols)),
                         (25, 24, 8, 14))
        for alphabet in match.groups():
            for char in "O0Il1":
                self.assertNotIn(char, alphabet, alphabet)
        en, de, _, _ = self._i18n_sections()
        for text in (
            "Jelszó generálása",
            "Mutat",
            "Elrejtés",
            "Másolás",
            "Jelszó a vágólapra másolva.",
            "A vágólapra másolás nem sikerült.",
            "A mentéssel a felhasználó jelszava megváltozik.",
        ):
            with self.subTest(text=text):
                self.assertIn(f"'{text}':", en, f"hiányzó angol fordítás: {text}")
                self.assertIn(f"'{text}':", de, f"hiányzó német fordítás: {text}")


    def test_rule_collection_and_duplicate_markup(self) -> None:
        for token in (
            "name: 'collection'",
            "pickedValues(box, 'members')",
            "submit({ ...base, collection: true, members })",
            "collection: false",
            "tcpField.hidden = collection",
            "udpField.hidden = collection",
            "accessField.hidden = collection",
            "membersField.hidden = !collection",
            "directionField.hidden = collection",
            "action: 'duplicate'",
            "Duplikálás",
            "Tartalmazott szabályok",
            "Legalább egy egyedi szabályt válassz a gyűjtőszabályhoz.",
            "rule.collection ?",
            "tr('gyűjtő')",
            "tr('másolat')",
        ):
            self.assertIn(token, self.source, token)
        # A gyűjtő payloadja nem tartalmaz saját irányt.
        self.assertNotIn("direction,\n      default_ttl", self.source)
        en, de, pen, pde = self._i18n_sections()
        sources = (
            "Gyűjtőszabály",
            "Tartalmazott szabályok",
            "Duplikálás",
            "másolat",
            "gyűjtő",
            "Legalább egy egyedi szabályt válassz a gyűjtőszabályhoz.",
            "A gyűjtőszabály portjai a tagok uniója. Teljes hozzáférésű és "
            "gyűjtő szabály nem választható tagként.",
            "Szabály duplikálva.",
            "gyűjtőszabályhoz nem adható meg port, ICMP vagy teljes hozzáférés",
            "a gyűjtőszabály nem tartalmazhatja önmagát",
            "ez egy fenntartott, régi azonosító, nem lehet gyűjtőszabály tagja",
            "ez egy fenntartott, régi azonosító, nem duplikálható",
            "members: ismétlődő szabály-azonosító",
            "members: 1–64 szabály-azonosítóból álló lista kell",
            "members: legalább 1 és legfeljebb 64 egyedi szabály kell",
            "collection: logikai érték kell",
        )
        for text in sources:
            with self.subTest(text=text):
                self.assertIn(text, en, f"hiányzó angol fordítás: {text}")
                self.assertIn(text, de, f"hiányzó német fordítás: {text}")
        for section in (pen, pde):
            self.assertIn("gyűjtőszabályban", section)
            self.assertIn("nem törölhető", section)
            self.assertIn("gyűjtőszabályoknak", section)


    def test_rule_direction_markup_and_translations(self) -> None:
        for token in (
            "name: 'direction'",
            "el('option', { value: 'forward', text: tr('Forward') })",
            "el('option', { value: 'input', text: tr('Input (host)') })",
            "directionSelect.value = draftValue(",
            "directionSelect.addEventListener('change', syncMode)",
            "direction,",
            "directionField.hidden = collection",
            "accessField.hidden = collection || host",
            "hostNote.hidden = !host",
            "!rule.collection && rule.direction === 'input'",
            "rule.direction || 'forward'",
            "class: 'dir-badge'",
            "A gyűjtőszabály tagjai különböző irányúak is lehetnek; "
            "minden tag a saját irányában kap engedélyt.",
            "A host szabály a portálgép saját szolgáltatásait nyitja meg "
            "a belépett kliens IP-jének. Csak a szükséges portokat add "
            "meg; a 8100 (portál) fenntartott.",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)
        # Az admin táblában és a hozzáférési kártyán is csak egyedi
        # szabálynál jelenik meg a Host jelzés.
        self.assertEqual(
            self.source.count("!rule.collection && rule.direction === 'input'"),
            2,
        )

        en, de, pen, pde = self._i18n_sections()
        sources = (
            "Irány",
            "Forward",
            "Input (host)",
            "Host",
            "A gyűjtőszabály tagjai különböző irányúak is lehetnek; "
            "minden tag a saját irányában kap engedélyt.",
            "A host szabály a portálgép saját szolgáltatásait nyitja meg "
            "a belépett kliens IP-jének. Csak a szükséges portokat add "
            "meg; a 8100 (portál) fenntartott.",
            "host szabály nem lehet teljes hozzáférésű",
            "host szabály nem tartalmazhat ICMP-t",
            "host szabály nem használhat szolgáltatáslistát",
            "host szabályhoz legalább egy TCP vagy UDP port kell",
            "a 8100-as port (portál) nem nyitható meg host szabállyal",
            "direction: forward vagy input érték kell",
        )
        for text in sources:
            with self.subTest(text=text):
                self.assertIn(
                    f"'{text}':", en, f"hiányzó angol fordítás: {text}"
                )
                self.assertIn(
                    f"'{text}':", de, f"hiányzó német fordítás: {text}"
                )
        # A 22-es port tiltásának fordítása eltűnt; a 8100-as megmaradt.
        for section in (en, de):
            self.assertNotIn(
                "a 22-es port (SSH) nem nyitható meg host szabállyal",
                section,
            )
            self.assertIn(
                "'a 8100-as port (portál) nem nyitható meg host szabállyal':",
                section,
            )
        for section in (en, de, pen, pde):
            self.assertNotIn("azonos irányúak lehetnek", section)
            self.assertNotIn("szabály iránya nem módosítható", section)
        for section in (pen, pde):
            self.assertIn(
                "host szabály nem használhat szolgáltatáslistát", section
            )

    @staticmethod
    def _js_function(name: str, source: str) -> str:
        match = re.search(
            rf"function {re.escape(name)}\([^)]*\) \{{.*?\n\}}",
            source, re.S,
        )
        if match is None:
            raise AssertionError(f"hiányzó JS függvény: {name}")
        return match.group(0)

    def test_duplicate_label_localization_and_suffix(self) -> None:
        """A másolat utótagja nyelvfüggetlenül tárolva, megjelenítéskor fordul."""
        for token in (
            "function ruleDisplayLabel(label)",
            "function duplicateLabel(label)",
            "const COPY_LABEL_SUFFIX = ' — másolat';",
            "ruleDisplayLabel(rule.label)",
            "ruleDisplayLabel(data.rule_label",
            "ruleDisplayLabel(row.rule_label",
            "Biztosan törlöd a szabályt: ${ruleDisplayLabel(rule.label)}?",
            "label: duplicateLabel(rule.label)",
        ):
            self.assertIn(token, self.source, token)
        # A kliens már nem a mindenkori nyelvű utótagot küldi el.
        self.assertNotIn(
            "rule.label + ' — ' + tr('másolat')", self.source
        )
        en, de, pen, pde = self._i18n_sections()
        for section in (pen, pde):
            self.assertIn("/^members: érvénytelen elem$/", section)
            self.assertIn("/^members: érvénytelen elem: (.+)$/", section)

        suffix_match = re.search(
            r"const COPY_LABEL_SUFFIX = '([^']*)';", self.source
        )
        self.assertIsNotNone(suffix_match)
        suffix = suffix_match.group(1)
        display = self._js_function("ruleDisplayLabel", self.source)
        duplicate = self._js_function("duplicateLabel", self.source)
        script = (
            "const tr = text => ({'Böngészés': 'Browse', "
            "'másolat': 'copy', 'Kopie': 'copy'}[text] ?? text);\n"
            + suffix_match.group(0) + "\n"
            + display + "\n" + duplicate + "\n"
            + "const out = {\n"
            + "  known: ruleDisplayLabel('Böngészés — másolat'),\n"
            + "  custom: ruleDisplayLabel('Saját szabály — másolat'),\n"
            + "  legacy: ruleDisplayLabel('Web — copy'),\n"
            + "  server: ruleDisplayLabel('Web (copy)'),\n"
            + "  plain: ruleDisplayLabel('Web'),\n"
            + "  long: duplicateLabel('x'.repeat(80)),\n"
            + "  short: duplicateLabel('Rövid'),\n"
            + "};\n"
            + "process.stdout.write(JSON.stringify(out));"
        )
        node = shutil.which("node")
        if node is None:
            self.skipTest("node nem érhető el a JS-helper teszthez")
        result = subprocess.run(
            [node, "-e", script],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["known"], "Browse — copy")
        self.assertEqual(data["custom"], "Saját szabály — copy")
        self.assertEqual(data["legacy"], "Web — copy")
        self.assertEqual(data["server"], "Web — copy")
        self.assertEqual(data["plain"], "Web")
        self.assertEqual(data["short"], "Rövid" + suffix)
        self.assertEqual(len(data["long"]), 80)
        self.assertTrue(data["long"].endswith(suffix))
        self.assertEqual(
            data["long"].count("x"),
            80 - len(suffix),
        )

    def test_password_copy_is_guarded_when_empty(self) -> None:
        for token in (
            "disabled: !passwordInput.value",
            "const text = passwordInput.value;",
            "if (!text) {",
            "setPasswordStatus('Nincs jelszó a vágólapra másoláshoz.', false);",
            "passwordCopy.disabled = !passwordInput.value;",
        ):
            self.assertIn(token, self.source, token)
        en, de, _, _ = self._i18n_sections()
        text = "Nincs jelszó a vágólapra másoláshoz."
        for section in (en, de):
            self.assertIn(f"'{text}':", section)

    def test_duplicate_button_ignores_double_click(self) -> None:
        start = self.source.index("action: 'duplicate'")
        window = self.source[max(0, start - 700):start + 900]
        for token in (
            "const button = event.currentTarget;",
            "if (button.disabled) return;",
            "button.disabled = true;",
            "await adminSend('/api/admin/rules'",
            "label: duplicateLabel(rule.label)",
            "finally {",
            "button.disabled = false;",
        ):
            self.assertIn(token, window, token)

    def test_version_placeholder_in_footer(self) -> None:
        self.assertIn(
            '<span class="version" aria-label="Verzió">v__VERSION__</span>',
            self.source,
        )
        self.assertNotIn(">v2.0<", self.source)


    def test_multi_select_ttl_hint_lists_all_rules_and_binding(self) -> None:
        """Több kiválasztott szabálynál minden címke és a kötő szabály látszik."""
        start = self.source.index("function ttlBounds()")
        end = self.source.index("function selectRule(", start)
        section = self.source[start:end]
        # A függvény a kiválasztott szabályokat és a felső korlátot adó(ka)t
        # is visszaadja; azonos maximum esetén mindet összegyűjti.
        self.assertIn("const capped = [];", section)
        self.assertIn("} else if (value === ruleCap) {", section)
        self.assertIn(
            "return { minSec, maxSec, rule, rules, binding };", section
        )
        self.assertIn("maxSec = Math.min(maxSec, value);", section)
        self.assertIn("const { rules, binding } = ttlBounds();", section)
        self.assertIn(
            "const labels = rules.map(item => ruleDisplayLabel(item.label || item.id));",
            section,
        )
        # Az egy szabályos forma változatlan, a több szabályos minden címkét
        # kiírja (3 után +N-nel), a teljes lista pedig a title-ben van.
        self.assertIn(
            "ttlHint.title = labels.length > 1 ? labels.join(' · ') : '';",
            section,
        )
        self.assertIn("const visible = labels.slice(0, 3);", section)
        self.assertIn(
            "if (hidden > 0) text += ` · +${hidden} ${tr('további')}`;",
            section,
        )
        self.assertIn(
            "text += ` · ${tr('felső korlát')}: ${names.join(', ')}`;",
            section,
        )
        # A kötő szabályok listája csak szigorú részhalmaz esetén jelenik meg,
        # így ha minden kiválasztott szabály kötő, a címkék nem ismétlődnek.
        self.assertIn(
            "if (binding.length && binding.length < rules.length) {", section
        )
        # Az időtartam beviteli mező mellett statikus mértékegység-suffix áll.
        self.assertIn(
            '<span class="ttl-unit" data-i18n="óra">óra</span>', self.source
        )
        self.assertIn(
            ".ttl-unit{font-size:12px;font-weight:600;color:#666;"
            "white-space:nowrap;user-select:none}",
            self.source,
        )
        self.assertIn(
            ':root[data-theme="dark"] .ttl-unit{color:#b7b9bb}', self.source
        )
        self.assertIn("} else if (labels.length === 1) {", section)
        self.assertIn("text += ` · ${labels[0]}`;", section)
        self.assertIn(
            "text = tr(`Beállítható: ${min}–${max} óra`);", section
        )
        # Egy óránál rövidebb szabály több kiválasztásnál többes számú üzenet.
        self.assertIn("text = rules.length > 1", section)
        self.assertIn(
            "A kiválasztott szabályok közül legalább egy legalább 1 órás "
            "időtartamot igényel.",
            section,
        )
        en, de, _, _ = self._i18n_sections()
        for text, english, german in (
            ("felső korlát", "upper limit", "Obergrenze"),
            ("további", "more", "weitere"),
            (
                "A kiválasztott szabályok közül legalább egy legalább 1 "
                "órás időtartamot igényel.",
                "At least one of the selected rules requires a duration of "
                "at least 1 hour.",
                "Mindestens eine der ausgewählten Regeln erfordert eine "
                "Dauer von mindestens 1 Stunde.",
            ),
        ):
            with self.subTest(text=text):
                self.assertIn(f"'{text}': '{english}'", en)
                self.assertIn(f"'{text}': '{german}'", de)

    def test_audit_event_select_manual_render_and_raw_code(self) -> None:
        """Az eseményszűrő legördülő, a kézi betöltés pedig mindig rajzol."""
        for token in (
            "const eventSelect = el('select'",
            "Object.keys(AUDIT_EVENT_LABELS)",
            ".sort((a, b) => auditEventLabel(a).localeCompare(",
            "if (logFilter.event && !eventCodes.includes(logFilter.event))",
            "value: '', text: tr('összes esemény')",
            "text: `${auditEventLabel(code)} (${code})`",
            "event: eventSelect.value",
            "['Esemény', eventSelect]",
            "for (const node of [userInput, qInput, ipInput])",
            "class: 'log-event-code muted'",
            "text: entry.event",
            "const searchPhrase = 'keresés a látható értékekben "
            "(esemény, felhasználó, IP, szabály, ok)';",
        ):
            self.assertIn(token, self.source, token)
        # A régi szabad szöveges esemény-mező és annak Enter-kezelője eltűnt.
        self.assertNotIn("placeholder: tr('esemény')", self.source)
        self.assertNotIn(
            "for (const node of [eventInput, userInput, qInput])",
            self.source,
        )
        logs_start = self.source.index("async function loadLogs")
        logs_end = self.source.index("function scheduleLogs", logs_start)
        self.assertIn(
            "if (manual || !typing)", self.source[logs_start:logs_end]
        )
        drops_start = self.source.index("async function loadDrops")
        drops_end = self.source.index("function scheduleDrops", drops_start)
        drops = self.source[drops_start:drops_end]
        self.assertIn("async function loadDrops(manual = false)", drops)
        self.assertIn("if (manual || !typing)", drops)
        # A szűrő gombjai kézi betöltésként rajzolnak.
        filter_start = self.source.index("function dropFiltersBar()")
        filter_end = self.source.index("function dropTimeCell(", filter_start)
        filter = self.source[filter_start:filter_end]
        self.assertGreaterEqual(filter.count("loadDrops(true)"), 2)
        en, de, _, _ = self._i18n_sections()
        for text, english, german in (
            ("összes esemény", "all events", "alle Ereignisse"),
            ("eseménykód", "event code", "Ereignis-Code"),
            (
                "keresés a látható értékekben (esemény, felhasználó, IP, "
                "szabály, ok)",
                "search visible values (event, user, IP, rule, reason)",
                "sichtbare Werte durchsuchen (Ereignis, Benutzer, IP, "
                "Regel, Grund)",
            ),
        ):
            with self.subTest(text=text):
                self.assertIn(f"'{text}': '{english}'", en)
                self.assertIn(f"'{text}': '{german}'", de)

    def test_fail2ban_drop_metric_switches_and_disabled_rendering(self) -> None:
        """A három jelzés külön kapcsolható; nincs 0 = kikapcsolva."""
        start = self.source.index("function fail2banConfigForm(fb)")
        end = self.source.index("function fail2banBanForm(fb)", start)
        form = self.source[start:end]
        # A tiltás hossza nem a belépés-csoportban van: a ban_seconds a
        # drop-alapú tiltásokat is szabályozza, ezért közös csoportba került.
        enabled_start = form.index("'enabled', fb.enabled !== false")
        enabled_end = form.index("makeGroup(", enabled_start)
        enabled_group = form[enabled_start:enabled_end]
        self.assertNotIn("ban_minutes", enabled_group)
        self.assertIn("max_attempts", enabled_group)
        self.assertIn("window_minutes", enabled_group)
        self.assertIn("tr('Közös beállítások')", form)
        self.assertIn("class: 'f2b-group-title'", form)
        shared_start = form.index("tr('Közös beállítások')")
        shared_end = form.index("class: 'form-actions'", shared_start)
        shared_group = form[shared_start:shared_end]
        self.assertIn("name: 'ban_minutes'", shared_group)
        self.assertIn("name: 'drop_window_minutes'", shared_group)
        self.assertIn(
            "fail2banDraftError('Adj meg érvényes számokat a küszöbhöz "
            "és az időtartamokhoz.')",
            form,
        )
        self.assertNotIn("küszöbökhöz", form)
        for token in (
            "type: 'checkbox', name",
            "'enabled', fb.enabled !== false",
            "'drop_count_enabled', fb.drop_count_enabled !== false",
            "'drop_ports_enabled', fb.drop_ports_enabled !== false",
            "drop_count_enabled: dropCountEnabled",
            "drop_ports_enabled: dropPortsEnabled",
            "min: limits.min_drop_max ?? 1",
            "min: limits.min_drop_ports ?? 1",
            "class: 'f2b-group'",
            "class: 'f2b-toggle'",
            "class: 'f2b-fields'",
            "classList.toggle('is-off', !on)",
            "node.disabled = !on",
            "tr('Sikertelen belépés a tiltásig')",
            "'Sikertelen belépések'",
            "'Eldobott csomagok'",
            "'Különböző célportok'",
            "tr('Mindkét drop-mérőszám ezt az időablakot használja.')",
        ):
            self.assertIn(token, form, token)
        # A régi drop-mesterkapcsoló és a 0 = kikapcsolva mechanizmus eltűnt.
        self.assertNotIn("name: 'drop_enabled'", form)
        self.assertNotIn("drop_enabled: boolValue", form)
        self.assertNotIn("0 = kikapcsolva", self.source)
        # A belépés és a drop-figyelés független a státuszkártyákon is.
        self.assertIn(
            "const loginActive = fb.enabled !== false;", self.source
        )
        self.assertIn(
            "const dropMaster = fb.drop_enabled !== false;", self.source
        )
        self.assertIn(
            "const dropRunning = countActive || portsActive;",
            self.source,
        )
        self.assertIn(
            "const running = loginActive || dropRunning || fb.proxy_enabled === true;",
            self.source
        )
        self.assertIn("fb.drop_count_active", self.source)
        self.assertIn("fb.drop_ports_active", self.source)
        self.assertIn("tr('csomagszám')", self.source)
        self.assertIn("tr('portszám')", self.source)
        # A várakozó drop-táblában a kikapcsolt mérőszám nem / 0 alakot kap.
        pending_start = self.source.index("function fail2banDropPendingTable(")
        pending_end = self.source.index("async function fail2banUnban(", pending_start)
        pending = self.source[pending_start:pending_end]
        self.assertIn("row.drop_count_active", pending)
        self.assertIn("row.drop_ports_active", pending)
        self.assertIn(
            "text: countActive ? `${row.count} / ${row.max_drops}` : tr('kikapcsolva')",
            pending,
        )
        en, de, _, _ = self._i18n_sections()
        for text, english, german in (
            ("Közös beállítások", "Shared settings", "Gemeinsame Einstellungen"),
            (
                "Minden automatikus tiltásra érvényes, a drop-alapúakra is.",
                "Applies to every automatic ban, including drop-based ones.",
                "Gilt für jede automatische Sperre, auch für drop-basierte.",
            ),
            (
                "Adj meg érvényes számokat a küszöbhöz és az időtartamokhoz.",
                "Enter valid numbers for the threshold and durations.",
                "Gib gültige Zahlen für Schwelle und Zeiträume ein.",
            ),
            ("Sikertelen belépések", "Failed sign-ins", "Fehlgeschlagene Anmeldungen"),
            (
                "Hibás jelszavas belépések; a captcha- és a gyakorisági "
                "hibák nem számítanak.",
                "Failed password sign-ins; captcha and rate-limit failures "
                "do not count.",
                "Fehlgeschlagene Passwort-Anmeldungen; Captcha- und "
                "Ratenlimit-Fehler zählen nicht.",
            ),
            (
                "A bejelentkezés nélküli forgalom eldobott csomagjait "
                "számolja.",
                "Counts dropped packets in traffic without a sign-in.",
                "Zählt verworfene Pakete im Verkehr ohne Anmeldung.",
            ),
            (
                "Különböző célportok",
                "Distinct destination ports",
                "Verschiedene Zielports",
            ),
            (
                "Portszkennerek észlelése a különböző célportok alapján.",
                "Detects port scanners by the number of distinct "
                "destination ports.",
                "Erkennt Portscanner anhand der Anzahl verschiedener "
                "Zielports.",
            ),
            (
                "Mindkét drop-mérőszám ezt az időablakot használja.",
                "Both drop metrics use this window.",
                "Beide Drop-Metriken verwenden dieses Zeitfenster.",
            ),
            (
                "A kikapcsolt mérőszám nem számol és nem tilt; a meglévő "
                "tiltások a megadott idő elteltével normálisan lejárnak.",
                "A disabled metric neither counts nor bans; existing bans "
                "expire normally after the configured time.",
                "Eine deaktivierte Metrik zählt nicht und sperrt nicht; "
                "bestehende Sperren laufen nach der festgelegten Zeit "
                "normal ab.",
            ),
        ):
            with self.subTest(text=text):
                self.assertIn(f"'{text}': '{english}'", en)
                self.assertIn(f"'{text}': '{german}'", de)
        # A kiváltott régi kulcsok már nem szerepelnek a fordításokban.
        for removed in (
            "0 = kikapcsolva",
            "Drop-alapú tiltás",
            "bejelentkezés nélküli portszkennerek tiltása",
            "eldobott csomagok számlálása",
            "portszkennelés számlálása",
        ):
            with self.subTest(removed=removed):
                self.assertNotIn(f"'{removed}':", en)
                self.assertNotIn(f"'{removed}':", de)


    def test_status_poll_refreshes_access_without_navigation(self) -> None:
        refresh_start = self.source.index("async function refreshStatus()")
        session_start = self.source.index(
            "if (activeView === 'session') {", refresh_start
        )
        access_start = self.source.index(
            "if (activeView === 'access') {", refresh_start
        )
        self.assertLess(access_start, session_start)
        access_branch = self.source[access_start:session_start]
        self.assertIn("refreshAccessFromStatus(data);", access_branch)
        self.assertIn("return;", access_branch)
        # A módosítás nézetben a poll nem navigál és nem hívja a session-nézetet.
        self.assertNotIn("showAccess(", access_branch)
        self.assertNotIn("showSession(", access_branch)

        start = self.source.index("function refreshAccessFromStatus(data)")
        end = self.source.index("async function refreshStatus()", start)
        section = self.source[start:end]
        for token in (
            "const previousRules = Array.isArray(previous.rules) "
            "? previous.rules : [];",
            "const freshRules = Array.isArray(data.rules) "
            "? data.rules : previousRules;",
            "rulesSignature(previousRules) !== rulesSignature(freshRules)",
            "const before = new Map(",
            "const after = new Map(",
            "const previousServer = Array.isArray(previous.selectedRules)",
            "const freshServer = statusSelection(data, previousServer);",
            "for (const id of previousServer) {",
            "if (!freshServer.includes(id)) revoked.add(id);",
            "renderAuth(data);",
            "selectedRuleIds = selectedRuleIds.filter(",
            "id => !revoked.has(id) && after.has(id)",
            "if (!selectedRuleIds.length) "
            "selectedRuleIds = chooseDefaultRules();",
            "if (catalogChanged || revoked.size) renderRules();",
            "updateTtlBounds();",
        ):
            self.assertIn(token, section, token)
        # A folyamatban lévő érvényes kijelölést nem törli a poll, és a
        # kártyák csak valódi katalógusváltozásnál rajzolódnak újra.
        self.assertIn("catalogChanged", section)
        self.assertIn("revoked.size", section)
        # A visszavonás azonnal látható a módosítás nézetben.
        self.assertIn(
            "Az új szabálydefiníció csak külön engedélyezéssel lép "
            "életbe; engedélyezd újra a hozzáférést.",
            section,
        )

        # Engedélyezés előtt (pending) is megmarad a képernyő és a
        # folyamatban lévő kijelölés; csak a katalógus változásakor rajzol.
        pending_start = self.source.index(
            "if (activeView !== 'access') showAccess(data);", refresh_start
        )
        pending_end = self.source.index("} catch (e) {", pending_start)
        pending = self.source[pending_start:pending_end]
        for token in (
            "const previousRules = auth && Array.isArray(auth.rules) "
            "? auth.rules : [];",
            "const freshRules = Array.isArray(data.rules) "
            "? data.rules : previousRules;",
            "rulesSignature(previousRules) !== rulesSignature(freshRules)",
            "renderAuth(data, true);",
            "selectedRuleIds = selectedRuleIds.filter(",
            "if (!selectedRuleIds.length) "
            "selectedRuleIds = chooseDefaultRules();",
            "if (catalogChanged) renderRules();",
            "updateTtlBounds();",
        ):
            self.assertIn(token, pending, token)

    def test_status_poll_keeps_session_view_fresh_and_notifies(self) -> None:
        refresh_start = self.source.index("async function refreshStatus()")
        session_start = self.source.index(
            "if (activeView === 'session') {", refresh_start
        )
        notice_call = "if (sessionRevokedNotice) "
        notice_end = self.source.index(notice_call, session_start)
        notice_end = self.source.index(
            "showSessionMsg(sessionRevokedNotice);",
            notice_end,
        ) + len("showSessionMsg(sessionRevokedNotice);")
        section = self.source[session_start:notice_end]
        for token in (
            "const revoked = auth",
            "!sameSelection(",
            "statusSelection(data, auth.selectedRules)",
            "showSession(data);",
            "if (Array.isArray(data.rules)) auth.rules = data.rules;",
            "auth.rulesSignature = rulesSignature(auth.rules);",
            "sessionRevokedNotice = ",
            "if (sessionRevokedNotice) "
            "showSessionMsg(sessionRevokedNotice);",
        ):
            self.assertIn(token, section, token)
        # A visszavonási értesítés a session-nézetben is megmarad a
        # következő pollok alatt, de új belépéskor/módosításkor törlődik.
        self.assertIn(
            "Az új szabálydefiníció csak külön engedélyezéssel lép "
            "életbe; a módosítás oldalon újra engedélyezheted.",
            section,
        )
        access_start = self.source.index("function showAccess(data)")
        access_end = self.source.index("function showSession(", access_start)
        self.assertIn(
            "sessionRevokedNotice = '';",
            self.source[access_start:access_end],
        )
        end_start = self.source.index("function endSession(")
        end_end = self.source.index("function updateTimer()", end_start)
        self.assertIn(
            "sessionRevokedNotice = '';",
            self.source[end_start:end_end],
        )
        grant_start = self.source.index("accessForm.addEventListener('submit'")
        grant_end = self.source.index("function cachedAccessPayload()", grant_start)
        grant_handler = self.source[grant_start:grant_end]
        self.assertIn(
            "sessionRevokedNotice = '';\n    showSession(data);",
            grant_handler,
        )

    def test_modify_button_fetches_fresh_status_before_access_view(self) -> None:
        start = self.source.index("modifyBtn.addEventListener")
        end = self.source.index("accessBack.addEventListener", start)
        handler = self.source[start:end]
        for token in (
            "modifyBtn.addEventListener('click', async () => {",
            "if (!auth) return;",
            "await fetch('/api/status', { cache: 'no-store' })",
            "data = await res.json();",
            "if (data && data.authenticated === true) {",
            "showAccess(data);",
            "if (data && data.authenticated === false) {",
            "await refreshStatus();",
            "showAccess(cachedAccessPayload());",
        ):
            self.assertIn(token, handler, token)
        # Hálózati hibánál a gyorsítótárazott pillanatkép marad, de nem
        # navigálunk el a session-nézetbe.
        self.assertNotIn("showSession(", handler)
        self.assertNotIn("location.", handler)
        helper_start = self.source.index("function cachedAccessPayload()")
        helper = self.source[helper_start:start]
        for token in (
            "expires_in: Math.max(0, (auth.expiresAt - Date.now()) / 1000)",
            "selected_rules: auth.selectedRules",
            "selected_rule_labels: auth.selectedRuleLabels",
            "grants: auth.grants",
        ):
            self.assertIn(token, helper, token)

    def test_rule_signature_helpers_are_order_insensitive(self) -> None:
        functions = "\n".join(
            self._js_function(name, self.source)
            for name in (
                "ruleSignature",
                "rulesSignature",
                "sameSelection",
                "statusSelection",
            )
        )
        script = functions + """
const ruleA = { id: 'a', label: 'A', tcp: [22], max_ttl: 3600 };
const ruleAReordered = { max_ttl: 3600, tcp: [22], label: 'A', id: 'a' };
const ruleB = { id: 'b', label: 'B', udp: [53], max_ttl: 7200 };
const out = {
  keyOrderStable: ruleSignature(ruleA) === ruleSignature(ruleAReordered),
  ruleOrderInsensitive:
    rulesSignature([ruleA, ruleB]) === rulesSignature([ruleB, ruleA]),
  changedDefinition:
    ruleSignature(ruleA) !== ruleSignature({ ...ruleA, tcp: [23] }),
  removedRule:
    rulesSignature([ruleA, ruleB]) !== rulesSignature([ruleA]),
  sameOrderInsensitive: sameSelection(['b', 'a'], ['a', 'b']),
  sameDifferent: !sameSelection(['a'], ['a', 'b']),
  selectedRulesPreferred:
    JSON.stringify(statusSelection(
      { selected_rules: ['b', 'a'], rule: 'a' }, ['x'])) ===
    JSON.stringify(['b', 'a']),
  ruleFallback:
    JSON.stringify(statusSelection({ rule: 'a' }, ['x'])) ===
    JSON.stringify(['a']),
  fallback:
    JSON.stringify(statusSelection({}, ['x', 'y'])) ===
    JSON.stringify(['x', 'y'])
};
process.stdout.write(JSON.stringify(out));
"""
        node = shutil.which("node")
        if node is None:
            self.skipTest("node nem érhető el a JS-helper teszthez")
        result = subprocess.run(
            [node, "-e", script],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        for name, value in data.items():
            with self.subTest(name=name):
                self.assertIs(value, True)

    def test_live_rule_notice_translations_present(self) -> None:
        en, de, _, _ = self._i18n_sections()
        for text, english, german in (
            (
                "A módosított szabály miatt az érintett hozzáférés azonnal "
                "visszavonásra került. Az új szabálydefiníció csak külön "
                "engedélyezéssel lép életbe; engedélyezd újra a "
                "hozzáférést.",
                "The affected access was revoked immediately because the "
                "rule was modified. The new rule definition only takes "
                "effect with a separate authorization; authorize access "
                "again.",
                "Der betroffene Zugriff wurde wegen der geänderten Regel "
                "sofort widerrufen. Die neue Regeldefinition wird nur mit "
                "einer gesonderten Autorisierung wirksam; autorisiere den "
                "Zugriff erneut.",
            ),
            (
                "A módosított szabály miatt az érintett hozzáférés azonnal "
                "visszavonásra került. Az új szabálydefiníció csak külön "
                "engedélyezéssel lép életbe; a módosítás oldalon újra "
                "engedélyezheted.",
                "The affected access was revoked immediately because the "
                "rule was modified. The new rule definition only takes "
                "effect with a separate authorization; you can authorize "
                "it again on the modify screen.",
                "Der betroffene Zugriff wurde wegen der geänderten Regel "
                "sofort widerrufen. Die neue Regeldefinition wird nur mit "
                "einer gesonderten Autorisierung wirksam; du kannst ihn "
                "auf der Änderungsseite erneut autorisieren.",
            ),
        ):
            with self.subTest(text=text):
                self.assertIn(f"'{text}': '{english}'", en)
                self.assertIn(f"'{text}': '{german}'", de)


class VersionMetadataTests(unittest.TestCase):
    """A verzió egyetlen forrásból, a VERSION fájlból származik."""

    def test_version_file_and_gateway_agree(self) -> None:
        text = (ROOT / "VERSION").read_text(encoding="utf-8")
        value = text.strip()
        self.assertRegex(value, r"^\d+\.\d+\.\d+$")
        self.assertEqual(value, gateway.APP_VERSION)
        self.assertTrue(text.endswith("\n"))

    def test_changelog_top_matches_version(self) -> None:
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        match = re.search(
            r"^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$",
            changelog,
            re.M,
        )
        self.assertIsNotNone(match, "hiányzó CHANGELOG-verziócím")
        self.assertEqual(match.group(1), gateway.APP_VERSION)

    def test_dockerfile_copies_version(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        copy_line = next(
            line for line in dockerfile.splitlines()
            if line.startswith("COPY ") and "gateway.py" in line
        )
        self.assertIn("VERSION", copy_line.split())

    def test_read_version_is_strict_semver(self) -> None:
        with mock.patch(
            "builtins.open", mock.mock_open(read_data="2.9.0\n")
        ):
            self.assertEqual(gateway._read_version(), "2.9.0")
        # Csak a szigorú x.y.z alak fogadható el; bármi más 0.0.0 lesz,
        # így tetszőleges tartalom nem kerülhet a HTML-be.
        for content in (
            "2.9", "v2.9.0", "<script>", "", "2.9.0-rc1",
            "2.١.0", "２.10.0",
        ):
            with self.subTest(content=content):
                with mock.patch(
                    "builtins.open", mock.mock_open(read_data=content)
                ):
                    self.assertEqual(gateway._read_version(), "0.0.0")
        with mock.patch("builtins.open", side_effect=OSError("nincs")):
            self.assertEqual(gateway._read_version(), "0.0.0")


class TotpQrCodegenTests(unittest.TestCase):
    """A beágyazott qrcodegen valódi mátrixot állít elő (node-dal)."""

    URI = (
        "otpauth://totp/Dropjak:alice?"
        "secret=JBSWY3DPEHPK3PXP&issuer=Dropjak"
    )
    EXPECTED_SIZE = 37
    EXPECTED_VERSION = 5
    EXPECTED_MASK = 4
    EXPECTED_CANONICAL_LENGTH = 1405
    EXPECTED_SHA256 = (
        "c750fdc37790a33c5b9b1bf7ab86f502"
        "515bb2f497b44076afe4e11dcb51a5e6"
    )

    @unittest.skipUnless(shutil.which("node"), "node nem érhető el")
    def test_embedded_qrcodegen_matrix(self) -> None:
        source = (ROOT / "index.html").read_text(encoding="utf-8")
        start_marker = (
            "/*\n * QR Code generator library (compiled from TypeScript)"
        )
        start = source.index(start_marker)
        i18n_start = source.index(
            "/* ============================================================ i18n",
            start,
        )
        end_marker = "})(qrcodegen || (qrcodegen = {}));"
        end = source.rindex(end_marker, start, i18n_start) + len(end_marker)
        library = source[start:end]
        self.assertIn("Project Nayuki", library)
        self.assertIn("MIT License", library)
        self.assertIn("qrcodegen.QrCode", library)

        script = r"""
const fs = require('fs');
const crypto = require('crypto');
const src = fs.readFileSync(process.argv[2], 'utf8');
const qrcodegen = new Function(src + '\nreturn qrcodegen;')();
const qr = qrcodegen.QrCode.encodeText(
  process.argv[3], qrcodegen.QrCode.Ecc.MEDIUM);
const rows = [];
for (let y = 0; y < qr.size; y++) {
  let row = '';
  for (let x = 0; x < qr.size; x++)
    row += qr.getModule(x, y) ? '1' : '0';
  rows.push(row);
}
const canonical = rows.join('\n');
process.stdout.write(JSON.stringify({
  size: qr.size,
  version: qr.version,
  mask: qr.mask,
  canonical_length: canonical.length,
  sha256: crypto.createHash('sha256').update(canonical, 'utf8').digest('hex'),
  rows: rows
}));
"""
        # Az idézett index.html-ből kinyert könyvtár és a futtató szkript
        # külön, a repón kívüli ideiglenes könyvtárba kerül.
        with tempfile.TemporaryDirectory(prefix="hv-qr-") as tmp:
            lib_path = os.path.join(tmp, "qrcodegen.js")
            script_path = os.path.join(tmp, "encode.js")
            Path(lib_path).write_text(library, encoding="utf-8")
            Path(script_path).write_text(script, encoding="utf-8")
            result = subprocess.run(
                [shutil.which("node"), script_path, lib_path, self.URI],
                cwd=tmp, capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["size"], self.EXPECTED_SIZE)
        self.assertEqual(data["version"], self.EXPECTED_VERSION)
        self.assertEqual(data["mask"], self.EXPECTED_MASK)
        self.assertEqual(
            data["canonical_length"], self.EXPECTED_CANONICAL_LENGTH
        )
        self.assertEqual(data["sha256"], self.EXPECTED_SHA256)
        rows = data["rows"]
        self.assertEqual(len(rows), self.EXPECTED_SIZE)
        for row in rows:
            self.assertEqual(len(row), self.EXPECTED_SIZE)
            self.assertEqual(set(row) - {"0", "1"}, set())



# ---------------------------------------------------- drop log és beállítások

def _nl_attr(attr_type: int, payload: bytes) -> bytes:
    length = 4 + len(payload)
    return (
        struct.pack("=HH", length, attr_type)
        + payload
        + b"\x00" * ((4 - length % 4) % 4)
    )


def _ipv4_packet(
    src: str,
    dst: str,
    proto: int = 6,
    sport: int = 0,
    dport: int = 0,
    frag: int = 0,
    icmp_type: int = 8,
) -> bytes:
    if proto in (6, 17):
        transport = struct.pack("!HH", sport, dport)
    elif proto == 1:
        transport = bytes([icmp_type, 0, 0, 0])
    else:
        transport = b""
    total = 20 + len(transport)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, 0, frag, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return header + transport


def _packet_body(
    prefix: bytes = b"dropjak-drop reason=block ",
    packet: bytes = b"",
    ts: float | None = None,
    mark: int = 0x44524A4B,
    ifindex: int = 1,
    mac: str = "aa:bb:cc:dd:ee:ff",
    hook: int = 0,
) -> bytes:
    body = struct.pack("!BBH", socket.AF_INET, 0, 5)
    body += _nl_attr(gateway.droplog.NFULA_PREFIX, prefix + b"\x00")
    body += _nl_attr(gateway.droplog.NFULA_PAYLOAD, packet)
    body += _nl_attr(gateway.droplog.NFULA_MARK, struct.pack("!I", mark))
    if ts is not None:
        seconds = int(ts)
        useconds = int(round((ts - seconds) * 1_000_000))
        body += _nl_attr(
            gateway.droplog.NFULA_TIMESTAMP,
            struct.pack("!QQ", seconds, useconds),
        )
    body += _nl_attr(
        gateway.droplog.NFULA_IFINDEX_INDEV, struct.pack("!I", ifindex)
    )
    if mac:
        body += _nl_attr(
            gateway.droplog.NFULA_HWADDR,
            struct.pack("!HH", 6, 0)
            + bytes.fromhex(mac.replace(":", "")),
        )
    body += _nl_attr(
        gateway.droplog.NFULA_PACKET_HDR,
        struct.pack("!HBB", 0x0800, hook, 0),
    )
    return body


class DropLogParserTests(unittest.TestCase):
    def test_parse_tcp_packet(self) -> None:
        packet = _ipv4_packet("10.0.0.5", "203.0.113.9", 6, 41000, 443)
        record = gateway.droplog.parse_packet_message(
            _packet_body(packet=packet, ts=1_700_000_000.5, hook=0),
            now=time.time(),
        )
        self.assertIsNotNone(record)
        self.assertEqual(record["reason"], "block")
        self.assertEqual(record["src"], "10.0.0.5")
        self.assertEqual(record["dst"], "203.0.113.9")
        self.assertEqual(record["proto"], "tcp")
        self.assertEqual(record["sport"], 41000)
        self.assertEqual(record["dport"], 443)
        self.assertEqual(record["length"], len(packet))
        self.assertEqual(record["mark"], 0x44524A4B)
        self.assertEqual(record["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(record["hook"], 0)
        self.assertTrue(record.get("if_in"))
        self.assertAlmostEqual(record["ts"], 1_700_000_000.5, places=3)
        self.assertIn("T", record["time"])

    def test_parse_udp_icmp_and_fragment(self) -> None:
        udp = gateway.droplog.parse_packet_message(
            _packet_body(
                packet=_ipv4_packet("10.0.0.6", "8.8.8.8", 17, 5353, 53)
            ),
            now=time.time(),
        )
        self.assertEqual(udp["proto"], "udp")
        self.assertEqual(udp["dport"], 53)

        icmp = gateway.droplog.parse_packet_message(
            _packet_body(packet=_ipv4_packet("10.0.0.7", "1.1.1.1", 1)),
            now=time.time(),
        )
        self.assertEqual(icmp["proto"], "icmp")
        self.assertEqual(icmp["icmp_type"], 8)
        self.assertNotIn("sport", icmp)

        fragment = gateway.droplog.parse_packet_message(
            _packet_body(
                packet=_ipv4_packet(
                    "10.0.0.8", "203.0.113.10", 6, 1234, 80, frag=0x2001
                )
            ),
            now=time.time(),
        )
        self.assertEqual(fragment["proto"], "tcp")
        self.assertNotIn("sport", fragment)
        self.assertNotIn("dport", fragment)

    def test_prefix_without_reason_and_missing_payload(self) -> None:
        record = gateway.droplog.parse_packet_message(
            _packet_body(prefix=b"valami mas szoveg "),
            now=1_700_000_000.0,
        )
        self.assertEqual(record["reason"], "valami mas szoveg")
        self.assertEqual(record["src"], "")
        self.assertAlmostEqual(record["ts"], 1_700_000_000.0, places=3)

        unknown = gateway.droplog.parse_packet_message(
            _packet_body(prefix=b""), now=time.time()
        )
        self.assertEqual(unknown["reason"], "unknown")
        self.assertIsNone(gateway.droplog.parse_packet_message(b"\x00"))

    def test_parse_netlink_buffer_with_ack(self) -> None:
        dl = gateway.droplog
        msg_type = (dl.NFNL_SUBSYS_ULOG << 8) | dl.NFULNL_MSG_PACKET
        packet = _ipv4_packet("10.0.0.5", "203.0.113.9", 6, 1000, 80)
        data = dl._nlmsg(msg_type, 0, 1, _packet_body(packet=packet))
        data += dl._nlmsg(dl.NLMSG_ERROR, 0, 2, struct.pack("=i", 0))
        data += dl._nlmsg(dl.NLMSG_NOOP, 0, 3, b"")
        items = dl.parse_netlink_buffer(data, now=time.time())
        self.assertEqual([item["kind"] for item in items], ["packet", "ack"])
        self.assertEqual(items[1]["error"], 0)
        self.assertEqual(items[0]["record"]["dport"], 80)
        self.assertEqual(dl.parse_netlink_buffer(b"\x00\x00"), [])

    def test_netlink_wire_format_is_native_endian(self) -> None:
        """A netlink fejléc/attribútum natív, a csoport-azonosító viszont BE."""
        dl = gateway.droplog
        raw = dl._nlmsg(0x0401, 0x0405, 7, b"\x00" * 4)
        self.assertEqual(raw[:4], struct.pack("=I", len(raw)))
        self.assertEqual(raw[4:6], struct.pack("=H", 0x0401))
        self.assertEqual(raw[6:8], struct.pack("=H", 0x0405))
        self.assertEqual(raw[8:12], struct.pack("=I", 7))
        attr = dl._nla(1, b"\x01")
        self.assertEqual(attr[:2], struct.pack("=H", 5))
        self.assertEqual(attr[2:4], struct.pack("=H", 1))
        self.assertEqual(attr[4:], b"\x01\x00\x00\x00")
        bind = dl._config_message(dl.NFULNL_CFG_CMD_BIND, 5, 123)
        self.assertEqual(bind[:4], struct.pack("=I", len(bind)))
        # nfgenmsg: family, version, majd a csoport __be16-ként.
        self.assertEqual(bind[16:20], b"\x00\x00\x00\x05")
        # A mód üzenet copy_range mezője szintén __be32.
        mode = dl._mode_message(5, 124)
        self.assertEqual(mode[20:22], struct.pack("=H", 10))
        self.assertEqual(mode[22:24], struct.pack("=H", dl.NFULA_CFG_MODE))
        self.assertEqual(mode[24:28], struct.pack("!I", 65535))


class DropLogStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "drops.jsonl")
        self.store = gateway.droplog.DropLog(
            self.path, logger=lambda *_: None
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_write_read_filters_and_permissions(self) -> None:
        now = time.time()
        self.store.write({"ts": now - 30, "src": "10.0.0.1",
                          "dst": "203.0.113.9", "proto": "tcp",
                          "sport": 41000, "dport": 443,
                          "reason": "no-grant"})
        self.store.write({"ts": now - 20, "src": "10.0.0.2",
                          "dst": "203.0.113.9", "proto": "udp",
                          "sport": 5353, "dport": 53, "reason": "block"})
        self.store.write({"ts": now - 10, "src": "10.0.0.1",
                          "dst": "198.51.100.7", "proto": "tcp",
                          "sport": 41001, "dport": 8443,
                          "reason": "block"})

        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600)

        self.assertEqual(len(self.store.read()), 3)
        self.assertEqual(
            [row["dport"] for row in self.store.read()], [8443, 53, 443]
        )
        self.assertEqual(len(self.store.read(src="10.0.0.1")), 2)
        self.assertEqual(len(self.store.read(dst="198.51.100")), 1)
        self.assertEqual(len(self.store.read(proto="udp")), 1)
        self.assertEqual(len(self.store.read(port=443)), 1)
        self.assertEqual(len(self.store.read(port=5353)), 1)
        self.assertEqual(len(self.store.read(reason="block")), 2)
        self.assertEqual(len(self.store.read(q="198.51.100")), 1)
        self.assertEqual(len(self.store.read(before=now - 25)), 1)
        self.assertEqual(len(self.store.read(limit=1)), 1)

        # A hiányzó kötelező mezők pótlódnak, a hosszú szöveg csonkolódik.
        record = self.store.write({"src": "x" * 1000})
        self.assertEqual(record["reason"], "unknown")
        self.assertIn("ts", record)
        self.assertLessEqual(len(record["src"]), 256)

    def test_fail2ban_packet_drops_collapse_to_single_ban_event(self) -> None:
        now = time.time()
        ban = self.store.write({
            "ts": now,
            "src": "192.0.2.9",
            "reason": "fail2ban",
            "event": "ban",
            "attempts": 12,
            "ban_until": now + 3600,
        })
        # A tiltás alatt naplózott, csomagszintű találatok.
        for index in range(20):
            self.store.write({
                "ts": now + 1 + index,
                "src": "192.0.2.9",
                "proto": "tcp",
                "dport": 1000 + index,
                "reason": "fail2ban",
            })
        rows = self.store.read(reason="fail2ban")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "ban")
        self.assertEqual(rows[0]["packets"], 20)
        self.assertEqual(rows[0]["ban_ts"], ban["ts"])
        self.assertEqual(rows[0]["ts"], now + 20)
        self.assertEqual(rows[0]["last_dport"], 1019)
        self.assertEqual(rows[0]["group"], "ban")
        # Más okú bejegyzéseket a szűrés nem érint.
        self.store.write({
            "ts": now + 31,
            "src": "192.0.2.10",
            "reason": "no-grant",
        })
        self.assertEqual(len(self.store.read()), 2)

    def test_legacy_fail2ban_packets_collapse_per_source(self) -> None:
        now = time.time()
        for index in range(5):
            self.store.write({
                "ts": now + index,
                "src": "192.0.2.20",
                "proto": "tcp",
                "dport": 2000 + index,
                "reason": "fail2ban",
            })
        for index in range(3):
            self.store.write({
                "ts": now + 10 + index,
                "src": "192.0.2.21",
                "proto": "tcp",
                "dport": 3000 + index,
                "reason": "fail2ban",
            })
        rows = self.store.read(reason="fail2ban")
        self.assertEqual(len(rows), 2)
        self.assertEqual([row["event"] for row in rows],
                         ["ban-drop", "ban-drop"])
        self.assertEqual(rows[0]["src"], "192.0.2.21")
        self.assertEqual(rows[0]["packets"], 3)
        self.assertEqual(rows[1]["src"], "192.0.2.20")
        self.assertEqual(rows[1]["packets"], 5)
        self.assertEqual(rows[1]["last_dport"], 2004)

    def test_reason_kinds(self) -> None:
        now = time.time()
        self.store.write({"ts": now, "src": "10.0.0.1",
                          "reason": "no-grant"})
        self.store.write({"ts": now + 1, "src": "10.0.0.2",
                          "reason": "spoof-lan"})
        self.store.write({"ts": now + 2, "src": "10.0.0.3",
                          "reason": "some-new-reason"})
        self.assertEqual(len(self.store.read(group="drop")), 3)
        self.assertEqual(len(self.store.read(group="ban")), 0)
        self.assertTrue(all(row.get("group") == "drop"
                            for row in self.store.read()))

    def test_rotation_keeps_old_entries(self) -> None:
        self.store.max_bytes = 200
        for index in range(8):
            self.store.write({
                "ts": time.time() + index,
                "src": f"10.0.0.{index}",
                "proto": "tcp", "dport": 80, "reason": "block",
            })
        self.assertTrue(os.path.exists(self.path + ".1"))
        rows = self.store.read(limit=2000)
        self.assertEqual(len(rows), 8)
        self.assertEqual(rows[0]["src"], "10.0.0.7")
        self.assertEqual(rows[-1]["src"], "10.0.0.0")


class SettingsStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "firewall-settings.json")
        self.store = gateway.settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_crud_and_atomic_commit(self) -> None:
        before = self.store.snapshot()
        self.assertNotIn("host_ssh", before)
        self.assertEqual(before["preauth"], [])
        self.assertEqual(before["error"], "")

        new = self.store.prepare(
            "create", "preauth",
            entry={"label": "Kiosk", "dst": "192.168.50.10",
                   "proto": "tcp", "ports": [443, 80, 443]},
        )
        # A prepare nem ír fájlt és nem módosítja a memóriabeli állapotot.
        self.assertEqual(self.store.snapshot()["preauth"], [])
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(new["preauth"][0]["ports"], [80, 443])
        entry_id = new["preauth"][0]["id"]

        self.store.commit(new)
        self.assertEqual(
            stat.S_IMODE(os.stat(self.path).st_mode), 0o600
        )
        self.assertEqual(
            [name for name in os.listdir(self.tmp.name)
             if name.startswith(".firewall-settings-")],
            [],
        )

        toggled = self.store.prepare(
            "toggle", "preauth", entry_id, {"enabled": False}
        )
        self.store.commit(toggled)
        self.assertFalse(self.store.snapshot()["preauth"][0]["enabled"])

        updated = self.store.prepare(
            "update", "preauth", entry_id,
            {"label": "Kiosk 2", "dst": "192.168.50.11",
             "proto": "tcp", "ports": [8080], "enabled": True},
        )
        self.store.commit(updated)
        reloaded = gateway.settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        )
        entry = reloaded.snapshot()["preauth"][0]
        self.assertEqual(entry["label"], "Kiosk 2")
        self.assertEqual(entry["dst"], "192.168.50.11")
        self.assertTrue(entry["enabled"])

        deleted = self.store.prepare("delete", "preauth", entry_id)
        self.store.commit(deleted)
        self.assertEqual(self.store.snapshot()["preauth"], [])
        self.assertEqual(
            gateway.settings_store.SettingsStore(
                self.path, logger=lambda *_: None
            ).snapshot()["preauth"],
            [],
        )

    def test_validation(self) -> None:
        with self.assertRaises(gateway.settings_store.SettingsError):
            self.store.prepare(
                "create", "preauth",
                entry={"label": "IPv6", "dst": "2001:db8::/32",
                       "proto": "tcp", "ports": [80]},
            )
        with self.assertRaises(gateway.settings_store.SettingsError):
            self.store.prepare(
                "create", "preauth",
                entry={"label": "Multicast", "dst": "224.0.0.1",
                       "proto": "udp", "ports": [53]},
            )
        with self.assertRaises(gateway.settings_store.SettingsError):
            self.store.prepare(
                "create", "block",
                entry={"label": "80 cél nélkül", "proto": "tcp",
                       "ports": [80]},
            )
        with self.assertRaises(gateway.settings_store.SettingsError):
            self.store.prepare(
                "create", "block",
                entry={"label": "Rossz port", "dst": "10.0.0.1",
                       "proto": "tcp", "ports": [0]},
            )
        with self.assertRaises(gateway.settings_store.SettingsError):
            self.store.prepare(
                "create", "block",
                entry={"label": "Rossz proto", "dst": "10.0.0.1",
                       "proto": "icmp", "ports": [80]},
            )
        with self.assertRaises(gateway.settings_store.SettingsError):
            self.store.prepare("host_ssh")
        with self.assertRaises(gateway.settings_store.SettingsError):
            self.store.prepare("ismeretlen")
        with self.assertRaises(gateway.settings_store.SettingsError):
            self.store.prepare(
                "update", "block", "nincs-ilyen",
                {"label": "X", "dst": "10.0.0.1", "proto": "tcp",
                 "ports": [80]},
            )
        # Blokk cél nélkül is érvényes, ha nem a 80-as TCP-port.
        new = self.store.prepare(
            "create", "block",
            entry={"label": "Minden DNS", "proto": "udp", "ports": [53]},
        )
        self.assertEqual(new["block"][0]["dst"], "")
        # Pre-auth cél nélkül is érvényes: minden célra nyit.
        any_dst = self.store.prepare(
            "create", "preauth",
            entry={"label": "Minden Minecraft", "proto": "tcp",
                   "ports": [25565]},
        )
        self.assertEqual(any_dst["preauth"][0]["dst"], "")

    def test_corrupt_file_fails_closed(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{nem json")
        store = gateway.settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        )
        snapshot = store.snapshot()
        self.assertEqual(snapshot["preauth"], [])
        self.assertEqual(snapshot["block"], [])
        self.assertNotIn("host_ssh", snapshot)
        self.assertTrue(snapshot["error"])

        # Egy sikeres mentés törli a hibát és felülírja a sérült fájlt.
        store.commit(store.prepare(
            "create", "preauth",
            entry={"label": "Kiosk", "dst": "192.168.50.10",
                   "proto": "tcp", "ports": [443]},
        ))
        self.assertEqual(store.snapshot()["error"], "")
        fresh = gateway.settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        )
        self.assertEqual(len(fresh.snapshot()["preauth"]), 1)

    def test_legacy_host_ssh_key_is_ignored_on_load(self) -> None:
        # A régi beállításfájl host_ssh kulcsa ismeretlen mező lett: betöltéskor
        # csendben eldobjuk, hibát nem okoz, és a következő mentésből kimarad.
        self.store.commit(self.store.prepare(
            "create", "preauth",
            entry={"label": "Kiosk", "dst": "192.168.50.10",
                   "proto": "tcp", "ports": [443]},
        ))
        raw = json.loads(Path(self.path).read_text(encoding="utf-8"))
        for legacy in ("any", "off", "bogus"):
            with self.subTest(value=legacy):
                raw["host_ssh"] = legacy
                Path(self.path).write_text(
                    json.dumps(raw), encoding="utf-8"
                )
                legacy_store = gateway.settings_store.SettingsStore(
                    self.path, logger=lambda *_: None
                )
                snapshot = legacy_store.snapshot()
                self.assertEqual(snapshot["error"], "")
                self.assertNotIn("host_ssh", snapshot)
                self.assertEqual(len(snapshot["preauth"]), 1)

        legacy_store.set_registration_enabled(True)
        saved = json.loads(Path(self.path).read_text(encoding="utf-8"))
        self.assertNotIn("host_ssh", saved)
        self.assertIs(saved["registration_enabled"], True)

    def test_registration_enabled_default_and_validation(self) -> None:
        self.assertIs(self.store.snapshot()["registration_enabled"], False)
        self.assertIs(
            gateway.settings_store.validate_state(
                {"registration_enabled": True}
            )["registration_enabled"],
            True,
        )
        self.assertIs(
            gateway.settings_store.validate_state({})["registration_enabled"],
            False,
        )
        for value in ("yes", 1, None, [], "true"):
            with self.subTest(value=value):
                with self.assertRaises(gateway.settings_store.SettingsError):
                    gateway.settings_store.validate_state(
                        {"registration_enabled": value}
                    )

    def test_set_registration_enabled_persists_and_toggles(self) -> None:
        preauth = self.store.prepare(
            "create", "preauth",
            entry={"label": "Kiosk", "dst": "192.168.50.10",
                   "proto": "tcp", "ports": [443]},
        )
        blocked = self.store.prepare(
            "create", "block",
            entry={"label": "Minden DNS", "proto": "udp", "ports": [53]},
        )
        self.store.commit(blocked)
        self.store.commit(preauth)
        before = self.store.snapshot()
        self.assertNotIn("host_ssh", before)
        self.assertIs(before["registration_enabled"], False)

        result = self.store.set_registration_enabled(True)
        self.assertIs(result["registration_enabled"], True)
        self.assertIs(self.store.snapshot()["registration_enabled"], True)
        raw = json.loads(Path(self.path).read_text(encoding="utf-8"))
        self.assertIs(raw["registration_enabled"], True)
        self.assertEqual(
            stat.S_IMODE(os.stat(self.path).st_mode), 0o600
        )

        reloaded = gateway.settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        )
        after = reloaded.snapshot()
        self.assertIs(after["registration_enabled"], True)
        self.assertNotIn("host_ssh", after)
        self.assertEqual(after["preauth"], before["preauth"])
        self.assertEqual(after["block"], before["block"])
        self.assertEqual(after["error"], "")

        self.store.set_registration_enabled(False)
        self.assertIs(self.store.snapshot()["registration_enabled"], False)
        self.assertIs(
            gateway.settings_store.SettingsStore(
                self.path, logger=lambda *_: None
            ).snapshot()["registration_enabled"],
            False,
        )
        for value in ("yes", 1, None):
            with self.subTest(value=value):
                with self.assertRaises(gateway.settings_store.SettingsError):
                    self.store.set_registration_enabled(value)
        self.assertIs(self.store.snapshot()["registration_enabled"], False)

    def test_site_name_default_set_persist_and_clear(self) -> None:
        self.assertEqual(self.store.snapshot()["site_name"], "")
        self.assertEqual(
            gateway.settings_store.validate_state({})["site_name"], ""
        )

        result = self.store.set_site_name("  Északi Torony  ")
        self.assertEqual(result["site_name"], "Északi Torony")
        self.assertEqual(
            self.store.snapshot()["site_name"], "Északi Torony"
        )
        raw = json.loads(Path(self.path).read_text(encoding="utf-8"))
        self.assertEqual(raw["site_name"], "Északi Torony")

        reloaded = gateway.settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        )
        self.assertEqual(reloaded.snapshot()["site_name"], "Északi Torony")

        cleared = self.store.set_site_name("")
        self.assertEqual(cleared["site_name"], "")
        self.assertIs(
            gateway.settings_store.SettingsStore(
                self.path, logger=lambda *_: None
            ).snapshot()["site_name"],
            "",
        )

    def test_site_name_validation_and_legacy_files(self) -> None:
        for value in (
            None, 1, True, [], {}, b"dropjak", "x" * 65, "a\nb", "a\x01b",
            "a\x7fb",
        ):
            with self.subTest(value=value):
                with self.assertRaises(gateway.settings_store.SettingsError):
                    self.store.set_site_name(value)
        self.assertEqual(self.store.snapshot()["site_name"], "")

        # A régi fájlban nincs site_name: alapértelmezésként üresen töltődik,
        # és a regisztrációs beállítás továbbra is olvasható.
        Path(self.path).write_text(
            json.dumps({"registration_enabled": True}), encoding="utf-8"
        )
        legacy = gateway.settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        )
        snapshot = legacy.snapshot()
        self.assertEqual(snapshot["site_name"], "")
        self.assertIs(snapshot["registration_enabled"], True)

        # A 64 karakteres név érvényes, a mentés megőrzi.
        maximum = "x" * gateway.settings_store.MAX_SITE_NAME
        self.assertEqual(
            legacy.set_site_name(maximum)["site_name"], maximum
        )


class HostSshPolicyRemovedTests(unittest.TestCase):
    """A régi, állítható host SSH politika és a külön SSH-plumbing eltűnt."""

    def _text(self, name: str) -> str:
        return (ROOT / name).read_text(encoding="utf-8")

    def test_policy_switch_is_gone(self) -> None:
        # A szimbólumneveket darabolva adjuk meg, hogy a forráskódban maradt
        # előfordulásokra kereső ellenőrzés ne találjon hamis találatot.
        env_switch = "HV_" + "HOST_SSH"
        mode_symbol = "host_ssh" + "_mode"
        removed_symbols = (
            env_switch,
            "HOST_SSH" + "_MODE",
            "HOST_SSH" + "_MODES",
            "DEFAULT_" + "HOST_SSH",
            mode_symbol,
            "_host_ssh" + "_wanted",
            "set_" + mode_symbol,
            "host_ssh" + "_policy_applied",
        )
        for name in (".env.example", "docker-compose.yml"):
            with self.subTest(file=name):
                self.assertNotIn(env_switch, self._text(name))

        for name in ("gateway.py", "settings_store.py", "server.py"):
            with self.subTest(file=name):
                text = self._text(name)
                for symbol in removed_symbols:
                    self.assertNotIn(symbol, text)

        for name in ("settings_store.py", "server.py"):
            with self.subTest(file=name):
                self.assertNotIn("host_ssh", self._text(name))

        page = self._text("index.html")
        self.assertNotIn("host_ssh", page)
        self.assertNotIn("Host SSH", page)

    def test_firewall_plumbing_is_gone(self) -> None:
        source = self._text("gateway.py")
        self.assertNotIn('self.ssh_set = "host_ssh_v4"', source)
        self.assertNotIn("def grant_host_ssh(", source)
        self.assertNotIn("def revoke_host_ssh(", source)
        self.assertNotIn('add_simple("host_ssh_v4", "host_ssh")', source)

        nft = self._text("deploy/hatarvedelem.nft")
        self.assertNotIn("host_ssh_v4", nft)
        self.assertNotIn("add set inet hatarvedelem host_ssh_v4", nft)
        self.assertNotIn("\n        tcp dport 22 accept", nft)
        ssh_guard = (
            "tcp dport 22 ct state established,related "
            "ip saddr . tcp dport != @allowed_input_tcp"
        )
        # A naplózó és az eldobó szabály is kizárólag a rendes host
        # szabályból származó engedélyt nézi.
        self.assertEqual(nft.count(ssh_guard), 2)
        self.assertEqual(nft.count(ssh_guard + " drop"), 1)
        self.assertIn(ssh_guard + " limit rate 30/minute", nft)


class FirewallCustomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tools = FakeTools(self.tmp.name)
        self.fw = gateway.Firewall(
            binary=str(self.tools.nft), logger=lambda *_: None,
            lan_if="eth1", wan_if="eth0",
            lan_network=ipaddress.ip_network("192.168.50.0/24"),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_clear_custom_creates_and_flushes_chains(self) -> None:
        self.fw.clear_custom()
        lines = self.tools.script()
        for chain in ("preauth", "block", "preauth_nat", "block_nat"):
            self.assertIn(
                f"add chain inet hatarvedelem {chain}", lines
            )
            self.assertIn(
                f"flush chain inet hatarvedelem {chain}", lines
            )
        self.assertEqual(len(lines), 8)

    def test_apply_custom_rules(self) -> None:
        self.fw.apply_custom(
            preauth=[{"dst": "192.168.50.10", "proto": "tcp",
                      "ports": [80]}],
            block=[{"dst": "10.0.0.0/24", "proto": "tcp",
                    "ports": [80, 443]}],
        )
        script = "\n".join(self.tools.script())
        preauth_lines = [
            line for line in self.tools.script()
            if "inet hatarvedelem preauth " in line
        ]
        self.assertEqual(
            preauth_lines[0],
            "add rule inet hatarvedelem preauth "
            "ip saddr @banned_v4 drop",
        )
        log = (
            'limit rate 30/minute burst 60 packets log prefix '
            '"dropjak-drop reason=block " group 5'
        )
        self.assertIn(
            "add rule inet hatarvedelem block meta l4proto tcp "
            "ct original ip daddr 10.0.0.0/24 ct original proto-dst "
            "{ 80, 443 } " + log,
            script,
        )
        self.assertIn(
            "add rule inet hatarvedelem block meta l4proto tcp "
            "ct original ip daddr 10.0.0.0/24 ct original proto-dst "
            "{ 80, 443 } drop",
            script,
        )
        self.assertIn(
            "add rule inet hatarvedelem block_nat meta l4proto tcp "
            "ct original ip daddr 10.0.0.0/24 ct original proto-dst 80 "
            "drop",
            script,
        )
        self.assertIn(
            'add rule inet hatarvedelem preauth iifname "eth1" '
            "meta l4proto tcp ct original ip daddr 192.168.50.10/32 "
            "ct original proto-dst 80 "
            f"meta mark set {self.fw.fwd_mark} accept",
            script,
        )
        self.assertIn(
            'add rule inet hatarvedelem preauth iifname "eth0" '
            "ct status dnat meta l4proto tcp "
            "ct original ip daddr 192.168.50.10/32 "
            "ct original proto-dst 80 "
            f"meta mark set {self.fw.fwd_mark} accept",
            script,
        )
        self.assertIn(
            "add rule inet hatarvedelem preauth ct state established "
            "meta l4proto tcp ct original ip daddr 192.168.50.10/32 "
            "ct original proto-dst 80 "
            f"meta mark set {self.fw.fwd_mark} accept",
            script,
        )
        self.assertIn(
            "add rule inet hatarvedelem preauth ct state related "
            "ct original ip daddr 192.168.50.10/32 "
            f"meta mark set {self.fw.fwd_mark} accept",
            script,
        )
        self.assertIn(
            "add rule inet hatarvedelem preauth_nat meta l4proto tcp "
            "ct original ip daddr 192.168.50.10/32 ct original proto-dst 80 "
            f"ct mark set {gateway.PREAUTH_CT_MARK}",
            script,
        )

    def test_preauth_any_destination(self) -> None:
        self.fw.apply_custom(
            preauth=[{"dst": "", "proto": "tcp", "ports": [25565]}]
        )
        script = "\n".join(self.tools.script())
        self.assertIn(
            'add rule inet hatarvedelem preauth iifname "eth1" '
            "meta l4proto tcp ct original proto-dst 25565 "
            f"meta mark set {self.fw.fwd_mark} accept",
            script,
        )
        self.assertIn(
            'add rule inet hatarvedelem preauth iifname "eth0" '
            "ct status dnat meta l4proto tcp ct original proto-dst 25565 "
            f"meta mark set {self.fw.fwd_mark} accept",
            script,
        )
        preauth_lines = [
            line for line in self.tools.script()
            if "inet hatarvedelem preauth " in line
        ]
        self.assertTrue(preauth_lines)
        self.assertFalse(
            any("ct original ip daddr" in line for line in preauth_lines)
        )
        # Cél nélkül nincs széles related szabály.
        self.assertFalse(
            any("ct state related" in line for line in preauth_lines)
        )

    def test_disabled_entries_are_not_installed(self) -> None:
        self.fw.apply_custom(
            preauth=[
                {"dst": "", "proto": "tcp", "ports": [25565],
                 "enabled": True},
                {"dst": "", "proto": "tcp", "ports": [25566],
                 "enabled": False},
            ],
            block=[
                {"dst": "10.0.0.0/24", "proto": "tcp", "ports": [443],
                 "enabled": True},
                {"dst": "10.9.9.0/24", "proto": "tcp", "ports": [8443],
                 "enabled": False},
            ],
        )
        script = "\n".join(self.tools.script())
        self.assertIn("ct original proto-dst 25565", script)
        self.assertNotIn("25566", script)
        self.assertIn("ct original ip daddr 10.0.0.0/24", script)
        self.assertNotIn("10.9.9.0/24", script)
        self.assertNotIn("8443", script)

    def test_only_disabled_preauth_does_not_require_lan_interface(self) -> None:
        no_lan = gateway.Firewall(
            binary=str(self.tools.nft), logger=lambda *_: None,
            lan_if="", lan_network=None,
        )
        no_lan.apply_custom(
            preauth=[{"dst": "192.168.50.10", "proto": "tcp",
                      "ports": [80], "enabled": False}]
        )
        preauth_lines = [
            line for line in self.tools.script()
            if "inet hatarvedelem preauth " in line
        ]
        # A kikapcsolt pre-auth bejegyzés nem kerül be; csak a tiltott
        # forrásokat mindenképp kizáró védőszabály marad.
        self.assertEqual(
            preauth_lines,
            ["add rule inet hatarvedelem preauth "
             "ip saddr @banned_v4 drop"],
        )

    def test_preauth_requires_lan_interface(self) -> None:
        no_lan = gateway.Firewall(
            binary=str(self.tools.nft), logger=lambda *_: None,
            lan_if="", lan_network=None,
        )
        with self.assertRaises(gateway.FirewallError):
            no_lan.apply_custom(
                preauth=[{"dst": "192.168.50.10", "proto": "tcp",
                          "ports": [80]}]
            )
        # Blokk szabály LAN interfész nélkül is alkalmazható.
        no_lan.apply_custom(
            block=[{"dst": "10.0.0.0/24", "proto": "udp", "ports": [53]}]
        )
        with self.assertRaises(gateway.FirewallError):
            no_lan.apply_custom(
                block=[{"dst": "10.0.0.0/24", "proto": "icmp",
                        "ports": [1]}]
            )


class RulesetTemplateTests(unittest.TestCase):
    """A telepített nftables sablon biztonsági sorrendje."""

    @classmethod
    def setUpClass(cls) -> None:
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "deploy",
            "hatarvedelem.nft",
        )
        with open(path, encoding="utf-8") as fh:
            cls.text = fh.read()
        cls.forward = cls.text.split("chain forward {", 1)[1].split(
            "chain input {", 1
        )[0]

    def test_banned_sources_are_dropped_before_preauth(self) -> None:
        self.assertIn("ip saddr @banned_v4 drop", self.forward)
        self.assertLess(
            self.forward.index("ip saddr @banned_v4 drop"),
            self.forward.index("jump preauth"),
        )

    def test_host_input_sets_and_accepts(self) -> None:
        input_chain = self.text.split("chain input {", 1)[1].split(
            "chain prerouting {", 1
        )[0]
        prerouting = self.text.split("chain prerouting {", 1)[1]
        for token in (
            "add set inet hatarvedelem allowed_input_tcp {",
            "add set inet hatarvedelem allowed_input_udp {",
            "ip saddr . tcp dport @allowed_input_tcp "
            "tcp dport != 8100 accept",
            "ip saddr . udp dport @allowed_input_udp "
            "udp dport != 8100 accept",
            "ip saddr . tcp dport @allowed_input_tcp "
            "ip saddr . ether saddr != @client_mac drop",
            "ip saddr . udp dport @allowed_input_udp "
            "ip saddr . ether saddr != @client_mac drop",
            "iifname \"__LAN_IF__\" meta l4proto tcp "
            "ip saddr . ct original proto-dst @allowed_input_tcp return",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.text)

        accept = input_chain.index(
            "ip saddr . tcp dport @allowed_input_tcp "
            "tcp dport != 8100 accept"
        )
        # A 22-es port szándékosan nincs kizárva a host elfogadásból: azt
        # admin által létrehozott host szabály megnyithatja. Csak a 8100
        # (portál) fenntartott, és az UDP elfogadás is csak azt zárja ki.
        accept_line = input_chain.splitlines()[input_chain[:accept].count("\n")]
        self.assertIn("tcp dport != 8100", accept_line)
        self.assertNotIn("tcp dport != 22", accept_line)
        self.assertIn(
            "ip saddr . udp dport @allowed_input_udp "
            "udp dport != 8100 accept",
            input_chain,
        )
        # A tiltás és a MAC-kötés előbb fut, mint a host elfogadás.
        self.assertLess(input_chain.index("ip saddr @banned_v4 drop"), accept)
        self.assertLess(
            input_chain.index(
                "ip saddr . tcp dport @allowed_input_tcp "
                "ip saddr . ether saddr != @client_mac drop"
            ),
            accept,
        )
        # A host TCP 80 megkerüli a portál-átirányítást.
        self.assertLess(
            prerouting.index(
                "ip saddr . ct original proto-dst @allowed_input_tcp return"
            ),
            prerouting.index(
                "meta l4proto tcp ct original proto-dst 80 redirect"
            ),
        )

    def test_host_revocation_guard_sets_and_order(self) -> None:
        # A host portok csak bővülő kerneloldali halmazai.
        self.assertIn(
            "add set inet hatarvedelem host_service_tcp {\n"
            "    type inet_service",
            self.text,
        )
        self.assertIn(
            "add set inet hatarvedelem host_service_udp {\n"
            "    type inet_service",
            self.text,
        )
        input_chain = self.text.split("chain input {", 1)[1].split(
            "chain prerouting {", 1
        )[0]
        # A host-őr csomagszintű: az input lánc csak a kliens→host irányt
        # látja, a portál-átirányított csomagok célportja pedig már 8100.
        # Protokollonként egy naplózó és egy eldobó szabály.
        tcp_guard = input_chain.index("tcp dport @host_service_tcp")
        udp_guard = input_chain.index("udp dport @host_service_udp")
        generic_accept = input_chain.index(
            "ct state established,related accept"
        )
        guard_block = input_chain[tcp_guard:generic_accept]
        self.assertEqual(
            guard_block.count("tcp dport @host_service_tcp"), 2
        )
        self.assertEqual(
            guard_block.count("udp dport @host_service_udp"), 2
        )
        self.assertEqual(
            guard_block.count(
                "ip saddr . tcp dport != @allowed_input_tcp"
            ),
            2,
        )
        self.assertEqual(
            guard_block.count(
                "ip saddr . udp dport != @allowed_input_udp"
            ),
            2,
        )
        # A TCP 22-es portot az általános host-őr szándékosan kiveszi: a
        # host_service_tcp csak bővül, ezért a 22 bekerülhet egy host
        # szabály miatt, és a kivétel nélkül a host-22 engedélyt is
        # eldobná. A 22-t kizárólag a fenti SSH-specifikus őr kezeli.
        tcp_guard_line = (
            "tcp dport @host_service_tcp tcp dport != 22 "
            "ct state established,related"
        )
        self.assertEqual(guard_block.count(tcp_guard_line), 2)
        # Az UDP őr nem kap ilyen kivételt: az SSH-őr TCP-only, a UDP 22
        # közönséges host-szabály-port.
        self.assertNotIn("udp dport != 22", guard_block)
        # Az eredeti tuple-ra épülő, széles forward-kivételek helyett a
        # csomag szintű dport a kulcs; ezek nem szerepelhetnek az őrben.
        for forbidden in (
            "ct original",
            "meta l4proto",
            "@allowed_v4",
            "@allowed_tcp",
            "@allowed_udp",
            "udp sport != 68",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, guard_block)

        # A host-DNS established kivételei szűken, csak a 53-as portra
        # érvényesek, és az őr előtt futnak.
        dns_accepts = (
            'iifname "__LAN_IF__" tcp dport 53 ct state established,'
            "related ip saddr @allowed_v4 accept",
            'iifname "__LAN_IF__" tcp dport 53 ct state established,'
            "related ip saddr . tcp dport @allowed_tcp accept",
            'iifname "__LAN_IF__" udp dport 53 ct state established,'
            "related ip saddr @allowed_v4 accept",
            'iifname "__LAN_IF__" udp dport 53 ct state established,'
            "related ip saddr . udp dport @allowed_udp accept",
        )
        for rule in dns_accepts:
            with self.subTest(rule=rule):
                self.assertIn(rule, input_chain)
                self.assertLess(input_chain.index(rule), tcp_guard)
        self.assertLess(
            input_chain.index("reason=dns-revoked"),
            input_chain.index(dns_accepts[0]),
        )
        # A DHCP-elfogadás a host-őr előtt, pontosan egyszer szerepel az
        # SSH-őr utáni szakaszban; a fail2ban-kivételként korábban álló
        # azonos szabály változatlanul megmarad. A generikus established-
        # accept után már nem lehet DHCP-elfogadás (a régi másolat törölve).
        ssh_guard = input_chain.index("reason=ssh-revoked")
        dhcp_accept = (
            'iifname "__LAN_IF__" udp sport 68 udp dport 67 accept'
        )
        self.assertEqual(
            input_chain[ssh_guard:tcp_guard].count(dhcp_accept), 1
        )
        self.assertLess(
            input_chain.index(dhcp_accept, ssh_guard), tcp_guard
        )
        self.assertNotIn(dhcp_accept, input_chain[generic_accept:])

        # Az SSH-őr után, de az általános established-accept előtt futnak,
        # különben a meglévő kapcsolat megkerülné a host engedélyt.
        self.assertLess(ssh_guard, tcp_guard)
        self.assertLess(tcp_guard, udp_guard)
        self.assertLess(udp_guard, generic_accept)
        self.assertIn("reason=host-revoked", input_chain)

    def test_dns_revoked_guard_spares_authorized_host_tcp_53(self) -> None:
        start = self.text.index("A meglévő TCP DNS-kapcsolat")
        end = self.text.index("Meglévő SSH-kapcsolat")
        block = self.text[start:end]
        # A naplózó és az eldobó szabály is kiveszi az engedélyezett host
        # TCP 53 kapcsolatot; a valódi jogosultságot a host_service_* őr
        # ellenőrzi.
        self.assertEqual(
            block.count("ip saddr . tcp dport != @allowed_input_tcp"),
            2,
        )
        self.assertIn("reason=dns-revoked", block)

    def test_entrypoint_warns_about_lockout_before_firewall(self) -> None:
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "docker",
            "entrypoint.sh",
        )
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        start = text.index("warn_lockout() {")
        end = text.index("\n}", start)
        warning = text[start:end]
        for token in (
            'log "FIGYELEM', "SSH", "22/TCP", "admin",
            "HV_ADMIN_ENABLED", "HV_ADMIN_PASSWORD_FILE", "konzol",
        ):
            self.assertIn(token, warning, token)
        main = text[text.index("skip_firewall=$(env_bool HV_SKIP_FIREWALL 0)"):]
        self.assertLess(
            main.index("warn_lockout"), main.index("load_firewall")
        )
        # A HV_SKIP_FIREWALL=1 ágban nincs figyelmeztetés (nincs tűzfal).
        skip_branch = main[
            main.index('if [ "$skip_firewall" = "1" ]; then'):
            main.index("else")
        ]
        self.assertNotIn("warn_lockout", skip_branch)

    def test_entrypoint_flushes_input_sets_but_keeps_service_sets(self) -> None:
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "docker",
            "entrypoint.sh",
        )
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        flush_loop = text.split("for hv_set in ", 1)[1].split("; do", 1)[0]
        for set_name in ("allowed_input_tcp", "allowed_input_udp"):
            self.assertIn(set_name, flush_loop)
        # A host_service_* halmazok add-only védőhalmazok: újraindításkor
        # sem szabad őket kiüríteni.
        self.assertNotIn("host_service_tcp", flush_loop)
        self.assertNotIn("host_service_udp", flush_loop)

    def test_entrypoint_stale_ssh_set_failure_only_warns(self) -> None:
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "docker",
            "entrypoint.sh",
        )
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        start = text.index(
            'if "$NFT_BIN" list set inet hatarvedelem host_ssh_v4'
        )
        end = text.index("# A hoston korán betöltött", start)
        block = text[start:end]
        # A meglévő halmazt továbbra is csak a list set sikeressége után
        # töröljük, és a sikeres törlést naplózzuk.
        self.assertIn("list set inet hatarvedelem host_ssh_v4", block)
        self.assertIn("delete set inet hatarvedelem host_ssh_v4", block)
        self.assertIn('log "a régi host_ssh_v4 halmaz törölve"', block)
        # Hiba esetén viszont nem szabad leállítani az indulást: a
        # szabálykészlet már betöltődött, a portálnak el kell indulnia.
        self.assertIn("FIGYELEM", block)
        self.assertNotIn("die ", block)
        self.assertNotIn("exit ", block)

    def test_entrypoint_lockout_warning_accepts_env_bool_spellings(self) -> None:
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "docker",
            "entrypoint.sh",
        )
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        start = text.index("warn_lockout() {")
        end = text.index("\n}", start) + 2
        function = text[start:end]
        script = (
            "log() { printf '%s\\n' \"$*\"; }\n"
            + function
            + "\nwarn_lockout\n"
        )
        message = "nincs beállított induláskori admin"

        def run(enabled: str) -> str:
            env = os.environ.copy()
            env.pop("HV_ADMIN_PASSWORD_FILE", None)
            env["HV_ADMIN_ENABLED"] = enabled
            env["HV_ADMIN_PASSWORD"] = "titok"
            result = subprocess.run(
                ["sh", "-c", script],
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

        # A gateway.py _env_bool() által elfogadott igaz értékek nem
        # kelthetnek hamis kizárási figyelmeztetést.
        for value in ("1", "true", "TRUE", "yes", "Yes", "on", "ON", " on "):
            with self.subTest(value=value):
                self.assertNotIn(message, run(value))
        for value in ("0", "false", "off", ""):
            with self.subTest(value=value):
                self.assertIn(message, run(value))

    def test_banned_packets_are_logged_with_rate_limit(self) -> None:
        # A tiltás alatti forgalom mintavételezve naplózódik, hogy a
        # drop log mutassa a további próbálkozásokat; a portál ezeket a
        # tiltás egyetlen eseményéhez rendeli.
        self.assertIn('reason=fail2ban ', self.text)
        self.assertIn("ip saddr @banned_v4 limit rate", self.forward)
        self.assertLess(
            self.forward.index("ip saddr @banned_v4 limit rate"),
            self.forward.index("ip saddr @banned_v4 drop"),
        )
        self.assertIn(
            "ip saddr @banned_v4 limit rate", self.text.split(
                "chain input {", 1)[1]
        )


class FakeBanFirewall:
    """A fail2ban tesztekhez elég tűzfal: hívásokat naplóz."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.fail = False

    def ban(self, ip: str, ttl: int) -> None:
        if self.fail:
            raise gateway.FirewallError("nft hiba")
        self.calls.append(("ban", ip, ttl))

    def unban(self, ip: str) -> None:
        self.calls.append(("unban", ip))

    def sync_bans(self, elements) -> None:
        self.calls.append(("sync", list(elements)))

    def sync_proxy_bans(self, elements) -> None:
        self.proxy_elements = list(elements)


class Fail2banTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "fail2ban.json")
        self.fw = FakeBanFirewall()
        self.manager = self.make_manager()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def make_manager(self, **kwargs):
        options = {
            "enabled": True,
            "max_attempts": 3,
            "window_seconds": 60,
            "ban_seconds": 120,
            "drop_enabled": True,
            "drop_max": 5,
            "drop_ports": 4,
            "drop_window_seconds": 60,
        }
        options.update(kwargs)
        return fail2ban_mod.Fail2ban(
            self.fw, path=self.path, logger=lambda *_: None, **options
        )

    def test_normalize_ip_rejects_unsafe_addresses(self) -> None:
        for value in (
            "127.0.0.1", "0.0.0.0", "224.0.0.1", "239.255.255.250",
            "255.255.255.255", "::1", "2001:db8::1", "nem-ip", "",
        ):
            with self.assertRaises(
                fail2ban_mod.Fail2banError, msg=value
            ):
                fail2ban_mod.normalize_ip(value)
        self.assertEqual(fail2ban_mod.normalize_ip("192.0.2.10"), "192.0.2.10")
        self.assertEqual(
            fail2ban_mod.normalize_ip(" 192.0.2.10 "), "192.0.2.10"
        )
        # A portál saját 127.0.0.1-e kivétel; más loopback cím tesztelhető.
        self.assertEqual(fail2ban_mod.normalize_ip("127.0.0.9"), "127.0.0.9")

    def test_auto_ban_after_threshold(self) -> None:
        ip = "192.0.2.10"
        self.assertIsNone(self.manager.record_failure(ip, "alice"))
        self.assertIsNone(self.manager.record_failure(ip, "alice"))
        view = self.manager.record_failure(ip, "alice")
        self.assertIsNotNone(view)
        self.assertEqual(view["ip"], ip)
        self.assertEqual(view["attempts"], 3)
        self.assertFalse(view["manual"])
        self.assertGreater(view["remaining"], 0)
        self.assertIn(("ban", ip, 120), self.fw.calls)
        self.assertTrue(os.path.exists(self.path))
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(self.manager.snapshot()["pending"], [])

        again = self.manager.record_failure(ip, "alice")
        self.assertIsNotNone(again)
        self.assertEqual(again["until"], view["until"])
        self.assertEqual(
            sum(1 for call in self.fw.calls if call[0] == "ban"), 1
        )

    def test_state_owner_defaults_to_state_directory(self) -> None:
        info = os.stat(self.tmp.name)
        self.assertEqual(
            self.manager._state_owner(self.tmp.name),
            (info.st_uid, info.st_gid),
        )

    def test_root_cli_save_preserves_state_owner(self) -> None:
        # A CLI rootként fut, a portál viszont a szolgáltatásfelhasználóval.
        # A mentésnek meg kell tartania a meglévő fájl tulajdonosát, különben
        # a futó portál a következő mentésnél már nem tudná írni.
        self.manager.ban("192.0.2.20", 120, manual=True)
        info = os.stat(self.path)
        self.assertEqual(
            self.manager._state_owner(self.tmp.name),
            (info.st_uid, info.st_gid),
        )
        calls = []
        with mock.patch.object(fail2ban_mod.os, "geteuid", return_value=0), \
                mock.patch.object(
                    fail2ban_mod.os, "chown",
                    side_effect=lambda *args: calls.append(args),
                ):
            self.assertTrue(self.manager.unban("192.0.2.20"))
        self.assertTrue(calls)
        self.assertEqual(calls[-1][1:], (info.st_uid, info.st_gid))

    def write_state(self, payload) -> None:
        """A CLI-hoz hasonló külső, atomi fájlírás."""
        tmp = self.path + ".external"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, self.path)

    def test_external_cli_ban_is_reloaded(self) -> None:
        self.manager.ban("192.0.2.10", 120, manual=True)
        with open(self.path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        now = time.time()
        payload["bans"].append({
            "ip": "192.0.2.30", "since": now, "until": now + 120,
            "attempts": 0, "user": "cli", "manual": True,
        })
        self.write_state(payload)
        ips = {ban["ip"] for ban in self.manager.snapshot()["bans"]}
        self.assertEqual(ips, {"192.0.2.10", "192.0.2.30"})
        self.assertIsNotNone(self.manager.banned("192.0.2.30"))

    def test_external_cli_unban_is_reloaded(self) -> None:
        self.manager.ban("192.0.2.10", 120, manual=True)
        with open(self.path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        payload["bans"] = []
        self.write_state(payload)
        self.assertIsNone(self.manager.banned("192.0.2.10"))
        self.assertEqual(self.manager.snapshot()["bans"], [])

    def test_loopback_portal_traffic_is_exempt(self) -> None:
        for _ in range(5):
            self.assertIsNone(
                self.manager.record_failure("127.0.0.1", "alice")
            )
        self.assertEqual(self.fw.calls, [])

    def test_success_clears_pending_attempts(self) -> None:
        ip = "192.0.2.11"
        self.assertIsNone(self.manager.record_failure(ip, "alice"))
        self.assertIsNone(self.manager.record_failure(ip, "alice"))
        self.manager.record_success(ip)
        self.assertIsNone(self.manager.record_failure(ip, "alice"))
        self.assertEqual(self.manager.snapshot()["pending"][0]["count"], 1)

    def test_manual_ban_persists_and_unban(self) -> None:
        view = self.manager.ban("192.0.2.20", 600, manual=True, user="root")
        self.assertEqual(view["ip"], "192.0.2.20")
        self.assertTrue(view["manual"])
        self.assertIn(("ban", "192.0.2.20", 600), self.fw.calls)

        reloaded = self.make_manager()
        bans = reloaded.snapshot()["bans"]
        self.assertEqual([row["ip"] for row in bans], ["192.0.2.20"])
        self.assertTrue(bans[0]["manual"])
        self.assertEqual(bans[0]["user"], "root")

        self.assertTrue(self.manager.unban("192.0.2.20"))
        self.assertFalse(self.manager.unban("192.0.2.20"))
        self.assertIn(("unban", "192.0.2.20"), self.fw.calls)

    def test_ban_validation_never_reaches_firewall(self) -> None:
        for payload in (
            ("127.0.0.1", 600),
            ("0.0.0.0", 600),
            ("10.0.0.0/8", 600),
            ("nem-ip", 600),
            ("192.0.2.21", 30),
            ("192.0.2.21", "600"),
        ):
            with self.assertRaises(fail2ban_mod.Fail2banError, msg=payload):
                self.manager.ban(*payload)
        self.assertEqual(self.fw.calls, [])

    def test_configure_validates_and_disabling_keeps_manual_bans(self) -> None:
        for _ in range(3):
            self.manager.record_failure("192.0.2.30", "alice")
        self.manager.ban("192.0.2.31", 600, manual=True)
        self.fw.calls.clear()

        snapshot = self.manager.configure({"enabled": False})
        self.assertFalse(snapshot["enabled"])
        bans = {row["ip"] for row in snapshot["bans"]}
        self.assertEqual(bans, {"192.0.2.31"})
        self.assertIn(("unban", "192.0.2.30"), self.fw.calls)
        self.assertNotIn(("unban", "192.0.2.31"), self.fw.calls)
        self.assertEqual(snapshot["pending"], [])
        # Kikapcsolva a további kísérletek nem tiltanak.
        for _ in range(5):
            self.assertIsNone(
                self.manager.record_failure("192.0.2.32", "alice")
            )

        snapshot = self.manager.configure({
            "enabled": True, "max_attempts": 7,
            "window_seconds": 90, "ban_seconds": 240,
        })
        self.assertTrue(snapshot["enabled"])
        self.assertEqual(snapshot["max_attempts"], 7)
        self.assertEqual(snapshot["window_seconds"], 90)
        self.assertEqual(snapshot["ban_seconds"], 240)

        for bad in (
            {"max_attempts": 0}, {"max_attempts": True},
            {"window_seconds": 10}, {"ban_seconds": 5},
            {"enabled": "igen"},
        ):
            with self.assertRaises(
                fail2ban_mod.Fail2banError, msg=bad
            ):
                self.manager.configure(bad)

    def test_sync_restores_remaining_ttl(self) -> None:
        self.manager.ban("192.0.2.40", 600, manual=True)
        self.fw.calls.clear()
        self.assertTrue(self.manager.sync())
        sync_calls = [call for call in self.fw.calls if call[0] == "sync"]
        self.assertEqual(len(sync_calls), 1)
        elements = sync_calls[0][1]
        self.assertEqual(elements[0][0], "192.0.2.40")
        self.assertTrue(540 <= elements[0][1] <= 600)

    def test_expired_ban_is_pruned(self) -> None:
        self.manager.ban("192.0.2.41", 600, manual=True)
        self.manager._bans["192.0.2.41"]["until"] = time.time() - 1
        self.assertEqual(self.manager.snapshot()["banned_count"], 0)
        self.assertIsNone(self.manager.banned("192.0.2.41"))

    def test_firewall_failure_keeps_attempts_and_retries(self) -> None:
        ip = "192.0.2.50"
        self.fw.fail = True
        self.assertIsNone(self.manager.record_failure(ip, "alice"))
        self.assertIsNone(self.manager.record_failure(ip, "alice"))
        with self.assertRaises(fail2ban_mod.Fail2banError):
            self.manager.record_failure(ip, "alice")
        self.assertEqual(self.manager.snapshot()["bans"], [])
        self.fw.fail = False
        view = self.manager.record_failure(ip, "alice")
        self.assertIsNotNone(view)
        self.assertEqual(view["attempts"], 4)

    def test_drop_threshold_bans_with_source_and_detail(self) -> None:
        ip = "192.0.2.60"
        manager = self.make_manager(drop_max=3, drop_ports=10)
        self.assertIsNone(manager.record_drop(
            ip, proto="tcp", dport=80, reason="input-wan"
        ))
        self.assertIsNone(manager.record_drop(
            ip, proto="tcp", dport=80, reason="input-wan"
        ))
        view = manager.record_drop(
            ip, proto="tcp", dport=80, reason="wan-drop"
        )
        self.assertIsNotNone(view)
        self.assertEqual(view["source"], "drop")
        self.assertEqual(view["detail"], "wan-drop")
        self.assertEqual(view["attempts"], 3)
        self.assertFalse(view["manual"])
        self.assertIn(("ban", ip, 120), self.fw.calls)

        snapshot = manager.snapshot()
        self.assertEqual(snapshot["drop_pending"], [])
        ban = snapshot["bans"][0]
        self.assertEqual(ban["source"], "drop")
        self.assertEqual(ban["detail"], "wan-drop")
        self.assertEqual(snapshot["drop_max"], 3)

        # A forrás és a részlet a mentésből is visszatöltődik.
        reloaded = self.make_manager()
        ban = reloaded.snapshot()["bans"][0]
        self.assertEqual(ban["source"], "drop")
        self.assertEqual(ban["detail"], "wan-drop")

    def test_drop_distinct_ports_detect_port_scan(self) -> None:
        ip = "192.0.2.61"
        manager = self.make_manager(drop_max=1000, drop_ports=4)
        for port in (22, 22, 80, 443):
            self.assertIsNone(manager.record_drop(
                ip, proto="tcp", dport=port, reason="input-wan"
            ), port)
        view = manager.record_drop(
            ip, proto="tcp", dport=8080, reason="input-wan"
        )
        self.assertIsNotNone(view)
        self.assertEqual(view["source"], "drop")
        self.assertEqual(view["attempts"], 5)
        self.assertIn(("ban", ip, 120), self.fw.calls)

    def test_drop_count_threshold_with_same_port(self) -> None:
        ip = "192.0.2.62"
        manager = self.make_manager(drop_max=3, drop_ports=10)
        for _ in range(2):
            self.assertIsNone(manager.record_drop(
                ip, proto="tcp", dport=443, reason="no-grant"
            ))
        view = manager.record_drop(
            ip, proto="tcp", dport=443, reason="no-grant"
        )
        self.assertIsNotNone(view)
        self.assertEqual(view["attempts"], 3)
        self.assertIn(("ban", ip, 120), self.fw.calls)

    def test_drop_window_prunes_old_events(self) -> None:
        ip = "192.0.2.63"
        manager = self.make_manager(drop_max=3, drop_ports=10)
        manager.record_drop(ip, proto="tcp", dport=22, reason="input-wan")
        # A régi esemény kívül kerül az időablakon, ezért nem számít.
        manager._drop_events[ip]["events"][0] = (
            time.time() - manager._config["drop_window_seconds"] - 5,
            "tcp/22",
            True,
        )
        for port in (80, 443):
            self.assertIsNone(manager.record_drop(
                ip, proto="tcp", dport=port, reason="input-wan"
            ), port)
        pending = manager.snapshot()["drop_pending"]
        self.assertEqual(pending[0]["count"], 2)
        self.assertEqual(pending[0]["distinct_ports"], 2)

    def test_drop_pending_lists_threshold_progress(self) -> None:
        ip = "192.0.2.64"
        manager = self.make_manager(drop_max=10, drop_ports=6)
        manager.record_drop(ip, proto="tcp", dport=22, reason="input-lan")
        manager.record_drop(ip, proto="tcp", dport=80, reason="input-lan")
        pending = manager.snapshot()["drop_pending"]
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["ip"], ip)
        self.assertEqual(pending[0]["count"], 2)
        self.assertEqual(pending[0]["distinct_ports"], 2)
        self.assertEqual(pending[0]["ports"], [22, 80])
        self.assertEqual(pending[0]["max_drops"], 10)
        self.assertEqual(pending[0]["max_ports"], 6)
        self.assertEqual(pending[0]["reason"], "input-lan")

    def test_lan_events_do_not_reach_the_packet_threshold(self) -> None:
        # Egy kijelentkezett böngésző sok azonos portú próbát indít; ezek
        # csak a portdiverzitáshoz számítanak, a csomagküszöbhöz nem.
        manager = self.make_manager(drop_max=2, drop_ports=10)
        ip = "192.0.2.71"
        for _ in range(5):
            self.assertIsNone(manager.record_drop(
                ip, proto="tcp", dport=443, reason="no-grant",
                count_total=False,
            ))
        pending = manager.snapshot()["drop_pending"][0]
        self.assertEqual(pending["count"], 0)
        self.assertEqual(pending["events"], 5)
        # A WAN-felőli események viszont a csomagküszöbhöz is számítanak.
        self.assertIsNone(manager.record_drop(
            ip, proto="tcp", dport=443, reason="input-wan"
        ))
        view = manager.record_drop(
            ip, proto="tcp", dport=443, reason="input-wan"
        )
        self.assertIsNotNone(view)
        self.assertEqual(view["attempts"], 7)

    def test_drop_disabled_and_exempt_addresses_are_ignored(self) -> None:
        manager = self.make_manager(drop_max=1, drop_ports=1)
        for ip in ("127.0.0.1", "0.0.0.0", "::1", "nem-ip"):
            self.assertIsNone(manager.record_drop(
                ip, proto="tcp", dport=22, reason="input-wan"
            ), ip)
        self.assertEqual(manager.snapshot()["drop_pending"], [])
        self.assertFalse(self.fw.calls)

        manager.configure({"drop_enabled": False})
        self.assertIsNone(manager.record_drop(
            "192.0.2.65", proto="tcp", dport=22, reason="input-wan"
        ))
        self.assertEqual(manager.snapshot()["drop_pending"], [])

    def test_disabling_drop_releases_only_drop_bans(self) -> None:
        manager = self.make_manager(drop_max=1, drop_ports=1)
        drop_ip = "192.0.2.66"
        login_ip = "192.0.2.67"
        self.assertIsNotNone(manager.record_drop(
            drop_ip, proto="tcp", dport=22, reason="input-wan"
        ))
        for _ in range(3):
            manager.record_failure(login_ip, "alice")
        manager.ban("192.0.2.68", 600, manual=True)
        self.fw.calls.clear()

        snapshot = manager.configure({"drop_enabled": False})
        self.assertFalse(snapshot["drop_enabled"])
        self.assertIn(("unban", drop_ip), self.fw.calls)
        bans = {row["ip"] for row in snapshot["bans"]}
        self.assertEqual(bans, {login_ip, "192.0.2.68"})

        # Újra bekapcsolva a két mérőszámot a drop-számlálás ismét tilt.
        manager.configure({
            "drop_count_enabled": True,
            "drop_ports_enabled": True,
        })
        self.assertIsNotNone(manager.record_drop(
            "192.0.2.69", proto="tcp", dport=22, reason="input-wan"
        ))

    def test_drop_ban_survives_restart_and_expires(self) -> None:
        manager = self.make_manager(drop_max=1, drop_ports=1)
        ip = "192.0.2.70"
        self.assertIsNotNone(manager.record_drop(
            ip, proto="tcp", dport=22, reason="input-wan"
        ))
        self.assertIsNotNone(manager.banned(ip))
        manager._bans[ip]["until"] = time.time() - 1
        self.assertIsNone(manager.banned(ip))

    def test_corrupt_state_file_fails_closed(self) -> None:
        Path(self.path).write_text("{", encoding="utf-8")
        manager = self.make_manager()
        snapshot = manager.snapshot()
        self.assertEqual(snapshot["bans"], [])
        self.assertTrue(snapshot["error"])


class DropBanWiringTests(unittest.TestCase):
    """A drop log és a fail2ban közötti szűrés."""

    class CaptureFail2ban:
        def __init__(self) -> None:
            self.calls: list[tuple] = []

        def record_drop(self, ip, **kwargs):
            self.calls.append((ip, kwargs))

    def make_gateway(self):
        gw = object.__new__(gateway.Gateway)
        gw.fail2ban = self.CaptureFail2ban()
        return gw

    def record(self, **overrides):
        row = {
            "src": "192.0.2.80",
            "proto": "tcp",
            "dport": 22,
            "reason": "input-wan",
        }
        row.update(overrides)
        return row

    def test_scanner_reasons_are_forwarded(self) -> None:
        gw = self.make_gateway()
        for reason in ("no-grant", "wan-drop", "input-wan", "input-lan"):
            gw._on_drop(self.record(reason=reason, dport=1000 + len(reason)))
        self.assertEqual(len(gw.fail2ban.calls), 4)
        self.assertEqual(
            gw.fail2ban.calls[0],
            ("192.0.2.80", {
                "proto": "tcp", "dport": 1008, "reason": "no-grant",
                "count_total": False,
            }),
        )
        self.assertTrue(gw.fail2ban.calls[1][1]["count_total"])  # wan-drop
        self.assertTrue(gw.fail2ban.calls[2][1]["count_total"])  # input-wan
        self.assertFalse(gw.fail2ban.calls[3][1]["count_total"])  # input-lan

    def test_non_scanning_events_are_ignored(self) -> None:
        gw = self.make_gateway()
        # Nem támadási okok: MAC/spoof/ipv6/fail2ban/DNS/SSH visszavonás.
        for reason in (
            "mac", "spoof-lan", "spoof-wan", "ipv6", "fail2ban",
            "ssh-revoked", "dns-revoked", "container-spoof",
            "container-pivot", "ismeretlen", "",
        ):
            gw._on_drop(self.record(reason=reason))
        # UDP-háttérzaj (mDNS, LLMNR, NetBIOS, DNS) nem számít.
        gw._on_drop(self.record(proto="udp", dport=5353, reason="input-lan"))
        gw._on_drop(self.record(proto="udp", dport=53, reason="input-lan"))
        gw._on_drop(self.record(proto="icmp", dport=None, reason="input-wan"))
        # A DNS és a portál TCP-portja kimarad.
        gw._on_drop(self.record(proto="tcp", dport=53, reason="input-lan"))
        gw._on_drop(self.record(proto="tcp", dport=gateway.PORT,
                                reason="input-lan"))
        # Forrás nélküli esemény.
        gw._on_drop(self.record(src=""))
        self.assertEqual(gw.fail2ban.calls, [])

    def test_callback_error_does_not_break_the_listener(self) -> None:
        class FakeStore:
            path = "drops.jsonl"

            def __init__(self) -> None:
                self.written = []

            def write(self, record) -> None:
                self.written.append(record)

        store = FakeStore()
        listener = droplog.DropLogListener(store, logger=lambda *_: None)
        seen = []
        listener.set_on_drop(seen.append)
        listener._count_packet({"src": "192.0.2.81", "reason": "input-wan"})
        self.assertEqual(seen, [{"src": "192.0.2.81", "reason": "input-wan"}])
        self.assertEqual(len(store.written), 1)

        def boom(_record):
            raise RuntimeError("callback hiba")

        listener.set_on_drop(boom)
        # A visszahívás hibája nem szakítja meg az NFLOG feldolgozást.
        listener._count_packet({"src": "192.0.2.82", "reason": "input-wan"})
        self.assertEqual(len(store.written), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
