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
import socket
import stat
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402
import server    # noqa: E402


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
                    if set_name in ("allowed_tcp", "allowed_udp")
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


def solve(challenge: dict) -> dict:
    zeros = "0" * int(challenge["difficulty"])
    n = 0
    while True:
        if hashlib.sha256(f'{challenge["salt"]}{n}'.encode()).hexdigest().startswith(zeros):
            return {**challenge, "number": n}
        n += 1


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
                "nft delete element inet hatarvedelem host_ssh_v4 { 192.168.50.23 }",
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
            3 + len(CATALOG.all_tcp_ports()) + len(CATALOG.all_udp_ports()),
        )
        for line in (
            "nft delete element inet hatarvedelem allowed_v4 { 192.168.50.23 }",
            "nft delete element inet hatarvedelem allowed_icmp { 192.168.50.23 }",
            "nft delete element inet hatarvedelem host_ssh_v4 { 192.168.50.23 }",
            "nft delete element inet hatarvedelem allowed_tcp { 192.168.50.23 . 80 }",
            "nft delete element inet hatarvedelem allowed_udp { 192.168.50.23 . 53 }",
            "nft delete element inet hatarvedelem allowed_udp { 192.168.50.23 . 51820 }",
        ):
            self.assertIn(line, lines)

    def test_grant_host_ssh_uses_dedicated_set(self) -> None:
        self.fw.grant_host_ssh("192.168.50.23", 120)
        self.assertEqual(
            self.tools.script(),
            [
                "add element inet hatarvedelem host_ssh_v4 "
                "{ 192.168.50.23 timeout 120s }"
            ],
        )
        self.assertIn(
            "nft delete element inet hatarvedelem host_ssh_v4 { 192.168.50.23 }",
            self.tools.deletes(),
        )

    def test_revoke_host_ssh_is_idempotent(self) -> None:
        self.fw.revoke_host_ssh("192.168.50.23")
        self.assertEqual(
            self.tools.deletes(),
            [
                "nft delete element inet hatarvedelem host_ssh_v4 { 192.168.50.23 }",
            ],
        )
        self.fw.revoke_host_ssh("nem-ip")
        self.fw.revoke_host_ssh("2001:db8::1")
        self.assertEqual(len(self.tools.deletes()), 1)

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
        self.tools.set_json("host_ssh_v4", [
            {"val": "192.168.50.23", "timeout": 90, "expires": 80},
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

    def test_group_snapshot_marks_orphans_and_mismatches(self) -> None:
        snapshot = {
            "table": "hatarvedelem",
            "generated": 1,
            "sets": {
                "allowed_v4": [],
                "allowed_icmp": [],
                "host_ssh_v4": [],
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
        self.assertIn("hiányzó host SSH", alice["mismatch"])
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
                "host_ssh_v4": [{"address": "10.0.0.9", "expires_in": 60,
                                 "timeout": 60}],
                "allowed_tcp": [],
                "allowed_udp": [],
            },
            "errors": [],
        }
        sessions = [{
            "user": "root", "ip": "10.0.0.9", "authorized": True,
            "tcp": [], "udp": [], "icmp": True, "full": True,
            "rule": "admin-full", "rule_label": "Admin",
            "ports_label": "Minden port", "expires_in": 60, "logged_in": 1,
        }]
        grouped = gateway.group_firewall_snapshot(snapshot, sessions)
        row = grouped["ips"][0]
        self.assertTrue(row["in_sync"], row)
        self.assertEqual(row["mismatch"], [])
        self.assertTrue(row["full"])
        self.assertTrue(row["icmp"])
        self.assertTrue(row["host_ssh"])
        self.assertEqual(row["ports_label"], "Minden port")
        self.assertEqual(grouped["counts"]["mismatched"], 0)


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
        self.assertFalse(
            any("client_mac" in line for line in self.tools.lines()),
            self.tools.lines(),
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
        self.assertEqual(gateway.Firewall.parse_mac_json("{nem json", "x"), [])

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
            self.fw, ttl=3600, pending_ttl=600, host_ssh_mode="any"
        )
        self.web_rule = make_rule("web-only", ("web",))
        self.icmp_rule = make_rule("icmp-only", ("icmp",))

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
            "add element inet hatarvedelem host_ssh_v4 { 192.168.50.23 timeout 90s }",
        ):
            self.assertIn(line, script)
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
            "nft delete element inet hatarvedelem host_ssh_v4 { 192.168.50.23 }",
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
        self.assertIn(
            "nft delete element inet hatarvedelem host_ssh_v4 { 192.168.50.23 }",
            deletes,
        )
        script = self.tools.script()
        self.assertIn(
            "add element inet hatarvedelem allowed_icmp { 192.168.50.23 timeout 60s }",
            script,
        )
        self.assertIn(
            "add element inet hatarvedelem host_ssh_v4 { 192.168.50.23 timeout 60s }",
            script,
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
        self.assertTrue(
            any("host_ssh_v4 { 192.168.50.23 }" in line for line in lines), lines
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
        self.assertIn(
            "nft delete element inet hatarvedelem host_ssh_v4 { 192.168.50.23 }",
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
        self.assertIn(
            "nft delete element inet hatarvedelem host_ssh_v4 { 192.168.50.23 }",
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

    # -- host SSH házirend --------------------------------------------------

    def _host_ssh_script(self, manager: gateway.SessionManager, role: str) -> list[str]:
        session = manager.login("user", "192.168.50.23", role=role)
        manager.authorize(session.token, "192.168.50.23", self.web_rule, 60)
        return [
            line for line in self.tools.script()
            if "host_ssh_v4" in line
        ]

    def test_host_ssh_default_admin_only(self) -> None:
        manager = gateway.SessionManager(
            self.fw, ttl=3600, pending_ttl=600, host_ssh_mode="admin"
        )
        self.assertEqual(
            self._host_ssh_script(manager, gateway.ROLE_USER), []
        )
        self.tools.clear()
        self.assertEqual(
            len(self._host_ssh_script(manager, gateway.ROLE_ADMIN)), 1
        )

    def test_host_ssh_off_grants_nothing(self) -> None:
        manager = gateway.SessionManager(
            self.fw, ttl=3600, pending_ttl=600, host_ssh_mode="off"
        )
        self.assertEqual(
            self._host_ssh_script(manager, gateway.ROLE_ADMIN), []
        )

    def test_host_ssh_any_grants_every_session(self) -> None:
        manager = gateway.SessionManager(
            self.fw, ttl=3600, pending_ttl=600, host_ssh_mode="any"
        )
        self.assertEqual(
            len(self._host_ssh_script(manager, gateway.ROLE_USER)), 1
        )

    def test_unknown_host_ssh_mode_falls_back_to_admin(self) -> None:
        manager = gateway.SessionManager(
            self.fw, ttl=3600, pending_ttl=600, host_ssh_mode="bogus"
        )
        self.assertEqual(manager.host_ssh_mode, "admin")

    # -- versenyhelyzetek és leállás ---------------------------------------

    def test_rule_check_rejects_removed_rule(self) -> None:
        manager = gateway.SessionManager(
            self.fw, ttl=3600, pending_ttl=600, host_ssh_mode="any",
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
        self.assertIn(
            "nft delete element inet hatarvedelem host_ssh_v4 "
            "{ 192.168.50.23 }",
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

    def test_set_host_ssh_mode_narrowing_revokes_ssh(self) -> None:
        alice = self.sessions.login("alice", "192.168.50.23")
        root = self.sessions.login(
            "root", "192.168.50.24", role=gateway.ROLE_ADMIN
        )
        self.sessions.authorize(
            alice.token, "192.168.50.23", self.web_rule, 60
        )
        self.sessions.authorize(
            root.token, "192.168.50.24", self.web_rule, 60
        )
        ssh_delete = (
            "nft delete element inet hatarvedelem host_ssh_v4 "
            "{ %s }"
        )
        self.tools.clear()
        self.assertEqual(self.sessions.set_host_ssh_mode("admin"), [])
        deletes = self.tools.deletes()
        self.assertIn(ssh_delete % "192.168.50.23", deletes)
        self.assertNotIn(ssh_delete % "192.168.50.24", deletes)

        self.tools.clear()
        self.assertEqual(self.sessions.set_host_ssh_mode("off"), [])
        deletes = self.tools.deletes()
        self.assertIn(ssh_delete % "192.168.50.23", deletes)
        self.assertIn(ssh_delete % "192.168.50.24", deletes)

        # Bővítéskor a meglévő munkamenetek nem kapnak utólag SSH-t.
        self.tools.clear()
        self.assertEqual(self.sessions.set_host_ssh_mode("any"), [])
        self.assertEqual(self.tools.deletes(), [])

    def test_set_host_ssh_mode_rejects_invalid(self) -> None:
        with self.assertRaises(ValueError):
            self.sessions.set_host_ssh_mode("sometimes")
        self.assertEqual(self.sessions.host_ssh_mode, "any")


# ------------------------------------------------------------------ egyéb mag

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

class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tools = FakeTools(cls.tmp.name)
        cls._old_conntrack = gateway.CONNTRACK_BIN
        cls._old_difficulty = gateway.POW_DIFFICULTY
        cls._old_portal_url = gateway.PORTAL_URL
        cls._old_host_ssh_mode = gateway.HOST_SSH_MODE
        gateway.CONNTRACK_BIN = str(cls.tools.conntrack)
        gateway.POW_DIFFICULTY = 2
        gateway.PORTAL_URL = ""
        # A HTTP-tesztek a visszafelé kompatibilis "any" módot vizsgálják;
        # a szűkebb alapértelmezést külön tesztek fedik le.
        gateway.HOST_SSH_MODE = "any"

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
        cls.gw = gateway.Gateway(
            users=cls.users, firewall=cls.fw, catalog=CATALOG,
            rules=cls.rules, groups=cls.groups, audit=cls.audit,
            rate_limiter=gateway.RateLimiter(window=60, maximum=1000),
        )
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
        gateway.CONNTRACK_BIN = cls._old_conntrack
        gateway.POW_DIFFICULTY = cls._old_difficulty
        gateway.PORTAL_URL = cls._old_portal_url
        gateway.HOST_SSH_MODE = cls._old_host_ssh_mode
        cls.tmp.cleanup()

    def setUp(self) -> None:
        self.tools.clear()
        self.tools.clear_fail()
        self.tools.clear_json()

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
            "add element inet hatarvedelem host_ssh_v4 { 127.0.0.1 timeout 60s }",
        ):
            self.assertIn(line, script)
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
            self.rules.create(gateway.ADMIN_RULE_ID, {"tcp": [80]})
        with self.assertRaises(gateway.RuleStoreError):
            self.rules.update(gateway.ADMIN_RULE_ID, {"tcp": [80]})
        with self.assertRaises(gateway.RuleStoreError):
            self.rules.delete(gateway.ADMIN_RULE_ID)
        self.rules.delete("web-only")
        self.assertIsNone(self.rules.get("web-only"))

    def test_empty_rules_file_is_not_reseeded(self) -> None:
        path = os.path.join(self.tmp.name, "empty-rules.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"rules": {}}, fh)
        store = gateway.RuleStore(path, catalog=CATALOG, logger=lambda *_: None)
        self.assertEqual(store.persisted_rules(), [])
        self.assertEqual(
            [rule.id for rule in store.all_rules()], [gateway.ADMIN_RULE_ID]
        )

    def test_legacy_services_are_migrated_with_backup(self) -> None:
        path = os.path.join(self.tmp.name, "legacy-rules.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "rules": {
                    "web-only": {
                        "label": "Csak web", "services": ["web"],
                        "default_ttl": 60, "max_ttl": 600,
                    },
                    "admin-full": {"services": ["all"]},
                }
            }, fh)
        store = gateway.RuleStore(path, catalog=CATALOG, logger=lambda *_: None)
        rule = store.get("web-only")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.tcp, (80, 443))
        self.assertEqual(rule.udp, (443,))
        self.assertFalse(rule.full)
        with open(path, encoding="utf-8") as fh:
            stored = json.load(fh)["rules"]["web-only"]
        self.assertEqual(stored["tcp"], [80, 443])
        self.assertEqual(stored["udp"], [443])
        self.assertNotIn("services", stored)
        backups = list(Path(self.tmp.name).glob(
            "legacy-rules.json.services-backup-*"
        ))
        self.assertEqual(len(backups), 1)
        with open(backups[0], encoding="utf-8") as fh:
            legacy = json.load(fh)["rules"]["web-only"]
        self.assertEqual(legacy["services"], ["web"])

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
        self.assertEqual(root_rules, [gateway.ADMIN_RULE_ID])
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


class AdminHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tools = FakeTools(cls.tmp.name)
        cls._old_conntrack = gateway.CONNTRACK_BIN
        cls._old_difficulty = gateway.POW_DIFFICULTY
        cls._old_portal_url = gateway.PORTAL_URL
        cls._old_host_ssh_mode = gateway.HOST_SSH_MODE
        gateway.CONNTRACK_BIN = str(cls.tools.conntrack)
        gateway.POW_DIFFICULTY = 2
        gateway.PORTAL_URL = ""
        # A HTTP-tesztek a visszafelé kompatibilis "any" módot vizsgálják;
        # a szűkebb alapértelmezést külön tesztek fedik le.
        gateway.HOST_SSH_MODE = "any"

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
        cls.groups = gateway.GroupStore(
            os.path.join(cls.tmp.name, "groups.json"), logger=lambda *_: None
        )
        cls.audit = gateway.AuditLog(
            os.path.join(cls.tmp.name, "audit.jsonl"), logger=lambda *_: None
        )
        cls.users.add(
            "root", "root-jelszo-1", role=gateway.ROLE_ADMIN
        )
        cls.users.add("alice", "alice-jelszo-1", rules=("web-only",))
        cls.users.add("resetme", "resetme-jelszo-1", rules=("web-only",))
        cls.fw = gateway.Firewall(
            binary=str(cls.tools.nft), logger=lambda *_: None, lan_if="eth1"
        )
        cls.settings = gateway.settings_store.SettingsStore(
            os.path.join(cls.tmp.name, "firewall-settings.json"),
            logger=lambda *_: None, default_host_ssh="any",
        )
        cls.drops = gateway.droplog.DropLogService(
            os.path.join(cls.tmp.name, "drops.jsonl"),
            enabled=False, logger=lambda *_: None,
        )
        cls.gw = gateway.Gateway(
            users=cls.users, firewall=cls.fw, catalog=CATALOG,
            rules=cls.rules, groups=cls.groups, audit=cls.audit,
            rate_limiter=gateway.RateLimiter(window=60, maximum=1000),
            settings=cls.settings, drops=cls.drops,
        )
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
        gateway.CONNTRACK_BIN = cls._old_conntrack
        gateway.POW_DIFFICULTY = cls._old_difficulty
        gateway.PORTAL_URL = cls._old_portal_url
        gateway.HOST_SSH_MODE = cls._old_host_ssh_mode
        cls.tmp.cleanup()

    def setUp(self) -> None:
        self.tools.clear()
        self.tools.clear_fail()
        self.tools.clear_json()
        # A beállítások és a drop napló közös a tesztek között; minden teszt
        # ismert, üres állapotból induljon.
        self.gw.settings.commit(
            {"host_ssh": "any", "preauth": [], "block": []}
        )
        self.gw.sessions.host_ssh_mode = "any"
        base = self.drops.store.path
        for suffix in ("", ".1", ".2", ".3", ".4", ".5"):
            try:
                os.unlink(base + suffix)
            except FileNotFoundError:
                pass

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
        self.tools.set_json("host_ssh_v4", [
            {"val": "127.0.0.2", "timeout": 120, "expires": 100},
        ])

        status, _, body = self.get(
            "/api/admin/firewall", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["counts"]["ips"], 1)
        self.assertEqual(data["counts"]["entries"], 4)
        self.assertEqual(data["counts"]["orphans"], 0)
        row = data["ips"][0]
        self.assertEqual(row["ip"], "127.0.0.2")
        self.assertEqual(row["users"], ["alice"])
        self.assertEqual(row["ports_label"], "TCP 80, 443 · UDP 443")
        self.assertEqual([entry["port"] for entry in row["tcp"]], [80, 443])
        self.assertEqual([entry["port"] for entry in row["udp"]], [443])
        self.assertIsNotNone(row["host_ssh"])
        self.assertTrue(row["in_sync"], row)
        self.assertEqual(row["rules"][0]["label"], "Csak web")
        self.assertEqual(row["sessions"][0]["user"], "alice")
        self.assertTrue(row["sessions"][0]["authorized"])

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
        self.assertIn(
            "nft delete element inet hatarvedelem host_ssh_v4 { 127.0.0.2 }",
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

    def test_admin_state_and_admin_full_access(self) -> None:
        cookie = self.admin_cookie()
        status, _, body = self.get("/api/admin/state", cookie=cookie, source="127.0.0.5")
        self.assertEqual(status, 200, body)
        state = json.loads(body)
        self.assertTrue(state["ok"])
        self.assertEqual(state["builtin_rule"], gateway.ADMIN_RULE_ID)
        names = [user["name"] for user in state["users"]]
        self.assertIn("alice", names)
        root = next(user for user in state["users"] if user["name"] == "root")
        self.assertIn(gateway.ADMIN_RULE_ID, root["effective_rules"])
        alice = next(user for user in state["users"] if user["name"] == "alice")
        self.assertEqual(alice["rules"], ["web-only"])

        status, _, body = self.post(
            "/api/access", {"rule": gateway.ADMIN_RULE_ID, "ttl": 60},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertEqual(data["rule"], gateway.ADMIN_RULE_ID)
        self.assertTrue(data["grant"]["full"])
        script = self.tools.script()
        self.assertIn(
            "add element inet hatarvedelem allowed_v4 { 127.0.0.5 timeout 60s }",
            script,
        )
        self.assertIn(
            "add element inet hatarvedelem host_ssh_v4 { 127.0.0.5 timeout 60s }",
            script,
        )

    def test_user_cannot_request_admin_rule(self) -> None:
        cookie, _ = self.login("alice", "alice-jelszo-1")
        status, _, body = self.post(
            "/api/access", {"rule": gateway.ADMIN_RULE_ID, "ttl": 60},
            cookie=cookie,
        )
        self.assertEqual(status, 400, body)
        self.assertIn("nem tartozik", json.loads(body)["error"])

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

    def test_admin_settings_crud_and_host_ssh(self) -> None:
        cookie = self.admin_cookie()

        status, _, body = self.get(
            "/api/admin/settings", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["settings"]["host_ssh"], "any")
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
            {"action": "host_ssh", "host_ssh": "off"},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["settings"]["host_ssh"], "off")
        self.assertEqual(self.gw.sessions.host_ssh_mode, "off")

        status, _, body = self.post(
            "/api/admin/settings",
            {"action": "delete", "kind": "preauth", "id": entry_id},
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["settings"]["preauth"], [])

        # A mentett állapot újratöltve is megmarad.
        self.gw.settings.load()
        self.assertEqual(self.gw.settings.snapshot()["host_ssh"], "off")

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
            {"action": "host_ssh", "host_ssh": "mindig"},
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
            self.path, logger=lambda *_: None, default_host_ssh="off"
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_crud_and_atomic_commit(self) -> None:
        before = self.store.snapshot()
        self.assertEqual(before["host_ssh"], "off")
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
            self.store.prepare("host_ssh", host_ssh="mindig")
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
            self.path, logger=lambda *_: None, default_host_ssh="any"
        )
        snapshot = store.snapshot()
        self.assertEqual(snapshot["preauth"], [])
        self.assertEqual(snapshot["block"], [])
        self.assertEqual(snapshot["host_ssh"], "any")
        self.assertTrue(snapshot["error"])

        # Egy sikeres mentés törli a hibát és felülírja a sérült fájlt.
        store.commit(store.prepare("host_ssh", host_ssh="admin"))
        self.assertEqual(store.snapshot()["error"], "")
        fresh = gateway.settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        )
        self.assertEqual(fresh.snapshot()["host_ssh"], "admin")


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
