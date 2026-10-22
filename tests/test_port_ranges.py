#!/usr/bin/env python3
"""Porttartományok: egység-, nft- és csomagszintű tesztek."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import gateway  # noqa: E402
from test_gateway import FakeTools  # noqa: E402

IP = "192.168.50.23"
RANGE = tuple(range(8000, 8101))


class PortParsingTests(unittest.TestCase):
    def test_mixed_list_is_merged_and_expanded(self) -> None:
        self.assertEqual(
            gateway._clean_ports(
                ["25565", "27000-27015", "27010-27020", "25566"], "tcp"
            ),
            (25565, 25566) + tuple(range(27000, 27021)),
        )

    def test_adjacent_ranges_merge(self) -> None:
        self.assertEqual(
            gateway._clean_ports("8000-8005, 8006-8010", "tcp"),
            tuple(range(8000, 8011)),
        )

    def test_en_dash_is_accepted(self) -> None:
        self.assertEqual(
            gateway._clean_ports("8000–8002", "tcp"), (8000, 8001, 8002)
        )

    def test_reversed_and_invalid_ranges_are_rejected(self) -> None:
        for value in ("8100-8000", "1-", "a-b", "0-10", "65000-70000"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    gateway._clean_ports(value, "tcp")

    def test_expanded_port_limit_is_enforced(self) -> None:
        with self.assertRaises(ValueError):
            gateway._clean_ports("1-300", "tcp")

    def test_reserved_port_inside_range_is_rejected_for_input(self) -> None:
        with self.assertRaises(ValueError):
            gateway._validate_host_ports(
                "input",
                gateway.Ports(tcp=tuple(range(8090, 8110)), direction="input"),
            )

    def test_tcp_22_remains_a_valid_host_port(self) -> None:
        gateway._validate_host_ports(
            "input", gateway.Ports(tcp=(20, 21, 22), direction="input")
        )

    def test_storage_round_trip_keeps_old_lists_and_ranges(self) -> None:
        rule = gateway.Rule(
            id="range", label="Range", description="",
            tcp=(20, 21, 22, 80),
        )
        stored = gateway.RuleStore._rule_storage(rule)
        self.assertEqual(stored["tcp"], ["20-22", 80])
        self.assertEqual(
            gateway._clean_ports(stored["tcp"], "tcp"),
            (20, 21, 22, 80),
        )

    def test_label_uses_en_dash(self) -> None:
        self.assertEqual(
            gateway.Ports(tcp=RANGE).label(), "TCP 8000–8100"
        )


class FirewallRangeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tools = FakeTools(self.tmp.name)
        self.fw = gateway.Firewall(
            table="hatarvedelem", set_name="allowed_v4",
            binary=str(self.tools.nft), dry_run=False,
            logger=lambda *_: None,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_grant_writes_one_interval_element(self) -> None:
        self.fw.grant(IP, gateway.Ports(tcp=RANGE), 120)
        self.assertEqual(
            self.tools.script(),
            [
                "add element inet hatarvedelem allowed_tcp "
                f"{{ {IP} . 8000-8100 timeout 120s }}"
            ],
        )

    def test_subset_grant_does_not_extend_the_outer_range(self) -> None:
        self.tools.set_json("allowed_tcp", [{
            "val": {"concat": [IP, {"range": [8000, 8100]}]},
            "timeout": 60, "expires": 40,
        }])
        self.fw.grant(IP, gateway.Ports(tcp=tuple(range(8050, 8061))), 120)
        script = self.tools.script()
        self.assertIn(
            f"add element inet hatarvedelem allowed_tcp "
            f"{{ {IP} . 8000-8049 timeout 40s }}", script,
        )
        self.assertIn(
            f"add element inet hatarvedelem allowed_tcp "
            f"{{ {IP} . 8050-8060 timeout 120s }}", script,
        )
        self.assertIn(
            f"add element inet hatarvedelem allowed_tcp "
            f"{{ {IP} . 8061-8100 timeout 40s }}", script,
        )
        self.assertIn(
            f"nft delete element inet hatarvedelem allowed_tcp "
            f"{{ {IP} . 8000-8100 }}", self.tools.deletes(),
        )

    def test_partial_revoke_preserves_the_rest_with_remaining_ttl(self) -> None:
        self.tools.set_json("allowed_tcp", [{
            "val": {"concat": [IP, {"range": [8000, 8100]}]},
            "timeout": 60, "expires": 40,
        }])
        self.fw.revoke(IP, gateway.Ports(tcp=tuple(range(8050, 8061))))
        script = self.tools.script()
        self.assertIn(
            f"add element inet hatarvedelem allowed_tcp "
            f"{{ {IP} . 8000-8049 timeout 40s }}", script,
        )
        self.assertIn(
            f"add element inet hatarvedelem allowed_tcp "
            f"{{ {IP} . 8061-8100 timeout 40s }}", script,
        )
        self.assertFalse(any("8050-8060" in line for line in script), script)

    def test_single_port_revoke_inside_range_keeps_the_range(self) -> None:
        self.tools.set_json("allowed_tcp", [{
            "val": {"concat": [IP, {"range": [8000, 8100]}]},
            "timeout": 60, "expires": 30,
        }])
        self.fw.revoke(IP, gateway.Ports(tcp=(8050,)))
        script = self.tools.script()
        self.assertIn(
            f"add element inet hatarvedelem allowed_tcp "
            f"{{ {IP} . 8000-8049 timeout 30s }}", script,
        )
        self.assertIn(
            f"add element inet hatarvedelem allowed_tcp "
            f"{{ {IP} . 8051-8100 timeout 30s }}", script,
        )

    def test_listing_failure_does_not_delete_existing_range(self) -> None:
        (self.tools.json_dir / "allowed_tcp.json").write_text(
            "not json", encoding="utf-8"
        )
        self.fw.grant(IP, gateway.Ports(tcp=tuple(range(8050, 8061))), 120)
        self.assertEqual(self.tools.deletes(), [])
        self.assertEqual(
            self.tools.script(),
            [
                "add element inet hatarvedelem allowed_tcp "
                f"{{ {IP} . 8050-8060 timeout 120s }}"
            ],
        )

    def test_parse_set_json_exposes_the_range_end(self) -> None:
        payload = json.dumps({"nftables": [{"set": {
            "name": "allowed_tcp", "elem": [{
                "elem": {
                    "val": {"concat": [IP, {"range": [8000, 8100]}]},
                    "timeout": 60, "expires": 50,
                }
            }],
        }}]})
        entry = gateway.Firewall.parse_set_json(
            payload, "allowed_tcp"
        )[0]
        self.assertEqual(entry["port"], 8000)
        self.assertEqual(entry["port_end"], 8100)

    def test_service_set_ranges_are_expanded(self) -> None:
        payload = json.dumps({"nftables": [{"set": {
            "name": "host_service_tcp",
            "elem": [22, {"range": [8000, 8002]}],
        }}]})
        self.assertEqual(
            gateway.Firewall.parse_service_set_json(
                payload, "host_service_tcp"
            ),
            {22, 8000, 8001, 8002},
        )

    def test_host_sync_adds_only_uncovered_ranges(self) -> None:
        self.tools.set_json("host_service_tcp", [{
            "elem": {"range": [8000, 8100]},
        }])
        self.fw.sync_host_ports({8050, 8200}, set())
        self.assertEqual(
            self.tools.script(),
            ["add element inet hatarvedelem host_service_tcp { 8200 }"],
        )

    def test_prune_keeps_range_elements(self) -> None:
        self.tools.set_json("host_service_tcp", [{
            "elem": {"range": [8000, 8100]},
        }])
        gateway.CONNTRACK_BIN = ""
        self.tools.clear()
        summary = self.fw.prune_host_service_ports(set(), set())
        self.assertEqual(summary["removed_tcp"], [])
        self.assertEqual(
            [line for line in self.tools.script()
             if line.startswith("delete element")],
            [],
        )

    def test_firewall_group_label_shows_range(self) -> None:
        snapshot = {"errors": [], "sets": {
            "allowed_tcp": [{
                "address": IP, "port": 8000, "port_end": 8100,
                "timeout": 120, "expires_in": 100,
            }],
            "allowed_udp": [], "allowed_v4": [], "allowed_icmp": [],
            "client_mac": [], "allowed_input_tcp": [],
            "allowed_input_udp": [],
        }}
        payload = gateway.group_firewall_snapshot(snapshot, [])
        self.assertEqual(payload["ips"][0]["ports_label"], "TCP 8000–8100")


class PackagingTests(unittest.TestCase):
    def test_interval_sets_and_migration_are_declared(self) -> None:
        template = (ROOT / "deploy" / "hatarvedelem.nft").read_text(
            encoding="utf-8"
        )
        for set_name in (
            "allowed_tcp", "allowed_udp",
            "allowed_input_tcp", "allowed_input_udp",
        ):
            block = template.split(
                f"add set inet hatarvedelem {set_name} {{", 1
            )[1].split("}", 1)[0]
            self.assertIn("flags interval,timeout", block, set_name)
        for set_name in ("host_service_tcp", "host_service_udp"):
            block = template.split(
                f"add set inet hatarvedelem {set_name} {{", 1
            )[1].split("}", 1)[0]
            self.assertIn("flags interval", block, set_name)
            self.assertNotIn("timeout", block, set_name)
        entrypoint = (ROOT / "docker" / "entrypoint.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("migrate_interval_sets", entrypoint)
        self.assertIn("delete table inet hatarvedelem", entrypoint)
        install = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("delete table inet hatarvedelem", install)
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("deploy/hatarvedelem-boot.nft ./deploy", dockerfile)

    def test_migration_runs_before_validation(self) -> None:
        # A régi set-flagek mellett az `nft -c` elbukna, ezért a migrációnak
        # (boot-védelem, majd tábla-törlés) a validálás ELŐTT kell futnia.
        entrypoint = (ROOT / "docker" / "entrypoint.sh").read_text(
            encoding="utf-8"
        )
        delete_at = entrypoint.index("delete table inet hatarvedelem")
        validate_at = entrypoint.rindex('-c -f "$RENDERED"')
        self.assertLess(
            entrypoint.index("    ensure_boot_guard\n"), delete_at
        )
        self.assertLess(delete_at, validate_at)
        self.assertLess(
            entrypoint.index("    migrate_interval_sets\n"), validate_at
        )
        install = (ROOT / "install.sh").read_text(encoding="utf-8")
        delete_at = install.index("delete table inet hatarvedelem")
        self.assertLess(
            install.index("hatarvedelem-boot.nft"), delete_at
        )
        # A migráció eldöntése az első validálás előtt, a törlés utáni
        # (második) validálás pedig a törlés után van.
        self.assertLess(
            install.index("recreate_table=1"),
            install.index('-c -f "$TMP_NFT"'),
        )
        self.assertLess(delete_at, install.rindex('-c -f "$TMP_NFT"'))


@unittest.skipUnless(
    all(shutil.which(tool) for tool in ("unshare", "nsenter", "nft", "ip")),
    "nincs unshare/nsenter/nft/ip",
)
class PortRangeNamespaceTests(unittest.TestCase):
    def _unshare_ok(self) -> None:
        probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True)
        if probe.returncode != 0:
            self.skipTest("a user namespace nem elérhető")

    def test_interval_set_syntax_and_timeout(self) -> None:
        self._unshare_ok()
        script = r"""
set -e
nft add table inet t
nft add set inet t s '{ type ipv4_addr . inet_service; flags interval,timeout; size 16384; }'
nft add chain inet t c '{ type filter hook input priority 0; policy drop; }'
nft add rule inet t c ip saddr . tcp dport @s accept
nft -c -f /dev/stdin <<'NFT'
add table inet t2
add set inet t2 s { type ipv4_addr . inet_service; flags interval,timeout; size 16; }
add chain inet t2 c { type filter hook input priority 0; policy drop; }
add rule inet t2 c ip saddr . tcp dport @s accept
NFT
nft add element inet t s '{ 10.0.0.1 . 8000-8100 timeout 60s }'
nft -j list set inet t s
"""
        result = subprocess.run(
            ["unshare", "-rn", "sh", "-c", script],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            if "Operation not permitted" in result.stderr:
                self.skipTest("a névtérben nem engedélyezett")
            self.fail(result.stderr[-2000:])
        self.assertIn('"range": [8000, 8100]', result.stdout.replace("\n", " "))
        self.assertIn('"timeout"', result.stdout)

    def test_old_sets_are_migrated_before_validation(self) -> None:
        # A 3.15.0-ig a validálás a migráció előtt futott, ezért egy régi
        # (interval flag nélküli) tábla mellett az indulás elbukott.
        self._unshare_ok()
        entrypoint = (ROOT / "docker" / "entrypoint.sh").read_text(
            encoding="utf-8"
        )

        def function(name: str) -> str:
            start = entrypoint.index(f"\n{name}() {{\n") + 1
            return entrypoint[start:entrypoint.index("\n}\n", start) + 3]

        template = (ROOT / "deploy" / "hatarvedelem.nft").read_text(
            encoding="utf-8"
        )
        replacements = {
            "__LAN_IF__": "eth0", "__WAN_IF__": "eth1",
            "__LAN_NET__": "192.168.10.0/24",
            "__PORTAL_NET__": "0.0.0.0/0", "__PORT__": "8100",
            "__FWD_MARK__": "0x44524a4b", "__DROP_LOG_GROUP__": "5",
            "__PROXY__": "# ",
        }
        for token, value in replacements.items():
            template = template.replace(token, value)

        with tempfile.TemporaryDirectory() as tmp:
            rendered = Path(tmp) / "hatarvedelem.nft"
            rendered.write_text(template, encoding="utf-8")
            script = """
set -eu
NFT_BIN=nft
PYTHON=@@PYTHON@@
HOST_PORTS_JSON=''
BOOT_NFT=@@BOOT@@
RENDERED=@@RENDERED@@
log() { printf '[hatarvedelem] %s\\n' "$*"; }
die() { printf '[hatarvedelem] HIBA: %s\\n' "$*" >&2; exit 1; }
@@ENSURE@@
@@MIGRATE@@

# Régi stílusú tábla: hat halmaz interval flag nélkül.
nft add table inet hatarvedelem
for s in allowed_tcp allowed_udp allowed_input_tcp allowed_input_udp; do
  nft add set inet hatarvedelem "$s" '{ type ipv4_addr . inet_service; flags timeout; size 16384; }'
done
for s in host_service_tcp host_service_udp; do
  nft add set inet hatarvedelem "$s" '{ type inet_service; size 65536; }'
done

# A régi sorrend bizonyítéka: így bukott el a 3.15.0-s indulás.
if nft -c -f "$RENDERED" 2>/dev/null; then
  echo 'REGRESSION: a régi set-ek mellett a validálás nem bukott el' >&2
  exit 1
fi

migrate_interval_sets
[ "$migrated" = "1" ]
# A törlés előtt betöltött boot-védelemnek aktívnak kell maradnia.
nft list table inet hatarvedelem_boot >/dev/null
nft -c -f "$RENDERED"
nft -f "$RENDERED"
for s in allowed_tcp allowed_udp allowed_input_tcp allowed_input_udp \
        host_service_tcp host_service_udp; do
  nft list set inet hatarvedelem "$s" | grep -q 'flags interval' \
    || { echo "hiányzó interval flag: $s" >&2; exit 1; }
done
echo MIGRATED_OK
""".replace("@@PYTHON@@", sys.executable) \
   .replace("@@BOOT@@", str(ROOT / "deploy" / "hatarvedelem-boot.nft")) \
   .replace("@@RENDERED@@", str(rendered)) \
   .replace("@@ENSURE@@", function("ensure_boot_guard")) \
   .replace("@@MIGRATE@@", function("migrate_interval_sets"))
            result = subprocess.run(
                ["unshare", "-rn", "sh", "-c", script],
                capture_output=True, text=True, timeout=120,
            )
        if result.returncode != 0 and "Operation not permitted" in result.stderr:
            self.skipTest("a névtérben nem engedélyezett")
        self.assertIn("MIGRATED_OK", result.stdout, result.stderr[-3000:])

    def test_packet_level_range_and_revoke(self) -> None:
        self._unshare_ok()
        helper = Path(__file__).resolve().with_name("portrange_netns.py")
        result = subprocess.run(
            ["unshare", "-rn", sys.executable, str(helper)],
            capture_output=True, text=True, timeout=240,
        )
        if result.returncode != 0 and not result.stdout.strip():
            if "Operation not permitted" in result.stderr:
                self.skipTest("a névtérben nem engedélyezett")
            self.fail(result.stderr[-3000:])
        report = json.loads(result.stdout)
        failed = {
            name: check["detail"]
            for name, check in report["checks"].items()
            if isinstance(check, dict) and not check["ok"]
        }
        self.assertEqual(failed, {}, json.dumps(report, indent=1,
                                                ensure_ascii=False))
        self.assertTrue(report["ok"])


if __name__ == "__main__":
    unittest.main()
