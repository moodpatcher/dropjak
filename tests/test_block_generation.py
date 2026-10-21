#!/usr/bin/env python3
"""A ``block`` és ``block_nat`` láncok tényleges szabálygenerálása.

Az audit F4 megállapításához tartozó, ``Firewall.apply_custom()`` által
előállított szabályokat vizsgáljuk. A tesztek a valódi generátort futtatják,
de a szkriptfuttatást elfogják, így nft nem indul és a rendszer tűzfala nem
változik.

A korábbi, csak a sorok számát és néhány töredéket ellenőrző teszt mellett
ezek a tesztek a teljes illesztő kifejezést, a döntést (``drop``), a
``block_nat`` feltételét és a hibás bejegyzések tranzakciós viselkedését is
rögzítik.
"""

from __future__ import annotations

import subprocess
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402

# A tisztításnak pontosan ezeket a láncokat kell ürítenie, és semmi mást.
CUSTOM_CHAINS = ("preauth", "block", "preauth_nat", "block_nat")


def valid_preauth_entry() -> dict:
    """Érvényes pre-auth bejegyzés: TCP 8080 a LAN felől, cél nélkül."""
    return {"enabled": True, "proto": "tcp", "ports": [8080]}


def valid_block_entry() -> dict:
    """Érvényes blokk-bejegyzés: UDP 53 a 10.0.0.0/8 felé."""
    return {
        "enabled": True,
        "proto": "udp",
        "ports": [53],
        "dst": "10.0.0.0/8",
    }


class BlockGenerationTestCase(unittest.TestCase):
    """Közös segéd: a ``Firewall`` által generált szkriptet memóriába gyűjti."""

    def setUp(self) -> None:
        self.firewall = gateway.Firewall(
            dry_run=True,
            logger=lambda *_: None,
            lan_if="eth1",
            wan_if="eth0",
        )
        self.table = self.firewall.table
        self.scripts: list[str] = []
        self.run_calls: list[list[str]] = []
        # A valódi nft/conntrack helyett csak feljegyezzük a hívásokat.
        self.firewall._run_script = self.scripts.append  # type: ignore[method-assign]
        self.firewall._run = self._record_run  # type: ignore[method-assign]

    def _record_run(
        self, args: list[str], check: bool = True
    ) -> subprocess.CompletedProcess:
        self.run_calls.append(list(args))
        return subprocess.CompletedProcess(
            [self.firewall.binary, *args], 0, b"", b""
        )

    def apply_block(self, block: list[dict]) -> list[str]:
        """Egy blokk-készlet telepítése, a generált sorok visszaadásával."""
        self.scripts.clear()
        self.run_calls.clear()
        self.firewall.apply_custom(block=block)
        self.assertEqual(len(self.scripts), 1, self.scripts)
        self.assertEqual(self.run_calls, [])
        return self.scripts[0].splitlines()

    def chain_lines(self, lines: list[str], chain: str) -> list[str]:
        """Csak az adott láncra vonatkozó ``add rule`` sorok."""
        prefix = f"add rule inet {self.table} {chain} "
        return [line for line in lines if line.startswith(prefix)]

    def assert_log_then_drop(
        self, lines: list[str], chain: str, match: str
    ) -> None:
        """A megadott illesztéshez tartozó log+drop pár pontosan egyszer van,
        és a naplózó szabály közvetlenül az eldobó előtt áll."""
        prefix = f"add rule inet {self.table} {chain} {match}"
        expected_drop = prefix + " drop"
        logs = [
            line
            for line in lines
            if line.startswith(prefix + " limit rate ")
        ]
        drops = [line for line in lines if line == expected_drop]
        self.assertEqual(len(logs), 1, lines)
        self.assertEqual(len(drops), 1, lines)

        log_line = logs[0]
        self.assertIn("reason=block", log_line)
        self.assertTrue(
            log_line.endswith(f"group {self.firewall.drop_log_group}"),
            log_line,
        )
        self.assertEqual(lines.index(expected_drop), lines.index(log_line) + 1)

        for line in (log_line, expected_drop):
            with self.subTest(line=line):
                # A blokk-szabály interfészfüggetlen, és soha nem engedélyez.
                self.assertNotIn("iifname", line)
                self.assertNotIn("oifname", line)
                self.assertNotIn(" accept", line)
                self.assertNotIn(" return", line)
        self.assertTrue(expected_drop.endswith(" drop"))


class ApplyCustomBlockGenerationTests(BlockGenerationTestCase):
    """``apply_custom()`` által generált blokk-szabályok pontos tartalma."""

    def test_tcp_block_without_destination(self) -> None:
        """Cél nélkül nincs ``ct original ip daddr``, és nincs ``block_nat``."""
        lines = self.apply_block(
            [{"proto": "tcp", "ports": [80, 443]}]
        )
        match = (
            "meta l4proto tcp "
            "ct original proto-dst { 80, 443 }"
        )
        self.assert_log_then_drop(lines, "block", match)

        block = self.chain_lines(lines, "block")
        self.assertEqual(len(block), 2, block)
        for line in block:
            self.assertNotIn("ct original ip daddr", line)
        self.assertFalse(
            any("ct original ip daddr" in line for line in lines), lines
        )
        # Cél nélkül a portál-átirányítás előtti külön blokk sem készül.
        self.assertEqual(self.chain_lines(lines, "block_nat"), [])

    def test_tcp_block_with_destination(self) -> None:
        """TCP 80 célra a normál blokk mellett a ``block_nat`` is elkészül."""
        lines = self.apply_block(
            [
                {
                    "dst": "203.0.113.0/24",
                    "proto": "tcp",
                    "ports": [80],
                }
            ]
        )
        match = (
            "meta l4proto tcp "
            "ct original ip daddr 203.0.113.0/24 "
            "ct original proto-dst 80"
        )
        self.assert_log_then_drop(lines, "block", match)
        self.assertEqual(len(self.chain_lines(lines, "block")), 2)

        self.assert_log_then_drop(lines, "block_nat", match)
        self.assertEqual(len(self.chain_lines(lines, "block_nat")), 2)

    def test_udp_block_with_destination(self) -> None:
        """UDP blokk pontos illesztése; UDP-hez soha nem készül ``block_nat``."""
        lines = self.apply_block(
            [
                {
                    "dst": "198.51.100.0/24",
                    "proto": "udp",
                    "ports": [53, 123],
                }
            ]
        )
        match = (
            "meta l4proto udp "
            "ct original ip daddr 198.51.100.0/24 "
            "ct original proto-dst { 53, 123 }"
        )
        self.assert_log_then_drop(lines, "block", match)
        self.assertEqual(len(self.chain_lines(lines, "block")), 2)
        self.assertEqual(self.chain_lines(lines, "block_nat"), [])

    def test_multi_port_block_lists_every_port_in_order(self) -> None:
        """Több port esetén a lista minden portot, adott sorrendben tartalmaz."""
        lines = self.apply_block(
            [
                {
                    "dst": "192.0.2.7",
                    "proto": "tcp",
                    "ports": [443, 80, 22, 8080],
                }
            ]
        )
        # A hosztcím /32-re normalizálódik, a portlista sorrendje megmarad.
        match = (
            "meta l4proto tcp "
            "ct original ip daddr 192.0.2.7/32 "
            "ct original proto-dst { 443, 80, 22, 8080 }"
        )
        self.assert_log_then_drop(lines, "block", match)

        # A 80 benne van, ezért a block_nat csak a 80-as portra készül.
        nat_match = (
            "meta l4proto tcp "
            "ct original ip daddr 192.0.2.7/32 "
            "ct original proto-dst 80"
        )
        self.assert_log_then_drop(lines, "block_nat", nat_match)
        self.assertEqual(len(self.chain_lines(lines, "block_nat")), 2)

    def test_destination_is_normalized(self) -> None:
        """A megadott cél CIDR-ré normalizálva, környező szóköz nélkül kerül be."""
        lines = self.apply_block(
            [
                {
                    "dst": " 203.0.113.77/24 ",
                    "proto": "udp",
                    "ports": [53],
                },
                {"dst": "192.0.2.7", "proto": "tcp", "ports": [443]},
            ]
        )
        script = "\n".join(lines)
        # A hosztbiteket tartalmazó hálózat a hálózati címre normalizálódik.
        self.assertIn("ct original ip daddr 203.0.113.0/24", script)
        self.assertNotIn("203.0.113.77", script)
        self.assertIn("ct original ip daddr 192.0.2.7/32", script)

    def test_block_nat_only_for_tcp_port_80_with_destination(self) -> None:
        """A ``block_nat`` feltétele: TCP, a 80-as port és megadott cél."""
        # TCP 80, de cél nélkül: nincs block_nat.
        lines = self.apply_block(
            [{"dst": "", "proto": "tcp", "ports": [80]}]
        )
        self.assertEqual(self.chain_lines(lines, "block_nat"), [])

        # TCP 80 megadott céllal: van block_nat, log+drop párban.
        lines = self.apply_block(
            [
                {
                    "dst": "203.0.113.0/24",
                    "proto": "tcp",
                    "ports": [80],
                }
            ]
        )
        nat_match = (
            "meta l4proto tcp "
            "ct original ip daddr 203.0.113.0/24 "
            "ct original proto-dst 80"
        )
        self.assert_log_then_drop(lines, "block_nat", nat_match)

        # UDP 80 megadott céllal: soha nincs block_nat.
        lines = self.apply_block(
            [
                {
                    "dst": "203.0.113.0/24",
                    "proto": "udp",
                    "ports": [80],
                }
            ]
        )
        self.assertEqual(self.chain_lines(lines, "block_nat"), [])

        # TCP megadott céllal, de 80 nélkül: nincs block_nat.
        lines = self.apply_block(
            [
                {
                    "dst": "203.0.113.0/24",
                    "proto": "tcp",
                    "ports": [443],
                }
            ]
        )
        self.assertEqual(self.chain_lines(lines, "block_nat"), [])

    def test_block_rules_never_accept_or_return_and_log_precedes_drop(
        self,
    ) -> None:
        """A blokk-láncok csak log+drop párokat tartalmaznak, más döntést nem."""
        lines = self.apply_block(
            [
                {"dst": "", "proto": "tcp", "ports": [8080]},
                {
                    "dst": "203.0.113.0/24",
                    "proto": "tcp",
                    "ports": [80, 443],
                },
                {
                    "dst": "198.51.100.0/24",
                    "proto": "udp",
                    "ports": [53],
                },
            ]
        )
        for chain in ("block", "block_nat"):
            chain_lines = self.chain_lines(lines, chain)
            self.assertTrue(chain_lines, chain)
            for line in chain_lines:
                with self.subTest(chain=chain, line=line):
                    self.assertNotIn(" accept", line)
                    self.assertNotIn(" return", line)
                    self.assertNotIn("iifname", line)
                    self.assertNotIn("oifname", line)

            logs = [
                line for line in chain_lines if "reason=block" in line
            ]
            drops = [
                line for line in chain_lines if line.endswith(" drop")
            ]
            self.assertEqual(len(logs), len(drops), chain_lines)
            # Minden eldobó szabályt közvetlenül az azonos illesztésű
            # naplózó szabály előz meg.
            for index, line in enumerate(chain_lines):
                if not line.endswith(" drop"):
                    continue
                self.assertGreater(index, 0, chain_lines)
                log_line = chain_lines[index - 1]
                prefix, separator, _ = log_line.partition(" limit rate ")
                self.assertTrue(separator, log_line)
                self.assertIn("reason=block", log_line)
                self.assertEqual(line, prefix + " drop")


class InvalidBlockEntryTests(BlockGenerationTestCase):
    """Hibás bejegyzés esetén a teljes tranzakció elmarad."""

    INVALID_ENTRIES = (
        # Nincs port.
        {"proto": "tcp", "ports": []},
        {"proto": "tcp"},
        # Nem tcp/udp protokoll.
        {"proto": "", "ports": [80]},
        {"proto": "icmp", "ports": [1]},
        {"proto": "sctp", "ports": [80]},
        # Érvénytelen cél-CIDR.
        {"dst": "nem-cidr", "proto": "tcp", "ports": [80]},
        {"dst": "999.0.0.0/24", "proto": "tcp", "ports": [80]},
        {"dst": "203.0.113.0/33", "proto": "tcp", "ports": [80]},
        # Érvénytelen port: nulla, tartományon kívül, nem egész, sztring.
        {"proto": "tcp", "ports": [0]},
        {"proto": "tcp", "ports": [-1]},
        {"proto": "tcp", "ports": [65536]},
        {"proto": "tcp", "ports": [80.0]},
        {"proto": "tcp", "ports": ["80"]},
        {"proto": "tcp", "ports": None},
        {"proto": "tcp", "ports": "80"},
        # Az IPv4-matcherhez IPv6 cél nem rendelhető.
        {"dst": "2001:db8::/32", "proto": "tcp", "ports": [80]},
    )

    def test_invalid_entry_raises_and_runs_no_script(self) -> None:
        """Minden hibás bejegyzés ``FirewallError``, és nft-szkript nem fut."""
        for entry in self.INVALID_ENTRIES:
            with self.subTest(entry=entry):
                self.scripts.clear()
                self.run_calls.clear()
                with self.assertRaises(gateway.FirewallError):
                    self.firewall.apply_custom(block=[entry])
                # A generátor előbb összeállítja a teljes szkriptet, ezért
                # hiba esetén egyetlen részleges szabály sem jut el az nft-hez.
                self.assertEqual(self.scripts, [])
                self.assertEqual(self.run_calls, [])

    def test_invalid_entry_after_valid_one_runs_no_partial_script(self) -> None:
        """Egy érvényes után álló hibás bejegyzés sem telepít részlegesen."""
        self.scripts.clear()
        self.run_calls.clear()
        with self.assertRaises(gateway.FirewallError):
            self.firewall.apply_custom(
                block=[
                    {
                        "dst": "203.0.113.0/24",
                        "proto": "tcp",
                        "ports": [80],
                    },
                    {"dst": "", "proto": "tcp", "ports": []},
                ]
            )
        self.assertEqual(self.scripts, [])
        self.assertEqual(self.run_calls, [])

    def test_invalid_preauth_entry_raises_and_runs_no_script(self) -> None:
        """A pre-auth ág ugyanazt a szigorú validációt használja."""
        for entry in (
            {"dst": "2001:db8::/32", "proto": "tcp", "ports": [80]},
            {"proto": "tcp", "ports": [0]},
            {"proto": "tcp", "ports": ["80"]},
        ):
            with self.subTest(entry=entry):
                self.scripts.clear()
                self.run_calls.clear()
                with self.assertRaises(gateway.FirewallError):
                    self.firewall.apply_custom(preauth=[entry])
                self.assertEqual(self.scripts, [])
                self.assertEqual(self.run_calls, [])


class ClearCustomTests(BlockGenerationTestCase):
    """A ``clear_custom()`` csak a négy egyedi láncot üríti."""

    def test_clear_custom_flushes_exactly_the_custom_chains(self) -> None:
        """Négy ``add chain`` és négy ``flush chain``, más mellékhatás nélkül."""
        self.scripts.clear()
        self.run_calls.clear()
        self.firewall.clear_custom()

        self.assertEqual(len(self.scripts), 1, self.scripts)
        lines = [
            line for line in self.scripts[0].splitlines() if line.strip()
        ]
        expected = [
            f"add chain inet {self.table} {chain}"
            for chain in CUSTOM_CHAINS
        ] + [
            f"flush chain inet {self.table} {chain}"
            for chain in CUSTOM_CHAINS
        ]
        self.assertEqual(lines, expected)

        # A munkamenet-halmazokhoz és a conntrackhez nem nyúlunk.
        self.assertEqual(self.run_calls, [])
        script = "\n".join(lines)
        for token in (
            "conntrack",
            "flush set",
            "delete element",
            "allowed_tcp",
            "allowed_udp",
            "allowed_input_tcp",
            "allowed_input_udp",
            "allowed_icmp",
            "host_service_tcp",
            "host_service_udp",
            "banned_v4",
            "client_mac",
            "@",
        ):
            with self.subTest(token=token):
                self.assertNotIn(token, script)

        # Minden lánc pontosan egyszer szerepel add és flush alakban.
        self.assertEqual(len(lines), 2 * len(CUSTOM_CHAINS))
        for chain in CUSTOM_CHAINS:
            hits = [
                line for line in lines if line.endswith(f" {chain}")
            ]
            self.assertEqual(len(hits), 2, (chain, hits))


class ReplaceCustomTests(BlockGenerationTestCase):
    """A ``replace_custom()`` egyetlen nft-tranzakcióban cserél (F11)."""

    def test_replace_custom_is_one_transaction(self) -> None:
        """Lánclétrehozás, ürítés és az új szabályok egyetlen szkriptben."""
        self.scripts.clear()
        self.run_calls.clear()
        self.firewall.replace_custom(
            preauth=[valid_preauth_entry()],
            block=[valid_block_entry()],
        )

        # Pontosan egy nft-hívás: nincs külön clear_custom()/_run() előtte
        # vagy utána, tehát nincs olyan köztes állapot, amelyben a régi
        # szabályok már törlődtek, de az újak még nem érvényesek.
        self.assertEqual(len(self.scripts), 1, self.scripts)
        self.assertEqual(self.run_calls, [])

        lines = self.scripts[0].splitlines()
        for chain in CUSTOM_CHAINS:
            with self.subTest(chain=chain):
                self.assertIn(
                    f"add chain inet {self.table} {chain}", lines
                )
                self.assertIn(
                    f"flush chain inet {self.table} {chain}", lines
                )

        # A generált pre-auth és blokk szabályok ugyanabban a szkriptben
        # vannak, nem külön tranzakciókban.
        preauth_rule = (
            f'add rule inet {self.table} preauth iifname "eth1" '
            "meta l4proto tcp ct original proto-dst 8080 "
            f"meta mark set {self.firewall.fwd_mark} accept"
        )
        block_drop = (
            f"add rule inet {self.table} block meta l4proto udp "
            "ct original ip daddr 10.0.0.0/8 "
            "ct original proto-dst 53 drop"
        )
        self.assertIn(preauth_rule, lines)
        self.assertIn(block_drop, lines)

    def test_replace_custom_render_error_runs_nothing(self) -> None:
        """Érvénytelen bejegyzés esetén a renderelés elbukik, nft nem indul."""
        self.scripts.clear()
        self.run_calls.clear()

        with self.assertRaises(gateway.FirewallError):
            self.firewall.replace_custom(
                block=[{"proto": "tcp", "ports": [0]}]
            )

        # A teljes szkript a végrehajtás előtt áll össze, ezért hiba esetén
        # egyetlen részleges szabály sem jut el az nft-hez.
        self.assertEqual(self.scripts, [])
        self.assertEqual(self.run_calls, [])

    def test_replace_custom_keep_block_preserves_block_chains(self) -> None:
        """``keep_block=True``: csak a pre-auth láncok cserélődnek."""
        self.scripts.clear()
        self.run_calls.clear()
        self.firewall.replace_custom(
            preauth=[valid_preauth_entry()],
            block=[valid_block_entry()],
            keep_block=True,
        )

        self.assertEqual(len(self.scripts), 1, self.scripts)
        self.assertEqual(self.run_calls, [])
        lines = self.scripts[0].splitlines()

        for chain in ("preauth", "preauth_nat"):
            with self.subTest(chain=chain):
                self.assertIn(
                    f"add chain inet {self.table} {chain}", lines
                )
                self.assertIn(
                    f"flush chain inet {self.table} {chain}", lines
                )

        preauth_rule = (
            f'add rule inet {self.table} preauth iifname "eth1" '
            "meta l4proto tcp ct original proto-dst 8080 "
            f"meta mark set {self.firewall.fwd_mark} accept"
        )
        self.assertIn(preauth_rule, lines)

        # A blokk láncokhoz egyáltalán nem nyúlunk: sem létrehozás, sem
        # ürítés, sem szabály nem szerepelhet rájuk. A pontos sorokat
        # vizsgáljuk, hogy a "block" szó más előfordulása (pl. egy
        # magyarázó szövegben) ne adjon hamis találatot.
        for chain in ("block", "block_nat"):
            prefix = f"add rule inet {self.table} {chain} "
            with self.subTest(chain=chain):
                self.assertNotIn(
                    f"add chain inet {self.table} {chain}", lines
                )
                self.assertNotIn(
                    f"flush chain inet {self.table} {chain}", lines
                )
                self.assertFalse(
                    any(line.startswith(prefix) for line in lines), lines
                )
                self.assertEqual(self.chain_lines(lines, chain), [])
        self.assertNotIn("reason=block", self.scripts[0])


class ApplyCustomSettingsTests(BlockGenerationTestCase):
    """``Gateway._apply_custom_settings()`` korrupt snapshot esetén."""

    def test_apply_custom_settings_corrupt_snapshot_keeps_block(self) -> None:
        """Hibás beállításnál a pre-auth ürül, a blokk láncok megmaradnak."""
        self.scripts.clear()
        self.run_calls.clear()
        audit_calls: list[tuple[str, dict]] = []

        # Minimális hamis Gateway: csak a tűzfalra és az auditnaplózásra
        # van szükség; a snapshotot közvetlenül adjuk át, ezért
        # settings/store nem kell.
        fake = types.SimpleNamespace()
        fake.firewall = self.firewall
        fake._write_audit = lambda event, **fields: audit_calls.append(
            (event, fields)
        )

        gateway.Gateway._apply_custom_settings(
            fake,
            {
                "error": "szimulált hiba",
                "preauth": [valid_preauth_entry()],
                "block": [valid_block_entry()],
            },
        )

        self.assertEqual(len(self.scripts), 1, self.scripts)
        self.assertEqual(self.run_calls, [])
        lines = self.scripts[0].splitlines()

        # Csak a pre-auth láncokat cseréli; a block/block_nat láncok
        # utolsó ismert jó tartalma a kernelben marad.
        for chain in ("preauth", "preauth_nat"):
            with self.subTest(chain=chain):
                self.assertIn(
                    f"add chain inet {self.table} {chain}", lines
                )
                self.assertIn(
                    f"flush chain inet {self.table} {chain}", lines
                )
        for chain in ("block", "block_nat"):
            prefix = f"add rule inet {self.table} {chain} "
            with self.subTest(chain=chain):
                self.assertNotIn(
                    f"add chain inet {self.table} {chain}", lines
                )
                self.assertNotIn(
                    f"flush chain inet {self.table} {chain}", lines
                )
                self.assertFalse(
                    any(line.startswith(prefix) for line in lines), lines
                )
        self.assertEqual(self.chain_lines(lines, "block"), [])
        self.assertEqual(self.chain_lines(lines, "block_nat"), [])

        # Fail-closed: a hibás snapshotból származó pre-auth bejegyzés nem
        # települhet, csak a mindig jelen lévő tiltott-forrás védőszabály
        # marad a (kiürített) preauth láncban.
        self.assertEqual(
            self.chain_lines(lines, "preauth"),
            [
                f"add rule inet {self.table} preauth "
                f"ip saddr @{self.firewall.ban_set} drop"
            ],
        )
        self.assertNotIn("8080", self.scripts[0])

        # A korrupt beállítást auditálni kell, hogy a hibát észre lehessen
        # venni, és a bejegyzés a pontos okot tartalmazza.
        self.assertEqual(
            [event for event, _fields in audit_calls],
            ["settings_invalid"],
        )
        self.assertEqual(
            audit_calls[0][1], {"reason": "szimulált hiba"}
        )


if __name__ == "__main__":
    unittest.main()
