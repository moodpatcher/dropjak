#!/usr/bin/env python3
"""Tests for the Caddy-based subdomain proxy.

* validation of the proxy settings (settings_store), input/forward targets;
* the domain rule (RuleStore) and the session selection (SessionManager);
* the loopback-only /api/proxy/ask and /api/proxy/auth endpoints on a real
  AppServer, with a minimal gateway double;
* rendering the docker/entrypoint.sh template with HV_PROXY=0/1.
"""

from __future__ import annotations

import glob
import http.client
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import fail2ban as fail2ban_mod  # noqa: E402
import gateway  # noqa: E402
import server  # noqa: E402
import settings_store  # noqa: E402
from test_gateway import CATALOG, FakeTools, solve  # noqa: E402

ROOT_DOMAIN = "z1.example.com"
SECOND_DOMAIN = "z2.example.org"
R = {"root": ROOT_DOMAIN}


def host(name, root=ROOT_DOMAIN):
    return f"{name}.{root}"


class ProxySettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "firewall-settings.json")
        self.store = settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_defaults_are_off(self) -> None:
        snap = self.store.snapshot()
        self.assertEqual(snap["proxy_domains"], [])
        self.assertEqual(snap["proxy_routes"], [])

    def test_valid_config_is_normalized_and_persisted(self) -> None:
        stored = self.store.set_proxy(
            [" Z1.Example.COM "],
            [{"name": "OWUI", "root": "Z1.example.com ", "port": 3000,
              "enabled": True},
             {"name": "a-b", "port": 8080, "enabled": False, **R}],
        )
        self.assertEqual(stored["proxy_domains"], [ROOT_DOMAIN])
        self.assertEqual(stored["proxy_routes"][0]["name"], "owui")
        self.assertEqual(stored["proxy_routes"][0]["root"], ROOT_DOMAIN)
        reloaded = settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        ).snapshot()
        self.assertEqual(reloaded["proxy_routes"], stored["proxy_routes"])
        self.assertEqual(reloaded["error"], "")

    def test_bad_domains_rejected(self) -> None:
        for domain in (
            "localhost", "*.z1.example.com", "https://z1.example.com",
            "z1.example.com:443", "-a.example.com", "a-.example.com",
            "a..example.com", "a_b.example.com", "a" * 64 + ".com",
            ("a" * 60 + ".") * 5 + "com", 42, "",
        ):
            with self.subTest(domain=domain):
                with self.assertRaises(settings_store.SettingsError):
                    self.store.set_proxy([domain], [])
        for domains in (
            ROOT_DOMAIN, None, [ROOT_DOMAIN, "Z1.EXAMPLE.COM"],
            [f"d{i}.example.com" for i in range(17)],
        ):
            with self.subTest(domains=str(domains)[:60]):
                with self.assertRaises(settings_store.SettingsError):
                    self.store.set_proxy(domains, [])
        self.assertEqual(self.store.snapshot()["proxy_domains"], [])

    def test_multiple_roots(self) -> None:
        roots = [ROOT_DOMAIN, SECOND_DOMAIN]
        # The same subdomain under two roots is a separate entry.
        stored = self.store.set_proxy(roots, [
            {"name": "owui", "port": 3000, **R},
            {"name": "owui", "root": SECOND_DOMAIN, "port": 3001},
        ])
        self.assertEqual(stored["proxy_domains"], roots)
        self.assertEqual(
            [(r["name"], r["root"]) for r in stored["proxy_routes"]],
            [("owui", ROOT_DOMAIN), ("owui", SECOND_DOMAIN)],
        )
        for domains, routes, message in (
            (roots, [{"name": "owui", "port": 3000, **R},
                     {"name": "OWUI", "port": 3001, **R}], "duplicate"),
            (roots, [{"name": "x", "root": "z3.example.net", "port": 3000}],
             "unknown root domain"),
            (roots, [{"name": "x", "port": 3000}], "unknown root domain"),
            # The entry's hostname is another root.
            (["example.com", ROOT_DOMAIN],
             [{"name": "z1", "root": "example.com", "port": 3000}],
             "cannot be a root domain"),
            # A root that has entries cannot be deleted.
            ([ROOT_DOMAIN],
             [{"name": "owui", "port": 3000, **R},
              {"name": "owui", "root": SECOND_DOMAIN, "port": 3001}],
             "unknown root domain: z2.example.org"),
        ):
            with self.subTest(domains=domains, routes=routes):
                with self.assertRaisesRegex(
                    settings_store.SettingsError, message
                ):
                    self.store.set_proxy(domains, routes)
        self.assertEqual(self.store.snapshot()["proxy_domains"], roots)
        # Without its entries the root can be deleted.
        stored = self.store.set_proxy(
            [ROOT_DOMAIN], [{"name": "owui", "port": 3000, **R}]
        )
        self.assertEqual(stored["proxy_domains"], [ROOT_DOMAIN])

    def test_bad_routes_rejected(self) -> None:
        reserved = (
            settings_store.PORTAL_PORT, 22, 53, 67, 80, 443, 2019
        )
        cases = [
            [{"name": "a.b", "port": 3000}],
            [{"name": "-a", "port": 3000}],
            [{"name": "", "port": 3000}],
            [{"name": "a" * 64, "port": 3000}],
            [{"name": "ok", "port": 0}],
            [{"name": "ok", "port": 65536}],
            [{"name": "ok", "port": "3000"}],
            [{"name": "ok", "port": True}],
            [{"name": "ok", "port": 3000, "enabled": "yes"}],
            [{"name": "ok", "port": 3000}, {"name": "OK", "port": 3001}],
            [{"name": f"r{i}", "port": 3000 + i} for i in range(65)],
        ]
        cases = [[{**R, **item} for item in routes] for routes in cases]
        cases += ["not a list"] + [
            [{"name": "ok", "port": port, **R}] for port in reserved
        ]
        for routes in cases:
            with self.subTest(routes=str(routes)[:80]):
                with self.assertRaises(settings_store.SettingsError):
                    self.store.set_proxy([ROOT_DOMAIN], routes)
        self.assertEqual(self.store.snapshot()["proxy_routes"], [])

    def test_legacy_single_root_is_migrated(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write('{"proxy_domain": "Z1.example.com", "proxy_routes": '
                     '[{"name": "a", "port": 3000, "enabled": true}]}')
        store = settings_store.SettingsStore(self.path, logger=lambda *_: None)
        snap = store.snapshot()
        self.assertEqual(snap["error"], "")
        self.assertEqual(store.legacy_proxy_domain, ROOT_DOMAIN)
        self.assertEqual(snap["proxy_domains"], [ROOT_DOMAIN])
        self.assertEqual(snap["proxy_routes"], [
            {"name": "a", "root": ROOT_DOMAIN, "type": "input", "port": 3000,
             "enabled": True, "visibility": "private"}
        ])
        # The next write contains only the new key.
        store.set_proxy(snap["proxy_domains"], snap["proxy_routes"])
        with open(self.path, encoding="utf-8") as fh:
            saved = json.load(fh)
        self.assertNotIn("proxy_domain", saved)
        self.assertEqual(saved["proxy_domains"], [ROOT_DOMAIN])
        self.assertEqual(
            settings_store.SettingsStore(
                self.path, logger=lambda *_: None
            ).legacy_proxy_domain, "",
        )

    def test_legacy_routes_without_root_are_dropped(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write('{"proxy_domain": "", "proxy_routes": '
                     '[{"name": "a", "port": 3000}], "preauth": '
                     '[{"id": "dns", "label": "DNS", "dst": "1.1.1.1", '
                     '"proto": "udp", "ports": [53]}]}')
        snap = settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        ).snapshot()
        self.assertEqual(snap["error"], "")
        self.assertEqual(snap["proxy_domains"], [])
        self.assertEqual(snap["proxy_routes"], [])
        self.assertEqual(len(snap["preauth"]), 1)

    def test_forward_entry(self) -> None:
        stored = self.store.set_proxy([ROOT_DOMAIN], [
            {"name": "nas", "type": "forward", "ip": " 192.168.10.20 ",
             "port": 443, **R},
            # The host's reserved ports do not apply to the forward target.
            {"name": "ssh", "type": "forward", "ip": "10.0.0.5", "port": 22,
             **R},
        ])
        self.assertEqual(stored["proxy_routes"][0], {
            "name": "nas", "root": ROOT_DOMAIN, "type": "forward",
            "port": 443, "enabled": True, "visibility": "private",
            "ip": "192.168.10.20",
        })
        self.assertEqual(stored["proxy_routes"][1]["ip"], "10.0.0.5")
        for ip in ("8.8.8.8", "127.0.0.1", "169.254.1.1", "224.0.0.1",
                   "0.0.0.0", "172.32.0.1", "100.64.0.1", "10.0.0.0/8",
                   "192.168.1", "fd00::1", "", None, 42):
            with self.subTest(ip=ip):
                with self.assertRaises(settings_store.SettingsError):
                    self.store.set_proxy([ROOT_DOMAIN], [
                        {"name": "x", "type": "forward", "ip": ip, "port": 80,
                         **R}
                    ])
        with self.assertRaises(settings_store.SettingsError):
            self.store.set_proxy([ROOT_DOMAIN], [
                {"name": "x", "type": "output", "port": 3000, **R}
            ])

    def test_visibility(self) -> None:
        stored = self.store.set_proxy([ROOT_DOMAIN], [
            {"name": "pub", "port": 3000, "visibility": "public", **R},
            {"name": "priv", "port": 3001, **R},
        ])
        self.assertEqual(
            [r["visibility"] for r in stored["proxy_routes"]],
            ["public", "private"],
        )
        for value in ("Public", "", None, True, "open"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    settings_store.SettingsError, "visibility"
                ):
                    self.store.set_proxy([ROOT_DOMAIN], [
                        {"name": "x", "port": 3000, "visibility": value, **R}
                    ])

    def test_referenced_entry_cannot_be_removed_or_renamed(self) -> None:
        roots = [ROOT_DOMAIN, SECOND_DOMAIN]
        self.store.set_proxy(roots, [{"name": "owui", "port": 3000, **R}])
        for routes in (
            [], [{"name": "owui2", "port": 3000, **R}],
            # Moving it under another root also makes the referenced hostname disappear.
            [{"name": "owui", "root": SECOND_DOMAIN, "port": 3000}],
        ):
            with self.subTest(routes=routes):
                with self.assertRaisesRegex(
                    settings_store.SettingsError, host("owui")
                ):
                    self.store.set_proxy(roots, routes, {host("owui")})
        # Changing the target (hostname unchanged) is allowed.
        stored = self.store.set_proxy(roots, [
            {"name": "owui", "type": "forward", "ip": "10.1.2.3", "port": 80,
             **R}
        ], {host("owui")})
        self.assertEqual(stored["proxy_routes"][0]["ip"], "10.1.2.3")

    def test_portal_domain_is_under_a_root_and_not_a_route(self) -> None:
        portal = "dropjak." + ROOT_DOMAIN
        self.store.set_proxy([ROOT_DOMAIN], [])
        self.assertEqual(self.store.snapshot()["portal_domain"], "")
        stored = self.store.set_portal_domain(portal)
        self.assertEqual(stored["portal_domain"], portal)
        # A URL pasted from the browser, and uppercase/a trailing dot, are accepted too.
        for pasted in (
            f"https://{portal}/", portal.upper() + ".",
            f"https://{portal}:443/path",
        ):
            with self.subTest(pasted=pasted):
                stored = self.store.set_portal_domain(pasted)
                self.assertEqual(stored["portal_domain"], portal)
        # The portal's challenge belongs to the address; it is deleted when disabled.
        stored = self.store.set_proxy(
            [ROOT_DOMAIN], [],
            portal_challenge={"triggers": ["always"], "interval_hours": 24},
        )
        self.assertEqual(stored["portal_challenge"]["triggers"], ["always"])
        for value in (
            ROOT_DOMAIN, "dropjak.example.net", "x." + SECOND_DOMAIN,
            "dropjak", "*.z1.example.com", 42,
        ):
            with self.subTest(value=value):
                with self.assertRaises(settings_store.SettingsError):
                    self.store.set_portal_domain(value)
        # Collision with an existing proxy entry.
        with self.assertRaisesRegex(
            settings_store.SettingsError, "proxy entry"
        ):
            self.store.set_proxy([ROOT_DOMAIN], [
                {"name": "dropjak", "port": 3000, **R}
            ])
        # The root cannot be deleted from under the portal's address.
        with self.assertRaisesRegex(
            settings_store.SettingsError, "under a root domain"
        ):
            self.store.set_proxy([SECOND_DOMAIN], [])
        stored = self.store.set_portal_domain("")
        self.assertEqual(stored["portal_domain"], "")
        self.assertIsNone(stored["portal_challenge"])

    def test_root_entry_requires_a_dedicated_portal_address(self) -> None:
        entry = {"name": "", "port": 3000, **R}
        # Without the portal's own address the root belongs to the portal.
        with self.assertRaisesRegex(
            settings_store.SettingsError, "dedicated portal address"
        ):
            self.store.set_proxy([ROOT_DOMAIN], [entry])
        self.store.set_proxy([ROOT_DOMAIN], [])
        self.store.set_portal_domain("dropjak." + ROOT_DOMAIN)
        stored = self.store.set_proxy([ROOT_DOMAIN], [entry])
        self.assertEqual(
            settings_store.route_host(stored["proxy_routes"][0]), ROOT_DOMAIN
        )
        with self.assertRaisesRegex(
            settings_store.SettingsError, "duplicate"
        ):
            self.store.set_proxy([ROOT_DOMAIN], [entry, dict(entry)])
        # A rule may reference the entry for the root, so it must not disappear.
        with self.assertRaisesRegex(
            settings_store.SettingsError, "references it"
        ):
            self.store.set_proxy(
                [ROOT_DOMAIN], [], referenced={ROOT_DOMAIN}
            )
        self.store.set_proxy([ROOT_DOMAIN], [])
        self.store.set_portal_domain("")

    def test_corrupt_file_turns_proxy_off(self) -> None:
        self.store.set_proxy([ROOT_DOMAIN], [{"name": "a", "port": 3000, **R}])
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write('{"proxy_domains": ["z1.example.com"], "proxy_routes": '
                     '[{"name": "a", "root": "z1.example.com", "port": 22}]}')
        snap = settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        ).snapshot()
        self.assertEqual(snap["proxy_domains"], [])
        self.assertEqual(snap["proxy_routes"], [])
        self.assertTrue(snap["error"])


def add_session(manager, ip, domains=(), *, authorized=True, ttl=60,
                role=gateway.ROLE_USER, full=False):
    """Insert a session directly with one selection."""
    now = time.time()
    grants = (gateway.Ports(full=True),) if full else ()
    manager._sessions[ip] = gateway.Session(
        token=ip, user="u", ip=ip, created=now, expires=now + ttl,
        authorized=authorized, role=role, full=full, grant_parts=grants,
        rule_parts=(gateway.RuleSelection("r", "r", grants, tuple(domains)),),
    )


class DomainRuleStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        path = os.path.join(self.tmp.name, "rules.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('{"rules": {}}')
        self.store = gateway.RuleStore(
            path, catalog=gateway.ServiceCatalog.load(
                str(ROOT / "services.json")
            ),
            logger=lambda *_: None,
            domain_names=lambda: {host("owui"), host("nas")},
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_valid_domain_rule(self) -> None:
        rule = self.store.create("dom", {
            "label": "OWUI",
            "domains": [host("OWUI"), host("nas"), host("owui")],
            "max_ttl": 3600, "default_ttl": 3600,
        })
        self.assertEqual(rule.domains, (host("owui"), host("nas")))
        self.assertEqual(rule.grants, ())
        self.assertEqual(
            rule.public()["domains"], [host("owui"), host("nas")]
        )
        self.assertEqual(
            self.store.domain_references(), {host("owui"), host("nas")}
        )
        # After a reload it is the same, without ports.
        reloaded = gateway.RuleStore(
            self.store.path, catalog=self.store.catalog,
            logger=lambda *_: None,
        ).get("dom")
        self.assertEqual(reloaded.domains, (host("owui"), host("nas")))
        self.assertEqual(reloaded.grants, ())

    def test_invalid_domain_rules(self) -> None:
        for data in (
            {"domains": ["owui"]},
            {"domains": [host("owui", SECOND_DOMAIN)]},
            {"domains": []},
            {"domains": host("owui")},
            {"domains": ["a..b"]},
            {"domains": [host("owui")], "tcp": [80]},
            {"domains": [host("owui")], "full": True},
            {"domains": [host("owui")], "icmp": True},
        ):
            with self.subTest(data=data):
                with self.assertRaises(gateway.RuleStoreError):
                    self.store.create("dom", {"label": "x", **data})
        self.assertIsNone(self.store.get("dom"))
        # Without an entry-name source a domain rule cannot be saved.
        self.store.domain_names = None
        with self.assertRaises(gateway.RuleStoreError):
            self.store.create("dom", {"label": "x", "domains": [host("owui")]})

    def test_collection_carries_member_domains(self) -> None:
        self.store.create("dom", {"label": "d", "domains": [host("owui")]})
        self.store.create("web", {"label": "w", "tcp": [80]})
        coll = self.store.create("both", {
            "label": "b", "collection": True, "members": ["dom", "web"],
        })
        self.assertEqual(coll.domains, (host("owui"),))
        self.assertEqual(
            coll.grants, (gateway.Ports(tcp=(80,), direction="forward"),)
        )
        # A legacy account without an assignment does not inherit the domain rule.
        legacy = types.SimpleNamespace(
            name="old", role=gateway.ROLE_USER, rules=(), rules_set=False
        )
        self.assertEqual(
            [rule.id for rule in self.store.effective_for(legacy, [])],
            ["web"],
        )


class DomainRuleMigrationTests(unittest.TestCase):
    """Conversion of the pre-3.6, dotless domain references."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings_path = os.path.join(self.tmp.name, "settings.json")
        self.rules_path = os.path.join(self.tmp.name, "rules.json")
        self.logs: list[str] = []
        self.catalog = gateway.ServiceCatalog.load(str(ROOT / "services.json"))
        with open(self.rules_path, "w", encoding="utf-8") as fh:
            json.dump({"rules": {
                "dom": {"label": "D", "domains": ["owui", "NAS"]},
                "web": {"label": "W", "direction": "forward", "tcp": [80]},
            }}, fh)

    def write_settings(self, root: str) -> None:
        with open(self.settings_path, "w", encoding="utf-8") as fh:
            json.dump({"proxy_domain": root, "proxy_routes": [
                {"name": "owui", "port": 3000},
                {"name": "nas", "type": "forward", "ip": "10.0.0.5",
                 "port": 443},
            ]}, fh)

    def gateway(self) -> "gateway.Gateway":
        tools = FakeTools(self.tmp.name)
        return gateway.Gateway(
            users=gateway.UserStore(
                os.path.join(self.tmp.name, "users.json"), iterations=10_000
            ),
            firewall=gateway.Firewall(
                binary=str(tools.nft), logger=lambda *_: None
            ),
            catalog=self.catalog,
            rules=gateway.RuleStore(
                self.rules_path, catalog=self.catalog,
                logger=self.logs.append,
            ),
            groups=gateway.GroupStore(
                os.path.join(self.tmp.name, "groups.json"),
                logger=lambda *_: None,
            ),
            audit=gateway.AuditLog(
                os.path.join(self.tmp.name, "audit.jsonl"),
                logger=lambda *_: None,
            ),
            settings=settings_store.SettingsStore(
                self.settings_path, logger=self.logs.append
            ),
        )

    def test_legacy_root_resolves_and_persists(self) -> None:
        self.write_settings(ROOT_DOMAIN)
        gw = self.gateway()
        rule = gw.rules.get("dom")
        self.assertEqual(rule.domains, (host("owui"), host("nas")))
        self.assertEqual(gw.rules.get("web").tcp, (80,))
        with open(self.rules_path, encoding="utf-8") as fh:
            saved = json.load(fh)["rules"]
        self.assertEqual(saved["dom"]["domains"], [host("owui"), host("nas")])
        self.assertEqual(
            len(glob.glob(self.rules_path + ".domains-backup-*")), 1
        )
        # The migrated rule allows the same, and the reference protection is live too.
        self.assertEqual(
            gw.rules.domain_names(), {host("owui"), host("nas")}
        )
        manager = gateway.SessionManager(firewall=None)
        add_session(manager, "198.51.100.1", rule.domains)
        self.assertTrue(manager.allows_domain("198.51.100.1", host("owui")))
        self.assertFalse(manager.allows_domain("198.51.100.1", "owui"))
        with self.assertRaisesRegex(settings_store.SettingsError, "owui"):
            gw.settings.set_proxy(
                [ROOT_DOMAIN], [], gw.rules.domain_references()
            )
        # After a restart (already without the old key) the full hostname remains.
        gw.settings.set_proxy(
            [ROOT_DOMAIN], gw.settings.snapshot()["proxy_routes"],
            gw.rules.domain_references(),
        )
        self.assertEqual(
            self.gateway().rules.get("dom").domains,
            (host("owui"), host("nas")),
        )

    def test_bare_name_without_legacy_root_is_dropped(self) -> None:
        with open(self.rules_path, "w", encoding="utf-8") as fh:
            json.dump({"rules": {
                "dom": {"label": "D", "domains": ["owui", host("nas")]},
                "old": {"label": "O", "domains": ["owui"]},
                "web": {"label": "W", "direction": "forward", "tcp": [80]},
            }}, fh)
        before = Path(self.rules_path).read_text(encoding="utf-8")
        self.write_settings("")
        gw = self.gateway()
        self.assertEqual(gw.rules.get("dom").domains, (host("nas"),))
        # The rule with only unresolvable names is left out, the rest remains.
        self.assertIsNone(gw.rules.get("old"))
        self.assertEqual(gw.rules.get("web").tcp, (80,))
        self.assertTrue(any("cannot be resolved" in line for line in self.logs))
        # Not a corrupted file: it is not set aside and not rewritten.
        self.assertEqual(
            Path(self.rules_path).read_text(encoding="utf-8"), before
        )
        self.assertEqual(glob.glob(self.rules_path + ".corrupt-*"), [])


class DomainSessionTests(unittest.TestCase):
    def test_allows_domain(self) -> None:
        manager = gateway.SessionManager(firewall=None)
        add_session(manager, "198.51.100.1", ("owui",))
        add_session(manager, "198.51.100.2", ("owui",), authorized=False)
        add_session(manager, "198.51.100.3", ("owui",), ttl=-1)
        add_session(manager, "198.51.100.4", full=True,
                    role=gateway.ROLE_ADMIN)
        self.assertTrue(manager.allows_domain("198.51.100.1", "owui"))
        self.assertFalse(manager.allows_domain("198.51.100.1", "nas"))
        for ip in ("198.51.100.2", "198.51.100.3", "198.51.100.4",
                   "198.51.100.5"):
            with self.subTest(ip=ip):
                self.assertFalse(manager.allows_domain(ip, "owui"))

    def test_domain_only_selection_authorizes_without_nft(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        tools = FakeTools(tmp.name)
        fw = gateway.Firewall(binary=str(tools.nft), logger=lambda *_: None)
        manager = gateway.SessionManager(fw, ttl=3600, pending_ttl=600)
        rule = gateway.Rule(id="dom", label="OWUI", description="",
                            domains=("owui",))
        web = gateway.Rule(id="web", label="Web", description="", tcp=(80,))
        session = manager.login("alice", "192.168.50.23")
        authorized = manager.authorize(
            session.token, "192.168.50.23", [rule], 600
        )
        self.assertTrue(authorized.authorized)
        self.assertEqual(authorized.grant_parts, ())
        self.assertEqual(authorized.direction, "forward")
        self.assertEqual(authorized.snapshot()["domains"], ["owui"])
        self.assertEqual(tools.script(), [])
        self.assertTrue(manager.allows_domain("192.168.50.23", "owui"))
        # Together with a port rule only the port goes into the kernel.
        manager.authorize(session.token, "192.168.50.23", [rule, web], 600)
        script = tools.script()
        self.assertEqual(len(script), 1, script)
        self.assertIn("allowed_tcp { 192.168.50.23 . 80 ", script[0])
        self.assertTrue(manager.allows_domain("192.168.50.23", "owui"))
        # Removing the domain selection does not touch the firewall.
        tools.clear()
        self.assertEqual(manager.revoke_rule("dom"), 1)
        self.assertEqual(tools.lines(), [])
        self.assertFalse(manager.allows_domain("192.168.50.23", "owui"))


class ProxyEndpointTests(unittest.TestCase):
    AUTHORIZED = "198.51.100.10"
    BANNED = "198.51.100.20"
    PORT_ONLY = "198.51.100.30"
    OTHER_DOMAIN = "198.51.100.40"
    ADMIN = "198.51.100.50"
    EXPIRED = "198.51.100.60"
    SECOND = "198.51.100.70"

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.settings = settings_store.SettingsStore(
            os.path.join(cls.tmp.name, "s.json"), logger=lambda *_: None
        )
        cls.settings.set_proxy([ROOT_DOMAIN, SECOND_DOMAIN], [
            {"name": "owui", "port": 3000, "enabled": True, **R},
            {"name": "off", "port": 3001, "enabled": False, **R},
            {"name": "nas", "type": "forward", "ip": "192.168.10.20",
             "port": 5001, **R},
            {"name": "wiki", "port": 3002, **R},
            {"name": "pub", "port": 3003, "visibility": "public", **R},
            # The same subdomain under the second root, with a different target.
            {"name": "owui", "root": SECOND_DOMAIN, "type": "forward",
             "ip": "192.168.10.30", "port": 8080},
        ])
        sessions = gateway.SessionManager(firewall=None)
        for ip in (cls.AUTHORIZED, cls.BANNED):
            add_session(sessions, ip, (host("owui"), host("off"), host("nas")))
        add_session(sessions, cls.PORT_ONLY)
        add_session(sessions, cls.OTHER_DOMAIN, (host("wiki"),))
        add_session(sessions, cls.ADMIN, full=True, role=gateway.ROLE_ADMIN)
        add_session(sessions, cls.EXPIRED, (host("owui"),), ttl=-1)
        add_session(sessions, cls.SECOND, (host("owui", SECOND_DOMAIN),))
        # Recording of the audit and drop rows for the navigation/401 tests.
        cls.audits, cls.drops = [], []
        cls.certs = settings_store.CertStore(
            os.path.join(cls.tmp.name, "certs"), logger=lambda *_: None
        )
        gw = types.SimpleNamespace(
            settings=cls.settings,
            sessions=sessions,
            fail2ban=types.SimpleNamespace(
                banned=lambda ip: {"ip": ip} if ip == cls.BANNED else None,
                proxy_banned=lambda ip: None,
                record_proxy_unauthorized=lambda ip: None,
            ),
            audit=types.SimpleNamespace(
                write=lambda event, **fields: cls.audits.append(
                    (event, fields)
                )
            ),
            record_proxy_drop=lambda *args: cls.drops.append(args),
            certs=cls.certs,
        )
        cls._old_portal_url = gateway.PORTAL_URL
        gateway.PORTAL_URL = ""
        cls.server = server.AppServer(("127.0.0.1", 0), gw)
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
        gateway.PORTAL_URL = cls._old_portal_url
        cls.tmp.cleanup()

    def get(self, path, headers=None, source="127.0.0.1"):
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=10, source_address=(source, 0)
        )
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp, body

    def auth(self, host, ip="", source="127.0.0.1"):
        headers = {"X-Forwarded-Host": host}
        if ip:
            headers["X-Forwarded-For"] = ip
        return self.get("/api/proxy/auth", headers, source)

    def test_ask(self) -> None:
        for domain, code in (
            (ROOT_DOMAIN, 200), ("owui." + ROOT_DOMAIN, 200),
            ("OWUI." + ROOT_DOMAIN.upper(), 200),
            ("off." + ROOT_DOMAIN, 404), ("x." + ROOT_DOMAIN, 404),
            (SECOND_DOMAIN, 200), (host("owui", SECOND_DOMAIN), 200),
            (host("nas", SECOND_DOMAIN), 404),
            ("evil.example.com", 404), ("", 404),
        ):
            with self.subTest(domain=domain):
                resp, _ = self.get(f"/api/proxy/ask?domain={domain}")
                self.assertEqual(resp.status, code)

    def test_non_loopback_peer_is_denied(self) -> None:
        for path in (
            f"/api/proxy/ask?domain={ROOT_DOMAIN}",
            "/api/proxy/auth", "/api/proxy/unauthorized.png",
        ):
            with self.subTest(path=path):
                resp, body = self.get(
                    path,
                    {"X-Forwarded-Host": "owui." + ROOT_DOMAIN,
                     "X-Forwarded-For": self.AUTHORIZED},
                    source="127.0.0.2",
                )
                self.assertEqual(resp.status, 404)
                self.assertEqual(body, b"")
                self.assertIsNone(resp.getheader("X-Dropjak-Upstream"))

    def test_authorized_ip_gets_upstream(self) -> None:
        resp, body = self.auth("owui." + ROOT_DOMAIN + ":443", self.AUTHORIZED)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Dropjak-Upstream"), "127.0.0.1:3000")
        self.assertEqual(body, b"")
        resp, _ = self.auth("nas." + ROOT_DOMAIN, self.AUTHORIZED)
        self.assertEqual(resp.status, 200)
        self.assertEqual(
            resp.getheader("X-Dropjak-Upstream"), "192.168.10.20:5001"
        )
        resp, _ = self.auth("wiki." + ROOT_DOMAIN, self.OTHER_DOMAIN)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Dropjak-Upstream"), "127.0.0.1:3002")
        # With a multi-element XFF the last IP (the one Caddy sees) counts.
        resp, _ = self.auth(
            "owui." + ROOT_DOMAIN, f"203.0.113.9, {self.AUTHORIZED}"
        )
        self.assertEqual(resp.status, 200)

    def test_unauthorized_variants_get_login_page(self) -> None:
        for ip in ("198.51.100.99", self.BANNED, "", "not-ip",
                   f"{self.AUTHORIZED}, 203.0.113.9", self.PORT_ONLY,
                   self.OTHER_DOMAIN, self.ADMIN, self.EXPIRED):
            with self.subTest(ip=ip):
                resp, body = self.auth("owui." + ROOT_DOMAIN, ip)
                self.assertEqual(resp.status, 401)
                self.assertIsNone(resp.getheader("X-Dropjak-Upstream"))
                self.assertEqual(
                    resp.getheader("Content-Type"), "text/html; charset=utf-8"
                )
                self.assertEqual(resp.getheader("Cache-Control"), "no-store")
                page = body.decode("utf-8")
                self.assertIn("/__dropjak/unauthorized.png", page)
                self.assertIn(f'href="https://{ROOT_DOMAIN}/"', page)
                # Icon-only login button: blue rectangle, SVG icon, accessible name.
                self.assertIn('class="login"', page)
                self.assertIn('aria-label="Log in"', page)
                self.assertIn('title="Log in"', page)
                self.assertNotIn('class="state-icon"', page)
                self.assertIn("<svg", page)
                # The button is below the image, centered: block-level, with an automatic
                # horizontal margin (otherwise it would slide next to the image).
                self.assertIn("margin:20px auto 0", page)
                # The login page has no visible text from the old Hungarian captions.
                visible = re.sub(r"<[^>]+>", " ", page)
                for removed in (
                    "Nincs hozzáférés", "Bejelentkezés",
                    "Ez a szolgáltatás csak a Dropjak tűzfalon",
                ):
                    with self.subTest(removed=removed):
                        self.assertNotIn(removed, visible)

    def test_login_url_ignores_portal_url(self) -> None:
        # The captive PORTAL_URL is the LAN address; the login page points to the HTTPS root.
        old = gateway.PORTAL_URL
        gateway.PORTAL_URL = 'http://portal/"><script>'
        try:
            _, body = self.auth("owui." + ROOT_DOMAIN, "198.51.100.99")
        finally:
            gateway.PORTAL_URL = old
        self.assertNotIn(b"portal", body)
        self.assertIn(f'href="https://{ROOT_DOMAIN}/"'.encode(), body)

    def test_portal_domain_host_serves_portal_and_roots_redirect(self) -> None:
        portal = "dropjak." + ROOT_DOMAIN
        self.settings.set_portal_domain(portal)
        try:
            for ip in ("198.51.100.99", self.AUTHORIZED):
                with self.subTest(ip=ip):
                    resp, _ = self.auth(portal, ip)
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(
                        resp.getheader("X-Dropjak-Upstream"),
                        f"127.0.0.1:{gateway.PORT}",
                    )
            # Unknown IP: as with any public entry, 401.
            resp, _ = self.auth(portal, "")
            self.assertEqual(resp.status, 401)
            # Without an entry the root no longer belongs to the portal: it has no certificate.
            resp, _ = self.auth(ROOT_DOMAIN, "198.51.100.99")
            self.assertEqual(resp.status, 404)
            self.assertIsNone(resp.getheader("X-Dropjak-Upstream"))
            resp, _ = self.get(f"/api/proxy/ask?domain={ROOT_DOMAIN}")
            self.assertEqual(resp.status, 404)
            resp, _ = self.get(f"/api/proxy/ask?domain={portal}")
            self.assertEqual(resp.status, 200)
            # The portal's address also blocks the loopback endpoints through Caddy.
            resp, _ = self.get("/api/proxy/auth", {
                "X-Forwarded-Host": portal,
                "X-Forwarded-For": "198.51.100.99",
                "X-Forwarded-Uri": "/api/proxy/auth",
            })
            self.assertEqual(resp.status, 404)
            # A challenge can be requested for the portal's address too; the captcha page comes.
            self.settings.set_proxy(
                [ROOT_DOMAIN, SECOND_DOMAIN],
                self.settings.snapshot()["proxy_routes"],
                portal_challenge={"triggers": ["always"]},
            )
            resp, body = self.auth(portal, "198.51.100.99")
            self.assertEqual(resp.status, 403)
            self.assertIn(b"proxy_challenge", body)
            # An entry with an empty name: the root provides its own service.
            snap = self.settings.snapshot()
            self.settings.set_proxy(
                snap["proxy_domains"],
                [dict(route) for route in snap["proxy_routes"]] + [
                    {"name": "", "root": ROOT_DOMAIN, "port": 3003,
                     "visibility": "public"}],
            )
            resp, _ = self.auth(ROOT_DOMAIN, "198.51.100.99")
            self.assertEqual(resp.status, 200)
            self.assertEqual(
                resp.getheader("X-Dropjak-Upstream"), "127.0.0.1:3003"
            )
            resp, _ = self.get(f"/api/proxy/ask?domain={ROOT_DOMAIN}")
            self.assertEqual(resp.status, 200)
        finally:
            snap = self.settings.snapshot()
            self.settings.set_proxy(
                snap["proxy_domains"],
                [route for route in snap["proxy_routes"] if route["name"]],
            )
            self.settings.set_portal_domain("")

    def test_public_entry(self) -> None:
        name = host("pub")
        for ip in ("198.51.100.99", self.PORT_ONLY, self.AUTHORIZED):
            with self.subTest(ip=ip):
                resp, _ = self.auth(name, ip)
                self.assertEqual(resp.status, 200)
                self.assertEqual(
                    resp.getheader("X-Dropjak-Upstream"), "127.0.0.1:3003"
                )
        for ip in (self.BANNED, "", "not-ip"):
            with self.subTest(ip=ip):
                resp, _ = self.auth(name, ip)
                self.assertEqual(resp.status, 401)
                self.assertIsNone(resp.getheader("X-Dropjak-Upstream"))
        # The private entry still requires a domain rule.
        resp, _ = self.auth(host("owui"), "198.51.100.99")
        self.assertEqual(resp.status, 401)

    def test_guard_uses_raw_peer(self) -> None:
        # A loopback peer with an external XFF (Caddy) gets through the guard ...
        resp, _ = self.get(
            f"/api/proxy/ask?domain={ROOT_DOMAIN}",
            {"X-Forwarded-For": "203.0.113.9"},
        )
        self.assertEqual(resp.status, 200)
        # ... a foreign peer with a forged loopback XFF does not.
        for path in (f"/api/proxy/ask?domain={ROOT_DOMAIN}",
                     "/api/proxy/unauthorized.png"):
            with self.subTest(path=path):
                resp, body = self.get(
                    path, {"X-Forwarded-For": "127.0.0.1"}, source="127.0.0.2"
                )
                self.assertEqual(resp.status, 404)
                self.assertEqual(body, b"")
        resp, _ = self.auth(host("pub"), "127.0.0.1", source="127.0.0.2")
        self.assertEqual(resp.status, 404)
        self.assertIsNone(resp.getheader("X-Dropjak-Upstream"))

    def test_root_serves_portal_and_unknown_is_404(self) -> None:
        for root in (ROOT_DOMAIN, SECOND_DOMAIN):
            with self.subTest(root=root):
                resp, _ = self.auth(root + ":443", "198.51.100.99")
                self.assertEqual(resp.status, 200)
                self.assertEqual(
                    resp.getheader("X-Dropjak-Upstream"),
                    f"127.0.0.1:{gateway.PORT}",
                )
        # Through Caddy the proxy endpoints are unreachable (there the peer is loopback).
        for uri in ("/api/proxy/auth", "/api/proxy/ask?domain=x",
                    "/api/proxy/unauthorized.png"):
            with self.subTest(uri=uri):
                resp, _ = self.get("/api/proxy/auth", {
                    "X-Forwarded-Host": ROOT_DOMAIN,
                    "X-Forwarded-For": "198.51.100.99",
                    "X-Forwarded-Uri": uri,
                })
                self.assertEqual(resp.status, 404)
                self.assertIsNone(resp.getheader("X-Dropjak-Upstream"))
        for name in ("off." + ROOT_DOMAIN, "x." + ROOT_DOMAIN,
                     "owui.other.com", "a.owui." + ROOT_DOMAIN,
                     host("nas", SECOND_DOMAIN)):
            with self.subTest(host=name):
                resp, _ = self.auth(name, self.AUTHORIZED)
                self.assertEqual(resp.status, 404)
                self.assertIsNone(resp.getheader("X-Dropjak-Upstream"))

    def test_second_root_entry_is_separate(self) -> None:
        second = host("owui", SECOND_DOMAIN)
        resp, _ = self.auth(second, self.SECOND)
        self.assertEqual(resp.status, 200)
        self.assertEqual(
            resp.getheader("X-Dropjak-Upstream"), "192.168.10.30:8080"
        )
        # The owui.<A> rule does not open owui.<B>, and vice versa; the
        # login page points to the requested entry's own root.
        for name, ip, root in (
            (second, self.AUTHORIZED, SECOND_DOMAIN),
            (host("owui"), self.SECOND, ROOT_DOMAIN),
        ):
            with self.subTest(host=name):
                resp, body = self.auth(name, ip)
                self.assertEqual(resp.status, 401)
                self.assertIsNone(resp.getheader("X-Dropjak-Upstream"))
                self.assertIn(
                    f'href="https://{root}/"', body.decode("utf-8")
                )

    def test_unauthorized_image_served_on_loopback(self) -> None:
        resp, body = self.get("/api/proxy/unauthorized.png")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Type"), "image/png")
        self.assertTrue(body.startswith(b"\x89PNG"))


class ProxiedPortalHttpTests(unittest.TestCase):
    """The portal on the root domain, through Caddy (loopback peer + XFF)."""

    CLIENT = "198.51.100.77"
    PORTAL = "http://192.168.10.1:8100/"

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        tools = FakeTools(cls.tmp.name)
        cls._old = (gateway.PORTAL_URL, gateway.POW_DIFFICULTY,
                    gateway.COOKIE_SECURE)
        gateway.PORTAL_URL = cls.PORTAL
        gateway.POW_DIFFICULTY = 2
        gateway.COOKIE_SECURE = False
        fw = gateway.Firewall(binary=str(tools.nft), logger=lambda *_: None)
        cls.audit_path = os.path.join(cls.tmp.name, "audit.jsonl")
        audit = gateway.AuditLog(cls.audit_path, logger=lambda *_: None)
        users = gateway.UserStore(
            os.path.join(cls.tmp.name, "users.json"), iterations=10_000
        )
        users.add("alice", "hosszu-jelszo-1")
        settings = settings_store.SettingsStore(
            os.path.join(cls.tmp.name, "s.json"), logger=lambda *_: None
        )
        settings.set_proxy([ROOT_DOMAIN], [])
        cls.gw = gateway.Gateway(
            users=users, firewall=fw, catalog=CATALOG,
            rules=gateway.RuleStore(
                os.path.join(cls.tmp.name, "rules.json"), catalog=CATALOG,
                logger=lambda *_: None,
            ),
            groups=gateway.GroupStore(
                os.path.join(cls.tmp.name, "groups.json"),
                logger=lambda *_: None,
            ),
            audit=audit, settings=settings,
            rate_limiter=gateway.RateLimiter(window=60, maximum=1000),
            fail2ban=fail2ban_mod.Fail2ban(
                fw, path=os.path.join(cls.tmp.name, "f2b.json"), audit=audit,
                logger=lambda *_: None,
            ),
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
        (gateway.PORTAL_URL, gateway.POW_DIFFICULTY,
         gateway.COOKIE_SECURE) = cls._old
        cls.tmp.cleanup()

    def request(self, method, path, headers, source="127.0.0.1", body=None):
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=10, source_address=(source, 0)
        )
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def proxied(self, xff=CLIENT, **extra):
        return {"Host": ROOT_DOMAIN, "X-Forwarded-For": xff, **extra}

    def login(self, headers, password="hosszu-jelszo-1", source="127.0.0.1"):
        _, body = self.request("GET", "/api/challenge", headers, source)
        payload = {"user": "alice", "pass": password,
                   "captcha": solve(json.loads(body))}
        return self.request(
            "POST", "/api/login",
            {**headers, "Content-Type": "application/json"}, source,
            json.dumps(payload),
        )

    def last_audit(self, event):
        with open(self.audit_path, encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh]
        return [row for row in rows if row.get("event") == event][-1]

    def test_proxied_login_uses_xff_ip_and_secure_cookie(self) -> None:
        resp, body = self.login(self.proxied(
            Origin=f"https://{ROOT_DOMAIN}"
        ))
        self.assertEqual(resp.status, 200, body)
        self.assertIn("; Secure", resp.getheader("Set-Cookie"))
        self.assertTrue(any(
            s.ip == self.CLIENT for s in self.gw.sessions._sessions.values()
        ))
        self.assertEqual(self.last_audit("login_success")["ip"], self.CLIENT)
        # Failed login: fail2ban also counts the real client IP.
        resp, _ = self.login(self.proxied("198.51.100.78"), "wrong-password")
        self.assertEqual(resp.status, 403)
        self.assertIn("198.51.100.78", self.gw.fail2ban._attempts)
        self.assertEqual(self.last_audit("login_failed")["ip"], "198.51.100.78")

    def test_plain_http_login_has_no_secure_cookie(self) -> None:
        resp, body = self.login({"Host": "192.168.10.1:8100"}, source="127.0.0.3")
        self.assertEqual(resp.status, 200, body)
        self.assertNotIn("Secure", resp.getheader("Set-Cookie"))

    def test_forged_xff_from_non_loopback_is_ignored(self) -> None:
        resp, _ = self.login(
            {"Host": "192.168.10.1:8100", "X-Forwarded-For": "203.0.113.5"},
            "wrong-password", source="127.0.0.2",
        )
        self.assertEqual(resp.status, 403)
        self.assertIn("127.0.0.2", self.gw.fail2ban._attempts)
        self.assertNotIn("203.0.113.5", self.gw.fail2ban._attempts)
        self.assertEqual(self.last_audit("login_failed")["ip"], "127.0.0.2")
        # Invalid XFF from loopback: the peer remains, no crash.
        resp, _ = self.request(
            "GET", "/api/status", self.proxied("not-ip, ::zz")
        )
        self.assertEqual(resp.status, 200)

    def test_root_host_serves_portal_only_via_loopback(self) -> None:
        resp, body = self.request("GET", "/", self.proxied())
        self.assertEqual(resp.status, 200)
        self.assertIn(b"<html", body)
        resp, _ = self.request(
            "GET", "/", {"Host": ROOT_DOMAIN.upper() + ":443"}
        )
        self.assertEqual(resp.status, 200)
        for headers, source in (
            ({"Host": ROOT_DOMAIN, "X-Forwarded-For": "127.0.0.1"},
             "127.0.0.2"),
            ({"Host": "evil.example.com"}, "127.0.0.2"),
            ({"Host": "evil.example.com"}, "127.0.0.1"),
        ):
            with self.subTest(headers=headers, source=source):
                resp, _ = self.request("GET", "/", headers, source)
                self.assertEqual(resp.status, 302)
                self.assertEqual(resp.getheader("Location"), self.PORTAL)

    def test_origin_check_on_https_root(self) -> None:
        resp, _ = self.request(
            "POST", "/api/logout",
            self.proxied(**{"Origin": f"https://{ROOT_DOMAIN}",
                            "Content-Type": "application/json"}),
            body="{}",
        )
        self.assertEqual(resp.status, 200)
        resp, _ = self.request(
            "POST", "/api/logout",
            self.proxied(**{"Origin": "https://evil.example.com",
                            "Content-Type": "application/json"}),
            body="{}",
        )
        self.assertEqual(resp.status, 403)

    # -- DJ-00: HV_WAN_HTTPS_ONLY ------------------------------------------

    WAN = "203.0.113.50"
    LAN = "192.168.10.20"
    KEY = "k" * 40

    def https_only(self):
        """WAN_HTTPS_ONLY on; 127.0.0.5 plays a WAN peer, 127.0.0.6 a LAN one.

        The test server only sees loopback peers, so the peer address is
        mapped; 127.0.0.1 stays the (keyed) Caddy peer.
        """
        mapping = {"127.0.0.5": self.WAN, "127.0.0.6": self.LAN}

        def peer(handler):
            raw = handler.client_address[0]
            return mapping.get(raw, raw)

        stack = mock.patch.multiple(
            gateway, WAN_HTTPS_ONLY=True, PROXY_KEY=self.KEY,
            LAN_NETWORK=ipaddress.ip_network("192.168.10.0/24"),
        )
        stack.start()
        self.addCleanup(stack.stop)
        for patcher in (
            mock.patch.object(server.Handler, "_peer_ip", peer),
            mock.patch.object(
                server, "_HTTPS_REQUIRED_AUDIT",
                gateway.RateLimiter(window=60, maximum=1),
            ),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def audit_rows(self, event):
        with open(self.audit_path, encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh]
        return [row for row in rows if row.get("event") == event]

    def test_wan_https_only_refuses_plain_http_from_wan(self) -> None:
        self.https_only()
        before = len(self.audit_rows("https_required"))
        direct = {"Host": "192.168.10.1:8100"}
        resp, body = self.login(direct, source="127.0.0.5")
        self.assertEqual(resp.status, 403, body)
        self.assertEqual(json.loads(body)["code"], "https_required")
        for method, path in (
            ("POST", "/api/login/totp"), ("POST", "/api/password"),
            ("GET", "/api/admin/state"), ("POST", "/api/admin/users"),
        ):
            with self.subTest(path=path):
                resp, body = self.request(
                    method, path,
                    {**direct, "Content-Type": "application/json"},
                    "127.0.0.5", body="{}" if method == "POST" else None,
                )
                self.assertEqual(resp.status, 403, body)
                self.assertEqual(json.loads(body)["code"], "https_required")
        # The status and challenge endpoints stay open (the page loads).
        resp, _ = self.request("GET", "/api/status", direct, "127.0.0.5")
        self.assertEqual(resp.status, 200)
        # One audit row per IP per minute, however many refusals.
        rows = self.audit_rows("https_required")[before:]
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["ip"], self.WAN)
        self.assertEqual(rows[0]["path"], "/api/login")

    def test_wan_https_only_spares_lan_loopback_and_caddy(self) -> None:
        self.https_only()
        direct = {"Host": "192.168.10.1:8100"}
        # LAN over plain HTTP: allowed, cookie without Secure.
        resp, body = self.login(direct, source="127.0.0.6")
        self.assertEqual(resp.status, 200, body)
        self.assertNotIn("Secure", resp.getheader("Set-Cookie"))
        # Loopback-direct (healthcheck, CLI, host tests).
        resp, body = self.login(direct, source="127.0.0.3")
        self.assertEqual(resp.status, 200, body)
        # Through Caddy (keyed), under any host name: allowed, Secure.
        resp, body = self.login({
            "Host": "192.168.10.1", "X-Forwarded-For": "198.51.100.79",
            server.PROXY_KEY_HEADER: self.KEY,
        })
        self.assertEqual(resp.status, 200, body)
        self.assertIn("; Secure", resp.getheader("Set-Cookie"))
        # A bare loopback peer without the key is not Caddy, and its
        # X-Forwarded-For is ignored: the peer is loopback, so it passes,
        # but the cookie is not Secure.
        resp, body = self.login({**direct, "X-Forwarded-For": self.WAN})
        self.assertEqual(resp.status, 200, body)
        self.assertNotIn("Secure", resp.getheader("Set-Cookie"))

    def test_https_required_has_ui_text_and_audit_label(self) -> None:
        index = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn("https_required: 'Erről a hálózatról csak HTTPS-en", index)
        self.assertIn("  https_required: ['", index)
        self.assertIn("API_ERROR_CODES[data.code]", index)
        for marker in ("'From this network you can sign in only over HTTPS.",
                       "'Aus diesem Netzwerk ist die Anmeldung nur über HTTPS"):
            self.assertIn(marker, index)

    def test_wan_https_only_off_keeps_plain_http(self) -> None:
        mapping = {"127.0.0.5": self.WAN}
        with mock.patch.object(
            server.Handler, "_peer_ip",
            lambda handler: mapping.get(handler.client_address[0],
                                        handler.client_address[0]),
        ):
            resp, body = self.login({"Host": "192.168.10.1:8100"},
                                    source="127.0.0.5")
        self.assertEqual(resp.status, 200, body)


class ProxyFirewallTemplateTests(unittest.TestCase):
    def render(self, proxy: str) -> str:
        text = (ROOT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
        helpers = text[:text.index("ensure_state_dir() {")]
        start = text.index("render_ruleset() {")
        function = text[start:text.index("\n}", start) + 2]
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "r.nft")
            env = dict(
                os.environ, HV_APP_DIR=str(ROOT), HV_NFT_FILE=out,
                HV_LAN_IF="eth1", HV_WAN_IF="eth0",
                HV_LAN_NET="192.168.10.0/24", HV_PORTAL_NET="0.0.0.0/0",
                PORT="8100", HV_PROXY=proxy,
            )
            result = subprocess.run(
                ["sh", "-c", helpers + function + "\nrender_ruleset\n"],
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(out, encoding="utf-8") as fh:
                return fh.read()

    WAN = 'iifname "eth0" tcp dport { 80, 443 } accept'
    LAN = ('iifname "eth1" tcp dport { 80, 443 } ip saddr . ether saddr '
           '@client_mac accept')

    def active_lines(self, rendered: str) -> list[str]:
        return [line.strip() for line in rendered.splitlines()
                if not line.strip().startswith("#")]

    def test_proxy_off_keeps_ports_closed(self) -> None:
        for value in ("0", "", "off"):
            with self.subTest(value=value):
                lines = self.active_lines(self.render(value))
                self.assertNotIn(self.WAN, lines)
                self.assertNotIn(self.LAN, lines)

    def test_proxy_on_accepts_after_ban_block_and_mac_drops(self) -> None:
        rendered = self.render("1")
        lines = self.active_lines(rendered)
        self.assertIn(self.WAN, lines)
        self.assertIn(self.LAN, lines)
        chain = rendered[rendered.index("chain input {"):]
        wan = chain.index(self.WAN)
        self.assertLess(chain.index("ip saddr @banned_v4 ct direction original drop"), wan)
        self.assertLess(chain.index("jump block"), wan)
        self.assertLess(
            chain.index("ether saddr != @client_mac drop"), wan
        )
        self.assertLess(wan, chain.index("chain prerouting"))


class ProductNameTests(unittest.TestCase):
    """The visible product name is Dropjak; the technical identifiers are unchanged."""

    def test_server_header_and_cli_description(self) -> None:
        self.assertEqual(server.Handler.server_version, "Dropjak/2")
        source = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn(
            'description="Manage users in the Dropjak users.json file."',
            source,
        )
        for line in source.splitlines():
            if "Hatarvedelem" in line or (
                "hatarvedelem" in line
                and ("server_version" in line or "description=" in line)
            ):
                self.fail(f"visible product name remained: {line.strip()}")


if __name__ == "__main__":
    unittest.main()
