#!/usr/bin/env python3
"""Domain settings, uploaded certificates and proxy logging.

* the ``proxy_acme`` switch (validation, legacy file default);
* ``CertStore``: valid pair, broken/mismatched/expired/non-covering certificate,
  wildcard coverage, metadata without key material, deletion, orphan cleanup;
* ``/api/proxy/cert`` (loopback, via-proxy protection), ``/api/proxy/ask``
  with ACME turned off;
* ``proxy_page_opened`` audit only for navigation and 200 entries;
* ``proxy-unauthorized`` drop rows for 401, and this does not feed fail2ban's
  drop/port signal;
* admin API (/api/admin/certs, proxy_acme, root deletion).

The test PEMs are once-generated, static EC P-256 pairs (valid until 2126,
and a certificate expired in 2021); no openssl call during the run.
"""

from __future__ import annotations

import http.client
import json
import os
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import fail2ban as fail2ban_mod  # noqa: E402
import gateway  # noqa: E402
import server  # noqa: E402
import settings_store  # noqa: E402
import test_gateway as tg  # noqa: E402
import test_proxy as tp  # noqa: E402

KEY_A = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgN6i2etytxkXgL7a+
Lu78ak5XqhofNa7yWA1/jvIPLS+hRANCAAS65bQqmYQQYIo6rXqiPhJe9TUd7Inu
xMjjUQNwMAB0xvE9m7ytSuOA2l5qZCAA5ByLdFGnvxbXbAtAIfULSOHI
-----END PRIVATE KEY-----
"""
KEY_B = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghCSwCMMahW/93/kW
P2KFvlBauz1ePCy7uh8ryg0BoHKhRANCAAT4CcoNol5IGikhIjUkdmWeP99Cljrd
l/pQzwJrgWn5W87xnKc0PPnyF6vfFj+BevjDiGW/+xNze0nAcXcZ2dRC
-----END PRIVATE KEY-----
"""
# CN=z1.example.com, O=Dropjak Test; SAN: z1.example.com, *.z1.example.com
CERT_VALID = """-----BEGIN CERTIFICATE-----
MIIB5jCCAYugAwIBAgIUYC19A2baCIZQj408P1c5AArgp98wCgYIKoZIzj0EAwIw
MDEXMBUGA1UEAwwOejEuZXhhbXBsZS5jb20xFTATBgNVBAoMDERyb3BqYWsgVGVz
dDAgFw0yNjEwMjEyMDQyMDdaGA8yMTI2MDkyNzIwNDIwN1owMDEXMBUGA1UEAwwO
ejEuZXhhbXBsZS5jb20xFTATBgNVBAoMDERyb3BqYWsgVGVzdDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABLrltCqZhBBgijqteqI+El71NR3sie7EyONRA3AwAHTG
8T2bvK1K44DaXmpkIADkHIt0Uae/FtdsC0Ah9QtI4cijgYAwfjAdBgNVHQ4EFgQU
5IsGnuTHqrJjfzO37ztMka2Ap8wwHwYDVR0jBBgwFoAU5IsGnuTHqrJjfzO37ztM
ka2Ap8wwDwYDVR0TAQH/BAUwAwEB/zArBgNVHREEJDAigg56MS5leGFtcGxlLmNv
bYIQKi56MS5leGFtcGxlLmNvbTAKBggqhkjOPQQDAgNJADBGAiEAvn1Pc3eayyMy
sbSYFW5vQl3RLmNT+d6AUOfLWpo9aGcCIQDaB6KtgZ/TfqaZCCmSx1v/ePDt3wju
dz674+jH6I8AVw==
-----END CERTIFICATE-----
"""
# SAN: only *.z1.example.com (it does not cover the root itself)
CERT_WILD = """-----BEGIN CERTIFICATE-----
MIIBqjCCAVCgAwIBAgIUEX4oUzzq0HIkAu084I4n+hu5zMswCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQKi56MS5leGFtcGxlLmNvbTAgFw0yNjEwMjEyMDQyMDdaGA8y
MTI2MDkyNzIwNDIwN1owGzEZMBcGA1UEAwwQKi56MS5leGFtcGxlLmNvbTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABLrltCqZhBBgijqteqI+El71NR3sie7EyONR
A3AwAHTG8T2bvK1K44DaXmpkIADkHIt0Uae/FtdsC0Ah9QtI4cijcDBuMB0GA1Ud
DgQWBBTkiwae5MeqsmN/M7fvO0yRrYCnzDAfBgNVHSMEGDAWgBTkiwae5MeqsmN/
M7fvO0yRrYCnzDAPBgNVHRMBAf8EBTADAQH/MBsGA1UdEQQUMBKCECouejEuZXhh
bXBsZS5jb20wCgYIKoZIzj0EAwIDSAAwRQIgIh765TGGfHYctMstD/0NsFeWrlCA
fxWJnXXy6fTGMCYCIQDeduPL82HRVuo8usRyXUdqBv7E/9GpeZdKSX7gDD6JhQ==
-----END CERTIFICATE-----
"""
# SAN: other.example.net
CERT_OTHER = """-----BEGIN CERTIFICATE-----
MIIBrjCCAVOgAwIBAgIUM9urgqumUJmjJBQjvdj4h73jhFkwCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRb3RoZXIuZXhhbXBsZS5uZXQwIBcNMjYxMDIxMjA0MjA3WhgP
MjEyNjA5MjcyMDQyMDdaMBwxGjAYBgNVBAMMEW90aGVyLmV4YW1wbGUubmV0MFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuuW0KpmEEGCKOq16oj4SXvU1HeyJ7sTI
41EDcDAAdMbxPZu8rUrjgNpeamQgAOQci3RRp78W12wLQCH1C0jhyKNxMG8wHQYD
VR0OBBYEFOSLBp7kx6qyY38zt+87TJGtgKfMMB8GA1UdIwQYMBaAFOSLBp7kx6qy
Y38zt+87TJGtgKfMMA8GA1UdEwEB/wQFMAMBAf8wHAYDVR0RBBUwE4IRb3RoZXIu
ZXhhbXBsZS5uZXQwCgYIKoZIzj0EAwIDSQAwRgIhAIJTvdSElHSzhqbNJqAxCuZW
8Qe09z0JvCCJJkQIiwR6AiEA0UaZzFAUxjjCi06Y0ENn9ElCR92GeW667TTJmnxz
aB4=
-----END CERTIFICATE-----
"""
# 2020-01-01 – 2021-01-01, SAN: z1.example.com, *.z1.example.com
CERT_EXPIRED = """-----BEGIN CERTIFICATE-----
MIIBtTCCAVugAwIBAgIUOaZ/uHCVP8g0Y165OA3Qa5VEWMQwCgYIKoZIzj0EAwIw
GTEXMBUGA1UEAwwOejEuZXhhbXBsZS5jb20wHhcNMjAwMTAxMDAwMDAwWhcNMjEw
MTAxMDAwMDAwWjAZMRcwFQYDVQQDDA56MS5leGFtcGxlLmNvbTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABLrltCqZhBBgijqteqI+El71NR3sie7EyONRA3AwAHTG
8T2bvK1K44DaXmpkIADkHIt0Uae/FtdsC0Ah9QtI4cijgYAwfjAdBgNVHQ4EFgQU
5IsGnuTHqrJjfzO37ztMka2Ap8wwHwYDVR0jBBgwFoAU5IsGnuTHqrJjfzO37ztM
ka2Ap8wwDwYDVR0TAQH/BAUwAwEB/zArBgNVHREEJDAigg56MS5leGFtcGxlLmNv
bYIQKi56MS5leGFtcGxlLmNvbTAKBggqhkjOPQQDAgNIADBFAiEAxsrJ8w9SRyqd
WmxtvaVsVEOnQ+0kYb7RiN6+gyrKy+ICIBJxg9TqKwHzvxskVGCkcTfHcjNLB+5J
TperK9H6NATh
-----END CERTIFICATE-----
"""
ROOT_DOMAIN = tp.ROOT_DOMAIN
SECOND = tp.SECOND_DOMAIN
ROUTES = [
    {"name": "owui", "port": 3000, **tp.R},
    {"name": "pub", "port": 3003, "visibility": "public", **tp.R},
]
KEY_MARKERS = ("PRIVATE", "BEGIN", "MIGHAgEA")


def quiet(*_args) -> None:
    pass


class ProxyAcmeSettingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "s.json")

    def test_default_legacy_and_validation(self) -> None:
        store = settings_store.SettingsStore(self.path, logger=quiet)
        self.assertIs(store.snapshot()["proxy_acme"], True)
        # Legacy file without a key: the earlier behaviour (ACME on).
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({"proxy_domains": [ROOT_DOMAIN], "proxy_routes": []}, fh)
        store = settings_store.SettingsStore(self.path, logger=quiet)
        self.assertIs(store.snapshot()["proxy_acme"], True)
        store.set_proxy_acme(False)
        reloaded = settings_store.SettingsStore(self.path, logger=quiet)
        self.assertIs(reloaded.snapshot()["proxy_acme"], False)
        self.assertEqual(reloaded.snapshot()["proxy_domains"], [ROOT_DOMAIN])
        for value in ("false", 0, 1, None, []):
            with self.subTest(value=value):
                with self.assertRaises(settings_store.SettingsError):
                    store.set_proxy_acme(value)
                with self.assertRaises(settings_store.SettingsError):
                    settings_store.validate_state({"proxy_acme": value})


class CertStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, "certs")
        self.store = settings_store.CertStore(self.dir, logger=quiet)
        self.settings = {
            "proxy_domains": [ROOT_DOMAIN, SECOND],
            "proxy_routes": [
                {"name": "owui", "root": ROOT_DOMAIN},
                {"name": "x", "root": SECOND},
            ],
        }

    def test_valid_pair_files_and_metadata(self) -> None:
        meta = self.store.install(ROOT_DOMAIN, CERT_VALID, KEY_A)
        self.assertEqual(meta["subject_cn"], ROOT_DOMAIN)
        self.assertEqual(meta["issuer"], ROOT_DOMAIN)
        self.assertEqual(meta["sans"], [ROOT_DOMAIN, f"*.{ROOT_DOMAIN}"])
        self.assertEqual(len(meta["fingerprint"]), 64)
        self.assertGreater(meta["not_after"], meta["not_before"])
        self.assertEqual(os.stat(self.dir).st_mode & 0o777, 0o700)
        self.assertEqual(
            sorted(os.listdir(self.dir)),
            [f"{ROOT_DOMAIN}.key", f"{ROOT_DOMAIN}.pem"],
        )
        for name in os.listdir(self.dir):
            self.assertEqual(
                os.stat(os.path.join(self.dir, name)).st_mode & 0o777, 0o600
            )
        public = self.store.public(self.settings)
        self.assertEqual([item["root"] for item in public], [ROOT_DOMAIN, SECOND])
        first, second = public
        self.assertTrue(first["installed"])
        self.assertEqual(first["covered"], [ROOT_DOMAIN, f"owui.{ROOT_DOMAIN}"])
        self.assertEqual(first["uncovered"], [])
        self.assertEqual(first["warning"], "")
        self.assertEqual(second, {"root": SECOND, "installed": False})
        text = json.dumps(public)
        for marker in KEY_MARKERS:
            self.assertNotIn(marker, text)
        # After a restart the same thing is loaded from disk.
        reloaded = settings_store.CertStore(self.dir, logger=quiet)
        self.assertEqual(reloaded.public(self.settings), public)

    def test_wildcard_covers_entries_but_not_root(self) -> None:
        self.store.install(ROOT_DOMAIN, CERT_WILD, KEY_A)
        first = self.store.public(self.settings)[0]
        self.assertEqual(first["covered"], [f"owui.{ROOT_DOMAIN}"])
        self.assertEqual(first["uncovered"], [ROOT_DOMAIN])
        self.assertIsNotNone(self.store.bundle(f"owui.{ROOT_DOMAIN}", ROOT_DOMAIN))
        self.assertIsNone(self.store.bundle(ROOT_DOMAIN, ROOT_DOMAIN))
        # Only one label: the deeper name is not covered.
        self.assertIsNone(
            self.store.bundle(f"a.owui.{ROOT_DOMAIN}", ROOT_DOMAIN)
        )

    def test_rejections_write_nothing(self) -> None:
        cases = [
            ("mismatched key", ROOT_DOMAIN, CERT_VALID, KEY_B, "do not belong together"),
            ("garbage", ROOT_DOMAIN, "not pem", KEY_A, "CERTIFICATE"),
            ("bad base64", ROOT_DOMAIN,
             "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
             KEY_A, "do not belong together"),
            ("garbage key", ROOT_DOMAIN, CERT_VALID, "x", "PRIVATE KEY"),
            ("too large", ROOT_DOMAIN,
             CERT_VALID + " " * settings_store.MAX_CERT_PEM, KEY_A, "KiB"),
            ("expired", ROOT_DOMAIN, CERT_EXPIRED, KEY_A, "expired"),
            ("does not cover", ROOT_DOMAIN, CERT_OTHER, KEY_A, "does not cover"),
            ("other root", SECOND, CERT_VALID, KEY_A, "does not cover"),
            ("key in the chain", ROOT_DOMAIN, CERT_VALID + KEY_A, KEY_A,
             "CERTIFICATE"),
            ("encrypted", ROOT_DOMAIN, CERT_VALID,
             KEY_A.replace("PRIVATE", "ENCRYPTED PRIVATE"), "unencrypted"),
            ("not text", ROOT_DOMAIN, None, KEY_A, "PEM"),
            ("bad root", "../x", CERT_VALID, KEY_A, "domain name"),
        ]
        for label, root, chain, key, message in cases:
            with self.subTest(label):
                with self.assertRaisesRegex(
                    settings_store.SettingsError, message
                ):
                    self.store.install(root, chain, key)
        self.assertEqual(os.listdir(self.dir) if os.path.isdir(self.dir) else [], [])
        self.assertEqual(self.store.public(self.settings)[0]["installed"], False)

    def test_bundle_expiry_warning_delete_and_prune(self) -> None:
        meta = self.store.install(ROOT_DOMAIN, CERT_VALID, KEY_A)
        bundle = self.store.bundle(f"owui.{ROOT_DOMAIN}", ROOT_DOMAIN)
        self.assertEqual(bundle, (CERT_VALID + KEY_A).encode("ascii"))
        self.assertIsNone(self.store.bundle(SECOND, SECOND))
        late = meta["not_after"] - 5 * 86400
        self.assertEqual(
            self.store.public(self.settings, now=late)[0]["warning"],
            "expiring",
        )
        after = meta["not_after"] + 1
        self.assertEqual(
            self.store.public(self.settings, now=after)[0]["warning"],
            "expired",
        )
        # Caddy does not get the expired uploaded certificate (204).
        self.assertIsNone(
            self.store.bundle(ROOT_DOMAIN, ROOT_DOMAIN, now=after)
        )
        self.assertEqual(self.store.prune([ROOT_DOMAIN]), {})
        self.assertEqual(
            list(self.store.prune([SECOND])), [ROOT_DOMAIN]
        )
        self.assertEqual(os.listdir(self.dir), [])
        self.assertIsNone(self.store.delete(ROOT_DOMAIN))

    def test_load_skips_mismatched_pair(self) -> None:
        self.store.install(ROOT_DOMAIN, CERT_VALID, KEY_A)
        with open(os.path.join(self.dir, f"{ROOT_DOMAIN}.key"), "w") as fh:
            fh.write(KEY_B)
        logs: list[str] = []
        reloaded = settings_store.CertStore(self.dir, logger=logs.append)
        self.assertFalse(reloaded.public(self.settings)[0]["installed"])
        self.assertTrue(any(ROOT_DOMAIN in line for line in logs))


class ProxyCertEndpointTests(unittest.TestCase):
    PRIVATE_USER_IP = "198.51.100.10"
    OUTSIDER = "198.51.100.99"

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.settings = settings_store.SettingsStore(
            os.path.join(cls.tmp.name, "s.json"), logger=quiet
        )
        cls.settings.set_proxy([ROOT_DOMAIN, SECOND], ROUTES)
        cls.certs = settings_store.CertStore(
            os.path.join(cls.tmp.name, "certs"), logger=quiet
        )
        cls.certs.install(ROOT_DOMAIN, CERT_VALID, KEY_A)
        sessions = gateway.SessionManager(firewall=None)
        tp.add_session(sessions, cls.PRIVATE_USER_IP, (tp.host("owui"),))
        cls.audits: list = []
        cls.drops: list = []
        gw = types.SimpleNamespace(
            settings=cls.settings, sessions=sessions, certs=cls.certs,
            fail2ban=types.SimpleNamespace(
                banned=lambda ip: None, proxy_banned=lambda ip: None,
                record_proxy_unauthorized=lambda ip: None,
            ),
            audit=types.SimpleNamespace(
                write=lambda event, **f: cls.audits.append((event, f))
            ),
            record_proxy_drop=lambda *args: cls.drops.append(args),
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

    def setUp(self) -> None:
        self.audits.clear()
        self.drops.clear()

    get = tp.ProxyEndpointTests.get

    def cert(self, name, headers=None, source="127.0.0.1"):
        return self.get(f"/api/proxy/cert?server_name={name}", headers, source)

    def auth(self, name, ip, **headers):
        bind = tp.bind_cookie(self.server.gateway.sessions, ip, name)
        return self.get("/api/proxy/auth", {
            "X-Forwarded-Host": name, "X-Forwarded-For": ip,
            "X-Forwarded-Uri": "/chat/abc?token=titok",
            **({"Cookie": bind} if bind else {}), **headers,
        })

    def test_loopback_covered_name_gets_chain_and_key(self) -> None:
        # The unknown but wildcard-covered name too (for the challenge).
        for name in (ROOT_DOMAIN, f"owui.{ROOT_DOMAIN}", f"PUB.{ROOT_DOMAIN}",
                     f"x.{ROOT_DOMAIN}"):
            with self.subTest(name=name):
                resp, body = self.cert(name)
                self.assertEqual(resp.status, 200)
                self.assertEqual(
                    resp.getheader("Content-Type"), "application/x-pem-file"
                )
                self.assertEqual(resp.getheader("Cache-Control"), "no-store")
                self.assertEqual(body, (CERT_VALID + KEY_A).encode("ascii"))

    def test_uncovered_or_unknown_name_is_204(self) -> None:
        for name in (SECOND, f"x.{SECOND}", f"a.owui.{ROOT_DOMAIN}",
                     "evil.example.com", ""):
            with self.subTest(name=name):
                resp, body = self.cert(name)
                self.assertEqual(resp.status, 204)
                self.assertEqual(body, b"")

    def test_non_loopback_and_proxied_requests_get_nothing(self) -> None:
        variants = [
            ({}, "127.0.0.2"),
            ({"X-Forwarded-For": self.OUTSIDER}, "127.0.0.1"),
            ({"X-Forwarded-Host": ROOT_DOMAIN}, "127.0.0.1"),
            ({"X-Forwarded-Uri": "/api/proxy/cert"}, "127.0.0.1"),
            # Caddy's reverse_proxy passes the root Host to the portal.
            ({"Host": ROOT_DOMAIN}, "127.0.0.1"),
        ]
        for headers, source in variants:
            with self.subTest(headers=headers, source=source):
                resp, body = self.cert(ROOT_DOMAIN, headers, source)
                self.assertEqual(resp.status, 404)
                self.assertEqual(body, b"")
        # Through the root domain (forward_auth) Caddy does not even forward it.
        resp, body = self.get("/api/proxy/auth", {
            "X-Forwarded-Host": ROOT_DOMAIN,
            "X-Forwarded-For": self.OUTSIDER,
            "X-Forwarded-Uri": f"/api/proxy/cert?server_name={ROOT_DOMAIN}",
        })
        self.assertEqual(resp.status, 404)
        self.assertIsNone(resp.getheader("X-Dropjak-Upstream"))
        self.assertNotIn(b"PRIVATE", body)

    def test_ask_is_404_when_acme_is_off(self) -> None:
        self.addCleanup(self.settings.set_proxy_acme, True)
        for acme, code in ((True, 200), (False, 404)):
            self.settings.set_proxy_acme(acme)
            for name in (ROOT_DOMAIN, f"owui.{ROOT_DOMAIN}", SECOND):
                with self.subTest(acme=acme, name=name):
                    resp, _ = self.get(f"/api/proxy/ask?domain={name}")
                    self.assertEqual(resp.status, code)
        # The uploaded certificate is served even with ACME turned off.
        resp, _ = self.cert(ROOT_DOMAIN)
        self.assertEqual(resp.status, 200)

    def opened(self) -> list[dict]:
        return [f for event, f in self.audits if event == "proxy_page_opened"]

    def test_page_open_audit_only_for_navigations(self) -> None:
        owui = f"owui.{ROOT_DOMAIN}"
        navigations = (
            {"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"},
            {"Sec-Fetch-Mode": "navigate"},
            {"Accept": "text/html,application/xhtml+xml"},
            {"Accept": "text/html", "X-Forwarded-Method": "GET"},
        )
        for headers in navigations:
            with self.subTest(headers=headers):
                self.audits.clear()
                resp, _ = self.auth(owui, self.PRIVATE_USER_IP, **headers)
                self.assertEqual(resp.status, 200)
                [row] = self.opened()
                self.assertEqual(row["ip"], self.PRIVATE_USER_IP)
                self.assertEqual(row["user"], "u")
                self.assertEqual(row["host"], owui)
                self.assertEqual(row["path"], "/chat/abc")
                self.assertEqual(row["visibility"], "private")
        not_navigations = (
            {"Sec-Fetch-Dest": "script", "Sec-Fetch-Mode": "no-cors"},
            {"Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
             "Accept": "text/html"},
            {"Sec-Fetch-Dest": "iframe", "Sec-Fetch-Mode": "navigate"},
            {"Accept": "application/json"},
            {"Accept": "text/html", "X-Forwarded-Method": "POST"},
            {},
        )
        self.audits.clear()
        for headers in not_navigations:
            with self.subTest(headers=headers):
                resp, _ = self.auth(owui, self.PRIVATE_USER_IP, **headers)
                self.assertEqual(resp.status, 200)
        self.assertEqual(self.opened(), [])
        nav = {"Sec-Fetch-Dest": "document"}
        # Public entry: empty user; long path truncated.
        resp, _ = self.auth(
            f"pub.{ROOT_DOMAIN}", self.OUTSIDER,
            **{**nav, "X-Forwarded-Uri": "/" + "a" * 500},
        )
        self.assertEqual(resp.status, 200)
        [row] = self.opened()
        self.assertEqual((row["user"], row["visibility"]), ("", "public"))
        self.assertEqual(len(row["path"]), 200)
        # The root domain's portal, the 401 and the 404 are not proxy page opens.
        self.audits.clear()
        for name, ip, code in ((ROOT_DOMAIN, self.OUTSIDER, 200),
                               (owui, self.OUTSIDER, 401),
                               (f"x.{SECOND}", self.OUTSIDER, 404)):
            with self.subTest(name=name):
                resp, _ = self.auth(name, ip, **nav)
                self.assertEqual(resp.status, code)
        self.assertEqual(self.opened(), [])

    def test_drop_event_only_on_401(self) -> None:
        owui = f"owui.{ROOT_DOMAIN}"
        for name, ip, code in ((owui, self.PRIVATE_USER_IP, 200),
                               (f"pub.{ROOT_DOMAIN}", self.OUTSIDER, 200),
                               (ROOT_DOMAIN, self.OUTSIDER, 200),
                               (f"x.{SECOND}", self.OUTSIDER, 404)):
            with self.subTest(name=name):
                resp, _ = self.auth(name, ip)
                self.assertEqual(resp.status, code)
        self.assertEqual(self.drops, [])
        resp, _ = self.auth(owui, self.OUTSIDER)
        self.assertEqual(resp.status, 401)
        self.assertEqual(self.drops, [(self.OUTSIDER, owui, "/chat/abc")])


class ProxyDropSignalTests(unittest.TestCase):
    """proxy-unauthorized drop rows do not trigger the drop/port signal."""

    IP = "203.0.113.50"

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        tools = tg.FakeTools(self.tmp.name)
        fw = gateway.Firewall(binary=str(tools.nft), logger=quiet)
        audit = gateway.AuditLog(
            os.path.join(self.tmp.name, "audit.jsonl"), logger=quiet
        )
        self.drops = gateway.droplog.DropLogService(
            os.path.join(self.tmp.name, "drops.jsonl"), enabled=False,
            logger=quiet,
        )
        self.f2b = fail2ban_mod.Fail2ban(
            fw, path=os.path.join(self.tmp.name, "f2b.json"), audit=audit,
            logger=quiet, drop_count_enabled=True, drop_ports_enabled=True,
            drop_max=5, drop_ports=3, drop_window_seconds=600,
        )
        self.gw = gateway.Gateway(
            users=gateway.UserStore(
                os.path.join(self.tmp.name, "users.json"), iterations=10_000
            ),
            firewall=fw, catalog=tg.CATALOG, audit=audit,
            rules=gateway.RuleStore(
                os.path.join(self.tmp.name, "rules.json"),
                catalog=tg.CATALOG, logger=quiet,
            ),
            groups=gateway.GroupStore(
                os.path.join(self.tmp.name, "groups.json"), logger=quiet
            ),
            settings=settings_store.SettingsStore(
                os.path.join(self.tmp.name, "s.json"), logger=quiet
            ),
            drops=self.drops, fail2ban=self.f2b,
        )

    def test_proxy_drop_rows_do_not_feed_drop_signals(self) -> None:
        for index in range(40):
            self.gw.record_proxy_drop(self.IP, "owui.z1.example.com", f"/{index}")
        rows = self.drops.read()
        # Following the nft log rules, 30/minute.
        self.assertEqual(len(rows), 30)
        self.assertTrue(all(
            row["reason"] == "proxy-unauthorized" and row["group"] == "proxy"
            and row["src"] == self.IP for row in rows
        ))
        # The same would not count through the NFLOG callback either (reason filtering).
        for port in (80, 443, 8080, 8443, 22, 3000):
            self.drops.listener._count_packet({
                "reason": "proxy-unauthorized", "src": self.IP,
                "proto": "tcp", "dport": port,
            })
        self.assertEqual(self.f2b._drop_events, {})
        self.assertIsNone(self.f2b.banned(self.IP))
        # Positive control: a real drop packet leads to a ban in the same place.
        for port in (81, 82, 83):
            self.drops.listener._count_packet({
                "reason": "wan-drop", "src": self.IP,
                "proto": "tcp", "dport": port,
            })
        self.assertIsNotNone(self.f2b.banned(self.IP))


class CertAdminHttpTests(unittest.TestCase):
    """Admin API: /api/admin/certs, proxy_acme, root deletion."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        tools = tg.FakeTools(cls.tmp.name)
        cls._old = (gateway.POW_DIFFICULTY, gateway.PORTAL_URL)
        gateway.POW_DIFFICULTY = 2
        gateway.PORTAL_URL = ""
        fw = gateway.Firewall(binary=str(tools.nft), logger=quiet)
        cls.audit_path = os.path.join(cls.tmp.name, "audit.jsonl")
        audit = gateway.AuditLog(cls.audit_path, logger=quiet)
        users = gateway.UserStore(
            os.path.join(cls.tmp.name, "users.json"), iterations=10_000
        )
        users.add("root", "root-jelszo-1", role=gateway.ROLE_ADMIN)
        users.add("alice", "alice-jelszo-1")
        cls.settings = settings_store.SettingsStore(
            os.path.join(cls.tmp.name, "firewall-settings.json"), logger=quiet
        )
        cls.gw = gateway.Gateway(
            users=users, firewall=fw, catalog=tg.CATALOG, audit=audit,
            rules=gateway.RuleStore(
                os.path.join(cls.tmp.name, "rules.json"),
                catalog=tg.CATALOG, logger=quiet,
            ),
            groups=gateway.GroupStore(
                os.path.join(cls.tmp.name, "groups.json"), logger=quiet
            ),
            rate_limiter=gateway.RateLimiter(window=60, maximum=1000),
            settings=cls.settings,
            drops=gateway.droplog.DropLogService(
                os.path.join(cls.tmp.name, "drops.jsonl"), enabled=False,
                logger=quiet,
            ),
            fail2ban=fail2ban_mod.Fail2ban(
                fw, path=os.path.join(cls.tmp.name, "f2b.json"),
                audit=audit, logger=quiet,
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
        gateway.POW_DIFFICULTY, gateway.PORTAL_URL = cls._old
        cls.tmp.cleanup()

    def setUp(self) -> None:
        self.settings.set_proxy([ROOT_DOMAIN, SECOND], ROUTES)
        self.settings.set_proxy_acme(True)
        self.gw.certs.prune([])

    conn = tg.AdminHttpTests.conn
    get = tg.AdminHttpTests.get
    post = tg.AdminHttpTests.post
    login = tg.AdminHttpTests.login

    def admin(self) -> str:
        cookie, data = self.login("root", "root-jelszo-1", source="127.0.0.5")
        self.assertTrue(data["admin"])
        return cookie

    def audit_rows(self) -> list[dict]:
        with open(self.audit_path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh]

    def test_upload_metadata_only_and_audit(self) -> None:
        cookie = self.admin()
        # A JSON body over 64 KiB (two large PEMs) also gets through this endpoint.
        status, _, body = self.post("/api/admin/certs", {
            "action": "upload", "root": ROOT_DOMAIN,
            "cert": CERT_VALID + "\n" * 40000, "key": KEY_A + "\n" * 10000,
        }, cookie=cookie, source="127.0.0.5")
        self.assertEqual(status, 200, body)
        for marker in KEY_MARKERS:
            self.assertNotIn(marker.encode(), body)
        data = json.loads(body)
        [first, second] = data["proxy_certs"]
        self.assertTrue(first["installed"])
        self.assertEqual(first["covered"], [ROOT_DOMAIN, f"owui.{ROOT_DOMAIN}",
                                            f"pub.{ROOT_DOMAIN}"])
        self.assertFalse(second["installed"])
        status, _, body = self.get(
            "/api/admin/state", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200)
        for marker in KEY_MARKERS:
            self.assertNotIn(marker.encode(), body)
        [row] = [r for r in self.audit_rows()
                 if r.get("action") == "proxy_cert_upload"]
        self.assertEqual(row["target"], ROOT_DOMAIN)
        self.assertEqual(row["sans"], f"{ROOT_DOMAIN}, *.{ROOT_DOMAIN}")
        self.assertEqual(row["fingerprint"], first["fingerprint"])
        self.assertEqual(row["not_after"], first["not_after"])
        with open(self.audit_path, encoding="utf-8") as fh:
            text = fh.read()
        for marker in KEY_MARKERS:
            self.assertNotIn(marker, text)
        # Delete, then again: nothing left to delete.
        status, _, body = self.post("/api/admin/certs", {
            "action": "delete", "root": ROOT_DOMAIN,
        }, cookie=cookie, source="127.0.0.5")
        self.assertEqual(status, 200, body)
        self.assertFalse(json.loads(body)["proxy_certs"][0]["installed"])
        status, _, _ = self.post("/api/admin/certs", {
            "action": "delete", "root": ROOT_DOMAIN,
        }, cookie=cookie, source="127.0.0.5")
        self.assertEqual(status, 400)

    def test_rejections(self) -> None:
        cookie = self.admin()
        for payload in (
            {"action": "upload", "root": ROOT_DOMAIN, "cert": CERT_VALID,
             "key": KEY_B},
            {"action": "upload", "root": ROOT_DOMAIN, "cert": CERT_EXPIRED,
             "key": KEY_A},
            {"action": "upload", "root": "z9.example.com", "cert": CERT_VALID,
             "key": KEY_A},
            {"action": "frob", "root": ROOT_DOMAIN},
        ):
            with self.subTest(payload=payload.get("action")):
                status, _, body = self.post(
                    "/api/admin/certs", payload, cookie=cookie,
                    source="127.0.0.5",
                )
                self.assertEqual(status, 400, body)
                self.assertNotIn(b"PRIVATE", body)
        user, _ = self.login("alice", "alice-jelszo-1", source="127.0.0.6")
        status, _, _ = self.post("/api/admin/certs", {
            "action": "upload", "root": ROOT_DOMAIN, "cert": CERT_VALID,
            "key": KEY_A,
        }, cookie=user, source="127.0.0.6")
        self.assertEqual(status, 403)
        self.assertEqual(os.listdir(self.gw.certs.directory), [])

    def test_proxy_acme_action_and_root_removal_prunes_cert(self) -> None:
        cookie = self.admin()
        status, _, body = self.post("/api/admin/settings", {
            "action": "proxy_acme", "enabled": False,
        }, cookie=cookie, source="127.0.0.5")
        self.assertEqual(status, 200, body)
        self.assertIs(json.loads(body)["settings"]["proxy_acme"], False)
        status, _, _ = self.post("/api/admin/settings", {
            "action": "proxy_acme", "enabled": "no",
        }, cookie=cookie, source="127.0.0.5")
        self.assertEqual(status, 400)
        self.gw.certs.install(ROOT_DOMAIN, CERT_VALID, KEY_A)
        status, _, body = self.post("/api/admin/settings", {
            "action": "proxy", "proxy_domains": [SECOND], "proxy_routes": [],
        }, cookie=cookie, source="127.0.0.5")
        self.assertEqual(status, 200, body)
        self.assertEqual(os.listdir(self.gw.certs.directory), [])
        self.assertEqual(
            json.loads(body)["proxy_certs"],
            [{"root": SECOND, "installed": False}],
        )
        self.assertTrue(any(
            r.get("action") == "proxy_cert_delete"
            and r.get("target") == ROOT_DOMAIN for r in self.audit_rows()
        ))


class HttpsPortalRedirectTests(unittest.TestCase):
    """The http portal opened directly from the WAN redirects with 308 to the HTTPS root."""

    WAN, BANNED, PROXY_BANNED, LAN = (
        "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.settings = settings_store.SettingsStore(
            os.path.join(cls.tmp.name, "s.json"), logger=lambda *_: None
        )
        cls.settings.set_proxy([ROOT_DOMAIN, tp.SECOND_DOMAIN], [])
        cls.certs = settings_store.CertStore(
            os.path.join(cls.tmp.name, "certs"), logger=lambda *_: None
        )
        cls.audits = []
        gw = types.SimpleNamespace(
            settings=cls.settings,
            sessions=gateway.SessionManager(firewall=None),
            fail2ban=types.SimpleNamespace(
                banned=lambda ip: {"ip": ip} if ip == cls.BANNED else None,
                proxy_banned=lambda ip: (
                    {"ip": ip} if ip == cls.PROXY_BANNED else None
                ),
            ),
            audit=types.SimpleNamespace(
                write=lambda event, **f: cls.audits.append((event, f))
            ),
            certs=cls.certs,
        )
        cls._old = (gateway.PORTAL_URL, gateway.PROXY_ENABLED,
                    gateway.LAN_NETWORK)
        gateway.PORTAL_URL = "http://192.168.10.1:8100/"
        gateway.PROXY_ENABLED = True
        gateway.LAN_NETWORK = gateway.ipaddress.ip_network(cls.LAN + "/32")
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
        (gateway.PORTAL_URL, gateway.PROXY_ENABLED,
         gateway.LAN_NETWORK) = cls._old
        cls.tmp.cleanup()

    def request(self, path="/", source=WAN, method="GET", headers=None):
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=10, source_address=(source, 0)
        )
        conn.request(method, path, body=b"" if method == "POST" else None,
                     headers=headers or {"Host": "203.0.113.1:8100"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp

    def assertRedirect(self, resp, target) -> None:
        self.assertEqual(resp.status, 308)
        self.assertEqual(resp.getheader("Location"), target)

    def assertNoHttpsRedirect(self, resp) -> None:
        self.assertFalse(
            (resp.getheader("Location") or "").startswith("https://"),
            resp.getheader("Location"),
        )

    def test_wan_get_and_head_redirect_with_path_and_query(self) -> None:
        self.assertRedirect(self.request(), f"https://{ROOT_DOMAIN}/")
        self.assertRedirect(
            self.request("/x/y?a=1&b=2"), f"https://{ROOT_DOMAIN}/x/y?a=1&b=2"
        )
        self.assertRedirect(
            self.request("/?q", method="HEAD"), f"https://{ROOT_DOMAIN}/?q"
        )
        event, fields = self.audits[-1]
        self.assertEqual(event, "portal_https_redirect")
        self.assertEqual(fields["target"], f"https://{ROOT_DOMAIN}/?q")
        self.assertEqual(fields["ip"], self.WAN)
        # Also without a foreign Host (with the gateway's own address).
        self.assertRedirect(
            self.request(headers={"Host": "192.168.10.1:8100"}),
            f"https://{ROOT_DOMAIN}/",
        )

    def test_post_and_api_not_redirected(self) -> None:
        self.assertEqual(self.request("/api/nonexistent").status, 404)
        self.assertNoHttpsRedirect(self.request("/", method="POST"))
        self.assertNoHttpsRedirect(self.request("/api/logout", method="POST"))

    def test_lan_loopback_and_banned_keep_http_portal(self) -> None:
        for source in (self.LAN, "127.0.0.1", self.BANNED, self.PROXY_BANNED):
            with self.subTest(source=source):
                resp = self.request(source=source)
                # The foreign-Host captive redirect stays at the gateway's address.
                self.assertEqual(resp.status, 302)
                self.assertEqual(
                    resp.getheader("Location"), gateway.PORTAL_URL
                )

    def test_via_proxy_not_redirected(self) -> None:
        resp = self.request(source="127.0.0.1", headers={
            "Host": ROOT_DOMAIN, "X-Forwarded-For": "198.51.100.9",
        })
        self.assertEqual(resp.status, 200)

    def test_proxy_off_or_no_roots_no_redirect(self) -> None:
        gateway.PROXY_ENABLED = False
        try:
            self.assertEqual(self.request().status, 302)
        finally:
            gateway.PROXY_ENABLED = True
        self.settings.set_proxy([], [])
        try:
            self.assertEqual(self.request().status, 302)
        finally:
            self.settings.set_proxy([ROOT_DOMAIN, tp.SECOND_DOMAIN], [])

    def test_acme_off_needs_covering_uploaded_cert(self) -> None:
        self.settings.set_proxy_acme(False)
        self.addCleanup(self.settings.set_proxy_acme, True)
        self.assertEqual(self.request().status, 302)
        # The certificate with only a *.root SAN does not cover the root.
        self.certs.install(ROOT_DOMAIN, CERT_WILD, KEY_A)
        self.addCleanup(self.certs.delete, ROOT_DOMAIN)
        self.assertEqual(self.request().status, 302)
        self.certs.install(ROOT_DOMAIN, CERT_VALID, KEY_A)
        self.assertRedirect(self.request("/a?b"), f"https://{ROOT_DOMAIN}/a?b")


if __name__ == "__main__":
    unittest.main()
