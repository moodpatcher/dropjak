#!/usr/bin/env python3
"""fail2ban's proxy category: unauthorized (401) domain proxy requests.

* ``Fail2ban``'s counting, banning, release, save and reload with a fake
  firewall (the proxy ban goes into the ``proxy_banned_v4`` set,
  independently of the full ban);
* ``/api/proxy/auth`` counts only the private entry's 401 response, with
  the real (XFF) client IP;
* the template puts the ``proxy_banned_v4`` set and the 80/443 drop before
  proxy acceptance (HV_PROXY=0/1), and it is valid according to ``nft -c``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
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
import test_proxy as tp  # noqa: E402

IP = "198.51.100.77"


class FakeFirewall:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.kernel: dict[str, int] = {}
        self.proxy_kernel: dict[str, int] = {}

    def ban(self, ip, ttl):
        self.calls.append(("ban", ip, ttl))
        self.kernel[ip] = ttl

    def unban(self, ip):
        self.calls.append(("unban", ip))
        self.kernel.pop(ip, None)

    def sync_bans(self, elements):
        self.kernel = dict(elements)

    def proxy_ban(self, ip, ttl):
        self.calls.append(("proxy_ban", ip, ttl))
        self.proxy_kernel[ip] = ttl

    def proxy_unban(self, ip):
        self.calls.append(("proxy_unban", ip))
        self.proxy_kernel.pop(ip, None)

    def sync_proxy_bans(self, elements):
        self.calls.append(("sync_proxy", list(elements)))
        self.proxy_kernel = dict(elements)


class ProxyCounterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "fail2ban.json")
        self.fw = FakeFirewall()
        self.notified: list[dict] = []

    def make(self, **kwargs):
        options = {"ban_seconds": 900, "proxy_max": 3,
                   "proxy_window_seconds": 60}
        options.update(kwargs)
        return fail2ban_mod.Fail2ban(
            self.fw, path=self.path, logger=lambda *_: None,
            on_ban=self.notified.append, **options
        )

    def hit(self, manager, times=1, ip=IP):
        result = None
        for _ in range(times):
            result = manager.record_proxy_unauthorized(ip)
        return result

    def test_defaults(self) -> None:
        manager = fail2ban_mod.Fail2ban(
            self.fw, path=self.path, logger=lambda *_: None
        )
        snap = manager.snapshot()
        self.assertTrue(snap["proxy_enabled"])
        self.assertEqual(snap["proxy_max"], 20)
        self.assertEqual(snap["proxy_window_seconds"], 600)
        self.assertEqual(snap["ban_seconds"], fail2ban_mod.DEFAULT_BAN)

    def test_threshold_creates_proxy_ban(self) -> None:
        manager = self.make()
        self.assertIsNone(self.hit(manager, 2))
        self.assertEqual(self.fw.calls, [])
        view = self.hit(manager)
        self.assertEqual(view["source"], "proxy")
        self.assertEqual(view["attempts"], 3)
        self.assertFalse(view["manual"])
        self.assertEqual(view["until"] - view["since"], 900)
        self.assertEqual(self.fw.calls, [("proxy_ban", IP, 900)])
        # Only the proxy set; the full ban is not created.
        self.assertIsNone(manager.banned(IP))
        self.assertIsNotNone(manager.proxy_banned(IP))
        self.assertEqual([row["source"] for row in self.notified], ["proxy"])
        rows = manager.snapshot()["bans"]
        self.assertEqual([(r["ip"], r["source"]) for r in rows], [(IP, "proxy")])

    def test_banned_ip_is_not_counted(self) -> None:
        manager = self.make()
        self.hit(manager, 3)
        self.assertIsNone(self.hit(manager, 5))
        self.assertEqual(
            [c for c in self.fw.calls if c[0] == "proxy_ban"],
            [("proxy_ban", IP, 900)],
        )
        self.assertEqual(manager.snapshot()["proxy_pending"], 0)
        # A fully banned IP does not count either.
        other = "198.51.100.78"
        manager.ban(other, 600)
        self.assertIsNone(self.hit(manager, 5, other))
        self.assertIsNone(manager.proxy_banned(other))

    def test_window_expiry_restarts_count(self) -> None:
        manager = self.make()
        with mock.patch("fail2ban.time.time", return_value=1000.0):
            self.hit(manager, 2)
        with mock.patch("fail2ban.time.time", return_value=1061.0):
            self.assertIsNone(self.hit(manager, 2))
        self.assertEqual(self.fw.calls, [])
        with mock.patch("fail2ban.time.time", return_value=1062.0):
            self.assertIsNotNone(self.hit(manager))

    def test_disabled_does_not_count(self) -> None:
        manager = self.make(proxy_enabled=False)
        self.assertIsNone(self.hit(manager, 10))
        self.assertEqual(self.fw.calls, [])
        self.assertEqual(manager.snapshot()["proxy_pending"], 0)

    def test_loopback_and_invalid_are_ignored(self) -> None:
        manager = self.make(proxy_max=1)
        for ip in ("127.0.0.1", "", "not-ip", "::1"):
            self.assertIsNone(manager.record_proxy_unauthorized(ip))
        self.assertEqual(self.fw.calls, [])

    def test_full_and_proxy_ban_coexist_and_unban_separately(self) -> None:
        manager = self.make()
        self.hit(manager, 3)
        manager.ban(IP, 600)
        sources = sorted(r["source"] for r in manager.snapshot()["bans"])
        self.assertEqual(sources, ["manual", "proxy"])
        # The proxy release does not affect the full ban ...
        self.assertTrue(manager.unban(IP, proxy=True))
        self.assertIsNone(manager.proxy_banned(IP))
        self.assertIsNotNone(manager.banned(IP))
        self.assertEqual(self.fw.calls[-1], ("proxy_unban", IP))
        self.assertIn(IP, self.fw.kernel)
        self.assertFalse(manager.unban(IP, proxy=True))
        # ... and releasing the full ban does not affect the proxy ban either.
        manager.unban(IP)
        self.hit(manager, 3)
        manager.ban(IP, 600)
        self.assertTrue(manager.unban(IP))
        self.assertIsNone(manager.banned(IP))
        self.assertIsNotNone(manager.proxy_banned(IP))
        self.assertIn(IP, self.fw.proxy_kernel)

    def test_unban_all_includes_proxy_bans(self) -> None:
        manager = self.make()
        self.hit(manager, 3)
        manager.ban("198.51.100.79", 600)
        self.assertEqual(manager.unban_all(), 2)
        self.assertEqual(manager.snapshot()["bans"], [])
        self.assertEqual(self.fw.proxy_kernel, {})

    def test_persisted_and_reapplied_at_startup(self) -> None:
        manager = self.make()
        self.hit(manager, 3)
        manager.ban("198.51.100.79", 600)
        with open(self.path, encoding="utf-8") as fh:
            saved = json.load(fh)
        self.assertEqual([r["ip"] for r in saved["proxy_bans"]], [IP])
        self.assertEqual(
            [r["ip"] for r in saved["bans"]], ["198.51.100.79"]
        )
        self.fw = FakeFirewall()
        restarted = self.make()
        self.assertTrue(restarted.sync())
        self.assertEqual(list(self.fw.proxy_kernel), [IP])
        self.assertLessEqual(self.fw.proxy_kernel[IP], 900)
        self.assertGreater(self.fw.proxy_kernel[IP], 890)
        self.assertEqual(list(self.fw.kernel), ["198.51.100.79"])
        self.assertEqual(restarted.proxy_banned(IP)["source"], "proxy")

    def test_expired_proxy_ban_is_dropped(self) -> None:
        manager = self.make()
        self.hit(manager, 3)
        with mock.patch("fail2ban.time.time", return_value=4102444800.0):
            self.assertIsNone(manager.proxy_banned(IP))
            self.assertTrue(manager.sync())
        self.assertEqual(self.fw.proxy_kernel, {})

    def test_legacy_settings_load_with_defaults(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({
                "version": 1,
                "config": {"enabled": True, "max_attempts": 7,
                           "window_seconds": 300, "ban_seconds": 1200},
                "bans": [],
            }, fh)
        manager = fail2ban_mod.Fail2ban(
            self.fw, path=self.path, logger=lambda *_: None
        )
        snap = manager.snapshot()
        self.assertEqual(snap["max_attempts"], 7)
        self.assertTrue(snap["proxy_enabled"])
        self.assertEqual(snap["proxy_max"], 20)
        self.assertEqual(snap["proxy_window_seconds"], 600)
        self.assertEqual(snap["error"], "")

    def test_validation(self) -> None:
        manager = self.make()
        for bad in ({"proxy_enabled": "igen"}, {"proxy_max": 0},
                    {"proxy_max": True}, {"proxy_max": 10001},
                    {"proxy_window_seconds": 10}):
            with self.subTest(bad=bad):
                with self.assertRaises(fail2ban_mod.Fail2banError):
                    manager.configure(bad)
        snap = manager.configure({"proxy_max": 5, "proxy_window_seconds": 120})
        self.assertEqual((snap["proxy_max"], snap["proxy_window_seconds"]),
                         (5, 120))

    def test_disabling_releases_only_proxy_bans(self) -> None:
        manager = self.make()
        self.hit(manager, 3)
        manager.ban("198.51.100.79", 600)
        self.hit(manager, 2, "198.51.100.80")
        snap = manager.configure({"proxy_enabled": False})
        self.assertEqual([r["source"] for r in snap["bans"]], ["manual"])
        self.assertEqual(snap["proxy_pending"], 0)
        self.assertIn(("proxy_unban", IP), self.fw.calls)


class ProxyAuthCountingTests(unittest.TestCase):
    AUTHORIZED = "198.51.100.10"

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        settings = settings_store.SettingsStore(
            os.path.join(self.tmp.name, "s.json"), logger=lambda *_: None
        )
        settings.set_proxy([tp.ROOT_DOMAIN], [
            {"name": "owui", "port": 3000, **tp.R},
            {"name": "pub", "port": 3003, "visibility": "public", **tp.R},
        ])
        sessions = gateway.SessionManager(firewall=None)
        tp.add_session(sessions, self.AUTHORIZED, (tp.host("owui"),))
        self.fw = FakeFirewall()
        self.f2b = fail2ban_mod.Fail2ban(
            self.fw, path=os.path.join(self.tmp.name, "f.json"),
            logger=lambda *_: None, proxy_max=3, ban_seconds=900,
        )
        gw = types.SimpleNamespace(
            settings=settings, sessions=sessions, fail2ban=self.f2b,
            audit=None, record_proxy_drop=lambda *_: None,
            certs=settings_store.CertStore(
                os.path.join(self.tmp.name, "certs"), logger=lambda *_: None
            ),
        )
        old = gateway.PORTAL_URL
        gateway.PORTAL_URL = ""
        self.addCleanup(setattr, gateway, "PORTAL_URL", old)
        self.server = server.AppServer(("127.0.0.1", 0), gw)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.get = tp.ProxyEndpointTests.get.__get__(self)
        self.port = self.server.server_address[1]

    def auth(self, name, ip="", **extra):
        headers = {"X-Forwarded-Host": name, **extra}
        if ip:
            headers["X-Forwarded-For"] = ip
            bind = tp.bind_cookie(self.server.gateway.sessions, ip, name)
            if bind:
                headers["Cookie"] = bind
        resp, _ = self.get("/api/proxy/auth", headers)
        return resp.status

    def test_only_private_401_counts_on_real_ip(self) -> None:
        owui, pub = tp.host("owui"), tp.host("pub")
        for _ in range(5):
            self.assertEqual(self.auth(owui, self.AUTHORIZED), 200)  # 200
            self.assertEqual(self.auth(tp.ROOT_DOMAIN, IP), 200)  # root
            self.assertEqual(self.auth("x." + tp.ROOT_DOMAIN, IP), 404)
            self.assertEqual(self.auth(pub, IP), 200)  # publikus
            self.assertEqual(self.auth(owui), 401)  # no XFF
        self.assertEqual(self.f2b.snapshot()["proxy_pending"], 0)
        self.assertEqual(self.fw.calls, [])
        # The private 401 counts against the XFF IP, not the loopback peer.
        for _ in range(3):
            self.assertEqual(self.auth(owui, IP), 401)
        self.assertEqual(self.fw.calls, [("proxy_ban", IP, 900)])
        self.assertIsNone(self.f2b.proxy_banned("127.0.0.1"))

    def test_proxy_banned_ip_is_401_without_counting(self) -> None:
        owui = tp.host("owui")
        for _ in range(3):
            self.f2b.record_proxy_unauthorized(self.AUTHORIZED)
        self.assertEqual(self.auth(owui, self.AUTHORIZED), 401)
        self.assertEqual(self.auth(tp.host("pub"), self.AUTHORIZED), 401)
        self.assertEqual(self.f2b.proxy_banned(self.AUTHORIZED)["attempts"], 3)
        self.assertEqual(self.f2b.snapshot()["proxy_pending"], 0)
        self.assertEqual(len(self.fw.calls), 1)
        self.f2b.unban(self.AUTHORIZED, proxy=True)
        self.assertEqual(self.auth(owui, self.AUTHORIZED), 200)


class ProxyBanTemplateTests(unittest.TestCase):
    DROP = "ip saddr @proxy_banned_v4 tcp dport { 80, 443 } drop"

    def render(self, proxy):
        return tp.ProxyFirewallTemplateTests.render(self, proxy)

    def test_set_and_drop_before_proxy_accepts(self) -> None:
        for proxy in ("0", "1"):
            with self.subTest(proxy=proxy):
                rendered = self.render(proxy)
                self.assertIn("add set inet hatarvedelem proxy_banned_v4 {",
                              rendered)
                chain = rendered[rendered.index("chain input {"):]
                chain = chain[:chain.index("chain prerouting")]
                lines = [line.strip() for line in chain.splitlines()]
                self.assertIn(self.DROP, lines)  # not commented out
                drop = chain.index(self.DROP)
                self.assertLess(drop, chain.index("tcp dport { 80, 443 } accept"))
                self.assertLess(drop, chain.index("ct state established,related accept"))
                self.assertIn('log prefix "dropjak-drop reason=proxy-ban "', chain)
                # The portal port remains accepted before the proxy drop.
                self.assertLess(chain.index('tcp dport 8100 accept'), drop)

    @unittest.skipUnless(
        shutil.which("nft") and shutil.which("unshare"), "no nft/unshare"
    )
    def test_nft_check(self) -> None:
        for proxy in ("0", "1"):
            with self.subTest(proxy=proxy), tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "r.nft")
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(self.render(proxy))
                result = subprocess.run(
                    ["unshare", "-rn", "nft", "-c", "-f", path],
                    capture_output=True, text=True, timeout=20,
                )
                if result.returncode != 0 and "Operation not permitted" in result.stderr:
                    self.skipTest("the user namespace is not available")
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
