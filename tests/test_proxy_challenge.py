#!/usr/bin/env python3
"""Challenges for proxy entries (captcha gate).

* validation of the ``challenge`` field (settings_store);
* the /api/proxy/auth decision: the challenge only for an authorized (200)
  request, with 403, without fail2ban and drop counting; per condition;
* the entry cookie (signature, host, IP, expiry) and the /api/gate/challenge
  endpoint (PoW puzzle, solution, Set-Cookie, failure counting);
* an unknown subdomain covered by the uploaded wildcard: always a challenge,
  then redirects to the root (without an entry), without ACME.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
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
import test_proxy as tp  # noqa: E402
import test_proxy_certs as tc  # noqa: E402
from test_fail2ban_proxy import FakeFirewall  # noqa: E402
from test_gateway import solve  # noqa: E402

USER = "198.51.100.10"
OTHER = "198.51.100.11"
STRANGER = "198.51.100.99"
NAV = {
    "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
    "Accept": "text/html", "Accept-Language": "hu",
    "User-Agent": "Mozilla/5.0",
}
XHR = {**NAV, "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
       "Accept": "application/json"}


class ChallengeSettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "s.json")
        self.store = settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        )

    def save(self, challenge=None, **extra):
        route = {"name": "app", "port": 3000, **tp.R, **extra}
        if challenge is not None:
            route["challenge"] = challenge
        return self.store.set_proxy([tp.ROOT_DOMAIN], [route])["proxy_routes"][0]

    def test_legacy_and_empty_have_no_challenge(self) -> None:
        self.assertNotIn("challenge", self.save())
        self.assertNotIn("challenge", self.save({"triggers": []}))
        self.assertNotIn(
            "challenge", self.save({"triggers": [], "interval_hours": 0})
        )

    def test_valid_challenge_is_stored_and_reloaded(self) -> None:
        route = self.save({"triggers": ["interval", "new_ip"], "interval_hours": 6})
        self.assertEqual(
            route["challenge"],
            {"triggers": ["interval", "new_ip"], "interval_hours": 6},
        )
        # Without an interval the given hour count does not count (24 remains).
        self.assertEqual(
            self.save({"triggers": ["always"], "interval_hours": 0})["challenge"],
            {"triggers": ["always"], "interval_hours": 24},
        )
        reloaded = settings_store.SettingsStore(
            self.path, logger=lambda *_: None
        ).snapshot()
        self.assertEqual(reloaded["proxy_routes"][0]["challenge"]["triggers"],
                         ["always"])

    def test_invalid_challenge_rejected(self) -> None:
        for challenge in (
            "always", ["always"], {"triggers": "always"},
            {"triggers": ["nope"]}, {"triggers": [1]}, {"triggers": [["x"]]},
            {"triggers": ["always", "always"]},
            {"triggers": ["interval"], "interval_hours": 0},
            {"triggers": ["interval"], "interval_hours": 721},
            {"triggers": ["interval"], "interval_hours": True},
            {"triggers": ["interval"], "interval_hours": "5"},
        ):
            with self.subTest(challenge=challenge):
                with self.assertRaises(settings_store.SettingsError):
                    self.save(challenge)


class ChallengeHttpTests(unittest.TestCase):
    ROUTES = [
        {"name": "always", "port": 3000, "challenge": {"triggers": ["always"]}},
        {"name": "plain", "port": 3001},
        {"name": "pub", "port": 3002, "visibility": "public",
         "challenge": {"triggers": ["always"]}},
        {"name": "ipbound", "port": 3003, "visibility": "public",
         "challenge": {"triggers": ["new_ip"]}},
        {"name": "hourly", "port": 3004,
         "challenge": {"triggers": ["interval"], "interval_hours": 1}},
        {"name": "daily", "port": 3005,
         "challenge": {"triggers": ["daily", "interval"], "interval_hours": 48}},
        {"name": "after401", "port": 3006,
         "challenge": {"triggers": ["after_401"]}},
        {"name": "f2b", "port": 3007, "challenge": {"triggers": ["fail2ban"]}},
        {"name": "sus", "port": 3008, "challenge": {"triggers": ["suspicious"]}},
        {"name": "burst", "port": 3010, "visibility": "public",
         "challenge": {"triggers": ["burst"]}},
        {"name": "off", "port": 3009, "enabled": False,
         "challenge": {"triggers": ["always"]}},
    ]

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        settings = settings_store.SettingsStore(
            os.path.join(self.tmp.name, "s.json"), logger=lambda *_: None
        )
        settings.set_proxy(
            [tp.ROOT_DOMAIN], [{**route, **tp.R} for route in self.ROUTES]
        )
        sessions = gateway.SessionManager(firewall=None)
        private = [tp.host(r["name"]) for r in self.ROUTES
                   if r.get("visibility") != "public" and r.get("enabled", True)]
        # The uploaded certificate for the root and *.root (unknown subdomain).
        certs = settings_store.CertStore(
            os.path.join(self.tmp.name, "certs"), logger=lambda *_: None
        )
        certs.install(tp.ROOT_DOMAIN, tc.CERT_VALID, tc.KEY_A)
        tp.add_session(sessions, USER, private)
        self.f2b = fail2ban_mod.Fail2ban(
            FakeFirewall(), path=os.path.join(self.tmp.name, "f.json"),
            logger=lambda *_: None, proxy_max=50, max_attempts=50,
            ban_seconds=900,
        )
        self.audits, self.drops = [], []
        gw = types.SimpleNamespace(
            settings=settings, sessions=sessions, fail2ban=self.f2b, certs=certs,
            audit=types.SimpleNamespace(
                write=lambda event, **f: self.audits.append((event, f))
            ),
            record_proxy_drop=lambda *args: self.drops.append(args),
            login_rate=gateway.RateLimiter(window=60, maximum=100),
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
        self.port = self.server.server_address[1]

    def request(self, method, path, headers, body=None, source="127.0.0.1"):
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=10, source_address=(source, 0)
        )
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def auth(self, name, ip=USER, cookie="", headers=NAV):
        extra = {"X-Forwarded-Host": name, "X-Forwarded-For": ip, **headers}
        # The browser has done the bind hop of the private entry (DJ-05).
        bind = tp.bind_cookie(self.server.gateway.sessions, ip, name)
        jar = ["a=1"] + ([bind] if bind else [])
        if cookie:
            jar.append(f"{server.PROXY_PASS_COOKIE}={cookie}")
        if cookie or bind:
            extra["Cookie"] = "; ".join(jar + ["b=2"])
        return self.request("GET", "/api/proxy/auth", extra)

    def status(self, *args, **kwargs):
        return self.auth(*args, **kwargs)[0].status

    @staticmethod
    def cookie(name, ip="", issued=None, ttl=3600):
        issued = time.time() if issued is None else issued
        return server._proxy_pass_value(
            tp.host(name), ip, issued, int(issued) + ttl
        )

    def gate(self, name, method="GET", body=None, source="127.0.0.1",
             ip=USER, **headers):
        extra = {"Host": name, "X-Forwarded-For": ip, **headers}
        if body is not None:
            body = json.dumps(body).encode()
            extra.setdefault("Content-Type", "application/json")
        return self.request(method, "/api/gate/challenge", extra, body, source)

    def events(self, event):
        return [f for e, f in self.audits if e == event]

    # -- decision matrix ---------------------------------------------------

    def test_no_trigger_and_root_pass(self) -> None:
        self.assertEqual(self.status(tp.host("plain")), 200)
        self.assertEqual(self.status(tp.ROOT_DOMAIN, STRANGER), 200)

    def test_always_shows_challenge_page_on_navigation(self) -> None:
        resp, body = self.auth(tp.host("always"))
        self.assertEqual(resp.status, 403)
        self.assertIsNone(resp.getheader("X-Dropjak-Upstream"))
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        page = body.decode()
        self.assertIn('src="/__dropjak/sus.png"', page)
        self.assertIn('id="powbox"', page)
        self.assertIn("I'm not a robot", page)
        self.assertIn("Checking…", page)
        self.assertIn("Verified", page)
        self.assertIn("const sha256 = (() => {", page)
        self.assertIn(".captcha-inner", page)
        # Text-free status page: only the image and the English captcha.
        self.assertNotIn('class="state-icon"', page)
        self.assertIn("<svg", page)
        self.assertIn("<title>Dropjak</title>", page)
        self.assertNotIn("<h1", page)
        # DJ-28: the inline captcha script runs by hash, not 'unsafe-inline'.
        csp = resp.getheader("Content-Security-Policy")
        script_src = next(part for part in csp.split(";")
                          if part.strip().startswith("script-src"))
        self.assertNotIn("'unsafe-inline'", script_src)
        self.assertEqual(
            server.inline_script_hashes(body),
            tuple(h for h in script_src.split() if h.startswith("'sha256-")),
        )
        self.assertEqual(len(server.inline_script_hashes(body)), 1)
        for removed in (
            "Ellenőrzés", "Erősítsd meg, hogy nem vagy robot.",
            "Nincs hozzáférés", "Bejelentkezés",
            "Ez a szolgáltatás csak a Dropjak tűzfalon",
        ):
            with self.subTest(removed=removed):
                self.assertNotIn(removed, page)
        self.assertNotIn("<a ", page)
        self.assertNotIn("<button", page)
        # The captcha script must be valid JS: because of a Python escape it once
        # became a syntax error, and the captcha never started.
        node = shutil.which("node")
        if node:
            script = page[page.index("<script>") + len("<script>"):
                          page.index("</script>")]
            result = subprocess.run(
                [node, "--check"], input=script, text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        shown = self.events("proxy_challenge_shown")
        self.assertEqual(len(shown), 1)
        self.assertEqual(shown[0]["triggers"], "always")
        self.assertEqual(shown[0]["host"], tp.host("always"))
        self.assertEqual(self.events("proxy_page_opened"), [])

    def test_non_navigation_gets_short_403(self) -> None:
        resp, body = self.auth(tp.host("always"), headers=XHR)
        self.assertEqual(resp.status, 403)
        self.assertEqual(json.loads(body)["code"], "proxy_challenge")
        self.assertEqual(self.events("proxy_challenge_shown"), [])

    def test_pass_cookie_validity(self) -> None:
        name = "always"
        self.assertEqual(self.status(tp.host(name), cookie=self.cookie(name)), 200)
        good = self.cookie(name)
        tampered = good[:-1] + ("0" if good[-1] != "0" else "1")
        for cookie in (
            tampered, "garbage", "a.b", self.cookie("plain"),
            self.cookie(name, issued=time.time() - 7200, ttl=3600),  # expired
            self.cookie(name, issued=time.time() - 90000, ttl=200000),  # >24 h
        ):
            with self.subTest(cookie=cookie):
                self.assertEqual(self.status(tp.host(name), cookie=cookie), 403)

    def test_interval_lifetime(self) -> None:
        name = "hourly"
        self.assertEqual(self.status(tp.host(name)), 403)
        fresh = self.cookie(name, issued=time.time() - 3000, ttl=7200)
        old = self.cookie(name, issued=time.time() - 3700, ttl=7200)
        self.assertEqual(self.status(tp.host(name), cookie=fresh), 200)
        self.assertEqual(self.status(tp.host(name), cookie=old), 403)

    def test_daily_needs_pass_from_today(self) -> None:
        now = time.time()
        today = time.localtime(now)
        midnight = time.mktime(
            (today.tm_year, today.tm_mon, today.tm_mday, 0, 0, 0, 0, 0, -1)
        )
        name = "daily"
        yesterday = self.cookie(name, issued=midnight - 60, ttl=172800)
        self.assertEqual(self.status(tp.host(name), cookie=yesterday), 403)
        self.assertEqual(self.status(tp.host(name), cookie=self.cookie(name)), 200)

    def test_new_ip_binds_pass_to_ip(self) -> None:
        # Without IP binding the "*" entry is good from any IP.
        loose = self.cookie("pub")
        self.assertEqual(self.status(tp.host("pub"), OTHER, loose), 200)
        name = "ipbound"
        self.assertEqual(self.status(tp.host(name), USER), 403)
        self.assertEqual(
            self.status(tp.host(name), USER, self.cookie(name)), 403
        )
        bound = self.cookie(name, ip=USER)
        self.assertEqual(self.status(tp.host(name), USER, bound), 200)
        self.assertEqual(self.status(tp.host(name), OTHER, bound), 403)

    def test_after_401_only_with_running_proxy_counter(self) -> None:
        name = "after401"
        early = self.cookie(name)
        self.assertEqual(self.status(tp.host(name)), 200)
        self.f2b.record_proxy_unauthorized(USER)
        self.assertEqual(self.status(tp.host(name)), 403)
        self.assertEqual(self.status(tp.host(name), cookie=early), 403)
        self.assertEqual(self.status(tp.host(name), cookie=self.cookie(name)), 200)
        # The login counter is not proxy-401: it does not arm after_401.
        self.f2b.record_failure(OTHER, "x")
        self.assertEqual(self.status(tp.host("pub"), OTHER, self.cookie("pub")), 200)

    def test_fail2ban_trigger_counts_any_signal(self) -> None:
        name = "f2b"
        self.assertEqual(self.status(tp.host(name)), 200)
        early = self.cookie(name)
        self.f2b.record_failure(USER, "x")
        self.assertEqual(self.status(tp.host(name)), 403)
        self.assertEqual(self.status(tp.host(name), cookie=early), 403)
        self.assertEqual(self.status(tp.host(name), cookie=self.cookie(name)), 200)
        self.assertEqual(self.status(tp.host("after401")), 200)

    def test_suspicious_clients(self) -> None:
        name = tp.host("sus")
        self.assertEqual(self.status(name), 200)
        self.assertEqual(self.status(name, headers=XHR), 200)
        for headers in (
            {**NAV, "User-Agent": "curl/8.5.0"},
            {**NAV, "User-Agent": "python-requests/2.31"},
            {**NAV, "User-Agent": ""},
            {k: v for k, v in NAV.items() if k != "Accept-Language"},
            {"Accept": "text/html", "Accept-Language": "hu",
             "User-Agent": "Mozilla/5.0"},  # navigation without Sec-Fetch
        ):
            with self.subTest(headers=headers):
                self.assertEqual(self.status(name, headers=headers), 403)
        curl = {"User-Agent": "curl/8.5.0", "Accept": "*/*"}
        self.assertEqual(
            self.status(name, cookie=self.cookie("sus"), headers=curl), 200
        )

    def test_burst_of_page_opens_needs_new_pass(self) -> None:
        name = tp.host("burst")
        server._PROXY_BURST.clear()
        old = self.cookie("burst", issued=time.time() - 60)
        for _ in range(20):  # an XHR/asset request does not count
            self.assertEqual(self.status(name, cookie=old, headers=XHR), 200)
        for _ in range(server.PROXY_BURST_LIMIT - 1):
            self.assertEqual(self.status(name, cookie=old), 200)
        self.assertEqual(self.status(name, cookie=old), 403)
        # The old entry is no good after detection either (not even for XHR), the new one is.
        self.assertEqual(self.status(name, cookie=old), 403)
        self.assertEqual(self.status(name, cookie=old, headers=XHR), 403)
        self.assertEqual(self.status(name), 403)
        self.assertEqual(self.status(name, cookie=self.cookie("burst")), 200)
        self.assertEqual(self.status(name, OTHER), 200)  # counts per IP
        self.assertEqual(self.events("proxy_challenge_shown")[0]["triggers"],
                         "burst")

    def test_unauthorized_gets_401_and_challenge_is_not_counted(self) -> None:
        resp, body = self.auth(tp.host("always"), STRANGER)
        self.assertEqual(resp.status, 401)
        self.assertIn(b"/__dropjak/unauthorized.png", body)
        self.assertIn(b'class="login"', body)
        self.assertIn(b'aria-label="Log in"', body)
        self.assertNotIn(b"Bejelentkez", body)
        self.assertEqual(len(self.drops), 1)
        self.assertEqual(self.f2b.last_hit(STRANGER, proxy_only=True) > 0, True)
        for _ in range(5):
            self.assertEqual(self.status(tp.host("always")), 403)
            self.assertEqual(self.status(tp.host("pub"), OTHER), 403)
        self.assertEqual(len(self.drops), 1)
        self.assertEqual(self.f2b.last_hit(USER), 0.0)
        self.assertEqual(self.f2b.last_hit(OTHER), 0.0)
        self.assertEqual(self.events("proxy_challenge_shown")[0]["user"], "u")

    def test_turnstile_page(self) -> None:
        with mock.patch.object(gateway, "TURNSTILE_ON", True), \
                mock.patch.object(gateway, "TURNSTILE_SITEKEY", "site-key-1"):
            _, body = self.auth(tp.host("always"))
        page = body.decode()
        self.assertIn('"mode": "turnstile"', page)
        self.assertIn("site-key-1", page)
        self.assertIn(
            "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit",
            page,
        )

    # -- /api/gate/challenge ----------------------------------------------

    def test_gate_issues_pow_and_sets_pass(self) -> None:
        name = tp.host("ipbound")
        resp, body = self.gate(name)
        self.assertEqual(resp.status, 200)
        challenge = json.loads(body)
        self.assertEqual(challenge["mode"], "pow")
        solution = solve(challenge)
        resp, body = self.gate(
            name, "POST", {"captcha": solution},
            Origin=f"https://{name}",
        )
        self.assertEqual(resp.status, 200, body)
        cookie = resp.getheader("Set-Cookie")
        self.assertTrue(cookie.startswith(f"{server.PROXY_PASS_COOKIE}="))
        for part in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/",
                     "Max-Age=86400"):
            self.assertIn(part, cookie)
        self.assertNotIn("Domain", cookie)
        value = cookie.split(";", 1)[0].split("=", 1)[1]
        self.assertEqual(self.status(name, USER, value), 200)
        self.assertEqual(self.status(name, OTHER, value), 403)  # new_ip
        passed = self.events("proxy_challenge_passed")
        self.assertEqual(passed[0]["host"], name)
        self.assertEqual(passed[0]["triggers"], "new_ip")
        # Replay: fails, and counts as a proxy hit.
        resp, body = self.gate(name, "POST", {"captcha": solution})
        self.assertEqual(resp.status, 403)
        self.assertIn("the captcha was already used", json.loads(body)["error"])
        self.assertGreater(self.f2b.last_hit(USER, proxy_only=True), 0)
        self.assertEqual(len(self.events("proxy_challenge_failed")), 1)

    def test_gate_rejections(self) -> None:
        name = tp.host("always")
        bad = {**json.loads(self.gate(name)[1]), "number": -1}
        self.assertEqual(self.gate(name, "POST", {"captcha": bad})[0].status, 403)
        self.assertEqual(self.gate(name, "POST", {"captcha": "x"})[0].status, 403)
        self.assertEqual(self.f2b.snapshot()["proxy_pending"], 1)
        self.assertEqual(
            self.gate(name, "POST", {"captcha": {}},
                      Origin="https://evil.example")[0].status, 403
        )
        self.assertEqual(
            self.gate(name, "POST", {"captcha": {}},
                      **{"Content-Type": "text/plain"})[0].status, 400
        )
        for host_name in (tp.host("plain"), tp.ROOT_DOMAIN, "x.example.com"):
            with self.subTest(host=host_name):
                self.assertEqual(self.gate(host_name)[0].status, 404)
        self.assertEqual(self.gate(name, source="127.0.0.2")[0].status, 404)
        self.assertEqual(
            self.gate(name, "POST", {"captcha": {}}, source="127.0.0.2")[0].status,
            404,
        )
        resp, _ = self.request(
            "GET", "/api/gate/other", {"Host": name, "X-Forwarded-For": USER}
        )
        self.assertEqual(resp.status, 404)
        self.f2b.ban(USER, 600)
        self.assertEqual(self.gate(name)[0].status, 403)

    # -- unknown (or disabled) subdomain covered by the wildcard --------------

    def test_unknown_covered_host_always_gets_challenge(self) -> None:
        for name in (tp.host("x"), tp.host("off")):
            with self.subTest(host=name):
                self.audits.clear()
                resp, body = self.auth(name)
                self.assertEqual(resp.status, 403)
                page = body.decode()
                self.assertIn('src="/__dropjak/sus.png"', page)
                self.assertIn('id="powbox"', page)
                self.assertIn("location.href = data.redirect", page)
                self.assertNotIn("<a ", page)
                # Entry, session and condition do not count.
                self.assertEqual(
                    self.status(name, STRANGER, self.cookie("off")), 403
                )
                shown = self.events("proxy_challenge_shown")
                self.assertEqual(len(shown), 2)
                self.assertEqual(shown[0]["host"], name)
                self.assertIs(shown[0]["unknown_host"], True)
                self.assertNotIn("triggers", shown[0])
                resp, body = self.auth(name, headers=XHR)
                self.assertEqual(json.loads(body)["code"], "proxy_challenge")
                # It never asks for ACME for an unknown name.
                resp, _ = self.request(
                    "GET", f"/api/proxy/ask?domain={name}", {}
                )
                self.assertEqual(resp.status, 404)
        self.assertEqual(self.drops, [])
        self.assertEqual(self.f2b.snapshot()["proxy_pending"], 0)
        # Uncovered unknown name: still 404.
        for name in (f"a.b.{tp.ROOT_DOMAIN}", "x.example.org"):
            with self.subTest(host=name):
                self.assertEqual(self.status(name), 404)
        self.f2b.ban(STRANGER, 600)
        resp, body = self.auth(tp.host("x"), STRANGER)
        self.assertEqual((resp.status, body), (403, b""))

    def test_gate_unknown_host_redirects_to_root_without_pass(self) -> None:
        name = tp.host("off")
        resp, body = self.gate(name)
        self.assertEqual(resp.status, 200)
        challenge = json.loads(body)
        resp, body = self.gate(
            name, "POST", {"captcha": solve(challenge)},
            Origin=f"https://{name}",
        )
        self.assertEqual(resp.status, 200, body)
        self.assertEqual(
            json.loads(body),
            {"ok": True, "redirect": f"https://{tp.ROOT_DOMAIN}/"},
        )
        self.assertIsNone(resp.getheader("Set-Cookie"))
        [passed] = self.events("proxy_challenge_passed")
        self.assertEqual(passed["host"], name)
        self.assertIs(passed["unknown_host"], True)
        bad = {**json.loads(self.gate(name)[1]), "number": -1}
        self.assertEqual(self.gate(name, "POST", {"captcha": bad})[0].status, 403)
        self.assertEqual(self.f2b.snapshot()["proxy_pending"], 1)
        [failed] = self.events("proxy_challenge_failed")
        self.assertIs(failed["unknown_host"], True)
        self.assertEqual(self.gate(f"a.b.{tp.ROOT_DOMAIN}")[0].status, 404)


class CaptchaAssetTests(unittest.TestCase):
    def test_login_widget_assets_are_extracted(self) -> None:
        css, script = server._captcha_assets_from_index()
        for rule in (".captcha{", ".captcha-inner[data-state=done] .box{",
                     ".spinner{", ".bar i{", "@keyframes spin", "#turnstile"):
            self.assertIn(rule, css)
        self.assertNotIn("data-theme", css)
        self.assertTrue(script.startswith("const sha256 = (() => {"))
        self.assertTrue(script.endswith("return { matches };\n})();"))


if __name__ == "__main__":
    unittest.main()
