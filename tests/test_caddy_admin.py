#!/usr/bin/env python3
"""A Caddy tanúsítvány-gyorsítótárának ürítése az admin API-n át.

* ``CaddyAdmin``: elérhetőség-ellenőrzés (GET /config/admin), kért
  újraindítás (POST /stop) egyszer és csak kérésre, újrapróbálás
  visszalépéssel, a jelzőfájl túléli a portál újraindítását, a /stop
  közben érkezett kérés nem vész el; mindez egy hamis Unix socketes
  admin szerverrel;
* admin API: az ACME be→ki váltása és az ACME melletti tanúsítványfeltöltés
  kér újraindítást, más mentés nem; az admin állapot tartalmazza a Caddy
  állapotát;
* a Caddyfile és a compose: admin API csak a közös kötet Unix socketjén.
"""

from __future__ import annotations

import json
import os
import socketserver
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import server  # noqa: E402
import test_proxy_certs as tpc  # noqa: E402


class FakeCaddy(socketserver.ThreadingUnixStreamServer):
    """Hamis Caddy admin API: rögzíti a kéréseket, a válaszkód állítható."""

    daemon_threads = True

    def __init__(self, path: str) -> None:
        self.requests: list[tuple[str, str]] = []
        self.status = 200
        self.on_stop = None
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _reply(self) -> None:
                outer.requests.append((self.command, self.path))
                if self.command == "POST" and outer.on_stop is not None:
                    outer.on_stop()
                self.send_response(outer.status)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            do_GET = do_POST = _reply

            def log_message(self, *args) -> None:
                pass

        super().__init__(path, Handler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.shutdown()
        self.server_close()


class CaddyAdminTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.sock = os.path.join(self.tmp.name, "admin.sock")
        self.flag = os.path.join(self.tmp.name, "caddy-restart-pending")
        self.fake: FakeCaddy | None = None

    def tearDown(self) -> None:
        if self.fake is not None:
            self.fake.close()
        self.tmp.cleanup()

    def start_fake(self) -> FakeCaddy:
        self.fake = FakeCaddy(self.sock)
        return self.fake

    def test_check_only_without_request(self) -> None:
        fake = self.start_fake()
        admin = server.CaddyAdmin(self.sock, self.flag)
        self.assertIsNone(admin.snapshot()["reachable"])
        for _ in range(3):
            self.assertEqual(admin.run_once(), admin.CHECK_INTERVAL)
        self.assertEqual(fake.requests, [("GET", "/config/admin")] * 3)
        snap = admin.snapshot()
        self.assertTrue(snap["reachable"])
        self.assertFalse(snap["pending"])
        self.assertEqual(snap["restarted_at"], 0)
        self.assertEqual(snap["error"], "")

    def test_requested_restart_runs_once(self) -> None:
        fake = self.start_fake()
        admin = server.CaddyAdmin(self.sock, self.flag)
        admin.request_restart()
        self.assertTrue(os.path.exists(self.flag))
        self.assertTrue(admin.snapshot()["pending"])
        self.assertEqual(admin.run_once(), 5.0)
        self.assertFalse(os.path.exists(self.flag))
        snap = admin.snapshot()
        self.assertFalse(snap["pending"])
        self.assertGreater(snap["restarted_at"], 0)
        admin.run_once()
        admin.run_once()
        self.assertEqual(fake.requests, [
            ("POST", "/stop"), ("GET", "/config/admin"),
            ("GET", "/config/admin"),
        ])

    def test_unreachable_backoff_then_restart(self) -> None:
        admin = server.CaddyAdmin(self.sock, self.flag)
        admin.request_restart()
        delays = [admin.run_once() for _ in range(8)]
        self.assertEqual(delays, [2.0, 4.0, 8.0, 16.0, 32.0, 60.0, 60.0, 60.0])
        snap = admin.snapshot()
        self.assertIs(snap["reachable"], False)
        self.assertTrue(snap["pending"])
        self.assertTrue(snap["error"])
        self.assertTrue(os.path.exists(self.flag))
        fake = self.start_fake()
        self.assertEqual(admin.run_once(), 5.0)
        self.assertEqual(fake.requests, [("POST", "/stop")])
        self.assertEqual(admin.snapshot()["error"], "")
        # A sikeres kör a visszalépést is nullázza.
        fake.close()
        self.fake = None
        self.assertEqual(admin.run_once(), 2.0)

    def test_http_error_keeps_request(self) -> None:
        fake = self.start_fake()
        fake.status = 500
        admin = server.CaddyAdmin(self.sock, self.flag)
        admin.request_restart()
        self.assertEqual(admin.run_once(), 2.0)
        snap = admin.snapshot()
        self.assertEqual(snap["error"], "HTTP 500")
        self.assertTrue(snap["pending"])
        fake.status = 200
        self.assertEqual(admin.run_once(), 5.0)
        self.assertFalse(admin.snapshot()["pending"])

    def test_pending_flag_survives_portal_restart(self) -> None:
        fake = self.start_fake()
        server.CaddyAdmin(self.sock, self.flag).request_restart()
        # Új portálfolyamat: a jelzőfájlból tudja, hogy még tartozik a /stop.
        admin = server.CaddyAdmin(self.sock, self.flag)
        self.assertTrue(admin.snapshot()["pending"])
        admin.run_once()
        self.assertEqual(fake.requests, [("POST", "/stop")])
        self.assertFalse(os.path.exists(self.flag))
        self.assertFalse(
            server.CaddyAdmin(self.sock, self.flag).snapshot()["pending"]
        )

    def test_request_during_stop_is_not_lost(self) -> None:
        fake = self.start_fake()
        admin = server.CaddyAdmin(self.sock, self.flag)
        admin.request_restart()
        fake.on_stop = admin.request_restart
        admin.run_once()
        fake.on_stop = None
        self.assertTrue(admin.snapshot()["pending"])
        self.assertTrue(os.path.exists(self.flag))
        admin.run_once()
        self.assertFalse(admin.snapshot()["pending"])
        self.assertFalse(os.path.exists(self.flag))
        admin.run_once()
        self.assertEqual(fake.requests, [
            ("POST", "/stop"), ("POST", "/stop"), ("GET", "/config/admin"),
        ])

    def test_thread_wakes_on_request(self) -> None:
        fake = self.start_fake()
        admin = server.CaddyAdmin(self.sock, self.flag)
        admin.start()
        try:
            for _ in range(200):
                if fake.requests:
                    break
                threading.Event().wait(0.01)
            # A szál most 60 s-ig várna; a kérés azonnal felébreszti.
            admin.request_restart()
            for _ in range(200):
                if not admin.snapshot()["pending"]:
                    break
                threading.Event().wait(0.01)
        finally:
            admin.stop()
        self.assertEqual(fake.requests[:2],
                         [("GET", "/config/admin"), ("POST", "/stop")])


class RecordingCaddy:
    def __init__(self) -> None:
        self.calls = 0

    def request_restart(self) -> None:
        self.calls += 1

    def snapshot(self) -> dict:
        return {"reachable": True, "checked_at": 1, "restarted_at": 0,
                "error": "", "pending": False}


class CaddyRestartHttpTests(unittest.TestCase):
    """Melyik admin művelet kér Caddy-újraindítást."""

    setUpClass = classmethod(tpc.CertAdminHttpTests.setUpClass.__func__)
    tearDownClass = classmethod(
        tpc.CertAdminHttpTests.tearDownClass.__func__
    )
    setUp = tpc.CertAdminHttpTests.setUp
    conn = tpc.CertAdminHttpTests.conn
    get = tpc.CertAdminHttpTests.get
    post = tpc.CertAdminHttpTests.post
    login = tpc.CertAdminHttpTests.login
    admin = tpc.CertAdminHttpTests.admin

    def acme(self, cookie: str, enabled: bool) -> dict:
        status, _, body = self.post("/api/admin/settings", {
            "action": "proxy_acme", "enabled": enabled,
        }, cookie=cookie, source="127.0.0.5")
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def upload(self, cookie: str) -> None:
        status, _, body = self.post("/api/admin/certs", {
            "action": "upload", "root": tpc.ROOT_DOMAIN,
            "cert": tpc.CERT_VALID, "key": tpc.KEY_A,
        }, cookie=cookie, source="127.0.0.5")
        self.assertEqual(status, 200, body)

    def test_restart_only_on_acme_off_and_upload_with_acme(self) -> None:
        caddy = self.gw.caddy = RecordingCaddy()
        try:
            cookie = self.admin()
            data = self.acme(cookie, True)  # be→be
            self.assertEqual(caddy.calls, 0)
            self.assertEqual(data["caddy"]["reachable"], True)
            self.upload(cookie)  # ACME mellett: a gyorsítótár elsőbbsége
            self.assertEqual(caddy.calls, 1)
            self.acme(cookie, False)  # be→ki
            self.assertEqual(caddy.calls, 2)
            self.acme(cookie, False)  # ki→ki
            self.upload(cookie)  # ACME nélkül nincs mit üríteni
            self.assertEqual(caddy.calls, 2)
            self.acme(cookie, True)  # ki→be: a /data-ból tölt, nem kell
            self.assertEqual(caddy.calls, 2)
        finally:
            del self.gw.caddy

    def test_state_without_proxy_has_no_caddy(self) -> None:
        cookie = self.admin()
        status, _, body = self.get(
            "/api/admin/state", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200)
        self.assertIsNone(json.loads(body)["caddy"])


class CaddyAdminDeployTests(unittest.TestCase):
    def test_caddyfile_admin_only_on_unix_socket(self) -> None:
        text = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
        admin = [line.strip() for line in text.splitlines()
                 if line.strip().startswith("admin ")]
        self.assertEqual(admin, ["admin unix//run/caddy-admin/admin.sock|0666"])
        self.assertIn("grace_period 5s", text)
        # A kikapcsolt ACME-t továbbra is az ask kapuzza.
        self.assertIn("ask http://127.0.0.1:{$PORT:8100}/api/proxy/ask", text)

    def test_compose_shares_admin_volume_only(self) -> None:
        text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertEqual(text.count("- caddy-admin:/run/caddy-admin"), 2)
        self.assertIn("\n  caddy-admin:\n", text)
        self.assertIn("HV_CADDY_ADMIN: ${HV_CADDY_ADMIN:-/run/caddy-admin/admin.sock}", text)
        self.assertNotIn("2019", text)

    def test_entrypoint_sets_admin_dir_permissions(self) -> None:
        text = (ROOT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn('chown "0:$APP_USER" "$_dir" && chmod 0750 "$_dir"', text)
        self.assertIn("\nensure_caddy_admin_dir\n", text)


if __name__ == "__main__":
    unittest.main()
