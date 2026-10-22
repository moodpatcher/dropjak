#!/usr/bin/env python3
"""A 80-as port átirányítása (/api/proxy/redirect, Caddy http:// forward_auth).

* döntési mátrix: gyökér, bekapcsolt bejegyzés, fedett/nem fedett ismeretlen
  aldomain, idegen név és nyers IP; gyökér nélkül a régi viselkedés;
* csak loopback peer; hibás Host (CRLF, szóköz, userinfo, túl hosszú) soha nem
  ad saját nevünkön kívüli Location-t; port levágása; hibás URI.
"""

from __future__ import annotations

import http.client
import os
import socket
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402
import server  # noqa: E402
import settings_store  # noqa: E402
import test_proxy as tp  # noqa: E402
import test_proxy_certs as tc  # noqa: E402

FIRST = f"https://{tp.ROOT_DOMAIN}/"
SECOND = f"https://{tp.SECOND_DOMAIN}/"


class ProxyRedirectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = settings_store.SettingsStore(
            os.path.join(self.tmp.name, "s.json"), logger=lambda *_: None
        )
        self.settings.set_proxy([tp.ROOT_DOMAIN, tp.SECOND_DOMAIN], [
            {"name": "owui", "port": 3000, **tp.R},
            {"name": "off", "port": 3001, "enabled": False, **tp.R},
            {"name": "nas", "port": 3002, "root": tp.SECOND_DOMAIN},
            {"name": "gone", "port": 3003, "enabled": False,
             "root": tp.SECOND_DOMAIN},
        ])
        # Csak az első gyökérnek van (root + *.root) feltöltött tanúsítványa.
        certs = settings_store.CertStore(
            os.path.join(self.tmp.name, "certs"), logger=lambda *_: None
        )
        certs.install(tp.ROOT_DOMAIN, tc.CERT_VALID, tc.KEY_A)
        self.audits = []
        gw = types.SimpleNamespace(
            settings=self.settings, certs=certs,
            audit=types.SimpleNamespace(
                write=lambda event, **f: self.audits.append(event)
            ),
        )
        self.server = server.AppServer(("127.0.0.1", 0), gw)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def redirect(self, host, uri="/a/b?c=1", source="127.0.0.1"):
        headers = {"X-Forwarded-Host": host}
        if uri is not None:
            headers["X-Forwarded-Uri"] = uri
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=10, source_address=(source, 0)
        )
        conn.request("GET", "/api/proxy/redirect", headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, resp.getheader("Location"), body

    def raw(self, header_block: bytes):
        with socket.create_connection(("127.0.0.1", self.port), 10) as sock:
            sock.sendall(
                b"GET /api/proxy/redirect HTTP/1.1\r\n" + header_block
                + b"Connection: close\r\n\r\n"
            )
            data = b""
            while chunk := sock.recv(65536):
                data += chunk
        head = data.partition(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
        locations = [h for h in head if h.lower().startswith("location:")]
        return int(head[0].split()[1]), head, locations

    def test_decision_matrix(self) -> None:
        own = lambda name: (308, f"https://{name}/a/b?c=1")  # noqa: E731
        for name, want in (
            (tp.ROOT_DOMAIN, own(tp.ROOT_DOMAIN)),
            (tp.SECOND_DOMAIN, own(tp.SECOND_DOMAIN)),
            (tp.host("owui"), own(tp.host("owui"))),
            (tp.host("nas", tp.SECOND_DOMAIN), own(tp.host("nas", tp.SECOND_DOMAIN))),
            # Ismeretlen vagy kikapcsolt, de a feltöltött *.root fedi: challenge.
            (tp.host("x"), own(tp.host("x"))),
            (tp.host("off"), own(tp.host("off"))),
            # Nem fedett: a tartalmazó gyökér portálja, útvonal nélkül.
            (f"a.b.{tp.ROOT_DOMAIN}", (302, FIRST)),
            (tp.host("x", tp.SECOND_DOMAIN), (302, SECOND)),
            (tp.host("gone", tp.SECOND_DOMAIN), (302, SECOND)),
            # Idegen név és nyers IP: az első gyökér.
            ("evil.example.com", (302, FIRST)),
            ("88.198.151.195", (302, FIRST)),
            ("[2001:db8::1]", (302, FIRST)),
            ("localhost", (302, FIRST)),
        ):
            with self.subTest(host=name):
                status, location, body = self.redirect(name)
                self.assertEqual((status, location), want)
                self.assertEqual(body, b"")
        self.assertEqual(self.audits, [])

    def test_port_is_stripped_and_case_folded(self) -> None:
        for name in (f"{tp.host('owui')}:80", tp.host("OWUI").upper() + ":8080"):
            with self.subTest(host=name):
                self.assertEqual(
                    self.redirect(name)[:2],
                    (308, f"https://{tp.host('owui')}/a/b?c=1"),
                )
        self.assertEqual(self.redirect("88.198.151.195:80")[:2], (302, FIRST))
        # Host fejléc, ha nincs X-Forwarded-Host.
        status, _, locations = self.raw(f"Host: {tp.host('owui')}:80\r\n".encode())
        self.assertEqual(status, 308)
        self.assertEqual(locations, [f"Location: https://{tp.host('owui')}/"])

    def test_bad_uri_falls_back_to_slash(self) -> None:
        for uri in (None, "", "a/b", "http://evil.com/", "/a b", "/\x7f",
                    "/é"):
            with self.subTest(uri=uri):
                self.assertEqual(
                    self.redirect(tp.ROOT_DOMAIN, uri)[:2],
                    (308, f"https://{tp.ROOT_DOMAIN}/"),
                )
        # A // kezdetű útvonal is a saját hoston marad.
        self.assertEqual(
            self.redirect(tp.ROOT_DOMAIN, "//evil.com/x")[1],
            f"https://{tp.ROOT_DOMAIN}//evil.com/x",
        )

    def test_malformed_host_never_leaves_our_names(self) -> None:
        long = "a." * 200 + tp.ROOT_DOMAIN
        for name in (
            "evil.com@" + tp.host("owui"), tp.host("owui") + "@evil.com",
            "evil.com " + tp.host("owui"), tp.host("owui") + " evil.com",
            "evil.com/" + tp.host("x"), "evil.com\\." + tp.host("x"),
            "evil.com#." + tp.host("x"), "[fe80::1%evil.com]", "[evil.com]",
            "-a." + tp.ROOT_DOMAIN, "a" * 64 + "." + tp.ROOT_DOMAIN,
            long, "a" * 5000, tp.host("owui") + ":http", ":80", "",
            tp.host("x") + ".",
        ):
            with self.subTest(host=name[:60]):
                status, location, _ = self.redirect(name)
                self.assertEqual(status, 302)
                self.assertIn(location, (FIRST, SECOND))
        # CRLF: sorátfűzés (obs-fold) és külön fejlécsor sem juthat át.
        for block in (
            b"X-Forwarded-Host: evil.com\r\n Location: https://evil.com/\r\n",
            b"X-Forwarded-Host: evil.com\r\nX-Forwarded-Uri: /\r\n"
            b" \r\nLocation: https://evil.com/\r\n",
            f"Host: {tp.host('owui')}\r\nX-Forwarded-Uri: /x\r\n"
            " Set-Cookie: a=1\r\n".encode(),
        ):
            with self.subTest(block=block):
                status, head, locations = self.raw(block)
                self.assertIn(status, (302, 308))
                self.assertEqual(len(locations), 1)
                self.assertTrue(
                    locations[0] in (f"Location: {FIRST}", f"Location: {SECOND}",
                                     f"Location: https://{tp.host('owui')}/"),
                    locations,
                )
                self.assertFalse(any("Set-Cookie" in h for h in head))

    def test_without_roots_keeps_old_behaviour(self) -> None:
        self.settings.set_proxy([], [])
        for name, want in (
            ("asd.example.com:80", (308, "https://asd.example.com/a/b?c=1")),
            ("88.198.151.195", (308, "https://88.198.151.195/a/b?c=1")),
            ("[2001:DB8::1]:80", (308, "https://[2001:db8::1]/a/b?c=1")),
            ("evil.com@x", (400, None)),
            ("a b", (400, None)),
        ):
            with self.subTest(host=name):
                self.assertEqual(self.redirect(name)[:2], want)

    def test_portal_domain_frees_the_root(self) -> None:
        portal = "dropjak." + tp.ROOT_DOMAIN
        self.settings.set_portal_domain(portal)
        addCleanup = self.addCleanup
        addCleanup(self.settings.set_portal_domain, "")
        # Bejegyzés nélkül a gyökér nem irányít a portálra (nincs tanúsítványa).
        for name in (tp.ROOT_DOMAIN, tp.SECOND_DOMAIN):
            with self.subTest(host=name):
                self.assertEqual(self.redirect(name)[:2], (404, None))
        # Az ismeretlen aldomain viszont a portálra megy.
        self.assertEqual(
            self.redirect(tp.host("x", tp.SECOND_DOMAIN))[:2],
            (302, f"https://{portal}/"),
        )
        # Gyökérre szóló bejegyzéssel a gyökér saját szolgáltatást kap.
        snap = self.settings.snapshot()
        self.settings.set_proxy(
            snap["proxy_domains"],
            [dict(route) for route in snap["proxy_routes"]] + [
                {"name": "", "root": tp.ROOT_DOMAIN, "port": 3000}],
        )
        addCleanup(
            self.settings.set_proxy,
            snap["proxy_domains"],
            [route for route in snap["proxy_routes"] if route["name"]],
        )
        self.assertEqual(
            self.redirect(tp.ROOT_DOMAIN)[:2],
            (308, f"https://{tp.ROOT_DOMAIN}/a/b?c=1"),
        )

    def test_loopback_only(self) -> None:
        status, location, body = self.redirect(tp.ROOT_DOMAIN, source="127.0.0.2")
        self.assertEqual((status, location, body), (404, None, b""))


if __name__ == "__main__":
    unittest.main()
