#!/usr/bin/env python3
"""
Dropjak — HTTP belépőkapu és adminisztrációs CLI.

Használat:

  python3 server.py                     # a kapu futtatása
  python3 server.py user add alice      # felhasználó létrehozása
  python3 server.py user passwd alice   # jelszó csere
  python3 server.py user del alice      # felhasználó törlése
  python3 server.py user list           # felhasználók listája
  python3 server.py check-firewall      # nftables halmaz ellenőrzése

A tényleges tűzfalkezelés a gateway.py-ban van.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import signal
import sys
import time
import urllib.parse
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import gateway
import settings_store

BASE = os.path.dirname(os.path.abspath(__file__))

STATIC_FILES = {
    "index.html": ("text/html; charset=utf-8", "no-store"),
    "icon.png": ("image/png", "public, max-age=3600"),
}

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; "
    "frame-src https://challenges.cloudflare.com; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self' https://challenges.cloudflare.com; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


# -------------------------------------------------------------------- HTTP réteg

class Handler(BaseHTTPRequestHandler):
    server_version = "Hatarvedelem/2"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    # Lassú/beragadt kapcsolatok ne foglalják örökre a szálakat.
    timeout = 30

    # -- segédek ---------------------------------------------------------------

    @property
    def gw(self) -> gateway.Gateway:
        return self.server.gateway  # type: ignore[attr-defined]

    def _client_ip(self) -> str:
        try:
            return gateway.normalize_ip(self.client_address[0])
        except ValueError:
            return str(self.client_address[0])

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{self._client_ip()}] {fmt % args}", flush=True)

    def _cookie_token(self) -> str:
        raw = self.headers.get("Cookie")
        if not raw:
            return ""
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except CookieError:
            return ""
        morsel = jar.get(gateway.COOKIE_NAME)
        return morsel.value if morsel else ""

    def _origin_ok(self) -> bool:
        """Azonos eredetű kérés-e (CSRF ellen, a SameSite mellett)."""
        origin = self.headers.get("Origin")
        if not origin:
            return True
        if origin == "null":
            return False
        try:
            origin_netloc = urllib.parse.urlsplit(origin).netloc
        except ValueError:
            return False
        host = (self.headers.get("Host") or "").strip()
        return bool(host) and origin_netloc.lower() == host.lower()

    def _send(
        self,
        code: int,
        body: bytes = b"",
        ctype: str = "application/json; charset=utf-8",
        headers: dict[str, str] | None = None,
        cache: str = "no-store",
    ) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _json(self, code: int, obj: dict, headers: dict[str, str] | None = None) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), headers=headers)

    def _static(self, name: str) -> None:
        ctype, cache = STATIC_FILES[name]
        try:
            with open(os.path.join(BASE, name), "rb") as fh:
                body = fh.read()
        except OSError:
            self._json(500, {"ok": False, "error": "a felület fájlja hiányzik"})
            return
        self._send(200, body, ctype, cache=cache)

    def _read_json(self) -> dict | None:
        # Az állapotmódosító végpontok csak JSON-t fogadnak. Ez a böngészők
        # űrlapos (simple request) CSRF-ját is kizárja, mert az űrlap nem tud
        # application/json tartalomtípust küldeni.
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0]
        if ctype.strip().lower() != "application/json":
            self.close_connection = True
            return None
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = -1
        if length <= 0 or length > 64 * 1024:
            self.close_connection = True
            return None
        try:
            data = json.loads(self.rfile.read(length))
        except (OSError, ValueError):
            self.close_connection = True
            return None
        return data if isinstance(data, dict) else None

    def _discard_body(self) -> None:
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length <= 0:
            return
        if length > 64 * 1024:
            self.close_connection = True
            return
        try:
            self.rfile.read(length)
        except OSError:
            self.close_connection = True

    def _ua(self) -> str:
        return (self.headers.get("User-Agent") or "")[:300]

    def _audit(self, event: str, **fields) -> None:
        fields.setdefault("ip", self._client_ip())
        fields.setdefault("ua", self._ua())
        self.gw.audit.write(event, **fields)

    def _session(self) -> gateway.Session | None:
        return self.gw.sessions.validate(self._cookie_token(), self._client_ip())

    def _admin_guard(self) -> gateway.Session | None:
        session = self._session()
        if session is None or not session.is_admin:
            self._audit(
                "admin_denied",
                user=session.user if session is not None else "",
                reason="nincs admin munkamenet",
                path=urllib.parse.urlsplit(self.path).path,
            )
            self._json(403, {"ok": False, "error": "admin jogosultság szükséges"})
            return None
        record = self.gw.users.record(session.user)
        if record is None or not record.enabled or not record.is_admin:
            # A munkamenet szerepkörét/aktív állapotát minden admin-kérésnél
            # a friss felhasználói nyilvántartásból ellenőrizzük, nem a
            # belépéskori pillanatképből. Elavult munkamenet nem maradhat.
            self.gw.sessions.terminate(session.sid, reason="revoked")
            self._audit(
                "admin_denied",
                user=session.user,
                reason="a felhasználó már nem aktív admin",
                path=urllib.parse.urlsplit(self.path).path,
            )
            self._json(403, {"ok": False, "error": "admin jogosultság szükséges"})
            return None
        if record.must_change_password:
            self._audit(
                "admin_denied",
                user=session.user,
                reason="kötelező jelszócsere előtt",
                path=urllib.parse.urlsplit(self.path).path,
            )
            self._json(
                403,
                {
                    "ok": False,
                    "error": "Előbb cseréld le a kezdetleges jelszavad.",
                    "must_change_password": True,
                },
            )
            return None
        return session

    def _admin_state(self) -> dict:
        users = []
        for record in self.gw.users.details():
            groups = self.gw.groups.groups_for(record.name)
            item = record.public([group.id for group in groups])
            item["effective_rules"] = [
                rule.id for rule in self.gw.rules.effective_for(record, groups)
            ]
            users.append(item)
        return {
            "ok": True,
            "users": users,
            "groups": [group.public() for group in self.gw.groups.all_groups()],
            "rules": [rule.public() for rule in self.gw.rules.all_rules()],
            "limits": self._limits(),
            "builtin_rule": gateway.ADMIN_RULE_ID,
            "roles": [gateway.ROLE_USER, gateway.ROLE_ADMIN],
            "settings": self.gw.settings.snapshot(),
            "drop_log": self.gw.drops.status(),
        }

    @staticmethod
    def _rule_ids(data: dict) -> list[str] | None:
        if "rules" not in data:
            return None
        raw = data.get("rules")
        if not isinstance(raw, list) or len(raw) > 64:
            raise gateway.RuleStoreError("a rules mező legfeljebb 64 elemű lista")
        out: list[str] = []
        for value in raw:
            if not isinstance(value, str) or not value.strip():
                raise gateway.RuleStoreError("érvénytelen szabály-azonosító")
            value = value.strip()
            if value == gateway.ADMIN_RULE_ID:
                raise gateway.RuleStoreError(
                    "az admin teljes szabály nem rendelhető hozzá kézzel"
                )
            if value not in out:
                out.append(value)
        return out

    def _known_rule_ids(self) -> set[str]:
        return {rule.id for rule in self.gw.rules.persisted_rules()}

    def _validate_rule_ids(self, rule_ids: list[str]) -> None:
        unknown = set(rule_ids) - self._known_rule_ids()
        if unknown:
            raise gateway.RuleStoreError(
                f"ismeretlen szabály: {', '.join(sorted(unknown))}"
            )

    def _group_ids(self, data: dict) -> list[str] | None:
        if "groups" not in data:
            return None
        raw = data.get("groups")
        if not isinstance(raw, list) or len(raw) > 64:
            raise gateway.GroupStoreError("a groups mező legfeljebb 64 elemű lista")
        out: list[str] = []
        for value in raw:
            if not isinstance(value, str) or not value.strip():
                raise gateway.GroupStoreError("érvénytelen csoport-azonosító")
            value = value.strip()
            if self.gw.groups.get(value) is None:
                raise gateway.GroupStoreError(f"ismeretlen csoport: {value}")
            if value not in out:
                out.append(value)
        return out

    def _members(self, data: dict) -> list[str] | None:
        if "members" not in data:
            return None
        raw = data.get("members")
        if not isinstance(raw, list) or len(raw) > 512:
            raise gateway.GroupStoreError("a members mező legfeljebb 512 elemű lista")
        out: list[str] = []
        for value in raw:
            if not isinstance(value, str) or not value.strip():
                raise gateway.GroupStoreError("érvénytelen felhasználónév")
            value = value.strip()
            if self.gw.users.record(value) is None:
                raise gateway.GroupStoreError(f"ismeretlen felhasználó: {value}")
            if value not in out:
                out.append(value)
        return out

    def _portal_host_matches(self) -> bool:
        if not gateway.PORTAL_URL:
            return True
        host = (self.headers.get("Host") or "").strip().lower()
        if not host:
            return True
        target = urllib.parse.urlsplit(gateway.PORTAL_URL).netloc.lower()
        return host == target

    # -- GET / HEAD ------------------------------------------------------------

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path

        if path == "/api/challenge":
            return self._challenge()
        if path == "/api/status":
            return self._status()
        if path == "/api/admin/state":
            return self._admin_state_api()
        if path == "/api/admin/logs":
            return self._admin_logs()
        if path == "/api/admin/sessions":
            return self._admin_sessions()
        if path == "/api/admin/firewall":
            return self._admin_firewall()
        if path == "/api/admin/firewall-rules":
            return self._admin_firewall_rules()
        if path == "/api/admin/drops":
            return self._admin_drops()
        if path == "/api/admin/settings":
            return self._admin_settings_api()
        if path.startswith("/api/"):
            return self._json(404, {"ok": False, "error": "ismeretlen végpont"})

        # Captive portal: idegen Hosttal érkező HTTP kérést a kapu saját
        # címére irányítjuk, hogy a süti és az állapot egy helyen legyen.
        if not self._portal_host_matches():
            return self._send(
                302, b"", "text/plain; charset=utf-8",
                headers={"Location": gateway.PORTAL_URL},
            )

        if path in ("/", "/index.html") or path not in ("/icon.png", "/favicon.ico"):
            if self.command == "GET":
                session = self._session()
                self._audit(
                    "portal_opened",
                    user=session.user if session is not None else "",
                    authenticated=session is not None,
                    authorized=bool(session and session.authorized),
                    path=path,
                    host=(self.headers.get("Host") or "")[:200],
                )
        if path in ("/", "/index.html"):
            return self._static("index.html")
        if path == "/icon.png" or path == "/favicon.ico":
            return self._static("icon.png")
        # Bármely más útvonalra a belépőoldalt adjuk (captive viselkedés).
        return self._static("index.html")

    do_HEAD = do_GET

    def _challenge(self) -> None:
        if gateway.TURNSTILE_ON:
            self._json(200, {"mode": "turnstile", "sitekey": gateway.TURNSTILE_SITEKEY})
        else:
            self._json(200, {"mode": "pow", **gateway.issue_challenge()})

    def _limits(self) -> dict:
        return {
            "min_ttl": gateway.MIN_TTL,
            "max_ttl": gateway.MAX_TTL,
            "default_ttl": self.gw.sessions.ttl,
        }

    def _rule_payload(self, rule) -> dict:
        return rule.public()

    def _status(self) -> None:
        session = self._session()
        if session is None:
            # A legutóbbi lezárás okát is megadjuk, hogy a felület meg tudja
            # mondani, miért esett ki a felhasználó a countdown közben.
            last_end = self.gw.sessions.last_end(self._client_ip())
            payload = {"ok": True, "authenticated": False}
            if last_end is not None:
                payload["last_end"] = last_end
            self._json(200, payload)
            return
        record = self.gw.users.record(session.user)
        if record is None or not record.enabled:
            self.gw.sessions.logout(
                session.token, session.ip,
                reason="disabled" if record is not None else "revoked",
            )
            last_end = self.gw.sessions.last_end(self._client_ip())
            payload = {"ok": True, "authenticated": False}
            if last_end is not None:
                payload["last_end"] = last_end
            self._json(200, payload)
            return
        rules = self.gw.effective_rules(session.user)
        payload = {
            "ok": True,
            "authenticated": True,
            "authorized": session.authorized,
            "user": session.user,
            "role": record.role,
            "admin": record.is_admin,
            "must_change_password": record.must_change_password,
            "expires_in": session.expires_in,
            "limits": self._limits(),
            "rules": [self._rule_payload(rule) for rule in rules],
        }
        if session.authorized:
            payload["rule"] = session.rule
            payload["rule_label"] = session.rule_label
            payload["grant"] = session.ports.public()
        else:
            payload["pending"] = True
        self._json(200, payload)

    def _admin_state_api(self) -> None:
        if self._admin_guard() is None:
            return
        self._json(200, self._admin_state())

    def _sessions_payload(self, current: gateway.Session | None) -> dict:
        rows = self.gw.sessions.active_sessions()
        current_sid = current.sid if current is not None else ""
        for row in rows:
            row["current"] = row.get("id") == current_sid
        return {
            "ok": True,
            "sessions": rows,
            "server_time": time.time(),
            "count": self.gw.sessions.count(),
        }

    def _admin_sessions(self) -> None:
        session = self._admin_guard()
        if session is None:
            return
        self._json(200, self._sessions_payload(session))

    def _admin_firewall(self) -> None:
        if self._admin_guard() is None:
            return
        try:
            snapshot = self.gw.firewall.snapshot()
        except gateway.FirewallError as exc:
            self._json(
                503,
                {
                    "ok": False,
                    "error": f"a tűzfal állapota nem olvasható: {exc}",
                },
            )
            return
        payload = gateway.group_firewall_snapshot(
            snapshot, self.gw.sessions.active_sessions()
        )
        payload["ok"] = True
        self._json(200, payload)

    def _admin_firewall_rules(self) -> None:
        """A kernelben élő nftables láncok nyers szöveges kiírása."""
        if self._admin_guard() is None:
            return
        try:
            payload = self.gw.firewall.ruleset()
        except gateway.FirewallError as exc:
            self._json(
                503,
                {
                    "ok": False,
                    "error": f"a nyers szabályok nem olvashatók: {exc}",
                },
            )
            return
        payload["ok"] = True
        self._json(200, payload)

    def _admin_sessions_action(self) -> None:
        session = self._admin_guard()
        if session is None:
            return
        if not self._origin_ok():
            self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
            return
        data = self._read_json()
        if data is None:
            return
        if str(data.get("action", "")).strip() != "terminate":
            self._json(400, {"ok": False, "error": "ismeretlen művelet"})
            return
        sid = data.get("id")
        if not isinstance(sid, str) or not sid.strip():
            self._json(400, {"ok": False, "error": "hiányzó munkamenet-azonosító"})
            return
        sid = sid.strip()
        if sid == session.sid:
            self._json(
                400,
                {
                    "ok": False,
                    "error": "a saját munkamenetedet a Kilépés gombbal zárhatod le",
                },
            )
            return
        terminated = self.gw.sessions.terminate(sid)
        if terminated is None:
            self._json(
                404,
                {"ok": False, "error": "nincs ilyen munkamenet (már lejárt)"},
            )
            return
        self._audit(
            "admin_session_terminated",
            target=terminated.user,
            user=session.user,
            ip=terminated.ip,
            rule=terminated.rule,
            rule_label=terminated.rule_label,
            authorized=terminated.authorized,
        )
        payload = self._sessions_payload(session)
        payload["message"] = f"{terminated.user} munkamenete lezárva."
        self._json(200, payload)

    def _admin_logs(self) -> None:
        if self._admin_guard() is None:
            return
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        try:
            limit = int((query.get("limit") or ["500"])[0])
        except ValueError:
            limit = 500
        try:
            before_raw = (query.get("before") or [""])[0]
            before = float(before_raw) if before_raw else None
        except ValueError:
            before = None
        rows = self.gw.audit.read(
            limit=limit,
            event=(query.get("event") or [""])[0],
            user=(query.get("user") or [""])[0],
            q=(query.get("q") or [""])[0],
            before=before,
        )
        self._json(
            200,
            {
                "ok": True,
                "logs": rows,
                "count": len(rows),
                "server_time": time.time(),
            },
        )

    def _admin_drops(self) -> None:
        if self._admin_guard() is None:
            return
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)

        def first(name: str) -> str:
            return (query.get(name) or [""])[0].strip()

        try:
            limit = int(first("limit") or "500")
        except ValueError:
            limit = 500
        limit = max(1, min(2000, limit))
        port: int | None = None
        port_raw = first("port")
        if port_raw:
            try:
                port = int(port_raw)
            except ValueError:
                port = -1
            if port < 1 or port > 65535:
                self._json(
                    400,
                    {
                        "ok": False,
                        "error": "a port 1 és 65535 között lehet",
                    },
                )
                return
        try:
            before_raw = first("before")
            before = float(before_raw) if before_raw else None
        except ValueError:
            before = None
        rows = self.gw.drops.read(
            limit=limit,
            src=first("src")[:120],
            dst=first("dst")[:120],
            proto=first("proto")[:16],
            port=port,
            reason=first("reason")[:80],
            q=first("q")[:120],
            before=before,
        )
        self._json(
            200,
            {
                "ok": True,
                "drops": rows,
                "count": len(rows),
                "server_time": time.time(),
                "status": self.gw.drops.status(),
            },
        )

    def _admin_settings_api(self) -> None:
        if self._admin_guard() is None:
            return
        self._json(
            200,
            {
                "ok": True,
                "settings": self.gw.settings.snapshot(),
                "drop_log": self.gw.drops.status(),
            },
        )

    def _admin_settings_action(self) -> None:
        session = self._admin_guard()
        if session is None:
            return
        if not self._origin_ok():
            self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
            return
        data = self._read_json()
        if data is None:
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        action = str(data.get("action", "")).strip().lower()
        kind = str(data.get("kind", "")).strip().lower()
        entry_id = data.get("id", "")
        if entry_id is None:
            entry_id = ""
        if not isinstance(entry_id, str):
            self._json(
                400, {"ok": False, "error": "érvénytelen bejegyzés-azonosító"}
            )
            return
        # A módosítás előkészítése és az nftables-re alkalmazása egy zár
        # alatt fut, hogy két párhuzamos admin-kérés ne írja felül
        # egymás beállításait (TOCTOU).
        with self.gw.admin_lock:
            try:
                new_data = self.gw.settings.prepare(
                    action,
                    kind=kind,
                    entry_id=entry_id.strip(),
                    entry=data.get("entry"),
                    host_ssh=data.get("host_ssh", ""),
                )
            except (settings_store.SettingsError, ValueError) as exc:
                self._admin_action_error(f"settings_{action}", exc)
                self._json(400, {"ok": False, "error": str(exc)})
                return
            try:
                warnings = self.gw.apply_settings(new_data)
            except (gateway.FirewallError, settings_store.SettingsError,
                    OSError) as exc:
                self._admin_action_error(f"settings_{action}", exc)
                self._json(
                    503,
                    {
                        "ok": False,
                        "error": "a tűzfal-beállítások alkalmazása nem "
                                 f"sikerült: {exc}",
                    },
                )
                return
            target = entry_id.strip()
            if action == "host_ssh":
                target = new_data.get("host_ssh", "")
            self._audit(
                "admin_settings_changed",
                user=session.user,
                action=action or "ismeretlen",
                kind=kind,
                target=target,
                host_ssh=new_data.get("host_ssh", ""),
                preauth_count=len(new_data.get("preauth", [])),
                block_count=len(new_data.get("block", [])),
                warnings=len(warnings),
            )
        payload = self._admin_state()
        payload["message"] = "A tűzfalbeállítások mentve."
        if warnings:
            payload["warnings"] = warnings
        self._json(200, payload)

    # -- POST ------------------------------------------------------------------

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/login":
            return self._login()
        if path == "/api/access":
            return self._access()
        if path == "/api/logout":
            return self._logout()
        if path == "/api/password":
            return self._password()
        if path == "/api/admin/users":
            return self._admin_users()
        if path == "/api/admin/groups":
            return self._admin_groups()
        if path == "/api/admin/rules":
            return self._admin_rules()
        if path == "/api/admin/sessions":
            return self._admin_sessions_action()
        if path == "/api/admin/settings":
            return self._admin_settings_action()
        self._discard_body()
        self._json(404, {"ok": False, "error": "ismeretlen végpont"})

    def _login(self) -> None:
        ip = self._client_ip()
        data = self._read_json()
        if data is None:
            self._audit("login_failed", reason="hibás kérés")
            return self._json(400, {"ok": False, "error": "hibás kérés"})

        if not self.gw.login_rate.allow(ip):
            self._audit("login_failed", reason="túl sok próbálkozás")
            return self._json(
                429,
                {"ok": False, "error": "Túl sok próbálkozás. Várj egy percet."},
                headers={"Retry-After": str(gateway.RATE_WINDOW)},
            )

        if not gateway.is_ipv4(ip):
            self._audit("login_failed", reason="nem IPv4 cím")
            return self._json(
                400, {"ok": False, "error": "A kapu csak IPv4-címmel érhető el."}
            )

        if not self._origin_ok():
            self._audit("login_failed", reason="érvénytelen kérés-eredet")
            return self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})

        user = data.get("user")
        password = data.get("pass")
        captcha = data.get("captcha")
        if not isinstance(user, str) or not isinstance(password, str) or not isinstance(captcha, dict):
            self._audit("login_failed", reason="hiányos adatok")
            return self._json(400, {"ok": False, "error": "hiányos adatok"})
        user = user.strip()
        if not user or len(user) > 64 or len(password) > 1024:
            self._audit("login_failed", user=user[:64], reason="hiányos adatok")
            return self._json(400, {"ok": False, "error": "hiányos adatok"})

        if gateway.TURNSTILE_ON:
            ok, why = gateway.verify_turnstile(str(captcha.get("token", "")), ip)
        else:
            ok, why = gateway.verify_pow(captcha)
        if not ok:
            self._audit("login_failed", user=user, reason=f"captcha: {why}")
            return self._json(403, {"ok": False, "error": f"Captcha: {why}"})

        if not self.gw.users.verify(user, password):
            self._audit("login_failed", user=user, reason="hibás felhasználónév vagy jelszó")
            print(f"[{ip}] sikertelen belépés: {user!r}", flush=True)
            return self._json(
                403, {"ok": False, "error": "Hibás felhasználónév vagy jelszó."}
            )

        record = self.gw.users.record(user)
        if record is None or not record.enabled:
            self._audit("login_failed", user=user, reason="letiltott felhasználó")
            return self._json(
                403, {"ok": False, "error": "Hibás felhasználónév vagy jelszó."}
            )

        try:
            session = self.gw.sessions.login(
                user, ip, role=record.role, ua=self._ua()
            )
        except gateway.FirewallError as exc:
            self._audit(
                "login_failed", user=user, reason=f"tűzfal hiba: {exc}"
            )
            print(f"[{ip}] a régi hozzáférés visszavonása nem sikerült: {exc}", flush=True)
            return self._json(
                503,
                {
                    "ok": False,
                    "error": "A belépés előtti tűzfal-frissítés nem sikerült, ezért "
                             "nem léptél be. Szólj az adminisztrátornak.",
                },
            )

        cookie = (
            f"{gateway.COOKIE_NAME}={session.token}; Path=/; HttpOnly; "
            f"SameSite=Lax; Max-Age={self.gw.sessions.pending_ttl}"
        )
        if gateway.COOKIE_SECURE:
            cookie += "; Secure"
        self._audit(
            "login_success",
            user=user,
            role=record.role,
            admin=record.is_admin,
            session=session.token[:10],
            pending_ttl=self.gw.sessions.pending_ttl,
            must_change_password=record.must_change_password,
        )
        print(
            f"[{ip}] hitelesítve: {user!r}; hozzáférés-választásra vár",
            flush=True,
        )
        self._json(
            200,
            {
                "ok": True,
                "authenticated": True,
                "authorized": False,
                "pending": True,
                "user": session.user,
                "role": record.role,
                "admin": record.is_admin,
                "must_change_password": record.must_change_password,
                "expires_in": session.expires_in,
                "limits": self._limits(),
                "rules": [
                    self._rule_payload(rule)
                    for rule in self.gw.effective_rules(user)
                ],
                "message": (
                    "Sikeres belépés. Első belépésnél le kell cserélned a "
                    "kezdetleges jelszavad."
                    if record.must_change_password else
                    "Sikeres belépés. Válaszd ki a hozzáférési szabályt "
                    "és azt, mennyi ideig szeretnéd használni a hálózatot."
                ),
            },
            headers={"Set-Cookie": cookie},
        )

    def _access(self) -> None:
        ip = self._client_ip()
        data = self._read_json()
        if data is None:
            self._audit("access_denied", reason="hibás kérés")
            return self._json(400, {"ok": False, "error": "hibás kérés"})

        if not self._origin_ok():
            self._audit("access_denied", reason="érvénytelen kérés-eredet")
            return self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
        if not gateway.is_ipv4(ip):
            self._audit("access_denied", reason="nem IPv4 cím")
            return self._json(
                400, {"ok": False, "error": "A kapu csak IPv4-címmel érhető el."}
            )

        if not self.gw.access_rate.allow(ip):
            self._audit("access_denied", reason="túl sok próbálkozás")
            return self._json(
                429,
                {"ok": False, "error": "Túl sok hozzáférés-módosítás. Várj egy percet."},
                headers={"Retry-After": "60"},
            )

        rule_id = data.get("rule")
        ttl = data.get("ttl")
        if not isinstance(rule_id, str) or isinstance(ttl, bool) or not isinstance(ttl, int):
            self._audit("access_denied", reason="hiányzó szabály vagy időtartam")
            return self._json(
                400, {"ok": False, "error": "hiányzó szabály vagy időtartam"}
            )

        token = self._cookie_token()
        current = self.gw.sessions.validate(token, ip)
        if current is None:
            self._audit("access_denied", reason="nincs érvényes munkamenet",
                        rule=rule_id)
            return self._json(
                400, {"ok": False, "error": "érvénytelen vagy lejárt munkamenet"}
            )
        record = self.gw.users.record(current.user)
        if record is None or not record.enabled:
            self.gw.sessions.logout(token, ip)
            self._audit(
                "access_denied", user=current.user,
                reason="letiltott vagy törölt felhasználó", rule=rule_id,
            )
            return self._json(403, {"ok": False, "error": "a felhasználó nem aktív"})
        if record.must_change_password:
            self._audit(
                "access_denied", user=current.user,
                reason="kötelező jelszócsere", rule=rule_id,
            )
            return self._json(
                403,
                {
                    "ok": False,
                    "error": "Előbb cseréld le a kezdetleges jelszavad.",
                    "must_change_password": True,
                },
            )

        groups = self.gw.groups.groups_for(current.user)
        try:
            rule = self.gw.rules.resolve_for(record, groups, rule_id)
            session = self.gw.sessions.authorize(token, ip, rule, ttl)
        except gateway.AccessError as exc:
            self._audit(
                "access_denied", user=current.user, rule=rule_id,
                ttl=ttl, reason=str(exc),
            )
            return self._json(400, {"ok": False, "error": str(exc)})
        except gateway.FirewallError as exc:
            self._audit(
                "access_denied", user=current.user, rule=rule_id,
                ttl=ttl, reason=f"tűzfal hiba: {exc}",
            )
            print(f"[{ip}] a hozzáférés beállítása nem sikerült: {exc}", flush=True)
            return self._json(
                503,
                {
                    "ok": False,
                    "error": "A tűzfal engedélyezése nem sikerült. Próbáld újra; "
                             "ha ismétlődik, szólj az adminisztrátornak.",
                },
            )

        cookie = (
            f"{gateway.COOKIE_NAME}={session.token}; Path=/; HttpOnly; "
            f"SameSite=Lax; Max-Age={max(1, session.expires_in)}"
        )
        if gateway.COOKIE_SECURE:
            cookie += "; Secure"
        minutes = max(1, (session.expires_in + 59) // 60)
        self._audit(
            "access_modified" if current.authorized else "access_granted",
            user=session.user,
            role=record.role,
            rule=rule.id,
            rule_label=rule.label,
            tcp=",".join(str(port) for port in session.tcp),
            udp=",".join(str(port) for port in session.udp),
            icmp=session.icmp,
            full=session.full,
            ports=session.ports.label(),
            ttl=ttl,
            expires_at=gateway._utc_iso(session.expires),
            modified=current.authorized,
        )
        print(
            f"[{ip}] hozzáférés engedélyezve: {session.user!r}, "
            f"{rule.id} ({session.ports.label()}), {minutes} perc",
            flush=True,
        )
        self._json(
            200,
            {
                "ok": True,
                "authenticated": True,
                "authorized": True,
                "user": session.user,
                "role": record.role,
                "admin": record.is_admin,
                "expires_in": session.expires_in,
                "rule": session.rule,
                "rule_label": session.rule_label,
                "grant": session.ports.public(),
                "limits": self._limits(),
                "rules": [
                    self._rule_payload(item)
                    for item in self.gw.effective_rules(session.user)
                ],
                "message": f"Hozzáférés engedélyezve {minutes} percre "
                           f"({rule.label}).",
            },
            headers={"Set-Cookie": cookie},
        )

    def _logout(self) -> None:
        self._discard_body()
        ip = self._client_ip()
        if not self._origin_ok():
            self._audit("logout_failed", reason="érvénytelen kérés-eredet")
            return self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
        token = self._cookie_token()
        session = self.gw.sessions.logout(token, ip)
        if session is not None:
            self._audit(
                "logout",
                user=session.user,
                role=session.role,
                authorized=session.authorized,
                rule=session.rule,
                rule_label=session.rule_label,
                ports=session.ports.label(),
                duration=max(0, int(time.time() - session.created)),
            )
        clear = (
            f"{gateway.COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        )
        if gateway.COOKIE_SECURE:
            clear += "; Secure"
        print(f"[{ip}] kilépés", flush=True)
        self._json(
            200, {"ok": True, "message": "Kiléptél. A hálózat le van tiltva."},
            headers={"Set-Cookie": clear},
        )

    def _password(self) -> None:
        """Saját jelszó cseréje (első belépéskor kötelező is lehet)."""
        ip = self._client_ip()
        data = self._read_json()
        if data is None:
            self._audit("password_change_failed", reason="hibás kérés")
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        if not self._origin_ok():
            self._audit("password_change_failed", reason="érvénytelen kérés-eredet")
            return self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
        if not gateway.is_ipv4(ip):
            self._audit("password_change_failed", reason="nem IPv4 cím")
            return self._json(
                400, {"ok": False, "error": "A kapu csak IPv4-címmel érhető el."}
            )
        if not self.gw.password_rate.allow(ip):
            self._audit("password_change_failed", reason="túl sok próbálkozás")
            return self._json(
                429,
                {"ok": False, "error": "Túl sok próbálkozás. Várj öt percet."},
                headers={"Retry-After": "300"},
            )
        token = self._cookie_token()
        session = self.gw.sessions.validate(token, ip)
        if session is None:
            self._audit("password_change_failed", reason="nincs érvényes munkamenet")
            return self._json(
                401, {"ok": False, "error": "érvénytelen vagy lejárt munkamenet"}
            )
        record = self.gw.users.record(session.user)
        if record is None or not record.enabled:
            self.gw.sessions.logout(
                token, ip,
                reason="disabled" if record is not None else "revoked",
            )
            self._audit(
                "password_change_failed", user=session.user,
                reason="letiltott vagy törölt felhasználó",
            )
            return self._json(403, {"ok": False, "error": "a felhasználó nem aktív"})

        current = data.get("current")
        new = data.get("new")
        if not isinstance(current, str) or not isinstance(new, str):
            self._audit(
                "password_change_failed", user=session.user,
                reason="hiányzó jelszó",
            )
            return self._json(
                400,
                {"ok": False, "error": "a jelenlegi és az új jelszó is kötelező"},
            )
        if not self.gw.users.verify(session.user, current):
            self._audit(
                "password_change_failed", user=session.user,
                reason="hibás jelenlegi jelszó",
            )
            return self._json(
                403, {"ok": False, "error": "A jelenlegi jelszó nem megfelelő."}
            )
        if current == new:
            self._audit(
                "password_change_failed", user=session.user,
                reason="az új jelszó azonos a régivel",
            )
            return self._json(
                400,
                {"ok": False, "error": "Az új jelszó térjen el a jelenlegitől."},
            )
        try:
            self.gw.users.set_password(
                session.user, new, must_change_password=False
            )
        except gateway.UserStoreError as exc:
            self._audit(
                "password_change_failed", user=session.user, reason=str(exc)
            )
            return self._json(400, {"ok": False, "error": str(exc)})

        revoked = self.gw.sessions.revoke_user(
            session.user, except_token=token, reason="password_changed"
        )
        self._audit(
            "password_changed",
            user=session.user,
            role=record.role,
            sessions_revoked=revoked,
        )
        print(f"[{ip}] jelszó megváltoztatva: {session.user!r}", flush=True)
        self._json(
            200,
            {
                "ok": True,
                "must_change_password": False,
                "sessions_revoked": revoked,
                "message": "A jelszavad megváltozott.",
            },
        )

    # -- admin CRUD ------------------------------------------------------------

    def _admin_action_error(self, action: str, exc: Exception) -> None:
        session = self._session()
        self._audit(
            "admin_action_failed",
            action=action,
            user=session.user if session is not None else "",
            reason=str(exc),
        )

    def _admin_users(self) -> None:
        data = self._read_json()
        if data is None:
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        if not self._origin_ok():
            return self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
        if self._admin_guard() is None:
            return
        action = str(data.get("action", "")).strip()
        try:
            if action == "create":
                self._admin_user_create(data)
            elif action == "update":
                self._admin_user_update(data)
            elif action == "delete":
                self._admin_user_delete(data)
            else:
                raise gateway.UserStoreError("ismeretlen művelet")
        except (gateway.UserStoreError, gateway.GroupStoreError,
                gateway.RuleStoreError, gateway.AccessError, ValueError) as exc:
            self._admin_action_error(f"user_{action}", exc)
            return self._json(400, {"ok": False, "error": str(exc)})
        self._json(200, self._admin_state())

    def _admin_user_create(self, data: dict) -> None:
        name = data.get("name")
        password = data.get("password")
        if not isinstance(name, str) or not isinstance(password, str):
            raise gateway.UserStoreError("a név és a jelszó kötelező")
        name = name.strip()
        role = data.get("role", gateway.ROLE_USER)
        if role not in (gateway.ROLE_USER, gateway.ROLE_ADMIN):
            raise gateway.UserStoreError("érvénytelen szerepkör")
        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            raise gateway.UserStoreError("az enabled mező logikai érték kell legyen")
        rules = self._rule_ids(data)
        if rules is not None:
            self._validate_rule_ids(rules)
        rule_ids = rules or []
        group_ids = self._group_ids(data) or []
        self.gw.users.add(
            name, password, role=role, enabled=enabled, rules=rule_ids,
            must_change_password=True,
        )
        try:
            self.gw.groups.set_memberships(name, group_ids)
        except Exception:
            self.gw.users.remove(name)
            raise
        self._audit(
            "admin_user_created",
            target=name,
            user=self._session().user if self._session() else "",
            role=role,
            enabled=enabled,
            rules=",".join(rule_ids),
            groups=",".join(group_ids),
            must_change_password=True,
        )

    def _admin_user_update(self, data: dict) -> None:
        # Az utolsó admin ellenőrzése és a módosítás egy zár alatt fut, hogy
        # két párhuzamos kérés ne tudja egyszerre lefokozni/letiltani az
        # utolsó adminokat (TOCTOU).
        with self.gw.admin_lock:
            self._admin_user_update_locked(data)

    def _admin_user_update_locked(self, data: dict) -> None:
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise gateway.UserStoreError("hiányzó felhasználónév")
        name = name.strip()
        record = self.gw.users.record(name)
        if record is None:
            raise gateway.UserStoreError(f"nincs ilyen felhasználó: {name}")
        role = data.get("role", record.role)
        if role not in (gateway.ROLE_USER, gateway.ROLE_ADMIN):
            raise gateway.UserStoreError("érvénytelen szerepkör")
        enabled = data.get("enabled", record.enabled)
        if not isinstance(enabled, bool):
            raise gateway.UserStoreError("az enabled mező logikai érték kell legyen")
        if record.is_admin and record.enabled and (
            role != gateway.ROLE_ADMIN or not enabled
        ) and self.gw.users.admin_count() <= 1:
            raise gateway.UserStoreError(
                "az utolsó aktív admin nem tiltható le és nem vehető el a jogosultsága"
            )
        rules = self._rule_ids(data)
        if rules is not None:
            self._validate_rule_ids(rules)
        group_ids = self._group_ids(data)
        password = data.get("password")
        if password is not None and not isinstance(password, str):
            raise gateway.UserStoreError("érvénytelen jelszó")
        must_change = data.get("must_change_password")
        if must_change is not None and not isinstance(must_change, bool):
            raise gateway.UserStoreError(
                "a must_change_password mező logikai érték kell legyen"
            )
        password_changed = bool(isinstance(password, str) and password)
        if password_changed:
            # Az admin által beállított (ideiglenes) jelszót az érintett
            # felhasználónak első belépéskor le kell cserélnie.
            self.gw.users.set_password(
                name, password, must_change_password=True
            )
            must_change = True
        self.gw.users.set_metadata(
            name, role=role, enabled=enabled, rules=rules,
            must_change_password=must_change,
        )
        if group_ids is not None:
            self.gw.groups.set_memberships(name, group_ids)
        reason = "disabled" if not enabled else (
            "password_changed" if password_changed else "revoked"
        )
        revoked = self.gw.sessions.revoke_user(name, reason=reason)
        updated = self.gw.users.record(name)
        self._audit(
            "admin_user_updated",
            target=name,
            user=self._session().user if self._session() else "",
            role=role,
            enabled=enabled,
            rules=",".join(rules) if rules is not None else "(változatlan)",
            groups=",".join(group_ids) if group_ids is not None else "(változatlan)",
            password_changed=password_changed,
            must_change_password=(
                updated.must_change_password if updated is not None
                else bool(must_change)
            ),
            sessions_revoked=revoked,
        )

    def _admin_user_delete(self, data: dict) -> None:
        with self.gw.admin_lock:
            self._admin_user_delete_locked(data)

    def _admin_user_delete_locked(self, data: dict) -> None:
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise gateway.UserStoreError("hiányzó felhasználónév")
        name = name.strip()
        record = self.gw.users.record(name)
        if record is None:
            raise gateway.UserStoreError(f"nincs ilyen felhasználó: {name}")
        if record.is_admin and self.gw.users.admin_count() <= 1:
            raise gateway.UserStoreError("az utolsó admin nem törölhető")
        self.gw.users.remove(name)
        self.gw.groups.remove_member_everywhere(name)
        revoked = self.gw.sessions.revoke_user(name)
        self._audit(
            "admin_user_deleted",
            target=name,
            user=self._session().user if self._session() else "",
            sessions_revoked=revoked,
        )

    def _admin_groups(self) -> None:
        data = self._read_json()
        if data is None:
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        if not self._origin_ok():
            return self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
        if self._admin_guard() is None:
            return
        action = str(data.get("action", "")).strip()
        try:
            if action == "create":
                self._admin_group_create(data)
            elif action == "update":
                self._admin_group_update(data)
            elif action == "delete":
                self._admin_group_delete(data)
            else:
                raise gateway.GroupStoreError("ismeretlen művelet")
        except (gateway.GroupStoreError, gateway.RuleStoreError,
                gateway.UserStoreError, ValueError) as exc:
            self._admin_action_error(f"group_{action}", exc)
            return self._json(400, {"ok": False, "error": str(exc)})
        self._json(200, self._admin_state())

    def _group_payload(self, data: dict, existing=None) -> dict:
        rules = self._rule_ids(data)
        if rules is not None:
            self._validate_rule_ids(rules)
        members = self._members(data)
        return {
            "label": data.get("label", existing.label if existing else ""),
            "description": data.get(
                "description", existing.description if existing else ""
            ),
            "rules": (
                rules if rules is not None
                else list(existing.rules) if existing else []
            ),
            "members": (
                members if members is not None
                else list(existing.members) if existing else []
            ),
        }

    def _admin_group_create(self, data: dict) -> None:
        group_id = data.get("id")
        if not isinstance(group_id, str):
            raise gateway.GroupStoreError("hiányzó csoport-azonosító")
        payload = self._group_payload(data)
        group = self.gw.groups.create(group_id, payload)
        self._audit(
            "admin_group_created",
            target=group.id,
            user=self._session().user if self._session() else "",
            rules=",".join(group.rules),
            members=",".join(group.members),
        )

    def _admin_group_update(self, data: dict) -> None:
        group_id = data.get("id")
        if not isinstance(group_id, str):
            raise gateway.GroupStoreError("hiányzó csoport-azonosító")
        existing = self.gw.groups.get(group_id.strip())
        if existing is None:
            raise gateway.GroupStoreError(f"nincs ilyen csoport: {group_id}")
        payload = self._group_payload(data, existing)
        updated = self.gw.groups.update(group_id, payload)
        affected = set(existing.members) | set(updated.members)
        revoked = sum(self.gw.sessions.revoke_user(name) for name in affected)
        self._audit(
            "admin_group_updated",
            target=updated.id,
            user=self._session().user if self._session() else "",
            rules=",".join(updated.rules),
            members=",".join(updated.members),
            sessions_revoked=revoked,
        )

    def _admin_group_delete(self, data: dict) -> None:
        group_id = data.get("id")
        if not isinstance(group_id, str):
            raise gateway.GroupStoreError("hiányzó csoport-azonosító")
        group = self.gw.groups.delete(group_id.strip())
        revoked = sum(self.gw.sessions.revoke_user(name) for name in group.members)
        self._audit(
            "admin_group_deleted",
            target=group.id,
            user=self._session().user if self._session() else "",
            members=",".join(group.members),
            sessions_revoked=revoked,
        )

    def _admin_rules(self) -> None:
        data = self._read_json()
        if data is None:
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        if not self._origin_ok():
            return self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
        if self._admin_guard() is None:
            return
        action = str(data.get("action", "")).strip()
        try:
            if action == "create":
                self._admin_rule_create(data)
            elif action == "update":
                self._admin_rule_update(data)
            elif action == "delete":
                self._admin_rule_delete(data)
            else:
                raise gateway.RuleStoreError("ismeretlen művelet")
        except (gateway.RuleStoreError, ValueError) as exc:
            self._admin_action_error(f"rule_{action}", exc)
            return self._json(400, {"ok": False, "error": str(exc)})
        self._json(200, self._admin_state())

    def _admin_rule_create(self, data: dict) -> None:
        rule_id = data.get("id")
        if not isinstance(rule_id, str):
            raise gateway.RuleStoreError("hiányzó szabály-azonosító")
        rule = self.gw.rules.create(rule_id, data)
        self._audit(
            "admin_rule_created",
            target=rule.id,
            user=self._session().user if self._session() else "",
            ports=rule.ports.label(),
            default_ttl=rule.default_ttl,
            max_ttl=rule.max_ttl,
        )

    def _admin_rule_update(self, data: dict) -> None:
        rule_id = data.get("id")
        if not isinstance(rule_id, str):
            raise gateway.RuleStoreError("hiányzó szabály-azonosító")
        rule = self.gw.rules.update(rule_id.strip(), data)
        revoked = self.gw.sessions.revoke_rule(rule.id)
        self._audit(
            "admin_rule_updated",
            target=rule.id,
            user=self._session().user if self._session() else "",
            ports=rule.ports.label(),
            default_ttl=rule.default_ttl,
            max_ttl=rule.max_ttl,
            sessions_revoked=revoked,
        )

    def _admin_rule_delete(self, data: dict) -> None:
        rule_id = data.get("id")
        if not isinstance(rule_id, str):
            raise gateway.RuleStoreError("hiányzó szabály-azonosító")
        rule = self.gw.rules.delete(rule_id.strip())
        users_changed = self.gw.users.remove_rule_everywhere(rule.id)
        groups_changed = self.gw.groups.remove_rule_everywhere(rule.id)
        revoked = self.gw.sessions.revoke_rule(rule.id)
        self._audit(
            "admin_rule_deleted",
            target=rule.id,
            user=self._session().user if self._session() else "",
            users_changed=users_changed,
            groups_changed=groups_changed,
            sessions_revoked=revoked,
        )


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], gw: gateway.Gateway) -> None:
        self.gateway = gw
        super().__init__(address, Handler)


# ---------------------------------------------------------------------- CLI

def _prompt_password(from_stdin: bool) -> str:
    if from_stdin:
        line = sys.stdin.readline()
        if line == "":
            raise SystemExit("hiba: nem érkezett jelszó a szabványos bemeneten")
        return line.rstrip("\r\n")
    first = getpass.getpass("Jelszó: ")
    second = getpass.getpass("Jelszó újra: ")
    if first != second:
        raise SystemExit("hiba: a két jelszó nem egyezik")
    return first


def _user_cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="server.py user",
        description="Felhasználók kezelése a hatarvedelem users.json fájljában.",
    )
    sub = parser.add_subparsers(dest="action", required=True)

    p_add = sub.add_parser("add", help="új felhasználó")
    p_add.add_argument("name")
    p_add.add_argument("--password-stdin", action="store_true")
    p_add.add_argument(
        "--no-must-change", action="store_true",
        help="első belépéskor ne kelljen lecserélni a jelszót",
    )
    p_add.add_argument(
        "--role", choices=(gateway.ROLE_USER, gateway.ROLE_ADMIN),
        default=gateway.ROLE_USER, help="szerepkör (alapértelmezés: user)",
    )
    p_add.add_argument(
        "--rule", action="append", default=[], metavar="ID",
        help="hozzárendelt szabály-azonosító (többször is megadható)",
    )

    p_pw = sub.add_parser("passwd", help="jelszó csere")
    p_pw.add_argument("name")
    p_pw.add_argument("--password-stdin", action="store_true")
    p_pw.add_argument(
        "--no-must-change", action="store_true",
        help="a felhasználónak ne kelljen első belépéskor lecserélnie",
    )

    p_del = sub.add_parser("del", help="felhasználó törlése")
    p_del.add_argument("name")

    sub.add_parser("list", help="felhasználók listája")

    args = parser.parse_args(argv)
    store = gateway.UserStore()

    try:
        if args.action == "add":
            password = _prompt_password(args.password_stdin)
            rules = tuple(
                dict.fromkeys(
                    value.strip() for value in args.rule if value.strip()
                )
            )
            for rule_id in rules:
                if not gateway._SERVICE_ID_RE.match(rule_id):
                    raise gateway.UserStoreError(
                        f"érvénytelen szabály-azonosító: {rule_id!r}"
                    )
                if rule_id == gateway.ADMIN_RULE_ID:
                    raise gateway.UserStoreError(
                        "az admin teljes szabály nem rendelhető hozzá kézzel"
                    )
            store.add(
                args.name, password,
                role=args.role,
                rules=rules,
                must_change_password=not args.no_must_change,
            )
            print(f"Felhasználó létrehozva: {args.name}")
        elif args.action == "passwd":
            password = _prompt_password(args.password_stdin)
            store.set_password(
                args.name, password,
                must_change_password=not args.no_must_change,
            )
            print(f"Jelszó frissítve: {args.name}")
        elif args.action == "del":
            if store.remove(args.name):
                print(f"Felhasználó törölve: {args.name}")
            else:
                print(f"Nincs ilyen felhasználó: {args.name}")
                return 1
        elif args.action == "list":
            names = store.names()
            if not names:
                print("Nincs felhasználó. Létrehozás: server.py user add <név>")
                return 0
            for name in names:
                print(name)
    except gateway.UserStoreError as exc:
        print(f"hiba: {exc}", file=sys.stderr)
        return 1
    return 0


def _serve() -> int:
    try:
        gw = gateway.Gateway()
    except gateway.CatalogError as exc:
        print(f"HIBA: {exc}", file=sys.stderr, flush=True)
        return 1

    print("Dropjak — hálózati belépőkapu", flush=True)
    print(f"Figyelés: 0.0.0.0:{gateway.PORT}", flush=True)
    print(
        f"Tűzfal: inet {gw.firewall.table} / {gw.firewall.set_name}, "
        f"{gw.firewall.tcp_set}, {gw.firewall.udp_set}, {gw.firewall.icmp_set}"
        + ("  (DRY-RUN — a szabályok nem módosulnak!)" if gw.firewall.dry_run else ""),
        flush=True,
    )
    captcha_mode = (
        "Cloudflare Turnstile" if gateway.TURNSTILE_ON
        else f"proof-of-work ({gateway.POW_DIFFICULTY} hex nulla)"
    )
    print(f"Captcha: {captcha_mode}", flush=True)
    print(
        f"Szolgáltatáskatalógus: {len(gw.catalog.service_order)} szolgáltatás, "
        f"{len(gw.catalog.scenario_order)} forgatókönyv ({gw.catalog.source})",
        flush=True,
    )
    print(
        f"Szabályok: {len(gw.rules.persisted_rules())} admin szabály "
        f"(+ beépített {gateway.ADMIN_RULE_ID}), "
        f"{len(gw.groups.all_groups())} csoport",
        flush=True,
    )
    print(f"Napló: {gw.audit.path}", flush=True)
    print(
        f"Választható hozzáférés: {(gateway.MIN_TTL + 59) // 60}–"
        f"{gateway.MAX_TTL // 60} perc; alapértelmezett: "
        f"{gw.sessions.ttl // 60} perc",
        flush=True,
    )
    if gateway.PORTAL_URL:
        print(f"Kanonikus portálcím: {gateway.PORTAL_URL}", flush=True)

    gw.prepare()
    try:
        admin_state = gateway.provision_admin(gw.users)
    except gateway.UserStoreError as exc:
        print(f"FIGYELEM: az admin fiók beállítása sikertelen: {exc}", flush=True)
    else:
        if admin_state == "created":
            print(f"[admin] felhasználó létrehozva: {gateway.ADMIN_USER}", flush=True)
        elif admin_state == "updated":
            print(f"[admin] jelszó frissítve: {gateway.ADMIN_USER}", flush=True)
        elif admin_state == "unchanged":
            print(f"[admin] felhasználó rendben: {gateway.ADMIN_USER}", flush=True)

    if not gw.users.names():
        print(
            "FIGYELEM: nincs egyetlen felhasználó sem. "
            "Létrehozás: python3 server.py user add <név>",
            flush=True,
        )

    gw.start()
    server = AppServer(("0.0.0.0", gateway.PORT), gw)

    # Konténerben a folyamat PID 1 is lehet, ilyenkor a kernel a SIGTERM-et
    # alapból figyelmen kívül hagyja. Kezeljük, hogy a docker stop gyorsan
    # és tisztán zárjon.
    def _terminate(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _terminate)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        gw.stop()
    return 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("serve", "run"):
        return _serve()
    if argv[0] == "user":
        return _user_cli(argv[1:])
    if argv[0] == "check-firewall":
        ok, why = gateway.Firewall().healthy()
        print("rendben" if ok else f"hiba: {why}")
        return 0 if ok else 1
    print(
        "Használat: server.py [serve | user ... | check-firewall]",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
