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
import hashlib
import hmac
import json
import os
import secrets
import signal
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import gateway
import fail2ban as fail2ban_mod
import settings_store

BASE = os.path.dirname(os.path.abspath(__file__))

STATIC_FILES = {
    "index.html": ("text/html; charset=utf-8", "no-store"),
    "icon.png": ("image/png", "public, max-age=3600"),
    "blocked.png": ("image/png", "public, max-age=3600"),
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


def _log_fail2ban_error(ip: str, exc: Exception) -> None:
    print(f"[{ip}] fail2ban: a tiltás nem sikerült: {exc}", flush=True)


# --------------------------------------------------- kétfaktoros belépőjegyek

LOGIN_TICKET_TTL = 300
LOGIN_TICKET_MAX_ATTEMPTS = 5
# A jegy a felhasználói rekord pillanatképéhez kötődik. A só folyamatonként
# új, így a memóriában tárolt ujjlenyomat külsőleg nem visszafejthető.
_TICKET_FP_SALT = secrets.token_bytes(32)


@dataclass
class LoginTicket:
    """Rövid életű, egyszer használatos jegy a jelszó utáni 2FA-lépéshez."""

    token: str
    purpose: str  # "verify" vagy "enroll"
    username: str
    ip: str
    fingerprint: str
    secret: str = ""
    attempts: int = 0
    expires_at: float = 0.0


class LoginTicketStore:
    """Memóriabeli jégytár szálbiztos, atomikus műveletekkel.

    A jegyet csak ugyanaz az IP-cím használhatja, mint amelyik kiváltotta.
    A sikertelen kódpróbákat a jegyhez számoljuk; a limit elérésével a jegy
    megszűnik, így a kliensnek elölről kell kezdenie a belépést.
    """

    def __init__(
        self,
        ttl: int = LOGIN_TICKET_TTL,
        max_attempts: int = LOGIN_TICKET_MAX_ATTEMPTS,
        clock=None,
    ) -> None:
        self._ttl = int(ttl)
        self._max_attempts = int(max_attempts)
        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._tickets: dict[str, LoginTicket] = {}

    def _purge_locked(self, now: float | None = None) -> None:
        now = self._clock() if now is None else now
        expired = [
            token
            for token, ticket in self._tickets.items()
            if ticket.expires_at <= now
        ]
        for token in expired:
            del self._tickets[token]

    def issue(
        self,
        purpose: str,
        username: str,
        ip: str,
        fingerprint: str,
        secret: str = "",
    ) -> str:
        token = secrets.token_urlsafe(32)
        ticket = LoginTicket(
            token=token,
            purpose=purpose,
            username=username,
            ip=ip,
            fingerprint=fingerprint,
            secret=secret,
            attempts=0,
            expires_at=self._clock() + self._ttl,
        )
        with self._lock:
            self._purge_locked()
            self._tickets[token] = ticket
        return token

    def peek(self, token: str, ip: str) -> LoginTicket | None:
        """A jegy olvasása fogyasztás nélkül; érvénytelen esetén None."""
        with self._lock:
            now = self._clock()
            self._purge_locked(now)
            ticket = self._tickets.get(token)
            if ticket is None:
                return None
            if ticket.expires_at <= now:
                del self._tickets[token]
                return None
            if ticket.ip != ip or ticket.attempts >= self._max_attempts:
                return None
            return ticket

    def consume(self, token: str, ip: str) -> LoginTicket | None:
        """Atomikus ellenőrzés és törlés: egy jegy csak egyszer használható."""
        with self._lock:
            now = self._clock()
            self._purge_locked(now)
            ticket = self._tickets.get(token)
            if ticket is None:
                return None
            if (
                ticket.expires_at <= now
                or ticket.ip != ip
                or ticket.attempts >= self._max_attempts
            ):
                return None
            del self._tickets[token]
            return ticket

    def fail(self, token: str, ip: str) -> int:
        """Sikertelen próba rögzítése; a hátralévő próbák száma (0 = nincs)."""
        with self._lock:
            now = self._clock()
            self._purge_locked(now)
            ticket = self._tickets.get(token)
            if ticket is None or ticket.ip != ip:
                return 0
            ticket.attempts += 1
            if ticket.attempts >= self._max_attempts:
                del self._tickets[token]
                return 0
            return self._max_attempts - ticket.attempts

    def revoke_user(self, username: str) -> int:
        with self._lock:
            self._purge_locked()
            tokens = [
                token
                for token, ticket in self._tickets.items()
                if ticket.username == username
            ]
            for token in tokens:
                del self._tickets[token]
            return len(tokens)

    def revoke_all(self) -> None:
        with self._lock:
            self._tickets.clear()

    def purge(self) -> None:
        with self._lock:
            self._purge_locked()


LOGIN_TICKETS = LoginTicketStore()


def _record_fingerprint(record: gateway.UserRecord) -> str:
    """A jegyhez kötött felhasználói pillanatkép ujjlenyomata."""
    digest = hashlib.sha256()
    digest.update(_TICKET_FP_SALT)
    digest.update(record.digest)
    digest.update(b"\x00")
    digest.update(record.totp_secret.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(b"1" if record.totp_required else b"0")
    return digest.hexdigest()


# -------------------------------------------------------------------- HTTP réteg

class Handler(BaseHTTPRequestHandler):
    server_version = "Hatarvedelem/2"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    # Lassú/beragadt kapcsolatok ne foglalják örökre a szálakat.
    timeout = 30
    # Kérésenként állítjuk; megakadályozza, hogy a már kiolvasott body-t
    # egy későbbi hibaág még egyszer „elfogyassza” a keep-alive kapcsolatból.
    _body_read = False

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
            self._discard_body()
            return False
        try:
            origin_netloc = urllib.parse.urlsplit(origin).netloc
        except ValueError:
            self._discard_body()
            return False
        host = (self.headers.get("Host") or "").strip()
        ok = bool(host) and origin_netloc.lower() == host.lower()
        if not ok:
            # A korai 403 előtt olvassuk ki a body-t, különben a keep-alive
            # kapcsolaton a következő kérés a régi body után olvasódna.
            self._discard_body()
        return ok

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
            self._body_read = True
            self.close_connection = True
            return None
        self._body_read = True
        return data if isinstance(data, dict) else None

    def _discard_body(self) -> None:
        if self._body_read:
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length <= 0:
            self._body_read = True
            return
        if length > 64 * 1024:
            self._body_read = True
            self.close_connection = True
            return
        try:
            self.rfile.read(length)
        except OSError:
            self.close_connection = True
        self._body_read = True

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
            # A body-t a 403 előtt ki kell olvasni, különben a keep-alive
            # kapcsolaton a következő kérés a régi body-ba futna.
            self._discard_body()
            self._json(
                403,
                {
                    "ok": False,
                    "error": "admin jogosultság szükséges",
                    "code": "admin_session",
                },
            )
            return None
        record = self.gw.users.record(session.user)
        if record is None or not record.enabled or record.pending or not record.is_admin:
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
            self._discard_body()
            self._json(
                403,
                {
                    "ok": False,
                    "error": "admin jogosultság szükséges",
                    "code": "admin_session",
                },
            )
            return None
        if record.must_change_password:
            self._audit(
                "admin_denied",
                user=session.user,
                reason="kötelező jelszócsere előtt",
                path=urllib.parse.urlsplit(self.path).path,
            )
            self._discard_body()
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
            "fail2ban": self.gw.fail2ban.snapshot(),
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
            record = self.gw.users.record(value)
            if record is None:
                raise gateway.GroupStoreError(f"ismeretlen felhasználó: {value}")
            if record.pending:
                raise gateway.GroupStoreError(
                    "a jóváhagyásra váró fiók nem rendelhető csoporthoz"
                )
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
        self._body_read = False
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
        if path == "/api/admin/fail2ban":
            return self._admin_fail2ban_api()
        if path.startswith("/api/"):
            return self._json(404, {"ok": False, "error": "ismeretlen végpont"})

        # Captive portal: idegen Hosttal érkező HTTP kérést a kapu saját
        # címére irányítjuk, hogy a süti és az állapot egy helyen legyen.
        if not self._portal_host_matches():
            return self._send(
                302, b"", "text/plain; charset=utf-8",
                headers={"Location": gateway.PORTAL_URL},
            )

        if path in ("/", "/index.html") or path not in (
            "/icon.png", "/favicon.ico", "/blocked.png"
        ):
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
        if path == "/blocked.png":
            return self._static("blocked.png")
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

    def _ban_fields(self) -> dict:
        """A kliens IP-címének fail2ban tiltása, ha van ilyen.

        A belépőoldal ebből tudja a normál felület helyére tenni a tiltott
        IP-címre figyelmeztető képernyőt.
        """
        banned = self.gw.fail2ban.banned(self._client_ip())
        if banned is None:
            return {}
        return {
            "banned": True,
            "ban_until": banned.get("until", 0),
            "remaining": int(banned.get("remaining", 0)),
            "ban_source": banned.get("source", "login"),
            "ban_detail": banned.get("detail", ""),
            "ban_attempts": int(banned.get("attempts", 0)),
        }

    def _status(self) -> None:
        registration_enabled = bool(
            self.gw.settings.snapshot().get("registration_enabled", False)
        )
        session = self._session()
        if session is None:
            # A legutóbbi lezárás okát is megadjuk, hogy a felület meg tudja
            # mondani, miért esett ki a felhasználó a countdown közben.
            last_end = self.gw.sessions.last_end(self._client_ip())
            payload = {
                "ok": True,
                "authenticated": False,
                "registration_enabled": registration_enabled,
            }
            if last_end is not None:
                payload["last_end"] = last_end
            payload.update(self._ban_fields())
            self._json(200, payload)
            return
        record = self.gw.users.record(session.user)
        if record is None or not record.enabled or record.pending:
            self.gw.sessions.logout(
                session.token, session.ip,
                reason="disabled" if record is not None else "revoked",
            )
            last_end = self.gw.sessions.last_end(self._client_ip())
            payload = {
                "ok": True,
                "authenticated": False,
                "registration_enabled": registration_enabled,
            }
            if last_end is not None:
                payload["last_end"] = last_end
            payload.update(self._ban_fields())
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
            "registration_enabled": registration_enabled,
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
            group=first("group")[:32],
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
        if action == "registration_enabled":
            # Portálkezelés: nem megy át az nftables-előkészítésen és
            # -alkalmazáson, ezért külön ágban kezeljük.
            value = data.get("enabled", data.get("registration_enabled"))
            if not isinstance(value, bool):
                self._json(
                    400,
                    {
                        "ok": False,
                        "error": "a registration_enabled mező igaz/hamis "
                                 "érték kell",
                    },
                )
                return
            with self.gw.admin_lock:
                self.gw.settings.set_registration_enabled(value)
                self._audit(
                    "admin_settings_changed",
                    user=session.user,
                    action="registration_enabled",
                    target="registration_enabled",
                    registration_enabled=value,
                )
            payload = self._admin_state()
            payload["message"] = "A fiókkérés beállítása mentve."
            self._json(200, payload)
            return
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

    def _admin_fail2ban_api(self) -> None:
        if self._admin_guard() is None:
            return
        self._json(
            200,
            {
                "ok": True,
                "fail2ban": self.gw.fail2ban.snapshot(),
                "server_time": time.time(),
            },
        )

    def _admin_fail2ban_action(self) -> None:
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
        target = ""
        message = ""
        try:
            with self.gw.admin_lock:
                if action == "config":
                    config_data = {
                        key: data[key]
                        for key in (
                            "enabled", "max_attempts",
                            "window_seconds", "ban_seconds",
                            "drop_enabled", "drop_max",
                            "drop_ports", "drop_window_seconds",
                        )
                        if key in data
                    }
                    self.gw.fail2ban.configure(config_data)
                    message = "A fail2ban beállításai mentve."
                elif action in ("ban", "unban"):
                    ip = data.get("ip")
                    if not isinstance(ip, str) or not ip.strip():
                        raise fail2ban_mod.Fail2banError("hiányzó IP-cím")
                    ip = ip.strip()
                    target = ip
                    if action == "ban":
                        if ip == self._client_ip():
                            raise fail2ban_mod.Fail2banError(
                                "a saját IP-címed nem tiltható le a portálról"
                            )
                        seconds = data.get("seconds", 0)
                        self.gw.fail2ban.ban(
                            ip, seconds, manual=True, user=session.user
                        )
                        message = f"{ip} letiltva."
                    else:
                        if not self.gw.fail2ban.unban(ip):
                            self._json(
                                404,
                                {
                                    "ok": False,
                                    "error": "ez az IP-cím nem volt letiltva",
                                },
                            )
                            return
                        message = f"{ip} tiltása feloldva."
                elif action == "unban_all":
                    removed = self.gw.fail2ban.unban_all()
                    message = f"{removed} tiltás feloldva."
                else:
                    self._json(
                        400, {"ok": False, "error": "ismeretlen művelet"}
                    )
                    return
                self._audit(
                    "admin_fail2ban_changed",
                    user=session.user,
                    action=action or "ismeretlen",
                    target=target,
                )
        except fail2ban_mod.Fail2banError as exc:
            self._admin_action_error(f"fail2ban_{action}", exc)
            self._json(400, {"ok": False, "error": str(exc)})
            return
        except Exception as exc:
            self._admin_action_error(f"fail2ban_{action}", exc)
            self._json(
                503,
                {
                    "ok": False,
                    "error": f"a fail2ban művelet nem sikerült: {exc}",
                },
            )
            return
        payload = self._admin_state()
        payload["message"] = message
        self._json(200, payload)

    # -- POST ------------------------------------------------------------------

    def do_POST(self) -> None:
        self._body_read = False
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/register":
            return self._register()
        if path == "/api/login":
            return self._login()
        if path == "/api/login/totp":
            return self._login_totp()
        if path == "/api/login/totp/enroll":
            return self._login_totp_enroll()
        if path == "/api/login/recovery":
            return self._login_recovery()
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
        if path == "/api/admin/fail2ban":
            return self._admin_fail2ban_action()
        self._discard_body()
        self._json(404, {"ok": False, "error": "ismeretlen végpont"})

    def _register(self) -> None:
        """Nyilvános fiókkérés: jóváhagyásra váró felhasználó létrehozása."""
        ip = self._client_ip()
        data = self._read_json()
        if data is None:
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        if not self._origin_ok():
            return self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
        if not gateway.is_ipv4(ip):
            return self._json(
                400, {"ok": False, "error": "A kapu csak IPv4-címmel érhető el."}
            )
        if not bool(self.gw.settings.snapshot().get("registration_enabled", False)):
            self._audit(
                "registration_failed", reason="a fiókkérés ki van kapcsolva"
            )
            return self._json(
                403,
                {
                    "ok": False,
                    "error": "A fiókkérés nem engedélyezett.",
                    "code": "registration_disabled",
                },
            )
        if not self.gw.register_rate.allow(ip):
            self._audit("registration_failed", reason="túl sok próbálkozás")
            return self._json(
                429,
                {"ok": False, "error": "Túl sok fiókkérés. Próbáld újra később."},
                headers={"Retry-After": "600"},
            )

        user = data.get("user", data.get("name"))
        password = data.get("pass", data.get("password"))
        email = data.get("email")
        captcha = data.get("captcha")
        if (
            not isinstance(user, str)
            or not isinstance(password, str)
            or not isinstance(email, str)
            or not isinstance(captcha, dict)
        ):
            self._audit("registration_failed", reason="hiányos adatok")
            return self._json(400, {"ok": False, "error": "hiányos adatok"})
        user = user.strip()
        if len(user) > 32 or not gateway.USERNAME_RE.match(user):
            self._audit(
                "registration_failed", reason="érvénytelen felhasználónév"
            )
            return self._json(
                400,
                {
                    "ok": False,
                    "error": "a felhasználónév 1–32 karakter lehet: betű, "
                             "szám, pont, kötőjel, aláhúzás",
                },
            )
        if not (
            gateway.UserStore.MIN_PASSWORD
            <= len(password)
            <= gateway.UserStore.MAX_PASSWORD
        ):
            self._audit(
                "registration_failed", user=user, reason="érvénytelen jelszóhossz"
            )
            return self._json(
                400,
                {
                    "ok": False,
                    "error": f"a jelszó {gateway.UserStore.MIN_PASSWORD}–"
                             f"{gateway.UserStore.MAX_PASSWORD} karakter legyen",
                },
            )
        try:
            email = gateway.normalize_email(email, strict=True)
        except ValueError:
            self._audit(
                "registration_failed", user=user, reason="érvénytelen e-mail-cím"
            )
            return self._json(
                400, {"ok": False, "error": "Érvénytelen e-mail-cím."}
            )

        if gateway.TURNSTILE_ON:
            ok, why = gateway.verify_turnstile(str(captcha.get("token", "")), ip)
        else:
            ok, why = gateway.verify_pow(captcha)
        if not ok:
            self._audit(
                "registration_failed", user=user, reason=f"captcha: {why}"
            )
            return self._json(403, {"ok": False, "error": f"Captcha: {why}"})

        if self.gw.users.record(user) is not None:
            self._audit("registration_failed", user=user, reason="foglalt név")
            return self._json(
                409,
                {
                    "ok": False,
                    "error": "Ez a bejelentkezési név már foglalt.",
                    "code": "username_taken",
                },
            )
        try:
            # A jelszót és az e-mail-címet kizárólag a felhasználótároló
            # kapja meg; naplóba és auditba egyik sem kerülhet.
            self.gw.users.add(
                user,
                password,
                role=gateway.ROLE_USER,
                enabled=False,
                rules=(),
                pending=True,
                email=email,
                must_change_password=False,
            )
        except gateway.UserStoreError as exc:
            if "már létezik" in str(exc):
                self._audit(
                    "registration_failed", user=user, reason="foglalt név"
                )
                return self._json(
                    409,
                    {
                        "ok": False,
                        "error": "Ez a bejelentkezési név már foglalt.",
                        "code": "username_taken",
                    },
                )
            self._audit(
                "registration_failed",
                user=user,
                reason="a felhasználó létrehozása nem sikerült",
            )
            return self._json(400, {"ok": False, "error": str(exc)})
        self._audit("registration_requested", target=user)
        print(f"[{ip}] fiókkérés rögzítve: {user!r}", flush=True)
        self._json(
            200,
            {
                "ok": True,
                "message": "Kérelmedet rögzítettük. Az admin jóváhagyása "
                           "után beléphetsz.",
            },
        )

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

        banned = self.gw.fail2ban.banned(ip)
        if banned is not None:
            remaining = int(banned.get("remaining", 0))
            source = str(banned.get("source") or "login")
            self._audit(
                "login_failed",
                reason="fail2ban tiltás alatt",
                source=source,
                ban_until=banned.get("until", 0),
                remaining=remaining,
            )
            if source == "drop":
                error = (
                    "Ez az IP-cím fail2ban tiltás alatt áll, mert a tűzfal "
                    "gyanús hálózati forgalmat (például portvizsgálatot) "
                    "észlelt. Próbáld újra később."
                )
            else:
                error = (
                    "Ez az IP-cím fail2ban tiltás alatt áll a túl sok "
                    "sikertelen belépés miatt. Próbáld újra később."
                )
            return self._json(
                403,
                {
                    "ok": False,
                    "error": error,
                    "banned": True,
                    "ban_until": banned.get("until", 0),
                    "remaining": remaining,
                    "ban_source": source,
                    "ban_detail": banned.get("detail", ""),
                    "ban_attempts": int(banned.get("attempts", 0)),
                },
                headers={"Retry-After": str(max(1, min(remaining, 86400)))},
            )

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
            try:
                ban = self.gw.fail2ban.record_failure(ip, user)
            except fail2ban_mod.Fail2banError as exc:
                _log_fail2ban_error(ip, exc)
                ban = None
            if ban is not None:
                return self._json(
                    403,
                    {
                        "ok": False,
                        "error": (
                            "Túl sok sikertelen belépés: az IP-címedet a "
                            "tűzfal letiltotta. Próbáld újra később."
                        ),
                        "banned": True,
                        "ban_until": ban.get("until", 0),
                        "remaining": ban.get("remaining", 0),
                    },
                )
            return self._json(
                403, {"ok": False, "error": "Hibás felhasználónév vagy jelszó."}
            )

        record = self.gw.users.record(user)
        if record is not None and record.pending:
            # A helyes jelszó ellenére sem jön létre munkamenet vagy 2FA-jegy,
            # és a fail2bant sem terheljük: ez nem hibás belépési kísérlet.
            self._audit(
                "login_failed", user=user, reason="a fiók jóváhagyásra vár"
            )
            return self._json(
                403,
                {
                    "ok": False,
                    "error": "A fiók jóváhagyásra vár. Az admin jóváhagyása "
                             "után beléphetsz.",
                    "code": "pending_approval",
                    "pending": True,
                },
            )
        if record is None or not record.enabled:
            self._audit("login_failed", user=user, reason="letiltott felhasználó")
            try:
                self.gw.fail2ban.record_failure(ip, user)
            except fail2ban_mod.Fail2banError as exc:
                _log_fail2ban_error(ip, exc)
            return self._json(
                403, {"ok": False, "error": "Hibás felhasználónév vagy jelszó."}
            )

        if record.totp_required:
            fingerprint = _record_fingerprint(record)
            if not record.totp_secret:
                # Első 2FA-belépés: a titkot még nem tároltuk. A jegyhez
                # kötjük, hogy csak ugyanaz az IP és felhasználói állapot
                # fejezhesse be a regisztrációt.
                secret = gateway.generate_totp_secret()
                ticket = LOGIN_TICKETS.issue(
                    "enroll", record.name, ip, fingerprint, secret=secret
                )
                return self._json(
                    200,
                    {
                        "ok": True,
                        "totp_required": True,
                        "totp_enroll_required": True,
                        "ticket": ticket,
                        "secret": secret,
                        "otpauth_uri": gateway.build_otpauth_uri(
                            record.name, secret
                        ),
                        "issuer": gateway.TOTP_ISSUER,
                    },
                )
            ticket = LOGIN_TICKETS.issue(
                "verify", record.name, ip, fingerprint
            )
            return self._json(
                200,
                {
                    "ok": True,
                    "totp_required": True,
                    "ticket": ticket,
                    "mode": "verify",
                },
            )

        self.gw.fail2ban.record_success(ip)
        self._login_session_response(record)

    def _login_session_response(
        self,
        record: gateway.UserRecord,
        method: str | None = None,
        extra: dict | None = None,
    ) -> None:
        """A jelszó vagy a 2FA lépés utáni közös munkamenet-válasz."""
        ip = self._client_ip()
        try:
            session = self.gw.sessions.login(
                record.name, ip, role=record.role, ua=self._ua()
            )
        except gateway.FirewallError as exc:
            self._audit(
                "login_failed", user=record.name, reason=f"tűzfal hiba: {exc}"
            )
            print(
                f"[{ip}] a régi hozzáférés visszavonása nem sikerült: {exc}",
                flush=True,
            )
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
        audit_fields = {
            "user": record.name,
            "role": record.role,
            "admin": record.is_admin,
            "session": session.token[:10],
            "pending_ttl": self.gw.sessions.pending_ttl,
            "must_change_password": record.must_change_password,
        }
        if method is not None:
            audit_fields["method"] = method
        self._audit("login_success", **audit_fields)
        print(
            f"[{ip}] hitelesítve: {record.name!r}; hozzáférés-választásra vár",
            flush=True,
        )
        payload = {
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
                for rule in self.gw.effective_rules(record.name)
            ],
            "message": (
                "Sikeres belépés. Első belépésnél le kell cserélned a "
                "kezdetleges jelszavad."
                if record.must_change_password else
                "Sikeres belépés. Válaszd ki a hozzáférési szabályt "
                "és azt, mennyi ideig szeretnéd használni a hálózatot."
            ),
        }
        if extra:
            payload.update(extra)
        self._json(200, payload, headers={"Set-Cookie": cookie})

    def _totp_ban_guard(self, ip: str) -> bool:
        """A 2FA-végpontok közös fail2ban tiltás-ellenőrzése."""
        banned = self.gw.fail2ban.banned(ip)
        if banned is None:
            return False
        remaining = int(banned.get("remaining", 0))
        source = str(banned.get("source") or "login")
        self._audit(
            "login_failed",
            reason="fail2ban tiltás alatt",
            source=source,
            ban_until=banned.get("until", 0),
            remaining=remaining,
        )
        if source == "drop":
            error = (
                "Ez az IP-cím fail2ban tiltás alatt áll, mert a tűzfal "
                "gyanús hálózati forgalmat (például portvizsgálatot) "
                "észlelt. Próbáld újra később."
            )
        else:
            error = (
                "Ez az IP-cím fail2ban tiltás alatt áll a túl sok "
                "sikertelen belépés miatt. Próbáld újra később."
            )
        self._json(
            403,
            {
                "ok": False,
                "error": error,
                "banned": True,
                "ban_until": banned.get("until", 0),
                "remaining": remaining,
                "ban_source": source,
                "ban_detail": banned.get("detail", ""),
                "ban_attempts": int(banned.get("attempts", 0)),
            },
            headers={"Retry-After": str(max(1, min(remaining, 86400)))},
        )
        return True

    def _record_login_failure(self, ip: str, user: str) -> dict | None:
        try:
            return self.gw.fail2ban.record_failure(ip, user)
        except fail2ban_mod.Fail2banError as exc:
            _log_fail2ban_error(ip, exc)
            return None

    def _totp_prelude(self) -> tuple[str, dict] | None:
        """JSON, IPv4, eredet, sebességkorlát és tiltás ellenőrzése."""
        ip = self._client_ip()
        data = self._read_json()
        if data is None:
            self._audit("login_failed", reason="hibás kérés")
            self._json(
                400,
                {"ok": False, "error": "hibás kérés", "code": "bad_request"},
            )
            return None
        if not gateway.is_ipv4(ip):
            self._audit("login_failed", reason="nem IPv4 cím")
            self._json(
                400, {"ok": False, "error": "A kapu csak IPv4-címmel érhető el."}
            )
            return None
        if not self._origin_ok():
            self._audit("login_failed", reason="érvénytelen kérés-eredet")
            self._json(
                403, {"ok": False, "error": "érvénytelen kérés-eredet"}
            )
            return None
        if not self.gw.login_rate.allow(ip):
            self._audit("login_failed", reason="túl sok próbálkozás")
            self._json(
                429,
                {"ok": False, "error": "Túl sok próbálkozás. Várj egy percet."},
                headers={"Retry-After": str(gateway.RATE_WINDOW)},
            )
            return None
        if self._totp_ban_guard(ip):
            return None
        return ip, data

    @staticmethod
    def _ticket_credentials(data: dict) -> tuple[str, str] | None:
        ticket = data.get("ticket")
        code = data.get("code")
        if not isinstance(ticket, str) or not ticket:
            return None
        if not isinstance(code, str):
            return None
        code = code.strip()
        if not code:
            return None
        return ticket, code

    def _ticket_invalid(self) -> None:
        # Ugyanaz a válasz jár a hiányzó, lejárt és elhasznált jegyre is.
        self._json(
            403,
            {
                "ok": False,
                "code": "ticket_invalid",
                "error": "Érvénytelen vagy lejárt bejelentkezés. Kezdd újra.",
            },
        )

    def _totp_failure(
        self, ip: str, token: str, username: str, recovery: bool = False
    ) -> None:
        """Hibás 2FA-kód: jegypróba, fail2ban és a megfelelő hibaüzenet."""
        remaining = LOGIN_TICKETS.fail(token, ip)
        ban = self._record_login_failure(ip, username)
        if ban is not None:
            retry_after = max(1, min(int(ban.get("remaining", 0)), 86400))
            return self._json(
                403,
                {
                    "ok": False,
                    "error": (
                        "Túl sok sikertelen belépés: az IP-címedet a "
                        "tűzfal letiltotta. Próbáld újra később."
                    ),
                    "banned": True,
                    "ban_until": ban.get("until", 0),
                    "remaining": ban.get("remaining", 0),
                },
                headers={"Retry-After": str(retry_after)},
            )
        if recovery:
            code = "recovery_invalid" if remaining > 0 else "ticket_locked"
            error = (
                f"Hibás recovery kód. Még {remaining} próbálkozás."
                if remaining > 0 else
                "Túl sok hibás kód. Kezdd újra a belépést."
            )
        else:
            code = "totp_invalid" if remaining > 0 else "ticket_locked"
            error = (
                f"Hibás kód. Még {remaining} próbálkozás."
                if remaining > 0 else
                "Túl sok hibás kód. Kezdd újra a belépést."
            )
        self._json(
            403,
            {
                "ok": False,
                "code": code,
                "error": error,
                "remaining": remaining,
            },
        )

    def _login_totp(self) -> None:
        """A jelszó utáni TOTP-kód ellenőrzése és a munkamenet létrehozása."""
        prelude = self._totp_prelude()
        if prelude is None:
            return
        ip, data = prelude
        credentials = self._ticket_credentials(data)
        if credentials is None:
            return self._json(
                400,
                {"ok": False, "error": "hibás kérés", "code": "bad_request"},
            )
        token, code = credentials
        ticket = LOGIN_TICKETS.peek(token, ip)
        if ticket is None:
            return self._ticket_invalid()
        if ticket.purpose != "verify":
            return self._ticket_invalid()
        # A felhasználót kizárólag a szerveroldali jegy választja ki.
        record = self.gw.users.record(ticket.username)
        if (
            record is None
            or not record.enabled
            or record.pending
            or not record.totp_required
            or not record.totp_secret
            or not hmac.compare_digest(
                _record_fingerprint(record), ticket.fingerprint
            )
        ):
            LOGIN_TICKETS.consume(token, ip)
            return self._ticket_invalid()
        if not self.gw.users.verify_totp(ticket.username, code):
            return self._totp_failure(ip, token, ticket.username)
        if LOGIN_TICKETS.consume(token, ip) is None:
            return self._ticket_invalid()
        try:
            self.gw.fail2ban.record_success(ip)
        except fail2ban_mod.Fail2banError as exc:
            _log_fail2ban_error(ip, exc)
        self._login_session_response(record, method="totp")

    def _login_totp_enroll(self) -> None:
        """Az első 2FA-beállítás: titok megerősítése és recovery kódok."""
        prelude = self._totp_prelude()
        if prelude is None:
            return
        ip, data = prelude
        credentials = self._ticket_credentials(data)
        if credentials is None:
            return self._json(
                400,
                {"ok": False, "error": "hibás kérés", "code": "bad_request"},
            )
        token, code = credentials
        ticket = LOGIN_TICKETS.peek(token, ip)
        if ticket is None:
            return self._ticket_invalid()
        if ticket.purpose != "enroll":
            return self._ticket_invalid()
        record = self.gw.users.record(ticket.username)
        if (
            record is None
            or not record.enabled
            or record.pending
            or not record.totp_required
            or record.totp_secret
            or not hmac.compare_digest(
                _record_fingerprint(record), ticket.fingerprint
            )
        ):
            LOGIN_TICKETS.consume(token, ip)
            return self._ticket_invalid()
        matched = gateway.totp_match(ticket.secret, code)
        if matched is None:
            return self._totp_failure(ip, token, ticket.username)
        if LOGIN_TICKETS.consume(token, ip) is None:
            return self._ticket_invalid()
        codes = gateway.generate_recovery_codes(10)
        hashes = [gateway.hash_recovery_code(value) for value in codes]
        if not self.gw.users.enroll_totp(
            ticket.username, ticket.secret, hashes, last_step=matched
        ):
            return self._json(
                400,
                {
                    "ok": False,
                    "code": "enroll_failed",
                    "error": (
                        "A kétfaktoros beállítás nem sikerült. "
                        "Próbáld újra."
                    ),
                },
            )
        record = self.gw.users.record(ticket.username)
        if record is None or not record.enabled or record.pending:
            return self._json(
                400,
                {
                    "ok": False,
                    "code": "enroll_failed",
                    "error": (
                        "A kétfaktoros beállítás nem sikerült. "
                        "Próbáld újra."
                    ),
                },
            )
        try:
            self.gw.fail2ban.record_success(ip)
        except fail2ban_mod.Fail2banError as exc:
            _log_fail2ban_error(ip, exc)
        self._audit(
            "totp_enrolled",
            target=record.name,
            user=record.name,
            recovery_codes=len(codes),
        )
        # A nyílt recovery kódok kizárólag ebben a válaszban jelennek meg.
        self._login_session_response(
            record, method="totp_enroll", extra={"recovery_codes": codes}
        )

    def _login_recovery(self) -> None:
        """Belépés egy egyszer használatos recovery kóddal."""
        prelude = self._totp_prelude()
        if prelude is None:
            return
        ip, data = prelude
        credentials = self._ticket_credentials(data)
        if credentials is None:
            return self._json(
                400,
                {"ok": False, "error": "hibás kérés", "code": "bad_request"},
            )
        token, code = credentials
        ticket = LOGIN_TICKETS.peek(token, ip)
        if ticket is None:
            return self._ticket_invalid()
        if ticket.purpose != "verify":
            return self._ticket_invalid()
        record = self.gw.users.record(ticket.username)
        if (
            record is None
            or not record.enabled
            or record.pending
            or not record.totp_required
            or not record.totp_secret
            or not hmac.compare_digest(
                _record_fingerprint(record), ticket.fingerprint
            )
        ):
            LOGIN_TICKETS.consume(token, ip)
            return self._ticket_invalid()
        if not self.gw.users.verify_recovery(ticket.username, code):
            return self._totp_failure(
                ip, token, ticket.username, recovery=True
            )
        if LOGIN_TICKETS.consume(token, ip) is None:
            return self._ticket_invalid()
        try:
            self.gw.fail2ban.record_success(ip)
        except fail2ban_mod.Fail2banError as exc:
            _log_fail2ban_error(ip, exc)
        self._audit(
            "totp_recovery_used",
            target=record.name,
            user=record.name,
            method="recovery",
        )
        self._login_session_response(record, method="recovery")

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
        if record is None or not record.enabled or record.pending:
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
        if record is None or not record.enabled or record.pending:
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
        session = self._admin_guard()
        if session is None:
            return
        action = str(data.get("action", "")).strip()
        message = ""
        try:
            if action == "create":
                self._admin_user_create(data)
            elif action == "update":
                self._admin_user_update(data)
            elif action == "delete":
                self._admin_user_delete(data)
            elif action == "approve":
                self._admin_user_approve(data)
                message = "A fiókkérés jóváhagyva."
            elif action == "reject":
                self._admin_user_reject(data)
                message = "A fiókkérés elutasítva."
            elif action == "totp_reset":
                self._admin_user_totp_reset(data, session)
                # A reset-ág maga küldi a választ; ne legyen második.
                return
            else:
                raise gateway.UserStoreError("ismeretlen művelet")
        except (gateway.UserStoreError, gateway.GroupStoreError,
                gateway.RuleStoreError, gateway.AccessError, ValueError) as exc:
            self._admin_action_error(f"user_{action}", exc)
            return self._json(400, {"ok": False, "error": str(exc)})
        payload = self._admin_state()
        if message:
            payload["message"] = message
        self._json(200, payload)

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
        totp_required = data.get("totp_required", False)
        if not isinstance(totp_required, bool):
            raise gateway.UserStoreError("érvénytelen totp_required")
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
            if totp_required:
                self.gw.users.set_totp_required(name, True)
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
            totp_required=totp_required,
        )

    def _admin_user_approve(self, data: dict) -> None:
        """Fiókkérés jóváhagyása: szabály és csoport nélkül engedélyezés."""
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise gateway.UserStoreError("hiányzó felhasználónév")
        name = name.strip()
        session = self._session()
        with self.gw.admin_lock:
            record = self.gw.users.record(name)
            if record is None or not record.pending:
                raise gateway.UserStoreError(
                    "ez a felhasználó nem jóváhagyásra váró kérelem"
                )
            if not self.gw.users.approve_user(name):
                raise gateway.UserStoreError(
                    "ez a felhasználó nem jóváhagyásra váró kérelem"
                )
            self._audit(
                "registration_approved",
                target=name,
                user=session.user if session is not None else "",
            )

    def _admin_user_reject(self, data: dict) -> None:
        """Fiókkérés elutasítása: a kérelem és minden maradéka törlődik."""
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise gateway.UserStoreError("hiányzó felhasználónév")
        name = name.strip()
        session = self._session()
        with self.gw.admin_lock:
            record = self.gw.users.record(name)
            if record is None:
                raise gateway.UserStoreError(f"nincs ilyen felhasználó: {name}")
            if not record.pending:
                raise gateway.UserStoreError(
                    "csak jóváhagyásra váró kérelem utasítható el"
                )
            if not self.gw.users.reject_user(name):
                raise gateway.UserStoreError(
                    "csak jóváhagyásra váró kérelem utasítható el"
                )
            self.gw.groups.remove_member_everywhere(name)
            revoked = self.gw.sessions.revoke_user(name)
            tickets = LOGIN_TICKETS.revoke_user(name)
            self._audit(
                "registration_rejected",
                target=name,
                user=session.user if session is not None else "",
                sessions_revoked=revoked,
                tickets_revoked=tickets,
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
        if record.pending:
            # A jóváhagyásra váró kérelem nem szerkeszthető: így nem kerülhet
            # rá szabály vagy csoport a jóváhagyás előtt.
            raise gateway.UserStoreError(
                "a jóváhagyásra váró fiók nem szerkeszthető; használd a "
                "jóváhagyás vagy az elutasítás műveletet"
            )
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
        totp_required = data.get("totp_required")
        if "totp_required" in data and not isinstance(totp_required, bool):
            raise gateway.UserStoreError("érvénytelen totp_required")
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
            must_change_password=must_change, totp_required=totp_required,
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
            totp_required=(
                (updated.totp_required if updated is not None else totp_required)
                if totp_required is not None else "(változatlan)"
            ),
            sessions_revoked=revoked,
        )

    def _admin_user_totp_reset(
        self, data: dict, session: gateway.Session
    ) -> None:
        """A 2FA-titok és recovery kódok törlése; a kötelező jelző marad."""
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise gateway.UserStoreError("hiányzó felhasználónév")
        name = name.strip()
        with self.gw.admin_lock:
            if self.gw.users.record(name) is None:
                raise gateway.UserStoreError(f"nincs ilyen felhasználó: {name}")
            if not self.gw.users.reset_totp(name):
                raise gateway.UserStoreError(f"nincs ilyen felhasználó: {name}")
            revoked = self.gw.sessions.revoke_user(name, reason="totp_reset")
            tickets = LOGIN_TICKETS.revoke_user(name)
            self._audit(
                "admin_totp_reset",
                target=name,
                user=session.user,
                sessions_revoked=revoked,
                tickets_revoked=tickets,
            )
        self._json(
            200,
            {
                **self._admin_state(),
                "message": f"{name} 2FA beállítása alaphelyzetbe állítva.",
            },
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

    p_totp = sub.add_parser(
        "totp-reset", help="kétfaktoros azonosítás alaphelyzetbe állítása"
    )
    p_totp.add_argument("name")

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
        elif args.action == "totp-reset":
            if store.reset_totp(args.name):
                print(f"2FA alaphelyzetbe állítva: {args.name}")
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


def _fail2ban_cli(argv: list[str]) -> int:
    """Fail2ban kezelése a parancssorból (kizárás esetén vészmegoldás)."""
    parser = argparse.ArgumentParser(
        prog="server.py fail2ban",
        description="A fail2ban tiltáslista kezelése.",
    )
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list", help="tiltott IP-k listája")
    p_ban = sub.add_parser("ban", help="IP-cím letiltása")
    p_ban.add_argument("ip")
    p_ban.add_argument(
        "--seconds", type=int, default=0,
        help="a tiltás hossza másodpercben (alapértelmezés: a beállított érték)",
    )
    p_unban = sub.add_parser("unban", help="egy IP-cím feloldása")
    p_unban.add_argument("ip")
    sub.add_parser("unban-all", help="minden tiltás feloldása")

    args = parser.parse_args(argv)
    manager = fail2ban_mod.Fail2ban(
        gateway.Firewall(), audit=gateway.AuditLog()
    )
    try:
        if args.action == "list":
            snapshot = manager.snapshot()
            state = "aktív" if snapshot["enabled"] else "kikapcsolva"
            drop_state = "aktív" if snapshot["drop_enabled"] else "kikapcsolva"
            print(
                f"Fail2ban: {state}; küszöb: {snapshot['max_attempts']} "
                f"próbálkozás / {snapshot['window_seconds']} mp; "
                f"tiltás: {snapshot['ban_seconds']} mp"
            )
            print(
                f"Drop-alapú tiltás: {drop_state}; küszöb: "
                f"{snapshot['drop_max']} csomag vagy "
                f"{snapshot['drop_ports']} különböző port / "
                f"{snapshot['drop_window_seconds']} mp"
            )
            if snapshot["error"]:
                print(f"FIGYELEM: {snapshot['error']}")
            bans = snapshot["bans"]
            if not bans:
                print("Nincs tiltott IP.")
                return 0
            print(f"Tiltott IP-k ({len(bans)}):")
            for ban in bans:
                source = ban.get("source") or (
                    "manual" if ban["manual"] else "login"
                )
                kind = {
                    "manual": "kézi",
                    "drop": "drop",
                    "login": "login",
                }.get(source, source)
                detail = ban.get("detail") or ""
                if source == "drop" and detail:
                    kind = f"drop/{detail}"
                print(
                    f"  {ban['ip']:<15}  hátralévő: {ban['remaining']:>6} mp  "
                    f"{kind:<16}  {ban['attempts']} esemény  "
                    f"user={ban['user'] or '-'}"
                )
            return 0
        if args.action == "ban":
            ban = manager.ban(args.ip, args.seconds, manual=True, user="cli")
            print(
                f"Letiltva: {ban['ip']} ({ban['remaining']} mp)"
            )
            return 0
        if args.action == "unban":
            if manager.unban(args.ip):
                print(f"Feloldva: {args.ip}")
            else:
                print(f"Nem volt letiltva: {args.ip}")
            return 0
        if args.action == "unban-all":
            print(f"Feloldva: {manager.unban_all()} tiltás")
            return 0
    except fail2ban_mod.Fail2banError as exc:
        print(f"hiba: {exc}", file=sys.stderr)
        return 1
    return 2


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
    if argv[0] == "fail2ban":
        return _fail2ban_cli(argv[1:])
    if argv[0] == "check-firewall":
        ok, why = gateway.Firewall().healthy()
        print("rendben" if ok else f"hiba: {why}")
        return 0 if ok else 1
    print(
        "Használat: server.py [serve | user ... | fail2ban ... | check-firewall]",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
