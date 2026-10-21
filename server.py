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
import html
import json
import os
import secrets
import signal
import socket
import socketserver
import stat
import struct
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
    "unauthorized.png": ("image/png", "public, max-age=3600"),
}

# A proxy-végpontokat csak a hoston futó Caddy hívhatja (a nyers socket
# peer, nem az X-Forwarded-For alapján; lásd _peer_ip).
PROXY_LOOPBACK = ("127.0.0.1", "::1")

PROXY_UNAUTHORIZED_PAGE = """<!doctype html>
<html lang="hu"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nincs hozzáférés</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:system-ui,sans-serif;background:#111418;color:#e8eaed;text-align:center}
main{max-width:420px;padding:24px}
img{width:min(320px,80vw);height:auto}
h1{font-size:1.5rem;margin:16px 0 8px}
p{color:#b0b6bd;line-height:1.5}
a{display:inline-block;margin-top:12px;padding:10px 22px;border-radius:8px;
background:#2f6fde;color:#fff;text-decoration:none;font-weight:600}
</style></head><body><main>
<img src="/__dropjak/unauthorized.png" alt="">
<h1>Nincs hozzáférés</h1>
<p>Ez a szolgáltatás csak a Dropjak tűzfalon történő bejelentkezés után érhető el.</p>
<a href="{login}">Bejelentkezés</a>
</main></body></html>
"""

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; "
    "frame-src https://challenges.cloudflare.com; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self' https://challenges.cloudflare.com; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)

# Egy munkamenet legfeljebb ennyi szabályt választhat egyszerre. A korlát
# az audit- és a válaszméretet is kordában tartja.
MAX_SESSION_RULES = 16


def _log_fail2ban_error(
    ip: str, exc: Exception, audit=None, operation: str = "record"
) -> None:
    print(f"[{ip}] fail2ban: a tiltás nem sikerült: {exc}", flush=True)
    if audit is None:
        return
    try:
        audit.write(
            "fail2ban_error",
            ip=ip,
            operation=operation,
            reason=str(exc),
        )
    except Exception as log_exc:  # a naplózás ne blokkolja a belépést
        print(f"[napló] fail2ban_error írása nem sikerült: {log_exc}", flush=True)


# --------------------------------------------------- kétfaktoros belépőjegyek

LOGIN_TICKET_TTL = 300
LOGIN_TICKET_MAX_ATTEMPTS = 5
# A jegy a felhasználói rekord pillanatképéhez kötődik. A só folyamatonként
# új, így a memóriában tárolt ujjlenyomat külsőleg nem visszafejthető.
_TICKET_FP_SALT = secrets.token_bytes(32)


def _ticket_hash(token: str) -> str:
    """A jegy nem visszafejthető, 12 karakteres hivatkozása a naplóhoz.

    A nyers jegy (és ezzel a belépés folytatásához szükséges titok) soha nem
    kerülhet az auditnaplóba; csak ez a SHA-256-kivonat első 12 karaktere.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


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
        self.audit = None
        # A lejárt vagy elhasznált jegyek elutasítási okát rövid ideig
        # megőrizzük, hogy egy későbbi kérés pontos indokot kaphasson. Ez
        # kizárólag memóriabeli adat; a token soha nem kerül a naplóba.
        self._tombstones: dict[str, tuple[str, float]] = {}
        self._tombstone_grace = max(60.0, float(self._ttl))
        self._tombstone_limit = 4096

    @property
    def ttl(self) -> int:
        return self._ttl

    def set_audit(self, audit) -> None:
        """Az auditnapló utólagos bekötése (az induló folyamatban)."""
        self.audit = audit

    def _write_audit(self, event: str, **fields) -> None:
        """Nem kötelező naplóbejegyzés; hiba esetén sem blokkol."""
        if self.audit is None:
            return
        try:
            self.audit.write(event, **fields)
        except Exception as exc:
            print(f"[napló] {event} írása nem sikerült: {exc}", flush=True)

    def _tombstone_locked(self, token: str, reason: str, now: float) -> None:
        self._tombstones[token] = (reason, now + self._tombstone_grace)
        if len(self._tombstones) > self._tombstone_limit:
            self._prune_tombstones_locked(now)
            while len(self._tombstones) > self._tombstone_limit:
                self._tombstones.pop(next(iter(self._tombstones)))

    def _prune_tombstones_locked(self, now: float) -> None:
        for token, (_, keep_until) in list(self._tombstones.items()):
            if keep_until <= now:
                del self._tombstones[token]

    def _tombstone_reason_locked(self, token: str, now: float) -> str:
        entry = self._tombstones.get(token)
        if entry is None:
            return ""
        reason, keep_until = entry
        if keep_until <= now:
            del self._tombstones[token]
            return ""
        return reason

    def _purge_locked(self, now: float | None = None) -> None:
        now = self._clock() if now is None else now
        expired = [
            (token, ticket)
            for token, ticket in self._tickets.items()
            if ticket.expires_at <= now
        ]
        for token, ticket in expired:
            del self._tickets[token]
            self._tombstone_locked(token, "expired", now)
        self._prune_tombstones_locked(now)
        # A naplóírás a tár zárja alatt történik; az AuditLog soha nem nyúl
        # vissza a jégytárhoz, így nem alakulhat ki holtpont.
        for token, ticket in expired:
            self._write_audit(
                "totp_ticket_expired",
                user=ticket.username,
                ip=ticket.ip,
                purpose=ticket.purpose,
                ticket_hash=_ticket_hash(token),
                attempts=ticket.attempts,
                age=max(
                    0, int(now - (ticket.expires_at - self._ttl))
                ),
                ttl=self._ttl,
                reason="expired",
                severity="info" if ticket.attempts == 0 else "warn",
            )

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

    def inspect(self, token: str, ip: str) -> tuple[LoginTicket | None, str]:
        """Nem fogyasztó ellenőrzés a pontos elutasítási okkal.

        Az érvényes jegyet és üres okot ad vissza; egyébként (None, ok),
        ahol az ok a naplózáshoz használható: ``unknown``, ``expired``,
        ``already_consumed``, ``too_many_attempts``, ``ip_mismatch`` vagy
        ``user_state_changed``.
        """
        if not token:
            return None, "bad_request"
        with self._lock:
            now = self._clock()
            self._purge_locked(now)
            ticket = self._tickets.get(token)
            if ticket is None:
                return None, (
                    self._tombstone_reason_locked(token, now) or "unknown"
                )
            if ticket.ip != ip:
                return None, "ip_mismatch"
            if ticket.attempts >= self._max_attempts:
                return None, "too_many_attempts"
            return ticket, ""

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
            self._tombstone_locked(token, "already_consumed", now)
            return ticket

    def fail_with_status(
        self, token: str, ip: str
    ) -> tuple[int, bool, int, bool]:
        """Sikertelen próba rögzítése részletes állapottal.

        Visszatérés: ``(hátralévő, most_záródott_le, próbák, létezett)``.
        A ``fail()`` régi, egész számos visszatérési értéke változatlanul
        megmarad a meglévő hívók és tesztek számára.
        """
        with self._lock:
            now = self._clock()
            self._purge_locked(now)
            ticket = self._tickets.get(token)
            if ticket is None or ticket.ip != ip:
                return 0, False, 0, False
            ticket.attempts += 1
            if ticket.attempts >= self._max_attempts:
                del self._tickets[token]
                self._tombstone_locked(token, "too_many_attempts", now)
                return 0, True, ticket.attempts, True
            return (
                self._max_attempts - ticket.attempts,
                False,
                ticket.attempts,
                True,
            )

    def fail(self, token: str, ip: str) -> int:
        """Sikertelen próba rögzítése; a hátralévő próbák száma (0 = nincs)."""
        return self.fail_with_status(token, ip)[0]

    def revoke_user(self, username: str, reason: str = "") -> int:
        """A felhasználó összes függő jegyének törlése.

        Nem üres ``reason`` esetén összesített auditbejegyzés is készül
        (admin elutasítás, letiltás, törlés vagy 2FA-reset).
        """
        with self._lock:
            now = self._clock()
            self._purge_locked(now)
            tokens = [
                token
                for token, ticket in self._tickets.items()
                if ticket.username == username
            ]
            for token in tokens:
                del self._tickets[token]
                self._tombstone_locked(token, "user_state_changed", now)
            count = len(tokens)
        if reason:
            self._write_audit(
                "totp_tickets_revoked",
                target=username,
                count=count,
                reason=reason,
            )
        return count

    def revoke_all(self, reason: str = "") -> int:
        """Minden jegy eldobása; nem üres ok esetén auditbejegyzéssel."""
        with self._lock:
            count = len(self._tickets)
            self._tickets.clear()
            self._tombstones.clear()
        if reason:
            self._write_audit(
                "totp_tickets_discarded", count=count, reason=reason
            )
        return count

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


def _access_rule_ids(data: dict) -> tuple[list[str], str]:
    """A /api/access kérés szabályválasztásának értelmezése.

    Visszatérés: (szabály-azonosítók, hibaüzenet). Az új ``rules`` lista
    elsőbbséget élvez a régi ``rule`` mezővel szemben. Az ismétlődő
    azonosítókat az első előfordulás sorrendjében vonjuk össze, így a
    hosszkorlát valóban az egyedi szabályokat számolja.
    """
    if "rules" in data:
        raw = data.get("rules")
        if not isinstance(raw, list):
            return [], "a szabályok listája kötelező"
        selected: list[str] = []
        seen: set[str] = set()
        for item in raw:
            if not isinstance(item, str) or not item.strip():
                return [], "érvénytelen szabálylista"
            rule_id = item.strip()
            if rule_id in seen:
                continue
            seen.add(rule_id)
            selected.append(rule_id)
        if not selected:
            return [], "válassz legalább egy szabályt"
        if len(selected) > MAX_SESSION_RULES:
            return [], (
                f"egyszerre legfeljebb {MAX_SESSION_RULES} szabály "
                "választható"
            )
        return selected, ""
    rule_id = data.get("rule")
    if not isinstance(rule_id, str):
        return [], "hiányzó szabály vagy időtartam"
    return [rule_id], ""


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

    def _peer_ip(self) -> str:
        """A nyers socket peer (a Caddy mögött 127.0.0.1)."""
        try:
            return gateway.normalize_ip(self.client_address[0])
        except ValueError:
            return str(self.client_address[0])

    def _client_ip(self) -> str:
        # Bizalmi határ: X-Forwarded-For-t csak loopback peertől (a hoston
        # futó Caddytől) fogadunk el. A Caddy reverse_proxy a kívülről
        # érkező XFF-et eldobja, és a valódi távoli címre állítja, így az
        # utolsó elem nem hamisítható. Idegen peer fejlécét figyelmen kívül
        # hagyjuk; érvénytelen értéknél a loopback peer marad.
        peer = self._peer_ip()
        headers = getattr(self, "headers", None)
        forwarded = headers.get("X-Forwarded-For") if headers else None
        if peer in PROXY_LOOPBACK and forwarded:
            try:
                return gateway.normalize_ip(forwarded.split(",")[-1])
            except ValueError:
                pass
        return peer

    def _via_proxy(self) -> bool:
        """A kérés a Caddyn át, egy gyökérdomain HTTPS-portáljára jött-e."""
        if self._peer_ip() not in PROXY_LOOPBACK:
            return False
        host = (self.headers.get("Host") or "").strip().lower()
        return host.partition(":")[0] in self.gw.settings.snapshot().get(
            "proxy_domains", []
        )

    def _cookie_secure(self) -> bool:
        return gateway.COOKIE_SECURE or self._via_proxy()

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
        if name == "index.html":
            body = body.replace(
                b"__VERSION__", gateway.APP_VERSION.encode("ascii", "replace")
            )
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
        # Védelem mélységben: egy tiltott IP-cím a már meglévő munkamenetét
        # sem használhatja a védett végpontokon. Itt szándékosan nem
        # vonjuk vissza a munkamenetet (azt a belépési/hozzáférési utak
        # teszik meg); a tiltott kliens egyszerűen nem hitelesített.
        ip = self._client_ip()
        if self.gw.fail2ban.banned(ip) is not None:
            return None
        return self.gw.sessions.validate(self._cookie_token(), ip)

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
            ended = self.gw.sessions.terminate(session.sid, reason="revoked")
            if ended is None:
                ended = session
            self._audit(
                "session_ended",
                user=ended.user,
                sid=ended.sid,
                ip=ended.ip,
                reason="no_longer_admin",
                authorized=ended.authorized,
                rule=ended.rule,
            )
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
            "rules": [
                self._rule_payload(rule) for rule in self.gw.rules.all_rules()
            ],
            "limits": self._limits(),
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
            if value == gateway.LEGACY_ADMIN_RULE_ID:
                raise gateway.RuleStoreError(
                    "ez egy fenntartott, régi azonosító, nem rendelhető hozzá"
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
        # A gyökérdomaineken a Caddy HTTPS-en a portált szolgálja ki.
        if not gateway.PORTAL_URL or self._via_proxy():
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
        if path.startswith("/api/proxy/"):
            return self._proxy_api(path)
        if path.startswith("/api/"):
            return self._json(404, {"ok": False, "error": "ismeretlen végpont"})

        # Captive portal: idegen Hosttal érkező HTTP kérést a kapu saját
        # címére irányítjuk, hogy a süti és az állapot egy helyen legyen.
        if not self._portal_host_matches():
            self._audit(
                "portal_host_redirect",
                host=(self.headers.get("Host") or "")[:200],
                target=gateway.PORTAL_URL,
            )
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

    # -- Caddy aldomain-proxy (csak loopbackről) ------------------------------

    def _proxy_target(self, host: str):
        """A host proxy-célja ("root", a bejegyzés vagy None) és gyökere."""
        settings = self.gw.settings.snapshot()
        if host and host in settings.get("proxy_domains", []):
            return "root", host
        for route in settings.get("proxy_routes", []):
            if route["enabled"] and host == f"{route['name']}.{route['root']}":
                return route, route["root"]
        return None, ""

    def _proxy_api(self, path: str) -> None:
        # A Caddy minden proxyzott kérésnél hívja: szándékosan nincs audit és
        # fail2ban-számlálás. Idegen peer semmit nem tudhat meg.
        if self._peer_ip() not in PROXY_LOOPBACK:
            return self._send(404, b"", "text/plain; charset=utf-8")
        if path == "/api/proxy/unauthorized.png":
            return self._static("unauthorized.png")
        if path == "/api/proxy/ask":
            # On-demand TLS: tanúsítvány csak a beállított nevekre kérhető.
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            domain = (query.get("domain") or [""])[0].strip().lower()
            target, _ = self._proxy_target(domain)
            code = 200 if target is not None else 404
            return self._send(code, b"", "text/plain; charset=utf-8")
        if path != "/api/proxy/auth":
            return self._send(404, b"", "text/plain; charset=utf-8")
        host = (
            self.headers.get("X-Forwarded-Host")
            or self.headers.get("Host") or ""
        )
        host = host.strip().lower().partition(":")[0]
        target, root = self._proxy_target(host)
        if target is None:
            return self._send(404, b"", "text/plain; charset=utf-8")
        login = f"https://{root}/"
        if target == "root":
            # A gyökérdomain maga a portál. A Caddyn át a proxy-végpontok
            # nem érhetők el (ott a peer is loopback lenne).
            uri = self.headers.get("X-Forwarded-Uri") or "/"
            if urllib.parse.urlsplit(uri).path.startswith("/api/proxy/"):
                return self._send(404, b"", "text/plain; charset=utf-8")
            return self._send(
                200, b"", "text/plain; charset=utf-8",
                headers={"X-Dropjak-Upstream": f"127.0.0.1:{gateway.PORT}"},
            )
        # A Caddy az X-Forwarded-For-t a valódi kliens IP-re állítja (nem
        # bízik a bejövő értékben); az utolsó elem a közvetlen kliens.
        forwarded = (self.headers.get("X-Forwarded-For") or "").split(",")[-1]
        try:
            ip = gateway.normalize_ip(forwarded)
        except ValueError:
            ip = ""
        # Publikus bejegyzés: bárki, akit a fail2ban nem tilt.
        if (
            ip
            and self.gw.fail2ban.banned(ip) is None
            and (
                target["visibility"] == "public"
                or self.gw.sessions.allows_domain(ip, host)
            )
        ):
            # A forward_auth csak 2xx esetén enged tovább, és ekkor mindig
            # mi adjuk a célt: a kliens által küldött fejléc nem irányíthat.
            upstream = (
                target["ip"] if target["type"] == "forward" else "127.0.0.1"
            )
            return self._send(
                200, b"", "text/plain; charset=utf-8",
                headers={
                    "X-Dropjak-Upstream": f"{upstream}:{target['port']}"
                },
            )
        page = PROXY_UNAUTHORIZED_PAGE.replace(
            "{login}", html.escape(login, quote=True)
        )
        return self._send(401, page.encode("utf-8"), "text/html; charset=utf-8")

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
        return self._with_hosts(rule.public())

    def _with_hosts(self, payload: dict) -> dict:
        """A domain-választás teljes hostnevei a megjelenítéshez.

        A ``ports_label`` domain szabálynál a hostneveket mutatja (portos
        résszel együtt ``·`` elválasztással), a ``hosts`` a teljes neveket.
        """
        domains = payload.get("domains") or []
        if not domains:
            return payload
        hosts = list(domains)
        label = "Domain: " + ", ".join(hosts)
        if any(payload.get(key) for key in ("tcp", "udp", "icmp", "full")):
            label = f"{payload.get('ports_label', '')} · {label}"
        payload["ports_label"] = label
        payload["hosts"] = hosts
        return payload

    def _selection_payload(self, session: gateway.Session) -> dict:
        """Az engedélyezett munkamenet szabályválasztásának közös mezői.

        A ``selected_rules``/``selected_rule_labels``/``grants`` a teljes,
        több szabályos választást írja le. A ``rule``/``rule_label``/
        ``grant`` mezők a régi kliensek számára az első választást tükrözik.
        """
        selected_rules = (
            list(session.rules)
            if session.rules
            else ([session.rule] if session.rule else [])
        )
        selected_labels = [part.label for part in session.selections()]
        if not selected_labels and session.rule:
            selected_labels = [session.rule_label]
        domains = list(dict.fromkeys(
            name for part in session.selections() for name in part.domains
        ))
        return {
            "selected_rules": selected_rules,
            "selected_rule_labels": selected_labels,
            "grants": [part.public() for part in session.grants],
            "hosts": self._with_hosts({"domains": domains}).get("hosts", []),
        }

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
        settings = self.gw.settings.snapshot()
        registration_enabled = bool(
            settings.get("registration_enabled", False)
        )
        # A tűzfal neve nyilvános: a belépőoldal fejléce és a böngésző
        # címe mutatja. A beállításfájl hibaszövegét nem adjuk ki.
        site_name = settings.get("site_name", "")
        # Védelem mélységben: tiltott IP a meglévő munkamenetével sem
        # kérdezheti le a védett állapotot. A válasz a belépő- és
        # hozzáférés-végpontokkal közös tiltásforma, munkamenet-adat nélkül.
        banned = self.gw.fail2ban.banned(self._client_ip())
        if banned is not None:
            payload, headers = self._ban_reply(banned)
            payload["authenticated"] = False
            payload["registration_enabled"] = registration_enabled
            payload["site_name"] = site_name
            payload["version"] = gateway.APP_VERSION
            self._json(403, payload, headers=headers)
            return
        session = self._session()
        if session is None:
            # A legutóbbi lezárás okát is megadjuk, hogy a felület meg tudja
            # mondani, miért esett ki a felhasználó a countdown közben.
            last_end = self.gw.sessions.last_end(self._client_ip())
            payload = {
                "ok": True,
                "authenticated": False,
                "registration_enabled": registration_enabled,
                "site_name": site_name,
                "version": gateway.APP_VERSION,
            }
            if last_end is not None:
                payload["last_end"] = last_end
            payload.update(self._ban_fields())
            self._json(200, payload)
            return
        record = self.gw.users.record(session.user)
        if record is None or not record.enabled or record.pending:
            end_reason = "disabled" if record is not None else "revoked"
            ended = self.gw.sessions.logout(
                session.token, session.ip, reason=end_reason
            )
            if ended is not None:
                self._audit(
                    "session_ended",
                    user=ended.user,
                    sid=ended.sid,
                    ip=ended.ip,
                    reason=end_reason,
                    authorized=ended.authorized,
                    rule=ended.rule,
                )
            last_end = self.gw.sessions.last_end(self._client_ip())
            payload = {
                "ok": True,
                "authenticated": False,
                "registration_enabled": registration_enabled,
                "site_name": site_name,
                "version": gateway.APP_VERSION,
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
            "site_name": site_name,
            "version": gateway.APP_VERSION,
        }
        if session.authorized:
            payload["rule"] = session.rule
            payload["rule_label"] = session.rule_label
            payload["grant"] = session.ports.public()
            payload.update(self._selection_payload(session))
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
            self._with_hosts(row)
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
            self._audit(
                "firewall_error", operation="snapshot", reason=str(exc)
            )
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
            self._audit(
                "firewall_error", operation="ruleset", reason=str(exc)
            )
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
            self._admin_request_rejected(
                "invalid_origin", user=session.user
            )
            self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
            return
        data = self._read_json()
        if data is None:
            self._admin_request_rejected("bad_request", user=session.user)
            return
        if str(data.get("action", "")).strip() != "terminate":
            self._audit(
                "admin_session_terminate_failed",
                user=session.user,
                target="",
                reason="unknown_action",
            )
            self._json(400, {"ok": False, "error": "ismeretlen művelet"})
            return
        sid = data.get("id")
        if not isinstance(sid, str) or not sid.strip():
            self._audit(
                "admin_session_terminate_failed",
                user=session.user,
                target="",
                reason="missing_id",
            )
            self._json(400, {"ok": False, "error": "hiányzó munkamenet-azonosító"})
            return
        sid = sid.strip()
        if sid == session.sid:
            self._audit(
                "admin_session_terminate_failed",
                user=session.user,
                target=sid,
                reason="self_terminate",
            )
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
            self._audit(
                "admin_session_terminate_failed",
                user=session.user,
                target=sid,
                reason="not_found",
            )
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
        session = self._admin_guard()
        if session is None:
            return
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)

        def first(name: str) -> str:
            return (query.get(name) or [""])[0]

        try:
            limit = int((query.get("limit") or ["500"])[0])
        except ValueError:
            limit = 500
        try:
            before_raw = (query.get("before") or [""])[0]
            before = float(before_raw) if before_raw else None
        except ValueError:
            before = None
        event_filter = first("event")
        user_filter = first("user")
        q_filter = first("q")
        severity_filter = first("severity").strip().lower()
        rows = self.gw.audit.read(
            limit=limit,
            event=event_filter,
            user=user_filter,
            q=q_filter,
            before=before,
            severity=severity_filter,
        )
        manual = first("manual").strip().lower() in ("1", "true", "yes")
        if manual:
            # Csak a felhasználó által indított lekérés kerül a naplóba; az
            # öt másodperces automatikus frissítés nem.
            self._audit(
                "admin_logs_read",
                user=session.user,
                limit=limit,
                event_filter=event_filter[:120],
                user_filter=user_filter[:120],
                severity_filter=severity_filter[:16],
                q_present=bool(q_filter),
                before_present=before is not None,
                count=len(rows),
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
            self._admin_request_rejected(
                "invalid_origin", user=session.user
            )
            self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
            return
        data = self._read_json()
        if data is None:
            self._admin_request_rejected("bad_request", user=session.user)
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        action = str(data.get("action", "")).strip().lower()
        if action == "registration_enabled":
            # Portálkezelés: nem megy át az nftables-előkészítésen és
            # -alkalmazáson, ezért külön ágban kezeljük.
            value = data.get("enabled", data.get("registration_enabled"))
            if not isinstance(value, bool):
                self._admin_request_rejected(
                    "invalid_registration_flag", user=session.user
                )
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
        if action == "site_name":
            # A tűzfal neve csak megjelenítési adat: nem megy át az
            # nftables-előkészítésen és -alkalmazáson.
            value = data.get("name", data.get("site_name"))
            if not isinstance(value, str):
                self._admin_request_rejected(
                    "invalid_site_name", user=session.user
                )
                self._json(
                    400,
                    {
                        "ok": False,
                        "error": "a tűzfal neve szöveg kell",
                    },
                )
                return
            try:
                with self.gw.admin_lock:
                    stored = self.gw.settings.set_site_name(value)
                    stored_name = str(stored.get("site_name", ""))
                    self._audit(
                        "admin_settings_changed",
                        user=session.user,
                        action="site_name",
                        target="site_name",
                        site_name=stored_name[:settings_store.MAX_SITE_NAME],
                    )
            except (settings_store.SettingsError, ValueError) as exc:
                self._admin_request_rejected(
                    "invalid_site_name", user=session.user
                )
                self._json(400, {"ok": False, "error": str(exc)})
                return
            payload = self._admin_state()
            payload["message"] = "A tűzfal neve mentve."
            self._json(200, payload)
            return
        if action == "proxy":
            # A Caddy kérésenként a portált kérdezi, ezért itt nincs
            # újratöltés és nftables-módosítás sem.
            try:
                with self.gw.admin_lock:
                    # A domain szabályok hivatkozásai ugyanezen zár alatt
                    # olvasódnak, mint a szabálymentés (lásd _admin_rules).
                    stored = self.gw.settings.set_proxy(
                        data.get("proxy_domains", []),
                        data.get("proxy_routes", []),
                        self.gw.rules.domain_references(),
                    )
                    self._audit(
                        "admin_settings_changed",
                        user=session.user,
                        action="proxy",
                        target="proxy",
                        proxy_domains=", ".join(stored["proxy_domains"]),
                        proxy_routes=", ".join(
                            f"{route['name']}.{route['root']}:"
                            + (f"{route['ip']}:" if "ip" in route else "")
                            + f"{route['port']}"
                            + ("" if route["enabled"] else " (off)")
                            + (" (public)" if route["visibility"] == "public"
                               else "")
                            for route in stored["proxy_routes"]
                        ),
                    )
            except (settings_store.SettingsError, ValueError) as exc:
                self._admin_request_rejected(
                    "invalid_proxy", user=session.user
                )
                self._json(400, {"ok": False, "error": str(exc)})
                return
            payload = self._admin_state()
            payload["message"] = "A proxy beállításai mentve."
            self._json(200, payload)
            return
        kind = str(data.get("kind", "")).strip().lower()
        entry_id = data.get("id", "")
        if entry_id is None:
            entry_id = ""
        if not isinstance(entry_id, str):
            self._admin_request_rejected(
                "invalid_entry_id", user=session.user
            )
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
                )
            except (settings_store.SettingsError, ValueError) as exc:
                self._admin_action_error(
                    f"settings_{action}", exc, target=entry_id.strip()
                )
                self._json(400, {"ok": False, "error": str(exc)})
                return
            try:
                self.gw.apply_settings(new_data)
            except (gateway.FirewallError, settings_store.SettingsError,
                    OSError) as exc:
                self._admin_action_error(
                    f"settings_{action}", exc, target=entry_id.strip()
                )
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
            self._audit(
                "admin_settings_changed",
                user=session.user,
                action=action or "ismeretlen",
                kind=kind,
                target=target,
                preauth_count=len(new_data.get("preauth", [])),
                block_count=len(new_data.get("block", [])),
            )
        payload = self._admin_state()
        payload["message"] = "A tűzfalbeállítások mentve."
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
            self._admin_request_rejected(
                "invalid_origin", user=session.user
            )
            self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
            return
        data = self._read_json()
        if data is None:
            self._admin_request_rejected("bad_request", user=session.user)
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        action = str(data.get("action", "")).strip().lower()
        target = ""
        message = ""
        audit_extra: dict = {}
        try:
            with self.gw.admin_lock:
                if action == "config":
                    config_data = {
                        key: data[key]
                        for key in (
                            "enabled", "max_attempts",
                            "window_seconds", "ban_seconds",
                            "drop_enabled", "drop_count_enabled",
                            "drop_ports_enabled", "drop_max",
                            "drop_ports", "drop_window_seconds",
                        )
                        if key in data
                    }
                    before_bans = self.gw.fail2ban.snapshot()["banned_count"]
                    config_snapshot = self.gw.fail2ban.configure(config_data)
                    audit_extra = {
                        key: config_snapshot[key]
                        for key in (
                            "enabled", "max_attempts", "window_seconds",
                            "ban_seconds", "drop_enabled",
                            "drop_count_enabled", "drop_ports_enabled",
                            "drop_count_active", "drop_ports_active",
                            "drop_max", "drop_ports", "drop_window_seconds",
                        )
                    }
                    audit_extra["released"] = max(
                        0, before_bans - config_snapshot["banned_count"]
                    )
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
                        record = self.gw.fail2ban.ban(
                            ip, seconds, manual=True, user=session.user
                        )
                        audit_extra = {
                            "manual": True,
                            "seconds": max(
                                0,
                                int(record.get("until", 0))
                                - int(record.get("since", 0)),
                            ),
                            "until": record.get("until", 0),
                        }
                        message = f"{ip} letiltva."
                    else:
                        existing = self.gw.fail2ban.banned(ip)
                        if not self.gw.fail2ban.unban(ip):
                            self._admin_request_rejected(
                                "not_banned", user=session.user
                            )
                            self._json(
                                404,
                                {
                                    "ok": False,
                                    "error": "ez az IP-cím nem volt letiltva",
                                },
                            )
                            return
                        audit_extra = {
                            "removed": True,
                            "was_manual": bool(
                                existing and existing.get("manual")
                            ),
                        }
                        message = f"{ip} tiltása feloldva."
                elif action == "unban_all":
                    removed = self.gw.fail2ban.unban_all()
                    audit_extra = {"removed": removed}
                    message = f"{removed} tiltás feloldva."
                else:
                    self._admin_request_rejected(
                        "unknown_action", user=session.user
                    )
                    self._json(
                        400, {"ok": False, "error": "ismeretlen művelet"}
                    )
                    return
                self._audit(
                    "admin_fail2ban_changed",
                    user=session.user,
                    action=action or "ismeretlen",
                    target=target,
                    **audit_extra,
                )
        except fail2ban_mod.Fail2banError as exc:
            self._admin_action_error(
                f"fail2ban_{action}", exc, target=target
            )
            self._json(400, {"ok": False, "error": str(exc)})
            return
        except Exception as exc:
            self._admin_action_error(
                f"fail2ban_{action}", exc, target=target
            )
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
            self._audit("registration_failed", reason="bad_request")
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        if not self._origin_ok():
            self._audit("registration_failed", reason="invalid_origin")
            return self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
        if not gateway.is_ipv4(ip):
            self._audit("registration_failed", reason="non_ipv4")
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
            payload, headers = self._ban_reply(banned)
            self._audit(
                "login_failed",
                reason="fail2ban tiltás alatt",
                source=payload["ban_source"],
                ban_until=payload["ban_until"],
                remaining=payload["remaining"],
            )
            return self._json(403, payload, headers=headers)

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
                _log_fail2ban_error(
                    ip, exc, self.gw.audit, operation="record_failure"
                )
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
                _log_fail2ban_error(
                    ip, exc, self.gw.audit, operation="record_failure"
                )
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
                self._audit(
                    "totp_ticket_issued",
                    user=record.name,
                    purpose="enroll",
                    ticket_hash=_ticket_hash(ticket),
                    ttl=LOGIN_TICKETS.ttl,
                    secret_generated=True,
                )
                site_name = str(
                    self.gw.settings.snapshot().get("site_name", "") or ""
                ).strip()
                issuer = site_name or gateway.TOTP_ISSUER
                return self._json(
                    200,
                    {
                        "ok": True,
                        "totp_required": True,
                        "totp_enroll_required": True,
                        "ticket": ticket,
                        "secret": secret,
                        "otpauth_uri": gateway.build_otpauth_uri(
                            record.name, secret, issuer=issuer
                        ),
                        "issuer": issuer,
                    },
                )
            ticket = LOGIN_TICKETS.issue(
                "verify", record.name, ip, fingerprint
            )
            self._audit(
                "totp_ticket_issued",
                user=record.name,
                purpose="verify",
                ticket_hash=_ticket_hash(ticket),
                ttl=LOGIN_TICKETS.ttl,
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
        # F7: versenyhelyzet a korai tiltás-ellenőrzés és a munkamenet
        # létrehozása között. A jelszó-/TOTP-/regisztrációs/recovery ág mind
        # ide fut be; itt, közvetlenül a munkamenet létrehozása előtt még
        # egyszer a démon authoritative állapotából ellenőrizzük a tiltást.
        # Így egy közben bekövetkező tiltás után sem jön létre munkamenet.
        banned = self.gw.fail2ban.banned(ip)
        if banned is not None:
            payload, headers = self._ban_reply(banned)
            self._audit(
                "login_banned",
                user=record.name,
                method=method or "password",
                source=payload["ban_source"],
                ban_until=payload["ban_until"],
                remaining=payload["remaining"],
            )
            return self._json(403, payload, headers=headers)
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

        # F7: a korai ellenőrzés és a login() között eltelt időben is
        # megtilthatja az IP-t egy másik kérés (pl. párhuzamos, sikertelen
        # belépések). A létrehozott munkamenetet azonnal visszavonjuk, és
        # a közös tiltásválaszt adjuk vissza — cookie nélkül.
        banned = self.gw.fail2ban.banned(ip)
        if banned is not None:
            ended = self.gw.sessions.logout(
                session.token, ip, reason="fail2ban"
            )
            if ended is not None:
                self._audit(
                    "session_ended",
                    user=ended.user,
                    sid=ended.sid,
                    ip=ended.ip,
                    reason="fail2ban",
                    authorized=ended.authorized,
                    rule=ended.rule,
                )
            payload, headers = self._ban_reply(banned)
            self._audit(
                "login_banned",
                user=record.name,
                method=method or "password",
                source=payload["ban_source"],
                ban_until=payload["ban_until"],
                remaining=payload["remaining"],
                post_login=True,
            )
            return self._json(403, payload, headers=headers)

        cookie = (
            f"{gateway.COOKIE_NAME}={session.token}; Path=/; HttpOnly; "
            f"SameSite=Lax; Max-Age={self.gw.sessions.pending_ttl}"
        )
        if self._cookie_secure():
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

    @staticmethod
    def _ban_error(source: str) -> str:
        if source == "drop":
            return (
                "Ez az IP-cím fail2ban tiltás alatt áll, mert a tűzfal "
                "gyanús hálózati forgalmat (például portvizsgálatot) "
                "észlelt. Próbáld újra később."
            )
        return (
            "Ez az IP-cím fail2ban tiltás alatt áll a túl sok "
            "sikertelen belépés miatt. Próbáld újra később."
        )

    @classmethod
    def _ban_reply(cls, banned: dict) -> tuple[dict, dict[str, str]]:
        """A belépő- és hozzáférés-végpontok közös tiltásválasza.

        A válasz sosem tartalmaz jelszót, cookie-t vagy tokent.
        """
        remaining = int(banned.get("remaining", 0))
        source = str(banned.get("source") or "login")
        payload = {
            "ok": False,
            "error": cls._ban_error(source),
            "banned": True,
            "ban_until": banned.get("until", 0),
            "remaining": remaining,
            "ban_source": source,
            "ban_detail": banned.get("detail", ""),
            "ban_attempts": int(banned.get("attempts", 0)),
        }
        headers = {"Retry-After": str(max(1, min(remaining, 86400)))}
        return payload, headers

    def _totp_ban_guard(self, ip: str) -> bool:
        """A 2FA-végpontok közös fail2ban tiltás-ellenőrzése."""
        banned = self.gw.fail2ban.banned(ip)
        if banned is None:
            return False
        payload, headers = self._ban_reply(banned)
        self._audit(
            "login_failed",
            reason="fail2ban tiltás alatt",
            source=payload["ban_source"],
            ban_until=payload["ban_until"],
            remaining=payload["remaining"],
        )
        self._json(403, payload, headers=headers)
        return True

    def _record_login_failure(self, ip: str, user: str) -> dict | None:
        try:
            return self.gw.fail2ban.record_failure(ip, user)
        except fail2ban_mod.Fail2banError as exc:
            _log_fail2ban_error(
                ip, exc, self.gw.audit, operation="record_failure"
            )
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

    def _ticket_invalid(
        self,
        token: str = "",
        reason: str = "unknown",
        purpose: str = "",
        user: str = "",
    ) -> None:
        # Ugyanaz a válasz jár a hiányzó, lejárt és elhasznált jegyre is; a
        # naplóban viszont megkülönböztetjük az okot.
        fields = {"purpose": purpose, "reason": reason}
        if user:
            fields["user"] = user
        if token:
            fields["ticket_hash"] = _ticket_hash(token)
        self._audit("totp_ticket_rejected", **fields)
        self._json(
            403,
            {
                "ok": False,
                "code": "ticket_invalid",
                "error": "Érvénytelen vagy lejárt bejelentkezés. Kezdd újra.",
            },
        )

    def _totp_failure(
        self,
        ip: str,
        token: str,
        username: str,
        recovery: bool = False,
        purpose: str = "",
    ) -> None:
        """Hibás 2FA-kód: jegypróba, fail2ban és a megfelelő hibaüzenet."""
        remaining, locked, attempts, existed = (
            LOGIN_TICKETS.fail_with_status(token, ip)
        )
        ban = self._record_login_failure(ip, username)
        self._audit(
            "totp_failed",
            user=username,
            method="recovery" if recovery else "totp",
            purpose=purpose,
            ticket_hash=_ticket_hash(token),
            attempts=attempts,
            remaining=remaining,
            banned=ban is not None,
            ban_until=ban.get("until", 0) if ban is not None else 0,
            severity=(
                "alert" if ban is not None or remaining == 0 else None
            ),
        )
        if locked:
            self._audit(
                "totp_ticket_locked",
                user=username,
                purpose=purpose,
                ticket_hash=_ticket_hash(token),
                attempts=attempts,
                reason="too_many_attempts",
            )
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
            self._audit(
                "totp_ticket_rejected",
                purpose="verify",
                reason="bad_request",
            )
            return self._json(
                400,
                {"ok": False, "error": "hibás kérés", "code": "bad_request"},
            )
        token, code = credentials
        ticket = LOGIN_TICKETS.peek(token, ip)
        if ticket is None:
            _, reason = LOGIN_TICKETS.inspect(token, ip)
            return self._ticket_invalid(
                token, reason=reason, purpose="verify"
            )
        if ticket.purpose != "verify":
            return self._ticket_invalid(
                token,
                reason="wrong_purpose",
                purpose=ticket.purpose,
                user=ticket.username,
            )
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
            return self._ticket_invalid(
                token,
                reason="user_state_changed",
                purpose=ticket.purpose,
                user=ticket.username,
            )
        if not self.gw.users.verify_totp(ticket.username, code):
            return self._totp_failure(
                ip, token, ticket.username, purpose=ticket.purpose
            )
        if LOGIN_TICKETS.consume(token, ip) is None:
            _, reason = LOGIN_TICKETS.inspect(token, ip)
            return self._ticket_invalid(
                token,
                reason=reason or "already_consumed",
                purpose=ticket.purpose,
                user=ticket.username,
            )
        try:
            self.gw.fail2ban.record_success(ip)
        except fail2ban_mod.Fail2banError as exc:
            _log_fail2ban_error(
                ip, exc, self.gw.audit, operation="record_success"
            )
        self._login_session_response(record, method="totp")

    def _login_totp_enroll(self) -> None:
        """Az első 2FA-beállítás: titok megerősítése és recovery kódok."""
        prelude = self._totp_prelude()
        if prelude is None:
            return
        ip, data = prelude
        credentials = self._ticket_credentials(data)
        if credentials is None:
            self._audit(
                "totp_ticket_rejected",
                purpose="enroll",
                reason="bad_request",
            )
            return self._json(
                400,
                {"ok": False, "error": "hibás kérés", "code": "bad_request"},
            )
        token, code = credentials
        ticket = LOGIN_TICKETS.peek(token, ip)
        if ticket is None:
            _, reason = LOGIN_TICKETS.inspect(token, ip)
            return self._ticket_invalid(
                token, reason=reason, purpose="enroll"
            )
        if ticket.purpose != "enroll":
            return self._ticket_invalid(
                token,
                reason="wrong_purpose",
                purpose=ticket.purpose,
                user=ticket.username,
            )
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
            return self._ticket_invalid(
                token,
                reason="user_state_changed",
                purpose=ticket.purpose,
                user=ticket.username,
            )
        matched = gateway.totp_match(ticket.secret, code)
        if matched is None:
            return self._totp_failure(
                ip, token, ticket.username, purpose=ticket.purpose
            )
        if LOGIN_TICKETS.consume(token, ip) is None:
            _, reason = LOGIN_TICKETS.inspect(token, ip)
            return self._ticket_invalid(
                token,
                reason=reason or "already_consumed",
                purpose=ticket.purpose,
                user=ticket.username,
            )
        codes = gateway.generate_recovery_codes(10)
        hashes = [gateway.hash_recovery_code(value) for value in codes]
        if not self.gw.users.enroll_totp(
            ticket.username, ticket.secret, hashes, last_step=matched
        ):
            self._audit(
                "totp_enroll_failed",
                user=ticket.username,
                target=ticket.username,
                ticket_hash=_ticket_hash(token),
                reason="persist_failed",
            )
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
            self._audit(
                "totp_enroll_failed",
                user=ticket.username,
                target=ticket.username,
                ticket_hash=_ticket_hash(token),
                reason="user_state_changed",
            )
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
            _log_fail2ban_error(
                ip, exc, self.gw.audit, operation="record_success"
            )
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
            self._audit(
                "totp_ticket_rejected",
                purpose="verify",
                reason="bad_request",
            )
            return self._json(
                400,
                {"ok": False, "error": "hibás kérés", "code": "bad_request"},
            )
        token, code = credentials
        ticket = LOGIN_TICKETS.peek(token, ip)
        if ticket is None:
            _, reason = LOGIN_TICKETS.inspect(token, ip)
            return self._ticket_invalid(
                token, reason=reason, purpose="verify"
            )
        if ticket.purpose != "verify":
            return self._ticket_invalid(
                token,
                reason="wrong_purpose",
                purpose=ticket.purpose,
                user=ticket.username,
            )
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
            return self._ticket_invalid(
                token,
                reason="user_state_changed",
                purpose=ticket.purpose,
                user=ticket.username,
            )
        if not self.gw.users.verify_recovery(ticket.username, code):
            return self._totp_failure(
                ip, token, ticket.username, recovery=True,
                purpose=ticket.purpose,
            )
        if LOGIN_TICKETS.consume(token, ip) is None:
            _, reason = LOGIN_TICKETS.inspect(token, ip)
            return self._ticket_invalid(
                token,
                reason=reason or "already_consumed",
                purpose=ticket.purpose,
                user=ticket.username,
            )
        try:
            self.gw.fail2ban.record_success(ip)
        except fail2ban_mod.Fail2banError as exc:
            _log_fail2ban_error(
                ip, exc, self.gw.audit, operation="record_success"
            )
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

        # F7: a tiltás-ellenőrzés a sebességkorlát és a munkamenet-zár előtt
        # fut, így nincs zár-inverzió. Az on_ban visszahívás rendszerint már
        # bontotta az IP munkameneteit; itt védelmi mélységként megismételjük,
        # és a tiltott kliens semmilyen engedélyt nem kaphat.
        banned = self.gw.fail2ban.banned(ip)
        if banned is not None:
            payload, headers = self._ban_reply(banned)
            try:
                revoked = self.gw.sessions.revoke_ip(ip, reason="fail2ban")
            except Exception as exc:
                revoked = 0
                print(
                    f"[{ip}] a fail2ban tiltás munkamenet-bontása nem "
                    f"sikerült: {exc}",
                    flush=True,
                )
            self._audit(
                "access_denied",
                reason="fail2ban",
                source=payload["ban_source"],
                ban_until=payload["ban_until"],
                remaining=payload["remaining"],
                sessions_revoked=revoked,
            )
            return self._json(403, payload, headers=headers)

        if not self.gw.access_rate.allow(ip):
            self._audit("access_denied", reason="túl sok próbálkozás")
            return self._json(
                429,
                {"ok": False, "error": "Túl sok hozzáférés-módosítás. Várj egy percet."},
                headers={"Retry-After": "60"},
            )

        rule_ids, rule_error = _access_rule_ids(data)
        if not rule_ids:
            self._audit("access_denied", reason=rule_error)
            return self._json(400, {"ok": False, "error": rule_error})
        rule_field = ",".join(rule_ids)

        ttl = data.get("ttl")
        if isinstance(ttl, bool) or not isinstance(ttl, int):
            self._audit("access_denied", reason="hiányzó szabály vagy időtartam")
            return self._json(
                400, {"ok": False, "error": "hiányzó szabály vagy időtartam"}
            )

        token = self._cookie_token()
        current = self.gw.sessions.validate(token, ip)
        if current is None:
            self._audit("access_denied", reason="nincs érvényes munkamenet",
                        rule=rule_field)
            return self._json(
                400, {"ok": False, "error": "érvénytelen vagy lejárt munkamenet"}
            )
        record = self.gw.users.record(current.user)
        if record is None or not record.enabled or record.pending:
            self.gw.sessions.logout(token, ip)
            self._audit(
                "access_denied", user=current.user,
                reason="letiltott vagy törölt felhasználó", rule=rule_field,
            )
            return self._json(403, {"ok": False, "error": "a felhasználó nem aktív"})
        if record.must_change_password:
            # F7: védelmi mélység. Ha a jelző olyan munkameneten látszik,
            # amely már engedélyt kapott (például egy másik folyamatból
            # történő beállítás után), a hálózati engedély nem maradhat
            # érvényben. A logout célzottan csak ezt a munkamenetet bontja.
            #
            # Trade-off: a /api/password végpont érvényes munkamenetet kér,
            # ezért a kijelentkeztetés után a felhasználónak újra be kell
            # lépnie az ideiglenes jelszóval, hogy lecserélhesse. Ez
            # elfogadható: nem hagyunk élő engedélyt, és a jelszócsere
            # továbbra is elérhető. (Ha a felhasználó csak a jelszavát
            # akarja cserélni, és nem hívja a /api/access végpontot, a
            # függő munkamenet megmarad, így közvetlenül cserélhet.)
            access_revoked = False
            if current.authorized:
                logged_out = self.gw.sessions.logout(
                    token, ip, reason="must_change_password"
                )
                access_revoked = logged_out is not None
            self._audit(
                "access_denied", user=current.user,
                reason="kötelező jelszócsere", rule=rule_field,
                access_revoked=access_revoked,
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
            # Előbb minden azonosítót feloldunk; hiba esetén egyik szabály
            # sem kerül engedélyezésre (nincs részleges hozzáférés).
            resolved_rules = [
                self.gw.rules.resolve_for(record, groups, rule_id)
                for rule_id in rule_ids
            ]
            session = self.gw.sessions.authorize(
                token, ip, resolved_rules, ttl
            )
        except gateway.AccessError as exc:
            self._audit(
                "access_denied", user=current.user, rule=rule_field,
                ttl=ttl, reason=str(exc),
            )
            return self._json(400, {"ok": False, "error": str(exc)})
        except gateway.FirewallError as exc:
            self._audit(
                "access_denied", user=current.user, rule=rule_field,
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
        if self._cookie_secure():
            cookie += "; Secure"
        selection = self._selection_payload(session)
        selected_ids = selection["selected_rules"]
        audit_fields = {
            "user": session.user,
            "role": record.role,
            "rule": session.rule,
            "rule_label": session.rule_label,
            "direction": session.direction,
            "tcp": ",".join(str(port) for port in session.tcp),
            "udp": ",".join(str(port) for port in session.udp),
            "icmp": session.icmp,
            "full": session.full,
            "ports": session.ports.label(),
            "rules": ",".join(selected_ids),
            "rule_labels": ",".join(selection["selected_rule_labels"]),
            "rule_count": len(selected_ids),
            "hosts": ",".join(selection["hosts"]),
            "ttl": ttl,
            "expires_at": gateway._utc_iso(session.expires),
            "modified": current.authorized,
        }
        if current.authorized:
            previous_ids = tuple(dict.fromkeys(
                current.rules
                or tuple(part.rule_id for part in current.selections())
            ))
            audit_fields["removed_rules"] = ",".join(
                rule_id for rule_id in previous_ids
                if rule_id not in selected_ids
            )
        self._audit(
            "access_modified" if current.authorized else "access_granted",
            **audit_fields,
        )
        print(
            f"[{ip}] hozzáférés engedélyezve: {session.user!r}, "
            f"{', '.join(selected_ids)} ({session.ports.label()}), "
            f"{gateway.format_duration(ttl)}",
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
                **selection,
                "limits": self._limits(),
                "rules": [
                    self._rule_payload(item)
                    for item in self.gw.effective_rules(session.user)
                ],
                "message": (
                    "Hozzáférés engedélyezve: "
                    f"{gateway.format_duration(ttl)} "
                    f"({', '.join(selection['selected_rule_labels'])})."
                ),
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
        else:
            self._audit("logout_failed", reason="no_valid_session")
        clear = (
            f"{gateway.COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        )
        if self._cookie_secure():
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
        # Védelem mélységben: tiltott IP a meglévő munkamenetével sem
        # cserélhet jelszót. A rate limitert megelőzően, a közös
        # tiltásválasszal zárjuk el; tokent/cookie-t nem adunk ki.
        banned = self.gw.fail2ban.banned(ip)
        if banned is not None:
            payload, headers = self._ban_reply(banned)
            self._audit(
                "password_change_failed",
                reason="fail2ban tiltás",
                source=payload["ban_source"],
            )
            return self._json(403, payload, headers=headers)
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

    def _admin_request_rejected(self, reason: str, user: str = "") -> None:
        """Az admin-végpontok előzetes (még nem műveleti) elutasításai."""
        self._audit(
            "admin_request_rejected",
            user=user,
            path=urllib.parse.urlsplit(self.path).path,
            reason=reason,
        )

    def _admin_action_error(
        self, action: str, exc: Exception, target: str = ""
    ) -> None:
        session = self._session()
        fields = {
            "action": action,
            "user": session.user if session is not None else "",
            "reason": str(exc),
            "path": urllib.parse.urlsplit(self.path).path,
        }
        if target:
            fields["target"] = target
        self._audit("admin_action_failed", **fields)

    def _admin_users(self) -> None:
        data = self._read_json()
        if data is None:
            self._admin_request_rejected("bad_request")
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        if not self._origin_ok():
            self._admin_request_rejected("invalid_origin")
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
                self._admin_request_rejected(
                    "unknown_action", user=session.user
                )
                raise gateway.UserStoreError("ismeretlen művelet")
        except (gateway.UserStoreError, gateway.GroupStoreError,
                gateway.RuleStoreError, gateway.AccessError, ValueError) as exc:
            self._admin_action_error(
                f"user_{action}", exc,
                target=str(data.get("name") or ""),
            )
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
            tickets = LOGIN_TICKETS.revoke_user(name, reason="rejected")
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
        reason = "disabled" if not enabled else (
            "password_changed" if password_changed else "revoked"
        )
        # A munkameneteket és a függő 2FA-jegyeket a módosítások előtt
        # vonjuk vissza. Ha egy későbbi írás hibára fut, a felhasználó nem
        # maradhat élő munkamenettel a részben módosított állapoton; így a
        # visszavonás köztes hiba miatt sem maradhat el.
        revoked = self.gw.sessions.revoke_user(name, reason=reason)
        tickets = 0
        if record.enabled and not enabled:
            # Letiltáskor a függő 2FA-jegyek sem maradhatnak életben.
            tickets = LOGIN_TICKETS.revoke_user(name, reason="disabled")
        stage = "password"
        try:
            if password_changed:
                # Az admin által beállított (ideiglenes) jelszót az érintett
                # felhasználónak első belépéskor le kell cserélnie.
                self.gw.users.set_password(
                    name, password, must_change_password=True
                )
                must_change = True
            stage = "metadata"
            self.gw.users.set_metadata(
                name, role=role, enabled=enabled, rules=rules,
                must_change_password=must_change, totp_required=totp_required,
            )
            stage = "groups"
            if group_ids is not None:
                self.gw.groups.set_memberships(name, group_ids)
        except Exception as exc:
            if password_changed:
                # A jelszó írása commitolódhatott a hiba előtt; a többi
                # lépés külön, atomikus fájlírással dolgozik, ezért csak a
                # jelszó-állapotot kell visszaállítani. A munkamenetek
                # visszavonása már megtörtént.
                try:
                    self.gw.users.restore_password(name, record)
                except Exception as restore_exc:
                    print(
                        f"[{name}] a jelszó visszaállítása sem sikerült: "
                        f"{restore_exc}",
                        flush=True,
                    )
            self._audit(
                "admin_user_update_failed",
                target=name,
                user=self._session().user if self._session() else "",
                stage=stage,
                reason=str(exc),
                password_changed=password_changed,
                sessions_revoked=revoked,
                tickets_revoked=tickets,
            )
            raise
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
            tickets_revoked=tickets,
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
            record = self.gw.users.record(name)
            if record is None:
                raise gateway.UserStoreError(f"nincs ilyen felhasználó: {name}")
            # A reset előtti állapotot rögzítjük a naplóhoz; a titok és a
            # recovery-hashek értéke természetesen nem kerülhet bele.
            was_enrolled = bool(record.totp_secret)
            if not self.gw.users.reset_totp(name):
                raise gateway.UserStoreError(f"nincs ilyen felhasználó: {name}")
            revoked = self.gw.sessions.revoke_user(name, reason="totp_reset")
            tickets = LOGIN_TICKETS.revoke_user(name, reason="totp_reset")
            self._audit(
                "admin_totp_reset",
                target=name,
                user=session.user,
                was_enrolled=was_enrolled,
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
        tickets = LOGIN_TICKETS.revoke_user(name, reason="deleted")
        self._audit(
            "admin_user_deleted",
            target=name,
            user=self._session().user if self._session() else "",
            sessions_revoked=revoked,
            tickets_revoked=tickets,
        )

    def _admin_groups(self) -> None:
        data = self._read_json()
        if data is None:
            self._admin_request_rejected("bad_request")
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        if not self._origin_ok():
            self._admin_request_rejected("invalid_origin")
            return self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
        session = self._admin_guard()
        if session is None:
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
                self._admin_request_rejected(
                    "unknown_action", user=session.user
                )
                raise gateway.GroupStoreError("ismeretlen művelet")
        except (gateway.GroupStoreError, gateway.RuleStoreError,
                gateway.UserStoreError, ValueError) as exc:
            self._admin_action_error(
                f"group_{action}", exc,
                target=str(data.get("id") or ""),
            )
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
            self._admin_request_rejected("bad_request")
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        if not self._origin_ok():
            self._admin_request_rejected("invalid_origin")
            return self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
        session = self._admin_guard()
        if session is None:
            return
        action = str(data.get("action", "")).strip()
        message = ""
        try:
            # Az admin_lock a proxy-bejegyzések mentésével sorosít: egy
            # domain szabály nem hivatkozhat közben törölt bejegyzésre.
            with self.gw.admin_lock:
                if action == "create":
                    self._admin_rule_create(data)
                elif action == "update":
                    self._admin_rule_update(data)
                elif action == "delete":
                    self._admin_rule_delete(data)
                elif action == "duplicate":
                    self._admin_rule_duplicate(data)
                    message = "Szabály duplikálva."
                else:
                    self._admin_request_rejected(
                        "unknown_action", user=session.user
                    )
                    raise gateway.RuleStoreError("ismeretlen művelet")
        except (gateway.RuleStoreError, ValueError) as exc:
            self._admin_action_error(
                f"rule_{action}", exc,
                target=str(data.get("id") or ""),
            )
            return self._json(400, {"ok": False, "error": str(exc)})
        payload = self._admin_state()
        if message:
            payload["message"] = message
        self._json(200, payload)

    def _admin_rule_create(self, data: dict) -> None:
        rule_id = data.get("id")
        if not isinstance(rule_id, str):
            raise gateway.RuleStoreError("hiányzó szabály-azonosító")
        rule = self.gw.rules.create(rule_id, data)
        self._audit(
            "admin_rule_created",
            target=rule.id,
            user=self._session().user if self._session() else "",
            direction=rule.direction,
            ports=rule.ports.label(),
            domains=",".join(rule.domains),
            default_ttl=rule.default_ttl,
            max_ttl=rule.max_ttl,
            collection=rule.collection,
            members=len(rule.members),
        )
        # A host (input) szabály portjai azonnal kerüljenek a kerneloldali
        # host_service_* védőhalmazokba; egy esetleges hiba csak naplózódik.
        self.gw.sync_host_ports()

    def _admin_rule_update(self, data: dict) -> None:
        rule_id = data.get("id")
        if not isinstance(rule_id, str):
            raise gateway.RuleStoreError("hiányzó szabály-azonosító")
        # A függő gyűjtők listáját a szabálytár a módosítással egy záron
        # belül, a commit pontján adja vissza: a közben létrehozott gyűjtő
        # is belekerül, így nem maradhat engedélyezett munkamenet a régi
        # portokkal, nem csak a szabály sajátjait kell bontani.
        rule, dependents = self.gw.rules.update_with_dependents(
            rule_id.strip(), data
        )
        revoked = self.gw.sessions.revoke_rules((rule.id, *dependents))
        self._audit(
            "admin_rule_updated",
            target=rule.id,
            user=self._session().user if self._session() else "",
            direction=rule.direction,
            ports=rule.ports.label(),
            domains=",".join(rule.domains),
            default_ttl=rule.default_ttl,
            max_ttl=rule.max_ttl,
            collection=rule.collection,
            members=len(rule.members),
            collections_affected=",".join(dependents),
            sessions_revoked=revoked,
        )
        # A feloldott portok a függő gyűjtők miatt is változhattak, ezért a
        # teljes szabálytárból szinkronizálunk (a halmazok csak bővülnek).
        self.gw.sync_host_ports()

    def _admin_rule_duplicate(self, data: dict) -> None:
        rule_id = data.get("id")
        if not isinstance(rule_id, str):
            raise gateway.RuleStoreError("hiányzó szabály-azonosító")
        label = data.get("label")
        if label is not None and not isinstance(label, str):
            raise gateway.RuleStoreError("label: szöveg kell")
        new_id = data.get("new_id")
        if new_id is not None and not isinstance(new_id, str):
            raise gateway.RuleStoreError("new_id: szöveg kell")
        rule = self.gw.rules.duplicate(
            rule_id.strip(), new_id=new_id, label=label
        )
        self._audit(
            "admin_rule_duplicated",
            target=rule.id,
            source=rule_id.strip(),
            user=self._session().user if self._session() else "",
            direction=rule.direction,
            ports=rule.ports.label(),
            domains=",".join(rule.domains),
            collection=rule.collection,
            members=len(rule.members),
        )
        self.gw.sync_host_ports()

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
            direction=rule.direction,
            users_changed=users_changed,
            groups_changed=groups_changed,
            sessions_revoked=revoked,
        )
        # A törölt szabály portjai szándékosan a host_service_* halmazokban
        # maradnak (add-only), így a meglévő kapcsolat nem nyílik meg újra.
        self.gw.sync_host_ports()


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], gw: gateway.Gateway) -> None:
        self.gateway = gw
        super().__init__(address, Handler)


# ------------------------------------------------------- helyi vezérlőcsatorna
#
# A parancssori műveletek eddig külön folyamatban, a futó démontól függetlenül
# módosították a fájlokat és a kernelt. Egy CLI-s törlés/jelszócsere után így
# a démon memóriájában élő munkamenet és tűzfalengedély a TTL-ig életben
# maradhatott. A vezérlőcsatorna egy csak helyi (Unix domain) socket, amelyen
# a CLI a futó démonhoz fordul; a démon a saját élő objektumaival hajtja végre
# a műveletet, és azonnal visszavonja az érintett munkameneteket.
#
# Biztonsági modell:
#   * a socket a STATE_DIR alatt van, 0600 jogosultsággal;
#   * a démon SO_PEERCRED-del ellenőrzi, hogy a kliens uid-je azonos-e;
#   * a kérés egyetlen, új sorral zárt JSON objektum, legfeljebb 64 KiB;
#   * a démon egyetlen JSON választ küld, és nem naplóz kérésbody-t,
#     jelszót, hasht, TOTP-titkot vagy tokent.

CONTROL_DIR_NAME = "control"
CONTROL_SOCKET_NAME = "control.sock"
SERVER_PID_NAME = "server.pid"
CONTROL_MAX_REQUEST = 64 * 1024
CONTROL_TIMEOUT = 5.0
# A CLI várakozási ideje hosszabb, mint a szerveroldali feldolgozási idő:
# egy lassú, de egészséges démont ne minősítsünk elérhetetlennek még a
# kérés elküldése előtt.
CONTROL_CLI_TIMEOUT = 15.0
_PEERCRED_SIZE = struct.calcsize("3i")


class ControlError(RuntimeError):
    """A vezérlőcsatorna általános hibája."""


class ControlUnavailable(ControlError):
    """A csatorna a kérés elküldése előtt nem érhető el (fallback lehet)."""


class ControlAmbiguous(ControlError):
    """A kérés elküldése után a válasz bizonytalan (fallback TILOS)."""


class ControlProtocolError(ControlError):
    """A csatorna válasza érvénytelen (a kérést már elküldtük)."""


def _control_dir_path() -> str:
    # Nem importáláskor rögzítjük: a tesztek és a HV_STATE_DIR átállítása
    # is érvényesüljön.
    return os.path.join(gateway.STATE_DIR, CONTROL_DIR_NAME)


def _control_socket_path() -> str:
    return os.path.join(_control_dir_path(), CONTROL_SOCKET_NAME)


def _server_pid_path() -> str:
    return os.path.join(gateway.STATE_DIR, SERVER_PID_NAME)


def _dir_security_error(
    directory: str, *, follow_symlinks: bool = False
) -> str | None:
    """A könyvtár tulajdonosa/jogosultsága alkalmas-e a socket tárolására."""
    stat_fn = os.stat if follow_symlinks else os.lstat
    try:
        state = stat_fn(directory)
    except OSError as exc:
        return f"nem érhető el: {exc}"
    if not stat.S_ISDIR(state.st_mode):
        return "nem könyvtár"
    if state.st_uid not in (0, os.geteuid()):
        return (
            f"a tulajdonosa uid {state.st_uid}, nem a folyamat "
            "felhasználója vagy root"
        )
    if state.st_mode & 0o022:
        return "csoport vagy más felhasználók által írható"
    return None


def _write_server_pid() -> int | None:
    """A futó démon pidje a state könyvtárban, 0600 jogosultsággal."""
    path = _server_pid_path()
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, f"{os.getpid()}\n".encode("ascii"))
            os.fsync(fd)
            inode = int(os.fstat(fd).st_ino)
        finally:
            os.close(fd)
        return inode
    except OSError as exc:
        print(
            f"FIGYELEM: a démon pidfájlja nem írható ({path}): {exc}",
            file=sys.stderr,
            flush=True,
        )
        return None


def _remove_server_pid(inode: int | None) -> None:
    """Csak a saját, változatlan pidfájlunkat távolítja el."""
    if inode is None:
        return
    path = _server_pid_path()
    try:
        state = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        print(
            f"[control] a pidfájl állapota nem vizsgálható: {exc}",
            file=sys.stderr,
            flush=True,
        )
        return
    if not stat.S_ISREG(state.st_mode) or state.st_ino != inode:
        return
    try:
        fd = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            read_state = os.fstat(fd)
            raw = os.read(fd, 64).decode("ascii", "replace").strip()
        finally:
            os.close(fd)
    except OSError:
        return
    if not stat.S_ISREG(read_state.st_mode) or read_state.st_ino != inode:
        return
    if raw != str(os.getpid()):
        return
    try:
        state = os.lstat(path)
        if not stat.S_ISREG(state.st_mode) or state.st_ino != inode:
            return
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(
            f"[control] a pidfájl eltávolítása nem sikerült: {exc}",
            file=sys.stderr,
            flush=True,
        )


def _control_peer_uid(sock) -> int | None:
    """A Unix socket túloldalának uid-je (Linux SO_PEERCRED)."""
    if not hasattr(socket, "SO_PEERCRED"):
        return None
    try:
        raw = sock.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED_SIZE
        )
    except (OSError, AttributeError, TypeError):
        return None
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < _PEERCRED_SIZE:
        return None
    try:
        _pid, uid, _gid = struct.unpack("3i", raw[:_PEERCRED_SIZE])
    except struct.error:
        return None
    return int(uid)


class ControlHandler(socketserver.StreamRequestHandler):
    """Egy kérés = egy új sorral zárt JSON objektum, egy JSON válasz."""

    def handle(self) -> None:
        try:
            self.request.settimeout(CONTROL_TIMEOUT)
        except OSError:
            pass
        if not self._peer_allowed():
            self._respond(
                {"ok": False, "status": 1, "error": "elutasítva"}
            )
            return

        try:
            line = self.rfile.readline(CONTROL_MAX_REQUEST + 1)
        except (OSError, ValueError):
            self._respond(
                {"ok": False, "status": 1, "error": "olvasási hiba"}
            )
            return
        if len(line) > CONTROL_MAX_REQUEST:
            self._respond(
                {"ok": False, "status": 1, "error": "túl nagy kérés"}
            )
            return
        if not line.endswith(b"\n"):
            self._respond(
                {"ok": False, "status": 1, "error": "hibás kérés"}
            )
            return
        try:
            data = json.loads(line)
        except ValueError:
            data = None
        if not isinstance(data, dict):
            self._audit("control_rejected", reason="bad_request")
            self._respond(
                {"ok": False, "status": 1, "error": "hibás kérés"}
            )
            return

        action = data.get("action")
        if not isinstance(action, str) or not action:
            self._audit("control_rejected", reason="bad_request")
            self._respond(
                {"ok": False, "status": 1, "error": "hiányzó művelet"}
            )
            return
        method = self._ACTIONS.get(action)
        if method is None:
            # A művelet nevét naplózzuk (nem titok), a body-t soha.
            self._audit(
                "control_rejected",
                reason="unknown_action",
                action=action[:64],
            )
            self._respond(
                {
                    "ok": False,
                    "status": 1,
                    "error": f"ismeretlen művelet: {action[:64]}",
                }
            )
            return
        try:
            payload = method(self, data)
        except (
            gateway.UserStoreError,
            gateway.GroupStoreError,
            gateway.RuleStoreError,
            fail2ban_mod.Fail2banError,
            ValueError,
        ) as exc:
            # Ezek az üzenetek nem tartalmaznak jelszót/hasht/titkot.
            self._audit(
                "control_action_failed",
                action=action[:64],
                reason=str(exc)[:200],
            )
            self._respond(
                {"ok": False, "status": 1, "error": str(exc)}
            )
        except Exception as exc:  # a csatorna ne haljon meg egy hibától
            print(
                f"[control] {action[:64]} hiba: {exc}",
                file=sys.stderr,
                flush=True,
            )
            self._respond(
                {"ok": False, "status": 1, "error": "belső hiba"}
            )
        else:
            self._respond(payload)

    # -- alacsony szintű segédek ------------------------------------------------

    def _peer_allowed(self) -> bool:
        uid = _control_peer_uid(self.request)
        if uid is not None and uid == os.geteuid():
            return True
        # Generikus elutasítás, a peer uid-jét/pid-jét nem naplózzuk.
        self._audit("control_denied", reason="peer_uid")
        return False

    def _audit(self, event: str, **fields) -> None:
        try:
            self.server.gateway.audit.write(event, **fields)
        except Exception as exc:  # a naplózás ne szakítsa meg a csatornát
            print(
                f"[control] naplózási hiba: {exc}",
                file=sys.stderr,
                flush=True,
            )

    def _respond(self, payload: dict) -> None:
        try:
            body = (
                json.dumps(
                    payload, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
                + b"\n"
            )
            self.wfile.write(body)
            self.wfile.flush()
        except OSError:
            pass

    # -- bemenet-ellenőrzés -----------------------------------------------------

    @staticmethod
    def _name(data: dict) -> str:
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("hiányzó felhasználónév")
        return name.strip()

    @staticmethod
    def _password(data: dict) -> str:
        password = data.get("password")
        if not isinstance(password, str):
            raise ValueError("hiányzó jelszó")
        return password

    @staticmethod
    def _bool(data: dict, key: str, default: bool) -> bool:
        value = data.get(key, default)
        if not isinstance(value, bool):
            raise ValueError(f"a {key} mező logikai érték kell legyen")
        return value

    @staticmethod
    def _rules(data: dict) -> tuple[str, ...]:
        raw = data.get("rules", [])
        if not isinstance(raw, list) or len(raw) > 64:
            raise ValueError("a rules mező legfeljebb 64 elemű lista")
        out: list[str] = []
        for value in raw:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("érvénytelen szabály-azonosító")
            value = value.strip()
            if not gateway._SERVICE_ID_RE.match(value):
                raise ValueError(f"érvénytelen szabály-azonosító: {value!r}")
            if value == gateway.LEGACY_ADMIN_RULE_ID:
                raise ValueError(
                    "ez egy fenntartott, régi azonosító, nem rendelhető hozzá"
                )
            if value not in out:
                out.append(value)
        return tuple(out)

    # -- műveletek --------------------------------------------------------------

    def _action_user_add(self, data: dict) -> dict:
        gw = self.server.gateway
        name = self._name(data)
        password = self._password(data)
        role = data.get("role", gateway.ROLE_USER)
        if role not in (gateway.ROLE_USER, gateway.ROLE_ADMIN):
            raise ValueError("érvénytelen szerepkör")
        must_change = self._bool(data, "must_change_password", True)
        rules = self._rules(data)
        gw.users.add(
            name, password, role=role, rules=rules,
            must_change_password=must_change,
        )
        # Ha korábban egy azonos nevű fiók munkamenete vagy belépőjegye élt
        # volna, ne örökölhesse az új fiók az engedélyt.
        revoked = gw.sessions.revoke_user(name, reason="created")
        tickets = LOGIN_TICKETS.revoke_user(name, reason="created")
        self._audit(
            "cli_user_created",
            target=name,
            role=role,
            rules=",".join(rules),
            must_change_password=must_change,
            sessions_revoked=revoked,
            tickets_revoked=tickets,
        )
        return {
            "ok": True,
            "status": 0,
            "message": f"Felhasználó létrehozva: {name}",
        }

    def _action_user_passwd(self, data: dict) -> dict:
        gw = self.server.gateway
        name = self._name(data)
        password = self._password(data)
        must_change = self._bool(data, "must_change_password", True)
        gw.users.set_password(
            name, password, must_change_password=must_change
        )
        revoked = gw.sessions.revoke_user(
            name, reason="password_changed"
        )
        tickets = LOGIN_TICKETS.revoke_user(
            name, reason="password_changed"
        )
        self._audit(
            "cli_password_changed",
            target=name,
            must_change_password=must_change,
            sessions_revoked=revoked,
            tickets_revoked=tickets,
        )
        return {
            "ok": True,
            "status": 0,
            "message": f"Jelszó frissítve: {name}",
        }

    def _action_user_del(self, data: dict) -> dict:
        gw = self.server.gateway
        name = self._name(data)
        if not gw.users.remove(name):
            self._audit(
                "cli_action_failed",
                action="del",
                target=name,
                reason="nincs ilyen felhasználó",
            )
            return {
                "ok": False,
                "status": 1,
                "stdout": True,
                "error": f"Nincs ilyen felhasználó: {name}",
            }
        # A csoporttagságot is törölni kell, különben egy később azonos
        # néven létrehozott fiók örökölné a régi csoport szabályait.
        gw.groups.remove_member_everywhere(name)
        revoked = gw.sessions.revoke_user(name, reason="deleted")
        tickets = LOGIN_TICKETS.revoke_user(name, reason="deleted")
        self._audit(
            "cli_user_deleted",
            target=name,
            sessions_revoked=revoked,
            tickets_revoked=tickets,
        )
        return {
            "ok": True,
            "status": 0,
            "message": f"Felhasználó törölve: {name}",
            "sessions_revoked": revoked,
        }

    def _action_user_totp_reset(self, data: dict) -> dict:
        gw = self.server.gateway
        name = self._name(data)
        record = gw.users.record(name)
        was_enrolled = bool(record is not None and record.totp_secret)
        if not gw.users.reset_totp(name):
            self._audit(
                "cli_action_failed",
                action="totp-reset",
                target=name,
                reason="nincs ilyen felhasználó",
            )
            return {
                "ok": False,
                "status": 1,
                "stdout": True,
                "error": f"Nincs ilyen felhasználó: {name}",
            }
        revoked = gw.sessions.revoke_user(name, reason="totp_reset")
        tickets = LOGIN_TICKETS.revoke_user(name, reason="totp_reset")
        self._audit(
            "cli_totp_reset",
            target=name,
            was_enrolled=was_enrolled,
            sessions_revoked=revoked,
            tickets_revoked=tickets,
        )
        return {
            "ok": True,
            "status": 0,
            "message": f"2FA alaphelyzetbe állítva: {name}",
            "sessions_revoked": revoked,
        }

    def _action_fail2ban_ban(self, data: dict) -> dict:
        gw = self.server.gateway
        ip = data.get("ip")
        if not isinstance(ip, str) or not ip.strip():
            raise ValueError("hiányzó IP-cím")
        seconds = data.get("seconds", 0)
        if isinstance(seconds, bool) or not isinstance(seconds, int):
            raise ValueError(
                "a tiltás hossza egész szám (másodperc) kell"
            )
        manual = self._bool(data, "manual", True)
        user = data.get("user", "cli")
        if not isinstance(user, str):
            user = "cli"
        # A futó démon menedzsere: az on_ban visszahívás bontja az IP
        # munkameneteit és üríti a conntracket. A fail2ban_ban eseményt az
        # on_ban írja, ezért itt nem duplikáljuk.
        ban = gw.fail2ban.ban(
            ip.strip(), seconds, manual=manual, user=user
        )
        duration = max(
            0, int(ban.get("until", 0)) - int(ban.get("since", 0))
        )
        self._audit(
            "cli_fail2ban_ban",
            target=ban["ip"],
            seconds=duration,
            until=ban.get("until", 0),
        )
        return {
            "ok": True,
            "status": 0,
            "message": f"Letiltva: {ban['ip']} ({ban['remaining']} mp)",
            "ip": ban["ip"],
            "until": ban.get("until", 0),
        }

    def _action_fail2ban_unban(self, data: dict) -> dict:
        gw = self.server.gateway
        ip = data.get("ip")
        if not isinstance(ip, str) or not ip.strip():
            raise ValueError("hiányzó IP-cím")
        ip = ip.strip()
        removed = gw.fail2ban.unban(ip)
        self._audit("fail2ban_unban", ip=ip, removed=removed)
        self._audit(
            "cli_fail2ban_unban", target=ip, removed=removed
        )
        if not removed:
            self._audit(
                "cli_action_failed",
                action="unban",
                target=ip,
                reason="not_banned",
            )
            message = f"Nem volt letiltva: {ip}"
        else:
            message = f"Feloldva: {ip}"
        return {
            "ok": True,
            "status": 0,
            "message": message,
            "removed": removed,
        }

    def _action_fail2ban_unban_all(self, data: dict) -> dict:
        gw = self.server.gateway
        removed = gw.fail2ban.unban_all()
        self._audit("fail2ban_unban", removed=removed)
        self._audit("cli_fail2ban_unban", removed=removed)
        return {
            "ok": True,
            "status": 0,
            "message": f"Feloldva: {removed} tiltás",
            "removed": removed,
        }

    def _action_status(self, data: dict) -> dict:
        """Diagnosztika; soha nem tartalmaz jelszót, hasht, tokent."""
        gw = self.server.gateway
        names = gw.users.names()
        try:
            f2b = gw.fail2ban.status()
        except Exception:
            f2b = {}
        return {
            "ok": True,
            "status": 0,
            "message": "A démon elérhető.",
            "user_count": len(names),
            "user_names": names,
            "sessions": gw.sessions.count(),
            "authorized_sessions": gw.sessions.count(authorized_only=True),
            "banned_count": int(f2b.get("banned", 0) or 0),
            "fail2ban_enabled": bool(f2b.get("enabled", False)),
        }

    _ACTIONS = {
        "user.add": _action_user_add,
        "user.passwd": _action_user_passwd,
        "user.del": _action_user_del,
        "user.totp_reset": _action_user_totp_reset,
        "fail2ban.ban": _action_fail2ban_ban,
        "fail2ban.unban": _action_fail2ban_unban,
        "fail2ban.unban_all": _action_fail2ban_unban_all,
        "status": _action_status,
    }


class ControlServer(socketserver.ThreadingUnixStreamServer):
    """Helyi, csak ugyanazon uid által elérhető vezérlőcsatorna."""

    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True

    def __init__(self, address: str, gw: gateway.Gateway) -> None:
        self.gateway = gw
        self._closed = False
        self._socket_ino: int | None = None
        self._thread: threading.Thread | None = None
        parent = os.path.dirname(os.path.abspath(address)) or "."
        parent_error = _dir_security_error(parent)
        if parent_error is not None:
            raise ControlUnavailable(
                f"a vezérlőcsatorna könyvtára nem biztonságos "
                f"({parent}): {parent_error}"
            )
        self._prepare_path(address)
        # A bind és a chmod közötti rövid ablakban se legyen szélesebb a
        # jogosultság; utána kifejezetten 0600-ra állítjuk.
        old_umask = os.umask(0o177)
        try:
            super().__init__(address, ControlHandler)
        finally:
            os.umask(old_umask)
        try:
            # A bind után ellenőrizzük, hogy valóban a mi socketünk van az
            # útvonalon, és csak utána módosítjuk a jogosultságát.
            state = os.lstat(address)
            if not stat.S_ISSOCK(state.st_mode):
                raise ControlUnavailable(
                    "a bind után az útvonal nem socket"
                )
            self._socket_ino = int(state.st_ino)
            os.chmod(address, 0o600)
            after = os.lstat(address)
            if (
                not stat.S_ISSOCK(after.st_mode)
                or after.st_ino != self._socket_ino
            ):
                raise ControlUnavailable(
                    "a socket a bind után kicserélődött"
                )
        except (OSError, ControlUnavailable) as exc:
            try:
                super().server_close()
            finally:
                self._unlink_socket()
            if isinstance(exc, ControlUnavailable):
                raise
            raise ControlUnavailable(
                "a vezérlőcsatorna jogosultságát nem sikerült beállítani: "
                f"{exc}"
            ) from exc

    @staticmethod
    def _prepare_path(address: str) -> None:
        """Elavult socket eltávolítása; idegen fájlhoz nem nyúlunk."""
        try:
            state = os.lstat(address)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ControlUnavailable(
                f"a(z) {address} állapota nem vizsgálható: {exc}"
            ) from exc
        if not stat.S_ISSOCK(state.st_mode):
            raise ControlUnavailable(
                f"a(z) {address} létezik, de nem socket; nem törlöm"
            )
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.5)
        try:
            probe.connect(address)
        except (ConnectionRefusedError, FileNotFoundError):
            # Elavult socket: a bind előtt biztonságosan eltávolítható.
            try:
                os.unlink(address)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise ControlUnavailable(
                    f"az elavult socketet nem sikerült eltávolítani: {exc}"
                ) from exc
            return
        except OSError as exc:
            raise ControlUnavailable(
                f"a(z) {address} állapota nem dönthető el: {exc}"
            ) from exc
        finally:
            probe.close()
        raise ControlUnavailable(
            f"a(z) {address} már használatban van (fut egy másik démon?)"
        )

    def start(self) -> threading.Thread:
        if self._thread is None:
            self._thread = threading.Thread(
                target=self.serve_forever,
                name="hv-control",
                daemon=True,
            )
            self._thread.start()
        return self._thread

    def stop(self) -> None:
        thread = self._thread
        if thread is not None and thread.is_alive():
            self.shutdown()
            thread.join(timeout=5)
        self.server_close()

    def server_close(self) -> None:
        """Idempotens lezárás: a socketfájlt is eltávolítja."""
        if self._closed:
            return
        self._closed = True
        try:
            super().server_close()
        finally:
            self._unlink_socket()

    def _unlink_socket(self) -> None:
        try:
            state = os.lstat(self.server_address)
        except FileNotFoundError:
            return
        except OSError as exc:
            print(
                f"[control] a socket eltávolítása nem sikerült: {exc}",
                file=sys.stderr,
                flush=True,
            )
            return
        # Csak a saját socketünket töröljük, és csak ha azóta nem cserélték
        # ki egy másik folyamatéra.
        if not stat.S_ISSOCK(state.st_mode):
            return
        if (
            self._socket_ino is not None
            and state.st_ino != self._socket_ino
        ):
            return
        try:
            os.unlink(self.server_address)
        except FileNotFoundError:
            pass
        except OSError as exc:
            print(
                f"[control] a socket eltávolítása nem sikerült: {exc}",
                file=sys.stderr,
                flush=True,
            )


def _start_control_server(gw: gateway.Gateway) -> ControlServer | None:
    path = _control_socket_path()
    directory = _control_dir_path()
    state_dir = gateway.STATE_DIR
    # A STATE_DIR az állapotfájlok (felhasználók, audit, fail2ban, PID) és a
    # vezérlőkönyvtár szülője. Ha mások írhatják, a socket/pidfile
    # helyettesíthető, ezért ott nem indítunk vezérlőcsatornát.
    state_error = _dir_security_error(state_dir, follow_symlinks=True)
    if state_error is not None:
        print(
            f"FIGYELEM: a(z) {state_dir} állapotkönyvtár nem biztonságos "
            f"({state_error}); a helyi vezérlőcsatorna nem indul el, a "
            "portál tovább működik. Amíg a démon fut, a CLI-módosítások "
            "helyi végrehajtását a PID-fájl miatt megtagadjuk; használd "
            "az admin felületet.",
            file=sys.stderr,
            flush=True,
        )
        return None
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as exc:
        print(
            f"FIGYELEM: a vezérlőcsatorna könyvtára nem hozható létre "
            f"({directory}): {exc}",
            file=sys.stderr,
            flush=True,
        )
        return None
    # A könyvtárat fd-en keresztül, symlink követése nélkül ellenőrizzük és
    # szigorítjuk 0700-ra; a meglévő, idegen tulajdonú könyvtárat nem
    # használjuk.
    try:
        dir_fd = os.open(
            directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
    except OSError as exc:
        print(
            f"FIGYELEM: a vezérlőcsatorna könyvtára nem biztonságos "
            f"({directory}): {exc}",
            file=sys.stderr,
            flush=True,
        )
        return None
    try:
        state = os.fstat(dir_fd)
        if state.st_uid not in (0, os.geteuid()):
            print(
                f"FIGYELEM: a vezérlőcsatorna könyvtárának tulajdonosa "
                f"uid {state.st_uid} ({directory}); nem indul el.",
                file=sys.stderr,
                flush=True,
            )
            return None
        if stat.S_IMODE(state.st_mode) != 0o700:
            try:
                os.fchmod(dir_fd, 0o700)
            except OSError as exc:
                print(
                    f"FIGYELEM: a vezérlőcsatorna könyvtárának "
                    f"jogosultságát nem sikerült 0700-ra állítani "
                    f"({directory}): {exc}",
                    file=sys.stderr,
                    flush=True,
                )
                return None
    finally:
        os.close(dir_fd)
    dir_error = _dir_security_error(directory)
    if dir_error is not None:
        print(
            f"FIGYELEM: a vezérlőcsatorna könyvtára nem biztonságos "
            f"({directory}): {dir_error}; nem indul el.",
            file=sys.stderr,
            flush=True,
        )
        return None
    try:
        control = ControlServer(path, gw)
    except (ControlUnavailable, OSError) as exc:
        print(
            f"FIGYELEM: a helyi vezérlőcsatorna nem indult el "
            f"({path}): {exc}",
            file=sys.stderr,
            flush=True,
        )
        return None
    control.start()
    print(
        f"Vezérlőcsatorna: {path} (helyi, 0600)", flush=True
    )
    return control


# ------------------------------------- vezérlőcsatorna: kliensoldal (CLI)


def _control_request(
    payload: dict, timeout: float | None = None
) -> dict:
    """Egy kérés a helyi vezérlőcsatornán.

    ``ControlUnavailable``: a kérés el sem indult (nincs socket, kapcsolódási
    vagy socket-létrehozási hiba); ilyenkor a CLI a helyi műveletre eshet
    vissza. ``ControlAmbiguous``: a kérés elküldése után timeout/IO/EOF
    történt, tehát nem tudjuk, végrehajtotta-e a démon; helyi módosítás
    TILOS. ``ControlProtocolError``: a kérés elküldve, de a válasz
    érvénytelen; szintén tilos a helyi módosítás.
    """
    if timeout is None:
        # Ne a függvény definíciójakor rögzítsük: a tesztek és a hívók
        # később is felülírhatják a konstansot.
        timeout = CONTROL_CLI_TIMEOUT
    path = _control_socket_path()
    try:
        state = os.stat(path)
    except FileNotFoundError as exc:
        raise ControlUnavailable("nincs vezérlőcsatorna") from exc
    except OSError as exc:
        raise ControlUnavailable(
            f"a vezérlőcsatorna nem vizsgálható: {exc}"
        ) from exc
    if not stat.S_ISSOCK(state.st_mode):
        raise ControlUnavailable("az útvonal nem socket")
    if stat.S_IMODE(state.st_mode) & 0o077:
        # Jelszó csak 0600 socketen mehet át.
        raise ControlUnavailable(
            "a vezérlőcsatorna jogosultsága nem 0600"
        )

    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
    except OSError as exc:
        if sock is not None:
            sock.close()
        raise ControlUnavailable(
            f"a vezérlőcsatorna socket nem hozható létre: {exc}"
        ) from exc
    try:
        try:
            sock.connect(path)
        except FileNotFoundError as exc:
            raise ControlUnavailable("nincs vezérlőcsatorna") from exc
        except ConnectionRefusedError as exc:
            raise ControlUnavailable(
                "a vezérlőcsatorna nem fogad kapcsolatot "
                "(elavult socket)"
            ) from exc
        except PermissionError as exc:
            raise ControlUnavailable(
                "nincs jogosultság a vezérlőcsatornához"
            ) from exc
        except socket.timeout as exc:
            raise ControlUnavailable(
                "időtúllépés a vezérlőcsatorna csatlakoztatásakor"
            ) from exc
        except OSError as exc:
            raise ControlUnavailable(
                f"a vezérlőcsatorna nem érhető el: {exc}"
            ) from exc

        peer = _control_peer_uid(sock)
        if peer is not None and peer != os.geteuid():
            raise ControlProtocolError(
                "a vezérlőcsatorna tulajdonosa nem azonos a hívóval"
            )

        # Innentől a kérés elküldése megkezdődhet: minden hiba legfeljebb
        # bizonytalan kimenetelű, ezért nem eshetünk vissza helyi módra.
        try:
            body = (
                json.dumps(
                    payload, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
                + b"\n"
            )
            sock.sendall(body)
        except socket.timeout as exc:
            raise ControlAmbiguous(
                "időtúllépés a kérés küldésekor; a kérés részben vagy "
                "egészben elküldve lehet"
            ) from exc
        except OSError as exc:
            raise ControlAmbiguous(
                f"küldési hiba a vezérlőcsatornán: {exc}"
            ) from exc

        chunks: list[bytes] = []
        total = 0
        complete = False
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > CONTROL_MAX_REQUEST:
                    raise ControlProtocolError(
                        "túl nagy válasz a vezérlőcsatornán"
                    )
                if b"\n" in chunk:
                    complete = True
                    break
        except socket.timeout as exc:
            raise ControlAmbiguous(
                "időtúllépés a vezérlőcsatorna válaszára; a kérés "
                "elküldve, a válasz nem érkezett meg"
            ) from exc
        except OSError as exc:
            raise ControlAmbiguous(
                f"olvasási hiba a vezérlőcsatornán: {exc}"
            ) from exc
    finally:
        sock.close()

    raw = b"".join(chunks)
    if not complete:
        # A szerver mindig új sorral zárja a választ. Ha a kapcsolat a
        # válasz közben szakadt meg, nem tudjuk, mi történt.
        raise ControlAmbiguous(
            "a vezérlőcsatorna válasza megszakadt vagy üres lett"
        )
    line = raw.split(b"\n", 1)[0]
    try:
        response = json.loads(line)
    except ValueError as exc:
        raise ControlProtocolError(
            "érvénytelen JSON válasz a vezérlőcsatornán"
        ) from exc
    if not isinstance(response, dict):
        raise ControlProtocolError(
            "érvénytelen válasz a vezérlőcsatornán"
        )
    return response


def _control_attempt(payload: dict) -> tuple[dict | None, str | None]:
    """(válasz, None) vagy (None, az elérhetetlenség oka)."""
    try:
        return _control_request(payload), None
    except ControlUnavailable as exc:
        return None, str(exc)


def _print_control_response(response: dict) -> int:
    ok = bool(response.get("ok"))
    status = response.get("status")
    if isinstance(status, bool) or not isinstance(status, int):
        status = 0 if ok else 1
    if ok:
        message = response.get("message")
        if isinstance(message, str) and message:
            print(message)
    else:
        error = response.get("error")
        if not isinstance(error, str) or not error:
            error = "a démon hibát jelzett"
        if response.get("stdout"):
            print(error)
        else:
            print(f"hiba: {error}", file=sys.stderr)
    return status if status >= 0 else 1


def _warn_control_fallback(reason: str | None) -> None:
    path = _control_socket_path()
    print(
        f"FIGYELEM: a vezérlőcsatorna ({path}) nem érhető el: "
        f"{reason or 'ismeretlen ok'}.",
        file=sys.stderr,
        flush=True,
    )
    print(
        "FIGYELEM: a módosítás csak helyben (lemezen/kernelben) történt "
        "meg; a futó démon élő munkameneteit NEM vonta vissza.",
        file=sys.stderr,
        flush=True,
    )


def _read_server_pid() -> int | None:
    """A futó démon PID-je a PID-fájlból, ha az hitelesnek tűnik."""
    path = _server_pid_path()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        print(
            f"FIGYELEM: a démon PID-fájlja nem olvasható ({path}): {exc}",
            file=sys.stderr,
            flush=True,
        )
        return None
    try:
        state = os.fstat(fd)
        if not stat.S_ISREG(state.st_mode):
            return None
        if state.st_uid not in (0, os.geteuid()):
            return None
        # A PID-fájlt a démon 0600-ra írja; csoport/más által írható
        # fájlból nem fogadunk el PID-et.
        if state.st_mode & 0o077:
            return None
        data = os.read(fd, 64)
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        pid = int(data.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        return None
    if pid <= 0:
        return None
    return pid


def _pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # A folyamat létezik, csak más felhasználóé.
        return True
    except OSError:
        return False
    return True


def _live_daemon_pid() -> int | None:
    """A démon PID-je, ha a PID-fájl szerint még fut; különben None."""
    pid = _read_server_pid()
    if pid is not None and _pid_is_alive(pid):
        return pid
    return None


def _control_mutation(payload: dict) -> tuple[bool, int]:
    """Megpróbálja a démonon végrehajtani a műveletet.

    Visszatérés: ``(True, kilépési_kód)``, ha a démon válaszolt vagy a
    kimenetel bizonytalan (hiba esetén is; ilyenkor nem szabad helyben is
    módosítani), ``(False, 0)``, ha a csatorna a kérés elküldése előtt nem
    volt elérhető, és nincs futó démon, ezért a helyi művelet következik.
    """
    try:
        response, reason = _control_attempt(payload)
    except ControlAmbiguous as exc:
        print(
            "hiba: a kérés elküldve, de a válasz nem érkezett meg; "
            "NEM futtattam helyi módosítást, ellenőrizd a listát "
            f"({exc}).",
            file=sys.stderr,
            flush=True,
        )
        return True, 1
    except ControlProtocolError as exc:
        print(
            f"hiba: a vezérlőcsatorna érvénytelen választ adott: {exc}; "
            "NEM futtattam helyi módosítást, ellenőrizd a listát.",
            file=sys.stderr,
            flush=True,
        )
        return True, 1
    if response is not None:
        return True, _print_control_response(response)
    pid = _live_daemon_pid()
    if pid is not None:
        print(
            f"hiba: a vezérlőcsatorna nem érhető el "
            f"({reason or 'ismeretlen ok'}), de a démon fut "
            f"(PID {pid}).",
            file=sys.stderr,
            flush=True,
        )
        print(
            "hiba: a helyi módosítást biztonsági okból NEM futtattam, "
            "mert a futó démon élő munkamenetei és tűzfalállapota "
            "eltérne a lemeztől. Használd az admin felületet, vagy "
            "állítsd le a démont.",
            file=sys.stderr,
            flush=True,
        )
        return True, 1
    _warn_control_fallback(reason)
    return False, 0


def _daemon_user_names() -> list[str] | None:
    """Csak olvasás: a démon authoritative felhasználólistája, ha elérhető."""
    try:
        response, _reason = _control_attempt({"action": "status"})
    except (ControlAmbiguous, ControlProtocolError):
        # Olvasásnál a helyi lista elfogadható, de a hívó tudja, hogy a
        # démon állapota bizonytalan.
        return None
    if response is None or not response.get("ok"):
        return None
    names = response.get("user_names")
    if not isinstance(names, list) or not all(
        isinstance(name, str) for name in names
    ):
        return None
    return names


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


def _cli_audit(audit, event: str, **fields) -> None:
    """CLI-művelet naplózása; hiba esetén sem szakítja meg a parancsot."""
    fields.setdefault("actor", "cli")
    try:
        audit.write(event, **fields)
    except Exception as exc:
        print(
            f"[napló] {event} írása nem sikerült: {exc}",
            file=sys.stderr,
            flush=True,
        )


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
    groups = gateway.GroupStore()
    audit = gateway.AuditLog()

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
                if rule_id == gateway.LEGACY_ADMIN_RULE_ID:
                    raise gateway.UserStoreError(
                        "ez egy fenntartott, régi azonosító, nem rendelhető hozzá"
                    )
            handled, status = _control_mutation({
                "action": "user.add",
                "name": args.name,
                "password": password,
                "role": args.role,
                "rules": list(rules),
                "must_change_password": not args.no_must_change,
            })
            if handled:
                return status
            store.add(
                args.name, password,
                role=args.role,
                rules=rules,
                must_change_password=not args.no_must_change,
            )
            _cli_audit(
                audit,
                "cli_user_created",
                target=args.name,
                role=args.role,
                rules=",".join(rules),
                must_change_password=not args.no_must_change,
            )
            print(f"Felhasználó létrehozva: {args.name}")
        elif args.action == "passwd":
            password = _prompt_password(args.password_stdin)
            handled, status = _control_mutation({
                "action": "user.passwd",
                "name": args.name,
                "password": password,
                "must_change_password": not args.no_must_change,
            })
            if handled:
                return status
            store.set_password(
                args.name, password,
                must_change_password=not args.no_must_change,
            )
            _cli_audit(
                audit,
                "cli_password_changed",
                target=args.name,
                must_change_password=not args.no_must_change,
            )
            print(f"Jelszó frissítve: {args.name}")
        elif args.action == "del":
            handled, status = _control_mutation({
                "action": "user.del",
                "name": args.name,
            })
            if handled:
                return status
            if store.remove(args.name):
                # A helyi (démon nélküli) törlés is tisztázza a
                # csoporttagságot, ugyanúgy, mint az admin API.
                groups.remove_member_everywhere(args.name)
                _cli_audit(
                    audit, "cli_user_deleted", target=args.name
                )
                print(f"Felhasználó törölve: {args.name}")
            else:
                _cli_audit(
                    audit,
                    "cli_action_failed",
                    action="del",
                    target=args.name,
                    reason="nincs ilyen felhasználó",
                )
                print(f"Nincs ilyen felhasználó: {args.name}")
                return 1
        elif args.action == "totp-reset":
            handled, status = _control_mutation({
                "action": "user.totp_reset",
                "name": args.name,
            })
            if handled:
                return status
            if store.reset_totp(args.name):
                _cli_audit(
                    audit, "cli_totp_reset", target=args.name
                )
                print(f"2FA alaphelyzetbe állítva: {args.name}")
            else:
                _cli_audit(
                    audit,
                    "cli_action_failed",
                    action="totp-reset",
                    target=args.name,
                    reason="nincs ilyen felhasználó",
                )
                print(f"Nincs ilyen felhasználó: {args.name}")
                return 1
        elif args.action == "list":
            # Csak olvasás: a démon authoritative listáját használjuk, ha
            # elérhető; különben a helyi fájlból olvasunk (offline is működik).
            names = _daemon_user_names()
            if names is None:
                names = store.names()
            if not names:
                print("Nincs felhasználó. Létrehozás: server.py user add <név>")
                return 0
            for name in names:
                print(name)
    except gateway.UserStoreError as exc:
        _cli_audit(
            audit,
            "cli_action_failed",
            action=args.action,
            target=getattr(args, "name", ""),
            reason=str(exc),
        )
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
    audit = gateway.AuditLog()
    manager = fail2ban_mod.Fail2ban(gateway.Firewall(), audit=audit)
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
                f"Drop-alapú tiltás: {drop_state}; csomagküszöb: "
                f"{snapshot['drop_max']} "
                f"({'aktív' if snapshot['drop_count_active'] else 'kikapcsolva'}), "
                f"portküszöb: {snapshot['drop_ports']} "
                f"({'aktív' if snapshot['drop_ports_active'] else 'kikapcsolva'}) / "
                f"{snapshot['drop_window_seconds']} mp"
            )
            print(
                "Kapcsolók: "
                f"belépés={'be' if snapshot['enabled'] else 'ki'}, "
                f"csomagszám={'be' if snapshot['drop_count_enabled'] else 'ki'}, "
                f"portok={'be' if snapshot['drop_ports_enabled'] else 'ki'}."
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
            handled, status = _control_mutation({
                "action": "fail2ban.ban",
                "ip": args.ip,
                "seconds": args.seconds,
                "manual": True,
                "user": "cli",
            })
            if handled:
                return status
            ban = manager.ban(args.ip, args.seconds, manual=True, user="cli")
            seconds = max(
                0, int(ban.get("until", 0)) - int(ban.get("since", 0))
            )
            _cli_audit(
                audit,
                "fail2ban_ban",
                ip=ban["ip"],
                manual=True,
                source="cli",
                seconds=seconds,
                until=ban.get("until", 0),
            )
            _cli_audit(
                audit,
                "cli_fail2ban_ban",
                target=ban["ip"],
                seconds=seconds,
                until=ban.get("until", 0),
            )
            print(
                f"Letiltva: {ban['ip']} ({ban['remaining']} mp)"
            )
            return 0
        if args.action == "unban":
            handled, status = _control_mutation({
                "action": "fail2ban.unban",
                "ip": args.ip,
            })
            if handled:
                return status
            if manager.unban(args.ip):
                _cli_audit(
                    audit,
                    "fail2ban_unban",
                    ip=args.ip,
                    removed=True,
                )
                _cli_audit(
                    audit,
                    "cli_fail2ban_unban",
                    target=args.ip,
                    removed=True,
                )
                print(f"Feloldva: {args.ip}")
            else:
                _cli_audit(
                    audit,
                    "cli_action_failed",
                    action="unban",
                    target=args.ip,
                    reason="not_banned",
                )
                print(f"Nem volt letiltva: {args.ip}")
            return 0
        if args.action == "unban-all":
            handled, status = _control_mutation({
                "action": "fail2ban.unban_all",
            })
            if handled:
                return status
            removed = manager.unban_all()
            _cli_audit(
                audit, "fail2ban_unban", removed=removed
            )
            _cli_audit(
                audit, "cli_fail2ban_unban", removed=removed
            )
            print(f"Feloldva: {removed} tiltás")
            return 0
    except fail2ban_mod.Fail2banError as exc:
        _cli_audit(
            audit,
            "cli_action_failed",
            action=args.action,
            target=getattr(args, "ip", ""),
            reason=str(exc),
        )
        print(f"hiba: {exc}", file=sys.stderr)
        return 1
    return 2


def _serve() -> int:
    try:
        gw = gateway.Gateway()
    except gateway.CatalogError as exc:
        print(f"HIBA: {exc}", file=sys.stderr, flush=True)
        try:
            gateway.AuditLog().write(
                "service_start_failed", reason=str(exc)
            )
        except Exception as audit_exc:
            print(
                f"[napló] service_start_failed írása nem sikerült: "
                f"{audit_exc}",
                file=sys.stderr,
                flush=True,
            )
        return 1

    # A belépőjegyek életciklusa (kiadás/elutasítás/lejárat) is auditált.
    LOGIN_TICKETS.set_audit(gw.audit)

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
        f"Szabályok: {len(gw.rules.persisted_rules())} admin szabály, "
        f"{len(gw.groups.all_groups())} csoport",
        flush=True,
    )
    print(f"Napló: {gw.audit.path}", flush=True)
    print(
        f"Választható hozzáférés: {gateway.format_duration(gateway.MIN_TTL)}–"
        f"{gateway.format_duration(gateway.MAX_TTL)}; alapértelmezett: "
        f"{gateway.format_duration(gw.sessions.ttl)}",
        flush=True,
    )
    if gateway.PORTAL_URL:
        print(f"Kanonikus portálcím: {gateway.PORTAL_URL}", flush=True)

    gw.prepare()
    try:
        admin_state = gateway.provision_admin(gw.users)
    except gateway.UserStoreError as exc:
        print(f"FIGYELEM: az admin fiók beállítása sikertelen: {exc}", flush=True)
        gw._write_audit(
            "admin_provision_failed",
            user=gateway.ADMIN_USER,
            reason=str(exc),
        )
    else:
        gw._write_audit(
            "admin_provisioned",
            user=gateway.ADMIN_USER,
            action=admin_state,
        )
        if admin_state == "created":
            print(f"[admin] felhasználó létrehozva: {gateway.ADMIN_USER}", flush=True)
        elif admin_state == "updated":
            print(f"[admin] jelszó frissítve: {gateway.ADMIN_USER}", flush=True)
        elif admin_state == "unchanged":
            print(f"[admin] felhasználó rendben: {gateway.ADMIN_USER}", flush=True)

    def _admin_has_tcp22_host_rule() -> bool:
        """Van-e engedélyezett adminnak hatásos, TCP 22-es host szabálya."""
        for record in gw.users.details():
            if not (
                record.is_admin and record.enabled and not record.pending
            ):
                continue
            groups = gw.groups.groups_for(record.name)
            for rule in gw.rules.effective_for(record, groups):
                if any(
                    part.direction == "input" and 22 in part.tcp
                    for part in rule.grants
                ):
                    return True
        return False

    if not _admin_has_tcp22_host_rule():
        print(
            "FIGYELEM: egyetlen engedélyezett adminisztrátornak sincs "
            "hatásos, TCP 22-es host (input) szabálya, ezért a host SSH "
            "zárva marad.",
            flush=True,
        )
        print(
            "FIGYELEM: az admin a portálon hozzon létre egy host szabályt, "
            "amely kifejezetten a TCP 22-es portot engedélyezi, rendelje "
            "a felhasználóhoz (vagy egy csoporthoz), majd ugyanarról a "
            "forrás IP-ről engedélyezze egy aktív munkamenetben.",
            flush=True,
        )
        print(
            "FIGYELEM: biztonságos első indítás SSH-n keresztül: először "
            "HV_SKIP_FIREWALL=1 értékkel indítsd a konténert, állítsd be a "
            "szabályt és a hozzárendelést, majd indítsd újra normálisan. "
            "Alternatíva: tartsd nyitva a szolgáltatói konzolt.",
            flush=True,
        )

    if not any(
        record.is_admin and record.enabled and not record.pending
        for record in gw.users.details()
    ):
        print(
            "FIGYELEM: nincs engedélyezett admin fiók.",
            flush=True,
        )
        print(
            "FIGYELEM: a portál Admin panelje nem érhető el, és a host SSH "
            "csak aktív, engedélyezett portál-munkamenettel, valamint a "
            "22-es TCP-portot kifejezetten engedélyező host szabállyal "
            "nyílik meg.",
            flush=True,
        )
        print(
            "FIGYELEM: állítsd be a .env fájlban a HV_ADMIN_ENABLED=1, "
            "HV_ADMIN_USER, valamint a HV_ADMIN_PASSWORD vagy "
            "HV_ADMIN_PASSWORD_FILE értéket, majd indítsd újra a konténert.",
            flush=True,
        )

    if not gw.users.names():
        print(
            "FIGYELEM: nincs egyetlen felhasználó sem. "
            "Létrehozás: python3 server.py user add <név>",
            flush=True,
        )

    gw.start()
    # A futó démon helyi vezérlőcsatornája: a CLI-műveletek így ugyanabban
    # a folyamatban futnak, és a valódi (élő) munkameneteket is tudják
    # visszavonni. Ha nem indul el, a CLI a helyi módra esik vissza.
    control = _start_control_server(gw)
    server = AppServer(("0.0.0.0", gateway.PORT), gw)
    # A PID-fájl a vezérlőcsatorna után, de még a kiszolgálás előtt készül
    # el. A CLI ebből tudja, hogy a daemon él, ezért nem szabad helyben
    # módosítania, ha a socket épp nem érhető el.
    pid_inode = _write_server_pid()

    # A 2FA-jegyek takarítása: a ki nem használt (elhagyott) jegyek
    # lejáratát így legkésőbb 30 másodperccel a lejárat után naplózzuk.
    sweeper_stop = threading.Event()

    def _ticket_sweeper() -> None:
        while not sweeper_stop.wait(30):
            try:
                LOGIN_TICKETS.purge()
            except Exception as exc:  # a takarító soha ne haljon meg
                print(
                    f"[napló] jégytakarítási hiba: {exc}",
                    file=sys.stderr,
                    flush=True,
                )

    threading.Thread(
        target=_ticket_sweeper, name="hv-tickets", daemon=True
    ).start()

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
        sweeper_stop.set()
        if control is not None:
            try:
                control.stop()
            except Exception as exc:  # a leállás ne akadjon el
                print(
                    f"[control] a vezérlőcsatorna leállítása nem "
                    f"sikerült: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
        server.server_close()
        LOGIN_TICKETS.revoke_all(reason="service_stop")
        try:
            gw.stop()
        finally:
            _remove_server_pid(pid_inode)
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
