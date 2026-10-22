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
import base64
import copy
import getpass
import hashlib
import hmac
import html
import http.client
import io
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import socketserver
import stat
import struct
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
from dataclasses import dataclass
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import gateway
import fail2ban as fail2ban_mod
import settings_store
import tunnel as tunnel_mod

BASE = os.path.dirname(os.path.abspath(__file__))

STATIC_FILES = {
    "index.html": ("text/html; charset=utf-8", "no-store"),
    "icon.png": ("image/png", "public, max-age=3600"),
    "blocked.png": ("image/png", "public, max-age=3600"),
    "unauthorized.png": ("image/png", "public, max-age=3600"),
    "sus.png": ("image/png", "public, max-age=3600"),
    "ok.png": ("image/png", "public, max-age=3600"),
}

# A proxy-végpontokat csak a hoston futó Caddy hívhatja (a nyers socket
# peer, nem az X-Forwarded-For alapján; lásd _peer_ip).
PROXY_LOOPBACK = ("127.0.0.1", "::1")
# A többes naplószűrő elemei: az eseménykódok alakja (kisbetű, számjegy, _).
AUDIT_EVENT_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")

# A 80-as port átirányításának Hostja: hostnév/IPv4 vagy [IPv6], opcionális
# porttal; minden más (CRLF, szóköz, userinfo, %-scope) érvénytelen.
_REDIRECT_HOST_RE = re.compile(
    r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}"
    r"[a-z0-9])?|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?"
)

# A proxy tiltó- és challenge-oldala közös váz; a {mező} helyőrzőket a
# _proxy_page tölti ki. Látható szöveg nincs: az állapotot ikon jelzi.
PROXY_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:system-ui,sans-serif;background:#111418;color:#e8eaed;text-align:center}
main{max-width:420px;padding:24px}
img{display:block;width:min(320px,80vw);height:auto;margin:0 auto}
a.login{display:flex;width:max-content;align-items:center;justify-content:center;margin:20px auto 0;
padding:12px 18px;border-radius:8px;background:#2f6fde;color:#fff;text-decoration:none}
a.login:hover{background:#3f7cea}
a.login:focus-visible{outline:3px solid #9fc3ff;outline-offset:2px}
{style}</style></head><body><main>
<img src="/__dropjak/{image}" alt="">
{body}
</main></body></html>
"""
_PROXY_PAGE_FIELD = re.compile(r"\{(title|style|image|body)\}")

# Belépés gomb: nyíl az ajtón át; a szöveget az aria-label adja.
PROXY_LOGIN_ICON = """<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
<path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h8"/>
<path d="M10 12h11"/>
<path d="m18 8 4 4-4 4"/>
</svg>"""


def _proxy_page(**values: str) -> bytes:
    # Egyetlen menet: a beillesztett CSS/JS kapcsos zárójelei érintetlenek.
    return _PROXY_PAGE_FIELD.sub(
        lambda match: values.get(match.group(1), ""), PROXY_PAGE
    ).encode("utf-8")


# A challenge-oldal a belépőoldal captcha-modulját használja: a stílusát és
# az SHA-256 PoW-kódját az index.html-ből emeljük ki (egyszer, lustán).
_CAPTCHA_CSS_LINE = re.compile(
    r'^\s*(?::root\[data-theme="dark"\] )?'
    r"(?:\.captcha|\.box|\.bar|\.spinner|#turnstile|@keyframes spin)\b.*$",
    re.M,
)
_captcha_assets: tuple[str, str] | None = None


def _captcha_assets_from_index() -> tuple[str, str]:
    global _captcha_assets
    if _captcha_assets is None:
        with open(os.path.join(BASE, "index.html"), encoding="utf-8") as fh:
            source = fh.read()
        style = source[source.index("<style>"):source.index("</style>")]
        # Az oldal mindig sötét: a sötét téma szabályai feltétel nélküliek.
        css = "\n".join(
            m.group(0).strip().replace(':root[data-theme="dark"] ', "")
            for m in _CAPTCHA_CSS_LINE.finditer(style)
        )
        start = source.index("const sha256 = (() => {")
        end = source.index("  return { matches };\n})();", start)
        _captcha_assets = css, source[start:end] + "  return { matches };\n})();"
    return _captcha_assets


PROXY_CHALLENGE_STYLE = """:root{--line-strong:#3b414b;--green:#7ecf8e;--ink:#e9e9e4;--muted:#9b9d99}
.captcha,#turnstile{max-width:300px;margin:16px auto 0;text-align:left}
main>img{position:relative;left:-8px}
#msg{min-height:1.5em;color:#ee8b8b}
"""

PROXY_CHALLENGE_SCRIPT = """
const CFG = __CFG__;
const slot = document.getElementById('slot');
const msg = document.getElementById('msg');
const show = text => { msg.textContent = text; };
async function verify(captcha) {
  const res = await fetch('/__dropjak/challenge', {
    method: 'POST', cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ captcha })
  });
  if (res.ok) {
    // Ismeretlen aldomainről a gyökérdomainre visz; a bejegyzés újratölt.
    const data = await res.json().catch(() => ({}));
    if (data.redirect) location.href = data.redirect; else location.reload();
    return;
  }
  const data = await res.json().catch(() => ({}));
  const error = new Error('Verification failed.');
  error.shown = true;
  throw error;
}
if (CFG.mode === 'turnstile') {
  slot.innerHTML = '<div id="turnstile"></div>';
  const s = document.createElement('script');
  s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
  s.async = true;
  s.onload = () => window.turnstile.render('#turnstile', {
    sitekey: CFG.sitekey, theme: 'dark', language: 'en',
    callback: token => verify({ token }).catch(e => {
      show(e.shown ? e.message : 'Verification failed.');
      try { window.turnstile.reset('#turnstile'); } catch (_) { /* nincs widget */ }
    }),
    'error-callback': () => show('The captcha could not load. Reload the page.')
  });
  s.onerror = () => show('The captcha could not load (network).');
  document.head.appendChild(s);
} else {
  slot.innerHTML = `
    <div class="captcha">
      <div class="captcha-inner" id="powbox" role="checkbox" aria-checked="false" tabindex="0">
        <span class="box">
          <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3.4"
               stroke-linecap="round" stroke-linejoin="round"><path d="M4 12.5 9.5 18 20 6.5"/></svg>
        </span>
        <span class="spinner"></span>
        <span class="captcha-text" id="powtext">I'm not a robot</span>
      </div>
      <div class="bar"><i id="powbar"></i></div>
    </div>`;
  const box = document.getElementById('powbox');
  const text = document.getElementById('powtext');
  const bar = document.getElementById('powbar');
  // A belépőoldal startPow() ciklusa, a megoldás után azonnali beküldéssel.
  const start = async () => {
    if (box.dataset.state === 'busy' || box.dataset.state === 'done') return;
    box.dataset.state = 'busy';
    text.textContent = 'Checking…';
    show('');
    try {
      const res = await fetch('/__dropjak/challenge', { cache: 'no-store' });
      const ch = await res.json();
      if (ch.mode !== 'pow') throw new Error('mód-váltás');
      const difficulty = Number(ch.difficulty);
      if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 6) {
        throw new Error('érvénytelen nehézség');
      }
      const saltBytes = new TextEncoder().encode(ch.salt);
      const expected = Math.pow(16, difficulty) / 2;
      const limit = Math.max(2_000_000, expected * 60);
      let n = 0;
      let found = -1;
      for (;;) {
        const end = n + 2000;
        for (; n < end; n++) {
          if (sha256.matches(saltBytes, String(n), difficulty)) { found = n; break; }
        }
        const done = found >= 0;
        bar.style.width = (done ? 100 : Math.min(96, (n / expected) * 100)).toFixed(1) + '%';
        if (done) break;
        if (n > limit) throw new Error('túl hosszú számítás');
        await new Promise(r => setTimeout(r, 0));
      }
      box.dataset.state = 'done';
      box.setAttribute('aria-checked', 'true');
      text.textContent = 'Verified';
      await verify({ ...ch, number: found });
    } catch (e) {
      box.dataset.state = '';
      box.setAttribute('aria-checked', 'false');
      text.textContent = "I'm not a robot";
      bar.style.width = '0%';
      show(e.shown ? e.message : 'Verification could not start. Try again.');
    }
  };
  box.addEventListener('click', start);
  box.addEventListener('keydown', e => {
    if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); start(); }
  });
}
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



def _proxy_challenge_page() -> bytes:
    css, sha256_js = _captcha_assets_from_index()
    config = (
        {"mode": "turnstile", "sitekey": gateway.TURNSTILE_SITEKEY}
        if gateway.TURNSTILE_ON else {"mode": "pow"}
    )
    script = PROXY_CHALLENGE_SCRIPT.replace(
        "__CFG__", json.dumps(config).replace("<", "\\u003c")
    )
    return _proxy_page(
        title="Dropjak",
        image="sus.png",
        style=css + "\n" + PROXY_CHALLENGE_STYLE,
        body=(
            '<div id="slot"></div>\n<p id="msg" role="alert"></p>\n'
            f"<script>\n{sha256_js}\n{script}</script>"
        ),
    )


# A proxy challenge belépője: __Host- süti a bejegyzés hostján, értéke
# base64url(host|ip vagy *|kiadva ms|lejár s).HMAC-SHA256. A kulcs folyamatonként
# új (mint a PoW-kulcs): újraindítás után minden belépő érvénytelen.
PROXY_PASS_COOKIE = "__Host-dropjak_pass"
PROXY_PASS_TTL = 24 * 3600
_PROXY_PASS_KEY = secrets.token_bytes(32)
_CLI_AGENT_RE = re.compile(
    r"^(?:curl|wget|python-|python/|go-http-client|libwww-perl|httpie|okhttp"
    r"|java/|aiohttp|axios|node-fetch|undici|powershell|scrapy)",
    re.I,
)


# A "burst" feltétel (sok frissítés / spam): ugyanarról az IP-ről ugyanarra a
# hostra ennyi oldalmegnyitás ennyi másodpercen belül. Folyamatonként a
# memóriában (mint a belépő kulcsa), újraindításkor törlődik.
PROXY_BURST_LIMIT = 10
PROXY_BURST_WINDOW = 30
PROXY_BURST_MAX_KEYS = 10000
_PROXY_BURST: dict[tuple[str, str], tuple[list[float], float]] = {}
_PROXY_BURST_LOCK = threading.Lock()


def _proxy_burst(ip: str, host: str, now: float, count: bool) -> float:
    """A legutóbbi spam-észlelés ideje az IP+hostra (0: nem volt).

    ``count``: ez a kérés oldalmegnyitás, beleszámít. A határ elérésekor az
    észlelés ideje frissül és a számláló nullázódik.
    """
    key = (ip, host)
    with _PROXY_BURST_LOCK:
        hits, flagged = _PROXY_BURST.get(key, ([], 0.0))
        if not count:
            return flagged
        hits = [t for t in hits if now - t < PROXY_BURST_WINDOW] + [now]
        if len(hits) >= PROXY_BURST_LIMIT:
            hits, flagged = [], now
        if key not in _PROXY_BURST and len(_PROXY_BURST) >= PROXY_BURST_MAX_KEYS:
            for old in [k for k, (h, f) in _PROXY_BURST.items()
                        if not f and (not h or now - h[-1] >= PROXY_BURST_WINDOW)]:
                del _PROXY_BURST[old]
            if len(_PROXY_BURST) >= PROXY_BURST_MAX_KEYS:
                # shortcut: tele táblánál minden észlelés elvész; LRU kell, ha
                # a valós forgalom eléri a 10 000 IP+host párt.
                _PROXY_BURST.clear()
        _PROXY_BURST[key] = (hits, flagged)
        return flagged


def _portal_parent_root(portal: str, roots) -> str:
    """A Dropjak-cím gyökérdomainje; a mentés ezt garantálja, de futásidejű
    állapotból is biztonságosan ""-t ad, ha nincs."""
    return next((root for root in roots if portal.endswith("." + root)), "")


def _tunnel_domain_target(settings: dict, host: str):
    """Egy domaines alagút-szolgáltatás szintetikus proxy-célja és gyökere.

    Csak bekapcsolt ügynök bekapcsolt szolgáltatása oldódik fel. A Caddy a
    ``10.77.0.2:<belső port>`` címre továbbít; az ügynök a wg0 felől DNAT-ol
    a szolgáltatás konténerére. Nincs WAN-port és nincs WAN-DNAT.
    """
    if not host:
        return None
    roots = settings.get("proxy_domains", [])
    # A leghosszabb illeszkedő gyökér nyer (a mentés ezt garantálja).
    root = max(
        (item for item in roots if host.endswith("." + item)),
        key=len, default="",
    )
    if not root:
        return None
    tunnels = settings.get("tunnels")
    if not isinstance(tunnels, dict):
        return None
    for agent in tunnels.get("agents", []):
        if not isinstance(agent, dict) or not agent.get("enabled", True):
            continue
        for service in agent.get("services", []):
            if not isinstance(service, dict):
                continue
            if not service.get("enabled", True):
                continue
            if service.get("domain", "") != host:
                continue
            try:
                ports = settings_store.tunnel_service_ports(service)
            except settings_store.SettingsError:
                return None
            if len(ports) != 1:
                return None
            return {
                "type": "forward",
                "ip": agent.get("address", ""),
                "port": ports[0]["tunnel_port"],
                "visibility": (
                    "public" if service.get("public") else "private"
                ),
                "enabled": True,
                "tunnel": True,
                **({"challenge": service["challenge"]}
                   if service.get("challenge") else {}),
            }, root
    return None


def _proxy_pass_lifetime(challenge: dict) -> int:
    if "interval" in challenge["triggers"]:
        return challenge["interval_hours"] * 3600
    return PROXY_PASS_TTL


def _proxy_pass_sign(payload: bytes) -> bytes:
    return hmac.new(_PROXY_PASS_KEY, payload, hashlib.sha256).hexdigest().encode()


def _proxy_pass_value(host: str, ip: str, issued: float, expires: int) -> str:
    # Ezredmásodperc, lefelé kerekítve: a belépő sosem tűnik későbbinek.
    payload = f"{host}|{ip or '*'}|{int(issued * 1000)}|{expires}".encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    return f"{encoded}.{_proxy_pass_sign(payload).decode()}"


def _proxy_pass_issued(value: str, host: str, ip: str, now: float) -> float:
    """Az érvényes belépő kiadási ideje; 0, ha hiányzik, hamis, lejárt vagy
    más hosté. Üres ``ip``: a belépő IP-től függetlenül érvényes."""
    encoded, _, signature = value.partition(".")
    try:
        payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if not hmac.compare_digest(
            _proxy_pass_sign(payload), signature.encode()
        ):
            return 0.0
        pass_host, pass_ip, issued, expires = payload.decode().split("|")
        issued_at, expires_at = int(issued) / 1000, int(expires)
    except ValueError:
        return 0.0
    if pass_host != host or (ip and pass_ip != ip) \
            or not issued_at <= now < expires_at:
        return 0.0
    return issued_at


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


# ------------------------------------------------------------ konfigurációs csomag

CONFIG_FORMAT = "dropjak-config"
# 2: a settings szakasz tunnels (WireGuard-alagút) részt is tartalmaz. Az
# 1. verziójú csomagokat továbbra is elfogadjuk: a hiányzó tunnels szakaszt
# alapértelmezéssel töltjük ki (nincs ügynök, a WireGuard port zárva).
CONFIG_FORMAT_VERSION = 2
CONFIG_FORMAT_MIN_VERSION = 1
CONFIG_MAX_BYTES = 8 * 1024 * 1024
CONFIG_SECTIONS = ("settings", "rules", "groups", "users", "certs", "fail2ban")
_FAIL2BAN_CONFIG_KEYS = frozenset({
    "enabled", "max_attempts", "window_seconds", "ban_seconds",
    "drop_enabled", "drop_count_enabled", "drop_ports_enabled",
    "drop_max", "drop_ports", "drop_window_seconds",
    "proxy_enabled", "proxy_max", "proxy_window_seconds",
})


class ConfigBundleError(ValueError):
    """A konfigurációs csomag érvénytelen vagy nem támogatott."""


def _fail2ban_config(snapshot: dict) -> dict:
    """Csak a beállítások, tiltások és számlálók nélkül."""
    return {key: snapshot[key] for key in _FAIL2BAN_CONFIG_KEYS}


def _config_bundle(gw) -> dict:
    """A teljes, exportálható konfiguráció (naplók és futásidejű állapot nélkül)."""
    try:
        settings = gw.settings.snapshot()
        error = settings.pop("error", "")
        if error:
            raise ConfigBundleError(f"a beállításfájl hibás: {error}")
        settings = settings_store.validate_state(settings)
        sections = {
            "settings": settings,
            "rules": gw.rules.export_records(),
            "groups": gw.groups.export_records(),
            "users": gw.users.export_records(),
            "certs": gw.certs.export_all(),
            "fail2ban": _fail2ban_config(gw.fail2ban.snapshot()),
        }
    except ConfigBundleError:
        raise
    except (
        settings_store.SettingsError,
        gateway.RuleStoreError,
        gateway.GroupStoreError,
        gateway.UserStoreError,
        fail2ban_mod.Fail2banError,
        OSError,
        ValueError,
    ) as exc:
        raise ConfigBundleError(str(exc)) from exc
    return {
        "format": CONFIG_FORMAT,
        "format_version": CONFIG_FORMAT_VERSION,
        "app_version": gateway.APP_VERSION,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sections": sections,
    }


def _validate_config_bundle(gw, bundle) -> dict:
    """A teljes csomag ellenőrzése írás nélkül; a normalizált szakaszokat adja."""
    if not isinstance(bundle, dict):
        raise ConfigBundleError("a csomag JSON-objektum kell")
    if bundle.get("format") != CONFIG_FORMAT:
        raise ConfigBundleError("ez nem Dropjak konfigurációs csomag")
    version = bundle.get("format_version")
    if isinstance(version, bool) or not isinstance(version, int) \
            or not CONFIG_FORMAT_MIN_VERSION <= version <= CONFIG_FORMAT_VERSION:
        # A nyers értéket szándékosan nem idézzük vissza: a csomag tartalma
        # ne szivárogjon a hibaüzenetbe.
        raise ConfigBundleError(
            "nem támogatott formátumverzió; ez a portál az "
            f"{CONFIG_FORMAT_MIN_VERSION}–{CONFIG_FORMAT_VERSION}. verziót "
            "ismeri (az 1-esnél a hiányzó tunnels szakasz alapértelmezéssel "
            "töltődik)"
        )
    raw_sections = bundle.get("sections")
    if not isinstance(raw_sections, dict):
        raise ConfigBundleError("a sections mező JSON-objektum kell")
    missing = [name for name in CONFIG_SECTIONS if name not in raw_sections]
    if missing:
        raise ConfigBundleError(
            "hiányzó szakasz(ok): " + ", ".join(missing)
        )
    unknown = sorted(set(raw_sections) - set(CONFIG_SECTIONS))
    if unknown:
        raise ConfigBundleError(
            "ismeretlen szakasz(ok): " + ", ".join(unknown)
        )
    raw_fail2ban = raw_sections["fail2ban"]
    if not isinstance(raw_fail2ban, dict) \
            or set(raw_fail2ban) != _FAIL2BAN_CONFIG_KEYS:
        raise ConfigBundleError(
            "a fail2ban szakasz hiányos vagy ismeretlen mezőt tartalmaz"
        )
    raw_settings = raw_sections["settings"]
    if version == 1 and isinstance(raw_settings, dict) \
            and "tunnels" not in raw_settings:
        raw_settings = dict(raw_settings)
        raw_settings["tunnels"] = settings_store.default_tunnels()
    elif version >= 2 and isinstance(raw_settings, dict) \
            and "tunnels" not in raw_settings:
        raise ConfigBundleError(
            "a(z) 2. verziójú csomag beállításaiból hiányzik a tunnels szakasz"
        )
    try:
        settings = settings_store.validate_state(raw_settings)
        users = gw.users.validate_import_records(raw_sections["users"])
        rules = gw.rules.validate_import_records(raw_sections["rules"])
        groups = gw.groups.validate_import_records(raw_sections["groups"])
    except (
        settings_store.SettingsError,
        gateway.RuleStoreError,
        gateway.GroupStoreError,
        gateway.UserStoreError,
        ValueError,
    ) as exc:
        raise ConfigBundleError(str(exc)) from exc

    # A tanúsítványok külön, mert a CertStore csak a saját hibáját dobja.
    raw_certs = raw_sections["certs"]
    if not isinstance(raw_certs, dict):
        raise ConfigBundleError("a certs szakasz JSON-objektum kell")
    checked_certs: dict[str, dict] = {}
    for raw_root, item in raw_certs.items():
        if not isinstance(item, dict):
            raise ConfigBundleError(f"{raw_root}: hibás tanúsítványbejegyzés")
        try:
            meta = gw.certs.validate_import(
                raw_root, item.get("cert"), item.get("key")
            )
        except settings_store.SettingsError as exc:
            raise ConfigBundleError(f"{raw_root}: {exc}") from exc
        if not isinstance(meta, dict):
            raise ConfigBundleError(f"{raw_root}: hibás tanúsítvány")
        root = raw_root.strip().lower()
        if root in checked_certs:
            raise ConfigBundleError(f"duplikált gyökérdomain: {root}")
        checked_certs[root] = {
            "cert": item.get("cert"), "key": item.get("key"),
        }
    try:
        fail2ban_config = fail2ban_mod.validate_config(raw_fail2ban)
    except fail2ban_mod.Fail2banError as exc:
        raise ConfigBundleError(f"fail2ban: {exc}") from exc

    # Hivatkozási integritás: szabály -> proxy host, felhasználó -> szabály,
    # csoport -> szabály/tag, tanúsítvány -> gyökérdomain.
    route_hosts = {
        settings_store.route_host(route)
        for route in settings["proxy_routes"]
    }
    for rule in rules.values():
        missing_hosts = [name for name in rule.domains if name not in route_hosts]
        if missing_hosts:
            raise ConfigBundleError(
                f"{rule.id}: nincs ilyen proxy útvonal: "
                + ", ".join(missing_hosts)
            )
    for name, item in users.items():
        missing_rules = [
            rule_id for rule_id in item.get("rules", ()) if rule_id not in rules
        ]
        if missing_rules:
            raise ConfigBundleError(
                f"{name}: ismeretlen szabály: " + ", ".join(missing_rules)
            )
    for group in groups.values():
        missing_rules = [rid for rid in group.rules if rid not in rules]
        if missing_rules:
            raise ConfigBundleError(
                f"{group.id}: ismeretlen szabály: " + ", ".join(missing_rules)
            )
        missing_users = [name for name in group.members if name not in users]
        if missing_users:
            raise ConfigBundleError(
                f"{group.id}: ismeretlen tag: " + ", ".join(missing_users)
            )
    for root in checked_certs:
        if root not in settings["proxy_domains"]:
            raise ConfigBundleError(
                f"{root}: a tanúsítványhoz nincs ilyen gyökérdomain"
            )
    if not any(
        item["role"] == gateway.ROLE_ADMIN
        and item["enabled"] and not item["pending"]
        for item in users.values()
    ):
        raise ConfigBundleError(
            "a csomag nem tartalmaz legalább egy engedélyezett admin fiókot"
        )
    return {
        "settings": settings,
        "rules": rules,
        "groups": groups,
        "users": users,
        "certs": checked_certs,
        "fail2ban": fail2ban_config,
    }


def _apply_config_bundle(gw, bundle: dict) -> None:
    """A már ellenőrzött szakaszok írása a meglévő tároló-utakon."""
    gw.users.replace_all(bundle["users"])
    gw.rules.replace_all(bundle["rules"])
    gw.groups.replace_all(bundle["groups"])
    gw.apply_settings(bundle["settings"])
    # A szabályok a beállítások előtt íródtak, ezért a csomagban érkező új
    # alagút-szolgáltatásokra hivatkozó szabályok feloldott portjai még
    # üresek lehetnek. A beállítások telepítése után azonnal újraszámoljuk
    # őket (és a függő gyűjtőket), hogy az importált szabály ne csak
    # újraindítás után legyen használható. A visszaszámolt portok nem
    # perzisztáltak, ezért nincs szükség további fájlírásra.
    refreshed = gw.rules.reflect_services()
    if refreshed:
        gw.sessions.revoke_rules(refreshed)
    gw.certs.replace_all(bundle["certs"])
    gw.fail2ban.configure(bundle["fail2ban"])
    gw.sync_host_ports()


def _config_counts(bundle: dict) -> dict:
    """Csak darabszámok az auditba (soha nem tartalom vagy titok)."""
    settings = bundle["settings"]
    return {
        "users": len(bundle["users"]),
        "rules": len(bundle["rules"]),
        "groups": len(bundle["groups"]),
        "certs": len(bundle["certs"]),
        "preauth": len(settings["preauth"]),
        "block": len(settings["block"]),
        "proxy_domains": len(settings["proxy_domains"]),
        "proxy_routes": len(settings["proxy_routes"]),
        "port_proxies": len(settings["port_proxies"]),
        "tunnel_agents": len(settings["tunnels"]["agents"]),
        "tunnel_services": sum(
            len(agent["services"]) for agent in settings["tunnels"]["agents"]
        ),
    }


_TUNNEL_CONFIG_FORMAT = "dropjak-agent"
_TUNNEL_CONFIG_VERSION = 1
_TUNNEL_SYNC_PATH = "/api/tunnel/config"
_TUNNEL_ACTIONS = frozenset({
    "tunnel_settings",
    "tunnel_agent_add",
    "tunnel_agent_update",
    "tunnel_agent_delete",
    "tunnel_service_save",
    "tunnel_service_delete",
    "tunnel_service_test",
})
_TUNNEL_SYNC_MIN_SECONDS = 5.0
# Az elérhetőségi teszt felső korlátai: a leképezések párhuzamosan futnak,
# így egy halott cél nem sokszorozza meg a várakozást. A TCP 2 s alatt
# eldől, az UDP-próba legfeljebb 0,6 s-ot vár válaszra.
_TUNNEL_TEST_MAX_MAPPINGS = 4
_TUNNEL_TEST_TCP_TIMEOUT = 2.0
_TUNNEL_TEST_UDP_WAIT = 0.6
_TUNNEL_TEST_DEADLINE = 6.0


def _tunnel_agent_bundle_dir() -> str:
    """Az ügynök-csomag forrásfájljai (Docker-layout: ./tunnel-agent)."""
    base = os.path.dirname(os.path.abspath(__file__))
    for path in (os.path.join(base, "tunnel-agent"),
                 os.path.join(base, "deploy", "tunnel-agent")):
        if os.path.isfile(os.path.join(path, "agent.py")):
            return path
    return ""


def _tar_member(tar: tarfile.TarFile, name: str, data: bytes,
                mode: int) -> None:
    """Egy fájl a memóriabeli tar.gz csomagban (nincs temp fájl)."""
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(data))


def _tunnel_service_public(service: dict) -> dict:
    """Egy szolgáltatás admin nézete a származtatott portokkal."""
    try:
        ports = settings_store.tunnel_service_ports(service)
    except settings_store.SettingsError:
        ports = []
    return {
        "id": service["id"],
        "label": service["label"],
        "target_host": service["target_host"],
        "enabled": service["enabled"],
        "public": bool(service.get("public", False)),
        "domain": service.get("domain", ""),
        "challenge": service.get("challenge"),
        "mappings": [dict(mapping) for mapping in service.get("mappings", [])],
        "ports": [
            {
                "proto": item["proto"],
                "listen_port": item["listen_port"],
                "target_port": item["target_port"],
            }
            for item in ports
        ],
    }


def _tunnels_public(gw, settings: dict) -> dict:
    """Az alagút-ügynökök admin nézete: kulcs és token nélkül."""
    tunnels = settings.get("tunnels")
    if not isinstance(tunnels, dict):
        tunnels = settings_store.default_tunnels()
    try:
        status = gw.tunnels.status(tunnels)
    except Exception:
        status = {"error": "", "agents": []}
    rows = {row.get("id"): row for row in status.get("agents", [])}
    # Az ügynök utolsó sikeres konfiguráció-szinkronjának kora másodpercben.
    # A szinkronidők monotonic órával készülnek; a pillanatkép a zár alatt
    # készül, hogy a frissítés ne olvasson félkész állapotot.
    now = time.monotonic()
    lock = getattr(gw, "tunnel_sync_lock", None)
    sync_times = getattr(gw, "tunnel_sync_times", {}) or {}
    if lock is not None:
        with lock:
            sync_times = dict(sync_times)
    else:
        sync_times = dict(sync_times)
    agents = []
    for agent in tunnels.get("agents", []):
        row = rows.get(agent["id"], {})
        last = sync_times.get(agent["id"])
        agents.append({
            "id": agent["id"],
            "label": agent["label"],
            "address": agent["address"],
            "enabled": agent["enabled"],
            "online": bool(row.get("online")),
            "last_handshake": int(row.get("last_handshake") or 0),
            "last_sync": (
                max(0, int(now - last)) if last else None
            ),
            "rx_bytes": int(row.get("rx_bytes") or 0),
            "tx_bytes": int(row.get("tx_bytes") or 0),
            "config_url": f"/api/admin/tunnels/{agent['id']}/config",
            "bundle_url": f"/api/admin/tunnels/{agent['id']}/bundle",
            "services": [
                _tunnel_service_public(service)
                for service in agent.get("services", [])
            ],
        })
    return {
        "port": tunnels["port"],
        "endpoint": tunnels["endpoint"],
        "error": str(status.get("error") or ""),
        "agents": agents,
    }


def _tunnel_error_field(error: str, fallback: str = "") -> str:
    """A validációs hiba szövegéből a mező neve (a felület jelöléséhez)."""
    for needle, field in (
        ("hallgató port", "listen_port"),
        ("belső port", "tunnel_port"),
        ("célport", "target"),
        ("célhost", "target_host"),
        ("portleképezés", "mappings"),
        ("leképezés", "mappings"),
        ("mappings", "mappings"),
        ("cél", "target"),
        ("protokoll", "proto"),
        ("ügynökcím", "address"),
        ("ügynök-azonosító", "id"),
        ("ügynök", "agents"),
        ("token", "token"),
        ("privát kulcs", "server_private_key"),
        ("megosztott kulcs", "preshared_key"),
        ("WireGuard-kulcs", "server_private_key"),
        ("WireGuard port", "port"),
        ("végpont", "endpoint"),
        ("címke", "label"),
    ):
        if needle in error:
            return field
    return fallback


def _effective_site_name(gw) -> str:
    value = gw.settings.snapshot().get("site_name")
    return value.strip() if isinstance(value, str) and value.strip() else "Dropjak"


def _config_state_nonempty(gw) -> bool:
    """Van-e olyan állapot, amit import előtt gépelt névvel kell védeni?

    A .env-ből létrehozott admin nem számít felhasználói állapotnak: friss
    telepítésnél ez az egyetlen fiók, és az újraindulás úgyis újra létrehozza.
    A kezdő (seedelt) szabályok szintén nem számítanak.
    """
    try:
        for name in gw.users.names():
            record = gw.users.record(name)
            if record is not None and record.is_admin \
                    and gw.users.provisioned_from(name):
                continue
            return True
        if gw.groups.all_groups() or gw.certs.export_all():
            return True
    except (gateway.UserStoreError, gateway.GroupStoreError,
            settings_store.SettingsError, OSError):
        # Ha nem tudjuk biztosan üresnek látni, kérjünk megerősítést.
        return True
    snapshot = gw.settings.snapshot()
    if snapshot.get("error"):
        return True
    if any(snapshot.get(key) for key in (
        "site_name", "motd_text", "motd_expires_at",
        "proxy_domains", "proxy_routes", "port_proxies", "preauth", "block",
    )):
        return True
    return bool(
        snapshot.get("registration_enabled") or snapshot.get("proxy_acme") is False
    )


def _config_confirm_ok(gw, data: dict) -> bool:
    if not _config_state_nonempty(gw):
        return True
    provided = data.get("confirm")
    return isinstance(provided, str) and provided.strip() == _effective_site_name(gw)


def _config_backup_path(gw) -> str:
    directory = os.path.dirname(gw.users.path) or "."
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    path = os.path.join(directory, f"config-backup-{stamp}.json")
    index = 1
    while os.path.exists(path):
        path = os.path.join(directory, f"config-backup-{stamp}-{index}.json")
        index += 1
    return path


def _write_private_json(path: str, data: dict) -> None:
    """A csomag mentése 0600-mal, atomikusan (a könyvtárat nem hozzuk létre)."""
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(
        dir=directory, prefix=".config-backup-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _request_service_restart(delay: float = 0.5) -> None:
    """SIGTERM a saját folyamatnak; a compose ``restart: unless-stopped`` indítja újra.

    Nem Docker alatt a folyamat egyszerűen leáll (a felület ezt jelzi).
    """
    def _stop() -> None:
        try:
            os.kill(os.getpid(), signal.SIGTERM)
        except OSError:
            pass

    timer = threading.Timer(delay, _stop)
    timer.daemon = True
    timer.start()


# -------------------------------------------------------------------- HTTP réteg

class Handler(BaseHTTPRequestHandler):
    server_version = "Dropjak/2"
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
        return self._cookie(gateway.COOKIE_NAME)

    def _cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie")
        if not raw:
            return ""
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except CookieError:
            return ""
        morsel = jar.get(name)
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

    def _read_json(self, limit: int = 64 * 1024) -> dict | None:
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
        if length <= 0 or length > limit:
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
        settings = self.gw.settings.snapshot()
        tunnels = _tunnels_public(self.gw, settings)
        # A nyers tunnels szakasz privát kulcsokat és tokeneket tartalmaz;
        # a felület csak a fenti, titok nélküli nézetet kapja.
        settings.pop("tunnels", None)
        caddy = getattr(self.gw, "caddy", None)
        return {
            "ok": True,
            "users": users,
            "groups": [group.public() for group in self.gw.groups.all_groups()],
            "rules": [
                self._rule_payload(rule) for rule in self.gw.rules.all_rules()
            ],
            "limits": self._limits(),
            "roles": [gateway.ROLE_USER, gateway.ROLE_ADMIN],
            "settings": settings,
            "tunnels": tunnels,
            # Csak metaadat: a kulcs és a PEM soha nem kerül a válaszba.
            "proxy_certs": self.gw.certs.public(settings),
            # A Caddy admin API állapota (None: nincs domain proxy).
            "caddy": caddy.snapshot() if caddy is not None else None,
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

    def _rule_users(self, data: dict) -> list[str] | None:
        """A szabály közvetlen felhasználó-kiosztásai (opcionális ``users``)."""
        if "users" not in data:
            return None
        raw = data.get("users")
        if not isinstance(raw, list) or len(raw) > 512:
            raise gateway.UserStoreError(
                "a users mező legfeljebb 512 elemű lista"
            )
        out: list[str] = []
        for value in raw:
            if not isinstance(value, str) or not value.strip():
                raise gateway.UserStoreError("érvénytelen felhasználónév")
            value = value.strip()
            record = self.gw.users.record(value)
            if record is None:
                raise gateway.UserStoreError(
                    f"ismeretlen felhasználó: {value}"
                )
            if record.pending:
                raise gateway.UserStoreError(
                    "a jóváhagyásra váró fiók nem rendelhető szabályhoz"
                )
            if value not in out:
                out.append(value)
        return out

    def _apply_rule_assignments(
        self, rule_id: str, users, groups
    ) -> dict:
        """A szabály közvetlen felhasználó- és csoportkiosztásainak alkalmazása.

        A hívó már ellenőrizte az azonosítókat és elmentette a szabályt. A
        két tár külön fájl, ezért a részleges hiba esetén a már alkalmazott
        felet visszaállítjuk: így a szabály elmentve marad, de a kiosztások
        nem maradnak félig módosítva. Visszatérés: az audit mezői.
        """
        if users is None and groups is None:
            return {}
        original_users = None
        original_groups = None
        if users is not None:
            original_users = [
                record.name for record in self.gw.users.details()
                if rule_id in record.rules
            ]
        if groups is not None:
            original_groups = [
                group.id for group in self.gw.groups.all_groups()
                if rule_id in group.rules
            ]
        result = {
            "users_added": (), "users_removed": (),
            "groups_added": (), "groups_removed": (),
        }
        stage = "users"
        try:
            if users is not None:
                added, removed = self.gw.users.set_rule_membership(
                    rule_id, users
                )
                result["users_added"] = added
                result["users_removed"] = removed
            stage = "groups"
            if groups is not None:
                added, removed = self.gw.groups.set_rule_groups(
                    rule_id, groups
                )
                result["groups_added"] = added
                result["groups_removed"] = removed
        except Exception as exc:
            rollback_failed = False
            try:
                if stage == "groups" and users is not None \
                        and original_users is not None:
                    self.gw.users.set_rule_membership(
                        rule_id, original_users
                    )
            except Exception as rollback_exc:
                rollback_failed = True
                print(
                    "[szabályok] a felhasználói kiosztás visszaállítása "
                    f"nem sikerült: {rollback_exc}",
                    flush=True,
                )
            message = (
                "a szabály elmentve, de a kiosztás alkalmazása nem "
                f"sikerült: {exc}"
            )
            if rollback_failed:
                message += " (a részleges módosítás visszaállítása sem sikerült)"
            raise gateway.RuleStoreError(message) from exc
        return {
            "users_added": ",".join(result["users_added"]),
            "users_removed": ",".join(result["users_removed"]),
            "groups_added": ",".join(result["groups_added"]),
            "groups_removed": ",".join(result["groups_removed"]),
        }

    def _portal_host_matches(self) -> bool:
        # A gyökérdomaineken a Caddy HTTPS-en a portált szolgálja ki.
        if not gateway.PORTAL_URL or self._via_proxy():
            return True
        host = (self.headers.get("Host") or "").strip().lower()
        if not host:
            return True
        target = urllib.parse.urlsplit(gateway.PORTAL_URL).netloc.lower()
        return host == target

    def _https_portal_url(self) -> str:
        """A WAN-ról közvetlenül (http) nyitott portál HTTPS-célja, vagy "".

        A LAN-kliens, a tiltott és a proxy-tiltott IP a 443-at nem éri el,
        ezért nekik a http portál marad; a loopback (healthcheck, Caddy)
        és a Caddyn át érkező kérés érintetlen.
        """
        if not gateway.PROXY_ENABLED or self._peer_ip() in PROXY_LOOPBACK:
            return ""
        settings = self.gw.settings.snapshot()
        roots = settings.get("proxy_domains", [])
        if not roots:
            return ""
        ip = self._client_ip()
        try:
            if gateway.LAN_NETWORK is not None and \
                    ipaddress.ip_address(ip) in gateway.LAN_NETWORK:
                return ""
        except ValueError:
            return ""
        root = roots[0]
        # A saját cím bekapcsolva: a közvetlen HTTP-portál is oda vált.
        host = settings.get("portal_domain") or root
        if host != root:
            root = _portal_parent_root(host, roots)
        if not settings.get("proxy_acme", True) \
                and self.gw.certs.bundle(host, root) is None:
            return ""
        if self.gw.fail2ban.banned(ip) is not None \
                or self.gw.fail2ban.proxy_banned(ip) is not None:
            return ""
        parts = urllib.parse.urlsplit(self.path)
        return urllib.parse.urlunsplit(
            ("https", host, parts.path or "/", parts.query, "")
        )

    # -- GET / HEAD ------------------------------------------------------------

    def do_GET(self) -> None:
        self._body_read = False
        path = urllib.parse.urlsplit(self.path).path

        if path == "/api/challenge":
            return self._challenge()
        if path == "/api/status":
            return self._status()
        if path == _TUNNEL_SYNC_PATH:
            return self._tunnel_config_sync()
        if path.startswith("/api/admin/tunnels/") and path.endswith("/config"):
            return self._admin_tunnel_config(path)
        if path.startswith("/api/admin/tunnels/") and path.endswith("/bundle"):
            return self._admin_tunnel_bundle(path)
        if path == "/api/admin/tunnels/status":
            return self._admin_tunnels_status()
        if path == "/api/admin/state":
            return self._admin_state_api()
        if path == "/api/admin/preview":
            return self._admin_preview()
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
        if path == "/api/admin/config/export":
            return self._admin_config_export()
        if path.startswith("/api/proxy/"):
            return self._proxy_api(path)
        if path.startswith("/api/gate/"):
            return self._gate_api(path)
        if path.startswith("/api/"):
            return self._json(404, {"ok": False, "error": "ismeretlen végpont"})

        # A WAN-ról közvetlenül nyitott http portál a gyökérdomain HTTPS
        # portáljára vált (a captive átirányítás előtt, annak célja helyett).
        https_url = self._https_portal_url()
        if https_url:
            self._audit("portal_https_redirect", target=https_url[:300])
            return self._send(
                308, b"", "text/plain; charset=utf-8",
                headers={"Location": https_url},
            )

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
            "/icon.png", "/favicon.ico", "/blocked.png", "/ok.png"
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
        if path == "/ok.png":
            return self._static("ok.png")
        # Bármely más útvonalra a belépőoldalt adjuk (captive viselkedés).
        return self._static("index.html")

    do_HEAD = do_GET

    # -- Caddy aldomain-proxy (csak loopbackről) ------------------------------

    def _proxy_target(self, host: str):
        """A host proxy-célja ("root", a bejegyzés, a portál vagy None) és gyökere."""
        settings = self.gw.settings.snapshot()
        portal = settings.get("portal_domain", "")
        if portal and host == portal:
            # A saját címén a portál egy publikus bejegyzésként viselkedik:
            # a challenge-feltételek ugyanúgy érvényesek rá.
            target = {
                "type": "input", "port": gateway.PORT,
                "visibility": "public", "enabled": True, "portal": True,
            }
            challenge = settings.get("portal_challenge")
            if challenge:
                target["challenge"] = challenge
            return target, _portal_parent_root(
                portal, settings.get("proxy_domains", [])
            )
        # A bejegyzések elsőbbséget élveznek: üres nevű bejegyzés a gyökérre
        # szól, és a gyökér csak saját portálcím nélkül szolgálja ki a portált.
        for route in settings.get("proxy_routes", []):
            if route["enabled"] and host == settings_store.route_host(route):
                return route, route["root"]
        # Domaines alagút-szolgáltatás: a Caddy ugyanazon a forward_auth
        # úton kérdez, a cél pedig az ügynök belső alagút-portja.
        tunnel = _tunnel_domain_target(settings, host)
        if tunnel is not None:
            return tunnel
        if host and host in settings.get("proxy_domains", []) and not portal:
            return "root", host
        return None, ""

    def _proxy_unknown_root(self, host: str) -> str:
        """A nem bejegyzett (vagy kikapcsolt) aldomain gyökere, ha a gyökér
        feltöltött, érvényes tanúsítványa ACME nélkül fedi a nevet; vagy "".

        Csak a _proxy_target None eredménye után értelmes.
        """
        for root in self.gw.settings.snapshot().get("proxy_domains", []):
            if host.endswith("." + root) \
                    and self.gw.certs.bundle(host, root) is not None:
                return root
        return ""

    def _proxy_redirect(self) -> None:
        """A 80-as port (Caddy http:// forward_auth) válasza: mindig 3xx.

        Saját név (gyökér, bekapcsolt bejegyzés, feltöltött tanúsítvánnyal
        fedett ismeretlen aldomain) az eredeti URI-val HTTPS-re vált (308);
        más névre nincs tanúsítvány, ezért a (tartalmazó, különben az első)
        gyökér portáljára visz (302: ideiglenes, egy később felvett
        bejegyzést nem takar el). Gyökér nélkül a régi viselkedés marad.
        Kérésenként fut: nincs audit.
        """
        raw = (
            self.headers.get("X-Forwarded-Host")
            or self.headers.get("Host") or ""
        ).strip().lower()
        match = len(raw) <= 300 and _REDIRECT_HOST_RE.fullmatch(raw)
        host = match.group(1) if match and len(match.group(1)) <= 253 else ""
        if host.startswith("["):
            try:
                ipaddress.IPv6Address(host[1:-1])
            except ValueError:
                host = ""
        uri = self.headers.get("X-Forwarded-Uri") or "/"
        if not (uri.startswith("/") and uri.isascii() and uri.isprintable()
                and " " not in uri):
            uri = "/"
        settings = self.gw.settings.snapshot()
        roots = settings.get("proxy_domains", [])
        portal = settings.get("portal_domain", "")
        if host and portal and host in roots \
                and self._proxy_target(host)[0] is None:
            # Saját portálcím mellett a gyökér már nem a portálé: bejegyzés
            # nélkül nincs hozzá tanúsítvány, ezért nem irányítunk rá.
            return self._send(404, b"", "text/plain; charset=utf-8")
        if host and (
            self._proxy_target(host)[0] is not None
            or self._proxy_unknown_root(host) or not roots
        ):
            code, location = 308, f"https://{host}{uri}"
        elif roots:
            # Ismeretlen név: a portál (vagy annak híján a tartalmazó gyökér).
            root = portal or next(
                (r for r in roots if host.endswith("." + r)), roots[0]
            )
            code, location = 302, f"https://{root}/"
        else:
            return self._send(400, b"", "text/plain; charset=utf-8")
        return self._send(
            code, b"", "text/plain; charset=utf-8",
            headers={"Location": location},
        )

    def _proxy_api(self, path: str) -> None:
        # A Caddy minden proxyzott kérésnél hívja: auditot csak a bejegyzés
        # oldalmegnyitása kap, a 401 drop-sort; a fail2ban csak a privát
        # bejegyzés 401-es válaszait számolja. Idegen peer semmit nem tudhat meg.
        if self._peer_ip() not in PROXY_LOOPBACK:
            return self._send(404, b"", "text/plain; charset=utf-8")
        if path in ("/api/proxy/unauthorized.png", "/api/proxy/sus.png"):
            return self._static(path.rpartition("/")[2])
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if path == "/api/proxy/ask":
            # On-demand TLS: tanúsítvány csak a beállított nevekre kérhető,
            # és csak bekapcsolt automatikus tanúsítványnál.
            domain = (query.get("domain") or [""])[0].strip().lower()
            target, _ = self._proxy_target(domain)
            acme = self.gw.settings.snapshot().get("proxy_acme", True)
            code = 200 if acme and target is not None else 404
            return self._send(code, b"", "text/plain; charset=utf-8")
        if path == "/api/proxy/cert":
            # A Caddy get_certificate http kérése (titkos kulcsot ad): a
            # Caddyn át érkező (proxyzott) kérés semmit nem kaphat. A Caddy
            # reverse_proxy/forward_auth mindig küld X-Forwarded-For-t, a
            # tanúsítványlekérés soha.
            if self._via_proxy() or any(
                self.headers.get(name) is not None
                for name in (
                    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Uri"
                )
            ):
                return self._send(404, b"", "text/plain; charset=utf-8")
            name = (query.get("server_name") or [""])[0].strip().lower()
            # A lefedettség dönt, nem a bejegyzés: az ismeretlen, de a
            # feltöltött wildcard által fedett név is megkapja (challenge-re).
            target, root = self._proxy_target(name)
            if target is None:
                root = self._proxy_unknown_root(name)
            bundle = self.gw.certs.bundle(name, root) if root else None
            if bundle is None:
                # 204: a Caddy a saját (on-demand ACME) útján folytatja.
                return self._send(204, b"", "text/plain; charset=utf-8")
            return self._send(200, bundle, "application/x-pem-file")
        if path == "/api/proxy/redirect":
            return self._proxy_redirect()
        if path != "/api/proxy/auth":
            return self._send(404, b"", "text/plain; charset=utf-8")
        host = (
            self.headers.get("X-Forwarded-Host")
            or self.headers.get("Host") or ""
        )
        host = host.strip().lower().partition(":")[0]
        # A Caddy az X-Forwarded-For-t a valódi kliens IP-re állítja (nem
        # bízik a bejövő értékben); az utolsó elem a közvetlen kliens.
        forwarded = (self.headers.get("X-Forwarded-For") or "").split(",")[-1]
        try:
            ip = gateway.normalize_ip(forwarded)
        except ValueError:
            ip = ""
        # Lekérdezés nélkül, csonkolva (a query tokent is hordozhat).
        page_path = urllib.parse.urlsplit(
            self.headers.get("X-Forwarded-Uri") or "/"
        ).path[:200]
        target, root = self._proxy_target(host)
        if target is None:
            if not self._proxy_unknown_root(host):
                return self._send(404, b"", "text/plain; charset=utf-8")
            # Ismeretlen, de feltöltött tanúsítvánnyal fedett aldomain:
            # feltételektől és munkamenettől függetlenül mindig challenge
            # (a sikeres megoldás a gyökérre visz, belépő nélkül).
            if (
                not ip
                or self.gw.fail2ban.banned(ip) is not None
                or self.gw.fail2ban.proxy_banned(ip) is not None
            ):
                return self._send(403, b"", "text/plain; charset=utf-8")
            if not self._proxy_navigation():
                return self._json(403, {
                    "ok": False, "error": "ellenőrzés szükséges",
                    "code": "proxy_challenge",
                })
            self._audit(
                "proxy_challenge_shown",
                ip=ip,
                host=host,
                path=page_path,
                unknown_host=True,
            )
            return self._send(
                403, _proxy_challenge_page(), "text/html; charset=utf-8"
            )
        login = f"https://{root}/"
        settings = self.gw.settings.snapshot()
        portal = settings.get("portal_domain", "")
        if portal:
            login = f"https://{portal}/"
        # A portál saját címe ugyanazt a loopback-védelmet kapja: a Caddy a
        # portálhoz továbbít, így a /api/proxy/ végpontok különben elérhetők
        # lennének (a peer ott is loopback).
        if isinstance(target, dict) and target.get("portal"):
            uri = self.headers.get("X-Forwarded-Uri") or "/"
            if urllib.parse.urlsplit(uri).path.startswith("/api/proxy/"):
                return self._send(404, b"", "text/plain; charset=utf-8")
        if target == "root":
            # A gyökérdomain maga a portál. A Caddyn át a proxy-végpontok
            # nem érhetők el (ott a peer is loopback lenne).
            uri = self.headers.get("X-Forwarded-Uri") or "/"
            if urllib.parse.urlsplit(uri).path.startswith("/api/proxy/"):
                return self._send(404, b"", "text/plain; charset=utf-8")
            if portal:
                # A felület a saját címére költözött; a gyökér oda irányít.
                if not (uri.startswith("/") and uri.isascii()
                        and uri.isprintable() and " " not in uri):
                    uri = "/"
                return self._send(
                    302, b"", "text/plain; charset=utf-8",
                    headers={"Location": f"https://{portal}{uri}"},
                )
            return self._send(
                200, b"", "text/plain; charset=utf-8",
                headers={"X-Dropjak-Upstream": f"127.0.0.1:{gateway.PORT}"},
            )
        # Publikus bejegyzés: bárki, akit a fail2ban nem tilt. A proxy-tiltott
        # IP-t a tűzfal a 80/443-on eldobja; itt is jogosulatlan (mélységi
        # védelem), és további kérése nem számít.
        user = None
        if (
            ip
            and self.gw.fail2ban.banned(ip) is None
            and self.gw.fail2ban.proxy_banned(ip) is None
        ):
            user = (
                "" if target["visibility"] == "public"
                else self.gw.sessions.domain_user(ip, host)
            )
        if user is not None:
            # A forward_auth csak 2xx esetén enged tovább, és ekkor mindig
            # mi adjuk a célt: a kliens által küldött fejléc nem irányíthat.
            upstream = (
                target["ip"] if target["type"] == "forward" else "127.0.0.1"
            )
            # A challenge 403-at ad (nem 401-et): sem a fail2ban, sem a drop
            # log nem számolja.
            fired = self._proxy_challenge_triggers(target, host, ip)
            if fired:
                if not self._proxy_navigation():
                    return self._json(403, {
                        "ok": False, "error": "ellenőrzés szükséges",
                        "code": "proxy_challenge",
                    })
                self._audit(
                    "proxy_challenge_shown",
                    ip=ip,
                    user=user,
                    host=host,
                    path=page_path,
                    triggers=",".join(fired),
                )
                return self._send(
                    403, _proxy_challenge_page(), "text/html; charset=utf-8"
                )
            if self._proxy_navigation():
                self._audit(
                    "proxy_page_opened",
                    ip=ip,
                    user=user,
                    host=host,
                    path=page_path,
                    visibility=target["visibility"],
                )
            return self._send(
                200, b"", "text/plain; charset=utf-8",
                headers={
                    "X-Dropjak-Upstream": f"{upstream}:{target['port']}"
                },
            )
        # Csak privát bejegyzésnél lehet ide jutni számolható IP-vel: a
        # publikus 401 mindig üres vagy már tiltott IP-é, az nem számít.
        if ip:
            try:
                self.gw.fail2ban.record_proxy_unauthorized(ip)
            except Exception as exc:
                _log_fail2ban_error(
                    ip, exc, self.gw.audit, operation="record_proxy"
                )
        self.gw.record_proxy_drop(ip, host, page_path)
        page = _proxy_page(
            title="Dropjak",
            image="unauthorized.png",
            body=(
                f'<a class="login" href="{html.escape(login, quote=True)}" '
                'aria-label="Log in" title="Log in">'
                f"{PROXY_LOGIN_ICON}</a>"
            ),
        )
        return self._send(401, page, "text/html; charset=utf-8")

    def _proxy_challenge_triggers(
        self, target: dict, host: str, ip: str
    ) -> list[str]:
        """A bejegyzés most teljesülő challenge-feltételei (üres: nem kell).

        Az always/interval/daily/new_ip érvényes belépőt kér (ezek az
        érvényességet szűkítik). Az after_401/fail2ban csak futó számlálónál
        kér, és a legutóbbi találat után kiadott belépőt; a burst ugyanígy
        a legutóbbi spam-észlelés (sok oldalmegnyitás) után kiadottat; a
        suspicious gyanús kérésnél bármely érvényes belépőt.
        """
        challenge = target.get("challenge")
        if not challenge:
            return []
        triggers = challenge["triggers"]
        now = time.time()
        issued = _proxy_pass_issued(
            self._cookie(PROXY_PASS_COOKIE), host,
            ip if "new_ip" in triggers else "", now,
        )
        if now - issued >= _proxy_pass_lifetime(challenge):
            issued = 0.0
        if issued and "daily" in triggers:
            today = time.localtime(now)
            midnight = time.mktime(
                (today.tm_year, today.tm_mon, today.tm_mday, 0, 0, 0, 0, 0, -1)
            )
            if issued < midnight:
                issued = 0.0
        fired = [
            name for name in ("always", "interval", "daily", "new_ip")
            if name in triggers and not issued
        ]
        for name, proxy_only in (("after_401", True), ("fail2ban", False)):
            if name in triggers:
                since = self.gw.fail2ban.last_hit(ip, proxy_only=proxy_only)
                if since and issued <= since:
                    fired.append(name)
        if "burst" in triggers:
            since = _proxy_burst(ip, host, now, self._proxy_navigation())
            if since and issued <= since:
                fired.append("burst")
        if "suspicious" in triggers and not issued and self._proxy_suspicious():
            fired.append("suspicious")
        return fired

    def _proxy_suspicious(self) -> bool:
        """Nem böngészőszerű-e a forward_auth által továbbított kérés."""
        agent = (self.headers.get("User-Agent") or "").strip()
        return (
            not agent
            or bool(_CLI_AGENT_RE.match(agent))
            or not self.headers.get("Accept-Language")
            or (
                self._proxy_navigation()
                and self.headers.get("Sec-Fetch-Mode") is None
            )
        )

    def _gate_api(self, path: str) -> None:
        """A proxy challenge végpontja (a Caddy /__dropjak/challenge útja).

        GET: PoW-feladvány vagy Turnstile-mód (mint a /api/challenge); POST:
        a megoldás ellenőrzése és a belépő sütije. Csak a Caddyn át (loopback
        peer), challenge-es bejegyzés vagy tanúsítvánnyal fedett ismeretlen
        aldomain hostján (ez utóbbinál belépő helyett a gyökérre irányít);
        minden más 404.
        """
        host = (self.headers.get("Host") or "").strip().lower().partition(":")[0]
        target, unknown_root = None, ""
        if self._peer_ip() in PROXY_LOOPBACK and path == "/api/gate/challenge":
            target, _ = self._proxy_target(host)
            if target is None:
                unknown_root = self._proxy_unknown_root(host)
        if not unknown_root and (
            not isinstance(target, dict) or not target.get("challenge")
        ):
            self._discard_body()
            return self._send(404, b"", "text/plain; charset=utf-8")
        ip = self._client_ip()
        if self.gw.fail2ban.banned(ip) is not None \
                or self.gw.fail2ban.proxy_banned(ip) is not None:
            self._discard_body()
            return self._json(403, {"ok": False, "error": "tiltott IP-cím"})
        if self.command != "POST":
            return self._challenge()
        data = self._read_json(limit=4096)
        if data is None:
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        if not self._origin_ok():
            return self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
        if not self.gw.login_rate.allow(ip):
            return self._json(
                429,
                {"ok": False, "error": "Túl sok próbálkozás. Várj egy percet."},
                headers={"Retry-After": str(gateway.RATE_WINDOW)},
            )
        extra = {"unknown_host": True} if unknown_root else {
            "triggers": ",".join(self._proxy_challenge_triggers(target, host, ip))
        }
        captcha = data.get("captcha")
        if not isinstance(captcha, dict):
            ok, why = False, "hiányos adatok"
        elif gateway.TURNSTILE_ON:
            ok, why = gateway.verify_turnstile(str(captcha.get("token", "")), ip)
        else:
            ok, why = gateway.verify_pow(captcha)
        if not ok:
            self._audit(
                "proxy_challenge_failed", ip=ip, host=host,
                reason=f"captcha: {why}", **extra,
            )
            # A sikertelen challenge a proxy-jel számlálójába megy.
            try:
                self.gw.fail2ban.record_proxy_unauthorized(ip)
            except Exception as exc:
                _log_fail2ban_error(
                    ip, exc, self.gw.audit, operation="record_proxy"
                )
            return self._json(403, {"ok": False, "error": f"Captcha: {why}"})
        self._audit("proxy_challenge_passed", ip=ip, host=host, **extra)
        if unknown_root:
            return self._json(
                200, {"ok": True, "redirect": f"https://{unknown_root}/"}
            )
        challenge = target["challenge"]
        now = time.time()
        lifetime = _proxy_pass_lifetime(challenge)
        value = _proxy_pass_value(
            host, ip if "new_ip" in challenge["triggers"] else "", now,
            int(now) + lifetime,
        )
        return self._json(200, {"ok": True}, headers={
            "Set-Cookie": (
                f"{PROXY_PASS_COOKIE}={value}; Max-Age={lifetime}; Path=/; "
                "Secure; HttpOnly; SameSite=Lax"
            ),
        })

    def _proxy_navigation(self) -> bool:
        """Oldalmegnyitás-e a forward_auth által továbbított eredeti kérés.

        A Sec-Fetch-* fejléc dönt; nélküle a GET + text/html Accept.
        """
        dest = self.headers.get("Sec-Fetch-Dest")
        if dest is not None:
            return dest == "document"
        mode = self.headers.get("Sec-Fetch-Mode")
        if mode is not None:
            return mode == "navigate"
        return (
            (self.headers.get("X-Forwarded-Method") or "GET").upper() == "GET"
            and "text/html" in (self.headers.get("Accept") or "")
        )

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
            "max_rules": MAX_SESSION_RULES,
        }

    def _rule_payload(self, rule) -> dict:
        return self._with_hosts(rule.public())

    def _service_index(self) -> dict:
        """A jelenlegi beállítások szolgáltatás-indexe hivatkozás szerint."""
        try:
            tunnels = self.gw.settings.snapshot().get("tunnels")
        except Exception:
            return {}
        if not isinstance(tunnels, dict):
            return {}
        return settings_store.tunnel_service_index(tunnels)

    def _services_payload(self, refs) -> list[dict]:
        """A kiválasztott szolgáltatások feloldott, megjelenítési alakja."""
        index = self._service_index()
        out: list[dict] = []
        for ref in refs:
            item = index.get(ref)
            if item is None:
                out.append({
                    "ref": ref, "label": ref, "tcp": [], "udp": [],
                    "domain": None,
                })
                continue
            out.append({
                "ref": ref,
                "label": item.get("label") or ref,
                "tcp": list(item.get("tcp", ())),
                "udp": list(item.get("udp", ())),
                # Domain-módú szolgáltatás: nincs portja, a proxy-gapun
                # keresztül a domainje nyílik meg.
                "domain": item.get("domain") or None,
            })
        return out

    @staticmethod
    def _services_label(services: list[dict]) -> str:
        parts: list[str] = []
        for service in services:
            pieces: list[str] = []
            if service.get("domain"):
                # Domain-módú szolgáltatás: a port helyett a hostnév.
                pieces.append(str(service["domain"]))
            if service.get("tcp"):
                pieces.append(
                    "TCP " + ", ".join(str(port) for port in service["tcp"])
                )
            if service.get("udp"):
                pieces.append(
                    "UDP " + ", ".join(str(port) for port in service["udp"])
                )
            detail = " · ".join(pieces) if pieces else "nincs elérhető port"
            parts.append(f"{service.get('label') or service.get('ref')} ({detail})")
        return "Szolgáltatás: " + ", ".join(parts)

    def _with_hosts(self, payload: dict) -> dict:
        """A domain- és szolgáltatás-választás megjelenítési mezői.

        A ``ports_label`` domain szabálynál a hostneveket mutatja (portos
        résszel együtt ``·`` elválasztással), a ``hosts`` a teljes neveket.
        Szolgáltatás-szabálynál a ``services`` a beállításokból feloldott
        címkéket és portokat tartalmazza, a ``ports_label`` pedig ezeket
        mutatja a nyers portok helyett.
        """
        refs = [
            ref for ref in (payload.get("service_refs") or [])
            if isinstance(ref, str)
        ]
        if refs:
            services = self._services_payload(refs)
            payload["services"] = services
            if not payload.get("collection") and not payload.get("domains"):
                payload["ports_label"] = self._services_label(services)
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
        service_refs = list(dict.fromkeys(
            ref for part in session.selections()
            for ref in getattr(part, "service_refs", ())
        ))
        return {
            "selected_rules": selected_rules,
            "selected_rule_labels": selected_labels,
            "grants": [part.public() for part in session.grants],
            "hosts": self._with_hosts({"domains": domains}).get("hosts", []),
            "services": self._services_payload(service_refs),
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
        # Csak a még érvényes közlemény hagyja el a szervert; a lejárt
        # vagy kikapcsolt MOTD nem kerül a válaszba.
        motd = settings_store.active_motd(settings)
        if motd:
            payload["motd"] = motd
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

    def _admin_preview(self) -> None:
        """Egy felhasználó portál-hozzáférési nézetének csak olvasható előnézete.

        Szándékosan nem hoz létre munkamenetet és nem nyit nft-engedélyt:
        ugyanazokat a szabályokat, limiteket és állapotmezőket adja vissza,
        amelyeket a ``/api/status`` adna a felhasználónak. Az előnézet
        megnyitása mindig audit-bejegyzést ír.
        """
        if not self._origin_ok():
            self._admin_request_rejected("invalid_origin")
            return self._json(
                403, {"ok": False, "error": "érvénytelen kérés-eredet"}
            )
        session = self._admin_guard()
        if session is None:
            return
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        name = (query.get("user") or [""])[0].strip()[:128]
        record = self.gw.users.record(name) if name else None
        if record is None:
            self._admin_action_error(
                "user_preview", gateway.UserStoreError("ismeretlen felhasználó"),
                target=name,
            )
            return self._json(
                404, {"ok": False, "error": "ismeretlen felhasználó"}
            )
        rules = self.gw.effective_rules(record.name)
        self._audit("admin_user_preview", user=session.user, target=record.name)
        self._json(200, {
            "ok": True,
            "preview": True,
            "user": record.name,
            "role": record.role,
            "admin": record.is_admin,
            "enabled": record.enabled,
            "pending": record.pending,
            "must_change_password": record.must_change_password,
            "totp_required": record.totp_required,
            "totp_enrolled": record.totp_enrolled,
            "authorized": False,
            "limits": self._limits(),
            "rules": [self._rule_payload(rule) for rule in rules],
        })

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
        # Többes eseményszűrő: ``events=a,b`` (ismételhető) vagy ismételt
        # ``event=``. Egyetlen ``event=`` a régi részleges egyezés marad.
        event_values = query.get("event") or []
        multi = list(query.get("events") or [])
        if len(event_values) > 1:
            multi += event_values
            event_values = []
        event_filter = event_values[0] if event_values else ""
        events = list(dict.fromkeys(
            code.strip().lower()
            for value in multi for code in value.split(",") if code.strip()
        ))
        if len(events) > 200 or not all(
            AUDIT_EVENT_CODE_RE.fullmatch(code) for code in events
        ):
            return self._json(400, {
                "ok": False, "error": "érvénytelen eseménykód a szűrőben",
            })
        user_filter = first("user")
        q_filter = first("q")
        severity_filter = first("severity").strip().lower()
        ip_raw = first("ip").strip()
        ip_filter = None
        if ip_raw:
            try:
                ip_filter = ipaddress.ip_network(ip_raw, strict=False)
            except ValueError:
                return self._json(400, {
                    "ok": False,
                    "error": "érvénytelen IP-cím vagy CIDR (pl. 192.168.10.0/24)",
                })
        rows = self.gw.audit.read(
            limit=limit,
            event=event_filter,
            user=user_filter,
            q=q_filter,
            before=before,
            severity=severity_filter,
            ip=ip_filter,
            events=events,
        )
        manual = first("manual").strip().lower() in ("1", "true", "yes")
        if manual:
            # Csak a felhasználó által indított lekérés kerül a naplóba; az
            # öt másodperces automatikus frissítés nem.
            self._audit(
                "admin_logs_read",
                user=session.user,
                limit=limit,
                event_filter=(event_filter or ",".join(events))[:120],
                user_filter=user_filter[:120],
                severity_filter=severity_filter[:16],
                ip_filter=str(ip_filter or ""),
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
        settings = self.gw.settings.snapshot()
        tunnels = _tunnels_public(self.gw, settings)
        settings.pop("tunnels", None)
        self._json(
            200,
            {
                "ok": True,
                "settings": settings,
                "tunnels": tunnels,
                "drop_log": self.gw.drops.status(),
            },
        )

    def _tunnel_endpoint_host(self) -> str:
        """A letöltött konfiguráció nyilvános végpontja (Host, majd PORTAL_URL)."""
        host = (self.headers.get("Host") or "").strip()
        if host:
            try:
                name = urllib.parse.urlsplit("//" + host).hostname
            except ValueError:
                name = None
            if name:
                return name
        if gateway.PORTAL_URL:
            try:
                return urllib.parse.urlsplit(gateway.PORTAL_URL).hostname or ""
            except ValueError:
                return ""
        return ""

    def _tunnel_download(self, agent_id: str):
        """A letöltésekhez tartozó beállítás és ügynök (hiányzó: None)."""
        snapshot = self.gw.settings.snapshot()
        tunnels = snapshot.get("tunnels")
        if not isinstance(tunnels, dict):
            tunnels = settings_store.default_tunnels()
        agent = next(
            (
                item for item in tunnels.get("agents", [])
                if item["id"] == agent_id
            ),
            None,
        )
        return tunnels, agent

    def _tunnel_agent_config(self, agent: dict, tunnels: dict):
        """Az ügynök konfigurációja (WireGuard-kulcsokkal) és a szolgáltatásai."""
        endpoint = tunnels.get("endpoint") or self._tunnel_endpoint_host()
        services = [
            {
                "id": f"p{item['listen_port']}", "label": item["label"],
                "proto": item["proto"],
                "tunnel_port": item["tunnel_port"],
                "target": f"{item['target_host']}:{item['target_port']}",
                "enabled": True,
            }
            for item in settings_store.agent_services_expanded(agent)
        ]
        config = {
            "format": _TUNNEL_CONFIG_FORMAT,
            "version": _TUNNEL_CONFIG_VERSION,
            "agent": {
                "id": agent["id"], "label": agent["label"],
                "address": agent["address"],
            },
            "wireguard": {
                "private_key": agent["private_key"],
                "address": f"{agent['address']}/24",
                "peer_public_key": tunnels.get("server_public_key", ""),
                "preshared_key": agent["preshared_key"],
                "endpoint": (
                    f"{endpoint}:{tunnels['port']}" if endpoint else ""
                ),
                "allowed_ips": [f"{settings_store.TUNNEL_SERVER_ADDRESS}/32"],
                "persistent_keepalive": 25,
            },
            "sync": {
                "url": (
                    f"http://{settings_store.TUNNEL_SERVER_ADDRESS}:"
                    f"{settings_store.PORTAL_PORT}{_TUNNEL_SYNC_PATH}"
                ),
                "token": agent["token"],
                "interval_seconds": 30,
            },
            "services": services,
        }
        return config, len(services)

    def _admin_tunnel_agent_rejected(self, session, agent_id: str,
                                     reason: str) -> None:
        self._audit(
            "tunnel_config_failed", user=session.user,
            target=agent_id[:64], reason=reason,
        )

    def _admin_tunnels_status(self) -> None:
        """Csak olvasó állapotfrissítés az ügynök-listához.

        A beállításfájlt nem írja és az nftables-t sem érinti: ugyanazt a
        titok nélküli nézetet adja vissza, mint az admin állapot, friss
        ``checked_at`` időbélyeggel. A felület ezzel kéri újra a
        kézfogás- és szinkronadatokat anélkül, hogy a teljes admin
        állapotot újratöltené.
        """
        if self._admin_guard() is None:
            return
        snapshot = self.gw.settings.snapshot()
        if snapshot.get("error"):
            self._json(
                503,
                {
                    "ok": False,
                    "error": f"a beállításfájl hibás: {snapshot['error']}",
                },
            )
            return
        self._json(
            200,
            {
                "ok": True,
                "checked_at": int(time.time()),
                "tunnels": _tunnels_public(self.gw, snapshot),
            },
        )

    def _admin_tunnel_config(self, path: str) -> None:
        """Egy ügynök letölthető konfigurációja (kulcsokkal, csak adminnak)."""
        session = self._admin_guard()
        if session is None:
            return
        if not self._origin_ok():
            self._audit(
                "tunnel_config_failed", user=session.user,
                reason="invalid_origin",
            )
            return self._json(
                403, {"ok": False, "error": "érvénytelen kérés-eredet"}
            )
        agent_id = path[
            len("/api/admin/tunnels/"):-len("/config")
        ].strip("/")
        tunnels, agent = self._tunnel_download(agent_id)
        if agent is None:
            self._admin_tunnel_agent_rejected(
                session, agent_id, "unknown_agent"
            )
            return self._json(
                404, {"ok": False, "error": "nincs ilyen ügynök"}
            )
        config, count = self._tunnel_agent_config(agent, tunnels)
        body = json.dumps(config, ensure_ascii=False, indent=2).encode("utf-8")
        self._audit(
            "tunnel_agent_config_downloaded",
            user=session.user, target=agent["id"], services=count,
        )
        self._send(
            200, body, "application/json; charset=utf-8",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="dropjak-agent-{agent["id"]}.json"'
                ),
            },
        )

    def _admin_tunnel_bundle(self, path: str) -> None:
        """A letölthető ügynök-telepítő: egyetlen önkitömörítő shell script.

        A script eleje a selfinstall.sh, utána a tar.gz csomag (compose,
        agent.json, forrás). Így a másik gépre egy fájlt kell átvinni.
        """
        session = self._admin_guard()
        if session is None:
            return
        if not self._origin_ok():
            self._audit(
                "tunnel_config_failed", user=session.user,
                reason="invalid_origin",
            )
            return self._json(
                403, {"ok": False, "error": "érvénytelen kérés-eredet"}
            )
        agent_id = path[
            len("/api/admin/tunnels/"):-len("/bundle")
        ].strip("/")
        tunnels, agent = self._tunnel_download(agent_id)
        if agent is None:
            self._admin_tunnel_agent_rejected(
                session, agent_id, "unknown_agent"
            )
            return self._json(
                404, {"ok": False, "error": "nincs ilyen ügynök"}
            )
        directory = _tunnel_agent_bundle_dir()
        contents = {}
        try:
            with open(
                os.path.join(directory, "compose.agent.yml"), encoding="utf-8"
            ) as fh:
                compose = fh.read()
            with open(
                os.path.join(directory, "selfinstall.sh"), "rb"
            ) as fh:
                header = fh.read()
            for name in ("Dockerfile", "agent.py", "check-containment.sh"):
                with open(os.path.join(directory, name), "rb") as fh:
                    contents[name] = fh.read()
        except OSError:
            self._admin_tunnel_agent_rejected(
                session, agent_id, "bundle_missing"
            )
            return self._json(
                500, {"ok": False, "error": "az ügynök-csomag nem elérhető"}
            )
        config, count = self._tunnel_agent_config(agent, tunnels)
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w:gz") as tar:
            _tar_member(tar, "compose.yml", compose.encode("utf-8"), 0o644)
            _tar_member(
                tar, "agent.json",
                json.dumps(config, ensure_ascii=False, indent=2).encode("utf-8"),
                0o600,
            )
            for name, mode in (
                ("Dockerfile", 0o644), ("agent.py", 0o755),
                ("check-containment.sh", 0o755),
            ):
                _tar_member(tar, name, contents[name], mode)
        self._audit(
            "tunnel_agent_config_downloaded",
            user=session.user, target=agent["id"], services=count,
            bundle=True,
        )
        self._send(
            200, header + payload.getvalue(), "application/x-sh",
            headers={
                "Content-Disposition": (
                    "attachment; filename="
                    f'"dropjak-agent-{agent["id"]}.sh"'
                ),
            },
        )

    def _tunnel_config_sync(self) -> None:
        """Az ügynök konfiguráció-szinkronja: forrás-IP + Bearer token.

        Nem admin-végpont: kizárólag a WireGuard-alagút forrás-IP-jéről
        (a nyers socket peer, nem X-Forwarded-For) és a token birtokában
        hívható. Minden más kérés részletek nélküli 403.
        """
        peer = self._peer_ip()
        snapshot = self.gw.settings.snapshot()
        tunnels = snapshot.get("tunnels")
        if not isinstance(tunnels, dict):
            tunnels = {}
        agent = next(
            (
                item for item in tunnels.get("agents", [])
                if item.get("enabled") and item.get("address") == peer
            ),
            None,
        )
        header = self.headers.get("Authorization") or ""
        scheme, _, token = header.partition(" ")
        authorized = False
        if agent is not None and scheme.lower() == "bearer":
            authorized = hmac.compare_digest(
                token.strip().encode("utf-8", "replace"),
                str(agent.get("token", "")).encode("utf-8", "replace"),
            )
        if not authorized:
            return self._json(403, {"ok": False})
        now = time.monotonic()
        with self.gw.tunnel_sync_lock:
            last = self.gw.tunnel_sync_times.get(agent["id"], 0.0)
            if now - last < _TUNNEL_SYNC_MIN_SECONDS:
                return self._json(
                    429, {"ok": False}, headers={"Retry-After": "5"}
                )
            self.gw.tunnel_sync_times[agent["id"]] = now
        services = [
            {
                "id": f"p{item['listen_port']}", "label": item["label"],
                "proto": item["proto"],
                "tunnel_port": item["tunnel_port"],
                "target": f"{item['target_host']}:{item['target_port']}",
                "enabled": True,
            }
            for item in settings_store.agent_services_expanded(agent)
        ]
        self._json(
            200,
            {
                "ok": True,
                "agent": {"id": agent["id"], "label": agent["label"]},
                "services": services,
            },
        )

    def _audit_cert(self, action: str, session, root: str, meta) -> None:
        # A naplóba csak a gyökér, a SAN-ok, a lejárat és az ujjlenyomat kerül.
        meta = meta or {}
        self._audit(
            "admin_settings_changed",
            user=session.user,
            action=action,
            target=root,
            sans=", ".join(meta.get("sans", []))[:500],
            not_after=meta.get("not_after", 0),
            fingerprint=meta.get("fingerprint", ""),
        )

    def _caddy_restart(self) -> None:
        caddy = getattr(self.gw, "caddy", None)
        if caddy is not None:
            caddy.request_restart()

    # -- konfigurációs csomag --------------------------------------------------

    def _admin_config_export(self) -> None:
        session = self._admin_guard()
        if session is None:
            return
        if not self._origin_ok():
            self._audit(
                "config_export_failed", user=session.user,
                reason="invalid_origin",
            )
            return self._json(
                403, {"ok": False, "error": "érvénytelen kérés-eredet"}
            )
        try:
            bundle = _config_bundle(self.gw)
        except ConfigBundleError as exc:
            # A részletes hiba a válaszba mehet, a naplóba nem.
            self._audit(
                "config_export_failed", user=session.user,
                reason="export_failed",
            )
            gateway.log(f"[konfiguráció] export sikertelen: {exc}")
            return self._json(
                500,
                {"ok": False, "error": f"az export nem sikerült: {exc}"},
            )
        body = json.dumps(bundle, ensure_ascii=False, indent=2).encode("utf-8")
        self._audit(
            "config_exported", user=session.user, size=len(body),
            **_config_counts(bundle["sections"]),
        )
        filename = (
            f"dropjak-config-{gateway.APP_VERSION}-"
            f"{time.strftime('%Y%m%d-%H%M%S')}.json"
        )
        self._send(
            200, body, "application/json; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    def _admin_config_import(self) -> None:
        session = self._admin_guard()
        if session is None:
            return
        if not self._origin_ok():
            self._audit(
                "config_import_failed", user=session.user,
                reason="invalid_origin",
            )
            return self._json(
                403, {"ok": False, "error": "érvénytelen kérés-eredet"}
            )
        data = self._read_json(CONFIG_MAX_BYTES)
        if data is None or not isinstance(data.get("bundle"), dict):
            self._audit(
                "config_import_failed", user=session.user, reason="bad_request"
            )
            return self._json(
                400, {"ok": False, "error": "hiányzó vagy hibás konfigurációs csomag"}
            )
        if not _config_confirm_ok(self.gw, data):
            self._audit(
                "config_import_failed", user=session.user,
                reason="confirmation_required",
            )
            return self._json(
                400,
                {
                    "ok": False,
                    "error": (
                        "a felülíráshoz gépeld be a jelenlegi oldalnevet"
                    ),
                    "confirm_required": True,
                    "site_name": _effective_site_name(self.gw),
                },
            )
        try:
            checked = _validate_config_bundle(self.gw, data["bundle"])
        except ConfigBundleError as exc:
            self._audit(
                "config_import_failed", user=session.user,
                reason="invalid_bundle",
            )
            return self._json(
                400,
                {"ok": False, "error": f"a csomag érvénytelen: {str(exc)[:300]}"},
            )

        # Az admin_lock sorosít az egyes admin-műveletekkel: a teljes csere
        # alatt más írás ne csúszhasson be a mentés és az alkalmazás közé.
        with self.gw.admin_lock:
            # Biztonsági mentés az első írás előtt; ennek kudarca esetén
            # semmi nem változik.
            try:
                backup_path = _config_backup_path(self.gw)
                _write_private_json(backup_path, _config_bundle(self.gw))
            except (OSError, ConfigBundleError) as exc:
                self._audit(
                    "config_import_failed", user=session.user,
                    reason="backup_failed",
                )
                gateway.log(f"[konfiguráció] az import előtti mentés nem sikerült: {exc}")
                return self._json(
                    500,
                    {
                        "ok": False,
                        "error": (
                            "az import előtti biztonsági mentés nem sikerült; "
                            "semmi nem változott"
                        ),
                    },
                )

            try:
                _apply_config_bundle(self.gw, checked)
            except Exception as exc:
                rollback_error = ""
                try:
                    with open(backup_path, "r", encoding="utf-8") as fh:
                        backup = json.load(fh)
                    _apply_config_bundle(
                        self.gw, _validate_config_bundle(self.gw, backup)
                    )
                except Exception as rollback_exc:
                    rollback_error = str(rollback_exc)[:300]
                self._audit(
                    "config_import_failed", user=session.user,
                    reason="apply_failed" if not rollback_error else "rollback_failed",
                    backup=os.path.basename(backup_path),
                )
                gateway.log(f"[konfiguráció] import hiba: {exc}")
                if rollback_error:
                    gateway.log(f"[konfiguráció] a visszaállítás sem sikerült: {rollback_error}")
                    return self._json(
                        500,
                        {
                            "ok": False,
                            "error": (
                                "az import félbeszakadt, és a biztonsági mentés "
                                "visszaállítása sem sikerült; a szolgáltatás nem "
                                f"indul újra. Mentés: {os.path.basename(backup_path)}"
                            ),
                        },
                    )
                return self._json(
                    500,
                    {
                        "ok": False,
                        "error": (
                            "az import nem sikerült; az előző állapot "
                            "visszaállítva, semmi nem változott"
                        ),
                    },
                )

        counts = _config_counts(checked)
        try:
            revoked = self.gw.sessions.shutdown(reason="config_import")
        except Exception as exc:
            revoked = 0
            gateway.log(f"[konfiguráció] a munkamenetek visszavonása nem sikerült: {exc}")
        LOGIN_TICKETS.revoke_all(reason="config_import")
        self._audit(
            "config_imported", user=session.user, revoked=revoked,
            backup=os.path.basename(backup_path), **counts,
        )
        _request_service_restart()
        return self._json(
            200,
            {
                "ok": True,
                "message": "a konfiguráció betöltve; a szolgáltatás újraindul",
                "restarting": True,
                "counts": counts,
            },
        )

    def _admin_config_reset(self) -> None:
        session = self._admin_guard()
        if session is None:
            return
        if not self._origin_ok():
            self._audit(
                "config_reset_failed", user=session.user,
                reason="invalid_origin",
            )
            return self._json(
                403, {"ok": False, "error": "érvénytelen kérés-eredet"}
            )
        data = self._read_json()
        expected = _effective_site_name(self.gw)
        provided = data.get("confirm") if data is not None else None
        if not isinstance(provided, str) or provided.strip() != expected:
            self._audit(
                "config_reset_failed", user=session.user,
                reason="confirmation_required",
            )
            self._discard_body()
            return self._json(
                400,
                {
                    "ok": False,
                    "error": "a visszaállításhoz gépeld be az oldalnevet",
                    "confirm_required": True,
                    "site_name": expected,
                },
            )

        with self.gw.admin_lock:
            # Előbb a futásidejű állapot; ha ez nem megy, semmi nem törlődik.
            try:
                revoked = self.gw.sessions.shutdown(reason="config_reset")
                LOGIN_TICKETS.revoke_all(reason="config_reset")
                self.gw.fail2ban.unban_all()
                self.gw.firewall.flush()
                self.gw.firewall.replace_custom((), ())
            except Exception as exc:
                self._audit(
                    "config_reset_failed", user=session.user,
                    reason="runtime_flush_failed",
                )
                gateway.log(f"[konfiguráció] a visszaállítás előtti tűzfalürítés nem sikerült: {exc}")
                return self._json(
                    503,
                    {
                        "ok": False,
                        "error": (
                            "a tűzfal állapotát nem sikerült törölni; "
                            "a visszaállítás nem történt meg"
                        ),
                    },
                )

            # A fájlok az egyes tárolók saját, 0600-os írási útján tűnnek el;
            # a .env, a naplók és a szolgáltatásfájlok érintetlenek maradnak.
            errors = 0
            for label, reset in (
                ("users", self.gw.users.reset),
                ("rules", self.gw.rules.reset),
                ("groups", self.gw.groups.reset),
                ("settings", self.gw.settings.reset),
                ("fail2ban", self.gw.fail2ban.reset),
                ("certs", self.gw.certs.reset),
                # A WireGuard-peerek a settings.reset után is a kernelben
                # maradnának; a visszaállításnál explicit töröljük őket.
                ("tunnels", self.gw.tunnels.remove_all),
            ):
                try:
                    reset()
                except Exception as exc:
                    errors += 1
                    gateway.log(f"[konfiguráció] a(z) {label} törlése nem sikerült: {exc}")
            directory = os.path.dirname(self.gw.users.path) or "."
            try:
                names = os.listdir(directory)
            except OSError:
                names = []
            for name in names:
                if name.startswith("config-backup-") and name.endswith(".json"):
                    try:
                        os.unlink(os.path.join(directory, name))
                    except OSError as exc:
                        errors += 1
                        gateway.log(f"[konfiguráció] a(z) {name} törlése nem sikerült: {exc}")
        try:
            self.gw.sync_host_ports()
        except Exception as exc:
            gateway.log(f"[konfiguráció] a host portok szinkronizálása nem sikerült: {exc}")
        self._audit(
            "config_reset", user=session.user, revoked=revoked, errors=errors
        )
        _request_service_restart()
        if errors:
            return self._json(
                500,
                {
                    "ok": False,
                    "restarting": True,
                    "error": (
                        "a visszaállítás részben nem sikerült; a szolgáltatás "
                        "újraindul, az eredmény a naplóban látható"
                    ),
                },
            )
        return self._json(
            200,
            {
                "ok": True,
                "message": "minden konfiguráció törölve; a szolgáltatás újraindul",
                "restarting": True,
            },
        )

    def _admin_certs_action(self) -> None:
        """Gyökérdomain-tanúsítvány feltöltése/cseréje (upload) és törlése."""
        session = self._admin_guard()
        if session is None:
            return
        if not self._origin_ok():
            self._admin_request_rejected("invalid_origin", user=session.user)
            self._json(403, {"ok": False, "error": "érvénytelen kérés-eredet"})
            return
        # Két, egyenként legfeljebb 64 KiB-os PEM JSON-kódolva.
        data = self._read_json(4 * settings_store.MAX_CERT_PEM)
        if data is None:
            self._admin_request_rejected("bad_request", user=session.user)
            return self._json(400, {"ok": False, "error": "hibás kérés"})
        action = str(data.get("action", "")).strip().lower()
        root = data.get("root")
        try:
            with self.gw.admin_lock:
                if root not in self.gw.settings.snapshot().get(
                    "proxy_domains", []
                ):
                    raise settings_store.SettingsError(
                        "ismeretlen gyökérdomain"
                    )
                if action == "upload":
                    meta = self.gw.certs.install(
                        root, data.get("cert"), data.get("key")
                    )
                    # A gyorsítótárban lévő ACME-tanúsítvány megelőzné a
                    # feltöltöttet; ACME nélkül nincs ilyen.
                    if self.gw.settings.snapshot().get("proxy_acme", True):
                        self._caddy_restart()
                    message = "A tanúsítvány mentve."
                elif action == "delete":
                    meta = self.gw.certs.delete(root)
                    if meta is None:
                        raise settings_store.SettingsError(
                            "ehhez a gyökérdomainhez nincs feltöltött "
                            "tanúsítvány"
                        )
                    message = "A tanúsítvány törölve."
                else:
                    raise settings_store.SettingsError(
                        f"ismeretlen művelet: {action!r}"
                    )
                self._audit_cert(f"proxy_cert_{action}", session, root, meta)
        except (settings_store.SettingsError, ValueError, OSError) as exc:
            self._admin_request_rejected("invalid_proxy_cert", user=session.user)
            # Az OSError szövege útvonalat tartalmazhat; nem adjuk ki.
            if isinstance(exc, ValueError):
                return self._json(400, {"ok": False, "error": str(exc)})
            return self._json(
                500, {"ok": False, "error": "a tanúsítvány mentése nem sikerült"}
            )
        payload = self._admin_state()
        payload["message"] = message
        self._json(200, payload)

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
        if action == "motd":
            # A közlemény csak megjelenítési adat: nem megy át az
            # nftables-előkészítésen és -alkalmazáson.
            try:
                with self.gw.admin_lock:
                    stored = self.gw.settings.set_motd(
                        data.get("text", ""), data.get("expires_at", "")
                    )
                    # A szöveg nem kerül a naplóba, csak a hossza és a lejárat.
                    self._audit(
                        "admin_settings_changed",
                        user=session.user,
                        action="motd",
                        target="motd",
                        motd_length=len(stored["motd_text"]),
                        motd_expires_at=stored["motd_expires_at"],
                    )
            except (settings_store.SettingsError, ValueError) as exc:
                self._admin_request_rejected("invalid_motd", user=session.user)
                self._json(400, {"ok": False, "error": str(exc)})
                return
            payload = self._admin_state()
            payload["message"] = "A közlemény mentve."
            self._json(200, payload)
            return
        if action == "proxy_acme":
            # A /api/proxy/ask válaszát változtatja; kikapcsoláskor a Caddy
            # újraindul, hogy a már kiadott tanúsítványokat se szolgálja ki.
            value = data.get("enabled")
            if not isinstance(value, bool):
                self._admin_request_rejected(
                    "invalid_proxy_acme", user=session.user
                )
                self._json(
                    400,
                    {
                        "ok": False,
                        "error": "a proxy_acme mező igaz/hamis érték kell",
                    },
                )
                return
            with self.gw.admin_lock:
                was_on = self.gw.settings.snapshot().get("proxy_acme", True)
                self.gw.settings.set_proxy_acme(value)
                if was_on and not value:
                    self._caddy_restart()
                self._audit(
                    "admin_settings_changed",
                    user=session.user,
                    action="proxy_acme",
                    target="proxy_acme",
                    proxy_acme=value,
                )
            payload = self._admin_state()
            payload["message"] = "Az automatikus tanúsítvány beállítása mentve."
            self._json(200, payload)
            return
        if action == "portal_domain":
            # A Caddy kérésenként kérdezi a portált, ezért nincs újratöltés;
            # a címnek gyökérdomain alatt kell lennie (a tanúsítvány miatt).
            value = data.get("domain", "")
            if not isinstance(value, str):
                self._admin_request_rejected(
                    "invalid_portal_domain", user=session.user
                )
                self._json(
                    400,
                    {"ok": False, "error": "portal_domain: szöveg kell"},
                )
                return
            try:
                with self.gw.admin_lock:
                    stored = self.gw.settings.set_portal_domain(value)
                    self._audit(
                        "admin_settings_changed",
                        user=session.user,
                        action="portal_domain",
                        target="portal_domain",
                        portal_domain=stored["portal_domain"],
                    )
            except (settings_store.SettingsError, ValueError) as exc:
                self._admin_request_rejected(
                    "invalid_portal_domain", user=session.user
                )
                self._json(400, {"ok": False, "error": str(exc)})
                return
            payload = self._admin_state()
            payload["message"] = "A Dropjak címe mentve."
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
                        portal_challenge=data.get(
                            "portal_challenge", settings_store.UNSET
                        ),
                    )
                    self._audit(
                        "admin_settings_changed",
                        user=session.user,
                        action="proxy",
                        target="proxy",
                        proxy_domains=", ".join(stored["proxy_domains"]),
                        proxy_routes=", ".join(
                            f"{settings_store.route_host(route)}:"
                            + (f"{route['ip']}:" if "ip" in route else "")
                            + f"{route['port']}"
                            + ("" if route["enabled"] else " (off)")
                            + (" (public)" if route["visibility"] == "public"
                               else "")
                            + (" (challenge: "
                               + "/".join(route["challenge"]["triggers"]) + ")"
                               if "challenge" in route else "")
                            for route in stored["proxy_routes"]
                        ),
                    )
                    # A törölt gyökérdomain tanúsítványa is törlődik.
                    for root, meta in self.gw.certs.prune(
                        stored["proxy_domains"]
                    ).items():
                        self._audit_cert("proxy_cert_delete", session, root, meta)
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
        if action == "port_proxies":
            return self._admin_port_proxies(session, data)
        if action in _TUNNEL_ACTIONS:
            return self._admin_tunnels(session, data, action)
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

    def _admin_port_proxies(self, session, data: dict) -> None:
        """A port proxy lista cseréje: nft alkalmazás -> mentés -> conntrack.

        Az apply_settings a többi testreszabott lánccal egy tranzakcióban
        cseréli a port proxy láncokat, és mentési hibánál visszaállít.
        """
        with self.gw.admin_lock:
            old = self.gw.settings.snapshot().get("port_proxies", [])
            try:
                new_data = self.gw.settings.prepare_port_proxies(
                    data.get("port_proxies")
                )
            except (settings_store.SettingsError, ValueError) as exc:
                self._admin_request_rejected(
                    "invalid_port_proxy", user=session.user
                )
                self._json(400, {"ok": False, "error": str(exc)})
                return
            try:
                self.gw.apply_settings(new_data)
            except (gateway.FirewallError, settings_store.SettingsError,
                    OSError) as exc:
                self._admin_action_error(
                    "settings_port_proxies", exc, target="port_proxies"
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
            entries = new_data["port_proxies"]
            # A régi NAT-kötésű folyamok a conntrackben a végükig a régi
            # célra mennének: a megváltozott hallgató portokét töröljük.
            changed = gateway.port_proxy_changes(old, entries)
            for proto, port in changed:
                gateway.conntrack_flush_port(proto, port, audit=self.gw.audit)
            self._audit(
                "admin_portproxy_changed",
                user=session.user,
                action="port_proxies",
                target="port_proxies",
                port_proxies=", ".join(
                    f"{entry['label']}: {entry['proto']}/{entry['listen_port']}"
                    f" -> {entry['type']} "
                    + (f"{entry['target_ip']}:" if entry["target_ip"] else ":")
                    + f"{entry['target_port']} ({entry['ifaces']}"
                    + (", snat" if entry["snat"] else "")
                    + ("" if entry["enabled"] else ", off") + ")"
                    for entry in entries
                ),
                port_proxy_count=len(entries),
                flushed_ports=", ".join(f"{p}/{n}" for p, n in changed),
            )
        payload = self._admin_state()
        payload["port_proxy_warnings"] = gateway.port_proxy_warnings(
            entries, gateway.listening_ports(),
            self.gw.firewall.docker_published_ports(),
            set(self.gw.firewall.portproxy_localnet_blocked(entries)),
        )
        payload["message"] = "A port proxy beállításai mentve."
        self._json(200, payload)

    def _tunnel_reference_error(self, refs) -> str:
        """Hibaüzenet, ha a megadott szolgáltatás-hivatkozásokra szabály épül.

        A hivatkozó szabályokat azonosítóval és címkével sorolja fel, hogy
        az admin tudja, mit kell előbb módosítania. Üres szöveg, ha nincs
        hivatkozás (a művelet folytatható).
        """
        try:
            references = self.gw.rules.service_references()
        except Exception as exc:
            raise settings_store.SettingsError(
                "tunnel: a szabályhivatkozások ellenőrzése nem sikerült: "
                f"{exc}"
            ) from exc
        rows: list[str] = []
        for ref in refs:
            rule_ids = references.get(ref)
            if not rule_ids:
                continue
            labels: list[str] = []
            for rule_id in rule_ids:
                rule = self.gw.rules.get(rule_id)
                labels.append(
                    f"{rule.label} ({rule_id})" if rule is not None
                    else rule_id
                )
            rows.append(f"{ref}: {', '.join(labels)}")
        if not rows:
            return ""
        return (
            "tunnel: a szolgáltatás nem törölhető, mert "
            "szabály hivatkozik rá; előbb módosítsd vagy töröld a "
            "hivatkozó szabályokat: " + "; ".join(rows)
        )

    def _tunnel_domain_reference_error(self, domains) -> str:
        """Hibaüzenet, ha egy domain szabály hivatkozik a megadott nevekre.

        A proxy-bejegyzéseknél megszokott viselkedést követi: a hivatkozott
        domain nem tűnhet el csendben, mert a szabály a döntéskori
        ellenőrzésnél érvénytelenné válna.
        """
        try:
            referenced = self.gw.rules.domain_references()
        except Exception as exc:
            raise settings_store.SettingsError(
                "tunnel: a domain-hivatkozások ellenőrzése nem sikerült: "
                f"{exc}"
            ) from exc
        missing = sorted({
            domain for domain in domains if domain and domain in referenced
        })
        if not missing:
            return ""
        return (
            "tunnel: domain szabály hivatkozik rá, ezért nem törölhető és "
            "a domainje nem módosítható: " + ", ".join(missing)
            + "; előbb vedd ki a szabályból"
        )

    @staticmethod
    def _tunnel_effective_ports(service) -> object:
        """A szolgáltatás teljes effektív leképezése; hibánál ``None``.

        A hallgató port mellett a protokollt, a célhostot és a célportot is
        tartalmazza, hogy a cél átirányítása akkor is változásnak számítson,
        ha a hallgató portok változatlanok. Domain-módú szolgáltatásnál a
        domainnév külön ``("domain", 0, név, 0)`` sorként szerepel: a UI a
        domain szerkesztésekor a belső hallgató portot változatlanul hagyja,
        ezért a domain átnevezése/törlése csak így számít változásnak, és
        csak így indul el a hivatkozó szabályok frissítése és a
        munkamenetek visszavonása.
        """
        try:
            ports = settings_store.tunnel_service_ports(service)
        except settings_store.SettingsError:
            return None
        host = (
            service.get("target_host", "")
            if isinstance(service, dict) else ""
        )
        rows = [
            (item["proto"], item["listen_port"], host or "",
             item["target_port"])
            for item in ports
        ]
        domain = (
            str(service.get("domain", "") or "")
            if isinstance(service, dict) else ""
        )
        if domain:
            rows.append(("domain", 0, domain, 0))
        return tuple(sorted(rows))

    def _admin_tunnels(self, session, data: dict, action: str) -> None:
        """WireGuard-ügynökök és szolgáltatásaik kezelése.

        A szakasz a prepare_tunnels -> apply_settings úton megy, ezért az
        nftables (jump + szintetikus forward szabályok) és a WireGuard-peer
        szinkron ugyanabban a műveletben frissül. A naplóba csak azonosítók,
        portok és darabszámok kerülnek: kulcs és token soha.
        """
        target = str(data.get("id") or data.get("agent_id") or "")[:64]
        extra: dict = {}
        message = ""
        # A letiltás mindig engedélyezett (fail-closed): a hivatkozó
        # szabályok hozzáférése megszűnik, ezért a művelet után a
        # érintett munkameneteket bontjuk. A törlés továbbra is tiltott,
        # amíg szabály hivatkozik az ügynökre/szolgáltatásra.
        agent_disabled = False
        agent_toggled = False
        agent_service_refs: list[str] = []
        if action == "tunnel_service_test":
            # Az elérhetőségi teszt csak olvas: nem megy át a beállítás-
            # előkészítésen és az nftables-alkalmazáson, és nem ír állapotot.
            self._admin_tunnel_service_test(session, data)
            return
        try:
            with self.gw.admin_lock:
                snapshot = self.gw.settings.snapshot()
                if snapshot.get("error"):
                    raise settings_store.SettingsError(
                        f"a beállításfájl hibás: {snapshot['error']}"
                    )
                tunnels = snapshot.get("tunnels")
                if not isinstance(tunnels, dict):
                    tunnels = settings_store.default_tunnels()
                if action == "tunnel_settings":
                    if "port" in data:
                        tunnels["port"] = data.get("port")
                    if "endpoint" in data:
                        tunnels["endpoint"] = data.get("endpoint")
                    message = "Az alagút beállításai mentve."
                elif action == "tunnel_agent_add":
                    keys = self.gw.tunnels.generate_keys()
                    if not (tunnels.get("server_private_key")
                            and tunnels.get("server_public_key")):
                        server = self.gw.tunnels.generate_keys()
                        tunnels["server_private_key"] = server["private_key"]
                        tunnels["server_public_key"] = server["public_key"]
                    used = {
                        agent["address"] for agent in tunnels["agents"]
                    }
                    address = ""
                    for offset in range(2, 255):
                        candidate = str(
                            settings_store.TUNNEL_SUBNET.network_address
                            + offset
                        )
                        if candidate not in used:
                            address = candidate
                            break
                    if not address:
                        raise settings_store.SettingsError(
                            "tunnel: nincs szabad ügynökcím"
                        )
                    agent_id = secrets.token_hex(4)
                    while any(
                        agent["id"] == agent_id for agent in tunnels["agents"]
                    ):
                        agent_id = secrets.token_hex(4)
                    tunnels["agents"].append({
                        "id": agent_id,
                        "label": data.get("label"),
                        "address": address,
                        "private_key": keys["private_key"],
                        "public_key": keys["public_key"],
                        "preshared_key": keys["preshared_key"],
                        "token": secrets.token_urlsafe(32),
                        "enabled": True,
                        "services": [],
                    })
                    target = agent_id
                    extra["agent_id"] = agent_id
                    message = (
                        "Az ügynök létrejött; töltsd le a konfigurációját."
                    )
                elif action == "tunnel_agent_update":
                    agent = self._tunnel_agent(tunnels, data.get("id"))
                    agent_disabled = (
                        "enabled" in data
                        and data.get("enabled") is False
                        and agent.get("enabled", True)
                    )
                    agent_toggled = (
                        "enabled" in data
                        and data.get("enabled") != agent.get("enabled", True)
                    )
                    if agent_toggled:
                        agent_service_refs = [
                            f"{agent['id']}/{service['id']}"
                            for service in agent.get("services", [])
                        ]
                    if "label" in data:
                        agent["label"] = data.get("label")
                    if "enabled" in data:
                        agent["enabled"] = data.get("enabled")
                    message = (
                        "Az ügynök letiltva."
                        if agent_disabled else "Az ügynök mentve."
                    )
                elif action == "tunnel_agent_delete":
                    agent = next(
                        (
                            item for item in tunnels["agents"]
                            if item["id"] == data.get("id")
                        ),
                        None,
                    )
                    if agent is None:
                        raise settings_store.SettingsError(
                            "tunnel: nincs ilyen ügynök"
                        )
                    refs = [
                        f"{agent['id']}/{service['id']}"
                        for service in agent.get("services", [])
                    ]
                    error = self._tunnel_reference_error(refs)
                    if error:
                        raise settings_store.SettingsError(error)
                    error = self._tunnel_domain_reference_error(
                        service.get("domain", "")
                        for service in agent.get("services", [])
                    )
                    if error:
                        raise settings_store.SettingsError(error)
                    tunnels["agents"] = [
                        item for item in tunnels["agents"]
                        if item["id"] != agent["id"]
                    ]
                    message = "Az ügynök törölve."
                elif action == "tunnel_service_save":
                    agent = self._tunnel_agent(tunnels, data.get("agent_id"))
                    services = agent["services"]
                    service_id = data.get("id")
                    changed_ref: str | None = None
                    became_disabled = False
                    enabled_changed = False
                    if service_id in (None, ""):
                        service_id = secrets.token_hex(4)
                        while any(
                            item["id"] == service_id for item in services
                        ):
                            service_id = secrets.token_hex(4)
                        service = {
                            "id": service_id,
                            "label": data.get("label"),
                            "target_host": data.get("target_host"),
                            "enabled": data.get("enabled", True),
                            "mappings": data.get("mappings"),
                            "public": data.get("public", False),
                            "domain": data.get("domain", ""),
                            "challenge": data.get("challenge"),
                        }
                        services.append(service)
                    else:
                        service = next(
                            (
                                item for item in services
                                if item["id"] == service_id
                            ),
                            None,
                        )
                        if service is None:
                            raise settings_store.SettingsError(
                                "tunnel: nincs ilyen szolgáltatás"
                            )
                        old_service = copy.deepcopy(service)
                        old_ports = self._tunnel_effective_ports(
                            old_service
                        )
                        was_enabled = service.get("enabled", True)
                        old_domain = old_service.get("domain", "")
                        for key in (
                            "label", "target_host", "enabled", "mappings",
                            "public", "domain", "challenge",
                        ):
                            if key in data:
                                service[key] = data[key]
                        # A domain elhagyásakor a challenge is törlődik:
                        # domain nélkül nincs host, amin érvényesülhetne.
                        if "domain" in data and not service.get("domain"):
                            service.pop("challenge", None)
                        ref = f"{agent['id']}/{service_id}"
                        # A letiltás mindig engedélyezett (fail-closed); a
                        # hivatkozó szabályok hozzáférése megszűnik. A
                        # domain-váltás/törlés továbbra is védett, mert a
                        # domain-szabály a döntéskori ellenőrzésnél
                        # érvénytelenné válna.
                        became_disabled = (
                            was_enabled
                            and service.get("enabled", True) is False
                        )
                        enabled_changed = (
                            was_enabled != service.get("enabled", True)
                        )
                        new_domain = service.get("domain", "")
                        if old_domain and new_domain != old_domain:
                            error = self._tunnel_domain_reference_error(
                                [old_domain]
                            )
                            if error:
                                raise settings_store.SettingsError(error)
                        new_ports = self._tunnel_effective_ports(service)
                        if old_ports != new_ports or enabled_changed:
                            changed_ref = ref
                    target = f"{agent['id']}/{service_id}"
                    extra["service_id"] = service_id
                    message = "A szolgáltatás mentve."
                elif action == "tunnel_service_delete":
                    agent = self._tunnel_agent(tunnels, data.get("agent_id"))
                    service_id = data.get("id")
                    ref = f"{agent['id']}/{service_id}"
                    error = self._tunnel_reference_error([ref])
                    if error:
                        raise settings_store.SettingsError(error)
                    doomed = next(
                        (
                            item for item in agent["services"]
                            if item["id"] == service_id
                        ),
                        None,
                    )
                    if doomed is not None:
                        error = self._tunnel_domain_reference_error(
                            [doomed.get("domain", "")]
                        )
                        if error:
                            raise settings_store.SettingsError(error)
                    before = len(agent["services"])
                    agent["services"] = [
                        item for item in agent["services"]
                        if item["id"] != service_id
                    ]
                    if len(agent["services"]) == before:
                        raise settings_store.SettingsError(
                            "tunnel: nincs ilyen szolgáltatás"
                        )
                    target = ref
                    message = "A szolgáltatás törölve."
                new_data = self.gw.settings.prepare_tunnels(tunnels)
                self.gw.apply_settings(new_data)
                if action == "tunnel_service_save":
                    saved_agent = next(
                        (
                            item["services"]
                            for item in new_data["tunnels"]["agents"]
                            if item["id"] == agent["id"]
                        ),
                        [],
                    )
                    saved_service = next(
                        (
                            item for item in saved_agent
                            if item["id"] == service_id
                        ),
                        None,
                    )
                    if saved_service is not None:
                        mappings = saved_service["mappings"]
                        extra["mappings"] = len(mappings)
                        extra["ports"] = ", ".join(
                            f"{mapping['proto']}:{mapping['listen']}"
                            f"->{mapping['target']}"
                            for mapping in mappings
                        )
                    # A módosított leképzésre épülő szabályok feloldott
                    # portjai frissülnek; a megváltozott szabályok
                    # munkameneteit azonnal bontjuk. Letiltáskor a
                    # hivatkozó szabályok hozzáférése mindenképpen
                    # megszűnik, ezért a hivatkozó szabályok munkamenetei
                    # is bontandók (fail-closed).
                    if changed_ref is not None:
                        references = self.gw.rules.service_references()
                        rule_ids = set(references.get(changed_ref, ()))
                        if rule_ids:
                            refreshed = self.gw.rules.reflect_services()
                            if refreshed:
                                extra["service_rules_refreshed"] = ",".join(
                                    refreshed
                                )
                            extra["sessions_revoked"] = (
                                self.gw.sessions.revoke_rules(
                                    sorted(set(refreshed) | rule_ids)
                                )
                            )
                        if became_disabled:
                            message = (
                                "A szolgáltatás letiltva; a hivatkozó "
                                "szabályok hozzáférése megszűnt."
                                if rule_ids else "A szolgáltatás letiltva."
                            )
                if action == "tunnel_agent_update" and agent_toggled:
                    # Az ügynök letiltása az összes szolgáltatását elérhetet-
                    # lenné teszi. A feloldott portok újraszámolása után a
                    # hivatkozó szabályok (a gyűjtőkön át is) munkamenetei
                    # azonnal bontandók.
                    refreshed = self.gw.rules.reflect_services()
                    try:
                        references = self.gw.rules.service_references()
                    except Exception:
                        references = {}
                    rule_ids = set(refreshed)
                    for ref in agent_service_refs:
                        rule_ids.update(references.get(ref, ()))
                    if rule_ids:
                        if refreshed:
                            extra["service_rules_refreshed"] = ",".join(
                                refreshed
                            )
                        extra["sessions_revoked"] = (
                            self.gw.sessions.revoke_rules(sorted(rule_ids))
                        )
                    if agent_disabled:
                        if any(
                            references.get(ref) for ref in agent_service_refs
                        ):
                            message = (
                                "Az ügynök letiltva; a hivatkozó szabályok "
                                "hozzáférése megszűnt."
                            )
                        else:
                            message = "Az ügynök letiltva."
                self._audit(
                    "admin_settings_changed",
                    user=session.user,
                    action=action,
                    target=target,
                    tunnel_agents=len(new_data["tunnels"]["agents"]),
                    tunnel_services=sum(
                        len(agent["services"])
                        for agent in new_data["tunnels"]["agents"]
                    ),
                    **extra,
                )
        except tunnel_mod.TunnelError as exc:
            self._admin_action_error(action, exc, target=target)
            self._json(
                503,
                {
                    "ok": False,
                    "field": "wireguard",
                    "error": f"a WireGuard-kulcsok előállítása nem sikerült: {exc}",
                },
            )
            return
        except (settings_store.SettingsError, ValueError) as exc:
            self._admin_action_error(action, exc, target=target)
            self._json(
                400,
                {
                    "ok": False,
                    "field": _tunnel_error_field(str(exc)),
                    "error": str(exc),
                },
            )
            return
        except (gateway.FirewallError, OSError) as exc:
            self._admin_action_error(action, exc, target=target)
            self._json(
                503,
                {
                    "ok": False,
                    "field": "tunnels",
                    "error": "a tűzfal-beállítások alkalmazása nem "
                             f"sikerült: {exc}",
                },
            )
            return
        payload = self._admin_state()
        payload.update(extra)
        payload["message"] = message
        self._json(200, payload)

    def _tunnel_test_address(self, agent: dict) -> str:
        """A teszt célcíme; tesztben felülbírálható (pl. 127.0.0.1)."""
        return str(agent.get("address") or "")

    @staticmethod
    def _tunnel_probe_tcp(address: str, port: int) -> dict:
        """Egy TCP-kapcsolat a teljes úton (portál -> WireGuard -> DNAT).

        A sikerhez elég a kapcsolat létrejötte: a port elérhető. A nyitott
        socketet azonnal bezárjuk, mert a teszt nem küld protokoll-adatot.
        """
        try:
            connection = socket.create_connection(
                (address, port), timeout=_TUNNEL_TEST_TCP_TIMEOUT
            )
            connection.close()
            return {"ok": True, "detail": "csatlakozás létrejött"}
        except socket.timeout:
            return {"ok": False, "detail": "időtúllépés"}
        except ConnectionRefusedError:
            return {"ok": False, "detail": "elutasítva"}
        except OSError as exc:
            return {"ok": False, "detail": f"hálózati hiba: {exc}"}

    @staticmethod
    def _tunnel_probe_udp(address: str, port: int) -> dict:
        """Egyetlen nulla bájt kiküldése UDP-n, rövid válaszvárakozással.

        UDP-n a válasz hiánya nem hiba: a cél nem köteles visszaírni. A
        ``ConnectionRefusedError`` viszont ICMP port-unreachable-t jelent,
        vagyis a cél nem hallgat a porton; ezt hibaként jelentjük.
        """
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.settimeout(_TUNNEL_TEST_UDP_WAIT)
            probe.connect((address, port))
            probe.send(b"\x00")
            try:
                probe.recv(1)
            except socket.timeout:
                return {
                    "ok": True,
                    "detail": "kiküldve, UDP-válasz nem várható",
                }
            return {"ok": True, "detail": "válasz érkezett"}
        except ConnectionRefusedError:
            return {"ok": False, "detail": "elutasítva (ICMP)"}
        except socket.timeout:
            # A send/connect várakozása sem tekinthető elutasításnak.
            return {
                "ok": True,
                "detail": "kiküldve, UDP-válasz nem várható",
            }
        except OSError as exc:
            return {"ok": False, "detail": f"hálózati hiba: {exc}"}
        finally:
            try:
                probe.close()
            except OSError:
                pass

    def _admin_tunnel_service_test(self, session, data: dict) -> None:
        """Egy szolgáltatás teljes elérési útjának próbája (csak olvasás).

        A portál host-hálózatú, ezért az ügynök WireGuard-címére
        (``10.77.0.2:<tunnel_port>``) csatlakozunk: az útvonal a portál
        hostjától a WireGuard-alagúton át az ügynök DNAT-jáig tart. Nem a
        nyilvános WAN-címet és nem a loopbacket használjuk, mert az nem
        ugyanazt az utat járja be. Állapot nem változik, kulcs/token nem
        kerül a naplóba.
        """
        agent_id = str(data.get("agent_id") or "")[:64]
        service_id = str(data.get("service_id") or "")[:64]
        if not agent_id or not service_id:
            self._json(400, {
                "ok": False,
                "error": "tunnel: az ügynök- és szolgáltatás-azonosító kell",
            })
            return
        try:
            snapshot = self.gw.settings.snapshot()
            if snapshot.get("error"):
                raise settings_store.SettingsError(
                    f"a beállításfájl hibás: {snapshot['error']}"
                )
            tunnels = snapshot.get("tunnels")
            if not isinstance(tunnels, dict):
                tunnels = settings_store.default_tunnels()
            agent = next(
                (
                    item for item in tunnels.get("agents", [])
                    if item.get("id") == agent_id
                ),
                None,
            )
            if agent is None:
                self._json(404, {
                    "ok": False, "field": "agent_id",
                    "error": "tunnel: nincs ilyen ügynök",
                })
                return
            service = next(
                (
                    item for item in agent.get("services", [])
                    if item.get("id") == service_id
                ),
                None,
            )
            if service is None:
                self._json(404, {
                    "ok": False, "field": "service_id",
                    "error": "tunnel: nincs ilyen szolgáltatás",
                })
                return
            if not agent.get("enabled", True):
                self._json(409, {
                    "ok": False, "field": "agent_id",
                    "error": "tunnel: az ügynök ki van kapcsolva",
                })
                return
            if not service.get("enabled", True):
                self._json(409, {
                    "ok": False, "field": "service_id",
                    "error": "tunnel: a szolgáltatás ki van kapcsolva",
                })
                return
            # A kiterjesztett leképezések a tartományokat is felbontják, és
            # a tcp+udp párt ugyanúgy ``both``-ra vonják össze, mint az
            # ügynök szinkronja.
            mappings = [
                item for item in settings_store.agent_services_expanded(agent)
                if item.get("service_id") == service_id
            ]
        except settings_store.SettingsError as exc:
            self._admin_action_error(
                "tunnel_service_test", exc, target=f"{agent_id}/{service_id}",
            )
            self._json(400, {"ok": False, "error": str(exc)})
            return
        if not mappings:
            self._json(409, {
                "ok": False, "field": "service_id",
                "error": "tunnel: nincs tesztelhető portleképezés",
            })
            return

        limited = mappings[:_TUNNEL_TEST_MAX_MAPPINGS]
        address = self._tunnel_test_address(agent)
        slots: list[list[dict]] = [[] for _ in limited]

        def probe(index: int, item: dict) -> None:
            host = str(item.get("target_host") or "—")
            target = f"{host}:{item.get('target_port')}"
            listen = int(item["tunnel_port"])
            proto = item.get("proto")
            local: list[dict] = []
            if proto in ("tcp", "both"):
                outcome = self._tunnel_probe_tcp(address, listen)
                local.append({
                    "proto": "tcp", "listen": listen, "target": target,
                    "ok": bool(outcome["ok"]), "detail": str(outcome["detail"]),
                })
            if proto in ("udp", "both"):
                outcome = self._tunnel_probe_udp(address, listen)
                local.append({
                    "proto": "udp", "listen": listen, "target": target,
                    "ok": bool(outcome["ok"]), "detail": str(outcome["detail"]),
                })
            slots[index] = local

        threads = []
        for index, item in enumerate(limited):
            thread = threading.Thread(
                target=probe, args=(index, item), daemon=True,
                name=f"tunnel-test-{agent_id}-{item['tunnel_port']}",
            )
            thread.start()
            threads.append(thread)
        deadline = time.monotonic() + _TUNNEL_TEST_DEADLINE
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        results = [row for slot in slots for row in slot]
        expected = sum(
            2 if item.get("proto") == "both" else 1 for item in limited
        )
        finished = len(results) >= expected
        # A TCP a mérvadó; ha nincs TCP-próba (tiszta UDP), akkor az UDP.
        tcp_results = [row for row in results if row["proto"] == "tcp"]
        authoritative = tcp_results or [
            row for row in results if row["proto"] == "udp"
        ]
        reachable = (
            finished and bool(authoritative)
            and all(row["ok"] for row in authoritative)
        )
        summary = "a szolgáltatás elérhető"
        if not reachable:
            failures = [row for row in authoritative if not row["ok"]]
            if failures:
                first = failures[0]
                summary = (
                    "a szolgáltatás nem érhető el: "
                    f"{first['proto'].upper()} {first['listen']} "
                    f"({first['detail']})"
                )
            else:
                summary = "a szolgáltatás nem érhető el: a teszt nem fejeződött be"
        if len(mappings) > len(limited):
            summary += (
                f"; csak az első {len(limited)} leképezés lett tesztelve"
            )
        self._audit(
            "tunnel_service_test",
            user=session.user,
            agent_id=agent_id,
            service_id=service_id,
            protos=",".join(row["proto"] for row in results),
            listen_ports=",".join(str(row["listen"]) for row in results),
            target_ports=",".join(
                str(item.get("target_port")) for item in limited
            ),
            ok=",".join("1" if row["ok"] else "0" for row in results),
        )
        self._json(200, {
            "ok": True,
            "service": _tunnel_service_public(service),
            "results": results,
            "summary": summary,
        })

    @staticmethod
    def _tunnel_agent(tunnels: dict, agent_id) -> dict:
        agent = next(
            (
                item for item in tunnels.get("agents", [])
                if item["id"] == agent_id
            ),
            None,
        )
        if agent is None:
            raise settings_store.SettingsError("tunnel: nincs ilyen ügynök")
        return agent

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
                            "proxy_enabled", "proxy_max",
                            "proxy_window_seconds",
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
                            "proxy_enabled", "proxy_max",
                            "proxy_window_seconds",
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
                        # A proxy-tiltás (TCP 80/443) külön oldható fel; a
                        # teljes tiltás ettől megmarad, és fordítva.
                        proxy = data.get("proxy", False) is True
                        existing = (
                            self.gw.fail2ban.proxy_banned(ip) if proxy
                            else self.gw.fail2ban.banned(ip)
                        )
                        if not self.gw.fail2ban.unban(ip, proxy=proxy):
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
                            "proxy": proxy,
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
        if path == "/api/admin/certs":
            return self._admin_certs_action()
        if path == "/api/admin/fail2ban":
            return self._admin_fail2ban_action()
        if path == "/api/admin/config/import":
            return self._admin_config_import()
        if path == "/api/admin/config/reset":
            return self._admin_config_reset()
        if path.startswith("/api/gate/"):
            return self._gate_api(path)
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
        # A belépés válasza ugyanazt a már érvényes közleményt kapja, mint
        # a /api/status; lejárt vagy kikapcsolt MOTD nem kerül bele.
        motd = settings_store.active_motd(self.gw.settings.snapshot())
        if motd:
            payload["motd"] = motd
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
            "tcp": gateway.format_ports(session.tcp, separator=","),
            "udp": gateway.format_ports(session.udp, separator=","),
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
        except (gateway.RuleStoreError, gateway.UserStoreError,
                gateway.GroupStoreError, ValueError) as exc:
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
        # A kiosztásokat a mentés ELŐTT ellenőrizzük: érvénytelen azonosító
        # esetén a szabály ne jöjjön létre.
        users = self._rule_users(data)
        groups = self._group_ids(data)
        rule = self.gw.rules.create(rule_id, data)
        assignments = self._apply_rule_assignments(rule.id, users, groups)
        self._audit(
            "admin_rule_created",
            target=rule.id,
            user=self._session().user if self._session() else "",
            direction=rule.direction,
            ports=rule.ports.label(),
            domains=",".join(rule.domains),
            service_refs=",".join(rule.service_refs),
            default_ttl=rule.default_ttl,
            max_ttl=rule.max_ttl,
            collection=rule.collection,
            members=len(rule.members),
            **assignments,
        )
        # A host (input) szabály portjai azonnal kerüljenek a kerneloldali
        # host_service_* védőhalmazokba; egy esetleges hiba csak naplózódik.
        self.gw.sync_host_ports()

    def _admin_rule_update(self, data: dict) -> None:
        rule_id = data.get("id")
        if not isinstance(rule_id, str):
            raise gateway.RuleStoreError("hiányzó szabály-azonosító")
        # A kiosztásokat a mentés ELŐTT ellenőrizzük: érvénytelen azonosító
        # esetén a szabály ne módosuljon.
        users = self._rule_users(data)
        groups = self._group_ids(data)
        # A függő gyűjtők listáját a szabálytár a módosítással egy záron
        # belül, a commit pontján adja vissza: a közben létrehozott gyűjtő
        # is belekerül, így nem maradhat engedélyezett munkamenet a régi
        # portokkal, nem csak a szabály sajátjait kell bontani.
        rule, dependents = self.gw.rules.update_with_dependents(
            rule_id.strip(), data
        )
        revoked = self.gw.sessions.revoke_rules((rule.id, *dependents))
        assignments = self._apply_rule_assignments(rule.id, users, groups)
        self._audit(
            "admin_rule_updated",
            target=rule.id,
            user=self._session().user if self._session() else "",
            direction=rule.direction,
            ports=rule.ports.label(),
            domains=",".join(rule.domains),
            service_refs=",".join(rule.service_refs),
            default_ttl=rule.default_ttl,
            max_ttl=rule.max_ttl,
            collection=rule.collection,
            members=len(rule.members),
            collections_affected=",".join(dependents),
            sessions_revoked=revoked,
            **assignments,
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
            service_refs=",".join(rule.service_refs),
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


# ---------------------------------------------- Caddy tanúsítvány-gyorsítótár
#
# A certmagic (Caddy 2.10.2) kézfogáskor először a memóriájában tartott
# tanúsítványt adja ki, csak utána kérdezi a get_certificate-et és az ask-et;
# a konfiguráció újratöltése pedig az on-demand tanúsítványokat nem veszi ki
# a gyorsítótárból. Az ACME kikapcsolása után így a már kiadott Let's
# Encrypt-tanúsítványok a Caddy újraindításáig megmaradnának. A portál ezért
# az admin API (Unix socket a közös caddy-admin köteten) POST /stop hívásával
# leállítja a Caddyt, amelyet a compose (restart: unless-stopped) azonnal
# újraindít, üres gyorsítótárral. A /data tárolóhoz nem nyúl: a
# visszakapcsolt ACME a meglévő tanúsítványt tölti be, új kiadás nélkül.

CADDY_RESTART_PENDING_NAME = "caddy-restart-pending"


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._unix_path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._unix_path)


class CaddyAdmin:
    """A Caddy admin API kliense és a gyorsítótár-ürítő háttérszál.

    Az újraindítási igény a jelzőfájlban is megmarad, így a portál
    újraindítása után is lefut; a sikeres /stop törli. Újraindítás csak
    kérésre és kérésenként egyszer történik, ciklusban soha.
    """

    CHECK_INTERVAL = 60.0
    MAX_BACKOFF = 60.0
    # A /stop a Caddy grace_period-jéig (5 s) is eltarthat.
    TIMEOUT = 15.0

    def __init__(self, socket_path: str, pending_path: str) -> None:
        self.socket_path = socket_path
        self.pending_path = pending_path
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None
        self._failures = 0
        # Minden kérés új generáció: a /stop alatt érkezett kérés nem vész el.
        self._generation = 1 if os.path.exists(pending_path) else 0
        self._done = 0
        self._status = {
            "reachable": None, "checked_at": 0, "restarted_at": 0, "error": "",
        }

    def _call(self, method: str, path: str) -> int:
        conn = _UnixHTTPConnection(self.socket_path, self.TIMEOUT)
        try:
            conn.request(method, path)
            response = conn.getresponse()
            response.read(65536)
            return response.status
        finally:
            conn.close()

    def request_restart(self) -> None:
        """A Caddy újraindításának kérése (ACME be→ki, tanúsítványfeltöltés)."""
        with self._lock:
            self._generation += 1
        try:
            with open(self.pending_path, "w", encoding="utf-8"):
                pass
        except OSError as exc:
            # A memóriabeli kérés így is lefut; csak a portál-újraindítás
            # utáni ismétlés vész el.
            print(f"[caddy] a jelzőfájl nem írható: {exc}",
                  file=sys.stderr, flush=True)
        self._wake.set()

    def run_once(self) -> float:
        """Egy kör (függő /stop vagy elérhetőség-ellenőrzés); a következő
        várakozás másodpercben."""
        with self._lock:
            generation = self._generation
        pending = generation != self._done
        now = int(time.time())
        try:
            status = self._call(
                "POST" if pending else "GET",
                "/stop" if pending else "/config/admin",
            )
            if status != 200:
                raise OSError(f"HTTP {status}")
        except (OSError, http.client.HTTPException) as exc:
            self._failures += 1
            with self._lock:
                self._status.update(
                    reachable=False, checked_at=now, error=str(exc)[:200]
                )
            return min(self.MAX_BACKOFF, 2.0 ** self._failures)
        self._failures = 0
        with self._lock:
            self._status.update(reachable=True, checked_at=now, error="")
            if not pending:
                return self.CHECK_INTERVAL
            self._status["restarted_at"] = now
            self._done = generation
            cleared = generation == self._generation
        if cleared:
            try:
                os.remove(self.pending_path)
            except FileNotFoundError:
                pass
            except OSError as exc:
                print(f"[caddy] a jelzőfájl nem törölhető: {exc}",
                      file=sys.stderr, flush=True)
        print("[caddy] a Caddy újraindult (tanúsítvány-gyorsítótár ürítve)",
              flush=True)
        # Az újraindult Caddy elérhetőségét hamar újra megnézzük.
        return 5.0

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._status, pending=self._generation != self._done)

    def _loop(self) -> None:
        delay = 0.0
        while True:
            self._wake.wait(delay)
            self._wake.clear()
            if self._stopping.is_set():
                return
            try:
                delay = self.run_once()
            except Exception as exc:  # a szál soha ne haljon meg
                print(f"[caddy] váratlan hiba: {exc}",
                      file=sys.stderr, flush=True)
                delay = self.MAX_BACKOFF

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, name="hv-caddy", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stopping.set()
        self._wake.set()


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
        description="Felhasználók kezelése a Dropjak users.json fájljában.",
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
                f"portok={'be' if snapshot['drop_ports_enabled'] else 'ki'}, "
                f"proxy={'be' if snapshot['proxy_enabled'] else 'ki'}."
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
                    "proxy": "proxy (HTTP/S)",
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
    # A Caddy tanúsítvány-gyorsítótárának ürítése (csak a domain proxyval).
    caddy = None
    if gateway.PROXY_ENABLED and gateway.CADDY_ADMIN:
        caddy = CaddyAdmin(
            gateway.CADDY_ADMIN,
            os.path.join(gateway.STATE_DIR, CADDY_RESTART_PENDING_NAME),
        )
        gw.caddy = caddy
        caddy.start()
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
        if caddy is not None:
            caddy.stop()
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
