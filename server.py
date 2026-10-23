#!/usr/bin/env python3
"""
Dropjak — HTTP gateway and administrative CLI.

Usage:

  python3 server.py                     # run the gateway
  python3 server.py user add alice      # create a user
  python3 server.py user passwd alice   # change password
  python3 server.py user del alice      # delete a user
  python3 server.py user list           # list users
  python3 server.py check-firewall      # check the nftables set

The actual firewall handling is in gateway.py.
"""

from __future__ import annotations

import argparse
import base64
import collections
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

# The proxy endpoints may only be called by Caddy running on the host (based
# on the raw socket peer, not X-Forwarded-For; see _peer_ip).
PROXY_LOOPBACK = ("127.0.0.1", "::1")
# Caddy's shared-secret header (gateway.PROXY_KEY). Caddy's get_certificate
# and ask calls cannot send headers, so there the key comes in the query.
PROXY_KEY_HEADER = "X-Dropjak-Proxy-Key"
_PROXY_KEY_QUERY_RE = re.compile(r"([?&]key=)[^&\s]*")
# HV_WAN_HTTPS_ONLY refusals are audited at most once per source IP per
# minute, so a client retrying in a loop does not flood the log.
_HTTPS_REQUIRED_AUDIT = gateway.RateLimiter(window=60, maximum=1)
# The /api/ paths that check their caller themselves (loopback/Caddy or the
# tunnel agent's token) and are therefore exempt from the Host allowlist.
_HOST_CHECK_EXEMPT_PREFIXES = ("/api/proxy/", "/api/gate/")
# Components of the multi-log filter: the shape of event codes (lowercase, digit, _).
AUDIT_EVENT_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")

# Host of the port 80 redirect: hostname/IPv4 or [IPv6], with an optional
# port; everything else (CRLF, space, userinfo, %-scope) is invalid.
_REDIRECT_HOST_RE = re.compile(
    r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}"
    r"[a-z0-9])?|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?"
)

# Shared skeleton for the proxy block and challenge pages; _proxy_page fills
# in the {field} placeholders. There is no visible text: an icon shows the state.
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

# Login button: arrow through the door; the text is provided by aria-label.
PROXY_LOGIN_ICON = """<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
<path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h8"/>
<path d="M10 12h11"/>
<path d="m18 8 4 4-4 4"/>
</svg>"""


def _proxy_page(**values: str) -> bytes:
    # Single pass: braces in the inserted CSS/JS are left untouched.
    return _PROXY_PAGE_FIELD.sub(
        lambda match: values.get(match.group(1), ""), PROXY_PAGE
    ).encode("utf-8")


# The challenge page uses the login page's captcha module: its style and
# SHA-256 PoW code are extracted from index.html (once, lazily).
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
        # The page is always dark: the dark theme rules are unconditional.
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
    // Redirects from an unknown subdomain to the root domain; the entry reloads.
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
      try { window.turnstile.reset('#turnstile'); } catch (_) { /* no widget */ }
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
  // The login page's startPow() loop, submitting immediately after solving.
  const start = async () => {
    if (box.dataset.state === 'busy' || box.dataset.state === 'done') return;
    box.dataset.state = 'busy';
    text.textContent = 'Checking…';
    show('');
    try {
      const res = await fetch('/__dropjak/challenge', { cache: 'no-store' });
      const ch = await res.json();
      if (ch.mode !== 'pow') throw new Error('mode changed');
      const difficulty = Number(ch.difficulty);
      if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 6) {
        throw new Error('invalid difficulty');
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
        if (n > limit) throw new Error('computation took too long');
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

TURNSTILE_ORIGIN = "https://challenges.cloudflare.com"


def content_security_policy() -> str:
    """CSP of the HTML pages; the Turnstile origin only while Turnstile is on."""
    extra = f" {TURNSTILE_ORIGIN}" if gateway.TURNSTILE_ON else ""
    frames = TURNSTILE_ORIGIN if gateway.TURNSTILE_ON else "'none'"
    return (
        "default-src 'self'; "
        f"script-src 'self' 'unsafe-inline'{extra}; "
        f"frame-src {frames}; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        f"connect-src 'self'{extra}; "
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


# Proxy challenge pass: a __Host- cookie on the entry host, whose value is
# base64url(host|ip or *|issued ms|expires s).HMAC-SHA256. The key is new per
# process (like the PoW key): every pass is invalid after a restart.
PROXY_PASS_COOKIE = "__Host-dropjak_pass"
PROXY_PASS_TTL = 24 * 3600
_PROXY_PASS_KEY = secrets.token_bytes(32)
_CLI_AGENT_RE = re.compile(
    r"^(?:curl|wget|python-|python/|go-http-client|libwww-perl|httpie|okhttp"
    r"|java/|aiohttp|axios|node-fetch|undici|powershell|scrapy)",
    re.I,
)


# The "burst" condition (many refreshes / spam): this many page loads from the
# same IP to the same host within this many seconds. In memory per process
# (like the pass key), cleared on restart.
PROXY_BURST_LIMIT = 10
PROXY_BURST_WINDOW = 30
PROXY_BURST_MAX_KEYS = 10000
# Least recently used first: a full table evicts the stalest keys only, so a
# client with many IP+host pairs cannot reset everyone's pending detection.
_PROXY_BURST: collections.OrderedDict[
    tuple[str, str], tuple[list[float], float]
] = collections.OrderedDict()
_PROXY_BURST_LOCK = threading.Lock()


def _proxy_burst(ip: str, host: str, now: float, count: bool) -> float:
    """Time of the most recent spam detection for the IP+host (0: none).

    ``count``: this request is a page load and counts. On reaching the limit,
    the detection time is refreshed and the counter is reset.
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
            while len(_PROXY_BURST) >= PROXY_BURST_MAX_KEYS:
                _PROXY_BURST.popitem(last=False)
        _PROXY_BURST[key] = (hits, flagged)
        _PROXY_BURST.move_to_end(key)
        return flagged


def _portal_parent_root(portal: str, roots) -> str:
    """Root domain of the Dropjak address; saving guarantees it, but it also
    safely returns "" from runtime state when there is none."""
    return next((root for root in roots if portal.endswith("." + root)), "")


def _tunnel_domain_target(settings: dict, host: str):
    """Synthetic proxy target and root for a domain-mode tunnel service.

    Only an enabled service of an enabled agent is resolved. Caddy forwards to
    ``10.77.0.2:<internal port>``; the agent DNATs from wg0 to the service's
    container. There is no WAN port and no WAN DNAT.
    """
    if not host:
        return None
    roots = settings.get("proxy_domains", [])
    # The longest matching root wins (saving guarantees this).
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
    # Milliseconds, rounded down: the pass never appears to be later.
    payload = f"{host}|{ip or '*'}|{int(issued * 1000)}|{expires}".encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    return f"{encoded}.{_proxy_pass_sign(payload).decode()}"


def _proxy_pass_issued(value: str, host: str, ip: str, now: float) -> float:
    """Issue time of a valid pass; 0 if missing, false, expired or for
    another host. Empty ``ip``: the pass is valid regardless of IP."""
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


# A session may select at most this many rules at once. The limit also keeps
# the audit and response sizes in check.
MAX_SESSION_RULES = 16


def _log_fail2ban_error(
    ip: str, exc: Exception, audit=None, operation: str = "record"
) -> None:
    print(f"[{ip}] fail2ban: blocking failed: {exc}", flush=True)
    if audit is None:
        return
    try:
        audit.write(
            "fail2ban_error",
            ip=ip,
            operation=operation,
            reason=str(exc),
        )
    except Exception as log_exc:  # logging must not block login
        print(f"[log] failed to write fail2ban_error: {log_exc}", flush=True)


# --------------------------------------------------- two-factor login tickets

LOGIN_TICKET_TTL = 300
LOGIN_TICKET_MAX_ATTEMPTS = 5
# The ticket is bound to a snapshot of the user record. The salt is new per
# process, so the fingerprint stored in memory cannot be reversed externally.
_TICKET_FP_SALT = secrets.token_bytes(32)


def _ticket_hash(token: str) -> str:
    """Non-reversible, 12-character reference to the ticket for the log.

    The raw ticket (and with it the secret needed to continue login) must
    never reach the audit log; only the first 12 characters of this SHA-256
    digest do.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


@dataclass
class LoginTicket:
    """Short-lived, single-use ticket for the 2FA step after the password."""

    token: str
    purpose: str  # "verify" or "enroll"
    username: str
    ip: str
    fingerprint: str
    secret: str = ""
    attempts: int = 0
    expires_at: float = 0.0


class LoginTicketStore:
    """In-memory ticket store with thread-safe, atomic operations.

    Only the same IP address that requested the ticket may use it.
    Failed code attempts are counted against the ticket; on reaching the
    limit the ticket ceases to exist, so the client must restart login.
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
        # The rejection reason of expired or used tickets is kept briefly so
        # a later request can receive the exact reason. This is in-memory data
        # only; the token never reaches the log.
        self._tombstones: dict[str, tuple[str, float]] = {}
        self._tombstone_grace = max(60.0, float(self._ttl))
        self._tombstone_limit = 4096

    @property
    def ttl(self) -> int:
        return self._ttl

    def set_audit(self, audit) -> None:
        """Late binding of the audit log (in the starting process)."""
        self.audit = audit

    def _write_audit(self, event: str, **fields) -> None:
        """Optional log entry; it does not block even on error."""
        if self.audit is None:
            return
        try:
            self.audit.write(event, **fields)
        except Exception as exc:
            print(f"[log] failed to write {event}: {exc}", flush=True)

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
        # Log writing happens under the store lock; AuditLog never reaches
        # back into the ticket store, so no deadlock can occur.
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
        """Read the ticket without consuming it; None if invalid."""
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
        """Non-consuming check with the exact rejection reason.

        Returns the valid ticket and an empty reason; otherwise (None, reason),
        where the reason is suitable for logging: ``unknown``, ``expired``,
        ``already_consumed``, ``too_many_attempts``, ``ip_mismatch`` or
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
        """Atomic check and delete: a ticket can be used only once."""
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
        """Record a failed attempt with detailed status.

        Returns: ``(remaining, just_closed, attempts, existed)``.
        The old integer return value of ``fail()`` remains unchanged for
        existing callers and tests.
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
        """Record a failed attempt; the number of remaining attempts (0 = none)."""
        return self.fail_with_status(token, ip)[0]

    def revoke_user(self, username: str, reason: str = "") -> int:
        """Delete all pending tickets of the user.

        With a non-empty ``reason``, an aggregate audit entry is also created
        (admin rejection, disabling, deletion or 2FA reset).
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
        """Discard every ticket; with a non-empty reason, also log an audit entry."""
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
    """Fingerprint of the user snapshot bound to the ticket."""
    digest = hashlib.sha256()
    digest.update(_TICKET_FP_SALT)
    digest.update(record.digest)
    digest.update(b"\x00")
    digest.update(record.totp_secret.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(b"1" if record.totp_required else b"0")
    return digest.hexdigest()


def _access_rule_ids(data: dict) -> tuple[list[str], str]:
    """Interpret the rule selection of the /api/access request.

    Returns: (rule IDs, error message). The new ``rules`` list takes
    precedence over the old ``rule`` field. Duplicate IDs are merged in
    order of first occurrence, so the length limit really counts unique
    rules.
    """
    if "rules" in data:
        raw = data.get("rules")
        if not isinstance(raw, list):
            return [], "the rules list is required"
        selected: list[str] = []
        seen: set[str] = set()
        for item in raw:
            if not isinstance(item, str) or not item.strip():
                return [], "invalid rule list"
            rule_id = item.strip()
            if rule_id in seen:
                continue
            seen.add(rule_id)
            selected.append(rule_id)
        if not selected:
            return [], "select at least one rule"
        if len(selected) > MAX_SESSION_RULES:
            return [], (
                f"at most {MAX_SESSION_RULES} rules can be "
                "selected at once"
            )
        return selected, ""
    rule_id = data.get("rule")
    if not isinstance(rule_id, str):
        return [], "missing rule or duration"
    return [rule_id], ""


# ------------------------------------------------------------ configuration bundle

CONFIG_FORMAT = "dropjak-config"
# 2: the settings section also contains the tunnels (WireGuard tunnel) part.
# Version 1 bundles are still accepted: the missing tunnels section is filled
# with defaults (no agents, the WireGuard port closed).
CONFIG_FORMAT_VERSION = 2
CONFIG_FORMAT_MIN_VERSION = 1
CONFIG_MAX_BYTES = 8 * 1024 * 1024
CONFIG_SECTIONS = ("settings", "rules", "groups", "users", "certs", "fail2ban")
_FAIL2BAN_CONFIG_KEYS = frozenset({
    "enabled", "max_attempts", "window_seconds", "ban_seconds",
    "drop_enabled", "drop_count_enabled", "drop_ports_enabled",
    "drop_max", "drop_ports", "drop_window_seconds",
    "proxy_enabled", "proxy_max", "proxy_window_seconds",
    "drop_exempt",
})
# Added after bundle version 2 was released: an older bundle may lack them.
_FAIL2BAN_OPTIONAL_KEYS = frozenset({"drop_exempt"})


class ConfigBundleError(ValueError):
    """The configuration bundle is invalid or unsupported."""


def _fail2ban_config(snapshot: dict) -> dict:
    """Only the settings, without blocks and counters."""
    return {key: snapshot[key] for key in _FAIL2BAN_CONFIG_KEYS}


def _config_bundle(gw, include_markers: bool = False) -> dict:
    """The full exportable configuration (without logs and runtime state).

    ``include_markers`` keeps the provisioning markers; only the private
    pre-import backup uses it, never a download (DJ-27).
    """
    try:
        settings = gw.settings.snapshot()
        error = settings.pop("error", "")
        if error:
            raise ConfigBundleError(f"the settings file is invalid: {error}")
        settings = settings_store.validate_state(settings)
        sections = {
            "settings": settings,
            "rules": gw.rules.export_records(),
            "groups": gw.groups.export_records(),
            "users": gw.users.export_records(include_marker=include_markers),
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
    """Validate the whole bundle without writing; returns the normalized sections."""
    if not isinstance(bundle, dict):
        raise ConfigBundleError("the bundle must be a JSON object")
    if bundle.get("format") != CONFIG_FORMAT:
        raise ConfigBundleError("this is not a Dropjak configuration bundle")
    version = bundle.get("format_version")
    if isinstance(version, bool) or not isinstance(version, int) \
            or not CONFIG_FORMAT_MIN_VERSION <= version <= CONFIG_FORMAT_VERSION:
        # The raw value is deliberately not echoed back: the bundle content
        # must not leak into the error message.
        raise ConfigBundleError(
            "unsupported format version; this portal supports versions "
            f"{CONFIG_FORMAT_MIN_VERSION}-{CONFIG_FORMAT_VERSION} "
            "(for version 1 the missing tunnels section is filled with "
            "defaults)"
        )
    raw_sections = bundle.get("sections")
    if not isinstance(raw_sections, dict):
        raise ConfigBundleError("the sections field must be a JSON object")
    missing = [name for name in CONFIG_SECTIONS if name not in raw_sections]
    if missing:
        raise ConfigBundleError(
            "missing section(s): " + ", ".join(missing)
        )
    unknown = sorted(set(raw_sections) - set(CONFIG_SECTIONS))
    if unknown:
        raise ConfigBundleError(
            "unknown section(s): " + ", ".join(unknown)
        )
    raw_fail2ban = raw_sections["fail2ban"]
    if not isinstance(raw_fail2ban, dict) \
            or not _FAIL2BAN_CONFIG_KEYS - _FAIL2BAN_OPTIONAL_KEYS \
            <= set(raw_fail2ban) <= _FAIL2BAN_CONFIG_KEYS:
        raise ConfigBundleError(
            "the fail2ban section is incomplete or contains an unknown field"
        )
    raw_settings = raw_sections["settings"]
    if version == 1 and isinstance(raw_settings, dict) \
            and "tunnels" not in raw_settings:
        raw_settings = dict(raw_settings)
        raw_settings["tunnels"] = settings_store.default_tunnels()
    elif version >= 2 and isinstance(raw_settings, dict) \
            and "tunnels" not in raw_settings:
        raise ConfigBundleError(
            "the settings of a version 2 bundle are missing the tunnels section"
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

    # Certificates are separate because CertStore throws only its own error.
    raw_certs = raw_sections["certs"]
    if not isinstance(raw_certs, dict):
        raise ConfigBundleError("the certs section must be a JSON object")
    checked_certs: dict[str, dict] = {}
    for raw_root, item in raw_certs.items():
        if not isinstance(item, dict):
            raise ConfigBundleError(f"{raw_root}: invalid certificate entry")
        try:
            meta = gw.certs.validate_import(
                raw_root, item.get("cert"), item.get("key")
            )
        except settings_store.SettingsError as exc:
            raise ConfigBundleError(f"{raw_root}: {exc}") from exc
        if not isinstance(meta, dict):
            raise ConfigBundleError(f"{raw_root}: invalid certificate")
        root = raw_root.strip().lower()
        if root in checked_certs:
            raise ConfigBundleError(f"duplicate root domain: {root}")
        checked_certs[root] = {
            "cert": item.get("cert"), "key": item.get("key"),
        }
    try:
        fail2ban_config = fail2ban_mod.validate_config(raw_fail2ban)
    except fail2ban_mod.Fail2banError as exc:
        raise ConfigBundleError(f"fail2ban: {exc}") from exc

    # Referential integrity: rule -> proxy host, user -> rule,
    # group -> rule/tag, certificate -> root domain.
    route_hosts = {
        settings_store.route_host(route)
        for route in settings["proxy_routes"]
    }
    for rule in rules.values():
        missing_hosts = [name for name in rule.domains if name not in route_hosts]
        if missing_hosts:
            raise ConfigBundleError(
                f"{rule.id}: no such proxy route: "
                + ", ".join(missing_hosts)
            )
    for name, item in users.items():
        missing_rules = [
            rule_id for rule_id in item.get("rules", ()) if rule_id not in rules
        ]
        if missing_rules:
            raise ConfigBundleError(
                f"{name}: unknown rule: " + ", ".join(missing_rules)
            )
    for group in groups.values():
        missing_rules = [rid for rid in group.rules if rid not in rules]
        if missing_rules:
            raise ConfigBundleError(
                f"{group.id}: unknown rule: " + ", ".join(missing_rules)
            )
        missing_users = [name for name in group.members if name not in users]
        if missing_users:
            raise ConfigBundleError(
                f"{group.id}: unknown member: " + ", ".join(missing_users)
            )
    for root in checked_certs:
        if root not in settings["proxy_domains"]:
            raise ConfigBundleError(
                f"{root}: no such root domain for the certificate"
            )
    if not any(
        item["role"] == gateway.ROLE_ADMIN
        and item["enabled"] and not item["pending"]
        for item in users.values()
    ):
        raise ConfigBundleError(
            "the bundle does not contain at least one enabled admin account"
        )
    return {
        "settings": settings,
        "rules": rules,
        "groups": groups,
        "users": users,
        "certs": checked_certs,
        "fail2ban": fail2ban_config,
    }


def _carry_provision_marker(gw, users: dict) -> dict:
    """Keep the provisioning markers of this installation across an import.

    Exports carry no marker (DJ-27), but without one ``provision_admin``
    would treat the imported .env admin as an old marker-less entry and
    reset its password to the .env value on the next start. An imported
    record without a marker keeps the current installation's marker for
    the same user; for HV_ADMIN_USER without one, a fresh marker of the
    current .env password is stored, so the imported password stays in
    effect. Old bundles that still carry a marker import it unchanged.
    """
    carried = dict(users)
    for name, record in users.items():
        if not isinstance(record, dict) or record.get("provisioned_from"):
            continue
        marker = gw.users.provisioned_from(name)
        if not marker and name == gateway.ADMIN_USER and gateway.ADMIN_PASSWORD:
            marker = gateway.provision_marker(
                gateway.ADMIN_PASSWORD, gw.users.iterations
            )
        if marker:
            carried[name] = dict(record, provisioned_from=marker)
    return carried


def _apply_config_bundle(gw, bundle: dict) -> None:
    """Write the already validated sections through the existing store paths."""
    gw.users.replace_all(_carry_provision_marker(gw, bundle["users"]))
    gw.rules.replace_all(bundle["rules"])
    gw.groups.replace_all(bundle["groups"])
    gw.apply_settings(bundle["settings"])
    # Rules were written before settings, so resolved ports of rules that
    # refer to new tunnel services arriving in the bundle may still be empty.
    # Right after installing the settings we recalculate them (and the
    # dependent collections) so the imported rule is usable without a restart.
    # The recalculated ports are not persisted, so no further file writes are
    # needed.
    refreshed = gw.rules.reflect_services()
    if refreshed:
        gw.sessions.revoke_rules(refreshed)
    gw.certs.replace_all(bundle["certs"])
    gw.fail2ban.configure(bundle["fail2ban"])
    gw.sync_host_ports()


def _config_counts(bundle: dict) -> dict:
    """Only counts for the audit (never content or secrets)."""
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
# Upper limits of the reachability test: mappings run in parallel, so a dead
# target does not multiply the wait. TCP settles within 2 s, the UDP probe
# waits at most 0.6 s for a reply.
_TUNNEL_TEST_MAX_MAPPINGS = 4
_TUNNEL_TEST_TCP_TIMEOUT = 2.0
_TUNNEL_TEST_UDP_WAIT = 0.6
_TUNNEL_TEST_DEADLINE = 6.0


def _tunnel_agent_bundle_dir() -> str:
    """Source files of the agent bundle (Docker layout: ./tunnel-agent)."""
    base = os.path.dirname(os.path.abspath(__file__))
    for path in (os.path.join(base, "tunnel-agent"),
                 os.path.join(base, "deploy", "tunnel-agent")):
        if os.path.isfile(os.path.join(path, "agent.py")):
            return path
    return ""


def _tar_member(tar: tarfile.TarFile, name: str, data: bytes,
                mode: int) -> None:
    """One file in the in-memory tar.gz bundle (no temp file)."""
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(data))


def _tunnel_service_public(service: dict) -> dict:
    """Admin view of one service with the derived ports."""
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
    """Admin view of tunnel agents: without key and token."""
    tunnels = settings.get("tunnels")
    if not isinstance(tunnels, dict):
        tunnels = settings_store.default_tunnels()
    try:
        status = gw.tunnels.status(tunnels)
    except Exception:
        status = {"error": "", "agents": []}
    rows = {row.get("id"): row for row in status.get("agents", [])}
    # Age in seconds of the agent's last successful configuration sync.
    # Sync times use the monotonic clock; the snapshot is taken under the
    # lock so the update does not read a half-finished state.
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
    """Field name from the validation error text (for marking in the UI)."""
    for needle, field in (
        ("listen port", "listen_port"),
        ("internal port", "tunnel_port"),
        ("target port", "target"),
        ("target host", "target_host"),
        ("port mapping", "mappings"),
        ("mapping", "mappings"),
        ("mappings", "mappings"),
        ("target", "target"),
        ("protocol", "proto"),
        ("agent address", "address"),
        ("agent ID", "id"),
        ("agent", "agents"),
        ("token", "token"),
        ("private key", "server_private_key"),
        ("preshared key", "preshared_key"),
        ("WireGuard key", "server_private_key"),
        ("WireGuard port", "port"),
        ("endpoint", "endpoint"),
        ("label", "label"),
    ):
        if needle in error:
            return field
    return fallback


def _effective_site_name(gw) -> str:
    value = gw.settings.snapshot().get("site_name")
    return value.strip() if isinstance(value, str) and value.strip() else "Dropjak"


def _config_state_nonempty(gw) -> bool:
    """Is there state that must be protected by a typed name before import?

    The admin created from .env does not count as user state: on a fresh
    installation this is the only account, and a restart recreates it anyway.
    The initial (seeded) rules also do not count.
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
        # If we cannot confidently see it as empty, ask for confirmation.
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
    """Save the bundle atomically with mode 0600 (the directory is not created)."""
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
    """SIGTERM to the own process; compose ``restart: unless-stopped`` restarts it.

    Outside Docker the process simply stops (the UI indicates this).
    """
    def _stop() -> None:
        try:
            os.kill(os.getpid(), signal.SIGTERM)
        except OSError:
            pass

    timer = threading.Timer(delay, _stop)
    timer.daemon = True
    timer.start()


# -------------------------------------------------------------------- HTTP layer

class Handler(BaseHTTPRequestHandler):
    server_version = "Dropjak/2"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    # Slow/stuck connections must not occupy threads forever.
    timeout = 30
    # Set per request; prevents a later error branch from consuming the
    # already read body again from the keep-alive connection.
    _body_read = False

    # -- helpers ---------------------------------------------------------------

    @property
    def gw(self) -> gateway.Gateway:
        return self.server.gateway  # type: ignore[attr-defined]

    def _peer_ip(self) -> str:
        """The raw socket peer (behind Caddy, 127.0.0.1)."""
        try:
            return gateway.normalize_ip(self.client_address[0])
        except ValueError:
            return str(self.client_address[0])

    def _from_caddy(self, query_key: bool = False) -> bool:
        """Whether the request comes from Caddy running on the host.

        A loopback peer is required. With HV_PROXY_KEY set, the shared
        secret is required too, so other host processes and host-network
        containers are no longer trusted as Caddy. ``query_key`` accepts the
        key from the ``key`` query parameter (get_certificate, ask).
        """
        if self._peer_ip() not in PROXY_LOOPBACK:
            return False
        if not gateway.PROXY_KEY:
            return True
        headers = getattr(self, "headers", None)
        provided = (headers.get(PROXY_KEY_HEADER) if headers else None) or ""
        if not provided and query_key:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            provided = (query.get("key") or [""])[0]
        return hmac.compare_digest(
            provided.encode("utf-8", "replace"),
            gateway.PROXY_KEY.encode("utf-8"),
        )

    def _tunnel_peer_refused(self, path: str) -> bool:
        """Tunnel peers may call only the agent sync endpoint.

        The firewall opens the whole portal port to the WireGuard network,
        but an agent needs nothing else. Every other path (login, account,
        admin) gets a detail-free 404, even when HV_PORTAL_NET is narrow.
        Returns True when the response has already been sent.
        """
        try:
            peer = ipaddress.ip_address(self._peer_ip())
        except ValueError:
            return False
        if peer not in settings_store.TUNNEL_SUBNET:
            return False
        if self.command == "GET" and path == _TUNNEL_SYNC_PATH:
            return False
        self._discard_body()
        self._json(404, {"ok": False, "error": "unknown endpoint"})
        return True

    def _client_ip(self) -> str:
        # Trust boundary: X-Forwarded-For is accepted only from Caddy (a
        # loopback peer, plus the HV_PROXY_KEY shared secret when it is set).
        # Caddy's reverse_proxy drops incoming XFF and sets it to the real
        # remote address, so the last element cannot be forged. Headers from
        # other peers are ignored; on an invalid value the peer remains.
        peer = self._peer_ip()
        headers = getattr(self, "headers", None)
        forwarded = headers.get("X-Forwarded-For") if headers else None
        if forwarded and self._from_caddy():
            try:
                return gateway.normalize_ip(forwarded.split(",")[-1])
            except ValueError:
                pass
        return peer

    def _via_proxy(self) -> bool:
        """Whether the request came through Caddy to a root domain's HTTPS portal."""
        if not self._from_caddy():
            return False
        host = (self.headers.get("Host") or "").strip().lower()
        return host.partition(":")[0] in self.gw.settings.snapshot().get(
            "proxy_domains", []
        )

    def _cookie_secure(self) -> bool:
        """Whether the session cookie gets the Secure attribute.

        Caddy serves the portal only in its https:// site (its http:// site
        only asks /api/proxy/redirect for a 3xx), so with HV_PROXY_KEY set a
        response that goes back through Caddy always reaches the browser
        over HTTPS, under any host name. Without a key a bare loopback peer
        is not conclusive; then only a proxy root domain counts. Plain-HTTP
        LAN logins keep a cookie without Secure (unless HV_COOKIE_SECURE=1).
        """
        if gateway.COOKIE_SECURE or self._via_proxy():
            return True
        return bool(gateway.PROXY_KEY) and self._from_caddy()

    @staticmethod
    def _https_only_path(path: str) -> bool:
        return (
            path == "/api/login" or path.startswith("/api/login/")
            or path == "/api/password" or path.startswith("/api/admin/")
        )

    def _https_required(self, path: str) -> bool:
        """HV_WAN_HTTPS_ONLY: refuse credentials over the plain-HTTP port.

        Applies to the login, password and admin endpoints. A request that
        came through Caddy (HTTPS) passes, and so do LAN sources and
        loopback-direct callers (healthcheck, the CLI, tests on the host).
        Returns True when the 403 has already been sent.
        """
        if not gateway.WAN_HTTPS_ONLY or not self._https_only_path(path):
            return False
        if self._from_caddy():
            return False
        peer = self._peer_ip()
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            address = None
        if address is not None and (
            address.is_loopback
            or (gateway.LAN_NETWORK is not None
                and address in gateway.LAN_NETWORK)
        ):
            return False
        if _HTTPS_REQUIRED_AUDIT.allow(peer):
            self._audit(
                "https_required",
                ip=peer,
                path=path[:200],
                reason="non-LAN source on the plain-HTTP portal port",
            )
        self._discard_body()
        self._json(
            403,
            {
                "ok": False,
                "error": "Sign-in from this network is allowed only over "
                         "HTTPS. Open the portal at its https:// address.",
                "code": "https_required",
            },
        )
        return True

    def log_message(self, fmt: str, *args) -> None:
        # The request line of Caddy's get_certificate/ask call carries the
        # shared secret in the query: it must not reach the log.
        line = _PROXY_KEY_QUERY_RE.sub(r"\1<redacted>", fmt % args)
        print(f"[{self._client_ip()}] {line}", flush=True)

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
        """Whether this is a same-origin request (against CSRF, alongside SameSite)."""
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
            # Read the body before the early 403, otherwise on a keep-alive
            # connection the next request would be read after the old body.
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
            self.send_header("Content-Security-Policy", content_security_policy())
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
            self._json(500, {"ok": False, "error": "the UI file is missing"})
            return
        if name == "index.html":
            body = body.replace(
                b"__VERSION__", gateway.APP_VERSION.encode("ascii", "replace")
            )
        self._send(200, body, ctype, cache=cache)

    def _read_json(self, limit: int = 64 * 1024) -> dict | None:
        # State-changing endpoints accept only JSON. This also excludes browser
        # form (simple request) CSRF, because a form cannot send an
        # application/json content type.
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
        # Defense in depth: a blocked IP address cannot use even its existing
        # session on protected endpoints. Here we deliberately do not revoke
        # the session (the login/access paths do that); the blocked client is
        # simply unauthenticated.
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
                reason="no admin session",
                path=urllib.parse.urlsplit(self.path).path,
            )
            # The body must be read before the 403, otherwise on a keep-alive
            # connection the next request would run into the old body.
            self._discard_body()
            self._json(
                403,
                {
                    "ok": False,
                    "error": "admin privileges required",
                    "code": "admin_session",
                },
            )
            return None
        record = self.gw.users.record(session.user)
        if record is None or not record.enabled or record.pending or not record.is_admin:
            # The session's role/active state is checked on every admin request
            # from the current user registry, not from the snapshot taken at
            # login. A stale session must not survive.
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
                reason="the user is no longer an active admin",
                path=urllib.parse.urlsplit(self.path).path,
            )
            self._discard_body()
            self._json(
                403,
                {
                    "ok": False,
                    "error": "admin privileges required",
                    "code": "admin_session",
                },
            )
            return None
        if record.must_change_password:
            self._audit(
                "admin_denied",
                user=session.user,
                reason="before mandatory password change",
                path=urllib.parse.urlsplit(self.path).path,
            )
            self._discard_body()
            self._json(
                403,
                {
                    "ok": False,
                    "error": "Change your initial password first.",
                    "must_change_password": True,
                },
            )
            return None
        return session

    def _step_up(self, session: gateway.Session, data: dict | None,
                 action: str) -> bool:
        """Fresh proof of identity before a sensitive admin action.

        The admin session alone (valid for the whole network grant, up to
        30 days) is not enough for export, import and reset: the request
        must carry the admin's current password, and the current TOTP code
        when 2FA is enrolled. A failure counts like a failed login (rate
        limit, account lock, fail2ban). On failure the response is sent and
        False is returned; the session itself stays valid.
        """
        ip = self._client_ip()
        data = data if isinstance(data, dict) else {}
        password = data.get("password")
        code = data.get("code")
        record = self.gw.users.record(session.user)
        totp = bool(record is not None and record.totp_secret)
        reason = ""
        if not isinstance(password, str) or not password:
            reason = "missing"
        elif not self.gw.login_rate.allow(ip):
            reason = "rate_limited"
        elif self._account_lock_applies(ip) \
                and self.gw.account_lockout.locked(session.user):
            reason = "account_locked"
        elif len(password) > 1024 \
                or not self.gw.users.verify(session.user, password):
            reason = "invalid_password"
        elif totp and not (
            isinstance(code, str) and self.gw.users.verify_totp(
                session.user, code.strip()
            )
        ):
            reason = "invalid_code"
        if not reason:
            return True
        self._audit(
            "step_up_failed", user=session.user, action=action, reason=reason,
        )
        if reason in ("invalid_password", "invalid_code"):
            self._account_failure(ip, session.user)
            try:
                self.gw.fail2ban.record_failure(ip, session.user)
            except fail2ban_mod.Fail2banError as exc:
                _log_fail2ban_error(
                    ip, exc, self.gw.audit, operation="record_failure"
                )
        self._json(
            429 if reason in ("rate_limited", "account_locked") else 403,
            {
                "ok": False,
                "error": "Enter your password (and 2FA code) again to "
                         "continue.",
                "code": "step_up_required",
                "totp": totp,
            },
        )
        return False

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
        # The raw tunnels section contains private keys and tokens;
        # the UI receives only the secret-free view above.
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
            # Metadata only: the key and PEM never enter the response.
            "proxy_certs": self.gw.certs.public(settings),
            # Status of the Caddy admin API (None: no domain proxy).
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
            raise gateway.RuleStoreError("the rules field must be a list of at most 64 elements")
        out: list[str] = []
        for value in raw:
            if not isinstance(value, str) or not value.strip():
                raise gateway.RuleStoreError("invalid rule ID")
            value = value.strip()
            if value == gateway.LEGACY_ADMIN_RULE_ID:
                raise gateway.RuleStoreError(
                    "this is a reserved legacy ID and cannot be assigned"
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
                f"unknown rule: {', '.join(sorted(unknown))}"
            )

    def _group_ids(self, data: dict) -> list[str] | None:
        if "groups" not in data:
            return None
        raw = data.get("groups")
        if not isinstance(raw, list) or len(raw) > 64:
            raise gateway.GroupStoreError("the groups field must be a list of at most 64 elements")
        out: list[str] = []
        for value in raw:
            if not isinstance(value, str) or not value.strip():
                raise gateway.GroupStoreError("invalid group ID")
            value = value.strip()
            if self.gw.groups.get(value) is None:
                raise gateway.GroupStoreError(f"unknown group: {value}")
            if value not in out:
                out.append(value)
        return out

    def _members(self, data: dict) -> list[str] | None:
        if "members" not in data:
            return None
        raw = data.get("members")
        if not isinstance(raw, list) or len(raw) > 512:
            raise gateway.GroupStoreError("the members field must be a list of at most 512 elements")
        out: list[str] = []
        for value in raw:
            if not isinstance(value, str) or not value.strip():
                raise gateway.GroupStoreError("invalid username")
            value = value.strip()
            record = self.gw.users.record(value)
            if record is None:
                raise gateway.GroupStoreError(f"unknown user: {value}")
            if record.pending:
                raise gateway.GroupStoreError(
                    "an account pending approval cannot be assigned to a group"
                )
            if value not in out:
                out.append(value)
        return out

    def _rule_users(self, data: dict) -> list[str] | None:
        """Direct user assignments of the rule (optional ``users``)."""
        if "users" not in data:
            return None
        raw = data.get("users")
        if not isinstance(raw, list) or len(raw) > 512:
            raise gateway.UserStoreError(
                "the users field must be a list of at most 512 elements"
            )
        out: list[str] = []
        for value in raw:
            if not isinstance(value, str) or not value.strip():
                raise gateway.UserStoreError("invalid username")
            value = value.strip()
            record = self.gw.users.record(value)
            if record is None:
                raise gateway.UserStoreError(
                    f"unknown user: {value}"
                )
            if record.pending:
                raise gateway.UserStoreError(
                    "an account pending approval cannot be assigned to a rule"
                )
            if value not in out:
                out.append(value)
        return out

    def _apply_rule_assignments(
        self, rule_id: str, users, groups
    ) -> dict:
        """Apply the rule's direct user and group assignments.

        The caller has already validated the IDs and saved the rule. The two
        stores are separate files, so on partial failure the already applied
        half is rolled back: the rule stays saved, but assignments do not
        remain half-modified. Returns: the audit fields.
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
                    "[rules] failed to roll back the user assignment: "
                    f"{rollback_exc}",
                    flush=True,
                )
            message = (
                "the rule was saved, but applying the assignment "
                f"failed: {exc}"
            )
            if rollback_failed:
                message += " (rolling back the partial change also failed)"
            raise gateway.RuleStoreError(message) from exc
        return {
            "users_added": ",".join(result["users_added"]),
            "users_removed": ",".join(result["users_removed"]),
            "groups_added": ",".join(result["groups_added"]),
            "groups_removed": ",".join(result["groups_removed"]),
        }

    def _portal_host_matches(self) -> bool:
        # On the root domains, Caddy serves the portal over HTTPS.
        if self._via_proxy():
            return True
        if not gateway.PORTAL_URL:
            # No canonical address: the page may stay under any host the
            # /api/ endpoints also accept (see _host_allowed).
            return self._host_allowed()
        host = (self.headers.get("Host") or "").strip().lower()
        if not host:
            return True
        target = urllib.parse.urlsplit(gateway.PORTAL_URL).netloc.lower()
        return host == target

    def _portal_redirect_url(self) -> str:
        """Where a foreign Host is sent: PORTAL_URL, or the address the
        connection arrived on (the gateway's own IP on that interface)."""
        if gateway.PORTAL_URL:
            return gateway.PORTAL_URL
        try:
            local = gateway.normalize_ip(self.connection.getsockname()[0])
        except (OSError, ValueError, IndexError):
            return "/"
        if ":" in local:
            local = f"[{local}]"
        return f"http://{local}:{gateway.PORT}/"

    def _host_allowed(self) -> bool:
        """Whether the Host header names this portal (DNS rebinding guard).

        Accepted: an IP literal (a rebinding page always uses a host name),
        the PORTAL_URL host, HV_PORTAL_HOSTS, and through Caddy the root
        domains and the portal's own address. A request without Host is not
        from a browser and is accepted.
        """
        host = (self.headers.get("Host") or "").strip().lower()
        if not host:
            return True
        name = host
        if name.startswith("["):
            name = name[1:].partition("]")[0]
        elif name.count(":") == 1:
            name = name.partition(":")[0]
        try:
            ipaddress.ip_address(name)
            return True
        except ValueError:
            pass
        if host in gateway.PORTAL_HOSTS or name in gateway.PORTAL_HOSTS:
            return True
        if gateway.PORTAL_URL and \
                host == urllib.parse.urlsplit(gateway.PORTAL_URL).netloc.lower():
            return True
        if self._from_caddy():
            settings = self.gw.settings.snapshot()
            if name in settings.get("proxy_domains", []) \
                    or name == settings.get("portal_domain", ""):
                return True
        return False

    def _reject_unknown_host(self, path: str) -> bool:
        """421 for an /api/ request under a foreign Host; True if it was sent."""
        if not path.startswith("/api/") or path == _TUNNEL_SYNC_PATH \
                or path.startswith(_HOST_CHECK_EXEMPT_PREFIXES):
            return False
        if self._host_allowed():
            return False
        self._audit(
            "host_rejected",
            host=(self.headers.get("Host") or "")[:200],
            path=path[:200],
        )
        self._discard_body()
        self.close_connection = True
        self._json(421, {"ok": False, "error": "unknown host"})
        return True

    def _https_portal_url(self) -> str:
        """HTTPS target for a portal opened directly (http) from the WAN, or "".

        LAN clients, blocked IPs and proxy-blocked IPs cannot reach port 443,
        so they keep the http portal; loopback (healthcheck, Caddy) and
        requests arriving through Caddy are untouched.
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
        # Own address enabled: the direct HTTP portal also switches there.
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
        if self._tunnel_peer_refused(path):
            return
        if self._reject_unknown_host(path):
            return
        if self._https_required(path):
            return

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
        if path.startswith("/api/proxy/"):
            return self._proxy_api(path)
        if path.startswith("/api/gate/"):
            return self._gate_api(path)
        if path.startswith("/api/"):
            return self._json(404, {"ok": False, "error": "unknown endpoint"})

        # The http portal opened directly from the WAN switches to the root
        # domain's HTTPS portal (before the captive redirect, in place of its target).
        https_url = self._https_portal_url()
        if https_url:
            self._audit("portal_https_redirect", target=https_url[:300])
            return self._send(
                308, b"", "text/plain; charset=utf-8",
                headers={"Location": https_url},
            )

        # Captive portal: an HTTP request with a foreign Host is redirected to
        # the gateway's own address so the cookie and state stay in one place.
        if not self._portal_host_matches():
            target = self._portal_redirect_url()
            self._audit(
                "portal_host_redirect",
                host=(self.headers.get("Host") or "")[:200],
                target=target,
            )
            return self._send(
                302, b"", "text/plain; charset=utf-8",
                headers={"Location": target},
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
        # Any other path returns the login page (captive behavior).
        return self._static("index.html")

    do_HEAD = do_GET

    # -- Caddy subdomain proxy (loopback only) --------------------------------

    def _proxy_target(self, host: str):
        """The host's proxy target ("root", the entry, the portal or None) and its root."""
        settings = self.gw.settings.snapshot()
        portal = settings.get("portal_domain", "")
        if portal and host == portal:
            # On its own address the portal behaves like a public entry:
            # the challenge conditions apply to it the same way.
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
        # Entries take precedence: an entry with an empty name refers to the
        # root, and the root serves the portal only without its own portal address.
        for route in settings.get("proxy_routes", []):
            if route["enabled"] and host == settings_store.route_host(route):
                return route, route["root"]
        # Domain-mode tunnel service: Caddy asks on the same forward_auth
        # path, and the target is the agent's internal tunnel port.
        tunnel = _tunnel_domain_target(settings, host)
        if tunnel is not None:
            return tunnel
        if host and host in settings.get("proxy_domains", []) and not portal:
            return "root", host
        return None, ""

    def _proxy_unknown_root(self, host: str) -> str:
        """Root of the unregistered (or disabled) subdomain, if the root's
        uploaded, valid certificate covers the name without ACME; or "".

        Only meaningful after _proxy_target returns None.
        """
        for root in self.gw.settings.snapshot().get("proxy_domains", []):
            if host.endswith("." + root) \
                    and self.gw.certs.bundle(host, root) is not None:
                return root
        return ""

    def _proxy_redirect(self) -> None:
        """Response for port 80 (Caddy http:// forward_auth): always 3xx.

        An own name (root, enabled entry, unknown subdomain covered by an
        uploaded certificate) switches to HTTPS with the original URI (308);
        other names have no certificate, so they go to the portal of the
        (containing, otherwise first) root (302: temporary, so it does not
        mask an entry added later). Without roots the old behavior remains.
        Runs per request: no audit.
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
            # With an own portal address the root no longer belongs to the
            # portal: without an entry there is no certificate, so we do not
            # redirect to it.
            return self._send(404, b"", "text/plain; charset=utf-8")
        if host and (
            self._proxy_target(host)[0] is not None
            or self._proxy_unknown_root(host) or not roots
        ):
            code, location = 308, f"https://{host}{uri}"
        elif roots:
            # Unknown name: the portal (or, lacking it, the containing root).
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
        # Caddy calls this for every proxied request: only the entry's page
        # load gets an audit, the 401 a drop row; fail2ban counts only the
        # private entry's 401 responses. A foreign peer must learn nothing.
        if not self._from_caddy(
            query_key=path in ("/api/proxy/cert", "/api/proxy/ask")
        ):
            return self._send(404, b"", "text/plain; charset=utf-8")
        if path in ("/api/proxy/unauthorized.png", "/api/proxy/sus.png"):
            return self._static(path.rpartition("/")[2])
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if path == "/api/proxy/ask":
            # On-demand TLS: a certificate may be requested only for configured
            # names, and only with automatic certificates enabled.
            domain = (query.get("domain") or [""])[0].strip().lower()
            target, _ = self._proxy_target(domain)
            acme = self.gw.settings.snapshot().get("proxy_acme", True)
            code = 200 if acme and target is not None else 404
            return self._send(code, b"", "text/plain; charset=utf-8")
        if path == "/api/proxy/cert":
            # Caddy's get_certificate http request (returns a private key): a
            # request arriving through Caddy (proxied) must get nothing. Caddy
            # reverse_proxy/forward_auth always sends X-Forwarded-For, the
            # certificate request never does.
            if self._via_proxy() or any(
                self.headers.get(name) is not None
                for name in (
                    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Uri"
                )
            ):
                return self._send(404, b"", "text/plain; charset=utf-8")
            name = (query.get("server_name") or [""])[0].strip().lower()
            # Coverage decides, not the entry: an unknown name covered by the
            # uploaded wildcard also gets it (for the challenge).
            target, root = self._proxy_target(name)
            if target is None:
                root = self._proxy_unknown_root(name)
            bundle = self.gw.certs.bundle(name, root) if root else None
            if bundle is None:
                # 204: Caddy continues on its own (on-demand ACME) path.
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
        # Caddy sets X-Forwarded-For to the real client IP (it does not trust
        # the incoming value); the last element is the direct client.
        forwarded = (self.headers.get("X-Forwarded-For") or "").split(",")[-1]
        try:
            ip = gateway.normalize_ip(forwarded)
        except ValueError:
            ip = ""
        # Without the query, truncated (the query may carry a token too).
        page_path = urllib.parse.urlsplit(
            self.headers.get("X-Forwarded-Uri") or "/"
        ).path[:200]
        target, root = self._proxy_target(host)
        if target is None:
            if not self._proxy_unknown_root(host):
                return self._send(404, b"", "text/plain; charset=utf-8")
            # Unknown subdomain covered by an uploaded certificate: always a
            # challenge regardless of conditions and session (a successful
            # solution redirects to the root, without a pass).
            if (
                not ip
                or self.gw.fail2ban.banned(ip) is not None
                or self.gw.fail2ban.proxy_banned(ip) is not None
            ):
                return self._send(403, b"", "text/plain; charset=utf-8")
            if not self._proxy_navigation():
                return self._json(403, {
                    "ok": False, "error": "verification required",
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
        # The portal's own address gets the same loopback protection: Caddy
        # forwards to the portal, so the /api/proxy/ endpoints would otherwise
        # be reachable (the peer is loopback there too).
        if isinstance(target, dict) and target.get("portal"):
            uri = self.headers.get("X-Forwarded-Uri") or "/"
            if urllib.parse.urlsplit(uri).path.startswith("/api/proxy/"):
                return self._send(404, b"", "text/plain; charset=utf-8")
        if target == "root":
            # The root domain is the portal itself. Through Caddy the proxy
            # endpoints are unreachable (the peer would be loopback there too).
            uri = self.headers.get("X-Forwarded-Uri") or "/"
            if urllib.parse.urlsplit(uri).path.startswith("/api/proxy/"):
                return self._send(404, b"", "text/plain; charset=utf-8")
            if portal:
                # The UI moved to its own address; the root redirects there.
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
        # Public entry: anyone not blocked by fail2ban. A proxy-blocked IP is
        # dropped by the firewall on 80/443; here it is also unauthorized
        # (defense in depth), and its further requests are not counted.
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
            # forward_auth allows through only on 2xx, and then we always
            # provide the target: a client-sent header cannot direct it.
            upstream = (
                target["ip"] if target["type"] == "forward" else "127.0.0.1"
            )
            # The challenge returns 403 (not 401): neither fail2ban nor the
            # drop log counts it.
            fired = self._proxy_challenge_triggers(target, host, ip)
            if fired:
                if not self._proxy_navigation():
                    return self._json(403, {
                        "ok": False, "error": "verification required",
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
        # Only a private entry can get here with a countable IP: a public 401
        # always belongs to an empty or already blocked IP, which does not count.
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
        """Challenge conditions of the entry that now apply (empty: none).

        always/interval/daily/new_ip require a valid pass (they narrow
        validity). after_401/fail2ban require one only while the counter is
        active, and a pass issued after the latest hit; burst likewise one
        issued after the latest spam detection (many page loads); suspicious
        accepts any valid pass for a suspicious request.
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
        """Whether the request forwarded by forward_auth is not browser-like."""
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
        """Proxy challenge endpoint (Caddy's /__dropjak/challenge path).

        GET: PoW puzzle or Turnstile mode (like /api/challenge); POST:
        verify the solution and set the pass cookie. Only through Caddy
        (loopback peer), on the host of a challenge entry or an unknown
        subdomain covered by a certificate (for the latter, redirect to the
        root instead of a pass); everything else is 404.
        """
        host = (self.headers.get("Host") or "").strip().lower().partition(":")[0]
        target, unknown_root = None, ""
        if self._from_caddy() and path == "/api/gate/challenge":
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
            return self._json(403, {"ok": False, "error": "blocked IP address"})
        if self.command != "POST":
            return self._challenge()
        data = self._read_json(limit=4096)
        if data is None:
            return self._json(400, {"ok": False, "error": "bad request"})
        if not self._origin_ok():
            return self._json(403, {"ok": False, "error": "invalid request origin"})
        if not self.gw.login_rate.allow(ip):
            return self._json(
                429,
                {"ok": False, "error": "Too many attempts. Wait a minute."},
                headers={"Retry-After": str(gateway.RATE_WINDOW)},
            )
        extra = {"unknown_host": True} if unknown_root else {
            "triggers": ",".join(self._proxy_challenge_triggers(target, host, ip))
        }
        captcha = data.get("captcha")
        if not isinstance(captcha, dict):
            ok, why = False, "incomplete data"
        elif gateway.TURNSTILE_ON:
            ok, why = gateway.verify_turnstile(str(captcha.get("token", "")), ip)
        else:
            ok, why = gateway.verify_pow(captcha)
        if not ok:
            self._audit(
                "proxy_challenge_failed", ip=ip, host=host,
                reason=f"captcha: {why}", **extra,
            )
            # A failed challenge goes into the proxy signal counter.
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
        """Whether the original request forwarded by forward_auth is a page load.

        The Sec-Fetch-* header decides; without it, GET + text/html Accept.
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
        """Service index of the current settings by reference."""
        try:
            tunnels = self.gw.settings.snapshot().get("tunnels")
        except Exception:
            return {}
        if not isinstance(tunnels, dict):
            return {}
        return settings_store.tunnel_service_index(tunnels)

    def _services_payload(self, refs) -> list[dict]:
        """Resolved display form of the selected services."""
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
                # Domain-mode service: it has no port; its domain opens
                # through the proxy gateway.
                "domain": item.get("domain") or None,
            })
        return out

    @staticmethod
    def _services_label(services: list[dict]) -> str:
        parts: list[str] = []
        for service in services:
            pieces: list[str] = []
            if service.get("domain"):
                # Domain-mode service: the hostname instead of the port.
                pieces.append(str(service["domain"]))
            if service.get("tcp"):
                pieces.append(
                    "TCP " + ", ".join(str(port) for port in service["tcp"])
                )
            if service.get("udp"):
                pieces.append(
                    "UDP " + ", ".join(str(port) for port in service["udp"])
                )
            detail = " · ".join(pieces) if pieces else "no available port"
            parts.append(f"{service.get('label') or service.get('ref')} ({detail})")
        return "Service: " + ", ".join(parts)

    def _with_hosts(self, payload: dict) -> dict:
        """Display fields for domain and service selection.

        For a domain rule, ``ports_label`` shows the hostnames (together with
        the port part, separated by ``·``), and ``hosts`` contains the full
        names. For a service rule, ``services`` contains the labels and ports
        resolved from settings, and ``ports_label`` shows these instead of the
        raw ports.
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
        """Shared fields for the rule selection of an authorized session.

        ``selected_rules``/``selected_rule_labels``/``grants`` describe the
        full multi-rule selection. The ``rule``/``rule_label``/``grant``
        fields mirror the first selection for old clients.
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
        """The fail2ban block of the client's IP address, if any.

        From this, the login page can put the blocked-IP warning screen in
        place of the normal UI.
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
        # The firewall's name is public: the login page header and the browser
        # title show it. The settings file's error text is not exposed.
        site_name = settings.get("site_name", "")
        # Defense in depth: a blocked IP cannot query the protected state even
        # with its existing session. The response is the block form shared with
        # the login and access endpoints, without session data.
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
            # The reason for the latest termination is also provided so the UI
            # can say why the user dropped out during the countdown.
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
        # Only a still-valid announcement leaves the server; an expired or
        # disabled MOTD does not enter the response.
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
        """Read-only preview of a user's portal access view.

        Deliberately creates no session and opens no nft grant: it returns the
        same rules, limits and status fields that ``/api/status`` would return
        for the user. Opening the preview always writes an audit entry.
        """
        if not self._origin_ok():
            self._admin_request_rejected("invalid_origin")
            return self._json(
                403, {"ok": False, "error": "invalid request origin"}
            )
        session = self._admin_guard()
        if session is None:
            return
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        name = (query.get("user") or [""])[0].strip()[:128]
        record = self.gw.users.record(name) if name else None
        if record is None:
            self._admin_action_error(
                "user_preview", gateway.UserStoreError("unknown user"),
                target=name,
            )
            return self._json(
                404, {"ok": False, "error": "unknown user"}
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
                    "error": f"cannot read firewall status: {exc}",
                },
            )
            return
        payload = gateway.group_firewall_snapshot(
            snapshot, self.gw.sessions.active_sessions()
        )
        payload["ok"] = True
        self._json(200, payload)

    def _admin_firewall_rules(self) -> None:
        """Raw text dump of the nftables chains live in the kernel."""
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
                    "error": f"cannot read raw rules: {exc}",
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
            self._json(403, {"ok": False, "error": "invalid request origin"})
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
            self._json(400, {"ok": False, "error": "unknown operation"})
            return
        sid = data.get("id")
        if not isinstance(sid, str) or not sid.strip():
            self._audit(
                "admin_session_terminate_failed",
                user=session.user,
                target="",
                reason="missing_id",
            )
            self._json(400, {"ok": False, "error": "missing session ID"})
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
                    "error": "you can end your own session with the Logout button",
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
                {"ok": False, "error": "no such session (already expired)"},
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
        payload["message"] = f"Session of {terminated.user} terminated."
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
        # Multi-event filter: ``events=a,b`` (repeatable) or repeated
        # ``event=``. A single ``event=`` keeps the old partial match.
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
                "ok": False, "error": "invalid event code in filter",
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
                    "error": "invalid IP address or CIDR (e.g. 192.168.10.0/24)",
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
            # Only a user-initiated query enters the log; the five-second
            # automatic refresh does not.
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
                        "error": "the port must be between 1 and 65535",
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
        """Public endpoint of the downloaded configuration (Host, then PORTAL_URL)."""
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
        """Settings and agent for downloads (missing: None)."""
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
        """The agent's configuration (with WireGuard keys) and its services."""
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
        """Read-only status refresh for the agent list.

        It does not write the settings file and does not touch nftables: it
        returns the same secret-free view as the admin state, with a fresh
        ``checked_at`` timestamp. The UI uses this to re-request handshake and
        sync data without reloading the full admin state.
        """
        if self._admin_guard() is None:
            return
        snapshot = self.gw.settings.snapshot()
        if snapshot.get("error"):
            self._json(
                503,
                {
                    "ok": False,
                    "error": f"the settings file is invalid: {snapshot['error']}",
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
        """Downloadable configuration of an agent (with keys, admin only)."""
        session = self._admin_guard()
        if session is None:
            return
        if not self._origin_ok():
            self._audit(
                "tunnel_config_failed", user=session.user,
                reason="invalid_origin",
            )
            return self._json(
                403, {"ok": False, "error": "invalid request origin"}
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
                404, {"ok": False, "error": "no such agent"}
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
        """Downloadable agent installer: a single self-extracting shell script.

        The script starts with selfinstall.sh, followed by the tar.gz bundle
        (compose, agent.json, source). This way only one file must be moved to
        the other machine.
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
                403, {"ok": False, "error": "invalid request origin"}
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
                404, {"ok": False, "error": "no such agent"}
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
                500, {"ok": False, "error": "the agent bundle is not available"}
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
        bundle = header + payload.getvalue()
        # The installer prints its own SHA-256; the admin compares it with
        # this value (shown by the UI, kept in the audit log) before running.
        digest = hashlib.sha256(bundle).hexdigest()
        self._audit(
            "tunnel_agent_config_downloaded",
            user=session.user, target=agent["id"], services=count,
            bundle=True, sha256=digest,
        )
        self._send(
            200, bundle, "application/x-sh",
            headers={
                "Content-Disposition": (
                    "attachment; filename="
                    f'"dropjak-agent-{agent["id"]}.sh"'
                ),
                "X-Dropjak-SHA256": digest,
            },
        )

    def _tunnel_config_sync(self) -> None:
        """Agent configuration sync: source IP + Bearer token.

        Not an admin endpoint: callable only from the WireGuard tunnel's
        source IP (the raw socket peer, not X-Forwarded-For) and in possession
        of the token. Every other request gets a detail-free 403.
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
        # Only the root, SANs, expiry and fingerprint enter the log.
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

    # -- configuration bundle --------------------------------------------------

    def _admin_config_export(self) -> None:
        # POST, because the request carries the admin's password (step-up):
        # the bundle holds every secret of the installation.
        session = self._admin_guard()
        if session is None:
            return
        if not self._origin_ok():
            self._audit(
                "config_export_failed", user=session.user,
                reason="invalid_origin",
            )
            return self._json(
                403, {"ok": False, "error": "invalid request origin"}
            )
        data = self._read_json(4096)
        if not self._step_up(session, data, "config_export"):
            return
        try:
            bundle = _config_bundle(self.gw)
        except ConfigBundleError as exc:
            # The detailed error may go into the response, but not the log.
            self._audit(
                "config_export_failed", user=session.user,
                reason="export_failed",
            )
            gateway.log(f"[configuration] export failed: {exc}")
            return self._json(
                500,
                {"ok": False, "error": f"export failed: {exc}"},
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
                403, {"ok": False, "error": "invalid request origin"}
            )
        data = self._read_json(CONFIG_MAX_BYTES)
        if data is None or not isinstance(data.get("bundle"), dict):
            self._audit(
                "config_import_failed", user=session.user, reason="bad_request"
            )
            return self._json(
                400, {"ok": False, "error": "missing or invalid configuration bundle"}
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
                        "type the current site name to overwrite"
                    ),
                    "confirm_required": True,
                    "site_name": _effective_site_name(self.gw),
                },
            )
        if not self._step_up(session, data, "config_import"):
            return
        try:
            checked = _validate_config_bundle(self.gw, data["bundle"])
        except ConfigBundleError as exc:
            self._audit(
                "config_import_failed", user=session.user,
                reason="invalid_bundle",
            )
            return self._json(
                400,
                {"ok": False, "error": f"the bundle is invalid: {str(exc)[:300]}"},
            )

        # admin_lock serializes with individual admin operations: no other
        # write may slip between the backup and the apply during the full swap.
        with self.gw.admin_lock:
            # Backup before the first write; if it fails, nothing changes.
            try:
                backup_path = _config_backup_path(self.gw)
                _write_private_json(
                    backup_path, _config_bundle(self.gw, include_markers=True)
                )
            except (OSError, ConfigBundleError) as exc:
                self._audit(
                    "config_import_failed", user=session.user,
                    reason="backup_failed",
                )
                gateway.log(f"[configuration] backup before import failed: {exc}")
                return self._json(
                    500,
                    {
                        "ok": False,
                        "error": (
                            "the backup before import failed; "
                            "nothing changed"
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
                gateway.log(f"[configuration] import error: {exc}")
                if rollback_error:
                    gateway.log(f"[configuration] rollback also failed: {rollback_error}")
                    return self._json(
                        500,
                        {
                            "ok": False,
                            "error": (
                                "the import was interrupted and restoring the "
                                "backup also failed; the service will not "
                                f"restart. Backup: {os.path.basename(backup_path)}"
                            ),
                        },
                    )
                return self._json(
                    500,
                    {
                        "ok": False,
                        "error": (
                            "import failed; the previous state was "
                            "restored, nothing changed"
                        ),
                    },
                )

        counts = _config_counts(checked)
        try:
            revoked = self.gw.sessions.shutdown(reason="config_import")
        except Exception as exc:
            revoked = 0
            gateway.log(f"[configuration] failed to revoke sessions: {exc}")
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
                "message": "configuration loaded; the service is restarting",
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
                403, {"ok": False, "error": "invalid request origin"}
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
                    "error": "type the site name to reset",
                    "confirm_required": True,
                    "site_name": expected,
                },
            )
        if not self._step_up(session, data, "config_reset"):
            return

        with self.gw.admin_lock:
            # Runtime state first; if this fails, nothing is deleted.
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
                gateway.log(f"[configuration] firewall flush before reset failed: {exc}")
                return self._json(
                    503,
                    {
                        "ok": False,
                        "error": (
                            "failed to clear the firewall state; "
                            "the reset did not happen"
                        ),
                    },
                )

            # Files disappear through each store's own 0600 write path;
            # .env, logs and service files remain untouched.
            errors = 0
            for label, reset in (
                ("users", self.gw.users.reset),
                ("rules", self.gw.rules.reset),
                ("groups", self.gw.groups.reset),
                ("settings", self.gw.settings.reset),
                ("fail2ban", self.gw.fail2ban.reset),
                ("certs", self.gw.certs.reset),
                # WireGuard peers would remain in the kernel even after
                # settings.reset; delete them explicitly on reset.
                ("tunnels", self.gw.tunnels.remove_all),
            ):
                try:
                    reset()
                except Exception as exc:
                    errors += 1
                    gateway.log(f"[configuration] failed to delete {label}: {exc}")
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
                        gateway.log(f"[configuration] failed to delete {name}: {exc}")
        try:
            self.gw.sync_host_ports()
        except Exception as exc:
            gateway.log(f"[configuration] failed to sync host ports: {exc}")
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
                        "the reset partially failed; the service is "
                        "restarting, the result is visible in the log"
                    ),
                },
            )
        return self._json(
            200,
            {
                "ok": True,
                "message": "all configuration deleted; the service is restarting",
                "restarting": True,
            },
        )

    def _admin_certs_action(self) -> None:
        """Upload/replace (upload) and delete a root domain certificate."""
        session = self._admin_guard()
        if session is None:
            return
        if not self._origin_ok():
            self._admin_request_rejected("invalid_origin", user=session.user)
            self._json(403, {"ok": False, "error": "invalid request origin"})
            return
        # Two PEMs, each at most 64 KiB, JSON-encoded.
        data = self._read_json(4 * settings_store.MAX_CERT_PEM)
        if data is None:
            self._admin_request_rejected("bad_request", user=session.user)
            return self._json(400, {"ok": False, "error": "bad request"})
        action = str(data.get("action", "")).strip().lower()
        root = data.get("root")
        try:
            with self.gw.admin_lock:
                if root not in self.gw.settings.snapshot().get(
                    "proxy_domains", []
                ):
                    raise settings_store.SettingsError(
                        "unknown root domain"
                    )
                if action == "upload":
                    meta = self.gw.certs.install(
                        root, data.get("cert"), data.get("key")
                    )
                    # An ACME certificate in the cache would take precedence
                    # over the uploaded one; without ACME there is none.
                    if self.gw.settings.snapshot().get("proxy_acme", True):
                        self._caddy_restart()
                    message = "Certificate saved."
                elif action == "delete":
                    meta = self.gw.certs.delete(root)
                    if meta is None:
                        raise settings_store.SettingsError(
                            "there is no uploaded certificate "
                            "for this root domain"
                        )
                    message = "Certificate deleted."
                else:
                    raise settings_store.SettingsError(
                        f"unknown operation: {action!r}"
                    )
                self._audit_cert(f"proxy_cert_{action}", session, root, meta)
        except (settings_store.SettingsError, ValueError, OSError) as exc:
            self._admin_request_rejected("invalid_proxy_cert", user=session.user)
            # The OSError text may contain a path; do not expose it.
            if isinstance(exc, ValueError):
                return self._json(400, {"ok": False, "error": str(exc)})
            return self._json(
                500, {"ok": False, "error": "failed to save the certificate"}
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
            self._json(403, {"ok": False, "error": "invalid request origin"})
            return
        data = self._read_json()
        if data is None:
            self._admin_request_rejected("bad_request", user=session.user)
            return self._json(400, {"ok": False, "error": "bad request"})
        action = str(data.get("action", "")).strip().lower()
        if action == "registration_enabled":
            # Portal setting: it does not go through nftables preparation and
            # application, so it is handled in a separate branch.
            value = data.get("enabled", data.get("registration_enabled"))
            if not isinstance(value, bool):
                self._admin_request_rejected(
                    "invalid_registration_flag", user=session.user
                )
                self._json(
                    400,
                    {
                        "ok": False,
                        "error": "the registration_enabled field must be "
                                 "a true/false value",
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
            payload["message"] = "The account request setting was saved."
            self._json(200, payload)
            return
        if action == "site_name":
            # The firewall's name is display data only: it does not go through
            # nftables preparation and application.
            value = data.get("name", data.get("site_name"))
            if not isinstance(value, str):
                self._admin_request_rejected(
                    "invalid_site_name", user=session.user
                )
                self._json(
                    400,
                    {
                        "ok": False,
                        "error": "the firewall name must be text",
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
            payload["message"] = "The firewall name was saved."
            self._json(200, payload)
            return
        if action == "motd":
            # The announcement is display data only: it does not go through
            # nftables preparation and application.
            try:
                with self.gw.admin_lock:
                    stored = self.gw.settings.set_motd(
                        data.get("text", ""), data.get("expires_at", "")
                    )
                    # The text does not enter the log, only its length and expiry.
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
            payload["message"] = "The announcement was saved."
            self._json(200, payload)
            return
        if action == "proxy_acme":
            # Changes the response of /api/proxy/ask; when disabled, Caddy
            # restarts so it does not serve already issued certificates either.
            value = data.get("enabled")
            if not isinstance(value, bool):
                self._admin_request_rejected(
                    "invalid_proxy_acme", user=session.user
                )
                self._json(
                    400,
                    {
                        "ok": False,
                        "error": "the proxy_acme field must be a true/false value",
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
            payload["message"] = "The automatic certificate setting was saved."
            self._json(200, payload)
            return
        if action == "portal_domain":
            # Caddy queries the portal per request, so there is no reload;
            # the address must be under a root domain (because of the certificate).
            value = data.get("domain", "")
            if not isinstance(value, str):
                self._admin_request_rejected(
                    "invalid_portal_domain", user=session.user
                )
                self._json(
                    400,
                    {"ok": False, "error": "portal_domain: text required"},
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
            payload["message"] = "The Dropjak address was saved."
            self._json(200, payload)
            return
        if action == "proxy":
            # Caddy queries the portal per request, so there is no reload and
            # no nftables change here either.
            try:
                with self.gw.admin_lock:
                    # Domain rule references are read under the same lock
                    # as rule saving (see _admin_rules).
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
                    # The certificate of a deleted root domain is also deleted.
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
            payload["message"] = "Proxy settings saved."
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
                400, {"ok": False, "error": "invalid entry ID"}
            )
            return
        # Preparing the change and applying it to nftables run under one lock
        # so two parallel admin requests cannot overwrite each other's
        # settings (TOCTOU).
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
                        "error": "failed to apply the firewall settings: "
                                 f"{exc}",
                    },
                )
                return
            target = entry_id.strip()
            self._audit(
                "admin_settings_changed",
                user=session.user,
                action=action or "unknown",
                kind=kind,
                target=target,
                preauth_count=len(new_data.get("preauth", [])),
                block_count=len(new_data.get("block", [])),
            )
        payload = self._admin_state()
        payload["message"] = "Firewall settings saved."
        self._json(200, payload)

    def _admin_port_proxies(self, session, data: dict) -> None:
        """Replace the port proxy list: nft apply -> save -> conntrack.

        apply_settings replaces the port proxy chains in one transaction with
        the other customized chains, and rolls back on a save error.
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
                        "error": "failed to apply the firewall settings: "
                                 f"{exc}",
                    },
                )
                return
            entries = new_data["port_proxies"]
            # Old NAT-bound flows in conntrack would go to the old target until
            # they end: delete the entries of changed listening ports.
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
        payload["message"] = "Port proxy settings saved."
        self._json(200, payload)

    def _tunnel_reference_error(self, refs) -> str:
        """Error message if a rule is built on the given service references.

        It lists the referencing rules by ID and label so the admin knows what
        must be changed first. Empty text if there is no reference (the
        operation can proceed).
        """
        try:
            references = self.gw.rules.service_references()
        except Exception as exc:
            raise settings_store.SettingsError(
                "tunnel: failed to check rule references: "
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
            "tunnel: the service cannot be deleted because "
            "a rule references it; first change or delete the "
            "referencing rules: " + "; ".join(rows)
        )

    def _tunnel_domain_reference_error(self, domains) -> str:
        """Error message if a domain rule references the given names.

        It follows the behavior usual for proxy entries: a referenced domain
        must not disappear silently, because the rule would become invalid at
        the check made at decision time.
        """
        try:
            referenced = self.gw.rules.domain_references()
        except Exception as exc:
            raise settings_store.SettingsError(
                "tunnel: failed to check domain references: "
                f"{exc}"
            ) from exc
        missing = sorted({
            domain for domain in domains if domain and domain in referenced
        })
        if not missing:
            return ""
        return (
            "tunnel: a domain rule references it, so it cannot be deleted and "
            "its domain cannot be changed: " + ", ".join(missing)
            + "; first remove it from the rule"
        )

    @staticmethod
    def _tunnel_effective_ports(service) -> object:
        """Full effective mapping of the service; ``None`` on error.

        Besides the listening port it also contains the protocol, target host
        and target port, so redirecting the target counts as a change even if
        the listening ports are unchanged. For a domain-mode service the domain
        name appears as a separate ``("domain", 0, name, 0)`` row: when editing
        the domain, the UI leaves the internal listening port unchanged, so
        renaming/deleting the domain counts as a change only this way, and only
        this way does refreshing the referencing rules and revoking sessions
        start.
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
        """Manage WireGuard agents and their services.

        The section goes through prepare_tunnels -> apply_settings, so nftables
        (jump + synthetic forward rules) and the WireGuard peer sync are
        updated in the same operation. Only IDs, ports and counts enter the
        log: key and token never.
        """
        target = str(data.get("id") or data.get("agent_id") or "")[:64]
        extra: dict = {}
        message = ""
        # Disabling is always allowed (fail-closed): access from referencing
        # rules ceases, so affected sessions are torn down after the operation.
        # Deletion is still forbidden while a rule references the
        # agent/service.
        agent_disabled = False
        agent_toggled = False
        agent_service_refs: list[str] = []
        if action == "tunnel_service_test":
            # The reachability test is read-only: it does not go through
            # settings preparation and nftables application, and writes no state.
            self._admin_tunnel_service_test(session, data)
            return
        try:
            with self.gw.admin_lock:
                snapshot = self.gw.settings.snapshot()
                if snapshot.get("error"):
                    raise settings_store.SettingsError(
                        f"the settings file is invalid: {snapshot['error']}"
                    )
                tunnels = snapshot.get("tunnels")
                if not isinstance(tunnels, dict):
                    tunnels = settings_store.default_tunnels()
                if action == "tunnel_settings":
                    if "port" in data:
                        tunnels["port"] = data.get("port")
                    if "endpoint" in data:
                        tunnels["endpoint"] = data.get("endpoint")
                    message = "Tunnel settings saved."
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
                            "tunnel: no free agent address"
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
                        "Agent created; download its configuration."
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
                        "Agent disabled."
                        if agent_disabled else "Agent saved."
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
                            "tunnel: no such agent"
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
                    message = "Agent deleted."
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
                                "tunnel: no such service"
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
                        # Removing the domain also deletes the challenge:
                        # without a domain there is no host for it to apply to.
                        if "domain" in data and not service.get("domain"):
                            service.pop("challenge", None)
                        ref = f"{agent['id']}/{service_id}"
                        # Disabling is always allowed (fail-closed); access from
                        # referencing rules ceases. Changing/deleting the domain
                        # remains protected because the domain rule would become
                        # invalid at the check made at decision time.
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
                    message = "Service saved."
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
                            "tunnel: no such service"
                        )
                    target = ref
                    message = "Service deleted."
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
                    # Resolved ports of rules built on the modified mapping are
                    # refreshed; sessions of changed rules are torn down
                    # immediately. On disable, access from referencing rules
                    # ceases in any case, so sessions of referencing rules must
                    # also be torn down (fail-closed).
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
                                "Service disabled; access from the referencing "
                                "rules ceased."
                                if rule_ids else "Service disabled."
                            )
                if action == "tunnel_agent_update" and agent_toggled:
                    # Disabling the agent makes all its services unreachable.
                    # After recalculating the resolved ports, sessions of
                    # referencing rules (also through collections) must be torn
                    # down immediately.
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
                                "Agent disabled; access from the referencing "
                                "rules ceased."
                            )
                        else:
                            message = "Agent disabled."
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
                    "error": f"failed to generate WireGuard keys: {exc}",
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
                    "error": "failed to apply the firewall settings: "
                             f"{exc}",
                },
            )
            return
        payload = self._admin_state()
        payload.update(extra)
        payload["message"] = message
        self._json(200, payload)

    def _tunnel_test_address(self, agent: dict) -> str:
        """The test target address; overridable in tests (e.g. 127.0.0.1)."""
        return str(agent.get("address") or "")

    @staticmethod
    def _tunnel_probe_tcp(address: str, port: int) -> dict:
        """One TCP connection along the full path (portal -> WireGuard -> DNAT).

        Connection establishment is enough for success: the port is reachable.
        The open socket is closed immediately because the test sends no
        protocol data.
        """
        try:
            connection = socket.create_connection(
                (address, port), timeout=_TUNNEL_TEST_TCP_TIMEOUT
            )
            connection.close()
            return {"ok": True, "detail": "connection established"}
        except socket.timeout:
            return {"ok": False, "detail": "timeout"}
        except ConnectionRefusedError:
            return {"ok": False, "detail": "refused"}
        except OSError as exc:
            return {"ok": False, "detail": f"network error: {exc}"}

    @staticmethod
    def _tunnel_probe_udp(address: str, port: int) -> dict:
        """Send a single zero byte over UDP, with a short wait for a reply.

        On UDP, absence of a reply is not an error: the target is not required
        to write back. ``ConnectionRefusedError``, however, means ICMP
        port-unreachable, that is, the target is not listening on the port; we
        report this as an error.
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
                    "detail": "sent, no UDP reply expected",
                }
            return {"ok": True, "detail": "reply received"}
        except ConnectionRefusedError:
            return {"ok": False, "detail": "refused (ICMP)"}
        except socket.timeout:
            # Waiting during send/connect cannot be considered a refusal either.
            return {
                "ok": True,
                "detail": "sent, no UDP reply expected",
            }
        except OSError as exc:
            return {"ok": False, "detail": f"network error: {exc}"}
        finally:
            try:
                probe.close()
            except OSError:
                pass

    def _admin_tunnel_service_test(self, session, data: dict) -> None:
        """Probe the full access path of a service (read-only).

        The portal uses host networking, so we connect to the agent's WireGuard
        address (``10.77.0.2:<tunnel_port>``): the path runs from the portal
        host through the WireGuard tunnel to the agent's DNAT. We do not use
        the public WAN address or loopback, because those do not follow the
        same path. State does not change, key/token do not enter the log.
        """
        agent_id = str(data.get("agent_id") or "")[:64]
        service_id = str(data.get("service_id") or "")[:64]
        if not agent_id or not service_id:
            self._json(400, {
                "ok": False,
                "error": "tunnel: agent and service ID required",
            })
            return
        try:
            snapshot = self.gw.settings.snapshot()
            if snapshot.get("error"):
                raise settings_store.SettingsError(
                    f"the settings file is invalid: {snapshot['error']}"
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
                    "error": "tunnel: no such agent",
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
                    "error": "tunnel: no such service",
                })
                return
            if not agent.get("enabled", True):
                self._json(409, {
                    "ok": False, "field": "agent_id",
                    "error": "tunnel: the agent is disabled",
                })
                return
            if not service.get("enabled", True):
                self._json(409, {
                    "ok": False, "field": "service_id",
                    "error": "tunnel: the service is disabled",
                })
                return
            # Expanded mappings also resolve ranges, and combine the tcp+udp
            # pair into ``both`` the same way as the agent sync does.
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
                "error": "tunnel: no testable port mapping",
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
        # TCP is authoritative; if there is no TCP probe (pure UDP), then UDP.
        tcp_results = [row for row in results if row["proto"] == "tcp"]
        authoritative = tcp_results or [
            row for row in results if row["proto"] == "udp"
        ]
        reachable = (
            finished and bool(authoritative)
            and all(row["ok"] for row in authoritative)
        )
        summary = "service reachable"
        if not reachable:
            failures = [row for row in authoritative if not row["ok"]]
            if failures:
                first = failures[0]
                summary = (
                    "service unreachable: "
                    f"{first['proto'].upper()} {first['listen']} "
                    f"({first['detail']})"
                )
            else:
                summary = "service unreachable: the test did not finish"
        if len(mappings) > len(limited):
            summary += (
                f"; only the first {len(limited)} mappings were tested"
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
            raise settings_store.SettingsError("tunnel: no such agent")
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
            self._json(403, {"ok": False, "error": "invalid request origin"})
            return
        data = self._read_json()
        if data is None:
            self._admin_request_rejected("bad_request", user=session.user)
            return self._json(400, {"ok": False, "error": "bad request"})
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
                            "proxy_window_seconds", "drop_exempt",
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
                            "proxy_window_seconds", "drop_exempt",
                        )
                    }
                    audit_extra["released"] = max(
                        0, before_bans - config_snapshot["banned_count"]
                    )
                    message = "Fail2ban settings saved."
                elif action in ("ban", "unban"):
                    ip = data.get("ip")
                    if not isinstance(ip, str) or not ip.strip():
                        raise fail2ban_mod.Fail2banError("missing IP address")
                    ip = ip.strip()
                    target = ip
                    if action == "ban":
                        if ip == self._client_ip():
                            raise fail2ban_mod.Fail2banError(
                                "your own IP address cannot be blocked from the portal"
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
                        message = f"{ip} blocked."
                    else:
                        # The proxy block (TCP 80/443) can be lifted separately;
                        # the full block remains, and vice versa.
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
                                    "error": "this IP address was not blocked",
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
                        message = f"Block on {ip} lifted."
                elif action == "unban_all":
                    removed = self.gw.fail2ban.unban_all()
                    audit_extra = {"removed": removed}
                    message = f"{removed} blocks lifted."
                else:
                    self._admin_request_rejected(
                        "unknown_action", user=session.user
                    )
                    self._json(
                        400, {"ok": False, "error": "unknown operation"}
                    )
                    return
                self._audit(
                    "admin_fail2ban_changed",
                    user=session.user,
                    action=action or "unknown",
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
                    "error": f"fail2ban operation failed: {exc}",
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
        if self._tunnel_peer_refused(path):
            return
        if self._reject_unknown_host(path):
            return
        if self._https_required(path):
            return
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
        if path == "/api/admin/config/export":
            return self._admin_config_export()
        if path == "/api/admin/config/import":
            return self._admin_config_import()
        if path == "/api/admin/config/reset":
            return self._admin_config_reset()
        if path.startswith("/api/gate/"):
            return self._gate_api(path)
        self._discard_body()
        self._json(404, {"ok": False, "error": "unknown endpoint"})

    def _register(self) -> None:
        """Public account request: create a user pending approval."""
        ip = self._client_ip()
        data = self._read_json()
        if data is None:
            self._audit("registration_failed", reason="bad_request")
            return self._json(400, {"ok": False, "error": "bad request"})
        if not self._origin_ok():
            self._audit("registration_failed", reason="invalid_origin")
            return self._json(403, {"ok": False, "error": "invalid request origin"})
        if not gateway.is_ipv4(ip):
            self._audit("registration_failed", reason="non_ipv4")
            return self._json(
                400, {"ok": False, "error": "The gateway is reachable only with an IPv4 address."}
            )
        if not bool(self.gw.settings.snapshot().get("registration_enabled", False)):
            self._audit(
                "registration_failed", reason="account requests are disabled"
            )
            return self._json(
                403,
                {
                    "ok": False,
                    "error": "Account requests are not allowed.",
                    "code": "registration_disabled",
                },
            )
        if not self.gw.register_rate.allow(ip):
            self._audit("registration_failed", reason="too many attempts")
            return self._json(
                429,
                {"ok": False, "error": "Too many account requests. Try again later."},
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
            self._audit("registration_failed", reason="incomplete data")
            return self._json(400, {"ok": False, "error": "incomplete data"})
        user = user.strip()
        if len(user) > 32 or not gateway.USERNAME_RE.match(user):
            self._audit(
                "registration_failed", reason="invalid username"
            )
            return self._json(
                400,
                {
                    "ok": False,
                    "error": "the username must be 1-32 characters: letter, "
                             "digit, dot, hyphen, underscore",
                },
            )
        if not (
            gateway.UserStore.MIN_PASSWORD
            <= len(password)
            <= gateway.UserStore.MAX_PASSWORD
        ):
            self._audit(
                "registration_failed", user=user, reason="invalid password length"
            )
            return self._json(
                400,
                {
                    "ok": False,
                    "error": f"the password must be {gateway.UserStore.MIN_PASSWORD}-"
                             f"{gateway.UserStore.MAX_PASSWORD} characters",
                },
            )
        try:
            email = gateway.normalize_email(email, strict=True)
        except ValueError:
            self._audit(
                "registration_failed", user=user, reason="invalid email address"
            )
            return self._json(
                400, {"ok": False, "error": "Invalid email address."}
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
            self._audit("registration_failed", user=user, reason="name taken")
            return self._json(
                409,
                {
                    "ok": False,
                    "error": "This login name is already taken.",
                    "code": "username_taken",
                },
            )
        try:
            # The password and email address go only to the user store;
            # neither may enter a log or the audit.
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
            if "already exists" in str(exc):  # matches gateway.py's message
                self._audit(
                    "registration_failed", user=user, reason="name taken"
                )
                return self._json(
                    409,
                    {
                        "ok": False,
                        "error": "This login name is already taken.",
                        "code": "username_taken",
                    },
                )
            self._audit(
                "registration_failed",
                user=user,
                reason="failed to create the user",
            )
            # The store's message may carry internal details (paths, I/O
            # errors): only the log gets it, the anonymous caller does not.
            print(f"[{ip}] account request failed: {exc}", flush=True)
            return self._json(
                400,
                {
                    "ok": False,
                    "error": "The request could not be recorded. "
                             "Try again later.",
                },
            )
        self._audit("registration_requested", target=user)
        print(f"[{ip}] account request recorded: {user!r}", flush=True)
        self._json(
            200,
            {
                "ok": True,
                "message": "Your request has been recorded. After admin "
                           "approval you can log in.",
            },
        )

    def _login(self) -> None:
        ip = self._client_ip()
        data = self._read_json()
        if data is None:
            self._audit("login_failed", reason="bad request")
            return self._json(400, {"ok": False, "error": "bad request"})

        if not self.gw.login_rate.allow(ip):
            self._audit("login_failed", reason="too many attempts")
            return self._json(
                429,
                {"ok": False, "error": "Too many attempts. Wait a minute."},
                headers={"Retry-After": str(gateway.RATE_WINDOW)},
            )

        if not gateway.is_ipv4(ip):
            self._audit("login_failed", reason="not an IPv4 address")
            return self._json(
                400, {"ok": False, "error": "The gateway is reachable only with an IPv4 address."}
            )

        if not self._origin_ok():
            self._audit("login_failed", reason="invalid request origin")
            return self._json(403, {"ok": False, "error": "invalid request origin"})

        banned = self.gw.fail2ban.banned(ip)
        if banned is not None:
            payload, headers = self._ban_reply(banned)
            self._audit(
                "login_failed",
                reason="under fail2ban block",
                source=payload["ban_source"],
                ban_until=payload["ban_until"],
                remaining=payload["remaining"],
            )
            return self._json(403, payload, headers=headers)

        user = data.get("user")
        password = data.get("pass")
        captcha = data.get("captcha")
        if not isinstance(user, str) or not isinstance(password, str) or not isinstance(captcha, dict):
            self._audit("login_failed", reason="incomplete data")
            return self._json(400, {"ok": False, "error": "incomplete data"})
        user = user.strip()
        if not user or len(user) > 64 or len(password) > 1024:
            self._audit("login_failed", user=user[:64], reason="incomplete data")
            return self._json(400, {"ok": False, "error": "incomplete data"})

        if gateway.TURNSTILE_ON:
            ok, why = gateway.verify_turnstile(str(captcha.get("token", "")), ip)
        else:
            ok, why = gateway.verify_pow(captcha)
        if not ok:
            self._audit("login_failed", user=user, reason=f"captcha: {why}")
            return self._json(403, {"ok": False, "error": f"Captcha: {why}"})

        if self._account_locked_reply(ip, user):
            return

        if not self.gw.users.verify(user, password):
            self._audit("login_failed", user=user, reason="invalid username or password")
            print(f"[{ip}] failed login: {user!r}", flush=True)
            self._account_failure(ip, user)
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
                            "Too many failed logins: your IP address was "
                            "blocked by the firewall. Try again later."
                        ),
                        "banned": True,
                        "ban_until": ban.get("until", 0),
                        "remaining": ban.get("remaining", 0),
                    },
                )
            return self._json(
                403, {"ok": False, "error": "Invalid username or password."}
            )

        record = self.gw.users.record(user)
        if record is not None and record.pending:
            # Despite the correct password, no session or 2FA ticket is created,
            # and fail2ban is not charged either: this is not a failed login attempt.
            self._audit(
                "login_failed", user=user, reason="the account is pending approval"
            )
            return self._json(
                403,
                {
                    "ok": False,
                    "error": "The account is pending approval. After admin "
                             "approval you can log in.",
                    "code": "pending_approval",
                    "pending": True,
                },
            )
        if record is None or not record.enabled:
            self._audit("login_failed", user=user, reason="disabled user")
            self._account_failure(ip, user)
            try:
                self.gw.fail2ban.record_failure(ip, user)
            except fail2ban_mod.Fail2banError as exc:
                _log_fail2ban_error(
                    ip, exc, self.gw.audit, operation="record_failure"
                )
            return self._json(
                403, {"ok": False, "error": "Invalid username or password."}
            )

        self.gw.account_lockout.record_success(user)
        if record.totp_required:
            fingerprint = _record_fingerprint(record)
            if not record.totp_secret:
                # First 2FA login: the secret is not stored yet. It is bound to
                # the ticket so only the same IP and user state can finish
                # enrollment.
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

    def _account_lock_applies(self, ip: str) -> bool:
        # LAN clients are on site and fail2ban limits them per IP; the account
        # lock must not let a WAN attacker lock the admin out of the LAN too.
        if gateway.LAN_NETWORK is None:
            return True
        try:
            return ipaddress.ip_address(ip) not in gateway.LAN_NETWORK
        except ValueError:
            return True

    def _account_locked_reply(self, ip: str, user: str) -> bool:
        """429 while the login name is locked; True if it was sent."""
        if not self._account_lock_applies(ip):
            return False
        remaining = self.gw.account_lockout.locked(user)
        if not remaining:
            return False
        self._audit(
            "login_failed", user=user, reason="account locked",
            remaining=remaining,
        )
        self._json(
            429,
            {
                "ok": False,
                "error": "Too many failed attempts for this account. "
                         "Try again later.",
                "code": "account_locked",
                "remaining": remaining,
            },
            headers={"Retry-After": str(remaining)},
        )
        return True

    def _account_failure(self, ip: str, user: str) -> None:
        if not self._account_lock_applies(ip):
            return
        length = self.gw.account_lockout.record_failure(user)
        if length:
            self._audit("account_locked", user=user, lock_seconds=length)
            print(
                f"[{ip}] account locked for {length} s: {user!r}", flush=True
            )

    def _login_session_response(
        self,
        record: gateway.UserRecord,
        method: str | None = None,
        extra: dict | None = None,
    ) -> None:
        """Shared session response after the password or 2FA step."""
        ip = self._client_ip()
        # F7: race between the early block check and session creation. The
        # password/TOTP/registration/recovery branches all end up here; here,
        # immediately before creating the session, we check the block once more
        # from the daemon's authoritative state. Thus no session is created even
        # after a block that occurs in the meantime.
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
                "login_failed", user=record.name, reason=f"firewall error: {exc}"
            )
            print(
                f"[{ip}] failed to revoke the old access: {exc}",
                flush=True,
            )
            return self._json(
                503,
                {
                    "ok": False,
                    "error": "The pre-login firewall refresh failed, so you "
                             "were not logged in. Contact the administrator.",
                },
            )

        # F7: in the time between the early check and login(), another request
        # (e.g. parallel failed logins) may also block the IP. The created
        # session is revoked immediately, and the shared block response is
        # returned - without a cookie.
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
            # The session id, never a part of the cookie value.
            "sid": session.sid,
            "pending_ttl": self.gw.sessions.pending_ttl,
            "must_change_password": record.must_change_password,
        }
        if method is not None:
            audit_fields["method"] = method
        self._audit("login_success", **audit_fields)
        print(
            f"[{ip}] authenticated: {record.name!r}; waiting for access selection",
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
                "Login successful. On first login you must change your "
                "initial password."
                if record.must_change_password else
                "Login successful. Select the access rule and how long "
                "you want to use the network."
            ),
        }
        # The login response gets the same still-valid announcement as
        # /api/status; an expired or disabled MOTD is not included.
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
                "This IP address is under a fail2ban block because the firewall "
                "detected suspicious network traffic (for example a port scan). "
                "Try again later."
            )
        return (
            "This IP address is under a fail2ban block due to too many "
            "failed logins. Try again later."
        )

    @classmethod
    def _ban_reply(cls, banned: dict) -> tuple[dict, dict[str, str]]:
        """Shared block response of the login and access endpoints.

        The response never contains a password, cookie or token.
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
        """Shared fail2ban block check of the 2FA endpoints."""
        banned = self.gw.fail2ban.banned(ip)
        if banned is None:
            return False
        payload, headers = self._ban_reply(banned)
        self._audit(
            "login_failed",
            reason="under fail2ban ban",
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
        """Check JSON, IPv4, origin, rate limit and block."""
        ip = self._client_ip()
        data = self._read_json()
        if data is None:
            self._audit("login_failed", reason="bad request")
            self._json(
                400,
                {"ok": False, "error": "bad request", "code": "bad_request"},
            )
            return None
        if not gateway.is_ipv4(ip):
            self._audit("login_failed", reason="not an IPv4 address")
            self._json(
                400, {"ok": False, "error": "The gateway is reachable only with an IPv4 address."}
            )
            return None
        if not self._origin_ok():
            self._audit("login_failed", reason="invalid request origin")
            self._json(
                403, {"ok": False, "error": "invalid request origin"}
            )
            return None
        if not self.gw.login_rate.allow(ip):
            self._audit("login_failed", reason="too many attempts")
            self._json(
                429,
                {"ok": False, "error": "Too many attempts. Wait a minute."},
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
        # The same response is given for a missing, expired and used ticket;
        # in the log, however, we distinguish the reason.
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
                "error": "Invalid or expired login. Start again.",
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
        """Invalid 2FA code: ticket attempt, fail2ban and the appropriate error message."""
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
                        "Too many failed logins: your IP address was "
                        "blocked by the firewall. Try again later."
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
                f"Invalid recovery code. {remaining} attempts left."
                if remaining > 0 else
                "Too many invalid codes. Restart login."
            )
        else:
            code = "totp_invalid" if remaining > 0 else "ticket_locked"
            error = (
                f"Invalid code. {remaining} attempts left."
                if remaining > 0 else
                "Too many invalid codes. Restart login."
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
        """Verify the TOTP code after the password and create the session."""
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
                {"ok": False, "error": "bad request", "code": "bad_request"},
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
        # The user is selected exclusively by the server-side ticket.
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
        """First 2FA setup: confirm the secret and generate recovery codes."""
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
                {"ok": False, "error": "bad request", "code": "bad_request"},
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
                        "Two-factor setup failed. "
                        "Try again."
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
                        "Two-factor setup failed. "
                        "Try again."
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
        # The plaintext recovery codes appear only in this response.
        self._login_session_response(
            record, method="totp_enroll", extra={"recovery_codes": codes}
        )

    def _login_recovery(self) -> None:
        """Log in with a single-use recovery code."""
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
                {"ok": False, "error": "bad request", "code": "bad_request"},
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
            self._audit("access_denied", reason="bad request")
            return self._json(400, {"ok": False, "error": "bad request"})

        if not self._origin_ok():
            self._audit("access_denied", reason="invalid request origin")
            return self._json(403, {"ok": False, "error": "invalid request origin"})
        if not gateway.is_ipv4(ip):
            self._audit("access_denied", reason="not an IPv4 address")
            return self._json(
                400, {"ok": False, "error": "The gateway is reachable only with an IPv4 address."}
            )

        # F7: the ban check runs before the rate limit and the session lock,
        # so there is no lock inversion. The on_ban callback usually has
        # already torn down the IP's sessions; here we repeat it as defense
        # in depth, and a banned client must not receive any authorization.
        banned = self.gw.fail2ban.banned(ip)
        if banned is not None:
            payload, headers = self._ban_reply(banned)
            try:
                revoked = self.gw.sessions.revoke_ip(ip, reason="fail2ban")
            except Exception as exc:
                revoked = 0
                print(
                    f"[{ip}] tearing down sessions for the fail2ban ban "
                    f"failed: {exc}",
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
            self._audit("access_denied", reason="too many attempts")
            return self._json(
                429,
                {"ok": False, "error": "Too many access changes. Wait a minute."},
                headers={"Retry-After": "60"},
            )

        rule_ids, rule_error = _access_rule_ids(data)
        if not rule_ids:
            self._audit("access_denied", reason=rule_error)
            return self._json(400, {"ok": False, "error": rule_error})
        rule_field = ",".join(rule_ids)

        ttl = data.get("ttl")
        if isinstance(ttl, bool) or not isinstance(ttl, int):
            self._audit("access_denied", reason="missing rule or duration")
            return self._json(
                400, {"ok": False, "error": "missing rule or duration"}
            )

        token = self._cookie_token()
        current = self.gw.sessions.validate(token, ip)
        if current is None:
            self._audit("access_denied", reason="no valid session",
                        rule=rule_field)
            return self._json(
                400, {"ok": False, "error": "invalid or expired session"}
            )
        record = self.gw.users.record(current.user)
        if record is None or not record.enabled or record.pending:
            self.gw.sessions.logout(token, ip)
            self._audit(
                "access_denied", user=current.user,
                reason="disabled or deleted user", rule=rule_field,
            )
            return self._json(403, {"ok": False, "error": "the user is not active"})
        if record.must_change_password:
            # F7: defense in depth. If the flag appears on a session that
            # has already received authorization (for example after a
            # setting made from another process), the network
            # authorization must not remain in effect. logout deliberately
            # tears down only this session.
            #
            # Trade-off: the /api/password endpoint requires a valid
            # session, so after logging out the user must log in again with
            # the temporary password to change it. This is acceptable: we
            # leave no live authorization, and password change is still
            # available. (If the user only wants to change their password
            # and does not call the /api/access endpoint, the pending
            # session remains, so they can change it directly.)
            access_revoked = False
            if current.authorized:
                logged_out = self.gw.sessions.logout(
                    token, ip, reason="must_change_password"
                )
                access_revoked = logged_out is not None
            self._audit(
                "access_denied", user=current.user,
                reason="mandatory password change", rule=rule_field,
                access_revoked=access_revoked,
            )
            return self._json(
                403,
                {
                    "ok": False,
                    "error": "Change your initial password first.",
                    "must_change_password": True,
                },
            )

        groups = self.gw.groups.groups_for(current.user)
        try:
            # First resolve every identifier; on error none of the rules is
            # granted (no partial access).
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
                ttl=ttl, reason=f"firewall error: {exc}",
            )
            print(f"[{ip}] failed to set access: {exc}", flush=True)
            return self._json(
                503,
                {
                    "ok": False,
                    "error": "Failed to enable the firewall access. Try again; "
                             "if it repeats, notify the administrator.",
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
            f"[{ip}] access granted: {session.user!r}, "
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
                    "Access granted: "
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
            self._audit("logout_failed", reason="invalid request origin")
            return self._json(403, {"ok": False, "error": "invalid request origin"})
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
        print(f"[{ip}] logout", flush=True)
        self._json(
            200, {"ok": True, "message": "You have logged out. The network is blocked."},
            headers={"Set-Cookie": clear},
        )

    def _password(self) -> None:
        """Change your own password (may be mandatory on first login)."""
        ip = self._client_ip()
        data = self._read_json()
        if data is None:
            self._audit("password_change_failed", reason="bad request")
            return self._json(400, {"ok": False, "error": "bad request"})
        if not self._origin_ok():
            self._audit("password_change_failed", reason="invalid request origin")
            return self._json(403, {"ok": False, "error": "invalid request origin"})
        if not gateway.is_ipv4(ip):
            self._audit("password_change_failed", reason="not an IPv4 address")
            return self._json(
                400, {"ok": False, "error": "The gateway is reachable only with an IPv4 address."}
            )
        # Defense in depth: a banned IP cannot change its password even with
        # its existing session. We block it before the rate limiter using the
        # common ban response; no token/cookie is issued.
        banned = self.gw.fail2ban.banned(ip)
        if banned is not None:
            payload, headers = self._ban_reply(banned)
            self._audit(
                "password_change_failed",
                reason="fail2ban ban",
                source=payload["ban_source"],
            )
            return self._json(403, payload, headers=headers)
        if not self.gw.password_rate.allow(ip):
            self._audit("password_change_failed", reason="too many attempts")
            return self._json(
                429,
                {"ok": False, "error": "Too many attempts. Wait five minutes."},
                headers={"Retry-After": "300"},
            )
        token = self._cookie_token()
        session = self.gw.sessions.validate(token, ip)
        if session is None:
            self._audit("password_change_failed", reason="no valid session")
            return self._json(
                401, {"ok": False, "error": "invalid or expired session"}
            )
        record = self.gw.users.record(session.user)
        if record is None or not record.enabled or record.pending:
            self.gw.sessions.logout(
                token, ip,
                reason="disabled" if record is not None else "revoked",
            )
            self._audit(
                "password_change_failed", user=session.user,
                reason="disabled or deleted user",
            )
            return self._json(403, {"ok": False, "error": "the user is not active"})

        current = data.get("current")
        new = data.get("new")
        if not isinstance(current, str) or not isinstance(new, str):
            self._audit(
                "password_change_failed", user=session.user,
                reason="missing password",
            )
            return self._json(
                400,
                {"ok": False, "error": "both the current and the new password are required"},
            )
        if not self.gw.users.verify(session.user, current):
            self._audit(
                "password_change_failed", user=session.user,
                reason="incorrect current password",
            )
            return self._json(
                403, {"ok": False, "error": "The current password is incorrect."}
            )
        if current == new:
            self._audit(
                "password_change_failed", user=session.user,
                reason="the new password matches the old one",
            )
            return self._json(
                400,
                {"ok": False, "error": "The new password must differ from the current one."},
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
        print(f"[{ip}] password changed: {session.user!r}", flush=True)
        self._json(
            200,
            {
                "ok": True,
                "must_change_password": False,
                "sessions_revoked": revoked,
                "message": "Your password has been changed.",
            },
        )

    # -- admin CRUD ------------------------------------------------------------

    def _admin_request_rejected(self, reason: str, user: str = "") -> None:
        """Preliminary (not yet operational) rejections of the admin endpoints."""
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
            return self._json(400, {"ok": False, "error": "bad request"})
        if not self._origin_ok():
            self._admin_request_rejected("invalid_origin")
            return self._json(403, {"ok": False, "error": "invalid request origin"})
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
                message = "The account request was approved."
            elif action == "reject":
                self._admin_user_reject(data)
                message = "The account request was rejected."
            elif action == "totp_reset":
                self._admin_user_totp_reset(data, session)
                # The reset branch sends the response itself; there must be no second one.
                return
            else:
                self._admin_request_rejected(
                    "unknown_action", user=session.user
                )
                raise gateway.UserStoreError("unknown action")
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
            raise gateway.UserStoreError("name and password are required")
        name = name.strip()
        role = data.get("role", gateway.ROLE_USER)
        if role not in (gateway.ROLE_USER, gateway.ROLE_ADMIN):
            raise gateway.UserStoreError("invalid role")
        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            raise gateway.UserStoreError("the enabled field must be a boolean")
        totp_required = data.get("totp_required", False)
        if not isinstance(totp_required, bool):
            raise gateway.UserStoreError("invalid totp_required")
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
        """Approve an account request: enable it without rules or groups."""
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise gateway.UserStoreError("missing username")
        name = name.strip()
        session = self._session()
        with self.gw.admin_lock:
            record = self.gw.users.record(name)
            if record is None or not record.pending:
                raise gateway.UserStoreError(
                    "this user is not a pending approval request"
                )
            if not self.gw.users.approve_user(name):
                raise gateway.UserStoreError(
                    "this user is not a pending approval request"
                )
            self._audit(
                "registration_approved",
                target=name,
                user=session.user if session is not None else "",
            )

    def _admin_user_reject(self, data: dict) -> None:
        """Reject an account request: the request and all its remnants are deleted."""
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise gateway.UserStoreError("missing username")
        name = name.strip()
        session = self._session()
        with self.gw.admin_lock:
            record = self.gw.users.record(name)
            if record is None:
                raise gateway.UserStoreError(f"no such user: {name}")
            if not record.pending:
                raise gateway.UserStoreError(
                    "only a pending approval request can be rejected"
                )
            if not self.gw.users.reject_user(name):
                raise gateway.UserStoreError(
                    "only a pending approval request can be rejected"
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
        # The last-admin check and the modification run under one lock so that
        # two concurrent requests cannot demote/disable the last admins at the
        # same time (TOCTOU).
        with self.gw.admin_lock:
            self._admin_user_update_locked(data)

    def _admin_user_update_locked(self, data: dict) -> None:
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise gateway.UserStoreError("missing username")
        name = name.strip()
        record = self.gw.users.record(name)
        if record is None:
            raise gateway.UserStoreError(f"no such user: {name}")
        if record.pending:
            # A pending approval request cannot be edited: this way no rule or
            # group can be attached to it before approval.
            raise gateway.UserStoreError(
                "the pending account cannot be edited; use the approve "
                "or reject action"
            )
        role = data.get("role", record.role)
        if role not in (gateway.ROLE_USER, gateway.ROLE_ADMIN):
            raise gateway.UserStoreError("invalid role")
        enabled = data.get("enabled", record.enabled)
        if not isinstance(enabled, bool):
            raise gateway.UserStoreError("the enabled field must be a boolean")
        if record.is_admin and record.enabled and (
            role != gateway.ROLE_ADMIN or not enabled
        ) and self.gw.users.admin_count() <= 1:
            raise gateway.UserStoreError(
                "the last active admin cannot be disabled or demoted"
            )
        rules = self._rule_ids(data)
        if rules is not None:
            self._validate_rule_ids(rules)
        group_ids = self._group_ids(data)
        password = data.get("password")
        if password is not None and not isinstance(password, str):
            raise gateway.UserStoreError("invalid password")
        must_change = data.get("must_change_password")
        if must_change is not None and not isinstance(must_change, bool):
            raise gateway.UserStoreError(
                "the must_change_password field must be a boolean"
            )
        totp_required = data.get("totp_required")
        if "totp_required" in data and not isinstance(totp_required, bool):
            raise gateway.UserStoreError("invalid totp_required")
        password_changed = bool(isinstance(password, str) and password)
        reason = "disabled" if not enabled else (
            "password_changed" if password_changed else "revoked"
        )
        # Revoke the sessions and pending 2FA tickets before the changes. If a
        # later write fails, the user must not keep live sessions on a
        # partially modified state; this way revocation cannot be skipped due
        # to an intermediate error either.
        revoked = self.gw.sessions.revoke_user(name, reason=reason)
        tickets = 0
        if record.enabled and not enabled:
            # When disabling, pending 2FA tickets must not survive either.
            tickets = LOGIN_TICKETS.revoke_user(name, reason="disabled")
        stage = "password"
        try:
            if password_changed:
                # The affected user must change the (temporary) password set
                # by the admin on first login.
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
                # The password write may have committed before the error; the
                # other steps use separate atomic file writes, so only the
                # password state has to be restored. The sessions have
                # already been revoked.
                try:
                    self.gw.users.restore_password(name, record)
                except Exception as restore_exc:
                    print(
                        f"[{name}] restoring the password also failed: "
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
            rules=",".join(rules) if rules is not None else "(unchanged)",
            groups=",".join(group_ids) if group_ids is not None else "(unchanged)",
            password_changed=password_changed,
            must_change_password=(
                updated.must_change_password if updated is not None
                else bool(must_change)
            ),
            totp_required=(
                (updated.totp_required if updated is not None else totp_required)
                if totp_required is not None else "(unchanged)"
            ),
            sessions_revoked=revoked,
            tickets_revoked=tickets,
        )

    def _admin_user_totp_reset(
        self, data: dict, session: gateway.Session
    ) -> None:
        """Delete the 2FA secret and recovery codes; the required flag stays."""
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise gateway.UserStoreError("missing username")
        name = name.strip()
        with self.gw.admin_lock:
            record = self.gw.users.record(name)
            if record is None:
                raise gateway.UserStoreError(f"no such user: {name}")
            # Record the pre-reset state for the log; the secret and the
            # recovery hashes must of course not be included.
            was_enrolled = bool(record.totp_secret)
            if not self.gw.users.reset_totp(name):
                raise gateway.UserStoreError(f"no such user: {name}")
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
                "message": f"2FA for {name} has been reset.",
            },
        )

    def _admin_user_delete(self, data: dict) -> None:
        with self.gw.admin_lock:
            self._admin_user_delete_locked(data)

    def _admin_user_delete_locked(self, data: dict) -> None:
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise gateway.UserStoreError("missing username")
        name = name.strip()
        record = self.gw.users.record(name)
        if record is None:
            raise gateway.UserStoreError(f"no such user: {name}")
        if record.is_admin and self.gw.users.admin_count() <= 1:
            raise gateway.UserStoreError("the last admin cannot be deleted")
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
            return self._json(400, {"ok": False, "error": "bad request"})
        if not self._origin_ok():
            self._admin_request_rejected("invalid_origin")
            return self._json(403, {"ok": False, "error": "invalid request origin"})
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
                raise gateway.GroupStoreError("unknown action")
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
            raise gateway.GroupStoreError("missing group ID")
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
            raise gateway.GroupStoreError("missing group ID")
        existing = self.gw.groups.get(group_id.strip())
        if existing is None:
            raise gateway.GroupStoreError(f"no such group: {group_id}")
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
            raise gateway.GroupStoreError("missing group ID")
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
            return self._json(400, {"ok": False, "error": "bad request"})
        if not self._origin_ok():
            self._admin_request_rejected("invalid_origin")
            return self._json(403, {"ok": False, "error": "invalid request origin"})
        session = self._admin_guard()
        if session is None:
            return
        action = str(data.get("action", "")).strip()
        message = ""
        try:
            # admin_lock serializes with saving proxy entries: a domain rule
            # must not reference an entry deleted in the meantime.
            with self.gw.admin_lock:
                if action == "create":
                    self._admin_rule_create(data)
                elif action == "update":
                    self._admin_rule_update(data)
                elif action == "delete":
                    self._admin_rule_delete(data)
                elif action == "duplicate":
                    self._admin_rule_duplicate(data)
                    message = "Rule duplicated."
                else:
                    self._admin_request_rejected(
                        "unknown_action", user=session.user
                    )
                    raise gateway.RuleStoreError("unknown action")
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
            raise gateway.RuleStoreError("missing rule ID")
        # Check the assignments BEFORE saving: on an invalid identifier the
        # rule must not be created.
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
        # The ports of a host (input) rule must immediately go into the
        # kernel-side host_service_* guard sets; any error is only logged.
        self.gw.sync_host_ports()

    def _admin_rule_update(self, data: dict) -> None:
        rule_id = data.get("id")
        if not isinstance(rule_id, str):
            raise gateway.RuleStoreError("missing rule ID")
        # Check the assignments BEFORE saving: on an invalid identifier the
        # rule must not be modified.
        users = self._rule_users(data)
        groups = self._group_ids(data)
        # The rule store returns the list of dependent collections together
        # with the modification, at the commit point under one lock: a
        # collection created in the meantime is included as well, so no
        # authorized session can remain with the old ports and not only the
        # rule's own ones have to be torn down.
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
        # The resolved ports may also have changed because of dependent
        # collections, so we sync from the whole rule store (sets only grow).
        self.gw.sync_host_ports()

    def _admin_rule_duplicate(self, data: dict) -> None:
        rule_id = data.get("id")
        if not isinstance(rule_id, str):
            raise gateway.RuleStoreError("missing rule ID")
        label = data.get("label")
        if label is not None and not isinstance(label, str):
            raise gateway.RuleStoreError("label: must be a string")
        new_id = data.get("new_id")
        if new_id is not None and not isinstance(new_id, str):
            raise gateway.RuleStoreError("new_id: must be a string")
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
            raise gateway.RuleStoreError("missing rule ID")
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
        # The ports of the deleted rule intentionally remain in the
        # host_service_* sets (add-only), so existing connections do not reopen.
        self.gw.sync_host_ports()


# ---------------------------------------------- Caddy certificate cache
#
# On a handshake, certmagic (Caddy 2.10.2) first serves the certificate held
# in its memory, and only afterwards consults get_certificate and ask;
# reloading the configuration does not evict on-demand certificates from the
# cache. Thus, after disabling ACME, already issued Let's Encrypt certificates
# would remain until Caddy restarts. The portal therefore stops Caddy by
# calling POST /stop on the admin API (a Unix socket on the shared
# caddy-admin volume), and compose (restart: unless-stopped) restarts it
# immediately with an empty cache. It does not touch the /data store: ACME
# re-enabled later loads the existing certificate, with no new issuance.

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
    """Caddy admin API client and certificate-cache flushing background thread.

    The restart request also survives in the flag file, so it runs even after
    the portal restarts; a successful /stop removes it. A restart happens only
    on request, once per request, never in a loop.
    """

    CHECK_INTERVAL = 60.0
    MAX_BACKOFF = 60.0
    # /stop can take up to Caddy's grace_period (5 s).
    TIMEOUT = 15.0

    def __init__(self, socket_path: str, pending_path: str) -> None:
        self.socket_path = socket_path
        self.pending_path = pending_path
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None
        self._failures = 0
        # Every request is a new generation: a request arriving during /stop
        # is not lost.
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
        """Request a Caddy restart (ACME on→off, certificate upload)."""
        with self._lock:
            self._generation += 1
        try:
            with open(self.pending_path, "w", encoding="utf-8"):
                pass
        except OSError as exc:
            # The in-memory request still runs; only its repetition after a
            # portal restart is lost.
            print(f"[caddy] cannot write the flag file: {exc}",
                  file=sys.stderr, flush=True)
        self._wake.set()

    def run_once(self) -> float:
        """One round (pending /stop or reachability check); the next wait in seconds."""
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
                print(f"[caddy] cannot remove the flag file: {exc}",
                      file=sys.stderr, flush=True)
        print("[caddy] Caddy restarted (certificate cache flushed)",
              flush=True)
        # Check reachability of the restarted Caddy again soon.
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
            except Exception as exc:  # the thread must never die
                print(f"[caddy] unexpected error: {exc}",
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


def _transport_warnings() -> list[str]:
    """Startup warnings about how the portal is exposed (plain HTTP, Caddy).

    The firewall template gets HV_PORTAL_NET (empty: 0.0.0.0/0, the
    entrypoint's public default); a broad, non-private source network means
    the portal port is open to the internet, where the direct portal speaks
    plain HTTP.
    """
    warnings: list[str] = []
    if gateway.SINGLE_NIC:
        warnings.append(
            "single-NIC mode (HV_SINGLE_NIC=1): there is no separate client "
            "LAN and grants are IP-based only (no MAC binding) on the public "
            "interface. Serve the portal over the HTTPS proxy (HV_PROXY=1) or "
            "set HV_WAN_HTTPS_ONLY=1."
        )
    raw = os.environ.get("HV_PORTAL_NET", "").strip() or "0.0.0.0/0"
    try:
        network = ipaddress.ip_network(raw, strict=False) if raw else None
    except ValueError:
        network = None
    if network is not None and not network.is_private \
            and network.prefixlen < 24 and not gateway.COOKIE_SECURE \
            and not gateway.WAN_HTTPS_ONLY:
        warnings.append(
            f"HV_PORTAL_NET={network} opens the portal port to the internet "
            "over plain HTTP: passwords, 2FA codes and session cookies "
            "cross the network unencrypted. Serve WAN users through the "
            "Caddy HTTPS proxy (HV_PROXY=1, COMPOSE_PROFILES=proxy), set "
            "HV_WAN_HTTPS_ONLY=1 (or HV_COOKIE_SECURE=1), and narrow "
            "HV_PORTAL_NET to a management network."
        )
    if gateway.PROXY_ENABLED and len(gateway.PROXY_KEY) < 32:
        # The Docker entrypoint refuses to start in this state; only a
        # portal started some other way gets this far.
        warnings.append(
            "HV_PROXY=1 requires an HV_PROXY_KEY of at least 32 characters "
            "(the container entrypoint refuses to start without it): "
            "without it every process on the host (and every host-network "
            "container) is trusted as Caddy, including X-Forwarded-For and "
            "the certificate private keys. Generate one with "
            "'openssl rand -hex 32' and give it to both services."
        )
    if gateway.WAN_HTTPS_ONLY and not gateway.PROXY_ENABLED:
        warnings.append(
            "HV_WAN_HTTPS_ONLY=1 without HV_PROXY=1: there is no HTTPS "
            "portal, so sources outside the LAN cannot sign in at all."
        )
    if not gateway.PORTAL_URL and not gateway.PORTAL_HOSTS:
        warnings.append(
            "neither HV_PORTAL_URL nor HV_PORTAL_HOSTS is set: the /api/ "
            "endpoints answer only under an IP address or a Caddy root "
            "domain; add the DNS names you open the portal under to "
            "HV_PORTAL_HOSTS."
        )
    return warnings


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], gw: gateway.Gateway) -> None:
        self.gateway = gw
        # Every connection holds a thread for as long as it is open (also
        # idle keep-alive and slowly trickling clients), so their number is
        # capped in total and per source IP; over the cap the new connection
        # is closed at once, before a thread is started.
        self.max_connections = gateway.MAX_CONNECTIONS
        self.max_connections_per_ip = gateway.MAX_CONNECTIONS_PER_IP
        self._conn_lock = threading.Lock()
        self._conn_total = 0
        self._conn_per_ip: dict[str, int] = {}
        super().__init__(address, Handler)

    def _conn_acquire(self, ip: str) -> bool:
        with self._conn_lock:
            if self._conn_total >= self.max_connections:
                return False
            count = self._conn_per_ip.get(ip, 0)
            if ip not in PROXY_LOOPBACK and count >= self.max_connections_per_ip:
                return False
            self._conn_total += 1
            self._conn_per_ip[ip] = count + 1
            return True

    def _conn_release(self, ip: str) -> None:
        with self._conn_lock:
            self._conn_total = max(0, self._conn_total - 1)
            count = self._conn_per_ip.get(ip, 0) - 1
            if count > 0:
                self._conn_per_ip[ip] = count
            else:
                self._conn_per_ip.pop(ip, None)

    def process_request(self, request, client_address) -> None:
        ip = str(client_address[0])
        if not self._conn_acquire(ip):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._conn_release(ip)
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._conn_release(str(client_address[0]))


# ------------------------------------------------- local control channel
#
# Until now, command-line operations modified files and the kernel in a
# separate process, independently of the running daemon. Thus, after a CLI
# delete/password change, a session and firewall grant living in the daemon's
# memory could remain alive until the TTL. The control channel is a local-only
# (Unix domain) socket through which the CLI contacts the running daemon; the
# daemon performs the operation with its own live objects and immediately
# revokes the affected sessions.
#
# Security model:
#   * the socket is under STATE_DIR with 0600 permissions;
#   * the daemon checks with SO_PEERCRED that the client uid is the same;
#   * a request is a single newline-terminated JSON object, at most 64 KiB;
#   * the daemon sends a single JSON response and never logs the request
#     body, password, hash, TOTP secret or token.

CONTROL_DIR_NAME = "control"
CONTROL_SOCKET_NAME = "control.sock"
SERVER_PID_NAME = "server.pid"
CONTROL_MAX_REQUEST = 64 * 1024
CONTROL_TIMEOUT = 5.0
# The CLI wait is longer than the server-side processing time: do not
# classify a slow but healthy daemon as unreachable before the request
# is even sent.
CONTROL_CLI_TIMEOUT = 15.0
_PEERCRED_SIZE = struct.calcsize("3i")


class ControlError(RuntimeError):
    """Generic error of the control channel."""


class ControlUnavailable(ControlError):
    """The channel is unavailable before the request is sent (fallback is allowed)."""


class ControlAmbiguous(ControlError):
    """The response is uncertain after the request was sent (fallback FORBIDDEN)."""


class ControlProtocolError(ControlError):
    """The channel's response is invalid (the request has already been sent)."""


def _control_dir_path() -> str:
    # We do not capture it at import time: tests and reassignment of
    # HV_STATE_DIR must also take effect.
    return os.path.join(gateway.STATE_DIR, CONTROL_DIR_NAME)


def _control_socket_path() -> str:
    return os.path.join(_control_dir_path(), CONTROL_SOCKET_NAME)


def _server_pid_path() -> str:
    return os.path.join(gateway.STATE_DIR, SERVER_PID_NAME)


def _dir_security_error(
    directory: str, *, follow_symlinks: bool = False
) -> str | None:
    """Whether the directory's owner/permissions are suitable for holding the socket."""
    stat_fn = os.stat if follow_symlinks else os.lstat
    try:
        state = stat_fn(directory)
    except OSError as exc:
        return f"unavailable: {exc}"
    if not stat.S_ISDIR(state.st_mode):
        return "not a directory"
    if state.st_uid not in (0, os.geteuid()):
        return (
            f"owned by uid {state.st_uid}, not the process "
            "user or root"
        )
    if state.st_mode & 0o022:
        return "writable by group or other users"
    return None


def _write_server_pid() -> int | None:
    """The running daemon's pid in the state directory, with 0600 permissions."""
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
            f"WARNING: cannot write the daemon pid file ({path}): {exc}",
            file=sys.stderr,
            flush=True,
        )
        return None


def _remove_server_pid(inode: int | None) -> None:
    """Remove only our own, unchanged pid file."""
    if inode is None:
        return
    path = _server_pid_path()
    try:
        state = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        print(
            f"[control] cannot inspect the pid file state: {exc}",
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
            f"[control] failed to remove the pid file: {exc}",
            file=sys.stderr,
            flush=True,
        )


def _control_peer_uid(sock) -> int | None:
    """The uid of the other end of a Unix socket (Linux SO_PEERCRED)."""
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
    """One request = one newline-terminated JSON object, one JSON response."""

    def handle(self) -> None:
        try:
            self.request.settimeout(CONTROL_TIMEOUT)
        except OSError:
            pass
        if not self._peer_allowed():
            self._respond(
                {"ok": False, "status": 1, "error": "rejected"}
            )
            return

        try:
            line = self.rfile.readline(CONTROL_MAX_REQUEST + 1)
        except (OSError, ValueError):
            self._respond(
                {"ok": False, "status": 1, "error": "read error"}
            )
            return
        if len(line) > CONTROL_MAX_REQUEST:
            self._respond(
                {"ok": False, "status": 1, "error": "request too large"}
            )
            return
        if not line.endswith(b"\n"):
            self._respond(
                {"ok": False, "status": 1, "error": "bad request"}
            )
            return
        try:
            data = json.loads(line)
        except ValueError:
            data = None
        if not isinstance(data, dict):
            self._audit("control_rejected", reason="bad_request")
            self._respond(
                {"ok": False, "status": 1, "error": "bad request"}
            )
            return

        action = data.get("action")
        if not isinstance(action, str) or not action:
            self._audit("control_rejected", reason="bad_request")
            self._respond(
                {"ok": False, "status": 1, "error": "missing action"}
            )
            return
        method = self._ACTIONS.get(action)
        if method is None:
            # Log the action name (not secret), never the body.
            self._audit(
                "control_rejected",
                reason="unknown_action",
                action=action[:64],
            )
            self._respond(
                {
                    "ok": False,
                    "status": 1,
                    "error": f"unknown action: {action[:64]}",
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
            # These messages contain no password/hash/secret.
            self._audit(
                "control_action_failed",
                action=action[:64],
                reason=str(exc)[:200],
            )
            self._respond(
                {"ok": False, "status": 1, "error": str(exc)}
            )
        except Exception as exc:  # the channel must not die from an error
            print(
                f"[control] {action[:64]} error: {exc}",
                file=sys.stderr,
                flush=True,
            )
            self._respond(
                {"ok": False, "status": 1, "error": "internal error"}
            )
        else:
            self._respond(payload)

    # -- low-level helpers -----------------------------------------------------

    def _peer_allowed(self) -> bool:
        uid = _control_peer_uid(self.request)
        if uid is not None and uid == os.geteuid():
            return True
        # Generic rejection; we do not log the peer uid/pid.
        self._audit("control_denied", reason="peer_uid")
        return False

    def _audit(self, event: str, **fields) -> None:
        try:
            self.server.gateway.audit.write(event, **fields)
        except Exception as exc:  # logging must not interrupt the channel
            print(
                f"[control] logging error: {exc}",
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

    # -- input validation ------------------------------------------------------

    @staticmethod
    def _name(data: dict) -> str:
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("missing username")
        return name.strip()

    @staticmethod
    def _password(data: dict) -> str:
        password = data.get("password")
        if not isinstance(password, str):
            raise ValueError("missing password")
        return password

    @staticmethod
    def _bool(data: dict, key: str, default: bool) -> bool:
        value = data.get(key, default)
        if not isinstance(value, bool):
            raise ValueError(f"the {key} field must be a boolean")
        return value

    @staticmethod
    def _rules(data: dict) -> tuple[str, ...]:
        raw = data.get("rules", [])
        if not isinstance(raw, list) or len(raw) > 64:
            raise ValueError("the rules field must be a list of at most 64 items")
        out: list[str] = []
        for value in raw:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("invalid rule ID")
            value = value.strip()
            if not gateway._SERVICE_ID_RE.match(value):
                raise ValueError(f"invalid rule ID: {value!r}")
            if value == gateway.LEGACY_ADMIN_RULE_ID:
                raise ValueError(
                    "this is a reserved legacy ID and cannot be assigned"
                )
            if value not in out:
                out.append(value)
        return tuple(out)

    # -- actions ---------------------------------------------------------------

    def _action_user_add(self, data: dict) -> dict:
        gw = self.server.gateway
        name = self._name(data)
        password = self._password(data)
        role = data.get("role", gateway.ROLE_USER)
        if role not in (gateway.ROLE_USER, gateway.ROLE_ADMIN):
            raise ValueError("invalid role")
        must_change = self._bool(data, "must_change_password", True)
        rules = self._rules(data)
        gw.users.add(
            name, password, role=role, rules=rules,
            must_change_password=must_change,
        )
        # If a session or login ticket for an account with the same name
        # existed before, the new account must not inherit the authorization.
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
            "message": f"User created: {name}",
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
            "message": f"Password updated: {name}",
        }

    def _action_user_del(self, data: dict) -> dict:
        gw = self.server.gateway
        name = self._name(data)
        if not gw.users.remove(name):
            self._audit(
                "cli_action_failed",
                action="del",
                target=name,
                reason="no such user",
            )
            return {
                "ok": False,
                "status": 1,
                "stdout": True,
                "error": f"No such user: {name}",
            }
        # Group membership must be deleted too, otherwise an account created
        # later with the same name would inherit the old group's rules.
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
            "message": f"User deleted: {name}",
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
                reason="no such user",
            )
            return {
                "ok": False,
                "status": 1,
                "stdout": True,
                "error": f"No such user: {name}",
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
            "message": f"2FA reset: {name}",
            "sessions_revoked": revoked,
        }

    def _action_fail2ban_ban(self, data: dict) -> dict:
        gw = self.server.gateway
        ip = data.get("ip")
        if not isinstance(ip, str) or not ip.strip():
            raise ValueError("missing IP address")
        seconds = data.get("seconds", 0)
        if isinstance(seconds, bool) or not isinstance(seconds, int):
            raise ValueError(
                "the ban duration must be an integer (seconds)"
            )
        manual = self._bool(data, "manual", True)
        user = data.get("user", "cli")
        if not isinstance(user, str):
            user = "cli"
        # The running daemon's manager: the on_ban callback tears down the
        # IP's sessions and flushes conntrack. The fail2ban_ban event is
        # written by on_ban, so we do not duplicate it here.
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
            "message": f"Banned: {ban['ip']} ({ban['remaining']} s)",
            "ip": ban["ip"],
            "until": ban.get("until", 0),
        }

    def _action_fail2ban_unban(self, data: dict) -> dict:
        gw = self.server.gateway
        ip = data.get("ip")
        if not isinstance(ip, str) or not ip.strip():
            raise ValueError("missing IP address")
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
            message = f"Was not banned: {ip}"
        else:
            message = f"Unbanned: {ip}"
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
            "message": f"Unbanned: {removed} ban(s)",
            "removed": removed,
        }

    def _action_status(self, data: dict) -> dict:
        """Diagnostics; never contains a password, hash or token."""
        gw = self.server.gateway
        names = gw.users.names()
        try:
            f2b = gw.fail2ban.status()
        except Exception:
            f2b = {}
        return {
            "ok": True,
            "status": 0,
            "message": "The daemon is reachable.",
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
    """Local control channel reachable only by the same uid."""

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
                f"the control channel directory is not secure "
                f"({parent}): {parent_error}"
            )
        self._prepare_path(address)
        # The permissions must not be wider even in the short window between
        # bind and chmod; afterwards we set them explicitly to 0600.
        old_umask = os.umask(0o177)
        try:
            super().__init__(address, ControlHandler)
        finally:
            os.umask(old_umask)
        try:
            # After bind we check that our socket is really at the path, and
            # only then change its permissions.
            state = os.lstat(address)
            if not stat.S_ISSOCK(state.st_mode):
                raise ControlUnavailable(
                    "the path is not a socket after bind"
                )
            self._socket_ino = int(state.st_ino)
            os.chmod(address, 0o600)
            after = os.lstat(address)
            if (
                not stat.S_ISSOCK(after.st_mode)
                or after.st_ino != self._socket_ino
            ):
                raise ControlUnavailable(
                    "the socket was replaced after bind"
                )
        except (OSError, ControlUnavailable) as exc:
            try:
                super().server_close()
            finally:
                self._unlink_socket()
            if isinstance(exc, ControlUnavailable):
                raise
            raise ControlUnavailable(
                "failed to set the control channel permissions: "
                f"{exc}"
            ) from exc

    @staticmethod
    def _prepare_path(address: str) -> None:
        """Remove a stale socket; we do not touch a foreign file."""
        try:
            state = os.lstat(address)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ControlUnavailable(
                f"cannot inspect the state of {address}: {exc}"
            ) from exc
        if not stat.S_ISSOCK(state.st_mode):
            raise ControlUnavailable(
                f"{address} exists but is not a socket; not removing it"
            )
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.5)
        try:
            probe.connect(address)
        except (ConnectionRefusedError, FileNotFoundError):
            # Stale socket: it can safely be removed before bind.
            try:
                os.unlink(address)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise ControlUnavailable(
                    f"failed to remove the stale socket: {exc}"
                ) from exc
            return
        except OSError as exc:
            raise ControlUnavailable(
                f"cannot determine the state of {address}: {exc}"
            ) from exc
        finally:
            probe.close()
        raise ControlUnavailable(
            f"{address} is already in use (is another daemon running?)"
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
        """Idempotent close: also removes the socket file."""
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
                f"[control] failed to remove the socket: {exc}",
                file=sys.stderr,
                flush=True,
            )
            return
        # Remove only our own socket, and only if it has not been replaced by
        # another process's since.
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
                f"[control] failed to remove the socket: {exc}",
                file=sys.stderr,
                flush=True,
            )


def _start_control_server(gw: gateway.Gateway) -> ControlServer | None:
    path = _control_socket_path()
    directory = _control_dir_path()
    state_dir = gateway.STATE_DIR
    # STATE_DIR is the parent of the state files (users, audit, fail2ban, PID)
    # and the control directory. If others can write it, the socket/pidfile
    # can be replaced, so we do not start a control channel there.
    state_error = _dir_security_error(state_dir, follow_symlinks=True)
    if state_error is not None:
        print(
            f"WARNING: the {state_dir} state directory is not secure "
            f"({state_error}); the local control channel will not start, the "
            "portal keeps running. While the daemon runs, we refuse local "
            "execution of CLI modifications because of the PID file; use "
            "the admin interface.",
            file=sys.stderr,
            flush=True,
        )
        return None
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as exc:
        print(
            f"WARNING: cannot create the control channel directory "
            f"({directory}): {exc}",
            file=sys.stderr,
            flush=True,
        )
        return None
    # Check the directory through an fd, without following symlinks, and
    # tighten it to 0700; we do not use an existing directory owned by
    # someone else.
    try:
        dir_fd = os.open(
            directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
    except OSError as exc:
        print(
            f"WARNING: the control channel directory is not secure "
            f"({directory}): {exc}",
            file=sys.stderr,
            flush=True,
        )
        return None
    try:
        state = os.fstat(dir_fd)
        if state.st_uid not in (0, os.geteuid()):
            print(
                f"WARNING: the control channel directory is owned by "
                f"uid {state.st_uid} ({directory}); not starting.",
                file=sys.stderr,
                flush=True,
            )
            return None
        if stat.S_IMODE(state.st_mode) != 0o700:
            try:
                os.fchmod(dir_fd, 0o700)
            except OSError as exc:
                print(
                    f"WARNING: cannot set the control channel directory's "
                    f"permissions to 0700 "
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
            f"WARNING: the control channel directory is not secure "
            f"({directory}): {dir_error}; not starting.",
            file=sys.stderr,
            flush=True,
        )
        return None
    try:
        control = ControlServer(path, gw)
    except (ControlUnavailable, OSError) as exc:
        print(
            f"WARNING: the local control channel did not start "
            f"({path}): {exc}",
            file=sys.stderr,
            flush=True,
        )
        return None
    control.start()
    print(
        f"Control channel: {path} (local, 0600)", flush=True
    )
    return control


# ------------------------------------- control channel: client side (CLI)


def _control_request(
    payload: dict, timeout: float | None = None
) -> dict:
    """One request on the local control channel.

    ``ControlUnavailable``: the request was not even started (no socket, a
    connection or socket-creation error); in this case the CLI may fall back
    to the local operation. ``ControlAmbiguous``: a timeout/IO/EOF occurred
    after the request was sent, so we do not know whether the daemon executed
    it; local modification is FORBIDDEN. ``ControlProtocolError``: the request
    was sent but the response is invalid; local modification is likewise
    forbidden.
    """
    if timeout is None:
        # Do not capture it at function definition time: tests and callers
        # may override the constant later.
        timeout = CONTROL_CLI_TIMEOUT
    path = _control_socket_path()
    try:
        state = os.stat(path)
    except FileNotFoundError as exc:
        raise ControlUnavailable("no control channel") from exc
    except OSError as exc:
        raise ControlUnavailable(
            f"cannot inspect the control channel: {exc}"
        ) from exc
    if not stat.S_ISSOCK(state.st_mode):
        raise ControlUnavailable("the path is not a socket")
    if stat.S_IMODE(state.st_mode) & 0o077:
        # A password may only travel over a 0600 socket.
        raise ControlUnavailable(
            "the control channel permissions are not 0600"
        )

    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
    except OSError as exc:
        if sock is not None:
            sock.close()
        raise ControlUnavailable(
            f"cannot create the control channel socket: {exc}"
        ) from exc
    try:
        try:
            sock.connect(path)
        except FileNotFoundError as exc:
            raise ControlUnavailable("no control channel") from exc
        except ConnectionRefusedError as exc:
            raise ControlUnavailable(
                "the control channel is not accepting connections "
                "(stale socket)"
            ) from exc
        except PermissionError as exc:
            raise ControlUnavailable(
                "no permission for the control channel"
            ) from exc
        except socket.timeout as exc:
            raise ControlUnavailable(
                "timeout while connecting to the control channel"
            ) from exc
        except OSError as exc:
            raise ControlUnavailable(
                f"the control channel is unavailable: {exc}"
            ) from exc

        peer = _control_peer_uid(sock)
        if peer is not None and peer != os.geteuid():
            raise ControlProtocolError(
                "the control channel owner is not the caller"
            )

        # From here on the request may be sent: any error is at most of
        # uncertain outcome, so we must not fall back to local mode.
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
                "timeout while sending the request; the request may have "
                "been sent partially or in full"
            ) from exc
        except OSError as exc:
            raise ControlAmbiguous(
                f"send error on the control channel: {exc}"
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
                        "response too large on the control channel"
                    )
                if b"\n" in chunk:
                    complete = True
                    break
        except socket.timeout as exc:
            raise ControlAmbiguous(
                "timeout waiting for the control channel response; the "
                "request was sent but the response did not arrive"
            ) from exc
        except OSError as exc:
            raise ControlAmbiguous(
                f"read error on the control channel: {exc}"
            ) from exc
    finally:
        sock.close()

    raw = b"".join(chunks)
    if not complete:
        # The server always terminates the response with a newline. If the
        # connection broke mid-response, we do not know what happened.
        raise ControlAmbiguous(
            "the control channel response was cut off or empty"
        )
    line = raw.split(b"\n", 1)[0]
    try:
        response = json.loads(line)
    except ValueError as exc:
        raise ControlProtocolError(
            "invalid JSON response on the control channel"
        ) from exc
    if not isinstance(response, dict):
        raise ControlProtocolError(
            "invalid response on the control channel"
        )
    return response


def _control_attempt(payload: dict) -> tuple[dict | None, str | None]:
    """(response, None) or (None, reason for unavailability)."""
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
            error = "the daemon reported an error"
        if response.get("stdout"):
            print(error)
        else:
            print(f"error: {error}", file=sys.stderr)
    return status if status >= 0 else 1


def _warn_control_fallback(reason: str | None) -> None:
    path = _control_socket_path()
    print(
        f"WARNING: the control channel ({path}) is unavailable: "
        f"{reason or 'unknown reason'}.",
        file=sys.stderr,
        flush=True,
    )
    print(
        "WARNING: the modification was made only locally (on disk/kernel) "
        "and did NOT revoke the running daemon's live sessions.",
        file=sys.stderr,
        flush=True,
    )


def _read_server_pid() -> int | None:
    """The running daemon's PID from the PID file, if it appears authentic."""
    path = _server_pid_path()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        print(
            f"WARNING: cannot read the daemon PID file ({path}): {exc}",
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
        # The daemon writes the PID file with 0600; we do not accept a PID
        # from a file writable by group/others.
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
        # The process exists, it just belongs to another user.
        return True
    except OSError:
        return False
    return True


def _live_daemon_pid() -> int | None:
    """The daemon PID if the PID file says it is still running; otherwise None."""
    pid = _read_server_pid()
    if pid is not None and _pid_is_alive(pid):
        return pid
    return None


def _control_mutation(payload: dict) -> tuple[bool, int]:
    """Try to execute the operation on the daemon.

    Returns ``(True, exit_code)`` if the daemon responded or the outcome is
    uncertain (even on error; in that case local modification must not be
    performed either), ``(False, 0)`` if the channel was unavailable before
    the request was sent and no daemon is running, so the local operation
    follows.
    """
    try:
        response, reason = _control_attempt(payload)
    except ControlAmbiguous as exc:
        print(
            "error: the request was sent but no response arrived; "
            "I did NOT run a local modification, check the list "
            f"({exc}).",
            file=sys.stderr,
            flush=True,
        )
        return True, 1
    except ControlProtocolError as exc:
        print(
            f"error: the control channel returned an invalid response: {exc}; "
            "I did NOT run a local modification, check the list.",
            file=sys.stderr,
            flush=True,
        )
        return True, 1
    if response is not None:
        return True, _print_control_response(response)
    pid = _live_daemon_pid()
    if pid is not None:
        print(
            f"error: the control channel is unavailable "
            f"({reason or 'unknown reason'}), but the daemon is running "
            f"(PID {pid}).",
            file=sys.stderr,
            flush=True,
        )
        print(
            "error: I did NOT run the local modification for security "
            "reasons, because the running daemon's live sessions and "
            "firewall state would diverge from disk. Use the admin "
            "interface or stop the daemon.",
            file=sys.stderr,
            flush=True,
        )
        return True, 1
    _warn_control_fallback(reason)
    return False, 0


def _daemon_user_names() -> list[str] | None:
    """Read-only: the daemon's authoritative user list, if available."""
    try:
        response, _reason = _control_attempt({"action": "status"})
    except (ControlAmbiguous, ControlProtocolError):
        # For reads the local list is acceptable, but the caller knows that
        # the daemon state is uncertain.
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
            raise SystemExit("error: no password received on standard input")
        return line.rstrip("\r\n")
    first = getpass.getpass("Password: ")
    second = getpass.getpass("Password again: ")
    if first != second:
        raise SystemExit("error: the two passwords do not match")
    return first


def _cli_audit(audit, event: str, **fields) -> None:
    """Log a CLI operation; even on error it does not interrupt the command."""
    fields.setdefault("actor", "cli")
    try:
        audit.write(event, **fields)
    except Exception as exc:
        print(
            f"[audit] failed to write {event}: {exc}",
            file=sys.stderr,
            flush=True,
        )


def _user_cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="server.py user",
        description="Manage users in the Dropjak users.json file.",
    )
    sub = parser.add_subparsers(dest="action", required=True)

    p_add = sub.add_parser("add", help="new user")
    p_add.add_argument("name")
    p_add.add_argument("--password-stdin", action="store_true")
    p_add.add_argument(
        "--no-must-change", action="store_true",
        help="do not require changing the password on first login",
    )
    p_add.add_argument(
        "--role", choices=(gateway.ROLE_USER, gateway.ROLE_ADMIN),
        default=gateway.ROLE_USER, help="role (default: user)",
    )
    p_add.add_argument(
        "--rule", action="append", default=[], metavar="ID",
        help="assigned rule ID (may be given multiple times)",
    )

    p_pw = sub.add_parser("passwd", help="change password")
    p_pw.add_argument("name")
    p_pw.add_argument("--password-stdin", action="store_true")
    p_pw.add_argument(
        "--no-must-change", action="store_true",
        help="do not require the user to change it on first login",
    )

    p_del = sub.add_parser("del", help="delete user")
    p_del.add_argument("name")

    p_totp = sub.add_parser(
        "totp-reset", help="reset two-factor authentication"
    )
    p_totp.add_argument("name")

    sub.add_parser("list", help="list users")

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
                        f"invalid rule ID: {rule_id!r}"
                    )
                if rule_id == gateway.LEGACY_ADMIN_RULE_ID:
                    raise gateway.UserStoreError(
                        "this is a reserved legacy ID and cannot be assigned"
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
            print(f"User created: {args.name}")
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
            print(f"Password updated: {args.name}")
        elif args.action == "del":
            handled, status = _control_mutation({
                "action": "user.del",
                "name": args.name,
            })
            if handled:
                return status
            if store.remove(args.name):
                # A local (daemon-less) delete also clears group membership,
                # just like the admin API.
                groups.remove_member_everywhere(args.name)
                _cli_audit(
                    audit, "cli_user_deleted", target=args.name
                )
                print(f"User deleted: {args.name}")
            else:
                _cli_audit(
                    audit,
                    "cli_action_failed",
                    action="del",
                    target=args.name,
                    reason="no such user",
                )
                print(f"No such user: {args.name}")
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
                print(f"2FA reset: {args.name}")
            else:
                _cli_audit(
                    audit,
                    "cli_action_failed",
                    action="totp-reset",
                    target=args.name,
                    reason="no such user",
                )
                print(f"No such user: {args.name}")
                return 1
        elif args.action == "list":
            # Read-only: use the daemon's authoritative list if available;
            # otherwise read from the local file (works offline too).
            names = _daemon_user_names()
            if names is None:
                names = store.names()
            if not names:
                print("No users. To create one: server.py user add <name>")
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
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _fail2ban_cli(argv: list[str]) -> int:
    """Manage fail2ban from the command line (a fallback when excluded)."""
    parser = argparse.ArgumentParser(
        prog="server.py fail2ban",
        description="Manage the fail2ban ban list.",
    )
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list", help="list banned IPs")
    p_ban = sub.add_parser("ban", help="ban an IP address")
    p_ban.add_argument("ip")
    p_ban.add_argument(
        "--seconds", type=int, default=0,
        help="ban duration in seconds (default: the configured value)",
    )
    p_unban = sub.add_parser("unban", help="unban a single IP address")
    p_unban.add_argument("ip")
    sub.add_parser("unban-all", help="unban everything")

    args = parser.parse_args(argv)
    audit = gateway.AuditLog()
    manager = fail2ban_mod.Fail2ban(gateway.Firewall(), audit=audit)
    try:
        if args.action == "list":
            snapshot = manager.snapshot()
            state = "active" if snapshot["enabled"] else "disabled"
            drop_state = "active" if snapshot["drop_enabled"] else "disabled"
            print(
                f"Fail2ban: {state}; threshold: {snapshot['max_attempts']} "
                f"attempt(s) / {snapshot['window_seconds']} s; "
                f"ban: {snapshot['ban_seconds']} s"
            )
            print(
                f"Drop-based banning: {drop_state}; packet threshold: "
                f"{snapshot['drop_max']} "
                f"({'active' if snapshot['drop_count_active'] else 'disabled'}), "
                f"port threshold: {snapshot['drop_ports']} "
                f"({'active' if snapshot['drop_ports_active'] else 'disabled'}) / "
                f"{snapshot['drop_window_seconds']} s"
            )
            print(
                "Switches: "
                f"login={'on' if snapshot['enabled'] else 'off'}, "
                f"drop-count={'on' if snapshot['drop_count_enabled'] else 'off'}, "
                f"ports={'on' if snapshot['drop_ports_enabled'] else 'off'}, "
                f"proxy={'on' if snapshot['proxy_enabled'] else 'off'}."
            )
            if snapshot["error"]:
                print(f"WARNING: {snapshot['error']}")
            bans = snapshot["bans"]
            if not bans:
                print("No banned IPs.")
                return 0
            print(f"Banned IPs ({len(bans)}):")
            for ban in bans:
                source = ban.get("source") or (
                    "manual" if ban["manual"] else "login"
                )
                kind = {
                    "manual": "manual",
                    "drop": "drop",
                    "login": "login",
                    "proxy": "proxy (HTTP/S)",
                }.get(source, source)
                detail = ban.get("detail") or ""
                if source == "drop" and detail:
                    kind = f"drop/{detail}"
                print(
                    f"  {ban['ip']:<15}  remaining: {ban['remaining']:>6} s  "
                    f"{kind:<16}  {ban['attempts']} events  "
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
                f"Banned: {ban['ip']} ({ban['remaining']} s)"
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
                print(f"Unbanned: {args.ip}")
            else:
                _cli_audit(
                    audit,
                    "cli_action_failed",
                    action="unban",
                    target=args.ip,
                    reason="not_banned",
                )
                print(f"Was not banned: {args.ip}")
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
            print(f"Unbanned: {removed} ban(s)")
            return 0
    except fail2ban_mod.Fail2banError as exc:
        _cli_audit(
            audit,
            "cli_action_failed",
            action=args.action,
            target=getattr(args, "ip", ""),
            reason=str(exc),
        )
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 2


def _serve() -> int:
    try:
        gw = gateway.Gateway()
    except gateway.CatalogError as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        try:
            gateway.AuditLog().write(
                "service_start_failed", reason=str(exc)
            )
        except Exception as audit_exc:
            print(
                f"[audit] failed to write service_start_failed: "
                f"{audit_exc}",
                file=sys.stderr,
                flush=True,
            )
        return 1

    # The login tickets' lifecycle (issue/reject/expiry) is audited too.
    LOGIN_TICKETS.set_audit(gw.audit)

    print("Dropjak — network gateway", flush=True)
    print(f"Listening: 0.0.0.0:{gateway.PORT}", flush=True)
    print(
        f"Firewall: inet {gw.firewall.table} / {gw.firewall.set_name}, "
        f"{gw.firewall.tcp_set}, {gw.firewall.udp_set}, {gw.firewall.icmp_set}"
        + ("  (DRY-RUN — rules are not modified!)" if gw.firewall.dry_run else ""),
        flush=True,
    )
    captcha_mode = (
        "Cloudflare Turnstile" if gateway.TURNSTILE_ON
        else f"proof-of-work ({gateway.POW_DIFFICULTY} hex zeros)"
    )
    print(f"Captcha: {captcha_mode}", flush=True)
    print(
        f"Service catalog: {len(gw.catalog.service_order)} services, "
        f"{len(gw.catalog.scenario_order)} scenarios ({gw.catalog.source})",
        flush=True,
    )
    print(
        f"Rules: {len(gw.rules.persisted_rules())} admin rules, "
        f"{len(gw.groups.all_groups())} groups",
        flush=True,
    )
    print(f"Audit: {gw.audit.path}", flush=True)
    print(
        f"Selectable access: {gateway.format_duration(gateway.MIN_TTL)}–"
        f"{gateway.format_duration(gateway.MAX_TTL)}; default: "
        f"{gateway.format_duration(gw.sessions.ttl)}",
        flush=True,
    )
    if gateway.PORTAL_URL:
        print(f"Canonical portal URL: {gateway.PORTAL_URL}", flush=True)

    gw.prepare()
    try:
        admin_state = gateway.provision_admin(gw.users)
    except gateway.UserStoreError as exc:
        print(f"WARNING: setting up the admin account failed: {exc}", flush=True)
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
            print(f"[admin] user created: {gateway.ADMIN_USER}", flush=True)
        elif admin_state == "updated":
            print(f"[admin] password updated: {gateway.ADMIN_USER}", flush=True)
        elif admin_state == "unchanged":
            print(f"[admin] user OK: {gateway.ADMIN_USER}", flush=True)

    def _admin_has_tcp22_host_rule() -> bool:
        """Whether any enabled admin has an effective TCP 22 host rule."""
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
            "WARNING: no enabled administrator has an effective TCP 22 host "
            "(input) rule, so host SSH remains closed.",
            flush=True,
        )
        print(
            "WARNING: the admin should create a host rule in the portal "
            "that explicitly allows TCP port 22, assign it to the user "
            "(or a group), then authorize it in an active session from the "
            "same source IP.",
            flush=True,
        )
        print(
            "WARNING: secure first start over SSH: first start the container "
            "with HV_SKIP_FIREWALL=1, set up the rule and the assignment, "
            "then restart it normally. Alternative: keep the provider "
            "console open.",
            flush=True,
        )

    if not any(
        record.is_admin and record.enabled and not record.pending
        for record in gw.users.details()
    ):
        print(
            "WARNING: there is no enabled admin account.",
            flush=True,
        )
        print(
            "WARNING: the portal's Admin panel is unavailable, and host SSH "
            "opens only with an active, authorized portal session and a host "
            "rule that explicitly allows TCP port 22.",
            flush=True,
        )
        print(
            "WARNING: set HV_ADMIN_ENABLED=1, HV_ADMIN_USER, and either "
            "HV_ADMIN_PASSWORD or HV_ADMIN_PASSWORD_FILE in the .env file, "
            "then restart the container.",
            flush=True,
        )

    if not gw.users.names():
        print(
            "WARNING: there is not a single user. "
            "To create one: python3 server.py user add <name>",
            flush=True,
        )

    for line in _transport_warnings():
        print(f"WARNING: {line}", flush=True)

    gw.start()
    # Flush Caddy's certificate cache (only with the domain proxy).
    caddy = None
    if gateway.PROXY_ENABLED and gateway.CADDY_ADMIN:
        caddy = CaddyAdmin(
            gateway.CADDY_ADMIN,
            os.path.join(gateway.STATE_DIR, CADDY_RESTART_PENDING_NAME),
        )
        gw.caddy = caddy
        caddy.start()
    # The running daemon's local control channel: CLI operations thus run in
    # the same process and can also revoke the real (live) sessions. If it
    # does not start, the CLI falls back to local mode.
    control = _start_control_server(gw)
    server = AppServer(("0.0.0.0", gateway.PORT), gw)
    # The PID file is created after the control channel but still before
    # serving. The CLI learns from it that the daemon is alive, so it must not
    # modify locally if the socket is temporarily unavailable.
    pid_inode = _write_server_pid()

    # Cleaning up 2FA tickets: this way unused (abandoned) tickets are
    # logged as expired at most 30 seconds after expiry.
    sweeper_stop = threading.Event()

    def _ticket_sweeper() -> None:
        while not sweeper_stop.wait(30):
            try:
                LOGIN_TICKETS.purge()
            except Exception as exc:  # the sweeper must never die
                print(
                    f"[audit] ticket sweeper error: {exc}",
                    file=sys.stderr,
                    flush=True,
                )

    threading.Thread(
        target=_ticket_sweeper, name="hv-tickets", daemon=True
    ).start()

    # In a container the process may be PID 1, in which case the kernel
    # ignores SIGTERM by default. Handle it so docker stop shuts down quickly
    # and cleanly.
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
            except Exception as exc:  # shutdown must not get stuck
                print(
                    f"[control] failed to stop the control channel: "
                    f"{exc}",
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
        print("OK" if ok else f"error: {why}")
        return 0 if ok else 1
    print(
        "Usage: server.py [serve | user ... | fail2ban ... | check-firewall]",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
