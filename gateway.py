#!/usr/bin/env python3
"""
Dropjak — the core of the gateway.

This module does not deal with HTTP. It contains users, password hashing,
sessions, captcha and nftables integration. The HTTP layer lives in
server.py.

Security principle: a password on its own only provides a choice, and
network access is created ONLY if the nftables rule actually took effect.
If the firewall cannot be updated, there is no grant.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone

import droplog
import fail2ban as fail2ban_mod
import settings_store
import tunnel as tunnel_mod


# --------------------------------------------------------------- configuration

BASE = os.path.dirname(os.path.abspath(__file__))

VERSION_PATH = os.path.join(BASE, "VERSION")


def _read_version() -> str:
    try:
        with open(VERSION_PATH, encoding="utf-8") as fh:
            value = fh.read().strip()
    except OSError:
        return "0.0.0"
    return value if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) else "0.0.0"


APP_VERSION = _read_version()


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, value)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


def _startup_flush_mode(
    flush_on_start: bool, allow_stale_grants: bool
) -> str:
    """Startup flush decision.

    ``flush``: the operator requested a clean start.
    ``reconcile``: flushing is disabled, but orphaned grants must not
    remain in the kernel; the dynamic sets are aligned with the in-memory
    (empty) session table.
    ``stale_allowed``: explicit, insecure opt-in; earlier grants may
    remain alive until the kernel TTL.
    """
    if flush_on_start:
        return "flush"
    if allow_stale_grants:
        return "stale_allowed"
    return "reconcile"


STATE_DIR = os.environ.get("HV_STATE_DIR", "").strip() or BASE
USERS_PATH = os.environ.get("HV_USERS", "").strip() or os.path.join(STATE_DIR, "users.json")
RULES_PATH = os.environ.get("HV_RULES", "").strip() or os.path.join(STATE_DIR, "rules.json")
GROUPS_PATH = os.environ.get("HV_GROUPS", "").strip() or os.path.join(STATE_DIR, "groups.json")
AUDIT_PATH = (
    os.environ.get("HV_AUDIT_LOG", "").strip()
    or os.path.join(STATE_DIR, "audit.jsonl")
)
AUDIT_MAX_BYTES = _env_int("HV_AUDIT_MAX_BYTES", 10 * 1024 * 1024, 256 * 1024)
AUDIT_KEEP = min(20, _env_int("HV_AUDIT_KEEP", 5, 1))

# Reserved legacy rule identifier. The identifier of the earlier built-in
# full-access rule; no such rule exists today, but the identifier is never
# handed out and cannot be taken, so that an old rules.json/users.json/
# groups.json cannot bring a hidden grant back to life.
LEGACY_ADMIN_RULE_ID = "admin-full"
ROLE_ADMIN = "admin"
ROLE_USER = "user"

# Startup admin account from the Docker Compose environment. When disabled,
# the portal does not touch the users.
ADMIN_ENABLED = _env_bool("HV_ADMIN_ENABLED", False)
ADMIN_USER = os.environ.get("HV_ADMIN_USER", "").strip()
ADMIN_PASSWORD = os.environ.get("HV_ADMIN_PASSWORD", "")
# The password may also come from a file instead of an environment
# variable (Docker secret, a file readable only by root). If both are
# given, the direct variable takes precedence.
ADMIN_PASSWORD_FILE = os.environ.get("HV_ADMIN_PASSWORD_FILE", "").strip()
if not ADMIN_PASSWORD and ADMIN_PASSWORD_FILE:
    try:
        with open(ADMIN_PASSWORD_FILE, "r", encoding="utf-8") as _admin_pw_file:
            ADMIN_PASSWORD = _admin_pw_file.read().rstrip("\r\n")
    except (OSError, UnicodeError):
        ADMIN_PASSWORD = ""
# Child processes (nft, conntrack, ip, wg) must not inherit the password.
# This does not clear /proc/<pid>/environ or `docker inspect`; prefer
# HV_ADMIN_PASSWORD_FILE.
os.environ.pop("HV_ADMIN_PASSWORD", None)

PORT = _env_int("PORT", 8100, 1)
CHALLENGE_TTL = _env_int("HV_CHALLENGE_TTL", 600, 30)   # seconds

# After login the user chooses the length of access. The product-level
# limit is 1 minute – 30 days; HV_MIN_TTL/HV_MAX_TTL can only narrow it.
ABSOLUTE_MIN_TTL = 60
ABSOLUTE_MAX_TTL = 30 * 24 * 60 * 60
MIN_TTL = max(
    ABSOLUTE_MIN_TTL,
    min(_env_int("HV_MIN_TTL", ABSOLUTE_MIN_TTL, 1), ABSOLUTE_MAX_TTL),
)
MAX_TTL = min(
    ABSOLUTE_MAX_TTL,
    max(_env_int("HV_MAX_TTL", ABSOLUTE_MAX_TTL, 1), MIN_TTL),
)
DEFAULT_TTL = min(max(_env_int("HV_SESSION_TTL", 3600, 1), MIN_TTL), MAX_TTL)
# The window between entering the password and choosing the service.
AUTH_TTL = min(max(_env_int("HV_AUTH_TTL", 600, 1), 60), 3600)
# Backward compatibility: the old name is the default access duration.
SESSION_TTL = DEFAULT_TTL

SERVICES_PATH = (
    os.environ.get("HV_SERVICES_FILE", "").strip()
    or os.path.join(BASE, "services.json")
)
# We also accept the original POW_DIFFICULTY name for backward compatibility.
POW_DIFFICULTY = min(
    6, _env_int("HV_POW_DIFFICULTY", _env_int("POW_DIFFICULTY", 4, 1), 1)
)
PBKDF2_ITERATIONS = _env_int("HV_PBKDF2_ITERATIONS", 600_000, 10_000)

RATE_WINDOW = _env_int("HV_RATE_WINDOW", 60, 1)
RATE_MAX = _env_int("HV_RATE_MAX", 10, 1)
# Per-account lock against password guessing from many source IPs: after
# ACCOUNT_LOCK_MAX failures within ACCOUNT_LOCK_WINDOW seconds the login name
# is locked for ACCOUNT_LOCK_BASE seconds, doubling up to ACCOUNT_LOCK_CAP.
ACCOUNT_LOCK_MAX = _env_int("HV_ACCOUNT_LOCK_MAX", 10, 1)
ACCOUNT_LOCK_WINDOW = _env_int("HV_ACCOUNT_LOCK_WINDOW", 900, 30)
ACCOUNT_LOCK_BASE = _env_int("HV_ACCOUNT_LOCK_BASE", 60, 1)
ACCOUNT_LOCK_CAP = _env_int("HV_ACCOUNT_LOCK_CAP", 900, 1)
# Concurrent portal connections (one thread each): in total and per source
# IP. Loopback (Caddy, healthcheck) counts only towards the total.
MAX_CONNECTIONS = _env_int("HV_MAX_CONNECTIONS", 256, 8)
MAX_CONNECTIONS_PER_IP = _env_int("HV_MAX_CONNECTIONS_PER_IP", 16, 1)

NFT_BIN = os.environ.get("HV_NFT_BIN", "").strip() or shutil.which("nft") or "/usr/sbin/nft"
NFT_TABLE = os.environ.get("HV_NFT_TABLE", "hatarvedelem").strip()
NFT_SET = os.environ.get("HV_NFT_SET", "allowed_v4").strip()
CONNTRACK_BIN = os.environ.get("HV_CONNTRACK_BIN", "").strip() or shutil.which("conntrack") or ""
# Identifier of the packets marked by the forward chain. The Docker
# protection lets through only this mark. The template and the portal use
# the same one.
FWD_MARK = os.environ.get("HV_FWD_MARK", "0x44524a4b").strip().lower()
if not re.match(r"^0x[0-9a-f]{1,8}$", FWD_MARK):
    FWD_MARK = "0x44524a4b"
# Pre-auth port 80 traffic receives a conntrack mark in prerouting so that
# the portal redirect does not divert it. This is not an access mark.
PREAUTH_CT_MARK = "0x50524541"
CUSTOM_CHAINS = (
    "preauth",
    "preauth_input",
    "block",
    "preauth_nat",
    "block_nat",
)
# Runtime chains of the port proxy (nftables DNAT). The template contains
# only the rules jumping to them; the portal fills in their contents:
#   portproxy_nat:   DNAT/redirect (from the -101 prerouting chain, before
#                    the Docker DNAT)
#   portproxy_input: allowing the redirected (input) proxy
#   portproxy_snat:  masquerade of the requested forward entries
PORTPROXY_CHAINS = ("portproxy_nat", "portproxy_input", "portproxy_snat")
# Receiving chain for the UDP port of the WireGuard tunnel. The portal fills
# it in; without an agent it stays empty, so the WireGuard port is closed.
TUNNEL_CHAIN = "tunnel_input"

# Drop-based fail2ban: only genuine, unapproved TCP traffic counts.
# The MAC/spoof/ipv6/fail2ban/dns/ssh reasons are excluded (fake source IP
# or a regular, expired session), and the regular client's UDP background
# noise (mDNS, LLMNR, NetBIOS, DNS) is not a ban either.
DROP_BAN_REASONS = frozenset(
    {"no-grant", "wan-drop", "input-wan", "input-lan", "portproxy"}
)
DROP_BAN_SKIP_TCP_PORTS = frozenset({53})


def infra_exempt_addresses(
    resolv_path: str = "/etc/resolv.conf",
    route_path: str = "/proc/net/route",
) -> list[str]:
    """Infrastructure the drop-based fail2ban must never ban.

    The host's IPv4 upstream resolvers and its default-route gateways. A
    forged packet with one of these sources would otherwise cut DNS or the
    uplink for the whole network. Read once at startup; addresses added
    later belong in HV_FAIL2BAN_DROP_EXEMPT or the admin list.
    """
    found: list[str] = []
    try:
        with open(resolv_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    found.append(parts[1])
    except OSError:
        pass
    try:
        with open(route_path, "r", encoding="ascii", errors="replace") as fh:
            next(fh, None)
            for line in fh:
                fields = line.split()
                # Destination 0.0.0.0 with the RTF_GATEWAY flag (0x2).
                if (
                    len(fields) >= 4 and fields[1] == "00000000"
                    and int(fields[3], 16) & 0x2
                ):
                    found.append(
                        str(ipaddress.IPv4Address(
                            int(fields[2], 16).to_bytes(4, sys.byteorder)
                        ))
                    )
    except (OSError, ValueError):
        pass
    result: list[str] = []
    for item in found:
        try:
            address = ipaddress.ip_address(item)
        except ValueError:
            continue
        if (
            address.version == 4 and not address.is_loopback
            and str(address) not in result
        ):
            result.append(str(address))
    return result
# Order of the chains that appear in the raw (iptables -L -n style) output
# of the admin Firewall view. The custom chains follow forward, so that the
# pre-auth and block rules are in one place in a readable order.
RULESET_CHAINS = (
    "forward",
    "input",
    "prerouting",
    "postrouting",
    "preauth",
    "preauth_input",
    "block",
    "preauth_nat",
    "block_nat",
    "portproxy_prerouting",
    "portproxy_nat",
    "portproxy_input",
    "portproxy_snat",
    "tunnel_input",
    "loopback_guard",
    "breakglass",
)


def _enabled_custom_entries(entries) -> list[dict]:
    """Only the enabled, well-formed pre-auth/block entries.

    An entry disabled in the UI (``enabled: false``) must not reach the
    kernel: the switch means the actual removal of the rule, not merely
    hiding it in the UI. Non-dict elements are left out, because the
    nft rule assembly could not interpret them anyway.
    """
    return [
        entry for entry in entries
        if isinstance(entry, dict) and entry.get("enabled", True)
    ]


def tunnel_proxy_entries(tunnels) -> list[dict]:
    """Synthetic port proxy entries for the enabled tunnel services.

    The DNAT points from the cloud listener port to the agent's WireGuard
    address; forwarding is allowed by the existing ct original rule of the
    forward chain, therefore the entry is of type ``forward``. The
    ``_tunnel`` marker separates it from user port proxy entries (warning,
    conntrack).
    """
    entries: list[dict] = []
    if not isinstance(tunnels, dict):
        return entries
    for agent in tunnels.get("agents", []):
        if not isinstance(agent, dict) or not agent.get("enabled"):
            continue
        for item in settings_store.agent_services_expanded(agent):
            if item.get("domain"):
                # Domain-mode service: no WAN listener port and no DNAT; the
                # traffic goes through Caddy over the WireGuard tunnel.
                continue
            entries.append({
                "id": (
                    f"tunnel:{agent.get('id', '')}:"
                    f"{item['proto']}:{item['listen_port']}"
                ),
                "label": item["label"],
                "proto": item["proto"],
                "type": "forward",
                "listen_port": item["listen_port"],
                "target_ip": agent.get("address"),
                "target_port": item["tunnel_port"],
                "ifaces": "wan", "snat": False, "enabled": True,
                "_tunnel": True,
            })
    return entries


def tunnel_public_preauth(tunnels) -> list[tuple[str, int]]:
    """WAN pre-auth pairs of the public, port-based tunnel services.

    Only the enabled, ``public`` services of enabled agents are included,
    and only the port-mode ones: a domain-mode service has no WAN listener
    port. Element: ``(proto, listen_port)``; ``both`` splits into two
    protocols. The list is deterministically sorted.
    """
    pairs: set[tuple[str, int]] = set()
    if not isinstance(tunnels, dict):
        return []
    for agent in tunnels.get("agents", []):
        if not isinstance(agent, dict) or not agent.get("enabled"):
            continue
        for item in settings_store.agent_services_expanded(agent):
            if item.get("domain") or not item.get("public"):
                continue
            protos = (
                ("tcp", "udp") if item["proto"] == "both"
                else (item["proto"],)
            )
            for proto in protos:
                if proto not in ("tcp", "udp"):
                    continue
                pairs.add((proto, int(item["listen_port"])))
    return sorted(pairs, key=lambda pair: (pair[1], pair[0]))


_LAN_IF_RE = re.compile(r"^[A-Za-z0-9_.:@+-]{1,15}$")
DRY_RUN = os.environ.get("HV_DRY_RUN", "0") == "1"
# We use the same permissive logic as for the other boolean variables:
# 1/true/yes/on (regardless of case and surrounding whitespace). The old
# ``== "1"`` comparison silently turned off the ``true``/``yes``/``on``
# values, which meant grants left behind in the kernel at startup.
FLUSH_ON_START = _env_bool("HV_FLUSH_ON_START", True)
# Explicit, NOT secure opt-in: if the operator disabled the startup
# flush, this allows the grants left in the kernel by an earlier process
# to remain alive until the TTL. Disabled by default: in that case the
# portal aligns the dynamic sets with the in-memory (empty) session table
# and removes the orphaned grants.
ALLOW_STALE_GRANTS_ON_START = _env_bool(
    "HV_ALLOW_STALE_GRANTS_ON_START", False
)

# The LAN interface and network. If both are known, the portal also
# records, for the client's allowed IP, the MAC address taken from the ARP
# table, and the firewall lets traffic through on the LAN only with this
# MAC address. This rules out a client using the IP address of another
# allowed client.
HV_LAN_IF = os.environ.get("HV_LAN_IF", "").strip()
HV_WAN_IF = os.environ.get("HV_WAN_IF", "").strip()
HV_LAN_NET_RAW = os.environ.get("HV_LAN_NET", "").strip()


def _parse_lan_network(raw: str):
    if not raw:
        return None
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None
    return network if network.version == 4 else None


LAN_NETWORK = _parse_lan_network(HV_LAN_NET_RAW)
MAC_BINDING = bool(HV_LAN_IF and LAN_NETWORK is not None)
ARP_PATH = os.environ.get("HV_ARP_PATH", "").strip() or "/proc/net/arp"

PORTAL_URL = os.environ.get("HV_PORTAL_URL", "").strip()
# Further host names (host or host:port, comma separated) under which the
# portal's /api/ endpoints answer, besides IP literals, the PORTAL_URL host
# and the Caddy root domains (DNS rebinding protection, see server.py).
PORTAL_HOSTS = frozenset(
    item.strip().lower()
    for item in os.environ.get("HV_PORTAL_HOSTS", "").split(",")
    if item.strip()
)
# Shared secret between Caddy and the portal (HV_PROXY_KEY, at least 32
# characters). When set, a loopback peer counts as Caddy only with this
# value in X-Dropjak-Proxy-Key; without it every loopback process is
# trusted (the old behaviour, a startup warning).
PROXY_KEY = os.environ.get("HV_PROXY_KEY", "").strip()
# Whether the Caddy domain proxy is enabled (HV_PROXY=1): in that case the
# portal is also reachable over HTTPS on the root domains.
PROXY_ENABLED = _env_bool("HV_PROXY", False)
# HV_WAN_HTTPS_ONLY=1: the login, password and admin endpoints refuse
# (403 https_required) a non-LAN source that did not come through Caddy, so
# WAN credentials never cross the network over the plain-HTTP portal port.
# LAN clients and loopback-direct callers are unaffected.
WAN_HTTPS_ONLY = _env_bool("HV_WAN_HTTPS_ONLY", False)
# Caddy admin API (Unix socket on the shared caddy-admin volume); the
# portal flushes Caddy's certificate cache through it. Empty means disabled.
CADDY_ADMIN = os.environ.get(
    "HV_CADDY_ADMIN", "/run/caddy-admin/admin.sock"
).strip()
COOKIE_NAME = "hv_session"
COOKIE_SECURE = (
    os.environ.get("HV_COOKIE_SECURE", "0") == "1"
    or PORTAL_URL.startswith("https://")
)

TURNSTILE_SITEKEY = os.environ.get("TURNSTILE_SITEKEY", "").strip()
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "").strip()
TURNSTILE_ON = bool(TURNSTILE_SITEKEY and TURNSTILE_SECRET)
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

# Time-based one-time password (TOTP, RFC 6238) for two-factor login.
TOTP_ISSUER = os.environ.get("HV_TOTP_ISSUER", "").strip() or "Dropjak"
TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1
_TOTP_RECOVERY_RE = re.compile(r"^[0-9a-f]{64}$")

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
# E-mail address for account requests. The 254 characters are the
# practical upper limit of RFC 5321; the pattern is simple, but it filters
# out the obviously invalid forms.
MAX_EMAIL = 254
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_NFT_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$")
_SERVICE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
# Service rule reference: "<agent-id>/<service-id>".
_SERVICE_REF_RE = re.compile(
    r"^[a-z0-9][a-z0-9_-]{0,31}/[a-z0-9][a-z0-9_-]{0,31}$"
)


def normalize_email(raw, strict=True) -> str:
    """Canonical form of an e-mail address: trimmed, lowercased.

    With ``strict`` it raises ``ValueError`` on invalid input; otherwise it
    returns an empty string so the caller can handle it in a fail-safe way.
    """
    if not isinstance(raw, str):
        if strict:
            raise ValueError("invalid e-mail address")
        return ""
    value = raw.strip().lower()
    if not value:
        if strict:
            raise ValueError("e-mail address is required")
        return ""
    if (
        len(value) > MAX_EMAIL
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or not EMAIL_RE.match(value)
    ):
        if strict:
            raise ValueError("invalid e-mail address")
        return ""
    return value


_log_lock = threading.Lock()


def log(message: str) -> None:
    with _log_lock:
        print(message, flush=True)


# ------------------------------------------------------------------ IP helpers

def normalize_ip(raw: str) -> str:
    """Reduces IPv4-mapped IPv6 addresses to plain IPv4."""
    addr = ipaddress.ip_address(str(raw).strip())
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def is_ipv4(raw: str) -> bool:
    try:
        return ipaddress.ip_address(str(raw).strip()).version == 4
    except ValueError:
        return False


_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


def arp_mac(ip: str, interface: str = "", path: str = ARP_PATH) -> str | None:
    """The LAN client's MAC address from the ARP table.

    We accept only complete (``0x2``) entries, and if the interface is
    known, only the entry on that interface. On any error we return
    ``None``, because the caller then denies the grant in a fail-closed
    way.
    """
    try:
        address = normalize_ip(ip)
    except ValueError:
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            next(fh, None)
            for line in fh:
                fields = line.split()
                if len(fields) < 6 or fields[0] != address:
                    continue
                try:
                    flags = int(fields[2], 16)
                except ValueError:
                    continue
                if flags & 0x2 == 0:
                    continue
                if interface and fields[5] != interface:
                    continue
                mac = fields[3].strip().lower()
                if mac == "00:00:00:00:00:00" or not _MAC_RE.match(mac):
                    continue
                return mac
    except (OSError, UnicodeError):
        return None
    return None


# --------------------------------------------------------------- services

class CatalogError(ValueError):
    """The service catalog is missing or invalid."""


class AccessError(ValueError):
    """The requested access is invalid (service or duration)."""


@dataclass(frozen=True)
class Ports:
    """Destination ports allowed by a rule.

    Rules consist of ports: several TCP and UDP ports, optionally ICMP,
    or full access. The port is the destination port requested by the
    client, before DNAT, therefore for a container port published by
    Docker the host port must be given.
    """

    tcp: tuple[int, ...] = ()
    udp: tuple[int, ...] = ()
    icmp: bool = False
    full: bool = False
    # forward: the gateway forwards the traffic (internet, Docker container).
    # input: opens the portal machine's own service to the client IP.
    direction: str = "forward"

    def public(self) -> dict:
        return {
            "tcp": list(self.tcp),
            "udp": list(self.udp),
            "icmp": self.icmp,
            "full": self.full,
            "direction": self.direction,
            "label": self.label(),
        }

    def label(self) -> str:
        if self.full:
            return "Minden port"
        parts: list[str] = []
        if self.tcp:
            parts.append("TCP " + format_ports(self.tcp, dash="–"))
        if self.udp:
            parts.append("UDP " + format_ports(self.udp, dash="–"))
        if self.icmp:
            parts.append("ICMP")
        return " · ".join(parts) or "Nincs port"


@dataclass(frozen=True)
class RuleSelection:
    """A rule selected by a session and its grants.

    A session may select several rules; the actual firewall grant is the
    per-direction union of the selections' grants. ``rule_id``/``label``
    identify the selection during partial revocation and display.
    """

    rule_id: str
    label: str
    grants: tuple[Ports, ...]
    # Proxy hostnames allowed by the selection (explicit domain rule and
    # domain-mode service together).
    domains: tuple[str, ...] = ()
    # The service references belonging to the selection and the domains
    # resolved from them; needed for display (label of the selected service).
    service_refs: tuple[str, ...] = ()
    service_domains: tuple[str, ...] = ()


def union_grants(parts) -> tuple[Ports, ...]:
    """Per-direction union of Ports grants.

    A ``full`` grant covers every port and ICMP in one direction, therefore
    the rest of that direction disappears from the union. Otherwise the
    TCP/UDP ports are united as sets (in ascending order), and ICMP gets a
    logical OR. The result is deterministic: ``forward``, then ``input``
    order, without the empty parts.

    An unknown direction raises ``FirewallError``, consistent with the
    behaviour of :meth:`Firewall._elements`.
    """

    combined: dict[str, dict] = {}
    for part in parts:
        direction = part.direction
        if direction not in ("forward", "input"):
            raise FirewallError(
                f"invalid rule direction: {direction!r}"
            )
        entry = combined.setdefault(
            direction, {"tcp": set(), "udp": set(), "icmp": False, "full": False}
        )
        if part.full:
            entry["full"] = True
        else:
            entry["tcp"].update(part.tcp)
            entry["udp"].update(part.udp)
            entry["icmp"] = entry["icmp"] or part.icmp
    result: list[Ports] = []
    for direction in ("forward", "input"):
        entry = combined.get(direction)
        if entry is None:
            continue
        if entry["full"]:
            result.append(Ports(full=True, direction=direction))
            continue
        if not (entry["tcp"] or entry["udp"] or entry["icmp"]):
            continue
        result.append(
            Ports(
                tcp=tuple(sorted(entry["tcp"])),
                udp=tuple(sorted(entry["udp"])),
                icmp=entry["icmp"],
                direction=direction,
            )
        )
    return tuple(result)


@dataclass(frozen=True)
class Service:
    """A selectable service and its destination ports.

    The catalog is needed only to create the initial rules and to convert
    the old, service-based rules.json. In the running system the rules
    already contain ports.
    """

    id: str
    label: str
    description: str
    tcp: tuple[int, ...] = ()
    udp: tuple[int, ...] = ()
    icmp: bool = False
    full: bool = False

    def public(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "tcp": list(self.tcp),
            "udp": list(self.udp),
            "icmp": self.icmp,
            "full": self.full,
        }


@dataclass(frozen=True)
class Scenario:
    """A ready-made service bundle for quick selection."""

    id: str
    label: str
    description: str
    services: tuple[str, ...]
    default_ttl: int
    default: bool = False

    def public(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "services": list(self.services),
            "default_ttl": self.default_ttl,
            "default": self.default,
        }


@dataclass(frozen=True)
class Rule:
    """An access rule managed by an admin.

    A rule contains one or more destination ports (TCP and/or UDP),
    optionally ICMP, or full access. The user may choose only from the
    rules assigned to them (directly or through a group), and the rule
    lives for the selected duration.
    """

    id: str
    label: str
    description: str
    tcp: tuple[int, ...] = ()
    udp: tuple[int, ...] = ()
    icmp: bool = False
    full: bool = False
    default_ttl: int = DEFAULT_TTL
    max_ttl: int = MAX_TTL
    builtin: bool = False
    created: int = 0
    # Collection rule: individual rule identifiers whose ports apply as a
    # union. The stored port fields are empty in this case; the resolved
    # view computes the union.
    members: tuple[str, ...] = ()
    # forward: forwarded (internet/Docker) traffic; input: the portal
    # machine's own service. For an individual rule this is its own
    # direction; a collection rule has no direction of its own, its grants
    # are derived from its members (see grants). For a resolved collection
    # the display value may also be "mixed" if the members' directions are
    # mixed.
    direction: str = "forward"
    # The resolved input (host) union of the collection. The tcp/udp/icmp
    # fields store the forward union; together the two give the display
    # union.
    input_tcp: tuple[int, ...] = ()
    input_udp: tuple[int, ...] = ()
    # Domain rule: full proxy hostnames, without ports; it does not touch
    # nftables. For a collection, the resolved union of the members' domains.
    domains: tuple[str, ...] = ()
    # Service rule: "<agent-id>/<service-id>" references. We deliberately
    # do not use the "services" key, because that marks the old
    # service-based rules (_is_legacy).
    service_refs: tuple[str, ...] = ()
    # Forward ports resolved from the references; non-persisted values.
    # They stay empty for a missing/disabled service (fail-closed).
    service_tcp: tuple[int, ...] = ()
    service_udp: tuple[int, ...] = ()
    # Proxy hostnames resolved from the references (domain-mode services
    # only); non-persisted, part of session_domains.
    service_domains: tuple[str, ...] = ()
    # The full mapping signature resolved from the references:
    # sorted union of ``(ref, proto, listen_port, target_host, target_port)``
    # tuples; for a domain-mode service a row with ``proto="domain"`` is
    # also included so that renaming invalidates it too. Non-persisted,
    # like service_tcp/service_udp. The check at decision time uses this to
    # detect a target-host/target-port redirect even if the listener ports
    # are unchanged.
    service_signature: tuple[tuple[str, str, int, str, int], ...] = ()

    @property
    def ports(self) -> Ports:
        """Display union; grants are authoritative for firewall enforcement.

        For an individual rule, its own ports. For a collection, the union
        of the forward and input ports so that the existing display code
        shows the full union; the direction is only a display value.
        """
        if self.service_refs and not self.collection:
            # A service rule is always forward direction; the ports are
            # given by the listener ports of the referenced services.
            return Ports(self.service_tcp, self.service_udp, direction="forward")
        if not self.collection:
            return Ports(
                self.tcp, self.udp, self.icmp, self.full, self.direction
            )
        tcp = tuple(sorted(set(self.tcp) | set(self.input_tcp)))
        udp = tuple(sorted(set(self.udp) | set(self.input_udp)))
        direction = (
            "forward" if self.tcp or self.udp or self.icmp else "input"
        )
        return Ports(tcp, udp, self.icmp, self.full, direction)

    @property
    def grants(self) -> tuple[Ports, ...]:
        """The actual access grants, per direction.

        Individual rule: exactly its own ports. Collection: the forward
        union in one forward Ports, the input union in one input Ports.
        The firewall always uses this, never the display ports field.
        """
        if self.service_refs and not self.collection:
            # Service rule: grants only if at least one port was resolved.
            # A missing reference therefore opens nothing.
            if not (self.service_tcp or self.service_udp):
                return ()
            return (self.ports,)
        if not self.collection:
            # A domain rule acts on the proxy gateway; it has no firewall
            # grant.
            return () if self.domains else (self.ports,)
        parts: list[Ports] = []
        if self.tcp or self.udp or self.icmp:
            parts.append(
                Ports(self.tcp, self.udp, self.icmp, False, "forward")
            )
        if self.input_tcp or self.input_udp:
            parts.append(
                Ports(self.input_tcp, self.input_udp, False, False, "input")
            )
        return tuple(parts)

    @property
    def session_domains(self) -> tuple[str, ...]:
        """The proxy hostnames opened in the session.

        The union of the explicit domain rule's hostnames and the names
        resolved from the domain-mode services, in order of first
        occurrence, without duplicates.
        """
        if not self.service_domains:
            return self.domains
        names: list[str] = []
        for name in (*self.domains, *self.service_domains):
            if name not in names:
                names.append(name)
        return tuple(names)

    @property
    def collection(self) -> bool:
        return bool(self.members)

    def _service_entries(self) -> list[dict]:
        """Display form of the service references.

        The label is filled in by the server from the settings. With a
        single reference the resolved ports are also included here; with
        several, resolution is a union, so the server resolves the
        individual ports.
        """
        if not self.service_refs:
            return []
        if len(self.service_refs) == 1:
            return [{
                "ref": self.service_refs[0],
                "label": "",
                "tcp": list(self.service_tcp),
                "udp": list(self.service_udp),
            }]
        return [
            {"ref": ref, "label": "", "tcp": [], "udp": []}
            for ref in self.service_refs
        ]

    def public(self) -> dict:
        if self.collection:
            # A collection has no direction of its own: the direction key
            # is deliberately left out of the payload, and the ports show
            # the display union.
            ports = self.ports
            return {
                "id": self.id,
                "label": self.label,
                "description": self.description,
                "tcp": list(ports.tcp),
                "udp": list(ports.udp),
                "icmp": ports.icmp,
                "full": False,
                "ports_label": ports.label(),
                "default_ttl": self.default_ttl,
                "max_ttl": self.max_ttl,
                "builtin": self.builtin,
                "created": self.created,
                "members": list(self.members),
                "collection": True,
                "domains": list(self.domains),
                "service_refs": list(self.service_refs),
                "services": self._service_entries(),
            }
        payload = {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "tcp": list(self.tcp),
            "udp": list(self.udp),
            "icmp": self.icmp,
            "full": self.full,
            "direction": self.direction,
            "ports_label": self.ports.label(),
            "default_ttl": self.default_ttl,
            "max_ttl": self.max_ttl,
            "builtin": self.builtin,
            "created": self.created,
            "members": list(self.members),
            "collection": self.collection,
            "domains": list(self.domains),
            "service_refs": list(self.service_refs),
            "services": self._service_entries(),
        }
        if self.service_refs:
            # A service rule is neither a domain nor a collection: these
            # fields are deliberately not returned. The ports are values
            # resolved from the references, not persisted, so the tcp/udp
            # fields show these as well (similar to the resolved view of a
            # collection).
            ports = self.ports
            payload["tcp"] = list(ports.tcp)
            payload["udp"] = list(ports.udp)
            payload["ports_label"] = ports.label()
            payload.pop("members", None)
            payload.pop("domains", None)
        return payload


@dataclass(frozen=True)
class Group:
    """A user group that bundles rules."""

    id: str
    label: str
    description: str
    rules: tuple[str, ...] = ()
    members: tuple[str, ...] = ()
    created: int = 0

    def public(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "rules": list(self.rules),
            "members": list(self.members),
            "created": self.created,
        }


def _utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


# Severity of the log entries. The central map lets the UI and the filters
# see the same classification as the log writer.
AUDIT_SEVERITY = {
    "login_failed": "warn", "logout_failed": "warn", "access_denied": "warn",
    "password_change_failed": "warn", "registration_failed": "warn",
    "registration_rejected": "warn", "admin_denied": "warn",
    "admin_action_failed": "warn", "admin_session_terminated": "warn",
    "admin_user_deleted": "warn", "admin_user_update_failed": "warn",
    "admin_group_deleted": "warn",
    "admin_rule_deleted": "warn", "admin_totp_reset": "warn",
    "totp_recovery_used": "warn", "access_revoked": "warn",
    "totp_ticket_rejected": "warn", "totp_failed": "warn",
    "totp_enroll_failed": "warn", "session_replaced": "warn",
    # Enrollment binds the second factor to whoever knew the password at
    # that moment (trust on first use): every enrollment is shown to admins.
    "totp_enrolled": "alert",
    "session_ip_changed": "warn", "session_ended": "warn",
    "fail2ban_unban": "warn", "fail2ban_bans_released": "warn",
    "fail2ban_ban_evicted": "warn",
    "fail2ban_ban_refused": "alert",
    "fail2ban_ban_evict_failed": "warn",
    "fail2ban_bans_release_failed": "warn",
    "fail2ban_ban_restore_failed": "warn",
    "admin_request_rejected": "warn",
    "admin_session_terminate_failed": "warn",
    "portal_host_redirect": "warn", "proxy_challenge_failed": "warn",
    "host_rejected": "warn", "account_locked": "alert",
    "https_required": "warn",
    "step_up_failed": "warn",
    "cli_password_changed": "warn",
    "cli_user_deleted": "warn", "cli_totp_reset": "warn",
    "cli_action_failed": "warn", "cli_fail2ban_unban": "warn",
    "firewall_error": "alert", "fail2ban_error": "alert",
    "fail2ban_ban": "alert", "fail2ban_sync_failed": "alert",
    "fail2ban_load_error": "alert", "totp_ticket_locked": "alert",
    "session_reaper_error": "alert", "session_shutdown_error": "alert",
    "service_start_failed": "alert", "admin_provision_failed": "alert",
    "settings_invalid": "alert", "conntrack_failed": "alert",
    "cli_fail2ban_ban": "alert",
    "config_export_failed": "warn", "config_import_failed": "warn",
    "config_reset": "warn", "config_reset_failed": "warn",
}
DEFAULT_SEVERITY = "info"

# These values must never reach the log. Exact key match: ``ticket_hash``
# and ``sid`` are allowed; ``session`` is dropped as a backstop, because a
# session token (or a part of it) must never be logged.
SENSITIVE_AUDIT_KEYS = {
    "pass", "password", "password_hash", "hash", "secret", "totp_secret",
    "code", "recovery", "recovery_code", "cookie", "token", "ticket",
    "otpauth_uri", "session",
}


def audit_severity(event: str) -> str:
    return AUDIT_SEVERITY.get(str(event), DEFAULT_SEVERITY)


def _search_key(value) -> str:
    """Text normalized for search: lowercased, separators turned into spaces.

    The underscore and the hyphen mark the same word boundary as a space,
    therefore ``access_granted``, ``ACCESS-GRANTED`` and ``Access granted``
    all end up on the same key. Repeated whitespace is collapsed.
    """
    text = str(value).lower().replace("_", " ").replace("-", " ")
    return " ".join(text.split())


def _search_values(value):
    """The values of the audit entry recursively, without the keys.

    Free-text search may match only visible values: the JSON key names
    (``event``, ``user``) should not match every row.
    """
    if isinstance(value, dict):
        for nested in value.values():
            yield from _search_values(nested)
    elif isinstance(value, (list, tuple, set)):
        for nested in value:
            yield from _search_values(nested)
    elif value is not None:
        yield value


# The IP filter searches in these fields: the client (ip), and the object
# of the operation (e.g. the address banned/unbanned by the admin in the
# target field).
AUDIT_IP_FIELDS = ("ip", "target", "target_ip", "session_ip", "request_ip")


def _audit_ip_match(item: dict, network) -> bool:
    for field in AUDIT_IP_FIELDS:
        try:
            if ipaddress.ip_address(str(item.get(field, ""))) in network:
                return True
        except ValueError:
            continue
    return False


class AuditLog:
    """JSON Lines log of every significant event of the portal.

    The log is kept in the state volume, rotated with a size limit. The
    entries never contain a password or password hash. A write error must
    not interrupt login: the error goes to the process log.
    """

    def __init__(
        self,
        path: str = AUDIT_PATH,
        max_bytes: int = AUDIT_MAX_BYTES,
        keep: int = AUDIT_KEEP,
        logger=log,
    ) -> None:
        self.path = os.path.abspath(path)
        self.max_bytes = max(256 * 1024, int(max_bytes))
        self.keep = max(1, min(20, int(keep)))
        self.log = logger
        self._lock = threading.Lock()

    def _rotate_locked(self) -> None:
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return
        if size < self.max_bytes:
            return
        for index in range(self.keep - 1, 0, -1):
            src = f"{self.path}.{index}"
            dst = f"{self.path}.{index + 1}"
            try:
                os.replace(src, dst)
            except FileNotFoundError:
                continue
            except OSError as exc:
                self.log(f"[audit] rotation failed: {exc}")
                return
        try:
            os.replace(self.path, f"{self.path}.1")
        except OSError as exc:
            self.log(f"[audit] rotation failed: {exc}")

    def write(self, event: str, **fields) -> dict:
        now = time.time()
        # An explicit severity overrides the central classification.
        severity = fields.pop("severity", None)
        if severity is None:
            severity = audit_severity(event)
        entry = {
            "ts": now,
            "time": _utc_iso(now),
            "event": str(event),
            "severity": str(severity)[:32],
        }
        for key, value in fields.items():
            if value is None:
                continue
            if key in SENSITIVE_AUDIT_KEYS:
                # We log only the name of the key to the process log, never
                # the value. The sensitive field is omitted from the audit
                # entry.
                self.log(f"[audit] sensitive field omitted: {key}")
                continue
            if isinstance(value, str):
                entry[key] = value[:500]
            elif isinstance(value, (int, float, bool)):
                entry[key] = value
            else:
                entry[key] = str(value)[:500]
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        try:
            directory = os.path.dirname(self.path) or "."
            os.makedirs(directory, exist_ok=True)
            with self._lock:
                self._rotate_locked()
                fd = os.open(
                    self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
                )
                try:
                    os.write(fd, (line + "\n").encode("utf-8"))
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except OSError as exc:
            self.log(f"[audit] write error: {exc}")
        else:
            user = entry.get("user", "")
            ip = entry.get("ip", "")
            detail = " ".join(
                f"{key}={entry[key]}"
                for key in ("rule", "ttl", "reason", "target", "action")
                if key in entry
            )
            self.log(
                f"[event] {entry['event']}"
                + (f" user={user}" if user else "")
                + (f" ip={ip}" if ip else "")
                + (f" {detail}" if detail else "")
            )
        return entry

    def _files(self) -> list[str]:
        files = [self.path]
        for index in range(1, self.keep + 1):
            path = f"{self.path}.{index}"
            if os.path.exists(path):
                files.append(path)
        return files

    def read(
        self,
        limit: int = 500,
        event: str = "",
        user: str = "",
        q: str = "",
        before: float | None = None,
        severity: str = "",
        ip=None,
        events=None,
    ) -> list[dict]:
        """``ip`` is an ipaddress network (a single address: /32 or /128) or None.

        ``events`` is a set of exact event codes (multi-filter); ``event`` is
        the old single filter with partial matching.
        """
        limit = max(1, min(2000, int(limit)))
        events = frozenset(str(code).lower() for code in events or ())
        event_raw = (event or "").strip().lower()
        event_key = _search_key(event_raw)
        user = (user or "").strip().lower()
        q = (q or "").strip().lower()
        q_key = _search_key(q)
        severity = (severity or "").strip().lower()
        rows: list[dict] = []
        for path in self._files():
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                        except ValueError:
                            continue
                        if not isinstance(item, dict):
                            continue
                        if before is not None:
                            try:
                                if float(item.get("ts", 0)) >= before:
                                    continue
                            except (TypeError, ValueError):
                                continue
                        if events and str(
                            item.get("event", "")
                        ).lower() not in events:
                            continue
                        if event_raw:
                            raw_event = str(item.get("event", "")).lower()
                            # Partial matching of the raw event code remains
                            # the previous behaviour (e.g. the ``admin_``
                            # family), and the normalized form also finds the
                            # displayed labels with spaces/hyphens.
                            if event_raw not in raw_event and (
                                not event_key
                                or event_key not in _search_key(raw_event)
                            ):
                                continue
                        if user and user not in str(item.get("user", "")).lower():
                            continue
                        if ip is not None and not _audit_ip_match(item, ip):
                            continue
                        # Old entries have no severity field: they count as
                        # "info" level by default.
                        if severity and str(
                            item.get("severity", DEFAULT_SEVERITY)
                        ).lower() != severity:
                            continue
                        if q:
                            # Only the values count: not the key names,
                            # otherwise ``q=event`` or ``q=user`` would match
                            # every row. We try both the raw and the
                            # normalized form, so that the underscored code
                            # and the label with spaces both match.
                            values = list(_search_values(item))
                            raw_haystack = " ".join(
                                str(value) for value in values
                            ).lower()
                            if q not in raw_haystack and (
                                not q_key
                                or q_key
                                not in " ".join(
                                    _search_key(value) for value in values
                                )
                            ):
                                continue
                        rows.append(item)
            except FileNotFoundError:
                continue
            except OSError as exc:
                self.log(f"[audit] read error ({path}): {exc}")
        rows.sort(key=lambda item: float(item.get("ts", 0)), reverse=True)
        return rows[:limit]


class ServiceCatalog:
    """The services and scenarios described by services.json.

    The catalog's ports determine which destination ports the forward
    chain opens. The file is loaded at startup; with an invalid catalog
    the portal does not start (fail-closed).
    """

    def __init__(
        self,
        services: tuple[Service, ...],
        scenarios: tuple[Scenario, ...] = (),
        source: str = "",
    ) -> None:
        self.services = {svc.id: svc for svc in services}
        self.service_order = tuple(svc.id for svc in services)
        self.scenarios = {scn.id: scn for scn in scenarios}
        self.scenario_order = tuple(scn.id for scn in scenarios)
        self.source = source
        self._tcp_ports = tuple(
            sorted({port for svc in services for port in svc.tcp})
        )
        self._udp_ports = tuple(
            sorted({port for svc in services for port in svc.udp})
        )
        self.default_scenario = next(
            (scn.id for scn in scenarios if scn.default), None
        )
        if self.default_scenario is None and scenarios:
            self.default_scenario = scenarios[0].id

    @staticmethod
    def _ports(raw, field: str, sid: str) -> tuple[int, ...]:
        if raw is None:
            return ()
        if not isinstance(raw, list):
            raise CatalogError(f"{sid}: {field} must be a list")
        ports: list[int] = []
        for value in raw:
            if isinstance(value, bool) or not isinstance(value, int):
                raise CatalogError(
                    f"{sid}: invalid port in the {field} list: {value!r}"
                )
            if not 1 <= value <= 65535:
                raise CatalogError(
                    f"{sid}: the port must be between 1 and 65535: {value}"
                )
            if value not in ports:
                ports.append(value)
        return tuple(sorted(ports))

    @classmethod
    def from_data(cls, data: dict, source: str = "") -> "ServiceCatalog":
        if not isinstance(data, dict):
            raise CatalogError("the catalog root must be a JSON object")
        raw_services = data.get("services")
        if not isinstance(raw_services, list) or not raw_services:
            raise CatalogError(
                "the catalog must contain at least one service"
            )

        services: list[Service] = []
        seen: set[str] = set()
        full_count = 0
        for item in raw_services:
            if not isinstance(item, dict):
                raise CatalogError(
                    "every service must be a JSON object"
                )
            sid = item.get("id")
            if not isinstance(sid, str) or not _SERVICE_ID_RE.match(sid):
                raise CatalogError(
                    f"invalid service identifier: {sid!r}"
                )
            if sid in seen:
                raise CatalogError(f"duplicate service identifier: {sid}")
            seen.add(sid)
            label = item.get("label", sid)
            description = item.get("description", "")
            if not isinstance(label, str) or not label.strip() or len(label) > 80:
                raise CatalogError(f"{sid}: the label must be 1–80 characters")
            if not isinstance(description, str) or len(description) > 240:
                raise CatalogError(
                    f"{sid}: the description may be at most 240 characters"
                )
            tcp = cls._ports(item.get("tcp"), "tcp", sid)
            udp = cls._ports(item.get("udp"), "udp", sid)
            icmp = item.get("icmp", False)
            full = item.get("all", False)
            if not isinstance(icmp, bool) or not isinstance(full, bool):
                raise CatalogError(
                    f"{sid}: the icmp/all field must be a boolean"
                )
            if full:
                full_count += 1
                if tcp or udp or icmp:
                    raise CatalogError(
                        f"{sid}: full access cannot have a port or icmp"
                    )
            if not (tcp or udp or icmp or full):
                raise CatalogError(
                    f"{sid}: at least one port, icmp or all is required"
                )
            services.append(
                Service(
                    sid,
                    label.strip(),
                    description.strip(),
                    tcp,
                    udp,
                    icmp,
                    full,
                )
            )
        if full_count > 1:
            raise CatalogError(
                "there may be at most one full-access service"
            )

        raw_scenarios = data.get("scenarios", [])
        if not isinstance(raw_scenarios, list):
            raise CatalogError("the scenarios field must be a list")
        scenarios: list[Scenario] = []
        scenario_ids: set[str] = set()
        default_count = 0
        for item in raw_scenarios:
            if not isinstance(item, dict):
                raise CatalogError("every scenario must be a JSON object")
            scn_id = item.get("id")
            if not isinstance(scn_id, str) or not _SERVICE_ID_RE.match(scn_id):
                raise CatalogError(
                    f"invalid scenario identifier: {scn_id!r}"
                )
            if scn_id in scenario_ids:
                raise CatalogError(
                    f"duplicate scenario identifier: {scn_id}"
                )
            scenario_ids.add(scn_id)
            label = item.get("label", scn_id)
            description = item.get("description", "")
            if not isinstance(label, str) or not label.strip() or len(label) > 80:
                raise CatalogError(
                    f"{scn_id}: the label must be 1–80 characters"
                )
            if not isinstance(description, str) or len(description) > 240:
                raise CatalogError(
                    f"{scn_id}: the description may be at most 240 characters"
                )
            raw_ids = item.get("services")
            if not isinstance(raw_ids, list) or not raw_ids:
                raise CatalogError(
                    f"{scn_id}: at least one service is required"
                )
            scn_services: list[str] = []
            for value in raw_ids:
                if not isinstance(value, str) or value not in seen:
                    raise CatalogError(
                        f"{scn_id}: unknown service: {value!r}"
                    )
                if value not in scn_services:
                    scn_services.append(value)
            ttl = item.get("default_ttl", DEFAULT_TTL)
            if isinstance(ttl, bool) or not isinstance(ttl, int):
                raise CatalogError(
                    f"{scn_id}: default_ttl must be an integer"
                )
            ttl = min(max(ttl, MIN_TTL), MAX_TTL)
            is_default = item.get("default", False)
            if not isinstance(is_default, bool):
                raise CatalogError(
                    f"{scn_id}: the default field must be a boolean"
                )
            if is_default:
                default_count += 1
            scenarios.append(
                Scenario(
                    scn_id,
                    label.strip(),
                    description.strip(),
                    tuple(scn_services),
                    ttl,
                    is_default,
                )
            )
        if default_count > 1:
            raise CatalogError(
                "there may be at most one default scenario"
            )

        return cls(tuple(services), tuple(scenarios), source)

    @classmethod
    def load(cls, path: str | None = None) -> "ServiceCatalog":
        path = path or SERVICES_PATH
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError as exc:
            raise CatalogError(
                f"missing service catalog: {path}"
            ) from exc
        except OSError as exc:
            raise CatalogError(
                f"the service catalog cannot be read: {path}: {exc}"
            ) from exc
        except ValueError as exc:
            raise CatalogError(
                f"the service catalog is not valid JSON: {path}: {exc}"
            ) from exc
        return cls.from_data(data, source=path)

    def service(self, sid: str) -> Service | None:
        return self.services.get(sid)

    def service_public(self, sid: str) -> dict | None:
        svc = self.services.get(sid)
        return svc.public() if svc is not None else None

    def public(self) -> dict:
        return {
            "services": [
                self.services[sid].public() for sid in self.service_order
            ],
            "scenarios": [
                self.scenarios[sid].public() for sid in self.scenario_order
            ],
            "default_scenario": self.default_scenario,
        }

    def resolve(self, ids) -> tuple[Service, ...]:
        """Validate and resolve the identifiers sent by the client.

        If full access is part of the selection, it includes everything
        else, so we return only that.
        """
        if not isinstance(ids, (list, tuple)):
            raise AccessError("the service list is missing")
        if len(ids) > 32:
            raise AccessError("too many services")
        chosen: list[str] = []
        for raw in ids:
            if not isinstance(raw, str):
                raise AccessError("invalid service identifier")
            sid = raw.strip()
            if sid not in self.services:
                raise AccessError(f"unknown service: {sid}")
            if sid not in chosen:
                chosen.append(sid)
        if not chosen:
            raise AccessError("select at least one service")
        full = next(
            (self.services[sid] for sid in chosen if self.services[sid].full),
            None,
        )
        if full is not None:
            return (full,)
        return tuple(self.services[sid] for sid in chosen)

    def all_services(self) -> tuple[Service, ...]:
        return tuple(self.services[sid] for sid in self.service_order)

    def all_tcp_ports(self) -> tuple[int, ...]:
        return self._tcp_ports

    def all_udp_ports(self) -> tuple[int, ...]:
        return self._udp_ports


def format_duration(seconds) -> str:
    """Human-readable English form of a duration given in seconds."""
    value = max(0, int(seconds))
    if value > 0 and value % 3600 == 0:
        count, unit = value // 3600, "hour"
    elif value % 60 == 0:
        count, unit = value // 60, "minute"
    else:
        count, unit = value, "second"
    return f"{count} {unit}" + ("" if count == 1 else "s")


def validate_ttl(raw) -> int:
    """Validation of the selected access duration (seconds)."""
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise AccessError("the access duration must be a whole number of seconds")
    if raw < MIN_TTL or raw > MAX_TTL:
        raise AccessError(
            f"the access duration must be between {format_duration(MIN_TTL)} and "
            f"{format_duration(MAX_TTL)}"
        )
    return raw


# ------------------------------------------------------------- rules/groups

class RuleStoreError(RuntimeError):
    """The rule store is invalid or not writable."""


class GroupStoreError(RuntimeError):
    """The group store is invalid or not writable."""


def _clean_text(raw, field: str, maximum: int, required: bool = True) -> str:
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ValueError(f"{field}: a string is required")
    value = raw.strip()
    if required and not value:
        raise ValueError(f"{field}: must not be empty")
    if len(value) > maximum:
        raise ValueError(f"{field}: at most {maximum} characters allowed")
    return value


def _copy_label(label: str, suffix: str = " (copy)", maximum: int = 80) -> str:
    """Copy name such that the suffix also fits within the length limit.

    The stem is truncated by the length of the suffix, so that even with a
    long source name the copy marker does not disappear and the two names
    do not become identical.
    """
    if len(label) + len(suffix) <= maximum:
        return label + suffix
    return label[: max(0, maximum - len(suffix))] + suffix


def _clean_id(raw, field: str = "identifier") -> str:
    if not isinstance(raw, str) or not _SERVICE_ID_RE.match(raw.strip()):
        raise ValueError(
            f"{field}: 1–32 characters, lowercase letter, digit, hyphen or underscore"
        )
    return raw.strip()


def _clean_str_list(raw, field: str, pattern=None, maximum: int = 64) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > maximum:
        raise ValueError(f"{field}: a list of at most {maximum} elements is required")
    out: list[str] = []
    for value in raw:
        if not isinstance(value, str):
            raise ValueError(f"{field}: invalid element")
        value = value.strip()
        if not value:
            continue
        if pattern is not None and not pattern.match(value):
            raise ValueError(f"{field}: invalid element: {value!r}")
        if value not in out:
            out.append(value)
    return tuple(out)


def _clean_rule_members(raw, field: str = "members") -> tuple[str, ...]:
    """Validation of the members of a collection rule.

    The members are individual rule identifiers; duplicates are not
    silently merged, because a mistyped rule list would otherwise change
    invisibly.
    """
    if not isinstance(raw, list):
        raise ValueError(
            f"{field}: a list of 1–64 rule identifiers is required"
        )
    values = [
        value.strip() for value in raw
        if isinstance(value, str) and value.strip()
    ]
    cleaned = _clean_str_list(
        raw, field, pattern=_SERVICE_ID_RE, maximum=64
    )
    if len(values) != len(cleaned):
        raise ValueError(f"{field}: duplicate rule identifier")
    if not 1 <= len(cleaned) <= 64:
        raise ValueError(
            f"{field}: at least 1 and at most 64 unique rules are required"
        )
    return cleaned


def _clean_rule_domains(raw, known=None) -> tuple[str, ...]:
    """Proxy entries of a domain rule: 1–64 unique full hostnames.

    When ``known`` is given (on save), the rule may reference only an
    existing entry; on load only the shape is validated.
    """
    if not isinstance(raw, list):
        raise ValueError("domains: a list of 1–64 proxy entries is required")
    cleaned = _clean_str_list(
        [value.lower() if isinstance(value, str) else value for value in raw],
        "domains", pattern=settings_store._FQDN_RE, maximum=64,
    )
    if not cleaned:
        raise ValueError("domains: select at least one proxy entry")
    if known is not None:
        missing = [name for name in cleaned if name not in known]
        if missing:
            raise ValueError(
                f"unknown proxy entry: {', '.join(missing)}"
            )
    return cleaned


def _clean_service_refs(raw, field: str = "service_refs") -> tuple[str, ...]:
    """References of a service rule: 1–64 unique ``agent/service``.

    The shape is strictly validated; existence and enabled state are
    checked by the caller (by the callback on save). On load, a missing
    reference does not discard the rule, it only yields empty resolved
    ports (fail-closed).
    """
    if not isinstance(raw, list):
        raise ValueError(
            f"{field}: a list of 1–64 service references is required"
        )
    values = [
        value.strip() for value in raw
        if isinstance(value, str) and value.strip()
    ]
    cleaned = _clean_str_list(
        raw, field, pattern=_SERVICE_REF_RE, maximum=64
    )
    if len(values) != len(cleaned):
        raise ValueError(f"{field}: duplicate service reference")
    if not 1 <= len(cleaned) <= 64:
        raise ValueError(
            f"{field}: at least 1 and at most 64 unique services are required"
        )
    return cleaned


def merge_port_intervals(values) -> list[tuple[int, int]]:
    """Contiguous intervals of ports; overlapping and adjacent parts merge."""
    merged: list[tuple[int, int]] = []
    for port in sorted(set(values)):
        if not isinstance(port, int) or isinstance(port, bool):
            continue
        if not 1 <= port <= 65535:
            continue
        if merged and port <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], port))
        else:
            merged.append((port, port))
    return merged


def format_port_interval(lo: int, hi: int, dash: str = "-") -> str:
    return str(lo) if lo == hi else f"{lo}{dash}{hi}"


def format_ports(values, dash: str = "-", separator: str = ", ") -> str:
    """Compact text form of ports; adjacent ports appear as a range."""
    return separator.join(
        format_port_interval(lo, hi, dash)
        for lo, hi in merge_port_intervals(values)
    )


def _parse_port_token(value, field: str) -> tuple[int, int]:
    """Parse a single port or a ``lo-hi`` range (both inclusive)."""
    text = value.strip().replace("–", "-").replace("—", "-")
    match = re.fullmatch(r"(\d+)(?:\s*-\s*(\d+))?", text)
    if match is None:
        raise ValueError(f"{field}: invalid port: {value!r}")
    low = int(match.group(1))
    high = int(match.group(2)) if match.group(2) else low
    if not 1 <= low <= 65535 or not 1 <= high <= 65535:
        raise ValueError(f"{field}: the port must be between 1 and 65535: {value}")
    if low > high:
        raise ValueError(
            f"{field}: the start of the range cannot be greater than its end: {value}"
        )
    return low, high


def _clean_ports(raw, field: str, maximum: int = 256) -> tuple[int, ...]:
    """Normalization of a port list.

    Accepts a JSON list (what the UI sends), a single integer, or
    comma/whitespace separated text. An element may be a single port or a
    ``lo-hi`` range. Overlapping ranges are merged, then split into unique,
    ascending ports for the internal, backward-compatible form. The limit
    applies to the number of resolved ports.
    """
    if raw is None:
        return ()
    if isinstance(raw, str):
        raw = [part for part in re.split(r"[\s,;]+", raw.strip()) if part]
    elif isinstance(raw, int) and not isinstance(raw, bool):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        raise ValueError(f"{field}: a port list is required")
    intervals: list[tuple[int, int]] = []
    for value in raw:
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
            intervals.append(_parse_port_token(value, field))
        elif isinstance(value, int) and not isinstance(value, bool):
            intervals.append(_parse_port_token(str(value), field))
        else:
            raise ValueError(f"{field}: invalid port: {value!r}")
    # Merge first, so that an overlapping list is not counted twice.
    merged: list[tuple[int, int]] = []
    for low, high in sorted(intervals):
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    total = sum(high - low + 1 for low, high in merged)
    if total > maximum:
        raise ValueError(f"{field}: at most {maximum} ports may be given")
    ports: list[int] = []
    for low, high in merged:
        ports.extend(range(low, high + 1))
    return tuple(ports)


def _clean_direction(raw) -> str:
    """The rule's direction: ``forward`` (default) or ``input``."""
    if raw is None:
        return "forward"
    if not isinstance(raw, str):
        raise ValueError("direction: must be forward or input")
    value = raw.strip()
    if not value:
        return "forward"
    if value not in ("forward", "input"):
        raise ValueError("direction: must be forward or input")
    return value


def _validate_host_ports(direction: str, ports: Ports) -> None:
    """Restrictions of a host (input) rule; forward rules are unaffected.

    A host rule may open only an explicit TCP/UDP port: full access, ICMP
    and a service list are not allowed. Only the portal's port (PORT) is
    reserved. TCP port 22 (SSH) may be opened as an ordinary host port;
    this is the only route to host SSH, therefore an administrator creates
    the rule and assigns it to the user. UDP 22 is not SSH but an ordinary
    host port.
    """
    if direction != "input":
        return
    if ports.full:
        raise ValueError("a host rule cannot have full access")
    if ports.icmp:
        raise ValueError("a host rule cannot contain ICMP")
    if not (ports.tcp or ports.udp):
        raise ValueError(
            "a host rule requires at least one TCP or UDP port"
        )
    if PORT in ports.tcp or PORT in ports.udp:
        raise ValueError(
            f"port {PORT} (portal) cannot be opened with a host rule"
        )


def _validate_host_payload(data: dict, direction: str) -> None:
    """Validation of the raw fields of a host rule before building the ports.

    Instead of the generic error message for an empty port list, here we
    give a message specific to the host rule, and reject the full/ICMP
    fields earlier than the generic ``_ports_from_payload`` does.
    """
    if direction != "input":
        return
    tcp = _clean_ports(data.get("tcp"), "tcp")
    udp = _clean_ports(data.get("udp"), "udp")
    icmp = data.get("icmp", False)
    full = data.get("full", False)
    if not isinstance(icmp, bool):
        raise ValueError("icmp: a boolean is required")
    if not isinstance(full, bool):
        raise ValueError("full: a boolean is required")
    _validate_host_ports(
        direction, Ports(tcp, udp, icmp, full, direction)
    )


def _ports_from_payload(data: dict) -> Ports:
    """Validation of the rule's port fields and construction of Ports."""
    tcp = _clean_ports(data.get("tcp"), "tcp")
    udp = _clean_ports(data.get("udp"), "udp")
    icmp = data.get("icmp", False)
    full = data.get("full", False)
    if not isinstance(icmp, bool):
        raise ValueError("icmp: a boolean is required")
    if not isinstance(full, bool):
        raise ValueError("full: a boolean is required")
    if full and (tcp or udp or icmp):
        raise ValueError(
            "full access cannot have a port or ICMP"
        )
    if not (tcp or udp or icmp or full):
        raise ValueError(
            "select at least one port, ICMP or full access"
        )
    return Ports(tcp, udp, icmp, full)


class RuleStore:
    """rules.json: access rules created by an admin.

    The rules at any time come exclusively from the file; there is no
    built-in or synthetic rule. LEGACY_ADMIN_RULE_ID is a reserved legacy
    identifier: it cannot be created or assigned, and loading filters it
    out of the file. If the file does not exist yet, the scenarios of
    services.json are created as initial rules, preserving the behaviour
    of earlier installations.
    """

    def __init__(
        self,
        path: str = RULES_PATH,
        catalog: ServiceCatalog | None = None,
        logger=log,
        domain_names=None,
        service_ports=None,
        service_domains=None,
    ) -> None:
        self.path = os.path.abspath(path)
        self.catalog = catalog if catalog is not None else ServiceCatalog.load()
        self.log = logger
        # Callback: the full hostnames of the existing proxy entries.
        # Without it a domain rule cannot be saved (fail-closed).
        self.domain_names = domain_names
        # Callback: "<agent>/<service>" -> {"tcp": (...), "udp": (...)}
        # or None if the service is missing/disabled. Without it the
        # resolved ports of a service rule are empty (fail-closed).
        self.service_ports = service_ports
        # Callback: "<agent>/<service>" -> resolved entry or None
        # (missing/disabled). The hostname of domain-mode services is
        # resolved from this; without it such a service yields no domain.
        self.service_domains = service_domains
        # The old, single proxy root: old references without a dot are
        # placed under it on load (see _resolve_bare_domains).
        self.legacy_proxy_domain = ""
        # RLock: _locked() can be nested within the same thread (for example
        # a create() called from a locked section), and _load() can also
        # re-enter.
        self._lock = threading.RLock()
        self._lock_state = threading.local()
        self._rules: dict[str, Rule] = {}
        self._loaded = False

    # -- file handling ---------------------------------------------------------

    @contextmanager
    def _locked(self):
        """Exclusive rule store lock (within the process and at file level).

        Nested calls use the same lock: only the outermost _locked() opens
        the flock, so a nested call does not block on itself. The in-process
        RLock also ensures the consistency of _load()/_rules under the file
        lock.
        """
        self._lock.acquire()
        try:
            depth = getattr(self._lock_state, "depth", 0)
            if depth:
                self._lock_state.depth = depth + 1
                try:
                    yield
                finally:
                    self._lock_state.depth -= 1
                return
            directory = os.path.dirname(self.path) or "."
            os.makedirs(directory, exist_ok=True)
            lock_path = self.path + ".lock"
            fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                self._lock_state.depth = 1
                try:
                    yield
                finally:
                    self._lock_state.depth = 0
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        finally:
            self._lock.release()

    def _read_raw(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise RuleStoreError(f"the rule store cannot be read: {exc}") from exc
        if not isinstance(data, dict):
            raise RuleStoreError("the rule store has an invalid format")
        raw_rules = data.get("rules", data)
        if not isinstance(raw_rules, dict):
            raise RuleStoreError("the rules field of the rule store is invalid")
        return raw_rules

    def _write_raw(self, data: dict) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        try:
            previous = os.stat(self.path)
        except FileNotFoundError:
            previous = None
        fd, tmp = tempfile.mkstemp(prefix=".rules-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(
                    {"rules": data}, fh, indent=2, ensure_ascii=False, sort_keys=True
                )
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            if previous is not None and (
                previous.st_uid, previous.st_gid
            ) != (os.geteuid(), os.getegid()):
                os.chown(tmp, previous.st_uid, previous.st_gid)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _quarantine(self, why: str) -> None:
        stamp = int(time.time())
        target = f"{self.path}.corrupt-{stamp}"
        try:
            os.replace(self.path, target)
            self.log(f"[rules] corrupt file set aside: {target} ({why})")
        except OSError as exc:
            self.log(f"[rules] failed to set aside the corrupt file: {exc}")

    # -- loading ---------------------------------------------------------------

    def _ports_from_services(self, services) -> Ports:
        """Convert an old, service-based rule into ports."""
        try:
            resolved = self.catalog.resolve(list(services))
        except AccessError as exc:
            raise RuleStoreError(str(exc)) from exc
        tcp: set[int] = set()
        udp: set[int] = set()
        icmp = False
        full = False
        for svc in resolved:
            tcp.update(svc.tcp)
            udp.update(svc.udp)
            icmp = icmp or svc.icmp
            full = full or svc.full
        return Ports(tuple(sorted(tcp)), tuple(sorted(udp)), icmp, full)

    @staticmethod
    def _is_legacy(item: dict) -> bool:
        return "services" in item and not any(
            key in item for key in ("tcp", "udp", "icmp", "full")
        )

    def _resolve_bare_domains(self, rule_id: str, item: dict):
        """Dotless entry names of old (pre-3.6) domain rules.

        The name is placed under the old, single root domain (true:
        deprecated). Without a root it cannot be resolved: it is logged and
        left out, the file stays unchanged.
        """
        raw = item.get("domains")
        if "members" in item or not isinstance(raw, list) or not any(
            isinstance(value, str) and value.strip() and "." not in value
            for value in raw
        ):
            return item, False
        root = self.legacy_proxy_domain
        domains = []
        for value in raw:
            if isinstance(value, str) and value.strip() and "." not in value:
                if not root:
                    self.log(
                        f"[rules] {rule_id}: proxy entry without a root "
                        f"domain cannot be resolved, left out: {value.strip()}"
                    )
                    continue
                value = f"{value.strip().lower()}.{root}"
            domains.append(value)
        return {**item, "domains": domains}, bool(root)

    def _resolve_service_ports(
        self, refs
    ) -> tuple[tuple[int, ...], tuple[int, ...]]:
        """Union of the resolved TCP/UDP listener ports of the references.

        For a missing or disabled reference the callback returns ``None``:
        that ref is skipped, but the rule is kept (fail-closed).
        """
        resolver = self.service_ports
        tcp: set[int] = set()
        udp: set[int] = set()
        if resolver is None:
            return (), ()
        for ref in refs:
            try:
                resolved = resolver(ref)
            except Exception as exc:  # a broken configuration must not open a port
                self.log(
                    f"[rules] failed to resolve service {ref}: {exc}"
                )
                continue
            if not resolved:
                continue
            tcp.update(resolved.get("tcp") or ())
            udp.update(resolved.get("udp") or ())
        return tuple(sorted(tcp)), tuple(sorted(udp))

    def _resolve_service_domains(self, refs) -> tuple[str, ...]:
        """Proxy hostnames resolved from the references.

        Only domain-mode services yield a name; the ``domain`` field is
        empty in a port service entry. For a missing or disabled reference
        the callback returns ``None``, that ref is skipped (fail-closed).
        """
        resolver = self.service_domains
        names: list[str] = []
        if resolver is None:
            return ()
        for ref in refs:
            try:
                resolved = resolver(ref)
            except Exception as exc:  # a broken configuration must not yield a domain
                self.log(
                    f"[rules] the domain of service {ref} cannot be "
                    f"resolved: {exc}"
                )
                continue
            if not resolved:
                continue
            name = str(resolved.get("domain", "") or "")
            if name and name not in names:
                names.append(name)
        return tuple(names)

    @staticmethod
    def _signature_rows(ref: str, resolved: dict) -> tuple:
        """Signature rows of one resolved reference.

        ``tunnel_service_index`` provides the full mapping in the
        ``signature`` key; for callbacks that know only ports (tests, old
        integrations) we build rows from the listener ports and the target
        host that are conservative but equally comparable at decision time.
        """
        rows = resolved.get("signature")
        if rows is not None:
            return tuple(
                (ref, str(proto), int(listen_port), str(target_host),
                 int(target_port))
                for proto, listen_port, target_host, target_port in rows
            )
        host = str(resolved.get("target_host", "") or "")
        out = []
        # Old/simple callbacks do not provide a signature; the name of a
        # domain-mode service is still taken as part of the signature, so
        # that renaming invalidates it.
        domain = str(resolved.get("domain", "") or "")
        if domain:
            out.append((ref, "domain", 0, domain, 0))
        for proto, key in (("tcp", "tcp"), ("udp", "udp")):
            for port in resolved.get(key) or ():
                port = int(port)
                out.append((ref, proto, port, host, port))
        return tuple(out)

    def _resolve_service_signature(self, refs) -> tuple:
        """The resolved, sorted mapping signature of the references.

        A missing/disabled reference is skipped; the separate
        ``service_tcp``/``service_udp`` check then fails closed separately.
        """
        resolver = self.service_ports
        rows: set[tuple] = set()
        if resolver is None:
            return ()
        for ref in refs:
            try:
                resolved = resolver(ref)
            except Exception as exc:  # a broken configuration must not open a port
                self.log(
                    f"[rules] failed to compute the signature of service "
                    f"{ref}: {exc}"
                )
                continue
            if not resolved:
                continue
            rows.update(self._signature_rows(ref, resolved))
        return tuple(sorted(rows))

    def service_signature(self, refs) -> tuple:
        """The public signature used for comparison at decision time."""
        return self._resolve_service_signature(refs)

    def _parse_rule(self, rule_id: str, item: dict) -> Rule:
        if not isinstance(item, dict):
            raise RuleStoreError(f"{rule_id}: invalid entry")
        members: tuple[str, ...] = ()
        domains: tuple[str, ...] = ()
        service_refs: tuple[str, ...] = ()
        service_tcp: tuple[int, ...] = ()
        service_udp: tuple[int, ...] = ()
        service_domains: tuple[str, ...] = ()
        service_signature: tuple = ()
        if "members" in item:
            # The stored port fields and direction of a collection rule are
            # not authoritative: the ports and directions are computed from
            # the members. Only the member list is kept in the file. A
            # possibly obsolete direction field is deliberately not
            # validated.
            try:
                members = _clean_rule_members(item.get("members"))
            except ValueError as exc:
                raise RuleStoreError(f"{rule_id}: {exc}") from exc
            ports = Ports()
            direction = "forward"
        elif "domains" in item:
            # Domain rule: the stored port fields are not authoritative.
            try:
                domains = _clean_rule_domains(item.get("domains"))
            except ValueError as exc:
                raise RuleStoreError(f"{rule_id}: {exc}") from exc
            ports = Ports()
            direction = "forward"
        elif "service_refs" in item:
            # Service rule: the stored port fields are not authoritative;
            # the ports are given by the listener ports of the referenced
            # services.
            try:
                service_refs = _clean_service_refs(item.get("service_refs"))
            except ValueError as exc:
                raise RuleStoreError(f"{rule_id}: {exc}") from exc
            service_tcp, service_udp = self._resolve_service_ports(service_refs)
            service_domains = self._resolve_service_domains(service_refs)
            service_signature = self._resolve_service_signature(service_refs)
            ports = Ports()
            direction = "forward"
        else:
            try:
                direction = _clean_direction(item.get("direction"))
            except ValueError as exc:
                raise RuleStoreError(f"{rule_id}: {exc}") from exc
            if self._is_legacy(item):
                if direction == "input":
                    raise RuleStoreError(
                        f"{rule_id}: a host rule cannot use "
                        "a service list"
                    )
                services = _clean_str_list(
                    item.get("services"), f"{rule_id}.services", maximum=32
                )
                if not services:
                    raise RuleStoreError(
                        f"{rule_id}: at least one port or service is required"
                    )
                ports = self._ports_from_services(services)
            else:
                try:
                    _validate_host_payload(item, direction)
                    ports = _ports_from_payload(item)
                except ValueError as exc:
                    raise RuleStoreError(f"{rule_id}: {exc}") from exc
        default_ttl = item.get("default_ttl", DEFAULT_TTL)
        max_ttl = item.get("max_ttl", MAX_TTL)
        if isinstance(default_ttl, bool) or not isinstance(default_ttl, int):
            raise RuleStoreError(f"{rule_id}: invalid default_ttl")
        if isinstance(max_ttl, bool) or not isinstance(max_ttl, int):
            raise RuleStoreError(f"{rule_id}: invalid max_ttl")
        if not (MIN_TTL <= default_ttl <= MAX_TTL):
            default_ttl = min(max(default_ttl, MIN_TTL), MAX_TTL)
        if not (MIN_TTL <= max_ttl <= MAX_TTL):
            max_ttl = min(max(max_ttl, MIN_TTL), MAX_TTL)
        max_ttl = max(max_ttl, default_ttl)
        return Rule(
            id=rule_id,
            label=_clean_text(item.get("label", rule_id), f"{rule_id}.label", 80),
            description=_clean_text(
                item.get("description", ""), f"{rule_id}.description", 240,
                required=False,
            ),
            tcp=ports.tcp,
            udp=ports.udp,
            icmp=ports.icmp,
            full=ports.full,
            default_ttl=default_ttl,
            max_ttl=max_ttl,
            builtin=False,
            created=int(item.get("created", 0) or 0),
            members=members,
            direction=direction,
            domains=domains,
            service_refs=service_refs,
            service_tcp=service_tcp,
            service_udp=service_udp,
            service_domains=service_domains,
            service_signature=service_signature,
        )

    @staticmethod
    def _collection_issue(
        rule: Rule, rules: dict[str, Rule]
    ) -> str:
        """The reference error of a collection rule, or an empty string.

        We allow one level of collection: the members may be existing,
        unique, non-full-access rules, but not another collection. The
        members' directions may be mixed; each member grants in its own
        direction. A service rule (service_refs) may deliberately BE a
        collection member: its resolved ports go into the forward union.
        """
        if not rule.members:
            return ""
        for member_id in rule.members:
            if member_id == rule.id:
                return "a collection rule cannot contain itself"
            if member_id == LEGACY_ADMIN_RULE_ID:
                return (
                    "this is a reserved, legacy identifier and cannot be "
                    "a member of a collection rule"
                )
            member = rules.get(member_id)
            if member is None:
                return f"unknown rule in the collection rule: {member_id}"
            if member.members:
                return (
                    "a collection rule cannot contain another "
                    f"collection rule: {member_id}"
                )
            if member.full:
                return (
                    "a collection rule cannot contain a full-access "
                    f"rule: {member_id}"
                )
        return ""

    def _seed(self) -> dict[str, Rule]:
        seeded: dict[str, Rule] = {}
        for sid in self.catalog.scenario_order:
            scn = self.catalog.scenarios[sid]
            try:
                ports = self._ports_from_services(scn.services)
            except RuleStoreError as exc:
                self.log(f"[rules] initial rule {sid} left out: {exc}")
                continue
            seeded[sid] = Rule(
                id=sid,
                label=scn.label,
                description=scn.description,
                tcp=ports.tcp,
                udp=ports.udp,
                icmp=ports.icmp,
                full=ports.full,
                default_ttl=scn.default_ttl,
                max_ttl=MAX_TTL,
                builtin=False,
                created=int(time.time()),
            )
        return seeded

    def _load(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            existed = os.path.exists(self.path)
            try:
                raw = self._read_raw()
            except RuleStoreError as exc:
                self.log(f"[rules] {exc}")
                raw = {}
                self._quarantine(str(exc))
            rules: dict[str, Rule] = {}
            legacy_found = False
            legacy_admin_found = False
            domains_migrated = False
            parse_failed = False
            seen_ids: set[str] = set()
            for raw_id, item in raw.items():
                try:
                    # Normalize the identifier BEFORE checking it against
                    # the reserved identifier: the "admin-full " /
                    # " admin-full" / "admin-full\t" variants must not get
                    # in either.
                    clean_id = _clean_id(raw_id, "rule identifier")
                except ValueError as exc:
                    parse_failed = True
                    self.log(f"[rules] invalid rule skipped: {exc}")
                    continue
                if clean_id == LEGACY_ADMIN_RULE_ID:
                    # Reserved legacy identifier (however it was written,
                    # with any whitespace): it never becomes a rule; we
                    # filter it out of the file below, without error.
                    legacy_admin_found = True
                    continue
                if clean_id in seen_ids:
                    # Two different raw keys normalized to the same
                    # identifier. We do not silently overwrite the first
                    # entry: this is as invalid a file as any other parse
                    # error, so we do not rewrite it automatically.
                    parse_failed = True
                    self.log(
                        "[rules] duplicate rule identifier skipped: "
                        f"{raw_id!r} -> {clean_id}"
                    )
                    continue
                seen_ids.add(clean_id)
                try:
                    if isinstance(item, dict) and self._is_legacy(item):
                        legacy_found = True
                    if isinstance(item, dict):
                        item, resolved = self._resolve_bare_domains(
                            clean_id, item
                        )
                        domains_migrated = domains_migrated or resolved
                    rules[clean_id] = self._parse_rule(clean_id, item)
                except (ValueError, RuleStoreError) as exc:
                    parse_failed = True
                    self.log(f"[rules] invalid rule skipped: {exc}")
            # The references of collection rules can only be checked after
            # all rules have been loaded. Invalid collections are left out;
            # thus neither the admin UI nor access sees a partial union.
            for collection_id in list(rules):
                issue = self._collection_issue(rules[collection_id], rules)
                if issue:
                    parse_failed = True
                    self.log(
                        "[rules] invalid collection rule skipped: "
                        f"{collection_id}: {issue}"
                    )
                    del rules[collection_id]
            # The resolved service ports of collections are values computed
            # from the members (not persisted). reflect_services() and the
            # re-check at decision time rely on this too.
            for collection_id, rule in list(rules.items()):
                if not rule.members:
                    continue
                tcp: set[int] = set()
                udp: set[int] = set()
                signature: set[tuple] = set()
                for member_id in rule.members:
                    member = rules.get(member_id)
                    if member is None:
                        continue
                    tcp.update(member.service_tcp)
                    udp.update(member.service_udp)
                    signature.update(member.service_signature)
                rules[collection_id] = replace(
                    rule,
                    service_tcp=tuple(sorted(tcp)),
                    service_udp=tuple(sorted(udp)),
                    service_signature=tuple(sorted(signature)),
                )
            # We seed only on the very first start (when there is no rule
            # file yet). If the admin later deletes all rules, the empty
            # file remains, and the rules do not come back to life on the
            # next start.
            if not rules and not existed:
                rules = self._seed()
                if rules:
                    try:
                        self._write_raw(
                            {rid: self._rule_storage(rule) for rid, rule in rules.items()}
                        )
                        self.log(
                            f"[rules] initial rules created: "
                            f"{', '.join(rules)}"
                        )
                    except OSError as exc:
                        self.log(f"[rules] failed to save the initial rules: {exc}")
            elif existed and not parse_failed and (
                legacy_admin_found or legacy_found or domains_migrated
            ):
                # Old file: first a 0600 backup, then write the cleaned,
                # new format. The reserved admin-full key is removed; if it
                # was the only one, the result is an empty rule store, and
                # we do not seed again.
                suffix = (
                    "admin-full-backup" if legacy_admin_found
                    else "services-backup" if legacy_found
                    else "domains-backup"
                )
                backup = f"{self.path}.{suffix}-{int(time.time())}"
                try:
                    shutil.copy2(self.path, backup)
                    os.chmod(backup, 0o600)
                    self._write_raw(
                        {rid: self._rule_storage(rule) for rid, rule in rules.items()}
                    )
                    if legacy_admin_found:
                        self.log(
                            "[rules] reserved legacy admin-full "
                            "entry removed; backup: "
                            f"{backup}"
                        )
                    if legacy_found:
                        self.log(
                            "[rules] old service-based rules converted "
                            f"to ports; backup: {backup}"
                        )
                    if domains_migrated:
                        self.log(
                            "[rules] old domain rules converted to full "
                            f"hostnames; backup: {backup}"
                        )
                except OSError as exc:
                    self.log(
                        "[rules] cleaning up the old rule file failed: "
                        f"{exc}"
                    )
            elif existed and parse_failed and (
                legacy_admin_found or legacy_found or domains_migrated
            ):
                self.log(
                    "[rules] WARNING: the old rule file contains an invalid "
                    "entry, so it is not rewritten automatically"
                )
            self._rules = rules
            self._loaded = True

    @staticmethod
    def _rule_storage(rule: Rule) -> dict:
        if rule.members:
            # For a collection the ports and the direction are also computed
            # values: we never persist them, otherwise a later change to the
            # members would yield a stale union or direction. A collection
            # has no direction of its own, so the direction field is not
            # written to the file either.
            return {
                "label": rule.label,
                "description": rule.description,
                "members": list(rule.members),
                "default_ttl": rule.default_ttl,
                "max_ttl": rule.max_ttl,
                "created": rule.created,
            }
        if rule.domains:
            return {
                "label": rule.label,
                "description": rule.description,
                "domains": list(rule.domains),
                "default_ttl": rule.default_ttl,
                "max_ttl": rule.max_ttl,
                "created": rule.created,
            }
        if rule.service_refs:
            # The resolved ports and the direction are computed values: they
            # are not written to the file, otherwise a later change to the
            # service would leave a stale grant behind.
            return {
                "label": rule.label,
                "description": rule.description,
                "service_refs": list(rule.service_refs),
                "default_ttl": rule.default_ttl,
                "max_ttl": rule.max_ttl,
                "created": rule.created,
            }
        return {
            "label": rule.label,
            "description": rule.description,
            # Individual ports remain whole numbers unchanged; ranges are
            # stored as backward-compatible "lo-hi" text.
            "tcp": [
                format_port_interval(low, high)
                if low != high else low
                for low, high in merge_port_intervals(rule.tcp)
            ],
            "udp": [
                format_port_interval(low, high)
                if low != high else low
                for low, high in merge_port_intervals(rule.udp)
            ],
            "icmp": rule.icmp,
            "full": rule.full,
            "direction": rule.direction,
            "default_ttl": rule.default_ttl,
            "max_ttl": rule.max_ttl,
            "created": rule.created,
        }

    # -- configuration bundle --------------------------------------------------

    def export_records(self) -> dict:
        """The storage form of the current rules for the configuration bundle."""
        self._load()
        with self._lock:
            return {
                rule_id: self._rule_storage(rule)
                for rule_id, rule in self._rules.items()
            }

    def validate_import_records(self, raw) -> dict[str, Rule]:
        """Strict, write-free validation of the rules section."""
        if not isinstance(raw, dict):
            raise RuleStoreError("the rules section must be a JSON object")
        rules: dict[str, Rule] = {}
        for raw_id, item in raw.items():
            if not isinstance(raw_id, str):
                raise RuleStoreError("invalid rule identifier")
            try:
                clean_id = _clean_id(raw_id, "rule identifier")
            except ValueError as exc:
                raise RuleStoreError(str(exc)) from exc
            if clean_id != raw_id:
                raise RuleStoreError(
                    f"the rule identifier is not normalized: {raw_id!r}"
                )
            if clean_id == LEGACY_ADMIN_RULE_ID:
                raise RuleStoreError(
                    "the reserved rule identifier cannot be imported"
                )
            if not isinstance(item, dict):
                raise RuleStoreError(f"{clean_id}: invalid entry")
            if self._is_legacy(item):
                raise RuleStoreError(
                    f"{clean_id}: the old service list cannot be imported"
                )
            if "members" in item and "domains" in item:
                raise RuleStoreError(
                    f"{clean_id}: members and domains cannot be present together"
                )
            if "service_refs" in item:
                mixed = [
                    key for key in ("members", "domains", "tcp", "udp",
                                    "icmp", "full")
                    if key in item
                ]
                if mixed:
                    raise RuleStoreError(
                        f"{clean_id}: service_refs cannot be combined with "
                        f"the following fields: {', '.join(mixed)}"
                    )
                # We validate only the shape: the referenced tunnels may be
                # imported in the same bundle, so existence is deliberately
                # not required here.
            rules[clean_id] = self._parse_rule(clean_id, item)
        for rule in rules.values():
            issue = self._collection_issue(rule, rules)
            if issue:
                raise RuleStoreError(f"{rule.id}: {issue}")
        return rules

    def replace_all(self, rules: dict[str, Rule]) -> None:
        """Replacement of the entire rule store (the caller has already validated)."""
        with self._locked():
            self._write_raw({
                rule_id: self._rule_storage(rule)
                for rule_id, rule in rules.items()
            })
            self._rules = dict(rules)
            self._loaded = True

    def reset(self) -> None:
        """Delete the file and clear the in-memory rule store."""
        with self._locked():
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self._rules = {}
            # Do not seed again within the process before shutdown.
            self._loaded = True

    # -- reading ---------------------------------------------------------------

    def _resolve_rule(
        self,
        rule: Rule,
        _seen: set[str] | None = None,
        _cache: dict[str, Rule] | None = None,
    ) -> Rule:
        """The resolved view of a collection rule, with per-direction grants.

        The members' ports are split by their own direction: forward
        members go into the forward sets, host (input) members into the
        input sets. The members' full access is deliberately not taken
        over: a collection can never grant full access. On a circular or
        missing reference we raise an error rather than return a partial
        grant.
        """
        if not rule.members:
            return rule
        cache = {} if _cache is None else _cache
        if rule.id in cache:
            return cache[rule.id]
        seen = set() if _seen is None else set(_seen)
        if rule.id in seen:
            raise RuleStoreError(
                f"circular collection rule reference: {rule.id}"
            )
        seen.add(rule.id)
        forward_tcp: set[int] = set()
        forward_udp: set[int] = set()
        forward_icmp = False
        input_tcp: set[int] = set()
        input_udp: set[int] = set()
        service_tcp: set[int] = set()
        service_udp: set[int] = set()
        service_signature: set[tuple] = set()
        service_refs: list[str] = []
        service_domains: list[str] = []
        domains: list[str] = []
        for member_id in rule.members:
            member = self._rules.get(member_id)
            if member is None:
                raise RuleStoreError(
                    f"missing collection rule member: {member_id}"
                )
            resolved = self._resolve_rule(member, seen, cache)
            domains.extend(
                name for name in resolved.domains if name not in domains
            )
            service_domains.extend(
                name for name in resolved.service_domains
                if name not in service_domains
            )
            service_tcp.update(resolved.service_tcp)
            service_udp.update(resolved.service_udp)
            service_signature.update(resolved.service_signature)
            service_refs.extend(
                ref for ref in resolved.service_refs
                if ref not in service_refs
            )
            for parts in resolved.grants:
                # Defence in depth: validation already excludes a
                # full-access member, but resolution must not let it
                # through either.
                if parts.full:
                    raise RuleStoreError(
                        "a collection rule cannot contain a full-"
                        f"access rule: {member_id}"
                    )
                if parts.direction == "input":
                    input_tcp.update(parts.tcp)
                    input_udp.update(parts.udp)
                else:
                    forward_tcp.update(parts.tcp)
                    forward_udp.update(parts.udp)
                    forward_icmp = forward_icmp or parts.icmp
        if forward_tcp or forward_udp or forward_icmp:
            display_direction = (
                "mixed" if (input_tcp or input_udp) else "forward"
            )
        elif input_tcp or input_udp:
            display_direction = "input"
        else:
            # Empty collection: no grant, the display direction is neutral.
            display_direction = "forward"
        resolved_rule = replace(
            rule,
            tcp=tuple(sorted(forward_tcp)),
            udp=tuple(sorted(forward_udp)),
            icmp=forward_icmp,
            full=False,
            input_tcp=tuple(sorted(input_tcp)),
            input_udp=tuple(sorted(input_udp)),
            domains=tuple(domains),
            service_refs=tuple(service_refs),
            service_tcp=tuple(sorted(service_tcp)),
            service_udp=tuple(sorted(service_udp)),
            service_domains=tuple(service_domains),
            service_signature=tuple(sorted(service_signature)),
            # "mixed" is only a display/audit value; Ports never receives
            # it, the ports property normalizes it.
            direction=display_direction,
        )
        cache[rule.id] = resolved_rule
        return resolved_rule

    def _resolved_or_none(
        self, rule: Rule, cache: dict[str, Rule] | None = None
    ) -> Rule | None:
        try:
            return self._resolve_rule(rule, _cache=cache)
        except RuleStoreError as exc:
            self.log(
                f"[rules] collection rule {rule.id} cannot be resolved: "
                f"{exc}"
            )
            return None

    def get(self, rule_id: str) -> Rule | None:
        self._load()
        rule = self._rules.get(rule_id)
        if rule is None:
            return None
        return self._resolved_or_none(rule)

    def all_rules(self) -> list[Rule]:
        self._load()
        cache: dict[str, Rule] = {}
        return [
            item for item in (
                self._resolved_or_none(rule, cache)
                for rule in self._rules.values()
            ) if item is not None
        ]

    def persisted_rules(self) -> list[Rule]:
        self._load()
        cache: dict[str, Rule] = {}
        resolved = [
            item for item in (
                self._resolved_or_none(rule, cache)
                for rule in self._rules.values()
            ) if item is not None
        ]
        return resolved

    def _can_grant_input(self, rule: Rule) -> bool:
        """Can the rule grant host (input) access?

        Old accounts without an assignment (non-admin) may inherit only
        forward rules, for backward compatibility. Host access always
        requires an explicit assignment, therefore the fallback excludes
        input-direction rules and also collections that have at least one
        input-direction member. Collections are single-level, so checking
        the direct members is enough. A domain rule (and a collection
        containing it) also requires an explicit assignment, just like a
        service rule.
        """
        if rule.direction == "input" or rule.domains or rule.service_refs:
            return True
        for member_id in rule.members:
            member = self._rules.get(member_id)
            if member is not None and (
                member.direction == "input"
                or member.domains
                or member.service_refs
            ):
                return True
        return False

    def domain_references(self) -> set[str]:
        """Full proxy hostnames referenced by the domain rules."""
        self._load()
        return {
            name for rule in self._rules.values() for name in rule.domains
        }

    def service_references(self) -> dict[str, tuple[str, ...]]:
        """Service reference -> identifiers of the rules containing it.

        It also covers collection rules: if a collection has a service
        rule as a member, the collection's identifier is also among the
        referencing rules. Thus the check before deletion/disable also
        sees indirect references.
        """
        self._load()
        mapping: dict[str, set[str]] = {}
        for rule_id, rule in self._rules.items():
            refs = set(rule.service_refs)
            for member_id in rule.members:
                member = self._rules.get(member_id)
                if member is not None:
                    refs.update(member.service_refs)
            for ref in refs:
                mapping.setdefault(ref, set()).add(rule_id)
        return {
            ref: tuple(sorted(rule_ids))
            for ref, rule_ids in mapping.items()
        }

    def reflect_services(self) -> tuple[str, ...]:
        """Recompute the resolved service ports (without writing the file).

        We call it after changing the service mapping: the resolved ports
        of service rules and of the collections containing them are
        refreshed from the callback. It returns the sorted identifiers of
        the changed rules so the caller can revoke their sessions.
        """
        self._load()
        changed: set[str] = set()
        with self._lock:
            # First the direct service rules, so that the collections
            # already compute from the fresh member values.
            for rule_id, rule in list(self._rules.items()):
                if rule.members or not rule.service_refs:
                    continue
                new_tcp, new_udp = self._resolve_service_ports(
                    rule.service_refs
                )
                new_domains = self._resolve_service_domains(
                    rule.service_refs
                )
                new_signature = self._resolve_service_signature(
                    rule.service_refs
                )
                if (new_tcp, new_udp, new_domains, new_signature) != (
                    rule.service_tcp, rule.service_udp,
                    rule.service_domains, rule.service_signature,
                ):
                    self._rules[rule_id] = replace(
                        rule, service_tcp=new_tcp, service_udp=new_udp,
                        service_domains=new_domains,
                        service_signature=new_signature,
                    )
                    changed.add(rule_id)
            for rule_id, rule in list(self._rules.items()):
                if not rule.members:
                    continue
                tcp: set[int] = set()
                udp: set[int] = set()
                domains: list[str] = []
                signature: set[tuple] = set()
                for member_id in rule.members:
                    member = self._rules.get(member_id)
                    if member is None:
                        continue
                    tcp.update(member.service_tcp)
                    udp.update(member.service_udp)
                    domains.extend(
                        name for name in member.service_domains
                        if name not in domains
                    )
                    signature.update(member.service_signature)
                new_tcp = tuple(sorted(tcp))
                new_udp = tuple(sorted(udp))
                new_domains = tuple(domains)
                new_signature = tuple(sorted(signature))
                if (new_tcp, new_udp, new_domains, new_signature) != (
                    rule.service_tcp, rule.service_udp,
                    rule.service_domains, rule.service_signature,
                ):
                    self._rules[rule_id] = replace(
                        rule, service_tcp=new_tcp, service_udp=new_udp,
                        service_domains=new_domains,
                        service_signature=new_signature,
                    )
                    changed.add(rule_id)
        return tuple(sorted(changed))

    def effective_for(self, user, groups: list[Group] | tuple[Group, ...]) -> list[Rule]:
        """The rules the user may choose from.

        Everyone, including the admin, receives only the rules assigned to
        them (directly or through a group). The admin also gets no built-in
        or synthetic rule: without an assignment they get an empty list. If
        no rule has yet been assigned to an old, non-admin user (there is
        no rules field in users.json), they get the forward-direction rules
        for backward compatibility. A host (input) rule and a collection
        containing an input member can only be obtained with an explicit
        assignment, because host access always requires an assignment. A
        new user explicitly set to empty, however, gets nothing until the
        admin assigns something.
        """
        self._load()
        if getattr(user, "pending", False):
            return []
        user_groups = [
            group for group in groups
            if user.name in group.members
        ]
        assigned: list[str] = list(getattr(user, "rules", ()))
        for group in user_groups:
            for rule_id in group.rules:
                if rule_id not in assigned:
                    assigned.append(rule_id)
        is_admin = getattr(user, "role", ROLE_USER) == ROLE_ADMIN
        cache: dict[str, Rule] = {}

        def resolved(rule_id: str) -> Rule | None:
            raw = self._rules.get(rule_id)
            if raw is None:
                return None
            return self._resolved_or_none(raw, cache)

        if is_admin:
            return [
                item for item in (resolved(rule_id) for rule_id in assigned)
                if item is not None
            ]
        if not assigned and not getattr(user, "rules_set", False):
            # Old account without an assignment: it may inherit only
            # forward rules. Host (input) access requires an explicit
            # assignment, therefore input rules and collections containing
            # an input member cannot be selected here.
            return [
                item for item in (
                    self._resolved_or_none(raw, cache)
                    for raw in self._rules.values()
                    if not self._can_grant_input(raw)
                ) if item is not None
            ]
        return [
            item for item in (resolved(rule_id) for rule_id in assigned)
            if item is not None
        ]

    def resolve_for(
        self, user, groups: list[Group] | tuple[Group, ...], rule_id
    ) -> Rule:
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise AccessError("select an access rule")
        rule = next(
            (item for item in self.effective_for(user, groups)
             if item.id == rule_id.strip()),
            None,
        )
        if rule is None:
            raise AccessError("this rule does not belong to you")
        return rule

    # -- writing ---------------------------------------------------------------

    def _validate_payload(self, data: dict, rule_id: str) -> Rule:
        if not isinstance(data, dict):
            raise RuleStoreError("invalid rule data")
        collection_flag = data.get("collection")
        if collection_flag is not None and not isinstance(collection_flag, bool):
            raise RuleStoreError("collection: a boolean is required")
        members_raw = data.get("members")
        if "members" in data and not isinstance(members_raw, list):
            raise RuleStoreError(
                "members: a list of 1–64 rule identifiers is required"
            )
        is_collection = collection_flag is True or bool(members_raw)
        members: tuple[str, ...] = ()
        domains: tuple[str, ...] = ()
        service_refs: tuple[str, ...] = ()
        service_tcp: tuple[int, ...] = ()
        service_udp: tuple[int, ...] = ()
        service_domains: tuple[str, ...] = ()
        service_signature: tuple = ()
        ports = Ports()
        if "service_refs" in data and is_collection:
            raise RuleStoreError(
                "a service rule cannot be a collection rule"
            )
        if is_collection:
            # A collection has no direction of its own: the payload's
            # direction field is deliberately ignored (and not validated).
            direction = "forward"
            tcp = _clean_ports(data.get("tcp"), "tcp")
            udp = _clean_ports(data.get("udp"), "udp")
            icmp = data.get("icmp", False)
            full = data.get("full", False)
            if not isinstance(icmp, bool):
                raise RuleStoreError("icmp: a boolean is required")
            if not isinstance(full, bool):
                raise RuleStoreError("full: a boolean is required")
            if tcp or udp or icmp or full:
                raise RuleStoreError(
                    "a collection rule cannot have a port, ICMP or "
                    "full access"
                )
            try:
                members = _clean_rule_members(members_raw)
            except ValueError as exc:
                raise RuleStoreError(str(exc)) from exc
            issue = self._collection_issue(
                Rule(
                    id=rule_id, label="", description="",
                    members=members,
                ),
                self._rules,
            )
            if issue:
                raise RuleStoreError(issue)
        elif "domains" in data:
            # Domain rule: no direction and no ports, only proxy entries.
            direction = "forward"
            if any(data.get(key) for key in ("tcp", "udp", "icmp", "full")):
                raise RuleStoreError(
                    "a domain rule cannot have a port, ICMP or "
                    "full access"
                )
            known = (
                set(self.domain_names()) if self.domain_names is not None
                else set()
            )
            try:
                domains = _clean_rule_domains(data.get("domains"), known)
            except ValueError as exc:
                raise RuleStoreError(str(exc)) from exc
        elif "service_refs" in data:
            # Service rule: exclusively the listener ports of the selected
            # tunnel services, in the forward direction.
            direction = "forward"
            mixed = [
                key for key in ("members", "domains", "tcp", "udp",
                                "icmp", "full")
                if key in data
            ]
            if mixed:
                raise RuleStoreError(
                    "a service rule cannot have "
                    f"{', '.join(mixed)}"
                )
            try:
                service_refs = _clean_service_refs(data.get("service_refs"))
            except ValueError as exc:
                raise RuleStoreError(str(exc)) from exc
            resolver = self.service_ports
            tcp: set[int] = set()
            udp: set[int] = set()
            for ref in service_refs:
                resolved = resolver(ref) if resolver is not None else None
                if resolved is None:
                    raise RuleStoreError(
                        f"unknown or disabled service: {ref}"
                    )
                tcp.update(resolved.get("tcp") or ())
                udp.update(resolved.get("udp") or ())
            # A domain-mode service has no listener port, but it opens its
            # domain through the proxy gateway; in that case the rule is
            # valid even without ports.
            service_domains = self._resolve_service_domains(service_refs)
            if not tcp and not udp and not service_domains:
                raise RuleStoreError(
                    "the selected services have no available port "
                    "or domain"
                )
            service_tcp = tuple(sorted(tcp))
            service_udp = tuple(sorted(udp))
            service_signature = self._resolve_service_signature(service_refs)
        else:
            try:
                direction = _clean_direction(data.get("direction"))
            except ValueError as exc:
                raise RuleStoreError(str(exc)) from exc
            if self._is_legacy(data):
                # Old API callers may still send service names.
                if direction == "input":
                    raise RuleStoreError(
                        "a host rule cannot use a service list"
                    )
                services = _clean_str_list(
                    data.get("services"), "services", maximum=32
                )
                if not services:
                    raise RuleStoreError("select at least one port")
                ports = self._ports_from_services(services)
            else:
                try:
                    _validate_host_payload(data, direction)
                    ports = _ports_from_payload(data)
                except ValueError as exc:
                    raise RuleStoreError(str(exc)) from exc
        default_ttl = data.get("default_ttl", DEFAULT_TTL)
        max_ttl = data.get("max_ttl", MAX_TTL)
        for name, value in (("default_ttl", default_ttl), ("max_ttl", max_ttl)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise RuleStoreError(f"{name}: a whole number of seconds is required")
            if not (MIN_TTL <= value <= MAX_TTL):
                raise RuleStoreError(
                    f"{name}: must be {format_duration(MIN_TTL)}–"
                    f"{format_duration(MAX_TTL)}"
                )
        if default_ttl > max_ttl:
            raise RuleStoreError(
                "the default duration cannot be longer than the maximum"
            )
        return Rule(
            id=rule_id,
            label=_clean_text(data.get("label", rule_id), "label", 80),
            description=_clean_text(
                data.get("description", ""), "description", 240, required=False
            ),
            tcp=ports.tcp,
            udp=ports.udp,
            icmp=ports.icmp,
            full=ports.full,
            default_ttl=default_ttl,
            max_ttl=max_ttl,
            builtin=False,
            created=int(time.time()),
            members=members,
            direction=direction,
            domains=domains,
            service_refs=service_refs,
            service_tcp=service_tcp,
            service_udp=service_udp,
            service_domains=service_domains,
            service_signature=service_signature,
        )

    def create(self, rule_id: str, data: dict) -> Rule:
        rule_id = _clean_id(rule_id, "rule identifier")
        if rule_id == LEGACY_ADMIN_RULE_ID:
            raise RuleStoreError(
                "this is a reserved, legacy identifier and cannot be used"
            )
        # Loading, existence checking, validation of the member references
        # and the commit happen under the same lock. Thus a concurrent
        # delete()/update() cannot invalidate an already validated
        # collection rule before saving.
        with self._locked():
            self._load()
            if rule_id in self._rules:
                raise RuleStoreError(f"a rule with this identifier already exists: {rule_id}")
            rule = self._validate_payload(data, rule_id)
            raw = {
                rid: self._rule_storage(item)
                for rid, item in {**self._rules, rule_id: rule}.items()
            }
            self._write_raw(raw)
            self._rules[rule_id] = rule
            return self._resolve_rule(rule)

    def _update_locked(self, rule_id: str, data: dict) -> tuple[Rule, list[str]]:
        """Modification under the _locked() held by the caller.

        Returns: (resolved rule, collections depending at the commit
        point). The dependent collections are read in the same locked
        section as the save: a collection created meanwhile is also
        included, so the session revocation cannot be skipped.
        """
        self._load()
        existing = self._rules.get(rule_id)
        if existing is None:
            raise RuleStoreError(f"no such rule: {rule_id}")
        updated = self._validate_payload(data, rule_id)
        # We read the list of parent collections at the commit point,
        # under the same lock. Since create() also holds the lock until
        # the commit, a collection that is queued up is already visible
        # here.
        parents = [
            rid for rid, item in self._rules.items()
            if rid != rule_id and rule_id in item.members
        ]
        # The member's direction may change: the collection computes the
        # grants from the members' current direction. The dependent
        # collections appear in the returned list, so the server revokes
        # their sessions too.
        if updated.members or updated.full:
            # A collection member cannot become a collection or gain full
            # access: that would make the parent collection two-level or
            # invalid. It must first be removed from the parents.
            if parents:
                raise RuleStoreError(
                    f"rule {rule_id} is a member of the following "
                    f"collection rules: {', '.join(parents)}; first "
                    "remove it from the members"
                )
        updated = replace(updated, created=existing.created)
        rules = dict(self._rules)
        rules[rule_id] = updated
        dependents = [
            rid for rid, item in rules.items()
            if rid != rule_id and rule_id in item.members
        ]
        self._write_raw(
            {rid: self._rule_storage(item) for rid, item in rules.items()}
        )
        self._rules = rules
        return self._resolve_rule(updated), dependents

    def update(self, rule_id: str, data: dict) -> Rule:
        rule_id = _clean_id(rule_id, "rule identifier")
        if rule_id == LEGACY_ADMIN_RULE_ID:
            raise RuleStoreError(
                "this is a reserved, legacy identifier and cannot be modified"
            )
        with self._locked():
            resolved, _ = self._update_locked(rule_id, data)
            return resolved

    def update_with_dependents(
        self, rule_id: str, data: dict
    ) -> tuple[Rule, list[str]]:
        """Modify a rule and the collections depending on it under one lock.

        The server must revoke the sessions of the rule itself and of the
        dependent collections as well. If we read the dependent list before
        the modification, under a separate lock, a collection created
        meanwhile could be missed, and its session would enjoy access with
        the old ports until expiry.
        """
        rule_id = _clean_id(rule_id, "rule identifier")
        if rule_id == LEGACY_ADMIN_RULE_ID:
            raise RuleStoreError(
                "this is a reserved, legacy identifier and cannot be modified"
            )
        with self._locked():
            return self._update_locked(rule_id, data)

    def duplicate(
        self,
        rule_id: str,
        new_id: str | None = None,
        label: str | None = None,
    ) -> Rule:
        """Copy an existing rule under a new identifier.

        The copy does not by itself grant access: it only enters the rule
        store, just like any new rule.
        """
        source_id = _clean_id(rule_id, "rule identifier")
        if source_id == LEGACY_ADMIN_RULE_ID:
            raise RuleStoreError(
                "this is a reserved, legacy identifier and cannot be duplicated"
            )
        self._load()
        with self._locked():
            source = self._rules.get(source_id)
            if source is None:
                raise RuleStoreError(f"no such rule: {source_id}")
            if new_id is None:
                target_id = self._unique_copy_id(source_id)
            else:
                target_id = _clean_id(new_id, "rule identifier")
                if target_id == LEGACY_ADMIN_RULE_ID:
                    raise RuleStoreError(
                        "this is a reserved, legacy identifier and cannot be used"
                    )
                if target_id in self._rules:
                    raise RuleStoreError(
                        f"a rule with this identifier already exists: {target_id}"
                    )
            # Always reserve room for the suffix: with an 80-character source
            # name, mere truncation would remove the copy marker, and the two
            # rules would have the same name.
            default_label = _copy_label(source.label)
            raw_label = label if label is not None else default_label
            # The explicit label is already sent by the caller (the UI)
            # together with the suffix, within the limit; we truncate here as
            # well for safety.
            clean_label = _clean_text(
                str(raw_label)[:80], "label", 80
            )
            copied = replace(
                source,
                id=target_id,
                label=clean_label,
                created=int(time.time()),
            )
            rules = dict(self._rules)
            rules[target_id] = copied
            self._write_raw(
                {rid: self._rule_storage(item) for rid, item in rules.items()}
            )
            self._rules = rules
            return self._resolve_rule(copied)

    def _unique_copy_id(self, source_id: str) -> str:
        def build(suffix: str) -> str:
            room = max(1, 32 - len(suffix))
            return f"{source_id[:room]}{suffix}"

        candidate = build("-copy")
        if candidate != LEGACY_ADMIN_RULE_ID and candidate not in self._rules:
            return candidate
        counter = 2
        while True:
            candidate = build(f"-{counter}")
            if candidate != LEGACY_ADMIN_RULE_ID and candidate not in self._rules:
                return candidate
            counter += 1

    def collections_containing(self, rule_id: str) -> list[str]:
        """Identifiers of the collection rules that reference it as a member."""
        self._load()
        return [
            rid for rid, item in self._rules.items()
            if rule_id in item.members
        ]

    def delete(self, rule_id: str) -> Rule:
        rule_id = _clean_id(rule_id, "rule identifier")
        if rule_id == LEGACY_ADMIN_RULE_ID:
            raise RuleStoreError(
                "this is a reserved, legacy identifier and cannot be deleted"
            )
        self._load()
        with self._locked():
            existing = self._rules.get(rule_id)
            if existing is None:
                raise RuleStoreError(f"no such rule: {rule_id}")
            parents = [
                rid for rid, item in self._rules.items()
                if rule_id in item.members
            ]
            if parents:
                raise RuleStoreError(
                    f"rule {rule_id} cannot be deleted because it is a member "
                    f"of the following collection rules: {', '.join(parents)}; "
                    "first remove it from the members"
                )
            rules = dict(self._rules)
            del rules[rule_id]
            self._write_raw(
                {rid: self._rule_storage(item) for rid, item in rules.items()}
            )
            self._rules = rules
        return existing


class GroupStore:
    """groups.json: groups, their rules and members."""

    def __init__(self, path: str = GROUPS_PATH, logger=log) -> None:
        self.path = os.path.abspath(path)
        self.log = logger
        self._lock = threading.Lock()
        self._groups: dict[str, Group] = {}
        self._loaded = False

    @contextmanager
    def _locked(self):
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        lock_path = self.path + ".lock"
        fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read_raw(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise GroupStoreError(f"the group store cannot be read: {exc}") from exc
        if not isinstance(data, dict):
            raise GroupStoreError("the group store has an invalid format")
        raw_groups = data.get("groups", data)
        if not isinstance(raw_groups, dict):
            raise GroupStoreError("the groups field of the group store is invalid")
        return raw_groups

    def _write_raw(self, data: dict) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        try:
            previous = os.stat(self.path)
        except FileNotFoundError:
            previous = None
        fd, tmp = tempfile.mkstemp(prefix=".groups-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(
                    {"groups": data}, fh, indent=2, ensure_ascii=False, sort_keys=True
                )
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            if previous is not None and (
                previous.st_uid, previous.st_gid
            ) != (os.geteuid(), os.getegid()):
                os.chown(tmp, previous.st_uid, previous.st_gid)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @staticmethod
    def _storage(group: Group) -> dict:
        return {
            "label": group.label,
            "description": group.description,
            "rules": list(group.rules),
            "members": list(group.members),
            "created": group.created,
        }

    def _parse(self, group_id: str, item: dict) -> Group:
        if not isinstance(item, dict):
            raise GroupStoreError(f"{group_id}: invalid entry")
        # We filter the reserved legacy admin-full identifier out of the
        # group's rules too, so that an old groups.json cannot grant hidden
        # access and editing the group does not get stuck on it.
        rules = tuple(
            rid for rid in _clean_str_list(
                item.get("rules"), f"{group_id}.rules", maximum=64
            )
            if rid != LEGACY_ADMIN_RULE_ID
        )
        return Group(
            id=group_id,
            label=_clean_text(item.get("label", group_id), f"{group_id}.label", 80),
            description=_clean_text(
                item.get("description", ""), f"{group_id}.description", 240,
                required=False,
            ),
            rules=rules,
            members=_clean_str_list(
                item.get("members"), f"{group_id}.members", USERNAME_RE, maximum=512
            ),
            created=int(item.get("created", 0) or 0),
        )

    def _load(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            try:
                raw = self._read_raw()
            except GroupStoreError as exc:
                self.log(f"[groups] {exc}")
                stamp = int(time.time())
                target = f"{self.path}.corrupt-{stamp}"
                try:
                    os.replace(self.path, target)
                    self.log(f"[groups] corrupt file set aside: {target}")
                except OSError:
                    pass
                raw = {}
            groups: dict[str, Group] = {}
            for group_id, item in raw.items():
                try:
                    clean_id = _clean_id(group_id, "group identifier")
                    groups[clean_id] = self._parse(clean_id, item)
                except (ValueError, GroupStoreError) as exc:
                    self.log(f"[groups] invalid group skipped: {exc}")
            self._groups = groups
            self._loaded = True

    def get(self, group_id: str) -> Group | None:
        self._load()
        return self._groups.get(group_id)

    def all_groups(self) -> list[Group]:
        self._load()
        return list(self._groups.values())

    def groups_for(self, user: str) -> list[Group]:
        self._load()
        return [group for group in self._groups.values() if user in group.members]

    def create(self, group_id: str, data: dict) -> Group:
        group_id = _clean_id(group_id, "group identifier")
        group = self._parse(group_id, {**data, "created": int(time.time())})
        self._load()
        with self._locked():
            if group_id in self._groups:
                raise GroupStoreError(f"a group with this identifier already exists: {group_id}")
            groups = dict(self._groups)
            groups[group_id] = group
            self._write_raw({gid: self._storage(item) for gid, item in groups.items()})
            self._groups = groups
        return group

    def update(self, group_id: str, data: dict) -> Group:
        group_id = _clean_id(group_id, "group identifier")
        self._load()
        with self._locked():
            existing = self._groups.get(group_id)
            if existing is None:
                raise GroupStoreError(f"no such group: {group_id}")
            updated = self._parse(group_id, {**data, "created": existing.created})
            groups = dict(self._groups)
            groups[group_id] = updated
            self._write_raw({gid: self._storage(item) for gid, item in groups.items()})
            self._groups = groups
        return updated

    def delete(self, group_id: str) -> Group:
        group_id = _clean_id(group_id, "group identifier")
        self._load()
        with self._locked():
            existing = self._groups.get(group_id)
            if existing is None:
                raise GroupStoreError(f"no such group: {group_id}")
            groups = dict(self._groups)
            del groups[group_id]
            self._write_raw({gid: self._storage(item) for gid, item in groups.items()})
            self._groups = groups
        return existing

    def set_memberships(self, user: str, group_ids) -> None:
        """Set the user's group memberships with a single write."""
        if not USERNAME_RE.match(user):
            raise GroupStoreError("invalid username")
        wanted = set(_clean_str_list(group_ids, "groups", maximum=64))
        self._load()
        with self._locked():
            known = set(self._groups)
            missing = wanted - known
            if missing:
                raise GroupStoreError(
                    f"unknown group: {', '.join(sorted(missing))}"
                )
            groups = dict(self._groups)
            changed = False
            for group_id, group in list(groups.items()):
                members = list(group.members)
                if group_id in wanted and user not in members:
                    members.append(user)
                    groups[group_id] = replace(group, members=tuple(members))
                    changed = True
                elif group_id not in wanted and user in members:
                    members.remove(user)
                    groups[group_id] = replace(group, members=tuple(members))
                    changed = True
            if changed:
                self._write_raw(
                    {gid: self._storage(item) for gid, item in groups.items()}
                )
                self._groups = groups

    def remove_member_everywhere(self, user: str) -> None:
        self._load()
        with self._locked():
            groups = dict(self._groups)
            changed = False
            for group_id, group in list(groups.items()):
                if user in group.members:
                    groups[group_id] = replace(
                        group,
                        members=tuple(name for name in group.members if name != user),
                    )
                    changed = True
            if changed:
                self._write_raw(
                    {gid: self._storage(item) for gid, item in groups.items()}
                )
                self._groups = groups

    def remove_rule_everywhere(self, rule_id: str) -> int:
        self._load()
        with self._locked():
            groups = dict(self._groups)
            changed = 0
            for group_id, group in list(groups.items()):
                if rule_id in group.rules:
                    groups[group_id] = replace(
                        group,
                        rules=tuple(rid for rid in group.rules if rid != rule_id),
                    )
                    changed += 1
            if changed:
                self._write_raw(
                    {gid: self._storage(item) for gid, item in groups.items()}
                )
                self._groups = groups
            return changed

    def set_rule_groups(
        self, rule_id: str, group_ids
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Set the rule's direct group assignments with a single write.

        For every group the rule is included exactly when it is in the
        requested set. Other rules and the groups' memberships stay
        unchanged. Returns: (added, removed) group identifiers.
        """
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise GroupStoreError("missing rule identifier")
        rule_id = rule_id.strip()
        if rule_id == LEGACY_ADMIN_RULE_ID:
            raise GroupStoreError(
                "the reserved rule identifier cannot be assigned"
            )
        wanted = set(_clean_str_list(group_ids, "groups", maximum=64))
        self._load()
        with self._locked():
            groups = dict(self._groups)
            missing = wanted - set(groups)
            if missing:
                raise GroupStoreError(
                    f"unknown group: {', '.join(sorted(missing))}"
                )
            added: list[str] = []
            removed: list[str] = []
            changed = False
            for group_id, group in list(groups.items()):
                rules = list(group.rules)
                if group_id in wanted and rule_id not in rules:
                    rules.append(rule_id)
                    groups[group_id] = replace(group, rules=tuple(rules))
                    added.append(group_id)
                    changed = True
                elif group_id not in wanted and rule_id in rules:
                    groups[group_id] = replace(
                        group,
                        rules=tuple(rid for rid in rules if rid != rule_id),
                    )
                    removed.append(group_id)
                    changed = True
            if changed:
                self._write_raw(
                    {gid: self._storage(item) for gid, item in groups.items()}
                )
                self._groups = groups
            return tuple(sorted(added)), tuple(sorted(removed))

    # -- configuration bundle --------------------------------------------------

    def export_records(self) -> dict:
        """The storage form of the current groups for the configuration bundle."""
        self._load()
        with self._lock:
            return {
                group_id: self._storage(group)
                for group_id, group in self._groups.items()
            }

    def validate_import_records(self, raw) -> dict[str, Group]:
        """Strict, write-free validation of the groups section."""
        if not isinstance(raw, dict):
            raise GroupStoreError("the groups section must be a JSON object")
        groups: dict[str, Group] = {}
        for raw_id, item in raw.items():
            if not isinstance(raw_id, str):
                raise GroupStoreError("invalid group identifier")
            try:
                clean_id = _clean_id(raw_id, "group identifier")
            except ValueError as exc:
                raise GroupStoreError(str(exc)) from exc
            if clean_id != raw_id:
                raise GroupStoreError(
                    f"the group identifier is not normalized: {raw_id!r}"
                )
            raw_rules = item.get("rules") if isinstance(item, dict) else None
            if isinstance(raw_rules, list) and LEGACY_ADMIN_RULE_ID in raw_rules:
                raise GroupStoreError(
                    f"{clean_id}: the reserved rule identifier cannot be imported"
                )
            groups[clean_id] = self._parse(clean_id, item)
        return groups

    def replace_all(self, groups: dict[str, Group]) -> None:
        """Replacement of the entire group store (the caller has already validated)."""
        with self._locked():
            self._write_raw({
                group_id: self._storage(group)
                for group_id, group in groups.items()
            })
            self._groups = dict(groups)
            self._loaded = True

    def reset(self) -> None:
        """Delete the file and clear the in-memory group store."""
        with self._locked():
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self._groups = {}
            self._loaded = True


# --------------------------------------------------------------------- firewall

class FirewallError(RuntimeError):
    """nftables could not perform the requested operation."""


class Firewall:
    """Management of the dynamic allow sets.

    The set elements have a kernel-side timeout, so access expires even if
    this process stops in the meantime.

    Full access is in the allowed_v4 set (one IP element). Port-bound
    access is in two composite sets: allowed_tcp and allowed_udp
    (IP . pre-DNAT destination port), and allowed_icmp. Host (input) rules
    go into separate sets (allowed_input_tcp and allowed_input_udp), with
    the session TTL. Host SSH is also such an ordinary TCP 22 host grant;
    there is no separate SSH set.
    """

    # Discovery of the port proxy input destination (tests override it).
    proc_net = "/proc/net"
    sysctl_conf = "/proc/sys/net/ipv4/conf"
    # The last installed port proxy rules (None: nothing yet).
    portproxy_applied: list[str] | None = None

    def __init__(
        self,
        table: str = NFT_TABLE,
        set_name: str = NFT_SET,
        binary: str = NFT_BIN,
        dry_run: bool = DRY_RUN,
        logger=log,
        lan_if: str = HV_LAN_IF,
        wan_if: str = HV_WAN_IF,
        lan_network=LAN_NETWORK,
        arp_path: str = ARP_PATH,
        fwd_mark: str = FWD_MARK,
        drop_log_group: int = droplog.DROP_LOG_GROUP,
    ) -> None:
        for name in (table, set_name):
            if not _NFT_NAME_RE.match(name):
                raise ValueError(f"invalid nftables name: {name!r}")
        fwd_mark = str(fwd_mark or "").strip().lower()
        if not re.match(r"^0x[0-9a-f]{1,8}$", fwd_mark):
            raise ValueError(f"invalid nftables mark: {fwd_mark!r}")
        if lan_if and not _LAN_IF_RE.match(lan_if):
            raise ValueError(f"invalid LAN interface: {lan_if!r}")
        if wan_if and not _LAN_IF_RE.match(wan_if):
            raise ValueError(f"invalid WAN interface: {wan_if!r}")
        self.fwd_mark = fwd_mark
        self.drop_log_group = max(1, min(65535, int(drop_log_group)))
        self.table = table
        self.set_name = set_name
        self.tcp_set = "allowed_tcp"
        self.udp_set = "allowed_udp"
        # The portal machine's own services (host/input rule): only for the
        # session's IP, until the TTL.
        self.input_tcp_set = "allowed_input_tcp"
        self.input_udp_set = "allowed_input_udp"
        # Destination ports ever declared in host (input) rules. The input
        # chain uses these to cut existing connections when the grant
        # disappears; the portal only adds, so a deleted rule cannot reopen
        # the process.
        self.service_tcp_set = "host_service_tcp"
        self.service_udp_set = "host_service_udp"
        self.icmp_set = "allowed_icmp"
        self.mac_set = "client_mac"
        self.ban_set = "banned_v4"
        # fail2ban proxy ban: closes only the host's TCP 80/443.
        self.proxy_ban_set = "proxy_banned_v4"
        self.lan_if = (lan_if or "").strip()
        self.wan_if = (wan_if or "").strip()
        self.lan_network = lan_network
        self.arp_path = arp_path
        self.mac_binding = bool(self.lan_if and self.lan_network is not None)
        self.binary = binary
        self.dry_run = dry_run
        self.log = logger
        self._lock = threading.Lock()
        # IP -> MAC recorded during the session. It can also be replenished
        # from listing the set, so this is only an acceleration and an exact
        # deletion helper.
        self._macs: dict[str, str] = {}
        # On host_service_* cleanup, log the missing/broken conntrack tool
        # only once, not on every sync.
        self._prune_conntrack_warned = False

    # -- low-level call --------------------------------------------------------

    def _run(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess:
        cmd = [self.binary, *args]
        if self.dry_run:
            self.log(f"[firewall] DRY-RUN: {' '.join(cmd)}")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=10)
        except FileNotFoundError as exc:
            raise FirewallError(f"nft not found: {self.binary}") from exc
        except PermissionError as exc:
            raise FirewallError("no permission to run nft (CAP_NET_ADMIN)") from exc
        except subprocess.TimeoutExpired as exc:
            raise FirewallError("nft did not respond in time") from exc
        if check and result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            raise FirewallError(detail or f"nft exit code: {result.returncode}")
        return result

    def _run_script(self, script: str) -> None:
        """Run an nft script on standard input.

        The element additions are handed to nft in one transaction, so no
        separate process is started for each port.
        """
        if self.dry_run:
            for line in script.splitlines():
                if line.strip():
                    self.log(f"[firewall] DRY-RUN: {line}")
            return
        try:
            result = subprocess.run(
                [self.binary, "-f", "-"],
                input=script.encode("utf-8"),
                capture_output=True,
                timeout=10,
            )
        except FileNotFoundError as exc:
            raise FirewallError(f"nft not found: {self.binary}") from exc
        except PermissionError as exc:
            raise FirewallError("no permission to run nft (CAP_NET_ADMIN)") from exc
        except subprocess.TimeoutExpired as exc:
            raise FirewallError("nft did not respond in time") from exc
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            raise FirewallError(detail or f"nft exit code: {result.returncode}")

    # -- admin customization ---------------------------------------------------

    @staticmethod
    def _port_set(ports: list[int]) -> str:
        values = [str(int(port)) for port in ports]
        if len(values) == 1:
            return values[0]
        return "{ " + ", ".join(values) + " }"

    @staticmethod
    def _custom_ports(entry: dict, kind: str) -> list[int]:
        """Valid, unique ports of a pre-auth/block entry.

        The previous ``int(port)`` conversion let invalid types through as
        ``TypeError``/``ValueError`` and converted the string ``"80"``
        character by character. Every invalid value raises
        ``FirewallError``, so the caller can reject the setting in a
        fail-closed way.
        """
        raw = entry.get("ports", [])
        if not isinstance(raw, (list, tuple)) or not raw:
            raise FirewallError(f"invalid {kind} entry")
        ports: list[int] = []
        for port in raw:
            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
            ):
                raise FirewallError(f"invalid {kind} port: {port!r}")
            if port not in ports:
                ports.append(port)
        return ports

    @staticmethod
    def _custom_dst(entry: dict, kind: str) -> str:
        """Normalized IPv4 destination; IPv6 is an error due to ``ct original ip daddr``."""
        dst = str(entry.get("dst", "")).strip()
        if not dst:
            return ""
        try:
            # strict: a destination with host bits is a typo; widening it
            # silently to the network would open more than intended.
            network = ipaddress.ip_network(dst, strict=True)
        except ValueError as exc:
            raise FirewallError(f"invalid {kind} destination: {dst}") from exc
        if network.version != 4:
            raise FirewallError(
                f"the {kind} destination can only be IPv4: {dst}"
            )
        return str(network)

    def _log_statement(self, reason: str, rate: str = "30/minute") -> str:
        """Rate-limited NFLOG log expression (for a standalone, non-dropping rule)."""
        return (
            f"limit rate {rate} burst 60 packets log prefix "
            f'"dropjak-drop reason={reason} " group {self.drop_log_group}'
        )

    def clear_custom(self) -> None:
        """Flush the pre-auth and block chains (by recreating the chains).

        It runs in a separate transaction before applying: if the new rules
        are invalid, the old pre-auth grants do not stay alive.
        """
        lines = [
            f"add chain inet {self.table} {chain}"
            for chain in CUSTOM_CHAINS
        ]
        lines.extend(
            f"flush chain inet {self.table} {chain}"
            for chain in CUSTOM_CHAINS
        )
        self._run_script("\n".join(lines) + "\n")

    def _custom_rules(
        self, preauth=(), block=(), *, include_block: bool = True,
        tunnel_public=(),
    ) -> list[str]:
        """Render the pre-auth and block rules (without executing them).

        An empty pre-auth destination applies to every destination. The
        ``forward`` direction opens from the LAN to the given
        destination/port; from the WAN only for DNAT-ed (published)
        traffic, so it does not become an open forwarder. The ``input``
        direction opens the portal machine's own ports before login,
        therefore it accepts the packet directly (no forward mark and no
        ``preauth_nat`` either). The block drops traffic originating from
        the LAN, including on TCP port 80 before the portal redirect.
        Disabled (``enabled: false``) entries are left out.

        With ``include_block=False`` the block rules are not rendered: the
        caller leaves the existing block/block_nat chains untouched. Any
        invalid entry raises ``FirewallError``, even before execution; thus
        a partial rule set cannot reach the kernel.
        """
        block = _enabled_custom_entries(block) if include_block else []
        preauth = _enabled_custom_entries(preauth)
        forward_preauth: list[dict] = []
        input_preauth: list[dict] = []
        for entry in preauth:
            # Old entries have no direction: they are forward-direction.
            direction = str(entry.get("direction") or "forward").strip()
            if direction not in ("forward", "input"):
                raise FirewallError("invalid pre-auth direction")
            if direction == "input":
                input_preauth.append(entry)
            else:
                forward_preauth.append(entry)
        if forward_preauth and not self.lan_if:
            raise FirewallError(
                "a pre-auth rule can only be applied with a known LAN interface"
            )
        # The input direction is traffic towards the host: the point is the
        # host ports reachable before login, so the WAN matters too. Without
        # a known interface the rule could not be restricted safely.
        input_ifaces: list[str] = []
        for name in (self.lan_if, self.wan_if):
            if name and name not in input_ifaces:
                input_ifaces.append(name)
        if input_preauth and not input_ifaces:
            raise FirewallError(
                "an input pre-auth rule can only be applied with a known LAN "
                "or WAN interface"
            )
        lines: list[str] = []
        # A banned source is also dropped as the first rule of the pre-auth
        # chain. In the base forward chain the banned_v4 drop already runs
        # before the pre-auth jump; this rule protects even if the chain
        # order later changes or a pre-auth entry would match an established
        # connection. The ban thus overrides every allowed/pre-auth port;
        # only the portal and DHCP remain reachable. Like the base chains it
        # matches the original direction only, so replies from a banned
        # remote host to a client's pre-auth connection still pass.
        lines.append(
            f"add rule inet {self.table} preauth "
            f"ip saddr @{self.ban_set} ct direction original drop"
        )
        # The first rule of the input pre-auth chain likewise drops the
        # banned sources, so that the ban does not open host ports either.
        lines.append(
            f"add rule inet {self.table} preauth_input "
            f"ip saddr @{self.ban_set} ct direction original drop"
        )
        for entry in block:
            proto = str(entry.get("proto", "")).strip().lower()
            if proto not in ("tcp", "udp"):
                raise FirewallError("invalid block entry")
            ports = self._custom_ports(entry, "block")
            dst = self._custom_dst(entry, "block")
            match = f"meta l4proto {proto}"
            if dst:
                match += f" ct original ip daddr {dst}"
            match += f" ct original proto-dst {self._port_set(ports)}"
            lines.append(
                f"add rule inet {self.table} block {match} "
                f"{self._log_statement('block')}"
            )
            lines.append(
                f"add rule inet {self.table} block {match} drop"
            )
            if proto == "tcp" and 80 in ports and dst:
                lines.append(
                    f"add rule inet {self.table} block_nat meta l4proto tcp "
                    f"ct original ip daddr {dst} ct original proto-dst 80 "
                    f"{self._log_statement('block')}"
                )
                lines.append(
                    f"add rule inet {self.table} block_nat meta l4proto tcp "
                    f"ct original ip daddr {dst} ct original proto-dst 80 drop"
                )
        for entry in forward_preauth:
            proto = str(entry.get("proto", "")).strip().lower()
            if proto not in ("tcp", "udp"):
                raise FirewallError("invalid pre-auth entry")
            ports = self._custom_ports(entry, "pre-auth")
            dst = self._custom_dst(entry, "pre-auth")
            match = f"meta l4proto {proto}"
            if dst:
                match += f" ct original ip daddr {dst}"
            match += f" ct original proto-dst {self._port_set(ports)}"
            # From the LAN the pre-auth opens to the given destination/port.
            # From the WAN only for DNAT-ed (published) traffic: thus the
            # rule does not become an open forwarder towards an arbitrary
            # external destination.
            interfaces = [(self.lan_if, "")]
            if self.wan_if and self.wan_if != self.lan_if:
                interfaces.append((self.wan_if, "ct status dnat "))
            for iface, extra in interfaces:
                lines.append(
                    f'add rule inet {self.table} preauth iifname "{iface}" '
                    f"{extra}{match} "
                    f"meta mark set {self.fwd_mark} accept"
                )
            lines.append(
                f"add rule inet {self.table} preauth ct state established "
                f"{match} meta mark set {self.fwd_mark} accept"
            )
            if dst:
                # We skip this for a destination-less pre-auth: without a
                # destination the related rule would let every related
                # traffic through.
                lines.append(
                    f"add rule inet {self.table} preauth ct state related "
                    f"ct original ip daddr {dst} "
                    f"meta mark set {self.fwd_mark} accept"
                )
            if proto == "tcp" and 80 in ports:
                # Prerouting redirects TCP 80 to the portal. The conntrack
                # mark makes this chain bypass the base chain's return rule;
                # the forward pre-auth rule still decides about the packet
                # separately. Without a destination this takes all LAN-side
                # HTTP out of the portal redirect.
                nat = "meta l4proto tcp"
                if dst:
                    nat += f" ct original ip daddr {dst}"
                nat += " ct original proto-dst 80"
                lines.append(
                    f"add rule inet {self.table} preauth_nat {nat} "
                    f"ct mark set {PREAUTH_CT_MARK}"
                )
        # WAN-only pre-auth accept rules for the public, port-mode tunnel
        # services. The entries come from the live settings on every apply,
        # so they disappear automatically when the service is disabled,
        # deleted or becomes private. We deliberately do not open the LAN
        # direction, and we do not insert the ``related`` rule without a
        # destination (it would let all related traffic through). The block
        # chain runs earlier in the base chain, so the ban still overrides
        # these.
        if tunnel_public and not self.wan_if:
            raise FirewallError(
                "a public tunnel service can only be applied with a known WAN "
                "interface"
            )
        for proto, port in tunnel_public:
            if proto not in ("tcp", "udp") or isinstance(port, bool) \
                    or not isinstance(port, int) or not 1 <= port <= 65535:
                raise FirewallError("invalid public tunnel port")
            match = (
                f"meta l4proto {proto} "
                f"ct original proto-dst {port}"
            )
            lines.append(
                f'add rule inet {self.table} preauth iifname "{self.wan_if}" '
                f"ct status dnat {match} "
                f"meta mark set {self.fwd_mark} accept"
            )
            lines.append(
                f"add rule inet {self.table} preauth ct state established "
                f"{match} meta mark set {self.fwd_mark} accept"
            )
        reserved_input = settings_store.preauth_reserved_input_ports()
        for entry in input_preauth:
            proto = str(entry.get("proto", "")).strip().lower()
            if proto not in ("tcp", "udp"):
                raise FirewallError("invalid pre-auth entry")
            ports = self._custom_ports(entry, "pre-auth")
            dst = self._custom_dst(entry, "pre-auth")
            # SSH, DNS, DHCP, Caddy admin and the portal port are never opened
            # before login. The settings store rejects new entries like this;
            # an entry stored by an older version is applied without them
            # (fail-closed), so it cannot stop the portal from starting.
            skipped = [port for port in ports if port in reserved_input]
            if skipped:
                self.log(
                    "[firewall] WARNING: input pre-auth "
                    f"{entry.get('id') or entry.get('label') or ''} skips "
                    "reserved host ports: "
                    + ", ".join(str(port) for port in skipped)
                )
                ports = [port for port in ports if port not in reserved_input]
                if not ports:
                    continue
            match = f"meta l4proto {proto}"
            if dst:
                match += f" ct original ip daddr {dst}"
            match += f" ct original proto-dst {self._port_set(ports)}"
            # The scope (DJ-09): "lan" (the default, also for entries stored
            # without the field) opens the host port only on the LAN
            # interface; "any" on every known interface, and keeps the
            # established accept interface-free.
            scope = str(entry.get("scope") or "lan").strip().lower()
            if scope not in settings_store.PREAUTH_SCOPES:
                raise FirewallError("invalid pre-auth scope")
            if scope == "lan":
                if not self.lan_if:
                    # Fail-closed for this entry only, like the reserved
                    # ports: the other chains must still be applied.
                    self.log(
                        "[firewall] WARNING: input pre-auth "
                        f"{entry.get('id') or entry.get('label') or ''} has "
                        "LAN scope but no LAN interface is known; skipped"
                    )
                    continue
                ifaces = [self.lan_if]
                established = f'iifname "{self.lan_if}" ct state established'
            else:
                ifaces = input_ifaces
                established = "ct state established"
            # The packet goes towards the host, so a direct accept is needed:
            # no forward mark, and the DNAT WAN condition is not applicable
            # either.
            for iface in ifaces:
                lines.append(
                    f'add rule inet {self.table} preauth_input '
                    f'iifname "{iface}" {match} accept'
                )
            # The existing connection should stay alive for the lifetime of
            # the rule as well (the host_service_* guards do not reach this
            # chain).
            lines.append(
                f"add rule inet {self.table} preauth_input "
                f"{established} {match} accept"
            )
        return lines

    def _portproxy_ifaces(self, value) -> list[str]:
        """The entry's interfaces; an unknown interface raises FirewallError."""
        wanted = {"wan": ("wan",), "lan": ("lan",), "both": ("lan", "wan")}
        if value not in wanted:
            raise FirewallError("invalid port proxy interface")
        names: list[str] = []
        for side in wanted[value]:
            name = self.lan_if if side == "lan" else self.wan_if
            if not name:
                raise FirewallError(
                    f"the port proxy can only be applied with a known "
                    f"{side.upper()} interface"
                )
            if name not in names:
                names.append(name)
        return names

    def _portproxy_loopback(self, proto: str, port: int, ifaces) -> str | None:
        """The loopback DNAT address if the destination listens only on loopback."""
        address = loopback_target(proto, port, self.proc_net)
        if address and route_localnet(ifaces, self.sysctl_conf):
            return address
        return None

    def _portproxy_input_nat(self, proto: str, port: int, ifaces) -> str:
        """Input proxy NAT: DNAT to a loopback-only destination, otherwise redirect.

        The redirect rewrites to the incoming interface's primary address
        (WAN/LAN IP); a service listening only on loopback (for example a
        Docker port published to 127.0.0.1) does not answer there, and the
        kernel sends an RST. The 127.0.0.1 DNAT requires route_localnet on
        the interfaces; the template's loopback_guard chain drops every
        other 127/8 packet arriving from outside.
        """
        address = self._portproxy_loopback(proto, port, ifaces)
        if address:
            return f"dnat ip to {address}:{port}"
        return f"redirect to :{port}"

    def portproxy_localnet_blocked(self, entries) -> list[tuple[str, int]]:
        """(protocol, listener port): loopback destination, but route_localnet is off."""
        blocked = []
        for entry in _enabled_custom_entries(entries):
            if entry.get("type") != "input":
                continue
            proto = entry.get("proto")
            try:
                ifaces = self._portproxy_ifaces(entry.get("ifaces"))
            except FirewallError:
                continue
            for p in (("tcp", "udp") if proto == "both" else (proto,)):
                if loopback_target(p, entry.get("target_port"), self.proc_net) \
                        and not route_localnet(ifaces, self.sysctl_conf):
                    blocked.append((p, entry.get("listen_port")))
        return sorted(blocked)

    def _portproxy_rules(self, entries=()) -> list[str]:
        """The rules of the port proxy chains (without executing them).

        Only traffic addressed to the host (``fib daddr type local``) is
        DNAT-ed: the proxy does not divert a LAN client's traffic to an
        external server on the same port. Forwarding permission is given by
        the forward chain's existing ``ct original`` rule (client IP .
        listener port in the allowed_tcp/udp set, with FWD_MARK); the input
        proxy is allowed by the portproxy_input chain (client IP . listener
        port in the allowed_input_* set), and there a non-allowed flow is
        dropped packet by packet, so revocation cuts the existing
        connection too. Any invalid entry raises FirewallError before
        execution.
        """
        table = self.table
        lines: list[str] = []
        for entry in _enabled_custom_entries(entries):
            proto = entry.get("proto")
            kind = entry.get("type")
            listen = entry.get("listen_port")
            target = entry.get("target_port")
            if proto not in ("tcp", "udp", "both") \
                    or kind not in ("input", "forward") or any(
                        isinstance(port, bool) or not isinstance(port, int)
                        or not 1 <= port <= 65535
                        for port in (listen, target)
                    ):
                raise FirewallError("invalid port proxy entry")
            ifaces = self._portproxy_ifaces(entry.get("ifaces"))
            iif = (
                f'iifname "{ifaces[0]}"' if len(ifaces) == 1
                else "iifname { " + ", ".join(f'"{n}"' for n in ifaces) + " }"
            )
            if kind == "forward":
                try:
                    address = ipaddress.IPv4Address(str(entry.get("target_ip")))
                except ValueError:
                    address = None
                if address is None or not any(
                    address in net for net in settings_store.PROXY_PRIVATE_NETS
                ):
                    raise FirewallError("invalid port proxy destination")
                nat = f"dnat ip to {address}:{target}"
            for p in (("tcp", "udp") if proto == "both" else (proto,)):
                if kind == "input":
                    nat = self._portproxy_input_nat(p, target, ifaces)
                lines.append(
                    f"add rule inet {table} portproxy_nat {iif} "
                    f"fib daddr type local {p} dport {listen} {nat}"
                )
                if kind == "forward":
                    if entry.get("snat"):
                        lines.append(
                            f"add rule inet {table} portproxy_snat "
                            f"meta l4proto {p} ct status dnat "
                            f"ct original proto-dst {listen} "
                            f"ip daddr {address} {p} dport {target} masquerade"
                        )
                    continue
                match = (
                    f"meta l4proto {p} ct status dnat "
                    f"ct original proto-dst {listen}"
                )
                grant = f"ip saddr . ct original proto-dst @allowed_input_{p}"
                if self.mac_binding and self.lan_if in ifaces:
                    mac = (
                        f'iifname "{self.lan_if}" {match} {grant} '
                        f"ip saddr . ether saddr != @{self.mac_set}"
                    )
                    lines.append(
                        f"add rule inet {table} portproxy_input {mac} "
                        f"{self._log_statement('mac')}"
                    )
                    lines.append(
                        f"add rule inet {table} portproxy_input {mac} drop"
                    )
                lines.append(
                    f"add rule inet {table} portproxy_input {match} {grant} "
                    "accept"
                )
                lines.append(
                    f"add rule inet {table} portproxy_input {match} "
                    f"{self._log_statement('portproxy')}"
                )
                lines.append(
                    f"add rule inet {table} portproxy_input {match} drop"
                )
        return lines

    def _tunnel_snat_rules(self, tunnels=()) -> list[str]:
        """Source masquerading of tunnel services towards dropjak0.

        We do not grant forwarding here: the synthetic entries go through
        the forward chain's existing ``ct original`` rule, so the portal
        grant is just as mandatory as with the port proxy. (Anyone who wants
        a public tunnel adds an explicit pre-auth rule.)
        """
        entries = tunnel_proxy_entries(tunnels)
        if not entries:
            return []
        lines: list[str] = []
        for entry in entries:
            address = entry.get("target_ip")
            target = entry.get("target_port")
            for proto in (
                ("tcp", "udp") if entry.get("proto") == "both"
                else (entry.get("proto"),)
            ):
                # The agent's allowed-ips is only 10.77.0.0/24, so the
                # client's source must be masqueraded to the server's
                # address, otherwise the response does not come back over
                # the tunnel.
                lines.append(
                    f"add rule inet {self.table} portproxy_snat "
                    f"meta l4proto {proto} ct status dnat "
                    f"ct original proto-dst {entry.get('listen_port')} "
                    f"ip daddr {address} {proto} dport {target} masquerade"
                )
        return lines

    def _tunnel_rules(self, tunnels=()) -> list[str]:
        """The tunnel receive rules, if there is an enabled agent.

        Besides the WireGuard UDP port, the portal's sync endpoint is also
        reachable from the tunnel; the portal's input chain would otherwise
        allow it only from the LAN and the portal network, so the agent
        could not refresh its service list.
        """
        if not isinstance(tunnels, dict):
            return []
        if not any(
            agent.get("enabled") for agent in tunnels.get("agents", [])
        ):
            return []
        if not self.wan_if:
            raise FirewallError(
                "a tunnel can only be applied with a known WAN interface"
            )
        port = tunnels.get("port")
        if isinstance(port, bool) or not isinstance(port, int) \
                or not 1 <= port <= 65535:
            raise FirewallError("invalid WireGuard port")
        return [
            f"add rule inet {self.table} {TUNNEL_CHAIN} "
            f'iifname "{self.wan_if}" '
            f"udp dport {port} accept",
            f"add rule inet {self.table} {TUNNEL_CHAIN} "
            f'iifname "{tunnel_mod.INTERFACE}" '
            f"ip saddr {settings_store.TUNNEL_SUBNET} "
            f"tcp dport {settings_store.PORTAL_PORT} accept",
        ]

    def docker_published_ports(self) -> set[tuple[str, int]]:
        """Host ports DNAT-ed (published) by Docker; on error: empty."""
        try:
            with self._lock:
                result = self._run(
                    ["list", "chain", "ip", "nat", "DOCKER"], check=False
                )
        except FirewallError:
            return set()
        if result.returncode != 0:
            return set()
        text = result.stdout.decode("utf-8", "replace")
        return {
            (proto, int(port))
            for proto, port in re.findall(r"\b(tcp|udp) dport (\d+)\b", text)
        }

    def apply_custom(self, preauth=(), block=()) -> None:
        """Install the pre-auth and block rules without flushing.

        This adds to the chains' contents; for a full, atomic replacement
        use :meth:`replace_custom`.
        """
        lines = self._custom_rules(preauth, block)
        self._run_script("\n".join(lines) + ("\n" if lines else ""))

    def replace_custom(
        self, preauth=(), block=(), *, keep_block: bool = False,
        port_proxies=(), tunnels=None,
    ) -> None:
        """Replace the pre-auth/block chains in a single nft transaction.

        Creating the chains, flushing them and installing the new rules
        happen in one ``nft -f -`` input, therefore there is no intermediate
        state in which the old block is already gone and the new one is not
        yet in effect. Rendering happens before execution; on an invalid
        entry the kernel state stays unchanged.

        With ``keep_block=True`` it replaces only the pre-auth chains: the
        block/block_nat chains stay untouched (on a broken settings file the
        last known good blocking must not disappear).

        The port proxy chains are replaced in the same transaction. The
        tunnel services are added among the port proxy rules as synthetic
        forward entries; the WireGuard UDP port goes into a separate chain.
        """
        tunnels = tunnels or {}
        synthetic = tunnel_proxy_entries(tunnels)
        proxy_rules = self._portproxy_rules(
            list(port_proxies) + synthetic
        )
        tunnel_rules = self._tunnel_rules(tunnels)
        rules = (
            self._custom_rules(
                preauth, block, include_block=not keep_block,
                tunnel_public=tunnel_public_preauth(tunnels),
            )
            + self._tunnel_snat_rules(tunnels)
            + tunnel_rules + proxy_rules
        )
        chains = (
            ("preauth", "preauth_input", "preauth_nat")
            if keep_block else CUSTOM_CHAINS
        ) + PORTPROXY_CHAINS + (TUNNEL_CHAIN,)
        lines = [
            f"add chain inet {self.table} {chain}" for chain in chains
        ]
        lines.extend(
            f"flush chain inet {self.table} {chain}" for chain in chains
        )
        lines.extend(rules)
        self._run_script("\n".join(lines) + "\n")
        self.portproxy_applied = proxy_rules

    def _delete_quiet(self, set_name: str, element: str) -> None:
        """Deleting a nonexistent element is not an error (the kernel may have expired it)."""
        result = self._run(
            ["delete", "element", "inet", self.table, set_name, "{", element, "}"],
            check=False,
        )
        if result.returncode == 0:
            return
        detail = result.stderr.decode("utf-8", "replace")
        if "No such file or directory" in detail or "does not exist" in detail:
            return
        raise FirewallError(detail.strip() or "nft deletion failed")

    def _elements(
        self, address: str, ports: Ports
    ) -> list[tuple[str, str]]:
        """(set, element) pairs for the requested ports.

        A host (input) rule opens the portal machine's own services,
        therefore it goes into a separate set; never into the
        ``allowed_tcp``/``allowed_udp`` forward sets.
        """
        direction = ports.direction
        if direction not in ("forward", "input"):
            # Internal error: no set is assigned to an unknown direction.
            raise FirewallError(
                f"invalid rule direction: {direction!r}"
            )
        if ports.full:
            if direction == "input":
                raise FirewallError(
                    "a host rule cannot have full access"
                )
            # Full access includes everything else.
            return [(self.set_name, address)]
        tcp_set = (
            self.input_tcp_set if direction == "input" else self.tcp_set
        )
        udp_set = (
            self.input_udp_set if direction == "input" else self.udp_set
        )
        elements: list[tuple[str, str]] = []
        # In an nft interval set adjacent ports are entered as one range;
        # thus an 8000-8100 rule yields a single element.
        for set_name, values in ((tcp_set, ports.tcp), (udp_set, ports.udp)):
            for low, high in merge_port_intervals(values):
                elements.append(
                    (set_name, f"{address} . {format_port_interval(low, high)}")
                )
        if ports.icmp:
            if direction == "input":
                raise FirewallError(
                    "a host rule cannot contain ICMP"
                )
            elements.append((self.icmp_set, address))
        return list(dict.fromkeys(elements))

    # -- MAC binding -----------------------------------------------------------

    def binds_mac(self, address: str) -> bool:
        """Whether a MAC binding is needed for this IP (yes for a LAN client)."""
        if not self.mac_binding:
            return False
        try:
            return ipaddress.ip_address(address) in self.lan_network
        except ValueError:
            return False

    @staticmethod
    def parse_mac_json(raw: bytes | str, address: str) -> list[str]:
        """The MACs belonging to the given IP from the ``client_mac`` set's JSON.

        Invalid or incomplete output raises ``FirewallError``, not an empty
        list: a listing error must not mean that there is no MAC binding,
        otherwise binding/unbinding would run without knowing the real
        kernel state.
        """
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise FirewallError(
                    "the output of the client_mac set is not UTF-8"
                ) from exc
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise FirewallError(
                "the output of the client_mac set is invalid JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise FirewallError(
                "the output of the client_mac set is not a JSON object"
            )
        raw_items = payload.get("nftables")
        if not isinstance(raw_items, list):
            raise FirewallError(
                "the nftables list is missing from the output of the client_mac set"
            )
        macs: list[str] = []
        for top in raw_items:
            if not isinstance(top, dict):
                continue
            item = top.get("set")
            if not isinstance(item, dict):
                continue
            raw_elements = item.get("elem") or []
            if not isinstance(raw_elements, list):
                continue
            for raw_element in raw_elements:
                if not isinstance(raw_element, dict):
                    continue
                body = raw_element.get("elem", raw_element)
                if not isinstance(body, dict):
                    continue
                value = body.get("val")
                if not isinstance(value, dict):
                    continue
                concat = value.get("concat")
                if not isinstance(concat, list) or len(concat) < 2:
                    continue
                first, second = concat[0], concat[1]
                if isinstance(first, dict):
                    first = first.get("val")
                if isinstance(second, dict):
                    second = second.get("val")
                if first != address or not isinstance(second, str):
                    continue
                mac = second.strip().lower()
                if _MAC_RE.match(mac) and mac not in macs:
                    macs.append(mac)
        return macs

    def _mac_values_locked(
        self, address: str, *, strict: bool = False
    ) -> list[str]:
        """The ``ip . mac`` elements belonging to the given IP from the kernel.

        With ``strict=True`` any listing error raises ``FirewallError`` (so
        a grant requiring a MAC binding stays fail-closed). Unbinding/cleanup
        must not be interrupted by a listing error, so there we work with
        the known in-memory values and log.
        """
        values: list[str] = []
        known = self._macs.get(address)
        if known:
            values.append(f"{address} . {known}")
        result = self._run(
            ["-j", "list", "set", "inet", self.table, self.mac_set],
            check=False,
        )
        if result.returncode != 0:
            if strict:
                detail = result.stderr.decode("utf-8", "replace").strip()
                raise FirewallError(
                    detail or "listing the client_mac set failed"
                )
            return values
        try:
            macs = self.parse_mac_json(result.stdout, address)
        except FirewallError as exc:
            if strict:
                raise
            self.log(
                f"[firewall] listing the client_mac set failed: {exc}"
            )
            return values
        for mac in macs:
            value = f"{address} . {mac}"
            if value not in values:
                values.append(value)
        return values

    def _bind_mac_locked(self, address: str, ttl: int) -> str:
        """Record the client's MAC address; if it cannot be determined, error (fail-closed)."""
        mac = arp_mac(address, self.lan_if, self.arp_path)
        if mac is None:
            raise FirewallError(
                f"the MAC address of client {address} cannot be determined "
                "from the ARP table; access cannot be granted for security reasons"
            )
        # We also delete earlier entries possibly left by hand or after a
        # crash, so that an IP belongs to only one MAC at a time.
        for value in self._mac_values_locked(address, strict=True):
            self._delete_quiet(self.mac_set, value)
        self._run_script(
            f"add element inet {self.table} {self.mac_set} "
            f"{{ {address} . {mac} timeout {ttl}s }}\n"
        )
        self._macs[address] = mac
        return mac

    def _unbind_mac_locked(self, address: str) -> None:
        """Delete a possibly remaining MAC entry belonging to the IP.

        We delete even if the IP is currently not a LAN client: the MAC
        binding's configuration or the network may have changed, and the
        old element could otherwise remain in the kernel differently until
        the TTL.
        """
        for value in self._mac_values_locked(address):
            self._delete_quiet(self.mac_set, value)
        self._macs.pop(address, None)

    def _mac_delete_elements(self, address: str) -> list[tuple[str, str]]:
        """The MAC elements of the IP to be banned; cleans up even for a non-LAN address."""
        with self._lock:
            values = self._mac_values_locked(address)
        return [(self.mac_set, value) for value in values]

    def _port_set_values_locked(self, set_name: str, address: str) -> list[str]:
        """The given IP's ``ip . port`` elements from a port set.

        Like the MAC listing, it processes the kernel's JSON output. A
        listing error must not interrupt the ban: in that case we return an
        empty list, and the other sets are still deleted.
        """
        result = self._run(
            ["-j", "list", "set", "inet", self.table, set_name],
            check=False,
        )
        if result.returncode != 0:
            return []
        try:
            entries = self.parse_set_json(result.stdout, set_name)
        except FirewallError as exc:
            self.log(
                f"[firewall] listing the {set_name} set failed: {exc}"
            )
            return []
        values: list[str] = []
        for entry in entries:
            if entry.get("address") != address:
                continue
            port = entry.get("port")
            if (
                isinstance(port, int) and not isinstance(port, bool)
                and 1 <= port <= 65535
            ):
                high = entry.get("port_end", port)
                if not isinstance(high, int) or isinstance(high, bool):
                    high = port
                values.append(
                    f"{address} . {format_port_interval(port, high)}"
                )
        return values

    def _list_port_elements_locked(
        self, set_name: str, address: str
    ) -> list[tuple[int, int, int]] | None:
        """The IP's live ``(lo, hi, remaining)`` port intervals.

        ``None`` on a listing or parsing error; the caller then falls back
        to the old, exact element deletion. A missing set is empty.
        """
        result = self._run(
            ["-j", "list", "set", "inet", self.table, set_name],
            check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace")
            if "No such file or directory" in detail or "does not exist" in detail:
                return []
            return None
        try:
            entries = self.parse_set_json(result.stdout, set_name)
        except FirewallError as exc:
            self.log(
                f"[firewall] listing the {set_name} set failed: {exc}"
            )
            return None
        intervals: list[tuple[int, int, int]] = []
        for entry in entries:
            if entry.get("address") != address:
                continue
            port = entry.get("port")
            high = entry.get("port_end", port)
            if not isinstance(port, int) or isinstance(port, bool):
                continue
            if not isinstance(high, int) or isinstance(high, bool):
                high = port
            expires = entry.get("expires_in")
            remaining = (
                int(expires)
                if isinstance(expires, int) and not isinstance(expires, bool)
                else 1
            )
            intervals.append((port, high, max(1, remaining)))
        return intervals

    def _grant_port_elements_locked(
        self,
        set_name: str,
        address: str,
        desired: list[tuple[int, int]],
        ttl: int,
    ) -> None:
        """Emit port intervals without overlap.

        We do not blindly touch the existing element: we add only the
        still-uncovered parts, and set the timeout of the overlapping
        existing element to the longer one. Thus a narrower new grant does
        not delete the larger active range and does not shorten the longer
        lifetime.
        """
        existing = self._list_port_elements_locked(set_name, address)
        if existing is None:
            # Listing error: we must not delete blindly, because that would
            # also remove a larger active range. Adding the new element is
            # safe (the kernel handles the overlapping interval); if it
            # fails, the grant reports an error, but the existing access
            # remains.
            self.log(
                f"[firewall] listing the {set_name} set failed; "
                "the existing elements remain untouched"
            )
            existing = []
        elif not existing:
            # Nothing to reconcile: the old behaviour (delete, then add)
            # restarts the timeout, and the tests also expect this.
            for low, high in desired:
                self._delete_quiet(
                    set_name, f"{address} . {format_port_interval(low, high)}"
                )
            lines = [
                f"add element inet {self.table} {set_name} "
                f"{{ {address} . {format_port_interval(low, high)} "
                f"timeout {ttl}s }}\n"
                for low, high in desired
            ]
            self._run_script("".join(lines))
            return
        # We rewrite only the overlapping elements. The uncovered parts
        # are kept with their previous, shorter timeout; the new grant
        # extends only within its own range. Thus a narrower grant does
        # not give a longer lifetime to the other ports of the larger old
        # range.
        affected = [
            (low, high, remaining)
            for low, high, remaining in existing
            if self._intervals_overlap(desired, low, high)
        ]
        if not affected:
            additions = self._merge_interval_list(desired)
            lines = [
                f"add element inet {self.table} {set_name} "
                f"{{ {address} . {format_port_interval(low, high)} "
                f"timeout {ttl}s }}\n"
                for low, high in additions
            ]
            if lines:
                self._run_script("".join(lines))
            return
        # We turn the boundaries of the affected elements and of the new
        # range into segment boundaries.
        points: set[int] = set()
        for low, high in desired:
            points.update((low, high + 1))
        for low, high, _remaining in affected:
            points.update((low, high + 1))
        ordered = sorted(points)
        segments: list[tuple[int, int, int]] = []
        for start, end in zip(ordered, ordered[1:]):
            low, high = start, end - 1
            old = max(
                (
                    remaining
                    for el_low, el_high, remaining in affected
                    if el_low <= low and high <= el_high
                ),
                default=0,
            )
            wanted = any(
                des_low <= low and high <= des_high
                for des_low, des_high in desired
            )
            if not old and not wanted:
                continue
            timeout = max(old, ttl) if wanted else old
            if timeout <= 0:
                continue
            if segments and segments[-1][1] + 1 == low \
                    and segments[-1][2] == timeout:
                segments[-1] = (segments[-1][0], high, timeout)
            else:
                segments.append((low, high, timeout))
        for low, high, _remaining in affected:
            self._delete_quiet(
                set_name, f"{address} . {format_port_interval(low, high)}"
            )
        lines = [
            f"add element inet {self.table} {set_name} "
            f"{{ {address} . {format_port_interval(low, high)} "
            f"timeout {timeout}s }}\n"
            for low, high, timeout in segments
        ]
        if lines:
            self._run_script("".join(lines))

    @staticmethod
    def _merge_interval_list(
        intervals: list[tuple[int, int]]
    ) -> list[tuple[int, int]]:
        merged: list[tuple[int, int]] = []
        for low, high in sorted(intervals):
            if merged and low <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], high))
            else:
                merged.append((low, high))
        return merged

    @staticmethod
    def _intervals_overlap(
        intervals: list[tuple[int, int]], low: int, high: int
    ) -> bool:
        return any(lo <= high and low <= hi for lo, hi in intervals)

    @staticmethod
    def _subtract_intervals(
        intervals: list[tuple[int, int]], low: int, high: int
    ) -> list[tuple[int, int]]:
        result: list[tuple[int, int]] = []
        for lo, hi in intervals:
            if high < lo or hi < low:
                result.append((lo, hi))
                continue
            if lo < low:
                result.append((lo, low - 1))
            if hi > high:
                result.append((high + 1, hi))
        return result

    def _input_delete_elements(self, address: str) -> list[tuple[str, str]]:
        """All host (input) set elements of the IP to ban."""
        elements: list[tuple[str, str]] = []
        with self._lock:
            for set_name in (self.input_tcp_set, self.input_udp_set):
                elements.extend(
                    (set_name, value)
                    for value in self._port_set_values_locked(set_name, address)
                )
        return elements

    def _forward_delete_elements(self, address: str) -> list[tuple[str, str]]:
        """All forward (``ip . port``) set elements of the IP to ban.

        We use it only if no session belongs to the IP. The portal keeps
        one session per IP, therefore the dynamic elements found in the
        kernel for this IP are our own earlier grants (possibly orphaned
        elements after a crash). The listing filters by IP, so it does not
        touch another client's elements.
        """
        elements: list[tuple[str, str]] = []
        with self._lock:
            for set_name in (self.tcp_set, self.udp_set):
                elements.extend(
                    (set_name, value)
                    for value in self._port_set_values_locked(set_name, address)
                )
        return elements

    # -- public operations -----------------------------------------------------

    def allow(self, ip: str, ttl: int) -> None:
        """Backward-compatible entry point: full access."""
        self.grant(ip, Ports(full=True), ttl)

    def grant(self, ip: str, ports: Ports, ttl: int) -> None:
        """Issue a single grant; backward-compatible wrapper."""
        self.grant_all(ip, (ports,), ttl)

    def grant_all(self, ip: str, grants, ttl: int) -> None:
        """Issue several grants, possibly in different directions, in one transaction.

        A collection rule may grant both forward and host (input) access;
        the set elements are produced per direction, then deduplicated.
        With an empty grant set there is nothing to do (and no MAC binding
        happens either).
        """
        if not is_ipv4(ip):
            raise FirewallError("only an IPv4 address can be allowed")
        address = normalize_ip(ip)
        ttl = max(1, int(ttl))
        elements = list(dict.fromkeys(
            element
            for ports in grants
            for element in self._elements(address, ports)
        ))
        if not elements:
            return
        with self._lock:
            # The MAC binding happens before the ports: if the client's MAC
            # address cannot be determined, no grant reaches the kernel.
            if self.binds_mac(address):
                self._bind_mac_locked(address, ttl)
            else:
                self._unbind_mac_locked(address)
            port_sets = {
                self.tcp_set, self.udp_set,
                self.input_tcp_set, self.input_udp_set,
            }
            grouped: dict[str, list[tuple[int, int]]] = {}
            simple: list[tuple[str, str]] = []
            for set_name, element in elements:
                if set_name in port_sets and " . " in element:
                    _address, spec = element.split(" . ", 1)
                    low, high = _parse_port_token(spec, set_name)
                    grouped.setdefault(set_name, []).append((low, high))
                else:
                    simple.append((set_name, element))
            # For full and ICMP elements, delete + add remains, because
            # they have no overlapping range.
            for set_name, element in simple:
                self._delete_quiet(set_name, element)
            if simple:
                script = "".join(
                    f"add element inet {self.table} {set_name} "
                    f"{{ {element} timeout {ttl}s }}\n"
                    for set_name, element in simple
                )
                self._run_script(script)
            for set_name, desired in grouped.items():
                self._grant_port_elements_locked(
                    set_name,
                    address,
                    self._merge_interval_list(desired),
                    ttl,
                )

    def ban(self, ip: str, ttl: int, set_name: str = "") -> None:
        """Add a source IP to the ``banned_v4`` (or the given) set.

        The ban has a kernel-side timeout. We delete before adding again,
        so extending a ban restarts the timeout.
        """
        if not is_ipv4(ip):
            raise FirewallError("only an IPv4 address can be banned")
        set_name = set_name or self.ban_set
        address = normalize_ip(ip)
        ttl = max(1, int(ttl))
        with self._lock:
            self._delete_quiet(set_name, address)
            self._run_script(
                f"add element inet {self.table} {set_name} "
                f"{{ {address} timeout {ttl}s }}\n"
            )

    def unban(self, ip: str, set_name: str = "") -> None:
        """Delete a source IP from the ``banned_v4`` (or the given) set.

        A missing element is not an error.
        """
        if not is_ipv4(ip):
            return
        self._delete_elements([(set_name or self.ban_set, normalize_ip(ip))])

    def sync_bans(self, elements, set_name: str = "") -> None:
        """Load the banned IPs and their remaining time into the set.

        We call it at startup after flushing the dynamic sets. We empty the
        set first so that the kernel and the saved record definitely agree.
        """
        set_name = set_name or self.ban_set
        lines = [f"flush set inet {self.table} {set_name}"]
        for ip, ttl in elements:
            if not is_ipv4(ip):
                continue
            lines.append(
                f"add element inet {self.table} {set_name} "
                f"{{ {normalize_ip(ip)} timeout {max(1, int(ttl))}s }}"
            )
        self._run_script("\n".join(lines) + "\n")

    # The proxy ban (TCP 80/443) works the same way, with the proxy_banned_v4 set.
    def proxy_ban(self, ip: str, ttl: int) -> None:
        self.ban(ip, ttl, self.proxy_ban_set)

    def proxy_unban(self, ip: str) -> None:
        self.unban(ip, self.proxy_ban_set)

    def sync_proxy_bans(self, elements) -> None:
        self.sync_bans(elements, self.proxy_ban_set)

    def _delete_elements(self, elements: list[tuple[str, str]]) -> None:
        """Delete elements; a nonexistent element is not an error.

        In port sets deletion is interval-aware: if a requested range only
        partially covers an existing element, we cut out the element and
        put the remaining part back with the remaining timeout. Thus a
        partial revocation does not delete the larger range of another
        active rule. On a listing error the old, exact deletion runs.
        """
        errors: list[str] = []
        port_sets = {
            self.tcp_set, self.udp_set,
            self.input_tcp_set, self.input_udp_set,
        }
        grouped: dict[tuple[str, str], list[tuple[int, int]]] = {}
        with self._lock:
            for set_name, element in elements:
                if set_name in port_sets and " . " in element:
                    address, spec = element.split(" . ", 1)
                    try:
                        low, high = _parse_port_token(spec, set_name)
                    except ValueError:
                        try:
                            self._delete_quiet(set_name, element)
                        except FirewallError as exc:
                            errors.append(str(exc))
                        continue
                    grouped.setdefault((set_name, address), []).append(
                        (low, high)
                    )
                    continue
                try:
                    self._delete_quiet(set_name, element)
                except FirewallError as exc:
                    errors.append(str(exc))
                else:
                    if set_name == self.mac_set:
                        address = element.split(" . ", 1)[0]
                        self._macs.pop(address, None)
            for (set_name, address), intervals in grouped.items():
                try:
                    self._delete_port_elements_locked(
                        set_name, address, intervals
                    )
                except FirewallError as exc:
                    errors.append(str(exc))
        if errors:
            raise FirewallError("; ".join(errors))

    def _delete_port_elements_locked(
        self,
        set_name: str,
        address: str,
        cuts: list[tuple[int, int]],
    ) -> None:
        """Delete port intervals while preserving partially covered elements."""
        existing = self._list_port_elements_locked(set_name, address)
        if existing is None or not existing:
            for low, high in self._merge_interval_list(cuts):
                self._delete_quiet(
                    set_name, f"{address} . {format_port_interval(low, high)}"
                )
            return
        merged_cuts = self._merge_interval_list(cuts)
        survivors: list[tuple[int, int, int]] = []
        for low, high, remaining in existing:
            parts = [(low, high)]
            for cut_low, cut_high in merged_cuts:
                parts = self._subtract_intervals(parts, cut_low, cut_high)
            if parts == [(low, high)]:
                continue
            self._delete_quiet(
                set_name, f"{address} . {format_port_interval(low, high)}"
            )
            for part_low, part_high in parts:
                survivors.append((part_low, part_high, remaining))
        if survivors:
            script = "".join(
                f"add element inet {self.table} {set_name} "
                f"{{ {address} . {format_port_interval(low, high)} "
                f"timeout {max(1, remaining)}s }}\n"
                for low, high, remaining in survivors
            )
            self._run_script(script)

    def revoke(self, ip: str, ports: Ports) -> None:
        if not is_ipv4(ip):
            return
        address = normalize_ip(ip)
        self._delete_elements(self._elements(address, ports))

    def deny(self, ip: str, ports: Ports | None = None) -> None:
        if not is_ipv4(ip):
            return
        address = normalize_ip(ip)
        # We always delete from the full and ICMP sets; the ports are known
        # from the given grant.
        elements: list[tuple[str, str]] = [
            (self.set_name, address),
            (self.icmp_set, address),
        ]
        if ports is not None:
            elements.extend(self._elements(address, ports))
        # A ban without ports should also delete every element from the
        # host (input) sets, not only from the forward sets.
        elements.extend(self._input_delete_elements(address))
        elements.extend(self._mac_delete_elements(address))
        self._delete_elements(list(dict.fromkeys(elements)))

    def revoke_all(
        self,
        ip: str,
        grants=(),
        discover: bool = False,
        only_grants: bool = False,
    ) -> None:
        """Revoke a client's grants.

        We always delete from the full and ICMP sets. The ports are taken
        from the given grants (Ports): rules may contain arbitrary ports,
        therefore they cannot be read out of the catalog. Callers know the
        issued grant from the session. The host TCP 22 grant is also
        deleted from the grants, from the ``allowed_input_tcp`` set.

        With ``only_grants=True`` we delete exclusively the elements
        belonging to the given grants; we do not touch the full
        (``allowed_v4``), ICMP and MAC elements. We use this when an active
        session belongs to the same IP, and only the old, non-overlapping
        grants may be removed.

        Host (input) grants are deleted from the grants (TCP 22 too, from
        the ``allowed_input_tcp`` set). With ``discover=True`` we discover
        all host and forward ``ip . port`` elements belonging to the IP,
        thus we also remove the orphaned element of an incomplete grant
        list or an earlier crash. This discovery path must only be used
        when no session belongs to the IP (because of the SessionManager's
        one-session-per-IP rule, the dynamic elements belonging to the IP
        are safely ours); normal revocation uses the exact grants.
        """
        if not is_ipv4(ip):
            return
        address = normalize_ip(ip)
        elements: list[tuple[str, str]] = []
        if not only_grants:
            elements.extend(
                [(self.set_name, address), (self.icmp_set, address)]
            )
        for ports in grants:
            elements.extend(self._elements(address, ports))
        if discover:
            elements.extend(self._input_delete_elements(address))
            elements.extend(self._forward_delete_elements(address))
        if not only_grants:
            elements.extend(self._mac_delete_elements(address))
        self._delete_elements(list(dict.fromkeys(elements)))

    def revoke_exact(self, ip: str, grants) -> None:
        """Delete exactly the elements belonging to the given grants.

        ``revoke_all(..., only_grants=True)`` deletes only the port and
        ICMP elements; this operation also removes the ``allowed_v4``
        element belonging to the ``full`` grant if the grant contains it.
        It never touches the MAC binding, because a still active session
        belonging to the same IP may need it. For a non-IPv4 address there
        is nothing to do.
        """
        if not is_ipv4(ip):
            return
        address = normalize_ip(ip)
        elements = list(dict.fromkeys(
            element
            for ports in grants
            for element in self._elements(address, ports)
        ))
        if not elements:
            return
        self._delete_elements(elements)

    def sync_host_ports(self, tcp_ports, udp_ports) -> None:
        """Load the ports of the host (input) rules into the kernel.

        The ``host_service_tcp``/``host_service_udp`` sets contain every
        host port ever declared; the input chain uses them to cut existing
        connections when the grant disappears. Normal sync only adds,
        never flushes: thus deleting a rule cannot reopen an already
        existing connection. Stale ports are harmless, because they only
        make the check of established traffic stricter; the unnecessary
        ones are removed by a separate, safe cleanup
        (:meth:`prune_host_service_ports`), only a port without a
        reference and live conntrack.
        """
        def clean(values) -> list[int]:
            ports: list[int] = []
            for value in values or ():
                if isinstance(value, bool) or not isinstance(value, int):
                    continue
                if not 1 <= value <= 65535:
                    continue
                if value not in ports:
                    ports.append(value)
            return sorted(ports)

        tcp = clean(tcp_ports)
        udp = clean(udp_ports)
        if not tcp and not udp:
            return
        desired = {
            self.service_tcp_set: merge_port_intervals(tcp),
            self.service_udp_set: merge_port_intervals(udp),
        }
        with self._lock:
            lines: list[str] = []
            for set_name, intervals in desired.items():
                if not intervals:
                    continue
                # In an interval set overlapping additions raise an error,
                # so we add only the still-uncovered parts.
                existing = self._list_service_ranges_locked(set_name)
                additions = list(intervals)
                if existing is not None:
                    for low, high in existing:
                        additions = self._subtract_intervals(
                            additions, low, high
                        )
                additions = self._merge_interval_list(additions)
                if additions:
                    lines.append(
                        f"add element inet {self.table} {set_name} "
                        f"{{ {', '.join(format_port_interval(low, high) for low, high in additions)} }}"
                    )
            if lines:
                self._run_script("\n".join(lines) + "\n")

    @staticmethod
    def _service_interval(raw_element) -> tuple[int, int] | None:
        """The ``(lo, hi)`` pair of an ``inet_service`` set element."""
        value = raw_element
        for _unused in range(3):
            if not isinstance(value, dict):
                break
            if isinstance(value.get("range"), list):
                pair = value["range"]
                if (
                    len(pair) == 2
                    and all(
                        isinstance(item, int) and not isinstance(item, bool)
                        for item in pair
                    )
                ):
                    low, high = pair
                    if 1 <= low <= high <= 65535:
                        return low, high
                return None
            if "elem" in value:
                value = value["elem"]
            elif "val" in value:
                value = value["val"]
            else:
                return None
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            port = value
        elif isinstance(value, str):
            text = value.strip()
            if not text.isdigit():
                return None
            port = int(text)
        else:
            return None
        return (port, port) if 1 <= port <= 65535 else None

    @staticmethod
    def parse_service_set_json(raw: bytes | str, set_name: str) -> set[int]:
        """Read the ports of an ``inet_service`` set (host_service_*).

        :meth:`parse_set_json` recognises only ``ipv4_addr`` and
        ``ipv4_addr . inet_service`` elements, therefore plain port numbers
        are processed separately. Unparseable elements are silently
        skipped: during cleanup we never delete just because we do not
        understand an element of a foreign format.
        """
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise FirewallError(
                    f"the output of the {set_name} set is not UTF-8"
                ) from exc
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise FirewallError(
                f"the JSON output of the {set_name} set is invalid: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise FirewallError(f"the output of the {set_name} set is invalid")
        ports: set[int] = set()
        for top in payload.get("nftables", []):
            if not isinstance(top, dict):
                continue
            item = top.get("set")
            if not isinstance(item, dict):
                continue
            if item.get("name") not in (None, set_name):
                continue
            raw_elements = item.get("elem") or []
            if not isinstance(raw_elements, list):
                continue
            for raw_element in raw_elements:
                interval = Firewall._service_interval(raw_element)
                if interval is not None:
                    ports.update(range(interval[0], interval[1] + 1))
        return ports

    @staticmethod
    def parse_service_set_intervals_json(
        raw: bytes | str, set_name: str
    ) -> list[tuple[int, int]]:
        """The intervals of an ``inet_service`` set, merged."""
        ports = Firewall.parse_service_set_json(raw, set_name)
        return Firewall._merge_interval_list(
            [(port, port) for port in sorted(ports)]
        )

    def _list_service_ports_locked(self, set_name: str) -> set[int] | None:
        """The elements of the host_service_* set; ``None`` on a listing error.

        A missing table/set counts as an empty set (it also works before
        installation). Every other error is ``None``: the caller then does
        not delete.
        """
        try:
            result = self._run(
                ["-j", "list", "set", "inet", self.table, set_name],
                check=False,
            )
        except FirewallError as exc:
            # Missing nft, permission or timeout: we do not delete.
            self.log(
                f"[firewall] listing the {set_name} set failed: "
                f"{exc}"
            )
            return None
        detail = result.stderr.decode("utf-8", "replace").strip()
        if result.returncode != 0:
            if (
                "No such file or directory" in detail
                or "does not exist" in detail
            ):
                return set()
            self.log(
                f"[firewall] listing the {set_name} set failed: "
                f"{detail or result.returncode}"
            )
            return None
        try:
            return self.parse_service_set_json(result.stdout, set_name)
        except FirewallError as exc:
            self.log(
                f"[firewall] the output of the {set_name} set is not parseable: "
                f"{exc}"
            )
            return None

    def _list_service_ranges_locked(
        self, set_name: str
    ) -> list[tuple[int, int]] | None:
        """The intervals of the host_service_* set; ``None`` on error."""
        try:
            result = self._run(
                ["-j", "list", "set", "inet", self.table, set_name],
                check=False,
            )
        except FirewallError as exc:
            self.log(
                f"[firewall] listing the {set_name} set failed: "
                f"{exc}"
            )
            return None
        detail = result.stderr.decode("utf-8", "replace").strip()
        if result.returncode != 0:
            if (
                "No such file or directory" in detail
                or "does not exist" in detail
            ):
                return []
            self.log(
                f"[firewall] listing the {set_name} set failed: "
                f"{detail or result.returncode}"
            )
            return None
        try:
            return self.parse_service_set_intervals_json(
                result.stdout, set_name
            )
        except FirewallError as exc:
            self.log(
                f"[firewall] the output of the {set_name} set is not parseable: "
                f"{exc}"
            )
            return None

    def _warn_prune_conntrack(self, reason: str) -> None:
        """Log the absence/failure of conntrack only once."""
        if self._prune_conntrack_warned:
            return
        self._prune_conntrack_warned = True
        self.log(f"[firewall] host port pruning skipped: {reason}")

    def _live_conntrack_ports(self, candidates: set[int]) -> set[int] | None:
        """Among the candidates, the ports present in live conntrack entries.

        ``None`` means that conntrack cannot be listed, so the caller must
        not delete any port. The search is deliberately conservative: any
        ``dport=<port>`` or ``sport=<port>`` match keeps the port, whether
        it appears on the client or the host side.
        """
        if not CONNTRACK_BIN:
            self._warn_prune_conntrack("the conntrack tool is not available")
            return None
        try:
            result = subprocess.run(
                [CONNTRACK_BIN, "-L"], capture_output=True, timeout=10
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._warn_prune_conntrack(
                f"listing conntrack failed: {exc}"
            )
            return None
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            self._warn_prune_conntrack(
                "listing conntrack returned an error code "
                f"({result.returncode}): {detail}".strip()
            )
            return None
        self._prune_conntrack_warned = False
        text = result.stdout.decode("utf-8", "replace")
        live: set[int] = set()
        for port in candidates:
            if re.search(rf"\b(?:dport|sport)={port}\b", text):
                live.add(port)
        return live

    def _delete_service_ports_locked(
        self, set_name: str, ports: set[int]
    ) -> tuple[list[int], list[str]]:
        """Delete ports from the set; an element already gone is not an error."""
        if not ports:
            return [], []
        ordered = sorted(ports)
        body = ", ".join(str(port) for port in ordered)
        try:
            self._run_script(
                f"delete element inet {self.table} {set_name} {{ {body} }}\n"
            )
            return ordered, []
        except FirewallError as exc:
            detail = str(exc)
            # We tolerate only elements that disappeared in the meantime,
            # one by one; on a persistent nft error we do not start
            # thousands of separate processes.
            if not (
                "No such file or directory" in detail
                or "does not exist" in detail
            ):
                return [], [detail]
        removed: list[int] = []
        errors: list[str] = []
        for port in ordered:
            try:
                self._delete_quiet(set_name, str(port))
            except FirewallError as exc:
                errors.append(f"{port}: {exc}")
            else:
                removed.append(port)
        return removed, errors

    def _audit_prune(self, audit, reason: str) -> None:
        if audit is None:
            return
        try:
            audit.write(
                "firewall_error",
                operation="host_ports_prune",
                reason=str(reason),
            )
        except Exception as exc:  # logging should never block
            self.log(
                f"[audit] writing host_ports_prune failed: {exc}"
            )

    def prune_host_service_ports(
        self, referenced_tcp, referenced_udp, audit=None
    ) -> dict:
        """Safe cleanup of the host_service_* sets.

        We delete a port only if (a) no persisted rule references it (a
        port of any direction or collection member protects it), and (b)
        there is no live conntrack entry for it. If the conntrack tool is
        missing or cannot be listed, we delete no port at all: the
        remaining guards only make the check stricter. We do the same if
        listing the nft set fails; a cleanup failure must never block
        granting.

        Normal sync remains add-only; this is the only path that deletes,
        with the two conditions above. At startup the sets are deliberately
        not flushed, so that the old flows of deleted ports remain cut off.
        Because of the 65536 set size, the number of ports can be at most
        65535, so the set cannot overflow.
        """
        summary = {
            "dry_run": bool(self.dry_run),
            "removed_tcp": [],
            "removed_udp": [],
            "live_kept": [],
            "errors": [],
            "skipped": None,
        }
        if self.dry_run:
            return summary
        ref_tcp = {int(port) for port in referenced_tcp or ()}
        ref_udp = {int(port) for port in referenced_udp or ()}
        with self._lock:
            ranges_tcp = self._list_service_ranges_locked(
                self.service_tcp_set
            )
            ranges_udp = self._list_service_ranges_locked(
                self.service_udp_set
            )
            if ranges_tcp is None or ranges_udp is None:
                reason = (
                    "listing the host_service_* sets failed, "
                    "cleanup skipped"
                )
                summary["errors"].append(reason)
                self.log(f"[firewall] {reason}")
                self._audit_prune(audit, reason)
                return summary
            # We clean up only single-port elements: partially deleting a
            # range would remove the whole element, so those remain safely
            # in place (this only makes the check stricter, it does not open
            # access).
            members_tcp = {low for low, high in ranges_tcp if low == high}
            members_udp = {low for low, high in ranges_udp if low == high}
            candidates_tcp = members_tcp - ref_tcp
            candidates_udp = members_udp - ref_udp
            candidates = candidates_tcp | candidates_udp
            if not candidates:
                return summary
            # Listing conntrack runs under the firewall lock, so that a
            # parallel grant cannot slip between the decision and the
            # deletion.
            live = self._live_conntrack_ports(candidates)
            if live is None:
                # No conntrack information: no candidate may be deleted.
                summary["skipped"] = "conntrack"
                return summary
            summary["live_kept"] = sorted(candidates & live)
            removed_tcp, errors_tcp = self._delete_service_ports_locked(
                self.service_tcp_set, candidates_tcp - live
            )
            removed_udp, errors_udp = self._delete_service_ports_locked(
                self.service_udp_set, candidates_udp - live
            )
            summary["removed_tcp"] = removed_tcp
            summary["removed_udp"] = removed_udp
            summary["errors"].extend(errors_tcp + errors_udp)
            if summary["errors"]:
                reason = "; ".join(summary["errors"])
                self.log(
                    "[firewall] host port cleanup partially failed: "
                    f"{reason}"
                )
                self._audit_prune(audit, reason)
        if summary["removed_tcp"] or summary["removed_udp"]:
            self.log(
                "[firewall] host port guards cleaned up: "
                f"TCP {summary['removed_tcp']}, UDP {summary['removed_udp']}; "
                f"kept because of live conntrack: {summary['live_kept']}"
            )
        return summary

    def flush(self) -> None:
        errors: list[str] = []
        with self._lock:
            for set_name in (
                self.set_name, self.tcp_set, self.udp_set,
                self.input_tcp_set, self.input_udp_set, self.icmp_set,
                self.mac_set, self.ban_set, self.proxy_ban_set,
            ):
                result = self._run(
                    ["flush", "set", "inet", self.table, set_name],
                    check=False,
                )
                if result.returncode == 0:
                    continue
                detail = result.stderr.decode("utf-8", "replace")
                if "No such file or directory" in detail or "does not exist" in detail:
                    continue
                errors.append(
                    detail.strip() or f"flushing the {set_name} set failed"
                )
            if not errors:
                self._macs.clear()
        if errors:
            raise FirewallError("; ".join(errors))

    @staticmethod
    def parse_set_json(raw: bytes | str, set_name: str) -> list[dict]:
        """Process the output of ``nft -j list set``.

        In nft JSON an element with a timeout looks like this::

            {"elem": {"val": {"concat": ["192.0.2.5", 80]},
                      "timeout": 90, "expires": 89}}

        The time values are in seconds. ``timeout`` is the original
        lifetime, ``expires`` is the remaining time. The returned list's
        elements are ``{"address", "port", "expires_in", "timeout"}``; the
        port is present only for composite (IP . port) sets.
        """
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise FirewallError(
                    f"the output of the {set_name} set is not UTF-8"
                ) from exc
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise FirewallError(
                f"the JSON output of the {set_name} set is invalid: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise FirewallError(f"the output of the {set_name} set is invalid")
        entries: list[dict] = []
        for top in payload.get("nftables", []):
            if not isinstance(top, dict):
                continue
            item = top.get("set")
            if not isinstance(item, dict):
                continue
            if item.get("name") not in (None, set_name):
                continue
            raw_elements = item.get("elem") or []
            if not isinstance(raw_elements, list):
                continue
            for raw_element in raw_elements:
                entry = Firewall._parse_set_element(raw_element)
                if entry is not None:
                    entries.append(entry)
        entries.sort(
            key=lambda entry: (
                entry["address"],
                entry.get("port") or 0,
            )
        )
        return entries

    @staticmethod
    def _parse_set_element(raw_element) -> dict | None:
        if not isinstance(raw_element, dict):
            return None
        body = raw_element.get("elem", raw_element)
        if not isinstance(body, dict):
            return None
        value = body.get("val")
        address: str | None = None
        port: int | None = None
        port_end: int | None = None
        mac: str | None = None
        if isinstance(value, str):
            address = value
        elif isinstance(value, dict):
            concat = value.get("concat")
            if isinstance(concat, list) and concat:
                first = concat[0]
                if isinstance(first, dict):
                    first = first.get("val")
                if isinstance(first, str):
                    address = first
                if len(concat) > 1:
                    second = concat[1]
                    if isinstance(second, dict):
                        if (
                            isinstance(second.get("range"), list)
                            and len(second["range"]) == 2
                        ):
                            low, high = second["range"]
                            if (
                                isinstance(low, int)
                                and not isinstance(low, bool)
                                and isinstance(high, int)
                                and not isinstance(high, bool)
                            ):
                                port = low
                                port_end = high
                            second = None
                        else:
                            second = second.get("val")
                    if isinstance(second, int) and not isinstance(second, bool):
                        port = second
                    elif isinstance(second, str):
                        candidate = second.strip().lower()
                        if _MAC_RE.match(candidate):
                            mac = candidate
        if address is None:
            return None
        try:
            if not is_ipv4(address):
                return None
        except (TypeError, ValueError):
            return None
        expires = body.get("expires")
        timeout = body.get("timeout")
        expires_in = (
            max(0, int(expires))
            if isinstance(expires, (int, float)) and not isinstance(expires, bool)
            else None
        )
        timeout_value = (
            max(0, int(timeout))
            if isinstance(timeout, (int, float)) and not isinstance(timeout, bool)
            else None
        )
        entry = {
            "address": normalize_ip(address),
            "port": port,
            "expires_in": expires_in,
            "timeout": timeout_value,
        }
        if port_end is not None and (
            port is None or not (1 <= port_end <= 65535) or port_end <= port
        ):
            port_end = None
        if port_end is not None:
            entry["port_end"] = port_end
        if mac is not None:
            entry["mac"] = mac
        return entry

    def snapshot(self) -> dict:
        """A snapshot of the dynamic sets, with the remaining times.

        Read-only, so the admin Firewall view can safely call it. A
        nonexistent set counts as empty (it also works before installation).
        """
        names = (
            self.set_name, self.tcp_set, self.udp_set,
            self.input_tcp_set, self.input_udp_set,
            self.icmp_set, self.mac_set, self.ban_set, self.proxy_ban_set,
        )
        sets: dict[str, list[dict]] = {name: [] for name in names}
        errors: list[str] = []
        if not self.dry_run:
            with self._lock:
                for set_name in names:
                    result = self._run(
                        ["-j", "list", "set", "inet", self.table, set_name],
                        check=False,
                    )
                    if result.returncode != 0:
                        detail = result.stderr.decode("utf-8", "replace").strip()
                        if not (
                            "No such file or directory" in detail
                            or "does not exist" in detail
                        ):
                            errors.append(
                                f"{set_name}: "
                                f"{detail or 'nft could not list the set'}"
                            )
                        continue
                    try:
                        sets[set_name] = self.parse_set_json(
                            result.stdout, set_name
                        )
                    except FirewallError as exc:
                        errors.append(str(exc))
        return {
            "table": self.table,
            "generated": time.time(),
            "dry_run": self.dry_run,
            "sets": sets,
            "errors": errors,
        }

    def ruleset(self) -> dict:
        """Raw nftables output of the chains for the admin Firewall view.

        Read-only, so the admin view can safely call it. It deliberately
        does not include the contents of the dynamic sets (snapshot() shows
        those); thus the output remains a short rule list similar to
        ``iptables -L -n``. A missing chain is not an error: the table may
        not exist yet before installation.
        """
        if self.dry_run:
            return {
                "table": self.table,
                "generated": time.time(),
                "dry_run": True,
                "text": "",
                "chains": [],
                "missing": [],
                "errors": [],
            }
        chunks: list[str] = []
        shown: list[str] = []
        missing: list[str] = []
        errors: list[str] = []
        with self._lock:
            for chain in RULESET_CHAINS:
                result = self._run(
                    ["list", "chain", "inet", self.table, chain],
                    check=False,
                )
                if result.returncode != 0:
                    detail = result.stderr.decode("utf-8", "replace").strip()
                    if (
                        "No such file or directory" in detail
                        or "does not exist" in detail
                    ):
                        missing.append(chain)
                    else:
                        errors.append(
                            f"{chain}: "
                            f"{detail or 'nft could not list the chain'}"
                        )
                    continue
                text = self._strip_chain_wrapper(
                    result.stdout.decode("utf-8", "replace").strip()
                )
                if text:
                    chunks.append(text)
                    shown.append(chain)
        return {
            "table": self.table,
            "generated": time.time(),
            "dry_run": False,
            "text": "\n\n".join(chunks),
            "chains": shown,
            "missing": missing,
            "errors": errors,
        }

    @staticmethod
    def _strip_chain_wrapper(text: str) -> str:
        """Remove the table wrapper around ``nft list chain``.

        Newer nft versions print the chain wrapped in a
        ``table inet <name> { ... }`` block too. The view should show the
        table only once, so we cut off the wrapper and also remove the
        extra indentation.
        """
        lines = text.splitlines()
        if (
            lines
            and lines[0].strip().startswith("table ")
            and lines[0].rstrip().endswith("{")
        ):
            lines = lines[1:]
            if lines and lines[-1].strip() == "}":
                lines = lines[:-1]
            lines = [
                line[1:] if line.startswith("\t") else line
                for line in lines
            ]
        return "\n".join(lines).strip()

    def healthy(self) -> tuple[bool, str]:
        try:
            with self._lock:
                for set_name in (
                    self.set_name, self.tcp_set, self.udp_set,
                    self.input_tcp_set, self.input_udp_set,
                    self.service_tcp_set, self.service_udp_set,
                    self.icmp_set, self.mac_set, self.ban_set,
                ):
                    self._run(["list", "set", "inet", self.table, set_name])
        except FirewallError as exc:
            return False, str(exc)
        return True, "ok"

    def state_token(self) -> int | None:
        """Generation of the live table, or None if it needs a resync.

        The value is the table's kernel handle: a deleted and reloaded table
        (``flush ruleset``, an nftables.service restart, the Docker watchdog's
        reload) gets a new handle, and with it empty custom chains and empty
        ban and host-guard sets. None means the table is missing, or the
        portal's own first rule in ``preauth`` (the ban drop, rendered on
        every apply) is gone because the chains were flushed. In dry-run mode
        the value is constant.
        """
        if self.dry_run:
            return 0
        listing = self._run(["-j", "list", "tables", "inet"], check=False)
        handle = None
        try:
            data = json.loads(listing.stdout or b"{}")
        except ValueError:
            return None
        for item in data.get("nftables", []):
            table = item.get("table") if isinstance(item, dict) else None
            if isinstance(table, dict) and table.get("name") == self.table:
                handle = table.get("handle")
        if not isinstance(handle, int) or isinstance(handle, bool):
            return None
        chain = self._run(
            ["list", "chain", "inet", self.table, "preauth"], check=False
        )
        # The marker must match the rule _custom_rules renders (DJ-01 made it
        # direction-aware); nft lists it back in the same form.
        marker = f"ip saddr @{self.ban_set} ct direction original drop"
        if marker.encode() not in (chain.stdout or b""):
            return None
        return handle


def _audit_conntrack_failure(
    audit, ip: str, returncode: int, detail: str, operation: str = "flush"
) -> None:
    """A conntrack deletion failure (optional, non-blocking logging)."""
    if audit is None:
        return
    try:
        audit.write(
            "conntrack_failed",
            ip=ip,
            operation=operation,
            returncode=int(returncode),
            detail=str(detail)[:500],
        )
    except Exception as exc:
        log(f"[audit] writing conntrack_failed failed: {exc}")


def conntrack_flush(ip: str, audit=None) -> bool:
    """Tear down the given client's existing connections.

    The return value indicates whether the deletion actually ran. Callers
    log it; expiry of the firewall sets applies to new connections
    independently of this. On a real error an optional audit log entry is
    also written (it never blocks).
    """
    if DRY_RUN or not CONNTRACK_BIN or not is_ipv4(ip):
        return False
    try:
        result = subprocess.run(
            [CONNTRACK_BIN, "-D", "-s", normalize_ip(ip)],
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"[firewall] conntrack deletion failed ({ip}): {exc}")
        _audit_conntrack_failure(audit, ip, -1, str(exc))
        return False
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        # Exit code 1 in conntrack often means "no such entry"; that is not
        # an error, there is nothing to delete then.
        if result.returncode != 1 or detail:
            log(
                f"[firewall] conntrack deletion returned an error code "
                f"({ip}): {result.returncode} {detail}".strip()
            )
            _audit_conntrack_failure(audit, ip, result.returncode, detail)
        return False
    return True


# We start at most this many targeted conntrack deletions at a time. Above
# that, a full per-IP flush is cheaper and more reliable than dozens of
# processes.
CONNTRACK_REMOVED_LIMIT = 16


def conntrack_flush_removed(
    ip: str, removed, remaining=(), audit=None
) -> bool:
    """Delete only the connections belonging to removed grants.

    ``removed`` are the departing grants, ``remaining`` the still valid
    ones (typically the session's new union). Conntrack cannot filter by
    direction, so the decision is based on the combined union of all
    directions:

    * For a removed ``full`` grant we perform a full per-IP flush only if
      ``remaining`` is empty (nothing remains allowed). If some grant
      remains, the packet-level nft rules stop the departing traffic; a
      full flush would also break the live connections of the remaining
      grant (for example input SSH on port 22, when input-22 replaces a
      full forward access).
    * If any remaining part is ``full`` (in any direction), we do not
      start targeted port/ICMP deletion at all: conntrack is
      direction-blind, and the command would break the remaining full
      access's connections too.
    * Otherwise the remaining TCP/UDP ports and ICMP count as the union of
      all directions, because ``conntrack -D -s IP -p tcp --dport N``
      deletes regardless of direction. Thus the connections of a port
      still allowed in another direction remain untouched.

    The operation starts at most :data:`CONNTRACK_REMOVED_LIMIT` unique
    commands. Beyond that we switch to a full per-IP flush only if
    ``remaining`` is empty; otherwise, to protect the remaining grants, we
    skip the cleanup and return ``False``. The
    ``DRY_RUN``/``CONNTRACK_BIN``/IPv4 conditions are the same as in
    :func:`conntrack_flush`. The function never raises; errors get an
    optional audit entry.
    """

    if DRY_RUN or not CONNTRACK_BIN or not is_ipv4(ip):
        return False
    address = normalize_ip(ip)
    removed = tuple(removed or ())
    remaining = tuple(remaining or ())
    if not remaining and any(part.full for part in removed):
        # Removed full access, and nothing remains allowed: a full per-IP
        # flush is the safest.
        return conntrack_flush(ip, audit)
    if any(part.full for part in remaining):
        # The remaining full access (in any direction) covers every port
        # and ICMP. Conntrack cannot filter by direction, so any targeted
        # deletion would also break its live connections.
        return False

    # conntrack -D -s is direction-blind: the remaining ports must count
    # as the union of all directions.
    covered_tcp = {port for part in remaining for port in part.tcp}
    covered_udp = {port for part in remaining for port in part.udp}
    covered_icmp = any(part.icmp for part in remaining)

    commands: list[tuple[str, int | None]] = []
    seen: set[tuple[str, int | None]] = set()

    def add(proto: str, port: int | None) -> None:
        key = (proto, port)
        if key not in seen:
            seen.add(key)
            commands.append(key)

    removed_tcp: set[int] = set()
    removed_udp: set[int] = set()
    removed_icmp = False
    for part in removed:
        if part.full:
            # The departing full element is handled by the branch above;
            # with a remaining grant we deliberately delete nothing for it.
            continue
        removed_tcp.update(part.tcp)
        removed_udp.update(part.udp)
        removed_icmp = removed_icmp or part.icmp
    for port in sorted(removed_tcp - covered_tcp):
        add("tcp", port)
    for port in sorted(removed_udp - covered_udp):
        add("udp", port)
    if removed_icmp and not covered_icmp:
        add("icmp", None)

    if len(commands) > CONNTRACK_REMOVED_LIMIT:
        if remaining:
            log(
                f"[firewall] targeted conntrack deletion for {ip} "
                f"would require {len(commands)} commands; skipping "
                "to protect the remaining grants"
            )
            return False
        return conntrack_flush(ip, audit)
    if not commands:
        return False

    ok = True
    for proto, port in commands:
        args = [CONNTRACK_BIN, "-D", "-s", address, "-p", proto]
        if port is not None:
            args.extend(["--dport", str(port)])
        try:
            result = subprocess.run(
                args, capture_output=True, timeout=3
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            log(
                f"[firewall] targeted conntrack deletion failed "
                f"({ip}, {proto}"
                + (f"/{port}" if port is not None else "")
                + f"): {exc}"
            )
            _audit_conntrack_failure(
                audit, ip, -1, str(exc), operation="flush_removed"
            )
            ok = False
            continue
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            # Exit code 1 often means "no such entry"; there is nothing to
            # delete then, but the call cannot be considered successful.
            if result.returncode != 1 or detail:
                log(
                    f"[firewall] targeted conntrack deletion returned "
                    f"an error code ({ip}, {proto}"
                    + (f"/{port}" if port is not None else "")
                    + f"): {result.returncode} {detail}".strip()
                )
                _audit_conntrack_failure(
                    audit,
                    ip,
                    result.returncode,
                    detail,
                    operation="flush_removed",
                )
            ok = False
    return ok


def _port_proxy_keys(entries) -> dict[tuple[str, int], tuple]:
    """Enabled entries: (protocol, listening port) -> their effect.

    Synthetic tunnel entries are omitted: they are not user port proxies,
    so they produce neither a warning nor a conntrack deletion.
    """
    keys: dict[tuple[str, int], tuple] = {}
    for entry in _enabled_custom_entries(entries):
        if entry.get("_tunnel"):
            continue
        proto = entry.get("proto")
        for p in (("tcp", "udp") if proto == "both" else (proto,)):
            keys[(p, entry.get("listen_port"))] = (
                entry.get("type"), entry.get("target_ip"),
                entry.get("target_port"), entry.get("ifaces"),
                entry.get("snat"),
            )
    return keys


def port_proxy_changes(old_entries, new_entries) -> list[tuple[str, int]]:
    """The (protocol, port) pairs whose NAT target has changed.

    Conntrack keeps the old NAT binding until the end of the flow,
    therefore their existing connections must be deleted (for an added,
    removed or modified entry alike).
    """
    old = _port_proxy_keys(old_entries)
    new = _port_proxy_keys(new_entries)
    return sorted(
        key for key in set(old) | set(new) if old.get(key) != new.get(key)
    )


def conntrack_flush_port(proto: str, port: int, audit=None) -> bool:
    """Delete the connections with the given original destination port (pre-DNAT)."""
    if DRY_RUN or not CONNTRACK_BIN:
        return False
    target = f"{proto}/{port}"
    try:
        result = subprocess.run(
            [CONNTRACK_BIN, "-D", "-p", proto, "--orig-port-dst", str(port)],
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"[firewall] conntrack deletion failed ({target}): {exc}")
        _audit_conntrack_failure(
            audit, target, -1, str(exc), operation="flush_port"
        )
        return False
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        # Exit code 1 with empty error text: no such entry.
        if result.returncode != 1 or detail:
            log(
                f"[firewall] conntrack deletion returned an error code "
                f"({target}): {result.returncode} {detail}".strip()
            )
            _audit_conntrack_failure(
                audit, target, result.returncode, detail,
                operation="flush_port",
            )
        return False
    return True


def _proc_sockets(proc_dir: str = "/proc/net"):
    """(protocol, local address, port) for listening TCP / bound UDP sockets on the host.

    The portal runs on the host network, therefore /proc/net shows the
    host's sockets (including docker-proxy's published ports). The address
    is an ``ipaddress`` object; a v4-mapped IPv6 address comes out as IPv4.
    """
    for proto in ("tcp", "udp"):
        for name in (proto, proto + "6"):
            try:
                with open(os.path.join(proc_dir, name), encoding="ascii") as fh:
                    next(fh, None)
                    for line in fh:
                        fields = line.split()
                        if len(fields) < 4:
                            continue
                        # For TCP only LISTEN (0A), for UDP bound (07).
                        if fields[3] != ("0A" if proto == "tcp" else "07"):
                            continue
                        try:
                            raw, port = fields[1].rsplit(":", 1)
                            # The kernel prints the address as 32-bit words
                            # in native order.
                            packed = b"".join(
                                struct.pack("=I", int(raw[i:i + 8], 16))
                                for i in range(0, len(raw), 8)
                            )
                            address = ipaddress.ip_address(packed)
                            port_number = int(port, 16)
                        except (ValueError, struct.error):
                            continue
                        if address.version == 6 and address.ipv4_mapped:
                            address = address.ipv4_mapped
                        yield proto, address, port_number
            except OSError:
                continue


def listening_ports(proc_dir: str = "/proc/net") -> set[tuple[str, int]]:
    """Listening TCP (LISTEN) and bound UDP ports on the host."""
    return {(proto, port) for proto, _, port in _proc_sockets(proc_dir)}


def loopback_target(proto: str, port: int, proc_dir: str = "/proc/net") -> str | None:
    """The address of a target port listening only on loopback, otherwise None.

    If the port has only a socket bound to a 127.0.0.0/8 address, the
    ``redirect`` (the incoming interface's primary address) would reach an
    empty port: in that case the DNAT target is this loopback address.
    With a wildcard (0.0.0.0 / ::) or otherwise bound socket the redirect
    remains: a wildcard UDP server chooses the reply's source address from
    the route (the interface address), so DNAT-ing to 127.0.0.1 would make
    the reply not match conntrack.
    """
    addresses = set()
    for sock_proto, address, sock_port in _proc_sockets(proc_dir):
        if sock_proto != proto or sock_port != port:
            continue
        if address.version == 6:
            if address.is_unspecified:
                return None  # a dual-stack [::] accepts IPv4 too
            continue  # ::1 / another IPv6 address does not affect the IPv4 proxy
        addresses.add(address)
    if not addresses or not all(address.is_loopback for address in addresses):
        return None
    preferred = ipaddress.IPv4Address("127.0.0.1")
    return str(preferred if preferred in addresses else min(addresses))


def route_localnet(ifaces, conf_dir: str = "/proc/sys/net/ipv4/conf") -> bool:
    """Whether the kernel allows a 127/8 destination on the given interfaces.

    The kernel ORs the ``all`` and per-interface values. In the portal
    container /proc/sys is read-only; on the host docker/setup-host.sh sets
    it.
    """
    def enabled(name: str) -> bool:
        try:
            with open(os.path.join(conf_dir, name, "route_localnet"),
                      encoding="ascii") as fh:
                return fh.read().strip() == "1"
        except OSError:
            return False

    return enabled("all") or all(enabled(name) for name in ifaces)


def port_proxy_warnings(entries, listening, published, localnet=()) -> list[dict]:
    """Warnings for already occupied listening ports of enabled entries.

    Not a prohibition: the proxy's DNAT (-101) runs before Docker's DNAT
    (-100), therefore on the configured interfaces the proxy wins, and the
    local socket / the Docker publication is not reachable from there. For
    a ``localnet`` (protocol, listening port) pair the target listens only
    on loopback, but route_localnet is off on the host, so the proxy
    cannot reach it.
    """
    warnings: list[dict] = []
    for proto, port in sorted(_port_proxy_keys(entries)):
        docker = (proto, port) in published
        listen = (proto, port) in listening
        blocked = (proto, port) in localnet
        if docker or listen or blocked:
            warnings.append(
                {"proto": proto, "port": port, "docker": docker,
                 "listen": listen, "localnet": blocked}
            )
    return warnings


def _ip_sort_key(ip: str):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return (9, str(ip))
    return (address.version, address.packed)


def group_firewall_snapshot(
    snapshot: dict, sessions: list[dict]
) -> dict:
    """Merge the kernel-side sets with the portal sessions.

    One group belongs to an IP address, containing the actual (in-kernel)
    grants, the sessions belonging to them and the remaining times.
    ``in_sync`` signals when the kernel and the session records differ
    (for example a port did not get in, or another got in by hand).
    """
    raw_sets = snapshot.get("sets")
    sets = raw_sets if isinstance(raw_sets, dict) else {}
    grouped: dict[str, dict] = {}

    def bucket(ip: str) -> dict:
        if ip not in grouped:
            grouped[ip] = {
                "ip": ip,
                "full": None,
                "icmp": None,
                "tcp": [],
                "udp": [],
                "sessions": [],
            }
        return grouped[ip]

    def entry_time(entry: dict) -> dict:
        return {
            "expires_in": entry.get("expires_in"),
            "timeout": entry.get("timeout"),
        }

    def add_simple(set_name: str, field: str) -> None:
        entries = sets.get(set_name)
        if not isinstance(entries, list):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            address = entry.get("address")
            if not isinstance(address, str) or not is_ipv4(address):
                continue
            bucket(normalize_ip(address))[field] = entry_time(entry)

    add_simple("allowed_v4", "full")
    add_simple("allowed_icmp", "icmp")

    for set_name, field, direction in (
        ("allowed_tcp", "tcp", "forward"),
        ("allowed_udp", "udp", "forward"),
        # Host (input) grants go into the same display list, with direction
        # indicated; thus every kernel-side grant is visible in an IP's
        # group, and the per-direction comparison is also correct.
        ("allowed_input_tcp", "tcp", "input"),
        ("allowed_input_udp", "udp", "input"),
    ):
        entries = sets.get(set_name)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            address = entry.get("address")
            port = entry.get("port")
            if (
                not isinstance(address, str) or not is_ipv4(address)
                or not isinstance(port, int) or isinstance(port, bool)
                or not 1 <= port <= 65535
            ):
                continue
            item = {
                "port": port,
                "direction": direction,
                **entry_time(entry),
            }
            if isinstance(entry.get("port_end"), int) \
                    and not isinstance(entry["port_end"], bool):
                item["port_end"] = entry["port_end"]
            bucket(normalize_ip(address))[field].append(item)

    for row in sessions:
        if not isinstance(row, dict) or not row.get("authorized"):
            continue
        address = row.get("ip")
        try:
            address = normalize_ip(address)
        except (TypeError, ValueError):
            continue
        if not is_ipv4(address):
            continue
        bucket(address)["sessions"].append(row)

    rows: list[dict] = []
    for ip, item in grouped.items():
        # We sort primarily by port; for the same port the forward entry
        # comes first so that the display stays stable.
        item["tcp"].sort(
            key=lambda entry: (entry["port"], entry.get("direction") == "input")
        )
        item["udp"].sort(
            key=lambda entry: (entry["port"], entry.get("direction") == "input")
        )
        item["sessions"].sort(
            key=lambda row: (
                row.get("user") or "",
                row.get("logged_in") or 0,
            )
        )

        actual_tcp = {"forward": set(), "input": set()}
        actual_udp = {"forward": set(), "input": set()}
        for field, actual in (("tcp", actual_tcp), ("udp", actual_udp)):
            for entry in item[field]:
                direction = entry.get("direction")
                if direction not in ("forward", "input"):
                    direction = "forward"
                low = entry["port"]
                high = entry.get("port_end", low)
                if not isinstance(high, int) or isinstance(high, bool):
                    high = low
                actual[direction].update(range(low, high + 1))
        expected_tcp = {"forward": set(), "input": set()}
        expected_udp = {"forward": set(), "input": set()}
        expected_icmp = False
        expected_full = False
        for row in item["sessions"]:
            # A host (input) session's ports must be compared against the
            # host sets, otherwise an allowed host rule would produce a
            # false "missing TCP" mismatch. A collection rule's session may
            # contain several grants per direction: in that case the
            # snapshot's "grants" list gives the exact breakdown.
            row_grants = row.get("grants")
            if isinstance(row_grants, list) and row_grants:
                for part in row_grants:
                    if not isinstance(part, dict):
                        continue
                    direction = part.get("direction")
                    if direction not in ("forward", "input"):
                        direction = "forward"
                    expected_tcp[direction].update(
                        value for value in (part.get("tcp") or [])
                        if isinstance(value, int)
                        and not isinstance(value, bool)
                    )
                    expected_udp[direction].update(
                        value for value in (part.get("udp") or [])
                        if isinstance(value, int)
                        and not isinstance(value, bool)
                    )
                    expected_icmp = expected_icmp or bool(part.get("icmp"))
                    expected_full = expected_full or bool(part.get("full"))
                continue
            direction = row.get("direction")
            if direction not in ("forward", "input"):
                direction = "forward"
            expected_tcp[direction].update(
                value for value in (row.get("tcp") or [])
                if isinstance(value, int) and not isinstance(value, bool)
            )
            expected_udp[direction].update(
                value for value in (row.get("udp") or [])
                if isinstance(value, int) and not isinstance(value, bool)
            )
            expected_icmp = expected_icmp or bool(row.get("icmp"))
            expected_full = expected_full or bool(row.get("full"))

        actual_icmp = item["icmp"] is not None
        actual_full = item["full"] is not None

        mismatch: list[str] = []
        for label, expected, actual in (
            ("TCP", expected_tcp["forward"], actual_tcp["forward"]),
            ("UDP", expected_udp["forward"], actual_udp["forward"]),
            ("host TCP", expected_tcp["input"], actual_tcp["input"]),
            ("host UDP", expected_udp["input"], actual_udp["input"]),
        ):
            for port in sorted(expected - actual):
                mismatch.append(f"missing {label} {port}")
            for port in sorted(actual - expected):
                mismatch.append(f"unexpected {label} {port}")
        if expected_full and not actual_full:
            mismatch.append("missing full access")
        if actual_full and not expected_full:
            mismatch.append("unexpected full access")
        if expected_icmp and not actual_icmp:
            mismatch.append("missing ICMP")
        if actual_icmp and not expected_icmp:
            mismatch.append("unexpected ICMP")

        users = sorted({
            row.get("user") for row in item["sessions"]
            if row.get("user")
        })
        rules: list[dict] = []
        seen_rules: set[tuple[str, str]] = set()
        for row in item["sessions"]:
            key = (str(row.get("user") or ""), str(row.get("rule") or ""))
            if key in seen_rules:
                continue
            seen_rules.add(key)
            rules.append({
                "id": row.get("rule") or "",
                "label": (
                    row.get("rule_label") or row.get("rule") or "—"
                ),
                "user": row.get("user") or "",
                "ports_label": row.get("ports_label") or "",
                "expires_in": row.get("expires_in"),
            })

        if actual_full:
            ports_label = "Minden port"
        else:
            # Host (input) ports are marked with a "Host" prefix, so that
            # forward and host grants with the same port number remain
            # distinguishable.
            parts: list[str] = []
            for direction, prefix in (("forward", ""), ("input", "Host ")):
                for field, proto in (("tcp", "TCP"), ("udp", "UDP")):
                    values: set[int] = set()
                    for entry in item[field]:
                        if (entry.get("direction") or "forward") != direction:
                            continue
                        low = entry["port"]
                        high = entry.get("port_end", low)
                        if not isinstance(high, int) or isinstance(high, bool):
                            high = low
                        values.update(range(low, high + 1))
                    if values:
                        parts.append(
                            f"{prefix}{proto} "
                            + format_ports(values, dash="–")
                        )
            if actual_icmp:
                parts.append("ICMP")
            ports_label = " · ".join(parts) or "Nincs port"
        timed = [
            item["full"], item["icmp"], *item["tcp"], *item["udp"],
        ]
        deadlines = [
            entry.get("expires_in")
            for entry in timed
            if isinstance(entry, dict)
            and isinstance(entry.get("expires_in"), int)
        ]
        item["users"] = users
        item["rules"] = rules
        item["ports_label"] = ports_label
        item["expires_in"] = min(deadlines) if deadlines else None
        item["entry_count"] = (
            int(actual_full) + int(actual_icmp)
            + len(item["tcp"]) + len(item["udp"])
        )
        item["orphan"] = not item["sessions"]
        item["mismatch"] = mismatch
        item["in_sync"] = bool(item["sessions"]) and not mismatch
        rows.append(item)

    rows.sort(key=lambda item: _ip_sort_key(item["ip"]))
    errors = snapshot.get("errors")
    errors = errors if isinstance(errors, list) else []
    return {
        "ips": rows,
        "errors": errors,
        "counts": {
            "ips": len(rows),
            "entries": sum(item["entry_count"] for item in rows),
            "sessions": sum(len(item["sessions"]) for item in rows),
            "orphans": sum(1 for item in rows if item["orphan"]),
            "mismatched": sum(
                1 for item in rows
                if not item["orphan"] and not item["in_sync"]
            ),
        },
        "dry_run": bool(snapshot.get("dry_run")),
        "table": snapshot.get("table", ""),
        "generated": snapshot.get("generated"),
        "server_time": time.time(),
    }


# ------------------------------------------------------------------------ TOTP

# The base32 alphabet for recovery codes (no 0/1/8/9, so they cannot be
# confused with letters).
_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_RECOVERY_CODE_LENGTH = 10


def generate_totp_secret() -> str:
    """A 20-byte, unpadded base32 TOTP secret (32 uppercase letters)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_key(secret: str) -> bytes:
    """The HMAC key derived from the base32 secret; ValueError on a bad secret."""
    if not isinstance(secret, str):
        raise ValueError("invalid TOTP secret")
    raw = secret.strip().replace(" ", "").upper()
    if not raw:
        raise ValueError("empty TOTP secret")
    padding = "=" * ((8 - len(raw) % 8) % 8)
    try:
        key = base64.b32decode(raw + padding, casefold=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid TOTP secret") from exc
    if not key:
        raise ValueError("empty TOTP secret")
    return key


def hotp_code(secret: str, counter: int) -> str:
    """RFC 4226 HOTP code (HMAC-SHA1, 6 digits, zero-padded)."""
    key = _totp_key(secret)
    try:
        counter = int(counter)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("invalid counter") from exc
    if counter < 0:
        raise ValueError("invalid counter")
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{value % (10 ** TOTP_DIGITS):0{TOTP_DIGITS}d}"


def totp_code(secret: str, now: float | None = None) -> str:
    """The current TOTP code (or the one belonging to the given time)."""
    current = time.time() if now is None else float(now)
    return hotp_code(secret, int(current // TOTP_PERIOD))


def totp_match(secret: str, code: str, now: float | None = None) -> int | None:
    """The counter belonging to the code if valid; otherwise ``None``.

    It accepts exactly 6 ASCII digits and also checks the neighbouring
    steps per ``TOTP_WINDOW`` (because of clock skew). The return value is
    the counter that actually matched, which the caller can use to filter
    out replay.
    """
    if (
        not isinstance(code, str)
        or len(code) != 6
        or not code.isascii()
        or not code.isdigit()
    ):
        return None
    current = int((time.time() if now is None else float(now)) // TOTP_PERIOD)
    try:
        for offset in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
            counter = current + offset
            if counter < 0:
                continue
            if hmac.compare_digest(hotp_code(secret, counter), code):
                return counter
    except (TypeError, ValueError, OverflowError):
        return None
    return None


def build_otpauth_uri(
    username: str, secret: str, issuer: str | None = None
) -> str:
    """An ``otpauth://`` URI that can be handed to an authenticator app.

    ``issuer`` appears in the label and in the query parameter; if empty,
    it falls back to the built-in :data:`TOTP_ISSUER` value.
    """
    effective_issuer = (issuer or "").strip() or TOTP_ISSUER
    label = urllib.parse.quote(f"{effective_issuer}:{username}", safe="")
    query = urllib.parse.urlencode(
        {
            "secret": secret,
            "issuer": effective_issuer,
            "algorithm": "SHA1",
            "digits": str(TOTP_DIGITS),
            "period": str(TOTP_PERIOD),
        }
    )
    return f"otpauth://totp/{label}?{query}"


def normalize_recovery_code(code: str) -> str:
    """The canonical form of a recovery code: uppercase, no spaces/hyphens."""
    if not isinstance(code, str):
        return ""
    return code.upper().replace(" ", "").replace("\t", "").replace("-", "")


def hash_recovery_code(code: str) -> str:
    """The SHA-256 hash of a recovery code (lowercase hex)."""
    normalized = normalize_recovery_code(code)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def generate_recovery_codes(count: int = 10) -> list[str]:
    """A list of single-use, unique recovery codes."""
    codes: list[str] = []
    seen: set[str] = set()
    while len(codes) < max(0, int(count)):
        candidate = "".join(
            secrets.choice(_BASE32_ALPHABET) for _ in range(_RECOVERY_CODE_LENGTH)
        )
        if candidate in seen:
            continue
        seen.add(candidate)
        codes.append(candidate)
    return codes


# --------------------------------------------------------------- users

class UserStoreError(RuntimeError):
    """The user database is corrupt or not writable."""


@dataclass(frozen=True)
class UserRecord:
    name: str
    salt: bytes
    digest: bytes
    iterations: int
    created: int
    role: str = ROLE_USER
    enabled: bool = True
    rules: tuple[str, ...] = ()
    rules_set: bool = False
    must_change_password: bool = False
    totp_secret: str = ""
    totp_required: bool = False
    totp_last_step: int = -1
    totp_recovery: tuple[str, ...] = ()
    pending: bool = False
    email: str = ""

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    @property
    def totp_enrolled(self) -> bool:
        """Whether a TOTP secret is configured (regardless of the required flag)."""
        return bool(self.totp_secret)

    def public(self, groups: list[str] | tuple[str, ...] = ()) -> dict:
        return {
            "name": self.name,
            "role": self.role,
            "enabled": self.enabled,
            "rules": list(self.rules),
            "rules_set": self.rules_set,
            "groups": list(groups),
            "created": self.created,
            "must_change_password": self.must_change_password,
            "totp_required": self.totp_required,
            "totp_enrolled": self.totp_enrolled,
            "pending": self.pending,
            "email": self.email,
        }


class UserStore:
    """users.json: password hashes with PBKDF2-HMAC-SHA256, atomic writes."""

    MIN_PASSWORD = 8
    MAX_PASSWORD = 1024

    def __init__(self, path: str = USERS_PATH, iterations: int = PBKDF2_ITERATIONS) -> None:
        self.path = os.path.abspath(path)
        self.iterations = max(10_000, int(iterations))
        self._lock = threading.Lock()
        self._cache: dict[str, UserRecord] | None = None
        self._cache_key: tuple[int, int, int] | None = None
        # We do the same amount of work even for an unknown user.
        self._dummy_salt = b"\x00" * 16
        self._dummy_digest = hashlib.pbkdf2_hmac(
            "sha256", b"hatarvedelem-dummy", self._dummy_salt, self.iterations
        )

    # -- reading ---------------------------------------------------------------

    def _read_raw(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise UserStoreError(f"the user database cannot be read: {exc}") from exc
        if not isinstance(data, dict):
            raise UserStoreError("the user database has an invalid format")
        return data

    def _load(self) -> dict[str, UserRecord]:
        try:
            stat = os.stat(self.path)
            # The inode is also needed: an atomic os.replace creates a new
            # file with the same size and mtime that the old key would not
            # have noticed.
            key = (stat.st_ino, stat.st_mtime_ns, stat.st_size)
        except FileNotFoundError:
            return {}
        with self._lock:
            if self._cache is not None and self._cache_key == key:
                return self._cache
        raw = self._read_raw()
        records: dict[str, UserRecord] = {}
        for name, item in raw.items():
            if not isinstance(name, str) or not isinstance(item, dict):
                continue
            try:
                role = str(item.get("role", ROLE_USER))
                if role not in (ROLE_USER, ROLE_ADMIN):
                    role = ROLE_USER
                enabled = item.get("enabled", True)
                if not isinstance(enabled, bool):
                    enabled = bool(enabled)
                must_change = item.get("must_change_password", False)
                if not isinstance(must_change, bool):
                    must_change = bool(must_change)
                # Missing key = inherited, not required setting. Any invalid
                # value, however, makes it required (fail closed), so that a
                # corrupted file cannot silently disable 2FA.
                if "totp_required" not in item:
                    totp_required = False
                else:
                    required_raw = item["totp_required"]
                    totp_required = (
                        required_raw if isinstance(required_raw, bool) else True
                    )
                totp_secret_raw = item.get("totp_secret", "")
                totp_secret = (
                    totp_secret_raw if isinstance(totp_secret_raw, str) else ""
                )
                try:
                    totp_last_step = int(item.get("totp_last_step", -1))
                except (TypeError, ValueError, OverflowError):
                    totp_last_step = -1
                recovery_raw = item.get("totp_recovery", ())
                if isinstance(recovery_raw, list):
                    totp_recovery = tuple(
                        value.lower()
                        for value in recovery_raw
                        if isinstance(value, str)
                        and _TOTP_RECOVERY_RE.match(value.lower())
                    )
                else:
                    totp_recovery = ()
                # Missing key = not a pending account. Any invalid value,
                # however, counts as pending (fail closed), as with
                # totp_required.
                if "pending" not in item:
                    pending = False
                else:
                    pending_raw = item["pending"]
                    pending = pending_raw if isinstance(pending_raw, bool) else True
                email = normalize_email(item.get("email", ""), strict=False)
                rules_raw = item.get("rules", ())
                if not isinstance(rules_raw, list):
                    rules_raw = ()
                rules = tuple(
                    value for value in (
                        str(rid).strip() for rid in rules_raw
                        if isinstance(rid, str)
                    )
                    if value and value != LEGACY_ADMIN_RULE_ID
                )
                records[name] = UserRecord(
                    name=name,
                    salt=bytes.fromhex(str(item["salt"])),
                    digest=bytes.fromhex(str(item["hash"])),
                    iterations=max(10_000, int(item.get("iterations", self.iterations))),
                    created=int(item.get("created", 0)),
                    role=role,
                    enabled=enabled,
                    rules=rules,
                    rules_set="rules" in item,
                    must_change_password=must_change,
                    totp_secret=totp_secret,
                    totp_required=totp_required,
                    totp_last_step=totp_last_step,
                    totp_recovery=totp_recovery,
                    pending=pending,
                    email=email,
                )
            except (KeyError, TypeError, ValueError):
                log(f"[users] skipped invalid entry: {name!r}")
        with self._lock:
            self._cache = records
            self._cache_key = key
        return records

    def verify(self, name: str, password: str) -> bool:
        try:
            record = self._load().get(name)
        except UserStoreError as exc:
            log(f"[users] {exc}")
            return False
        # A pending account must also be able to prove its password, so
        # that the HTTP layer can give it a distinct response.
        if record is None or (not record.enabled and not record.pending):
            digest = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), self._dummy_salt, self.iterations
            )
            hmac.compare_digest(digest, self._dummy_digest)
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), record.salt, record.iterations
        )
        if not hmac.compare_digest(digest, record.digest):
            return False
        if record.iterations != self.iterations:
            # Rehash to the current count, so every account converges to
            # the setting and the cost of a known and an unknown name (the
            # dummy digest) is the same again.
            self._rehash(name, password, record.digest)
        return True

    def _rehash(self, name: str, password: str, old_digest: bytes) -> None:
        try:
            with self._lock, self._locked():
                data = self._read_raw()
                item = data.get(name)
                # Changed in the meantime (password change): leave it alone.
                if not isinstance(item, dict) \
                        or str(item.get("hash", "")) != old_digest.hex():
                    return
                salt = secrets.token_bytes(16)
                item["salt"] = salt.hex()
                item["hash"] = hashlib.pbkdf2_hmac(
                    "sha256", password.encode("utf-8"), salt, self.iterations
                ).hex()
                item["iterations"] = self.iterations
                data[name] = item
                self._write_raw(data)
                self._cache = None
                self._cache_key = None
        except UserStoreError as exc:
            log(f"[users] rehash failed: {exc}")

    def names(self) -> list[str]:
        return sorted(self._load().keys())

    def record(self, name: str) -> UserRecord | None:
        return self._load().get(name)

    def provisioned_from(self, name: str) -> str:
        """The deterministic marker of a password originating from Compose."""
        try:
            data = self._read_raw()
        except UserStoreError:
            return ""
        item = data.get(name)
        if not isinstance(item, dict):
            return ""
        value = item.get("provisioned_from", "")
        return value if isinstance(value, str) else ""

    def details(self) -> list[UserRecord]:
        return sorted(self._load().values(), key=lambda rec: rec.name)

    def admin_count(self) -> int:
        return sum(
            1 for rec in self._load().values()
            if rec.is_admin and rec.enabled and not rec.pending
        )

    def pending_records(self) -> list[UserRecord]:
        """The accounts waiting for approval, by name."""
        return sorted(
            (rec for rec in self._load().values() if rec.pending),
            key=lambda rec: rec.name,
        )

    # -- writing ---------------------------------------------------------------

    @contextmanager
    def _locked(self):
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        lock_path = self.path + ".lock"
        fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _write_raw(self, data: dict) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        try:
            previous = os.stat(self.path)
        except FileNotFoundError:
            previous = None
        fd, tmp = tempfile.mkstemp(prefix=".users-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False, sort_keys=True)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            # The CLI may also run as root: preserve the file's owner,
            # otherwise the service could not read it on the next sign-in.
            if previous is not None and (
                previous.st_uid, previous.st_gid
            ) != (os.geteuid(), os.getegid()):
                os.chown(tmp, previous.st_uid, previous.st_gid)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _check_credentials(self, name: str, password: str) -> None:
        if not isinstance(name, str) or not USERNAME_RE.match(name):
            raise UserStoreError(
                "the username must be 1–32 characters: letter, digit, dot, hyphen, underscore"
            )
        if not isinstance(password, str) or not (
            self.MIN_PASSWORD <= len(password) <= self.MAX_PASSWORD
        ):
            raise UserStoreError(
                f"the password must be {self.MIN_PASSWORD}–{self.MAX_PASSWORD} characters"
            )

    def _new_record(
        self,
        name: str,
        password: str,
        *,
        role: str = ROLE_USER,
        enabled: bool = True,
        rules: tuple[str, ...] | None = None,
        created: int | None = None,
        must_change_password: bool = False,
        pending: bool = False,
        email: str = "",
    ) -> dict:
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, self.iterations
        )
        record = {
            "salt": salt.hex(),
            "hash": digest.hex(),
            "iterations": self.iterations,
            "algo": "pbkdf2-sha256",
            "created": int(time.time()) if created is None else int(created),
            "role": role,
            "enabled": bool(enabled),
            "must_change_password": bool(must_change_password),
            "pending": bool(pending),
            "email": email,
        }
        if rules is not None:
            record["rules"] = list(rules)
        return record

    def add(
        self,
        name: str,
        password: str,
        *,
        role: str = ROLE_USER,
        enabled: bool = True,
        rules: tuple[str, ...] | None = None,
        must_change_password: bool = False,
        pending: bool = False,
        email: str = "",
    ) -> None:
        self._check_credentials(name, password)
        normalized_email = normalize_email(email, strict=False)
        if pending:
            # A pending account is not active until approval, and gets no
            # rules, regardless of values the caller may have passed.
            role = ROLE_USER
            enabled = False
            rules = ()
            must_change_password = False
            if not normalized_email:
                raise UserStoreError(
                    "an e-mail address is required for a pending account"
                )
        if role not in (ROLE_USER, ROLE_ADMIN):
            raise UserStoreError("invalid role")
        with self._locked():
            data = self._read_raw()
            # Case-insensitive: "Admin" next to "admin" would confuse the
            # approving admin.
            folded = name.casefold()
            if any(existing.casefold() == folded for existing in data):
                raise UserStoreError(f"a user with this name already exists: {name}")
            data[name] = self._new_record(
                name, password, role=role, enabled=enabled, rules=rules,
                must_change_password=must_change_password,
                pending=pending, email=normalized_email,
            )
            self._write_raw(data)

    def approve_user(self, name: str) -> bool:
        """Activate a pending account.

        The password hash, rules, e-mail, role and creation time remain
        unchanged; this method does not assign rules. ``False`` for an
        unknown user.
        """
        if not isinstance(name, str):
            return False
        with self._lock, self._locked():
            data = self._read_raw()
            item = data.get(name)
            if not isinstance(item, dict):
                return False
            item["pending"] = False
            item["enabled"] = True
            data[name] = item
            self._write_raw(data)
            return True

    def reject_user(self, name: str) -> bool:
        """Reject a pending account: delete the entry.

        ``False`` for an unknown user.
        """
        if not isinstance(name, str):
            return False
        with self._lock, self._locked():
            data = self._read_raw()
            if not isinstance(data.get(name), dict):
                return False
            del data[name]
            self._write_raw(data)
            return True

    def set_password(
        self,
        name: str,
        password: str,
        *,
        must_change_password: bool = False,
    ) -> None:
        self._check_credentials(name, password)
        with self._locked():
            data = self._read_raw()
            if name not in data:
                raise UserStoreError(f"no such user: {name}")
            salt = secrets.token_bytes(16)
            digest = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, self.iterations
            )
            # We update in place so that fields independent of the password
            # (role, groups, provisioning marker) are preserved.
            item = data[name]
            item["salt"] = salt.hex()
            item["hash"] = digest.hex()
            item["iterations"] = self.iterations
            item["algo"] = "pbkdf2-sha256"
            item["must_change_password"] = bool(must_change_password)
            if not item.get("created"):
                item["created"] = int(time.time())
            data[name] = item
            self._write_raw(data)

    def restore_password(self, name: str, record: UserRecord) -> None:
        """Restore a previously read password state.

        It serves solely to return the password hash and the
        ``must_change_password`` flag exactly to their original values
        after an error during a multi-step admin change. A new password is
        set by :meth:`set_password`; this method does not accept a
        plaintext password, so a secret cannot get into the log either.
        """
        with self._locked():
            data = self._read_raw()
            item = data.get(name)
            if not isinstance(item, dict):
                raise UserStoreError(f"no such user: {name}")
            item["salt"] = record.salt.hex()
            item["hash"] = record.digest.hex()
            item["iterations"] = int(record.iterations)
            item["algo"] = "pbkdf2-sha256"
            item["must_change_password"] = bool(record.must_change_password)
            data[name] = item
            self._write_raw(data)

    def set_metadata(
        self,
        name: str,
        *,
        role: str | None = None,
        enabled: bool | None = None,
        rules: tuple[str, ...] | list[str] | None = None,
        must_change_password: bool | None = None,
        provisioned_from: str | None = None,
        totp_required: bool | None = None,
    ) -> None:
        if role is not None and role not in (ROLE_USER, ROLE_ADMIN):
            raise UserStoreError("invalid role")
        with self._locked():
            data = self._read_raw()
            if name not in data:
                raise UserStoreError(f"no such user: {name}")
            item = data[name]
            if role is not None:
                item["role"] = role
            if enabled is not None:
                item["enabled"] = bool(enabled)
            if must_change_password is not None:
                item["must_change_password"] = bool(must_change_password)
            if provisioned_from is not None:
                item["provisioned_from"] = str(provisioned_from)
            if totp_required is not None:
                # We write only the flag: the secret and the recovery codes
                # are touched exclusively by the dedicated methods.
                item["totp_required"] = bool(totp_required)
            if rules is not None:
                clean: list[str] = []
                for value in rules:
                    if not isinstance(value, str) or not value.strip():
                        raise UserStoreError("invalid rule identifier")
                    value = value.strip()
                    if value not in clean:
                        clean.append(value)
                item["rules"] = clean
            data[name] = item
            self._write_raw(data)

    # -- two-factor authentication ---------------------------------------------

    def set_totp_required(self, name: str, required: bool) -> bool:
        """Require or release two-factor sign-in.

        It does not touch the secret, the counter or the recovery codes.
        ``False`` for an unknown user, otherwise ``True``.
        """
        with self._lock, self._locked():
            data = self._read_raw()
            item = data.get(name)
            if not isinstance(item, dict):
                return False
            item["totp_required"] = bool(required)
            data[name] = item
            self._write_raw(data)
            return True

    def enroll_totp(
        self,
        name: str,
        secret: str,
        recovery_hashes: list[str] | tuple[str, ...],
        last_step: int | None = None,
    ) -> bool:
        """Record the TOTP secret and the recovery code hashes.

        It keeps the previous ``totp_required`` flag. With a valid,
        non-negative integer ``last_step`` it records the time step
        already accepted at sign-in, so the code confirming enrollment
        cannot be replayed later; otherwise the counter becomes -1. The
        recovery hashes are stored in canonical (lowercase, 64 hex) form;
        invalid elements are skipped. ``False`` for an unknown user.
        """
        if not isinstance(secret, str) or not secret:
            return False
        if (
            isinstance(last_step, bool)
            or not isinstance(last_step, int)
            or last_step < 0
        ):
            last_step = -1
        with self._lock, self._locked():
            data = self._read_raw()
            item = data.get(name)
            if not isinstance(item, dict):
                return False
            recovery: list[str] = []
            for value in recovery_hashes:
                if not isinstance(value, str):
                    continue
                value = value.lower()
                if _TOTP_RECOVERY_RE.match(value) and value not in recovery:
                    recovery.append(value)
            item["totp_secret"] = secret
            item["totp_last_step"] = last_step
            item["totp_recovery"] = recovery
            data[name] = item
            self._write_raw(data)
            return True

    def verify_totp(
        self, name: str, code: str, now: float | None = None
    ) -> bool:
        """Verify a TOTP code with replay protection.

        Reading, checking and writing run in a single locked section, so
        of two parallel requests at most one can accept the same time
        step. A step not greater than the existing one is invalid. This
        method does not check the ``totp_required`` flag; the caller (the
        HTTP layer) enforces it.
        """
        try:
            with self._lock, self._locked():
                data = self._read_raw()
                item = data.get(name)
                if not isinstance(item, dict) or not item.get("enabled", True):
                    return False
                secret = item.get("totp_secret", "")
                if not isinstance(secret, str) or not secret:
                    return False
                matched = totp_match(secret, code, now=now)
                if matched is None:
                    return False
                try:
                    last_step = int(item.get("totp_last_step", -1))
                except (TypeError, ValueError, OverflowError):
                    last_step = -1
                if matched <= last_step:
                    return False
                item["totp_last_step"] = matched
                data[name] = item
                self._write_raw(data)
                return True
        except UserStoreError as exc:
            log(f"[users] {exc}")
            return False

    def verify_recovery(self, name: str, code: str) -> bool:
        """Verify and single-use delete a recovery code.

        We normalize the code, hash it, then search the stored hashes with
        a constant-time comparison. A failed attempt does not consume the
        code. ``False`` for an unknown or disabled user.
        """
        digest = hash_recovery_code(code)
        try:
            with self._lock, self._locked():
                data = self._read_raw()
                item = data.get(name)
                if not isinstance(item, dict) or not item.get("enabled", True):
                    return False
                stored = item.get("totp_recovery", [])
                if not isinstance(stored, list):
                    return False
                matched = -1
                # We go through every element so that the runtime does not
                # reveal which hash matched (deletion happens at the end).
                for index, value in enumerate(stored):
                    if (
                        isinstance(value, str)
                        and _TOTP_RECOVERY_RE.match(value)
                        and hmac.compare_digest(value, digest)
                    ):
                        matched = index
                if matched < 0:
                    return False
                del stored[matched]
                item["totp_recovery"] = stored
                data[name] = item
                self._write_raw(data)
                return True
        except UserStoreError as exc:
            log(f"[users] {exc}")
            return False

    def reset_totp(self, name: str) -> bool:
        """Delete the TOTP secret, the counter and the recovery codes.

        It deliberately keeps the ``totp_required`` flag: the admin's
        decision that sign-in requires two-factor authentication does not
        change. ``False`` for an unknown user.
        """
        with self._lock, self._locked():
            data = self._read_raw()
            item = data.get(name)
            if not isinstance(item, dict):
                return False
            item["totp_secret"] = ""
            item["totp_last_step"] = -1
            item["totp_recovery"] = []
            data[name] = item
            self._write_raw(data)
            return True

    def remove_rule_everywhere(self, rule_id: str) -> int:
        with self._locked():
            data = self._read_raw()
            changed = 0
            for name, item in data.items():
                values = item.get("rules")
                if isinstance(values, list) and rule_id in values:
                    item["rules"] = [rid for rid in values if rid != rule_id]
                    data[name] = item
                    changed += 1
            if changed:
                self._write_raw(data)
            return changed

    def set_rule_membership(
        self, rule_id: str, user_ids
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Set the rule's direct user assignments.

        For every user in users.json the rule is present exactly when it
        is in the requested set. Other rules, group memberships and other
        fields are unchanged. It works with a single atomic file write
        (0600), and returns the (added, removed) usernames.
        """
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise UserStoreError("missing rule identifier")
        rule_id = rule_id.strip()
        if rule_id == LEGACY_ADMIN_RULE_ID:
            raise UserStoreError(
                "the reserved rule identifier cannot be assigned"
            )
        wanted = set(_clean_str_list(user_ids, "users", maximum=512))
        with self._locked():
            data = self._read_raw()
            missing = wanted - {
                name for name, item in data.items()
                if isinstance(item, dict)
            }
            if missing:
                raise UserStoreError(
                    f"unknown user: {', '.join(sorted(missing))}"
                )
            added: list[str] = []
            removed: list[str] = []
            changed = False
            for name, item in list(data.items()):
                if not isinstance(item, dict):
                    continue
                values = item.get("rules")
                if not isinstance(values, list):
                    values = []
                if name in wanted and rule_id not in values:
                    item["rules"] = [*values, rule_id]
                    data[name] = item
                    added.append(name)
                    changed = True
                elif name not in wanted and rule_id in values:
                    item["rules"] = [
                        rid for rid in values if rid != rule_id
                    ]
                    data[name] = item
                    removed.append(name)
                    changed = True
            if changed:
                self._write_raw(data)
            return tuple(sorted(added)), tuple(sorted(removed))

    def remove(self, name: str) -> bool:
        with self._locked():
            data = self._read_raw()
            if name not in data:
                return False
            del data[name]
            self._write_raw(data)
            return True

    # -- configuration bundle --------------------------------------------------

    @staticmethod
    def _clean_import_records(raw) -> dict:
        """Strict, write-free validation of the users section."""
        if not isinstance(raw, dict):
            raise UserStoreError("the users section must be a JSON object")
        clean: dict[str, dict] = {}
        folded: set[str] = set()
        for name, item in raw.items():
            if not isinstance(name, str) or not USERNAME_RE.match(name):
                raise UserStoreError(f"invalid username: {name!r}")
            if name.casefold() in folded:
                raise UserStoreError(
                    f"{name}: duplicate username (names are case-insensitive)"
                )
            folded.add(name.casefold())
            if not isinstance(item, dict):
                raise UserStoreError(f"{name}: invalid user entry")
            try:
                salt = bytes.fromhex(str(item["salt"]))
                digest = bytes.fromhex(str(item["hash"]))
                iterations = int(item.get("iterations", PBKDF2_ITERATIONS))
                created = int(item.get("created", 0) or 0)
            except (KeyError, TypeError, ValueError) as exc:
                raise UserStoreError(f"{name}: invalid password data") from exc
            # More than 5 million iterations would already be a denial of
            # service.
            # The loader uses at least 10,000 iterations, so a lower count
            # could never verify; more than 5 million would already be a
            # denial of service.
            if len(salt) != 16 or len(digest) != 32 \
                    or not 10_000 <= iterations <= 5_000_000:
                raise UserStoreError(f"{name}: invalid password data")
            if created < 0:
                raise UserStoreError(f"{name}: invalid creation time")
            role = item.get("role", ROLE_USER)
            if role not in (ROLE_USER, ROLE_ADMIN):
                raise UserStoreError(f"{name}: invalid role")
            flags = {}
            for key in ("enabled", "must_change_password", "pending"):
                value = item.get(key, False)
                if not isinstance(value, bool):
                    raise UserStoreError(f"{name}: the {key} field must be true/false")
                flags[key] = value
            if "totp_required" in item:
                if not isinstance(item["totp_required"], bool):
                    raise UserStoreError(
                        f"{name}: the totp_required field must be true/false"
                    )
            secret = item.get("totp_secret", "")
            if not isinstance(secret, str):
                raise UserStoreError(f"{name}: invalid TOTP secret")
            if secret:
                try:
                    _totp_key(secret)
                except ValueError as exc:
                    raise UserStoreError(f"{name}: invalid TOTP secret") from exc
            try:
                last_step = int(item.get("totp_last_step", -1))
            except (TypeError, ValueError, OverflowError) as exc:
                raise UserStoreError(f"{name}: invalid TOTP step") from exc
            if last_step < -1:
                raise UserStoreError(f"{name}: invalid TOTP step")
            recovery_raw = item.get("totp_recovery", [])
            if not isinstance(recovery_raw, list) or any(
                not isinstance(value, str) or not _TOTP_RECOVERY_RE.match(value)
                for value in recovery_raw
            ):
                raise UserStoreError(f"{name}: invalid recovery code")
            email_raw = item.get("email", "")
            email = normalize_email(email_raw, strict=False)
            if email_raw and not email:
                raise UserStoreError(f"{name}: invalid e-mail address")
            if flags["pending"] and (
                role != ROLE_USER or flags["enabled"] or flags["must_change_password"]
            ):
                raise UserStoreError(
                    f"{name}: a pending account cannot be an active admin"
                )
            rules = item.get("rules")
            if rules is not None:
                if not isinstance(rules, list):
                    raise UserStoreError(f"{name}: the rules field must be a list")
                try:
                    rules = list(_clean_str_list(
                        rules, f"{name}.rules", _SERVICE_ID_RE, maximum=64
                    ))
                except ValueError as exc:
                    raise UserStoreError(f"{name}: {exc}") from exc
                if LEGACY_ADMIN_RULE_ID in rules:
                    raise UserStoreError(
                        f"{name}: the reserved rule identifier cannot be imported"
                    )
            record = {
                "salt": salt.hex(),
                "hash": digest.hex(),
                "iterations": iterations,
                "algo": "pbkdf2-sha256",
                "created": created,
                "role": role,
                "enabled": flags["enabled"],
                "must_change_password": flags["must_change_password"],
                "pending": flags["pending"],
                "email": email,
            }
            if rules is not None:
                record["rules"] = rules
            if "totp_secret" in item:
                record["totp_secret"] = secret
            if "totp_required" in item:
                record["totp_required"] = item["totp_required"]
            if "totp_last_step" in item:
                record["totp_last_step"] = last_step
            if "totp_recovery" in item:
                record["totp_recovery"] = list(recovery_raw)
            provisioned = item.get("provisioned_from", "")
            if provisioned:
                if not isinstance(provisioned, str) or len(provisioned) > 128:
                    raise UserStoreError(f"{name}: invalid provisioning marker")
                record["provisioned_from"] = provisioned
            clean[name] = record
        return clean

    def export_records(self, include_marker: bool = False) -> dict:
        """The current user records for the configuration bundle.

        The provisioning marker is left out (DJ-27): it is derived from the
        .env admin password and allows offline guessing of it. The import
        side carries the target installation's own marker over instead
        (``server._carry_provision_marker``). ``include_marker`` is only for
        the private pre-import backup, which must restore the exact state.
        """
        records = self._clean_import_records(self._read_raw())
        if not include_marker:
            for record in records.values():
                record.pop("provisioned_from", None)
        return records

    def validate_import_records(self, raw) -> dict:
        return self._clean_import_records(raw)

    def replace_all(self, raw) -> None:
        """Replace the entire user registry."""
        clean = self._clean_import_records(raw)
        with self._locked():
            self._write_raw(clean)
        with self._lock:
            self._cache = None
            self._cache_key = None

    def reset(self) -> None:
        """Delete the file and clear the in-memory state (factory reset)."""
        with self._lock, self._locked():
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self._cache = None
            self._cache_key = None


# Version 1 markers used this salt in every installation; they are still
# recognised (and replaced by a version 2 marker on the next start).
_PROVISION_SALT = b"hatarvedelem-provision-v1"
_PROVISION_V2 = "v2"


def provision_marker(
    password: str,
    iterations: int = PBKDF2_ITERATIONS,
    salt: bytes | None = None,
) -> str:
    """Marker for recognising that the password from .env is unchanged.

    Thus a password change made through the UI does not "revert" on the
    next container start, while a new password given in .env takes effect.
    Format ``v2$<iterations>$<salt hex>$<digest hex>``: a random salt per
    marker, so markers cannot be matched against a precomputed table and
    are not comparable across installations.
    """
    iterations = max(10_000, int(iterations))
    salt = secrets.token_bytes(16) if salt is None else salt
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return f"{_PROVISION_V2}${iterations}${salt.hex()}${digest.hex()}"


def provision_marker_matches(
    marker: str, password: str, iterations: int = PBKDF2_ITERATIONS
) -> bool:
    """Whether ``marker`` was made from ``password`` (version 1 or 2)."""
    if not isinstance(marker, str) or not marker:
        return False
    parts = marker.split("$")
    if len(parts) == 4 and parts[0] == _PROVISION_V2:
        try:
            rounds = int(parts[1])
            salt = bytes.fromhex(parts[2])
        except ValueError:
            return False
        if not 10_000 <= rounds <= 5_000_000 or len(salt) != 16:
            return False
        expected = provision_marker(password, rounds, salt)
    else:
        expected = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _PROVISION_SALT,
            max(10_000, int(iterations)),
        ).hex()
    return hmac.compare_digest(marker.encode(), expected.encode())


def provision_admin(store: UserStore) -> str:
    """Create or update the admin account configured from Compose.

    Return value: ``disabled``, ``created``, ``updated`` or ``unchanged``.
    In the disabled state it deliberately does not delete a user: the
    previously created account remains and can be managed with the CLI.
    """
    if not ADMIN_ENABLED:
        return "disabled"
    if not ADMIN_USER or not ADMIN_PASSWORD:
        raise UserStoreError(
            "HV_ADMIN_ENABLED is on, but one of HV_ADMIN_USER and "
            "HV_ADMIN_PASSWORD is missing"
        )
    marker = provision_marker(ADMIN_PASSWORD, store.iterations)
    if ADMIN_USER not in store.names():
        store.add(
            ADMIN_USER, ADMIN_PASSWORD, role=ROLE_ADMIN, enabled=True,
            rules=(), must_change_password=True,
        )
        store.set_metadata(ADMIN_USER, provisioned_from=marker)
        return "created"
    record = store.record(ADMIN_USER)
    stored_marker = store.provisioned_from(ADMIN_USER)
    if not stored_marker:
        # Old (marker-less) entry. If the seed password is still in effect,
        # it must be changed on first sign-in; if not, the password given
        # in .env is authoritative.
        if store.verify(ADMIN_USER, ADMIN_PASSWORD):
            store.set_metadata(
                ADMIN_USER, role=ROLE_ADMIN, enabled=True,
                must_change_password=True, provisioned_from=marker,
            )
        else:
            store.set_password(
                ADMIN_USER, ADMIN_PASSWORD, must_change_password=True
            )
            store.set_metadata(
                ADMIN_USER, role=ROLE_ADMIN, enabled=True,
                provisioned_from=marker,
            )
        return "updated"
    changed = False
    if record is not None and (not record.is_admin or not record.enabled):
        store.set_metadata(ADMIN_USER, role=ROLE_ADMIN, enabled=True)
        changed = True
    if not provision_marker_matches(
        stored_marker, ADMIN_PASSWORD, store.iterations
    ):
        # The password changed in .env: that is authoritative, and it must
        # also be changed on first sign-in.
        store.set_password(ADMIN_USER, ADMIN_PASSWORD, must_change_password=True)
        store.set_metadata(ADMIN_USER, role=ROLE_ADMIN, enabled=True,
                           provisioned_from=marker)
        return "updated"
    if not stored_marker.startswith(_PROVISION_V2 + "$"):
        # Same password, old (global salt) marker: only the marker changes.
        store.set_metadata(ADMIN_USER, provisioned_from=marker)
    return "updated" if changed else "unchanged"


# ---------------------------------------------------------------- sessions

# The session termination reasons and the explanation shown to the user.
END_REASONS: dict[str, str] = {
    "logout": "Kiléptél a portálról.",
    "expired": "Lejárt a munkamenet ideje.",
    "replaced": (
        "Ugyanerről az IP-címről új belépés történt, ezért ez a munkamenet "
        "lejárt. Egyszerre IP-címenként csak egy munkamenet lehet aktív."
    ),
    "ip_changed": (
        "A nyilvános IP-címed megváltozott, ezért a munkamenet érvénytelenné "
        "vált. Lépj be újra."
    ),
    "revoked": "Az adminisztrátor visszavonta a hozzáférést.",
    "password_changed": (
        "A jelszavad megváltozott, ezért a többi munkamenet lezárult."
    ),
    "disabled": "A fiókot kikapcsolták.",
    "admin_terminated": "Az adminisztrátor lezárta a munkamenetet.",
    "fail2ban": (
        "A forrás IP-címet a fail2ban tiltotta le a túl sok sikertelen "
        "belépési kísérlet miatt."
    ),
    "server_restart": "A portál újraindult, ezért a munkamenetek törlődtek.",
    "firewall_reset": (
        "A tűzfal újratöltődött, ezért a munkamenet lezárult. Lépj be újra."
    ),
}


@dataclass
class Session:
    token: str
    user: str
    ip: str
    created: float
    expires: float
    tcp: tuple[int, ...] = ()
    udp: tuple[int, ...] = ()
    icmp: bool = False
    full: bool = False
    authorized: bool = False
    role: str = ROLE_USER
    rule: str = ""
    rule_label: str = ""
    logged_in: float = 0.0
    ua: str = ""
    sid: str = ""
    # On revocation the matching (forward or input) sets must be cleaned
    # up, therefore the session keeps the grant's direction. For a
    # collection rule this may also be "mixed": the actual per-direction
    # breakdown is in grant_parts, direction is only a display/audit value.
    direction: str = "forward"
    # The Ports parts issued at grant time, per direction. If empty, the
    # old behaviour applies: a single grant from the ports fields.
    grant_parts: tuple[Ports, ...] = ()
    # The identifiers of the selected rules and the full selection. The
    # ``rule``/``rule_label`` are the compatibility view of the first
    # selection.
    rules: tuple[str, ...] = ()
    rule_parts: tuple[RuleSelection, ...] = ()

    @property
    def expires_in(self) -> int:
        return max(0, int(self.expires - time.time()))

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    @property
    def grants(self) -> tuple[Ports, ...]:
        """The per-direction grants needed for revocation."""
        return self.grant_parts or (self.ports,)

    def selections(self) -> tuple[RuleSelection, ...]:
        """The session's selections; the old, single-rule form is also supported."""
        if self.rule_parts:
            return self.rule_parts
        if self.rule:
            return (
                RuleSelection(self.rule, self.rule_label, self.grants),
            )
        return ()

    @property
    def ports(self) -> Ports:
        # "mixed" is only a display value; Ports always knows a single
        # direction. For display we pass the union as forward.
        direction = "input" if self.direction == "input" else "forward"
        return Ports(
            self.tcp, self.udp, self.icmp, self.full, direction
        )

    def snapshot(self) -> dict:
        """For the admin list: raw data, the UI computes with it."""
        if self.rules:
            selected_rules = list(self.rules)
        elif self.rule:
            selected_rules = [self.rule]
        else:
            selected_rules = []
        if self.rule_parts:
            selected_labels = [part.label for part in self.rule_parts]
        elif self.rule:
            selected_labels = [self.rule_label or self.rule]
        else:
            selected_labels = []
        return {
            "id": self.sid,
            "user": self.user,
            "role": self.role,
            "ip": self.ip,
            "authorized": self.authorized,
            "rule": self.rule,
            "rule_label": self.rule_label,
            "selected_rules": selected_rules,
            "selected_rule_labels": selected_labels,
            "tcp": list(self.tcp),
            "udp": list(self.udp),
            "icmp": self.icmp,
            "full": self.full,
            "direction": self.direction,
            "grants": [
                {
                    "direction": part.direction,
                    "tcp": list(part.tcp),
                    "udp": list(part.udp),
                    "icmp": part.icmp,
                    "full": part.full,
                }
                for part in self.grants
            ],
            "ports_label": self.ports.label(),
            "domains": list(dict.fromkeys(
                name for part in self.selections() for name in part.domains
            )),
            "logged_in": int(self.logged_in or self.created),
            "created": int(self.created),
            "expires": int(self.expires),
            "expires_in": self.expires_in,
            "ttl": max(0, int(self.expires - self.created)),
            "ua": self.ua,
        }


@dataclass
class _PendingRevocation:
    """A failed firewall revocation in the bounded retry queue."""

    ip: str
    grants: tuple[Ports, ...]
    discover: bool
    attempts: int = 0
    next_at: float = 0.0
    first_failed: float = 0.0
    last_error: str = ""
    in_flight: bool = False


class SessionManager:
    """IP-bound, in-memory sessions + firewall grants.

    Sign-in is two-step: after checking the password the session still
    grants no network access. The client then selects a rule and a
    duration; only then does the forward chain open, to the rule's ports.
    Host SSH (TCP 22) opens only if the selected host (input) rule assigned
    to the user explicitly contains TCP 22; full-access and collection
    rules do not grant it separately.

    Session expiry and the nftables element timeout are the same value. If
    the process stops, the kernel deletes the grant by itself at the
    timeout.

    On failure a firewall revocation is not lost: it goes into a
    bounded-size, thread-safe queue, and the cleaner thread retries it
    with increasing delay. The session ends immediately in this case too;
    the queue only cleans up the grant left in the kernel.
    """

    # After the first failure 5 s, then 15, 60, 300, and at most 600 s.
    PENDING_BACKOFF = (5, 15, 60, 300, 600)
    # The queue size is bounded; when full it cannot grow further even with
    # loud logging/audit (the failure remains a failure, we do not report
    # success).
    PENDING_LIMIT = 4096
    # The first failure is always logged; of the retries only every tenth,
    # so that a persistent nft error does not flood the log every 5 s.
    PENDING_AUDIT_EVERY = 10

    def __init__(
        self,
        firewall: Firewall,
        ttl: int = SESSION_TTL,
        pending_ttl: int = AUTH_TTL,
        audit: AuditLog | None = None,
        rule_check=None,
        guard_check=None,
        state_check=None,
    ) -> None:
        self.firewall = firewall
        self.ttl = max(MIN_TTL, min(int(ttl), MAX_TTL))
        self.pending_ttl = max(1, int(pending_ttl))
        self.audit = audit
        # Callback: whether the rule still belongs to the user at the moment
        # of the decision. This closes the race where the admin would allow
        # a request arriving after deleting the rule but before the grant.
        self.rule_check = rule_check
        # Callback: whether the host (input) port guard set is healthy. If
        # the caller supplies it, an input-direction grant may be issued
        # only if this returns true. The default None keeps the previous
        # behaviour for callers that do not use a port guard.
        self.guard_check = guard_check
        # Callback: whether the kernel table is the one the portal last
        # synchronized (block chains, bans, host guards). While it returns
        # false, no grant is issued: a reloaded bare table would let a new
        # grant bypass the admin's block entries.
        self.state_check = state_check
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        # IP -> (timestamp, reason): the explanation of the most recently
        # ended session.
        self._last_end: dict[str, tuple[float, str]] = {}
        # (IP, exact grant tuple) -> pending revocation. Separate lock:
        # _revoke_access() is also callable under the session lock
        # (authorize).
        self._pending_lock = threading.Lock()
        self._pending_revocations: dict[
            tuple[str, tuple[Ports, ...]], _PendingRevocation
        ] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- internal --------------------------------------------------------------

    def _remember_end_locked(self, ip: str, reason: str, now: float | None = None) -> None:
        self._last_end[ip] = (time.time() if now is None else now, reason)
        # Do not grow without bound: we drop the oldest entries.
        if len(self._last_end) > 2048:
            cutoff = time.time() - 86400
            for key, (when, _) in list(self._last_end.items()):
                if when < cutoff:
                    del self._last_end[key]

    def _write_audit(self, event: str, **fields) -> None:
        """Optional logging: a failure must not block the operation either."""
        if self.audit is None:
            return
        try:
            self.audit.write(event, **fields)
        except Exception as exc:  # logging should never block
            log(f"[audit] writing {event} failed: {exc}")

    def _drop_ip_locked(self, ip: str, reason: str = "replaced") -> list[Session]:
        dropped: list[Session] = []
        for token, session in list(self._sessions.items()):
            if session.ip == ip:
                del self._sessions[token]
                dropped.append(session)
        if dropped:
            self._remember_end_locked(ip, reason)
        return dropped

    def last_end(self, ip: str) -> dict | None:
        """The reason of the most recently ended session for the given IP (if any)."""
        try:
            ip = normalize_ip(ip)
        except ValueError:
            return None
        with self._lock:
            entry = self._last_end.get(ip)
        if entry is None:
            return None
        when, reason = entry
        return {
            "at": int(when),
            "reason": reason,
            "message": END_REASONS.get(reason, "A munkamenet megszűnt."),
        }

    def active_sessions(self) -> list[dict]:
        """A snapshot of every live session (for the admin UI)."""
        now = time.time()
        with self._lock:
            current = [
                session for session in self._sessions.values()
                if session.expires > now
            ]
        current.sort(key=lambda item: (not item.authorized, item.logged_in or item.created))
        return [session.snapshot() for session in current]

    def allows_domain(self, ip: str, name: str) -> bool:
        """Whether the IP's live session allows the proxy entry (proxy gate).

        Only an explicitly selected domain rule counts: full access and the
        admin role do not open a domain either.
        """
        return self.domain_user(ip, name) is not None

    def domain_user(self, ip: str, name: str) -> str | None:
        """The user of allows_domain()'s session (or None)."""
        now = time.time()
        with self._lock:
            return next(
                (
                    session.user for session in self._sessions.values()
                    if session.ip == ip and session.authorized
                    and session.expires > now
                    and any(
                        name in part.domains for part in session.selections()
                    )
                ),
                None,
            )

    def _active_authorized_ips_locked(self) -> set[str]:
        return {
            session.ip
            for session in self._sessions.values()
            if session.authorized
        }

    @staticmethod
    def _grant_tuple(grants) -> tuple[Ports, ...]:
        """The exact identifier of the revocation; duplicates are dropped."""
        return tuple(dict.fromkeys(grants or ()))

    def pending_count(self) -> int:
        """The number of pending (still failed) revocations."""
        with self._pending_lock:
            return len(self._pending_revocations)

    def _pending_delay(self, attempts: int) -> int:
        """The delay of the next retry in seconds."""
        index = max(0, min(int(attempts), len(self.PENDING_BACKOFF) - 1))
        return self.PENDING_BACKOFF[index]

    def _queue_pending_locked(
        self,
        ip: str,
        grants: tuple[Ports, ...],
        discover: bool,
        now: float,
        error: Exception,
    ) -> tuple[_PendingRevocation | None, bool, bool]:
        """Add a failed revocation to the queue.

        Return: (entry, is-new, is-full). For an existing (IP, grant) key we
        only update the last error and the discovery need; thus a repeated
        call neither grows the queue nor logs again.
        """
        key = (ip, grants)
        entry = self._pending_revocations.get(key)
        if entry is not None:
            entry.discover = entry.discover or discover
            entry.last_error = str(error)
            return entry, False, False
        if len(self._pending_revocations) >= self.PENDING_LIMIT:
            return None, False, True
        entry = _PendingRevocation(
            ip=ip,
            grants=grants,
            discover=discover,
            next_at=now + self._pending_delay(0),
            first_failed=now,
            last_error=str(error),
        )
        self._pending_revocations[key] = entry
        return entry, True, False

    def _queue_pending(
        self,
        ip: str,
        grants: tuple[Ports, ...],
        discover: bool,
        error: Exception,
    ) -> tuple[_PendingRevocation | None, bool, bool]:
        with self._pending_lock:
            result = self._queue_pending_locked(
                ip, grants, discover, time.time(), error
            )
        if result[2]:
            # Fail-closed: the revocation failed and the queue is also full.
            # We do not claim success; we log and audit loudly.
            log(
                f"[firewall] ERROR: the pending revocations queue is full "
                f"({self.PENDING_LIMIT}); the grant of {ip} may remain in "
                "effect until the kernel TTL"
            )
            self._write_audit(
                "firewall_error",
                ip=ip,
                operation="revoke_all_ledger_full",
                limit=int(self.PENDING_LIMIT),
                reason=str(error),
            )
        return result

    def _clear_pending_keys(
        self, keys: list[tuple[str, tuple[Ports, ...]]]
    ) -> None:
        if not keys:
            return
        with self._pending_lock:
            for key in keys:
                self._pending_revocations.pop(key, None)

    def _pending_for_ip(
        self, ip: str
    ) -> list[tuple[tuple[str, tuple[Ports, ...]], _PendingRevocation]]:
        with self._pending_lock:
            return [
                (key, entry)
                for key, entry in self._pending_revocations.items()
                if entry.ip == ip
            ]

    def _clear_pending_after_success(
        self, ip: str, grants: tuple[Ports, ...], discover: bool
    ) -> None:
        """Delete the covered pending entry after a successful revocation.

        If the pending entry also requested forward discovery, a grant-based
        (non-discovering) successful deletion does not necessarily cover all
        orphaned elements; in that case the entry remains and is cleaned up
        later by a full discovery.
        """
        with self._pending_lock:
            entry = self._pending_revocations.get((ip, grants))
            if entry is not None and (discover or not entry.discover):
                del self._pending_revocations[(ip, grants)]

    def _revoke_exact(self, ip: str, grants) -> None:
        """Exact element-level deletion, compatible with the old firewall fakes.

        We use the real :class:`Firewall`'s ``revoke_exact`` method, which
        also deletes the ``full`` and ICMP elements. The old tests' simple
        fake firewalls only know ``revoke_all``; for them ``only_grants=True``
        is the closest compatible operation.
        """
        revoke_exact = getattr(self.firewall, "revoke_exact", None)
        if revoke_exact is None:
            self.firewall.revoke_all(ip, grants, only_grants=True)
        else:
            revoke_exact(ip, grants)

    def _revoke_access(
        self,
        ip: str,
        grants=(),
        discover: bool = False,
        *,
        exact: bool = False,
        only_grants: bool = False,
    ) -> bool:
        """Revoke access; on failure we retry from the queue.

        The return value indicates the success of the firewall operation.
        Removing the session is the caller's job and happens on failure too;
        thus no session remains referring to a grant that a later retry may
        remove. We perform the conntrack deletion on failure too, because
        existing connections must be torn down immediately.

        With ``only_grants=True`` we delete only the given grant elements
        (see :meth:`Firewall.revoke_all`), and we perform no conntrack flush
        on success or failure either. In that case an active session belongs
        to the IP, which may share the conntrack entries; the flush would
        also break its live connections.

        With ``exact=True`` :meth:`Firewall.revoke_exact` runs, which deletes
        the ``full`` and ICMP elements exactly according to the given grants
        too. No conntrack flush happens then on success or failure either:
        the caller decides what (partial) connection cleanup is needed. Error
        handling and enqueueing are the same as on the other paths.
        """
        grants = self._grant_tuple(grants)
        try:
            if exact:
                self._revoke_exact(ip, grants)
            elif discover:
                self.firewall.revoke_all(ip, grants, discover=True)
            elif only_grants:
                self.firewall.revoke_all(ip, grants, only_grants=True)
            else:
                self.firewall.revoke_all(ip, grants)
        except FirewallError as exc:
            log(f"[firewall] revoking {ip} failed: {exc}")
            _entry, is_new, _overflow = self._queue_pending(
                ip, grants, discover, exc
            )
            if is_new:
                # We audit the first failure immediately; of the retries only
                # every PENDING_AUDIT_EVERY-th.
                self._write_audit(
                    "firewall_error",
                    ip=ip,
                    operation="revoke_all",
                    reason=str(exc),
                    pending=True,
                    attempts=0,
                )
            # With only_grants/exact there is deliberately NO conntrack flush:
            # the connections of the active session belonging to the IP would
            # also break. The pending entry contains only the exact,
            # non-overlapping grants, so the retry does not touch the active
            # session either.
            if not only_grants and not exact:
                conntrack_flush(ip, self.audit)
            return False
        self._clear_pending_after_success(ip, grants, discover)
        if not only_grants and not exact:
            conntrack_flush(ip, self.audit)
        return True

    @staticmethod
    def _subtract_grants(
        grants: tuple[Ports, ...], covered: tuple[Ports, ...]
    ) -> tuple[Ports, ...]:
        """The grants to revoke minus the grants of the active sessions.

        ``covered`` is the union of the grants of the active, authorized
        sessions belonging to the same IP. Only elements that no active
        session needs remain in the remainder. The computation is at
        kernel-element level: a ``full`` grant uses the single element of
        ``allowed_v4``, and port grants use the elements of
        ``allowed_tcp``/``allowed_udp``. Therefore an old ``full`` grant
        remains only if an active session is also full-access in the same
        direction; if the active session allows only ports, the old
        ``allowed_v4`` element can be deleted without affecting the active
        session's access.

        An active ``full`` grant covers port and ICMP access in that
        direction, but does not replace the history of kernel elements: the
        departing ``allowed_tcp``/``allowed_udp``/``allowed_icmp`` element
        belonging to a non-``full`` part still exists, while it no longer
        appears in the session's merged ``grant_parts``. Therefore such a
        part must be kept in the remainder so that the exact deletion
        (``revoke_exact``) removes it; otherwise it could surface again
        later, when the full access is revoked. Only the departing ``full``
        part can be omitted if an active ``full`` covers it in the same
        direction.
        """
        active_tcp: dict[str, set[int]] = {}
        active_udp: dict[str, set[int]] = {}
        active_icmp: set[str] = set()
        active_full: set[str] = set()
        for part in covered:
            direction = part.direction
            if part.full:
                active_full.add(direction)
                continue
            active_tcp.setdefault(direction, set()).update(part.tcp)
            active_udp.setdefault(direction, set()).update(part.udp)
            if part.icmp:
                active_icmp.add(direction)
        remainder: list[Ports] = []
        for part in grants:
            direction = part.direction
            if direction in active_full and part.full:
                # The active full access in the same direction covers the
                # departing full access's kernel element (allowed_v4),
                # therefore it does not need separate deletion. Non-full
                # parts, however, must be kept according to the docstring
                # above.
                continue
            if part.full:
                remainder.append(part)
                continue
            tcp = tuple(
                port
                for port in part.tcp
                if port not in active_tcp.get(direction, ())
            )
            udp = tuple(
                port
                for port in part.udp
                if port not in active_udp.get(direction, ())
            )
            icmp = part.icmp and direction not in active_icmp
            if tcp or udp or icmp:
                remainder.append(
                    Ports(tcp=tcp, udp=udp, icmp=icmp, direction=direction)
                )
        return tuple(dict.fromkeys(remainder))

    def _revoke_access_locked(
        self, ip: str, grants, now: float | None = None
    ) -> bool:
        """Revoke access while holding the session lock.

        The caller must hold the ``self._lock`` lock. The firewall mutation
        runs under the same lock as session removal, so a parallel
        ``authorize()`` cannot slip between removal and revocation, and
        cannot lose its new grant.

        If an active, authorized session still belongs to the IP after the
        revocation, we delete only those parts of the old grants that the
        active session does not need (``_subtract_grants``). With such a
        partial deletion we do not flush conntrack, because that would also
        break the active session's live connections. If the remaining
        session covers every element, no firewall call is made at all.

        Locking invariant: ``self._lock`` -> firewall -> ``_pending_lock``
        (leaf lock); the reverse order is forbidden.
        """
        if now is None:
            now = time.time()
        grants = self._grant_tuple(grants)
        active_grants = tuple(
            part
            for session in self._sessions.values()
            if session.ip == ip
            and session.authorized
            and session.expires > now
            for part in session.grants
        )
        if active_grants:
            remainder = self._subtract_grants(grants, active_grants)
            if not remainder:
                # The remaining session needs every affected element; there
                # is nothing to delete, and conntrack must not be touched
                # either.
                return True
            # Exact element-level deletion: the full (allowed_v4) and ICMP
            # elements also disappear if the departing grant contained them,
            # while the remaining port grants stay untouched.
            return self._revoke_access(ip, remainder, exact=True)
        return self._revoke_access(ip, grants)

    def _remove_selections_locked(
        self, sessions, rule_ids, reason: str, now: float
    ) -> int:
        """Remove the given rule selections from the sessions.

        The caller must hold the ``self._lock`` lock. Only the selections
        among ``rule_ids`` disappear from a session; the other selections'
        grants remain in effect. If no selection remains, the session ends
        completely. With a partial removal, the elements brought by the
        departing selection and not covered by another selection are deleted
        by ``revoke_exact``, and then only the entries belonging to the
        departing ports disappear from conntrack too.

        On a firewall error, fail-closed: the session ends, and the full old
        union is revoked (enqueued if necessary). Every affected (partially
        or fully removed) session counts in the return value.

        We do not partially refresh an expired session: reissuing the
        remaining selections' grants would give the expired access back for
        a second. Instead it goes down the full-removal path.

        The elements of ``sessions`` may be ``(token, session)`` pairs or
        ``Session`` objects.
        """
        wanted = (
            {rule_ids} if isinstance(rule_ids, str) else set(rule_ids or ())
        )
        touched = 0
        for item in list(sessions):
            if isinstance(item, tuple):
                token, session = item
            else:
                token, session = item.token, item
            if self._sessions.get(token) is not session:
                continue
            old_parts = session.selections()
            kept = tuple(
                part for part in old_parts if part.rule_id not in wanted
            )
            if kept == old_parts:
                continue
            touched += 1
            old_union = union_grants(
                grant
                for selection in old_parts
                for grant in selection.grants
            )
            if session.expires <= now:
                # An expired session must not get anything back: a partial
                # refresh would reissue the remaining selections' grants, so
                # the expired access would live for one more second. Instead,
                # full removal, as in the empty ``kept`` case.
                del self._sessions[token]
                self._remember_end_locked(session.ip, reason, now)
                self._revoke_access_locked(
                    session.ip, old_union, now=now
                )
                continue
            if not kept:
                del self._sessions[token]
                self._remember_end_locked(session.ip, reason, now)
                self._revoke_access_locked(
                    session.ip, old_union, now=now
                )
                continue
            new_union = union_grants(
                grant
                for selection in kept
                for grant in selection.grants
            )
            removed = self._subtract_grants(old_union, new_union)
            # The dataclass is deliberately mutable: expiry stays unchanged,
            # only the selections and the fields derived from them refresh.
            session.rule_parts = kept
            session.rules = tuple(part.rule_id for part in kept)
            session.rule = kept[0].rule_id
            session.rule_label = kept[0].label
            session.grant_parts = new_union
            session.tcp = tuple(
                sorted({port for part in new_union for port in part.tcp})
            )
            session.udp = tuple(
                sorted({port for part in new_union for port in part.udp})
            )
            session.icmp = any(part.icmp for part in new_union)
            session.full = any(part.full for part in new_union)
            directions = {part.direction for part in new_union}
            session.direction = (
                next(iter(directions)) if len(directions) == 1
                else ("mixed" if directions else "forward")
            )
            if not removed:
                continue
            remaining_ttl = max(1, int(session.expires - now))
            try:
                self._revoke_exact(session.ip, removed)
                # If the departing selection granted full access, the
                # remaining ports were not necessarily separate kernel
                # elements until now (allowed_v4 covered them). After
                # deleting the departing allowed_v4, the remaining union must
                # therefore be reissued, otherwise the session would live on
                # paper, but its ports would not be allowed.
                self.firewall.grant_all(
                    session.ip, new_union, remaining_ttl
                )
            except FirewallError as exc:
                log(
                    f"[firewall] revoking the selection of {session.ip} "
                    f"failed: {exc}"
                )
                del self._sessions[token]
                self._remember_end_locked(
                    session.ip, "revoke_failed", now
                )
                self._write_audit(
                    "firewall_error",
                    ip=session.ip,
                    operation="revoke_selection",
                    reason=str(exc),
                )
                self._revoke_access_locked(
                    session.ip, old_union, now=now
                )
            else:
                conntrack_flush_removed(
                    session.ip, removed, new_union, self.audit
                )
        return touched

    def _retry_pending_revocations(self, now: float) -> int:
        """Retry expired revocations; delete the successful ones.

        We perform the firewall call under the session lock, so that a
        parallel authorize() cannot issue a new grant for the same IP during
        the revocation.

        If an active, authorized session belongs to the IP, we do not
        postpone the whole entry: we compute the union of the active
        sessions' grants, and delete only those elements of the old grants
        that the new session does not need (``_subtract_grants``). The
        overlapping elements belong to the new session's lifecycle; its
        revocation deletes them. If the remainder is empty, the entry is
        deleted. With such a partial deletion we do not flush conntrack,
        because that would also break the new session's live connections.

        The ``discover=True`` entry (the ``revoke_ip``/fail2ban path) runs a
        full discovery only if there is no active session for the IP. With
        an active session, discovery would delete its elements too, so we
        delete only the non-overlapping exact grants, and the entry stays in
        the queue marked ``discover=True``. When the session ends, discovery
        runs again and cleans up the orphaned elements too.
        """
        due: list[
            tuple[tuple[str, tuple[Ports, ...]], _PendingRevocation]
        ] = []
        with self._pending_lock:
            for key, entry in self._pending_revocations.items():
                if entry.in_flight or entry.next_at > now:
                    continue
                entry.in_flight = True
                due.append((key, entry))
        if not due:
            return 0
        retried = 0
        for key, entry in due:
            retried += 1
            retry_audit = False
            # Locking invariant: computing the grant union, the
            # firewall.revoke_all() mutation AND conntrack_flush() all run
            # under the session lock. Thus a parallel authorize() cannot slip
            # between the decision and the deletion: it cannot get a grant
            # that the partial deletion or the discovery would immediately
            # remove. The conntrack flush deliberately stays under the lock,
            # so that we do not break the connections of a new session
            # authorizing after the mutation. _pending_lock is a leaf lock:
            # we never acquire it in reverse order after _lock.
            with self._lock:
                active_grants = tuple(
                    part
                    for session in self._sessions.values()
                    if session.ip == entry.ip
                    and session.authorized
                    and session.expires > now
                    for part in session.grants
                )
                partial = bool(active_grants)
                if entry.discover and not partial:
                    revoke_grants = entry.grants
                    discover_now = True
                else:
                    revoke_grants = self._subtract_grants(
                        entry.grants, active_grants
                    )
                    discover_now = False
                if not revoke_grants and not discover_now and (
                    entry.discover or partial
                ):
                    # There is no non-overlapping element. For a
                    # non-discovering entry the overlapping elements are
                    # deleted by the active session's lifecycle, so the entry
                    # ends. For a discovering entry the full discovery is
                    # still pending, so it stays in the queue until the
                    # session ends. If there is no active session and the
                    # grant list is empty, the call below runs: deletion of
                    # the full/ICMP/MAC elements must also be retried.
                    with self._pending_lock:
                        current = self._pending_revocations.get(key)
                        if current is entry:
                            if entry.discover:
                                entry.in_flight = False
                                entry.next_at = now + self._pending_delay(
                                    entry.attempts
                                )
                            else:
                                del self._pending_revocations[key]
                    continue
                try:
                    if discover_now:
                        self.firewall.revoke_all(
                            entry.ip, revoke_grants, discover=True
                        )
                    elif partial:
                        # We delete only the old, non-overlapping elements
                        # with an exact, element-level deletion. We do not
                        # touch the ports covered by the remaining active
                        # grants or the MAC binding; the departing full/ICMP
                        # element, however, thus does not stay in the kernel.
                        self._revoke_exact(entry.ip, revoke_grants)
                    else:
                        self.firewall.revoke_all(entry.ip, revoke_grants)
                except FirewallError as exc:
                    with self._pending_lock:
                        current = self._pending_revocations.get(key)
                        if current is entry:
                            entry.in_flight = False
                            entry.attempts += 1
                            entry.last_error = str(exc)
                            entry.next_at = now + self._pending_delay(
                                entry.attempts
                            )
                            if not entry.discover:
                                entry.grants = revoke_grants
                            retry_audit = (
                                entry.attempts % self.PENDING_AUDIT_EVERY == 0
                            )
                    if not partial:
                        conntrack_flush(entry.ip, self.audit)
                    if retry_audit:
                        self._write_audit(
                            "firewall_error",
                            ip=entry.ip,
                            operation="revoke_all_retry",
                            reason=str(exc),
                            pending=True,
                            attempts=entry.attempts,
                        )
                else:
                    with self._pending_lock:
                        current = self._pending_revocations.get(key)
                        if current is entry:
                            if entry.discover and partial:
                                # The exact grants are deleted; the full
                                # discovery waits for the end of the session.
                                entry.in_flight = False
                                entry.next_at = now + self._pending_delay(
                                    entry.attempts
                                )
                            else:
                                del self._pending_revocations[key]
                    if not partial:
                        conntrack_flush(entry.ip, self.audit)
                        log(
                            f"[firewall] the pending revocation of {entry.ip} "
                            "finally succeeded"
                        )
        return retried

    # -- public operations -----------------------------------------------------

    def login(
        self, user: str, ip: str, role: str = ROLE_USER, ua: str = ""
    ) -> Session:
        """After the password: NO network access yet, only a selection."""
        ip = normalize_ip(ip)
        if not is_ipv4(ip):
            raise FirewallError("sign-in is possible only from an IPv4 address")
        if role not in (ROLE_USER, ROLE_ADMIN):
            role = ROLE_USER
        now = time.time()
        revoked_access = False
        with self._lock:
            previous = [
                session
                for session in self._sessions.values()
                if session.ip == ip
            ]
            previous_grants = [
                part
                for session in previous
                if session.authorized
                for part in session.grants
            ]
            if previous_grants:
                # We revoke the old access first. If this fails, the
                # revocation may run later from the queue, therefore the old
                # session must not remain referring to a grant: we drop it,
                # and the new sign-in is not created either (fail-closed).
                if not self._revoke_access(ip, previous_grants):
                    self._drop_ip_locked(ip, "revoke_failed")
                    raise FirewallError(
                        "revoking the previous access failed; "
                        "sign in again"
                    )
                revoked_access = True
            # There should be one session per IP. We remember the previous
            # session's termination reason for the UI.
            dropped = self._drop_ip_locked(ip, "replaced")
            session = Session(
                token=secrets.token_urlsafe(32),
                user=user,
                ip=ip,
                created=now,
                expires=now + self.pending_ttl,
                authorized=False,
                role=role,
                logged_in=now,
                ua=(ua or "")[:300],
                sid=secrets.token_hex(8),
            )
            self._sessions[session.token] = session
        # Every session displaced from the same IP (including the pending
        # one) gets a separate event; the fact of the access revocation
        # remains the aggregated access_revoked event.
        for old in dropped:
            self._write_audit(
                "session_replaced",
                old_user=old.user,
                new_user=user,
                ip=ip,
                old_sid=old.sid,
                old_authorized=old.authorized,
                old_rule=old.rule,
                reason="new_login_same_ip",
            )
        if revoked_access:
            # _revoke_access has already performed the conntrack deletion.
            self._write_audit(
                "access_revoked",
                user=user,
                ip=ip,
                reason="new sign-in from the same IP",
            )
        return session

    def validate(self, token: str, ip: str) -> Session | None:
        if not token:
            return None
        try:
            ip = normalize_ip(ip)
        except ValueError:
            return None
        now = time.time()
        revoke: Session | None = None
        ip_changed: Session | None = None
        expired: Session | None = None
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if session.ip != ip:
                # The cookie arrived from another IP: the session is IP-bound.
                # We also terminate the session and its firewall grant; we do
                # not leave it in effect until the TTL.
                del self._sessions[token]
                self._remember_end_locked(session.ip, "ip_changed", now)
                ip_changed = session
                if session.authorized:
                    revoke = session
            elif session.expires <= now:
                del self._sessions[token]
                self._remember_end_locked(ip, "expired", now)
                expired = session
                if session.authorized:
                    revoke = session
            else:
                return session
            if revoke is not None:
                # The revocation runs under the same lock as session
                # deletion, so that a parallel authorize() starting from the
                # same IP cannot slip between the two and lose its freshly
                # issued grant.
                self._revoke_access_locked(
                    revoke.ip, revoke.grants, now=now
                )
        if ip_changed is not None:
            self._write_audit(
                "session_ip_changed",
                user=ip_changed.user,
                sid=ip_changed.sid,
                session_ip=ip_changed.ip,
                request_ip=ip,
                authorized=ip_changed.authorized,
                rule=ip_changed.rule,
            )
        if expired is not None:
            self._write_audit(
                "session_expired",
                user=expired.user,
                sid=expired.sid,
                ip=expired.ip,
                authorized=expired.authorized,
                rule=expired.rule,
                rule_label=expired.rule_label,
                ports=expired.ports.label(),
                duration=max(0, int(now - expired.created)),
                reason="expired",
            )
        return None

    def authorize(
        self, token: str, ip: str, rules, ttl: int
    ) -> Session:
        """Validate the selected rule(s) and duration.

        ``rules`` may be a single :class:`Rule` (compatibility for old
        callers) or a non-empty sequence of rules. The session receives the
        union of the selected rules' grants; duplicates by identifier are
        dropped.
        """
        ip = normalize_ip(ip)
        if not is_ipv4(ip):
            raise AccessError("access can be requested only from an IPv4 address")
        if isinstance(rules, Rule):
            candidates = [rules]
        elif rules is None or isinstance(rules, (str, bytes)):
            raise AccessError("invalid access rule")
        else:
            try:
                candidates = list(rules)
            except TypeError:
                raise AccessError("invalid access rule")
        if not candidates or not all(
            isinstance(rule, Rule) for rule in candidates
        ):
            raise AccessError("invalid access rule")
        # Deduplication by identifier, in order of first occurrence.
        selected: list[Rule] = []
        seen_ids: set[str] = set()
        for rule in candidates:
            if rule.id in seen_ids:
                continue
            seen_ids.add(rule.id)
            selected.append(rule)
        rules = tuple(selected)

        # Every selected rule must grant access (fail-closed), and the
        # requested TTL must not exceed the strictest rule's max_ttl. V1: a
        # single session TTL, we reject the request instead of truncating.
        for rule in rules:
            grants = rule.grants
            if not rule.session_domains and (not grants or all(
                not (part.tcp or part.udp or part.icmp or part.full)
                for part in grants
            )):
                raise AccessError("this rule does not grant access")
        ttl = validate_ttl(ttl)
        if len(rules) == 1:
            rule = rules[0]
            if ttl > rule.max_ttl:
                raise AccessError(
                    f"this rule allows at most "
                    f"{format_duration(rule.max_ttl)} "
                    "of access"
                )
        else:
            strictest = min(rules, key=lambda rule: rule.max_ttl)
            if ttl > strictest.max_ttl:
                raise AccessError(
                    f"because of the {strictest.label} rule, at most "
                    f"{format_duration(strictest.max_ttl)}"
                )

        rule_parts = tuple(
            RuleSelection(
                rule.id, rule.label, rule.grants, rule.session_domains,
                rule.service_refs, rule.service_domains,
            )
            for rule in rules
        )
        new_union = union_grants(
            grant
            for selection in rule_parts
            for grant in selection.grants
        )
        # For display the session stores the union of the grants; the
        # actual per-direction breakdown is in the grant_parts field.
        tcp = tuple(
            sorted({port for part in new_union for port in part.tcp})
        )
        udp = tuple(
            sorted({port for part in new_union for port in part.udp})
        )
        icmp = any(part.icmp for part in new_union)
        full = any(part.full for part in new_union)
        directions = {part.direction for part in new_union}
        # Only a domain rule has no grant, hence no direction either.
        direction = (
            next(iter(directions)) if len(directions) == 1
            else ("mixed" if directions else "forward")
        )
        now = time.time()
        with self._lock:
            session = self._sessions.get(token)
            if session is None or session.ip != ip:
                raise AccessError("invalid or expired session")
            if session.expires <= now:
                del self._sessions[token]
                self._remember_end_locked(ip, "expired", now)
                self._write_audit(
                    "session_expired",
                    user=session.user,
                    sid=session.sid,
                    ip=session.ip,
                    authorized=session.authorized,
                    rule=session.rule,
                    rule_label=session.rule_label,
                    ports=session.ports.label(),
                    duration=max(0, int(now - session.created)),
                    reason="expired",
                )
                if session.authorized:
                    # We revoke the expired session's grant immediately too;
                    # do not wait for the cleaner thread.
                    self._revoke_access(ip, session.grants)
                raise AccessError("the session has expired")

            for rule in rules:
                if self.rule_check is not None and not self.rule_check(
                    session.user, rule
                ):
                    raise AccessError("this rule is no longer available")

            # Without the host (input) port guard set, an established
            # connection could survive a later revocation, therefore we do
            # not issue such a grant without the guard set being healthy
            # (fail-closed). The callback acquires only the rule store's and
            # the firewall's locks, never the session lock; since we are
            # running under the session lock here, the lock order is always
            # SessionManager -> RuleStore/Firewall, a reverse order cannot
            # arise.
            if any(
                part.direction == "input" for part in new_union
            ) and (self.guard_check is not None):
                try:
                    guard_ok = bool(self.guard_check())
                except FirewallError:
                    raise
                except Exception as exc:
                    raise FirewallError(
                        "the state of the host-port guard set cannot be checked; "
                        "host access is safely disabled"
                    ) from exc
                if not guard_ok:
                    raise FirewallError(
                        "the host-port guard set was not built; "
                        "host access is safely disabled"
                    )

            if self.state_check is not None and not self.state_check():
                raise FirewallError(
                    "the firewall table was reloaded and is being "
                    "resynchronized; try again in a few seconds"
                )

            old_union = self._grant_tuple(session.grants)
            removed: tuple[Ports, ...] = ()
            if session.authorized:
                # On modification we delete only the departing elements; the
                # common ports belong to the new grant's lifecycle. If the
                # exact deletion fails, the old session must NOT remain
                # referring to a grant: the revocation may run later from
                # the queue, therefore we drop the session, and the user must
                # authorize again. We issue no new grant in this case
                # (fail-closed).
                removed = self._subtract_grants(old_union, new_union)
                if removed:
                    try:
                        self._revoke_exact(ip, removed)
                    except FirewallError as exc:
                        self._sessions.pop(token, None)
                        self._remember_end_locked(ip, "revoke_failed", now)
                        # _revoke_access already audits, but it records the
                        # context of the re-authorization separately (it
                        # contains no secret).
                        self._write_audit(
                            "firewall_error",
                            ip=ip,
                            operation="authorize_revoke",
                            reason=(
                                "revoking the previous access failed; the "
                                "session ended, authorization must be "
                                f"repeated ({exc})"
                            ),
                            pending=True,
                        )
                        # The union of the old and the new grant: since we
                        # issue no new grant, every element may be deleted.
                        self._revoke_access(
                            ip, (*old_union, *new_union)
                        )
                        # The revocation is a firewall failure, not a client
                        # error: the server responds with 503, not 400.
                        raise FirewallError(
                            "revoking the earlier access failed; "
                            "the session ended, sign in again"
                        )

            try:
                # We reissue even on a successful modification: thus the
                # kernel-side timeout refreshes to the new session TTL.
                self.firewall.grant_all(ip, new_union, ttl)
            except FirewallError:
                # No partial grant may remain. A cleanup failure also goes
                # into the retry queue; it is not lost.
                self._revoke_access(ip, (*old_union, *new_union))
                self._sessions[token] = Session(
                    token=session.token,
                    user=session.user,
                    ip=ip,
                    created=now,
                    expires=now + self.pending_ttl,
                    authorized=False,
                    role=session.role,
                    logged_in=session.logged_in,
                    ua=session.ua,
                    sid=session.sid,
                )
                raise

            # We tear down only the departing ports' connections; the live
            # connections of the common ports belonging to the new grant
            # remain.
            conntrack_flush_removed(
                ip, removed, new_union, self.audit
            )

            authorized = Session(
                token=session.token,
                user=session.user,
                ip=ip,
                created=now,
                expires=now + ttl,
                tcp=tcp,
                udp=udp,
                icmp=icmp,
                full=full,
                direction=direction,
                grant_parts=new_union,
                rules=tuple(rule.id for rule in rules),
                rule_parts=rule_parts,
                authorized=True,
                role=session.role,
                rule=rules[0].id,
                rule_label=rules[0].label,
                logged_in=session.logged_in,
                ua=session.ua,
                sid=session.sid,
            )
            self._sessions[token] = authorized
        return authorized

    def logout(self, token: str, ip: str, reason: str = "logout") -> Session | None:
        if not token:
            return None
        try:
            ip = normalize_ip(ip)
        except ValueError:
            return None
        with self._lock:
            session = self._sessions.get(token)
            if session is None or session.ip != ip:
                return None
            del self._sessions[token]
            self._remember_end_locked(ip, reason)
            was_authorized = session.authorized
            if was_authorized:
                # The firewall mutation runs under the same lock as removal:
                # thus a parallel authorize() cannot get a grant that this
                # revocation would immediately delete.
                self._revoke_access_locked(ip, session.grants)
        return session

    def terminate(self, sid: str, reason: str = "admin_terminated") -> Session | None:
        """Terminate a specific session from the admin UI."""
        if not sid:
            return None
        found: Session | None = None
        with self._lock:
            for token, session in list(self._sessions.items()):
                if session.sid and session.sid == sid:
                    del self._sessions[token]
                    self._remember_end_locked(session.ip, reason)
                    found = session
                    if found.authorized:
                        # The firewall call runs under the session lock (see
                        # the comment in logout()).
                        self._revoke_access_locked(found.ip, found.grants)
                    break
        return found

    def revoke_user(
        self,
        user: str,
        *,
        except_token: str | None = None,
        reason: str = "revoked",
    ) -> int:
        """Tear down all sessions and grants of a user.

        We deliberately write no per-session event: the aggregate event of
        the triggering operation (admin change/deletion, password change,
        fail2ban ban) already contains the number of terminated sessions.
        Thus the log does not swell on a mass revocation.
        """
        revoked: list[Session] = []
        with self._lock:
            for token, session in list(self._sessions.items()):
                if session.user != user or token == except_token:
                    continue
                del self._sessions[token]
                revoked.append(session)
                self._remember_end_locked(session.ip, reason)
            grants: dict[str, list[Ports]] = {}
            for session in revoked:
                if session.authorized:
                    grants.setdefault(session.ip, []).extend(session.grants)
            for ip, ports in grants.items():
                # The firewall call runs under the same lock as removal;
                # thus a parallel authorize() cannot slip between the two.
                self._revoke_access_locked(ip, ports)
        return len(revoked)

    def revoke_user_rules(
        self, user: str, rule_ids, reason: str = "revoked"
    ) -> int:
        """Tear down only the given selections from the user's sessions.

        Thus when a rule is modified, the other selected rules' access
        remains in effect. The return value is the number of affected
        (partially or fully removed) sessions.
        """
        with self._lock:
            affected = [
                (token, session)
                for token, session in self._sessions.items()
                if session.user == user
            ]
            return self._remove_selections_locked(
                affected, rule_ids, reason, time.time()
            )

    def revoke_rule(self, rule_id: str, reason: str = "revoked") -> int:
        """Remove the given rule selection from the affected sessions.

        If the session selected only this rule (the old single-rule
        sessions always do), the whole session ends. With several
        selections only the rule's grants disappear; the session and the
        other selections remain.

        Like revoke_user(), we write no per-session event: the aggregate
        event of the admin rule change/deletion covers it.
        """
        with self._lock:
            affected = [
                (token, session)
                for token, session in self._sessions.items()
                if session.rule == rule_id or rule_id in session.rules
            ]
            return self._remove_selections_locked(
                affected, (rule_id,), reason, time.time()
            )

    def revoke_rules(self, rule_ids, reason: str = "revoked") -> int:
        """Remove several rule selections under a single lock.

        When a rule and the collections containing it are modified at the
        same time, separate ``revoke_rule()`` calls would refresh the same
        session in two steps: the first step would create a partial state
        and reissue the intermediate remaining grant before the second step
        removes it. Here the whole set disappears at once. The return value
        is the number of affected sessions.
        """
        wanted = (
            {rule_ids} if isinstance(rule_ids, str) else set(rule_ids or ())
        )
        with self._lock:
            affected = [
                (token, session)
                for token, session in self._sessions.items()
                if session.rule in wanted
                or any(rule_id in wanted for rule_id in session.rules)
            ]
            return self._remove_selections_locked(
                affected, wanted, reason, time.time()
            )

    def revoke_ip(self, ip: str, reason: str = "fail2ban") -> int:
        """Tear down all sessions and grants of a source IP.

        We call it on a fail2ban ban: the banned client must not be able to
        use the access already opened, and its existing connections must
        also be broken.

        We drop every session belonging to this IP, then add the grants of
        recently failed revocations to the deletion too. Since no session
        remains for the IP under the lock (and because of the
        one-session-per-IP rule no other session could have inherited these
        elements), the host (input) and forward ``ip . port`` elements
        belonging to the IP can be safely discovered and deleted; thus no
        orphaned grants remain in the kernel after a crash or earlier
        failure either. The listing uses an exact IP match, so it does not
        affect another client's elements.
        """
        try:
            ip = normalize_ip(ip)
        except ValueError:
            return 0
        with self._lock:
            revoked = self._drop_ip_locked(ip, reason)
            pending = self._pending_for_ip(ip)
            grants = [
                part for session in revoked for part in session.grants
            ]
            grants.extend(
                part for _key, entry in pending for part in entry.grants
            )
            # The firewall call runs under the session lock, so that a
            # parallel authorize() cannot issue a new grant for the IP
            # between discovery and deletion.
            ok = self._revoke_access(ip, grants, discover=True)
            if ok:
                self._clear_pending_keys([key for key, _entry in pending])
        # We flush conntrack even if there was no portal session: a pre-auth
        # or earlier connection may also be alive at the moment of the ban.
        return len(revoked)

    def reap_once(self, now: float | None = None) -> int:
        """Delete expired sessions; ban the IPs that became empty."""
        now = time.time() if now is None else now
        expired_authorized: dict[str, list[Ports]] = {}
        expired_sessions: list[Session] = []
        with self._lock:
            for token, session in list(self._sessions.items()):
                if session.expires <= now:
                    del self._sessions[token]
                    expired_sessions.append(session)
                    self._remember_end_locked(session.ip, "expired", now)
                    if session.authorized:
                        expired_authorized.setdefault(
                            session.ip, []
                        ).extend(session.grants)
            active_ips = self._active_authorized_ips_locked()
            for ip, grants in expired_authorized.items():
                # The firewall call runs under the same lock as removal of
                # the expired session. The helper aligns the deletion with
                # the remaining active sessions' grants, and if needed
                # deletes only the non-overlapping elements without a
                # conntrack flush.
                self._revoke_access_locked(ip, grants, now=now)
        to_revoke = len(set(expired_authorized) - active_ips)
        # Sessions already removed by validate()/authorize() are not in the
        # list, so no second event is written for them.
        for session in expired_sessions:
            self._write_audit(
                "session_expired",
                user=session.user,
                sid=session.sid,
                ip=session.ip,
                authorized=session.authorized,
                rule=session.rule,
                rule_label=session.rule_label,
                ports=session.ports.label(),
                duration=max(0, int(now - session.created)),
                reason="expired",
            )
        # Retry earlier failed firewall revocations. This runs in the
        # cleaner thread, so callers need not start a separate thread; thus
        # the revocation is not lost if nft failed temporarily either.
        self._retry_pending_revocations(now)
        return to_revoke

    def start_reaper(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.wait(5):
                try:
                    self.reap_once()
                except Exception as exc:  # the reaper must never die
                    log(f"[session] cleanup error: {exc}")
                    self._write_audit(
                        "session_reaper_error", reason=str(exc)
                    )

        self._thread = threading.Thread(target=loop, name="hv-reaper", daemon=True)
        self._thread.start()

    def stop_reaper(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def end_authorized(self, reason: str = "firewall_reset") -> list[Session]:
        """End every authorized session and revoke its grants.

        Called after a table resync: the kernel elements of these sessions
        went with the old table, so the clients look authorized but are
        dropped. Ending them is fail-closed; the clients log in again.
        Sessions still waiting for authorization have no grant and stay.
        Returns the ended sessions, so the caller can audit each one.
        """
        ended: list[Session] = []
        with self._lock:
            for token, session in list(self._sessions.items()):
                if not session.authorized:
                    continue
                del self._sessions[token]
                ended.append(session)
                self._remember_end_locked(session.ip, reason)
            grants: dict[str, list[Ports]] = {}
            for session in ended:
                grants.setdefault(session.ip, []).extend(session.grants)
            for ip, ports in grants.items():
                # Under the session lock like revoke_user(); the conntrack
                # flush also cuts flows the reloaded table still accepts as
                # established.
                self._revoke_access_locked(ip, ports)
        return ended

    def shutdown(self, reason: str = "service_stop") -> int:
        """Immediately revoke every session and firewall grant.

        We call it before shutdown, so that stopping does not leave access
        open until the TTL. On a crash the kernel-side timeout protects.
        """
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
            for session in sessions:
                self._remember_end_locked(session.ip, reason)
        grants: dict[str, list[Ports]] = {}
        for session in sessions:
            if session.authorized:
                grants.setdefault(session.ip, []).extend(session.grants)
        for ip, ports in grants.items():
            self._revoke_access(ip, ports)
        return len(sessions)

    def count(self, authorized_only: bool = False) -> int:
        with self._lock:
            if authorized_only:
                return sum(
                    1 for session in self._sessions.values()
                    if session.authorized
                )
            return len(self._sessions)


# ---------------------------------------------------------------- rate limit

class RateLimiter:
    """A sliding-window limit (per IP)."""

    def __init__(self, window: int = RATE_WINDOW, maximum: int = RATE_MAX) -> None:
        self.window = max(1, int(window))
        self.maximum = max(1, int(maximum))
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < self.window]
            if len(hits) >= self.maximum:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            if len(self._hits) > 4096:
                self._prune_locked(now)
            return True

    def _prune_locked(self, now: float) -> None:
        for key, hits in list(self._hits.items()):
            fresh = [t for t in hits if now - t < self.window]
            if fresh:
                self._hits[key] = fresh
            else:
                del self._hits[key]


class AccountLockout:
    """Failed password attempts per login name, across all source IPs.

    fail2ban and the rate limiter count per IP, so an attacker with many
    addresses could guess one account's password without limit. After
    ``maximum`` failures within ``window`` seconds the name is locked for
    ``base`` seconds; every further lock doubles it up to ``cap``. Names are
    compared case-insensitively, and unknown names are counted the same way,
    so the lock does not reveal which accounts exist. In memory only: a
    restart clears it, like the rate limiter.
    """

    MAX_NAMES = 10_000

    def __init__(
        self,
        maximum: int = ACCOUNT_LOCK_MAX,
        window: int = ACCOUNT_LOCK_WINDOW,
        base: int = ACCOUNT_LOCK_BASE,
        cap: int = ACCOUNT_LOCK_CAP,
    ) -> None:
        self.maximum = max(1, int(maximum))
        self.window = max(1, int(window))
        self.base = max(1, int(base))
        self.cap = max(self.base, int(cap))
        self._lock = threading.Lock()
        # name -> [failure times], lock until, number of locks so far
        self._state: dict[str, tuple[list[float], float, int]] = {}

    @staticmethod
    def _key(name: str) -> str:
        return str(name).strip().lower()[:64]

    def locked(self, name: str) -> int:
        """Remaining lock in whole seconds (0: not locked)."""
        now = time.time()
        with self._lock:
            state = self._state.get(self._key(name))
            if state is None or state[1] <= now:
                return 0
            return max(1, int(state[1] - now + 0.999))

    def record_failure(self, name: str) -> int:
        """Count a failure; returns the new lock length when it just locked."""
        now = time.time()
        key = self._key(name)
        with self._lock:
            hits, until, locks = self._state.get(key, ([], 0.0, 0))
            hits = [t for t in hits if now - t < self.window]
            hits.append(now)
            length = 0
            if len(hits) >= self.maximum and until <= now:
                length = min(self.cap, self.base * (2 ** min(locks, 16)))
                until = now + length
                locks += 1
                hits = []
            self._state[key] = (hits, until, locks)
            if len(self._state) > self.MAX_NAMES:
                self._prune_locked(now)
            return length

    def record_success(self, name: str) -> None:
        with self._lock:
            self._state.pop(self._key(name), None)

    def _prune_locked(self, now: float) -> None:
        for key, (hits, until, _) in list(self._state.items()):
            if until <= now and not [t for t in hits if now - t < self.window]:
                del self._state[key]
        # Still too many (a spray of random names): drop the oldest.
        while len(self._state) > self.MAX_NAMES:
            self._state.pop(next(iter(self._state)))


# ------------------------------------------------------------------- captcha

# Process-wide key: after a restart the old challenges are invalid.
_POW_SECRET = secrets.token_bytes(32)
_seen_lock = threading.Lock()
_seen: dict[str, int] = {}


def _canon(challenge: str, salt: str, algorithm: str, difficulty: int, expires: int) -> bytes:
    return f"{challenge}:{salt}:{algorithm}:{difficulty}:{expires}".encode()


def issue_challenge(difficulty: int | None = None) -> dict:
    difficulty = POW_DIFFICULTY if difficulty is None else int(difficulty)
    challenge = secrets.token_hex(16)
    salt = secrets.token_hex(8)
    algorithm = "SHA-256"
    expires = int(time.time()) + CHALLENGE_TTL
    signature = hmac.new(
        _POW_SECRET, _canon(challenge, salt, algorithm, difficulty, expires), hashlib.sha256
    ).hexdigest()
    return {
        "challenge": challenge,
        "salt": salt,
        "algorithm": algorithm,
        "difficulty": difficulty,
        "expires": expires,
        "signature": signature,
    }


def verify_pow(payload: dict) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, "invalid captcha package"
    try:
        challenge = str(payload["challenge"])
        salt = str(payload["salt"])
        algorithm = str(payload["algorithm"])
        difficulty = int(payload["difficulty"])
        expires = int(payload["expires"])
        signature = str(payload["signature"])
        number = int(payload["number"])
    except (KeyError, TypeError, ValueError):
        return False, "invalid captcha package"

    if not (0 <= number < 2 ** 64):
        return False, "invalid solution"

    # The client could not have altered the difficulty / expiry.
    expected = hmac.new(
        _POW_SECRET, _canon(challenge, salt, algorithm, difficulty, expires), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False, "invalid signature"

    if time.time() > expires:
        return False, "expired captcha"

    digest = hashlib.sha256(f"{salt}{number}".encode()).hexdigest()
    if not digest.startswith("0" * difficulty):
        return False, "wrong solution"

    now = time.time()
    with _seen_lock:
        for key, exp in list(_seen.items()):
            if exp < now:
                _seen.pop(key, None)
        if challenge in _seen:
            return False, "the captcha was already used"
        _seen[challenge] = expires

    return True, "ok"


def verify_turnstile(token: str, remote_ip: str) -> tuple[bool, str]:
    if not TURNSTILE_ON:
        return False, "Turnstile is not enabled"
    if not token:
        return False, "missing token"
    data = urllib.parse.urlencode(
        {"secret": TURNSTILE_SECRET, "response": token, "remoteip": remote_ip}
    ).encode()
    try:
        with urllib.request.urlopen(TURNSTILE_VERIFY_URL, data=data, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # network error = safe rejection
        return False, f"verification unavailable ({type(exc).__name__})"
    if body.get("success") is True:
        return True, "ok"
    return False, "the captcha is invalid"


# ------------------------------------------------------------------- root

class Gateway:
    """The components used by the HTTP layer in one package."""

    # Serialization of settings deployment and the port proxy refresh: the
    # refresher must not write back an old snapshot's rules after an admin
    # save.
    _custom_lock = threading.RLock()
    PORTPROXY_REFRESH_SECONDS = 10
    # How often the portal checks that the kernel table is still the one it
    # synchronized (see check_firewall_state).
    FIREWALL_CHECK_SECONDS = 5

    def __init__(
        self,
        users: UserStore | None = None,
        firewall: Firewall | None = None,
        sessions: SessionManager | None = None,
        rate_limiter: RateLimiter | None = None,
        catalog: ServiceCatalog | None = None,
        rules: RuleStore | None = None,
        groups: GroupStore | None = None,
        audit: AuditLog | None = None,
        settings: "settings_store.SettingsStore | None" = None,
        drops: "droplog.DropLogService | None" = None,
        fail2ban: "fail2ban_mod.Fail2ban | None" = None,
        certs: "settings_store.CertStore | None" = None,
    ) -> None:
        self.catalog = (
            catalog if catalog is not None else ServiceCatalog.load()
        )
        self.users = users if users is not None else UserStore()
        self.audit = audit if audit is not None else AuditLog()
        self.rules = (
            rules if rules is not None else RuleStore(catalog=self.catalog)
        )
        self.groups = groups if groups is not None else GroupStore()
        self.firewall = firewall if firewall is not None else Firewall()
        self.settings = (
            settings
            if settings is not None
            else settings_store.SettingsStore()
        )
        # Uploaded certificates live next to the settings file, under certs/.
        self.certs = certs if certs is not None else settings_store.CertStore(
            os.path.join(
                os.path.dirname(
                    getattr(self.settings, "path", settings_store.SETTINGS_PATH)
                ),
                "certs",
            )
        )
        # The WireGuard tunnel (dropjak0) runs in the host network namespace;
        # after a settings change it is left alone if the signature matches.
        self.tunnels = tunnel_mod.TunnelManager(logger=log)
        # The minimum per-agent interval of the agent sync
        # (GET /api/tunnel/config); the token never gets here or into the log.
        self.tunnel_sync_times: dict[str, float] = {}
        self.tunnel_sync_lock = threading.Lock()
        # A domain rule may refer only to an existing proxy entry or a
        # domain-mode tunnel service.
        if getattr(self.rules, "domain_names", False) is None:
            self.rules.domain_names = self._domain_names
            self.rules.legacy_proxy_domain = getattr(
                self.settings, "legacy_proxy_domain", ""
            )
        # We resolve the service rule's references from the settings on every
        # call, so that a mapping change takes effect immediately. The
        # callback is bound before the first lazy _load().
        self.rules.service_ports = self._service_ports_for
        # We resolve the hostnames of domain-mode services from the same
        # index; thus a service rule can also grant domain access.
        self.rules.service_domains = self._service_domains_for
        self.drops = (
            drops if drops is not None else droplog.DropLogService()
        )
        # The state of the host (input) port guard set. Conservatively false
        # until the first successful sync_host_ports() sets it: thus host
        # grants cannot be issued even if the sync has not run yet
        # (fail-closed). prepare() synchronizes before serving.
        self._host_ports_ok = False
        # Sync + cleanup run under one lock: a cleanup starting with a stale
        # reference list must not delete a freshly added port of a rule
        # created in the meantime.
        self._host_ports_lock = threading.Lock()
        # The table generation (Firewall.state_token) after the last full
        # synchronization; None until prepare() has run. A different live
        # value means the table was lost and reloaded bare.
        self._fw_token: int | None = None
        self._fw_lost_logged = False
        self.sessions = (
            sessions
            if sessions is not None
            else SessionManager(
                self.firewall,
                ttl=DEFAULT_TTL,
                pending_ttl=AUTH_TTL,
                audit=self.audit,
                rule_check=self._rule_available,
                guard_check=self._host_ports_healthy,
                state_check=self._firewall_in_sync,
            )
        )
        if self.sessions.audit is None:
            self.sessions.audit = self.audit
        self.fail2ban = (
            fail2ban
            if fail2ban is not None
            else fail2ban_mod.Fail2ban(
                self.firewall,
                path=fail2ban_mod.FAIL2BAN_PATH,
                audit=self.audit,
                exempt=infra_exempt_addresses(),
                on_ban=self._on_fail2ban_ban,
            )
        )
        if self.fail2ban.audit is None:
            self.fail2ban.audit = self.audit
        # Automatic (login/drop) bans must also reach the common
        # post-processing if the instance was passed in from outside.
        if getattr(self.fail2ban, "_on_ban", None) is None:
            self.fail2ban._on_ban = self._on_fail2ban_ban
        # We pass every recorded packet of the drop log to fail2ban; it
        # decides whether the given reason/protocol warrants a ban.
        setter = getattr(self.drops, "set_on_drop", None)
        if setter is not None:
            setter(self._on_drop)
        self.login_rate = (
            rate_limiter if rate_limiter is not None else RateLimiter()
        )
        # Per-account failure counter (across source IPs), see AccountLockout.
        self.account_lockout = AccountLockout()
        # Account requests have their own limit: they must not consume the
        # sign-in budget.
        self.register_rate = RateLimiter(window=600, maximum=3)
        # Proxy 401 drop log lines are rate-limited like the nft log rules
        # (30/minute), globally.
        self.proxy_drop_rate = RateLimiter(window=60, maximum=30)
        # A separate limit for password changes, so that they do not consume
        # sign-in attempts, and vice versa.
        self.password_rate = RateLimiter(window=300, maximum=10)
        # Access changes start nft transactions; frequent switching must not
        # burden the firewall or consume the sign-in budget.
        self.access_rate = RateLimiter(window=60, maximum=20)
        # Serialization of admin changes (checking the last admin + write).
        self.admin_lock = threading.Lock()

    def _write_audit(self, event: str, **fields) -> None:
        """Optional logging for the portal's lifecycle events."""
        try:
            self.audit.write(event, **fields)
        except Exception as exc:  # logging should never block
            log(f"[audit] writing {event} failed: {exc}")

    def _domain_names(self) -> set[str]:
        """The full hostnames a domain rule may reference.

        Besides the proxy entries, the domain-mode services of authorized
        tunnel agents also belong here, so that a private domain rule can be
        created for them. The domain of a disabled service is also visible:
        the lifecycle limit of deletion/disablement can thus reference it.
        """
        settings = self.settings.snapshot()
        names = {
            settings_store.route_host(route)
            for route in settings.get("proxy_routes", [])
        }
        tunnels = settings.get("tunnels")
        if isinstance(tunnels, dict):
            for agent in tunnels.get("agents", []):
                if not isinstance(agent, dict):
                    continue
                for service in agent.get("services", []):
                    if not isinstance(service, dict):
                        continue
                    domain = service.get("domain", "")
                    if domain:
                        names.add(domain)
        return names

    def _service_entry_for(self, ref: str):
        """The index entry of a service reference from the settings.

        ``None`` if the reference is unknown or the service/agent is
        disabled. Thus both saving a rule and checking at decision time
        behave in a fail-closed way.
        """
        tunnels = self.settings.snapshot().get("tunnels")
        if not isinstance(tunnels, dict):
            return None
        return settings_store.tunnel_service_index(tunnels).get(ref)

    def _service_ports_for(self, ref: str):
        """The resolved ports of a service reference from the settings."""
        return self._service_entry_for(ref)

    def _service_domains_for(self, ref: str):
        """The resolved domain of a service reference.

        The same index entry as for the ports; the ``domain`` field is
        non-empty only for a domain-mode service.
        """
        return self._service_entry_for(ref)

    def effective_rules(self, user_name: str):
        record = self.users.record(user_name)
        if record is None:
            return []
        return self.rules.effective_for(
            record, self.groups.groups_for(user_name)
        )

    def _rule_available(self, user_name: str, rule: Rule) -> bool:
        """Whether the rule still belongs to the user at the moment of the decision."""
        record = self.users.record(user_name)
        if record is None or not record.enabled or record.pending:
            return False
        try:
            current = self.rules.resolve_for(
                record, self.groups.groups_for(user_name), rule.id
            )
        except (AccessError, KeyError, ValueError):
            return False
        if rule.service_refs:
            # A service rule (or a collection containing one) should have its
            # permission computed from the current tunnel mapping at the
            # moment of the decision too. With a missing/disabled reference or
            # different ports, the session must not remain valid.
            resolver = getattr(self.rules, "service_ports", None)
            tcp: set[int] = set()
            udp: set[int] = set()
            for ref in rule.service_refs:
                resolved = resolver(ref) if resolver is not None else None
                if resolved is None:
                    return False
                tcp.update(resolved.get("tcp") or ())
                udp.update(resolved.get("udp") or ())
            if (tuple(sorted(tcp)), tuple(sorted(udp))) != (
                rule.service_tcp, rule.service_udp
            ):
                return False
            # The listening ports may be unchanged while the target host
            # or target port redirection would mean a different permission:
            # the full mapping signature must also be compared (fail-closed).
            if self.rules.service_signature(rule.service_refs) != (
                rule.service_signature
            ):
                return False
        return (
            current.grants == rule.grants
            and current.session_domains == rule.session_domains
        )

    def _firewall_in_sync(self) -> bool:
        """Whether the live table is the one prepare()/the last resync filled.

        Called by ``SessionManager.authorize()`` under the session lock; it
        only runs nft, it takes no lock. Before prepare() (no token yet) it
        does not block, so the startup order is unchanged.
        """
        if self._fw_token is None:
            return True
        try:
            return self.firewall.state_token() == self._fw_token
        except FirewallError:
            return False

    def check_firewall_state(self) -> bool:
        """Detect a lost or reloaded table and restore the portal's state.

        After a table loss the template reload (Docker watchdog, native
        nftables.service restart) brings back only the bare rules: the block,
        pre-auth, port proxy and tunnel chains, the bans and the host guard
        sets are empty. This re-runs everything prepare() pushes, except the
        startup flush. Until it succeeds, ``_host_ports_ok`` is false and
        ``_firewall_in_sync`` refuses new grants. Returns True if a resync ran.
        Existing sessions are not re-granted: their kernel elements went with
        the old table, so every authorized session is ended with reason
        ``firewall_reset`` (fail-closed) and those clients log in again.
        """
        if self._fw_token is None or self._firewall_in_sync():
            return False
        with Gateway._custom_lock:
            token = self.firewall.state_token()
            if token == self._fw_token:
                return False
            self._host_ports_ok = False
            exists, _why = self.firewall.healthy()
            if not exists:
                if not self._fw_lost_logged:
                    self._fw_lost_logged = True
                    log(
                        "[firewall] ERROR: the nftables table is missing; "
                        "new grants are refused until it is reloaded"
                    )
                    self._write_audit(
                        "firewall_error", operation="table_lost",
                        reason="table missing",
                    )
                return False
            log(
                "[firewall] WARNING: the nftables table was reloaded; "
                "restoring host guards, bans and custom chains"
            )
            self.sync_host_ports()
            bans_ok = self.fail2ban.sync()
            try:
                self._apply_custom_settings()
            except FirewallError:
                return False
            new_token = self.firewall.state_token()
            if new_token is None or not self._host_ports_ok or not bans_ok:
                self._write_audit(
                    "firewall_error", operation="resync",
                    reason="partial resync; retrying",
                )
                return False
        # Outside the Gateway lock (lock order SessionManager -> Gateway), but
        # before the new token is recorded: until then _firewall_in_sync()
        # still refuses grants, so every authorized session here predates
        # the reload.
        ended = self.sessions.end_authorized(reason="firewall_reset")
        for session in ended:
            self._write_audit(
                "session_ended",
                user=session.user,
                sid=session.sid,
                ip=session.ip,
                reason="firewall_reset",
                authorized=session.authorized,
                rule=session.rule,
            )
        self._fw_token = new_token
        self._fw_lost_logged = False
        if ended:
            log(
                f"[firewall] ended {len(ended)} authorized session(s) after "
                "the table reload; the clients must log in again"
            )
        self._write_audit(
            "firewall_resync", reason="table reloaded",
            sessions_revoked=len(ended),
        )
        return True

    def _firewall_watch_loop(self) -> None:
        while not self._fw_watch_stop.wait(self.FIREWALL_CHECK_SECONDS):
            try:
                self.check_firewall_state()
            except Exception as exc:  # the thread must never die
                log(f"[firewall] state check error: {exc}")

    def _host_ports_healthy(self) -> bool:
        """The state of the host-port guard set; retries once after a failure.

        This is called by ``SessionManager.authorize()`` under the session
        lock, before issuing an input direction permission. ``sync_host_ports()``
        acquires the Gateway host-port lock as well as the RuleStore and
        Firewall locks, never the session lock, so the lock order is always
        SessionManager -> Gateway -> RuleStore/Firewall, and no deadlock can
        arise. The false state can be healed by a single retry, so that a
        transient nft error does not block further sign-ins.
        """
        if not self._host_ports_ok:
            self.sync_host_ports()
        return self._host_ports_ok

    def sync_host_ports(self) -> None:
        """Carrying the ports of the host (input) rules through to the kernel.

        We collect the resolved ports from the whole rule store, so the set
        content is correct after modifying a collection rule too. During a
        normal sync the ``host_service_*`` sets only grow (the Firewall fills
        them in an add-only way), so a deleted rule does not reopen existing
        connections. After a successful fill, the Firewall performs a safe
        cleanup: it deletes only a port that no persisted rule references and
        to which no live conntrack entry belongs.

        On error ``_host_ports_ok`` remains false and the error is logged and
        audited. Host (input) permissions are then rejected with 503
        (fail-closed); forward-only authorization keeps working, because it
        is not protected by this set.

        At startup the sets are deliberately not cleared: old flows of
        deleted ports thus remain cut off. Because of the 65536 size, all
        65535 valid ports fit, so the set cannot fill up and no guard element
        can be silently lost.
        """
        # Reading the rule store, adding the ports and the cleanup run under
        # one lock. Without that, a cleanup starting with a stale reference
        # list could delete a freshly added port of a rule created in the
        # meantime (the cleanup only deletes, it does not replace).
        with self._host_ports_lock:
            self._sync_host_ports_locked()

    def _sync_host_ports_locked(self) -> None:
        # Conservative: after any error (or unexpected exception) it remains
        # false and host permissions stay closed.
        self._host_ports_ok = False
        try:
            rules = self.rules.persisted_rules()
        except RuleStoreError as exc:
            log(f"[firewall] collecting host ports failed: {exc}")
            self._write_audit(
                "firewall_error",
                operation="host_ports",
                reason=str(exc),
                healthy=False,
            )
            return
        host_tcp: set[int] = set()
        host_udp: set[int] = set()
        # The cleanup's reference list is deliberately wider than the sync's:
        # any port of any persisted rule protects, not only those of the input
        # parts. Thus the port of a forward rule cannot be deleted from the
        # guard set either.
        referenced_tcp: set[int] = set()
        referenced_udp: set[int] = set()
        for rule in rules:
            # A collection rule's permissions are separate parts per
            # direction; only the ports of the input parts are needed in the
            # host_service_* set.
            for part in rule.grants:
                referenced_tcp.update(part.tcp)
                referenced_udp.update(part.udp)
                if part.direction != "input":
                    continue
                host_tcp.update(part.tcp)
                host_udp.update(part.udp)
        try:
            self.firewall.sync_host_ports(
                sorted(host_tcp), sorted(host_udp)
            )
        except FirewallError as exc:
            log(f"[firewall] synchronizing host ports failed: {exc}")
            self._write_audit(
                "firewall_error",
                operation="host_ports",
                reason=str(exc),
                healthy=False,
            )
            return
        self._host_ports_ok = True
        # The cleanup runs only after the complete, successful fill, and its
        # failure cannot spoil the health: the guard set is already complete.
        prune = getattr(self.firewall, "prune_host_service_ports", None)
        if prune is None:
            return
        try:
            prune(sorted(referenced_tcp), sorted(referenced_udp),
                  audit=self.audit)
        except Exception as exc:  # the cleanup must never block the grant
            log(f"[firewall] host port cleanup failed: {exc}")
            self._write_audit(
                "firewall_error",
                operation="host_ports_prune",
                reason=str(exc),
            )

    def user_public(self, name: str) -> dict | None:
        record = self.users.record(name)
        if record is None:
            return None
        groups = [group.id for group in self.groups.groups_for(name)]
        return record.public(groups)

    def _on_drop(self, record: dict) -> None:
        """Passing a dropped packet to fail2ban.

        Only unauthorized TCP traffic is counted. Port scanners and bots
        typically try TCP; the legitimate client's UDP background noise
        (mDNS, LLMNR, NetBIOS, DNS) does not result in a ban. DNS and the
        portal's own port are excluded.
        """
        reason = str(record.get("reason") or "").strip()
        if reason not in DROP_BAN_REASONS:
            return
        if str(record.get("proto") or "").strip().lower() != "tcp":
            return
        try:
            dport = int(record.get("dport") or 0)
        except (TypeError, ValueError):
            dport = 0
        if dport in DROP_BAN_SKIP_TCP_PORTS or dport == PORT:
            return
        src = str(record.get("src") or "").strip()
        if not src:
            return
        try:
            # Traffic from the WAN also counts toward the packet threshold;
            # LAN-side no-grant/input-lan only toward port diversity, because
            # a signed-out browser also starts many TCP attempts.
            self.fail2ban.record_drop(
                src, proto="tcp", dport=dport, reason=reason,
                count_total=reason in ("wan-drop", "input-wan"),
            )
        except Exception as exc:
            log(f"[fail2ban] drop-based ban of {src} failed: {exc}")

    def record_proxy_drop(self, ip: str, host: str, path: str) -> None:
        """A proxy 401 (block page) line in the drop log.

        Writes directly to the store, not through the NFLOG callback: it
        does not feed the drop and port count signals (401s are counted by
        the proxy signal).
        """
        if not self.proxy_drop_rate.allow("proxy"):
            return
        try:
            self.drops.store.write(
                {
                    "reason": droplog.PROXY_DROP_REASON,
                    "src": ip,
                    "dst": host,
                    "proto": "tcp",
                    "dport": 443,
                    "source": "proxy",
                    "path": path,
                }
            )
        except Exception as exc:
            log(f"[proxy] writing the drop log entry failed: {exc}")

    def _on_fail2ban_ban(self, record: dict) -> None:
        """Post-processing of a fresh ban.

        The firewall already enforces the ban; here we tear down the client's
        existing sessions and connections, log the event, and write the fact
        of the ban into the drop log. Errors do not revoke the ban.
        """
        ip = str(record.get("ip", "")).strip()
        if not ip:
            return
        manual = bool(record.get("manual"))
        attempts = int(record.get("attempts") or 0)
        user = str(record.get("user") or "")
        until = int(record.get("until") or 0)
        source = str(record.get("source") or "")
        if source not in ("manual", "login", "drop", "proxy"):
            source = "manual" if manual else "login"
        detail = str(record.get("detail") or "")[:64]
        if source == "proxy":
            # A proxy ban only closes TCP 80/443: the session and the other
            # connections remain, and the plain portal stays reachable. The
            # existing 80/443 connections are cut by the state-independent
            # drop of the input chain, so no conntrack flush is needed either
            # (it would be direction-blind and would also tear down the
            # client's forwarded web traffic). The drop log ban event belongs
            # to a full ban, we do not write it here.
            self.audit.write(
                "fail2ban_ban",
                ip=ip,
                manual=False,
                attempts=attempts,
                user="",
                until=until,
                source=source,
                detail="",
                sessions_revoked=0,
            )
            log(
                f"[fail2ban] proxy ban (HTTP/HTTPS only): {ip} "
                f"({attempts} unauthorized proxy requests)"
            )
            return
        revoked = 0
        try:
            revoked = self.sessions.revoke_ip(ip, reason="fail2ban")
        except Exception as exc:
            log(f"[fail2ban] tearing down the sessions of {ip} failed: {exc}")
        self.audit.write(
            "fail2ban_ban",
            ip=ip,
            manual=manual,
            attempts=attempts,
            user=user,
            until=until,
            source=source,
            detail=detail,
            sessions_revoked=revoked,
        )
        try:
            self.drops.store.write(
                {
                    "reason": droplog.BAN_EVENT_REASON,
                    "src": ip,
                    "dst": "",
                    "proto": "",
                    "event": droplog.BAN_EVENT_KIND,
                    "attempts": attempts,
                    "user": user,
                    "ban_until": until,
                    "manual": manual,
                    "source": source,
                    "detail": detail,
                }
            )
        except Exception as exc:
            log(f"[fail2ban] writing the drop log entry failed: {exc}")
        if source == "manual":
            log(f"[fail2ban] manual ban: {ip} ({until - int(time.time())} s)")
        elif source == "drop":
            log(
                f"[fail2ban] automatic ban: {ip} "
                f"({attempts} dropped packets, reason={detail or 'drop'})"
            )
        else:
            log(
                f"[fail2ban] automatic ban: {ip} "
                f"({attempts} failed sign-ins, {user!r})"
            )

    def _startup_flush(self) -> None:
        """Startup flush/reconciliation according to the effective env value.

        ``HV_FLUSH_ON_START`` uses the same truthy/falsy interpretation as
        the other boolean variables (1/true/yes/on). If it is disabled, the
        default (safe) behaviour is reconciling orphaned grants: the dynamic
        sets are aligned with the in-memory, empty session table. Only the
        explicit, unsafe ``HV_ALLOW_STALE_GRANTS_ON_START=1`` opt-in lets
        earlier grants stay alive until the kernel TTL; we log that loudly.
        The ``host_service_*`` sets are not touched.
        """
        mode = _startup_flush_mode(
            FLUSH_ON_START, ALLOW_STALE_GRANTS_ON_START
        )
        effective = "1" if FLUSH_ON_START else "0"
        log(f"[firewall] effective value of HV_FLUSH_ON_START: {effective}")
        if mode == "stale_allowed":
            log(
                "[firewall] WARNING: HV_FLUSH_ON_START is disabled and "
                "HV_ALLOW_STALE_GRANTS_ON_START=1 is set. Earlier "
                "grants left in the kernel by the previous process may "
                "remain valid until the TTL (up to 30 days), without a "
                "session!"
            )
            return
        try:
            self.firewall.flush()
        except FirewallError as exc:
            # A failed startup flush may mean that the previous process's
            # grants would keep living. In that case we do not start: the
            # fail-closed principle matters more than availability.
            log(
                "[firewall] ERROR: deleting earlier grants failed, "
                f"startup aborted: {exc}"
            )
            self._write_audit(
                "firewall_error",
                operation="flush",
                mode=mode,
                reason=str(exc),
            )
            raise
        if mode == "reconcile":
            log(
                "[firewall] WARNING: HV_FLUSH_ON_START is disabled, but "
                "orphaned grants must not remain in the kernel; the dynamic "
                "sets are aligned with the in-memory (empty) session table."
            )
        else:
            log("[firewall] earlier grants deleted (clean start)")

    def prepare(self) -> None:
        """Startup firewall check and deletion of old grants."""
        self.rules.all_rules()
        log(
            f"[catalog] {len(self.catalog.service_order)} services, "
            f"{len(self.catalog.scenario_order)} scenarios "
            f"({self.catalog.source})"
        )
        log(
            f"[rules] {len(self.rules.persisted_rules())} admin rules, "
            f"{len(self.groups.all_groups())} groups"
        )
        log(
            "[access] selectable duration: "
            f"{format_duration(MIN_TTL)}–{format_duration(MAX_TTL)}; "
            f"default: {format_duration(self.sessions.ttl)}"
        )
        # Clean start, or if the flush is disabled, a safe reconciliation with
        # the in-memory (empty) session table. Orphaned grants may survive only
        # with an explicit, unsafe opt-in; _startup_flush decides and logs this.
        self._startup_flush()
        # Loading the ports declared in host rules into the host_service_*
        # sets that cut established traffic. The startup flush deliberately
        # does not touch these (old flows of deleted ports should stay cut
        # off), so we replenish their content here. This still runs before
        # serving and the health check, so the _host_ports_ok state already
        # reflects the real startup sync result: if it failed, host
        # permissions retry once at the first authorize and remain closed in a
        # fail-closed manner.
        self.sync_host_ports()
        ok, why = self.firewall.healthy()
        if ok:
            log(
                f"[firewall] healthy: inet {self.firewall.table} "
                f"/ {self.firewall.set_name}, {self.firewall.tcp_set}, "
                f"{self.firewall.udp_set}, {self.firewall.icmp_set}, "
                f"{self.firewall.input_tcp_set}, "
                f"{self.firewall.input_udp_set}, {self.firewall.mac_set}, "
                f"{self.firewall.ban_set}"
            )
        else:
            log(
                "[firewall] WARNING: dynamic sets are unreachable "
                f"({why}). Sign-ins will not work until the error is fixed."
            )
            self._write_audit(
                "firewall_error", operation="health", reason=str(why)
            )
        # Reloading the bans configured in the UI after a possible startup
        # flush. If this fails, the portal still starts but protection is
        # weaker; the admin sees the error in the UI.
        if self.fail2ban.sync():
            status = self.fail2ban.status()
            log(
                "[fail2ban] sign-in monitoring: "
                f"{'active' if status['enabled'] else 'disabled'}; "
                f"drop metrics: "
                f"packet count={'on' if status['drop_count_enabled'] else 'off'}, "
                f"ports={'on' if status['drop_ports_enabled'] else 'off'}, "
                f"proxy={'on' if status['proxy_enabled'] else 'off'}; "
                f"{status['banned']} banned IPs, threshold: "
                f"{status['max_attempts']} attempts / "
                f"{status['window_seconds']} s, ban: "
                f"{status['ban_seconds']} s"
            )
        else:
            log(
                "[fail2ban] WARNING: saved bans could not be "
                "reloaded into the firewall"
            )
            status = self.fail2ban.status()
            self._write_audit(
                "fail2ban_sync_failed",
                reason=str(status.get("error") or "reload failed"),
            )
        # Installing the settings file's pre-auth and block rules.
        self._apply_custom_settings()
        # The generation of the table we just filled; check_firewall_state()
        # compares against it. None (unreadable) makes the first check resync.
        try:
            self._fw_token = self.firewall.state_token()
        except FirewallError:
            self._fw_token = None
        if self._fw_token is None:
            self._fw_token = -1

    def _apply_custom_settings(self, snapshot: dict | None = None) -> None:
        """Installing the pre-auth and block rules into nftables.

        We flush first, then apply. If the apply fails, the pre-auth
        permissions do not remain alive (fail-closed).
        """
        with Gateway._custom_lock:
            snapshot = snapshot if snapshot is not None else self.settings.snapshot()
            invalid = bool(snapshot.get("error"))
            if invalid:
                log(
                    "[settings] WARNING: the settings file is invalid; the "
                    "pre-auth list is cleared, the last known good content of "
                    f"the block chains stays unchanged: {snapshot['error']}"
                )
                self._write_audit(
                    "settings_invalid", reason=str(snapshot["error"])
                )
            try:
                if invalid:
                    # Fail-closed: pre-auth permissions must not stay alive from
                    # an invalid file, but blocking must not disappear either.
                    self.firewall.replace_custom((), (), keep_block=True)
                else:
                    self.firewall.replace_custom(
                        snapshot.get("preauth", []), snapshot.get("block", []),
                        port_proxies=snapshot.get("port_proxies", []),
                        tunnels=snapshot.get("tunnels", {}),
                    )
            except FirewallError as exc:
                log(
                    "[settings] ERROR: installing the customized rules "
                    f"failed: {exc}"
                )
                self._write_audit(
                    "firewall_error", operation="apply_custom", reason=str(exc)
                )
                raise
            active_preauth = (
                [] if invalid else _enabled_custom_entries(
                    snapshot.get("preauth", [])
                )
            )
            active_block = (
                [] if invalid else _enabled_custom_entries(
                    snapshot.get("block", [])
                )
            )
            active_proxies = (
                [] if invalid else _enabled_custom_entries(
                    snapshot.get("port_proxies", [])
                )
            )
            log(
                f"[settings] {len(active_preauth)} pre-auth, "
                f"{len(active_block)} block, {len(active_proxies)} port proxy "
                "entries"
            )

    def _restore_custom_settings(self, old: dict) -> None:
        """Restoring the earlier pre-auth/block state in one transaction."""
        if old.get("error"):
            # The old snapshot is invalid, so we do not know the last known
            # good content of the block chains; we leave those untouched.
            self.firewall.replace_custom((), (), keep_block=True)
        else:
            self.firewall.replace_custom(
                old.get("preauth", []), old.get("block", []),
                port_proxies=old.get("port_proxies", []),
                tunnels=old.get("tunnels", {}),
            )

    def apply_settings(self, new_data: dict) -> None:
        """Installing and saving the settings prepared by the admin.

        Order: nft apply -> atomic file write. If the save fails, we restore
        the earlier nft rules.
        """
        with Gateway._custom_lock:
            old = self.settings.snapshot()
            tunnels = new_data.get("tunnels", {})
            try:
                self.firewall.replace_custom(
                    new_data.get("preauth", []), new_data.get("block", []),
                    port_proxies=new_data.get("port_proxies", []),
                    tunnels=tunnels,
                )
            except FirewallError:
                try:
                    self._restore_custom_settings(old)
                except FirewallError as rollback_exc:
                    log(
                        "[settings] restoring the earlier rules also "
                        f"failed: {rollback_exc}"
                    )
                    self._write_audit(
                        "firewall_error",
                        operation="rollback_apply",
                        reason=str(rollback_exc),
                    )
                raise
            try:
                self.settings.commit(new_data)
            except Exception:
                try:
                    self._restore_custom_settings(old)
                except FirewallError as rollback_exc:
                    log(
                        "[settings] restoring the earlier rules after a save "
                        f"error failed: {rollback_exc}"
                    )
                    self._write_audit(
                        "firewall_error",
                        operation="rollback_commit",
                        reason=str(rollback_exc),
                    )
                raise
            # The WireGuard sync runs after the save; its failure only shows
            # up in the state and does not spoil saving the settings.
            try:
                self.tunnels.reconcile(tunnels)
            except Exception as exc:
                log(f"[tunnel] WireGuard sync failed: {exc}")

    def refresh_port_proxies(self) -> list[tuple[str, int]]:
        """Re-render if an input target's port binding or route_localnet changed.

        The loopback / redirect decision depends on the target's socket, which
        may also start after the portal (at boot, Docker publishes later). On
        change the chains are replaced atomically, and the conntrack entries
        of the affected listening ports are deleted (otherwise the old
        NAT-bound UDP flow would stay alive with the client's traffic).
        """
        with Gateway._custom_lock:
            old = self.firewall.portproxy_applied
            snapshot = self.settings.snapshot()
            if old is None or snapshot.get("error"):
                return []
            try:
                new = self.firewall._portproxy_rules(
                    list(snapshot.get("port_proxies", []))
                    + tunnel_proxy_entries(snapshot.get("tunnels", {}))
                )
            except FirewallError:
                return []
            if new == old:
                return []
            self._apply_custom_settings(snapshot)
        changed = sorted({
            (match.group(1), int(match.group(2)))
            for line in set(old) ^ set(new) if " portproxy_nat " in line
            for match in [re.search(r" (tcp|udp) dport (\d+) ", line)] if match
        })
        log(
            "[port proxy] target binding changed, rules refreshed: "
            + ", ".join(f"{p}/{n}" for p, n in changed)
        )
        for proto, port in changed:
            conntrack_flush_port(proto, port, audit=self.audit)
        return changed

    def _portproxy_loop(self) -> None:
        while not self._portproxy_stop.wait(self.PORTPROXY_REFRESH_SECONDS):
            try:
                self.refresh_port_proxies()
            except Exception as exc:  # the thread must never die
                log(f"[port proxy] refresh error: {exc}")

    def start(self) -> None:
        self.sessions.start_reaper()
        # The WireGuard interface and the peers are synced at startup. The
        # error only shows in the status; the portal starts.
        try:
            self.tunnels.reconcile(
                self.settings.snapshot().get("tunnels", {})
            )
        except Exception as exc:
            log(f"[tunnel] startup WireGuard sync failed: {exc}")
        self._portproxy_stop = threading.Event()
        threading.Thread(
            target=self._portproxy_loop, name="hv-portproxy", daemon=True
        ).start()
        self._fw_watch_stop = threading.Event()
        threading.Thread(
            target=self._firewall_watch_loop, name="hv-fwwatch", daemon=True
        ).start()
        try:
            fail2ban_enabled = bool(self.fail2ban.snapshot().get("enabled"))
        except Exception:
            fail2ban_enabled = False
        self._write_audit(
            "service_start",
            reason="portal process started",
            users_count=len(self.users.names()),
            rules_count=len(self.rules.persisted_rules()),
            groups_count=len(self.groups.all_groups()),
            ttl=self.sessions.ttl,
            fail2ban_enabled=fail2ban_enabled,
            dry_run=bool(self.firewall.dry_run),
        )
        if not self.drops.start():
            status = self.drops.status()
            log(f"[drop log] inactive: {status.get('error') or 'unknown reason'}")

    def stop(self) -> None:
        for name in ("_portproxy_stop", "_fw_watch_stop"):
            stop_event = getattr(self, name, None)
            if stop_event is not None:
                stop_event.set()
        try:
            self.drops.stop()
        except Exception as exc:  # shutdown must not get stuck on logging
            log(f"[drop log] shutdown error: {exc}")
        self.sessions.stop_reaper()
        # On shutdown, no permission should stay open until the TTL.
        before_shutdown = self.sessions.count()
        try:
            revoked = self.sessions.shutdown()
        except Exception as exc:  # shutdown must not get stuck on cleanup
            log(f"[firewall] shutdown revocation failed: {exc}")
            self._write_audit(
                "session_shutdown_error", reason=str(exc)
            )
            # shutdown deletes the sessions before the firewall operations,
            # so the real count is the value before the call.
            revoked = before_shutdown
        self._write_audit(
            "service_stop",
            reason="portal process stopped",
            sessions_revoked=revoked,
        )
