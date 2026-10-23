#!/usr/bin/env python3
"""
Dropjak — administrative customization of the firewall.

Stores two rule types manageable in the portal:

* ``preauth``: destinations and ports open even before login. Their
  ``direction`` field may be ``forward`` (default: forwarded traffic, in the
  forward chain) or ``input`` (a service of the portal host itself, in the
  ``preauth_input`` chain); a missing field becomes ``forward`` on load.
  The forward direction lets traffic through even without a portal session
  (and marks it for Docker protection). An empty destination applies to every
  destination. Use it only when the destination and port are intentionally
  public; the ``input`` direction opens a host port bypassing the portal
  gateway.
* ``block``: destinations and ports that are always dropped. The block
  overrides the pre-auth rule too.

The ``site_name`` is the displayed name of the firewall/portal (when empty
the built-in name ``Dropjak`` applies); it appears in the portal header, the
browser title and as the issuer/labels of new 2FA enrollments.

``motd_text`` and ``motd_expires_at`` are the post-login notice (MOTD): an
empty text disables it, an empty ISO-8601 UTC expiry means permanent. The
portal no longer receives an expired notice.

``proxy_domains`` and ``proxy_routes`` configure the Caddy-based subdomain
proxy (empty root list = disabled): ``<name>.<root>`` (``root`` being one of
the root domains) points to the ``<port>`` of the host (``input``) or a
private-network machine behind it (``forward``, ``ip``). ``visibility`` is
``private`` (a domain rule is required) or ``public`` (anyone). ``challenge``
(``{"triggers": [...], "interval_hours": n}``, optional) defines the
conditions of the proxy challenge (captcha); without it there is no
challenge. The old single ``proxy_domain`` becomes a one-element list on
load. Caddy queries the portal's loopback endpoints per request, so no
reload or nftables operation is needed for a change.
``proxy_acme`` (default: true), when disabled, forbids on-demand ACME
certificate requests; then only uploaded certificates (CertStore, per root
domain in the ``certs/`` directory) are served.

``port_proxies`` holds the kernel-level (nftables DNAT) port proxy entries:
TCP/UDP traffic arriving on the host's ``listen_port`` is sent to the host
(``input``, ``redirect``) or a private-network machine (``forward``,
``target_ip``). The Gateway renders these into nftables chains, so this is
the only proxy setting that requires a firewall operation.

The settings are kept in the state volume, in a JSON file with 0600
permissions. If the file is damaged, the pre-auth list stays empty
(fail-closed); the admin can overwrite it in the UI.

The module deliberately does not touch nftables: the Gateway applies the
rules and commits the file only on success.
"""

from __future__ import annotations

import base64
import copy
import datetime
import hashlib
import ipaddress
import json
import os
import re
import secrets
import ssl
import tempfile
import threading
import time


BASE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.environ.get("HV_STATE_DIR", "").strip() or BASE
SETTINGS_PATH = (
    os.environ.get("HV_SETTINGS", "").strip()
    or os.path.join(STATE_DIR, "firewall-settings.json")
)

MAX_ENTRIES = 64
MAX_PORTS = 64
MAX_LABEL = 64
MAX_SITE_NAME = 64
MAX_MOTD = 2000
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
MAX_PROXY_ROUTES = 64
MAX_PROXY_DOMAINS = 16
# set_proxy()'s sentinel that the caller did not supply a challenge.
UNSET = object()
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
# At least two-label, lowercase FQDN (root domain and full proxy hostname).
_FQDN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
try:
    PORTAL_PORT = int(os.environ.get("PORT", "").strip() or 8100)
except ValueError:
    PORTAL_PORT = 8100
# Ports forbidden as proxy targets. The portal treats a request coming from
# loopback as Caddy's, so a route pointing at the portal would bypass the
# check; 80/443 are Caddy itself (a self-pointing loop), the rest are host
# services.
PROXY_RESERVED_PORTS = (22, 53, 67, 80, 443, 2019)
PROXY_PRIVATE_NETS = tuple(
    ipaddress.IPv4Network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
# Port proxy (nftables DNAT). The listening port cannot be a service of the
# host itself (SSH, DNS, DHCP, the portal redirect/Caddy 80/443, Caddy admin
# 2019) or the portal port: prerouting would take these away from them.
MAX_PORT_PROXIES = 64
PORT_PROXY_RESERVED_LISTEN = (22, 53, 67, 80, 443, 2019)
# The input proxy's target cannot be SSH (it can only be opened by an
# explicit TCP 22 host rule), Caddy admin or the portal.
PORT_PROXY_RESERVED_INPUT_TARGET = (22, 2019)
# Host ports an input-direction pre-auth entry cannot open before login: SSH
# (only an explicit TCP 22 host rule with a session opens it), DNS (a
# pre-login DNS tunnel), DHCP, Caddy admin, and the portal port, which is
# always open anyway.
PREAUTH_RESERVED_INPUT = (22, 53, 67, 2019)


def preauth_reserved_input_ports() -> tuple[int, ...]:
    """The reserved input pre-auth ports, including the portal port."""
    return tuple(sorted(set(PREAUTH_RESERVED_INPUT) | {PORTAL_PORT}))

# WireGuard tunnel (cloud side): agents get an address on the 10.77.0.0/24
# network, the server is 10.77.0.1. Internal (tunnel) ports are unique per
# agent; listening ports share a namespace with port proxies.
MAX_TUNNEL_AGENTS = 16
MAX_TUNNEL_SERVICES = 64
TUNNEL_SUBNET = ipaddress.IPv4Network("10.77.0.0/24")
TUNNEL_SERVER_ADDRESS = "10.77.0.1"
TUNNEL_DEFAULT_PORT = 51820
# The effective (per-port) entries of a port mapping, a service and an agent
# may also expand to at most this many ports.
MAX_TUNNEL_PORTS = 256
TUNNEL_RESERVED_TARGET_PORTS = (22, 2019)
# The internal port of a domain-mode (Caddy → agent → target) tunnel service
# gets an automatic, deterministic value from this range. This port does not
# appear on the WAN, only towards Caddy from wg0.
TUNNEL_DOMAIN_PORT_LOW = 41000
TUNNEL_DOMAIN_PORT_HIGH = 60999
_WG_KEY_BYTES = 32
# The token is URL-safe, at least 32 characters (secrets.token_urlsafe(32) is 43).
_TUNNEL_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
# Enrolled agents keep only SHA-256 hex digests of their tokens (DJ-25).
_TOKEN_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
# Target hostname: Docker service names may also contain underscores.
_TUNNEL_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$"
)
# The entry's challenge conditions (see README: Challenge).
PROXY_CHALLENGE_TRIGGERS = (
    "always", "interval", "daily", "after_401", "fail2ban", "suspicious",
    "new_ip", "burst",
)


def _default_log(message: str) -> None:
    print(message, flush=True)


class SettingsError(ValueError):
    """Invalid setting or entry."""


def _text(value, field: str, maximum: int = MAX_LABEL) -> str:
    if not isinstance(value, str):
        raise SettingsError(f"{field}: must be a string")
    value = value.strip()
    if not value:
        raise SettingsError(f"{field}: must not be empty")
    if len(value) > maximum:
        raise SettingsError(f"{field}: at most {maximum} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise SettingsError(f"{field}: must not contain control characters")
    return value


def _site_name(value) -> str:
    """The firewall's name: text, trimmed; may be empty."""
    if not isinstance(value, str):
        raise SettingsError("site_name: must be a string")
    value = value.strip()
    if len(value) > MAX_SITE_NAME:
        raise SettingsError(
            f"site_name: at most {MAX_SITE_NAME} characters"
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise SettingsError("site_name: must not contain control characters")
    return value


def _motd_text(value) -> str:
    """The text of the post-login notice; empty = disabled."""
    if not isinstance(value, str):
        raise SettingsError("motd: must be a string")
    value = value.strip()
    if len(value) > MAX_MOTD:
        raise SettingsError(f"motd: at most {MAX_MOTD} characters")
    return value


def _motd_expires(value) -> str:
    """The notice's expiry in ISO-8601 UTC; empty = permanent."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise SettingsError("motd: the expiry must be a string")
    text = value.strip()
    if not text:
        return ""
    try:
        parsed = datetime.datetime.fromisoformat(
            text[:-1] + "+00:00" if text.endswith("Z") else text
        )
    except ValueError:
        raise SettingsError(
            "motd: invalid expiry (an ISO-8601 timestamp is required)"
        ) from None
    if parsed.tzinfo is None:
        raise SettingsError(
            "motd: the expiry must include a timezone"
        )
    return parsed.astimezone(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def active_motd(settings: dict, now: float | None = None) -> str:
    """The text of the still-valid notice; "" when expired or empty."""
    text = settings.get("motd_text", "")
    if not text:
        return ""
    expires = settings.get("motd_expires_at", "")
    if expires:
        parsed = datetime.datetime.fromisoformat(
            expires[:-1] + "+00:00" if expires.endswith("Z") else expires
        )
        if parsed.timestamp() <= (time.time() if now is None else now):
            return ""
    return text


def _proxy_domain(value) -> str:
    """A root domain: a lowercase FQDN, or empty."""
    if not isinstance(value, str):
        raise SettingsError("proxy_domains: must be a string")
    value = value.strip().lower()
    if value and not _FQDN_RE.match(value):
        raise SettingsError(
            "proxy_domains: a valid lowercase domain name is required "
            "(e.g. z1.example.com)"
        )
    return value


def _proxy_domains(raw) -> list[str]:
    """The proxy root domains: unique FQDNs; an empty list = disabled."""
    if not isinstance(raw, list):
        raise SettingsError("proxy_domains: must be a list")
    if len(raw) > MAX_PROXY_DOMAINS:
        raise SettingsError(
            f"proxy_domains: at most {MAX_PROXY_DOMAINS} root domains are allowed"
        )
    domains = [_proxy_domain(value) for value in raw]
    if "" in domains:
        raise SettingsError(
            "proxy_domains: a valid lowercase domain name is required "
            "(e.g. z1.example.com)"
        )
    if len(set(domains)) != len(domains):
        raise SettingsError("proxy: duplicate root domain")
    return domains


def route_host(route: dict) -> str:
    """The entry's full hostname; an empty subdomain name means the root domain itself."""
    return f"{route['name']}.{route['root']}" if route["name"] else route["root"]


def _proxy_routes(raw, domains=(), default_root: str = "") -> list[dict]:
    """The entries; ``default_root`` is the root for legacy entries without one."""
    if not isinstance(raw, list):
        raise SettingsError("proxy_routes: must be a list")
    if len(raw) > MAX_PROXY_ROUTES:
        raise SettingsError(
            f"proxy_routes: at most {MAX_PROXY_ROUTES} routes are allowed"
        )
    routes: list[dict] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise SettingsError("proxy: the route must be a JSON object")
        name = item.get("name")
        if isinstance(name, str):
            name = name.strip().lower()
        # Empty name: the root domain itself (only alongside its own portal address).
        if not isinstance(name, str) or (name and not _DNS_LABEL_RE.match(name)):
            raise SettingsError(
                "proxy: the subdomain must be a single DNS label "
                "(a–z, 0–9, hyphen)"
            )
        root = item.get("root", default_root)
        if isinstance(root, str):
            root = root.strip().lower()
        if root not in domains:
            raise SettingsError(
                f"proxy: unknown root domain: {root or '—'}; a root domain "
                "can be deleted only after its entries are deleted or moved"
            )
        host = f"{name}.{root}" if name else root
        if len(host) > 253:
            raise SettingsError("proxy: the full hostname may be at most 253 characters")
        if host in seen:
            raise SettingsError("proxy: duplicate full hostname")
        if name and host in domains:
            raise SettingsError(
                f"proxy: the full hostname cannot be a root domain: {host}"
            )
        port = item.get("port")
        if isinstance(port, bool) or not isinstance(port, int) \
                or not 1 <= port <= 65535:
            raise SettingsError("proxy: the port must be between 1 and 65535")
        # An entry without a type (legacy) is a service of the host itself.
        kind = item.get("type", "input")
        if kind not in ("input", "forward"):
            raise SettingsError("proxy: the type must be input or forward")
        if kind == "input" and (
            port in PROXY_RESERVED_PORTS or port == PORTAL_PORT
        ):
            raise SettingsError(
                "proxy: reserved port (portal, 22, 53, 67, 80, 443, 2019)"
            )
        enabled = item.get("enabled", True)
        if not isinstance(enabled, bool):
            raise SettingsError("the enabled field must be true/false")
        # An entry without visibility (legacy) remains private.
        visibility = item.get("visibility", "private")
        if visibility not in ("private", "public"):
            raise SettingsError("proxy: the visibility must be private or public")
        seen.add(host)
        route = {
            "name": name, "root": root, "type": kind, "port": port,
            "enabled": enabled, "visibility": visibility,
        }
        if kind == "forward":
            route["ip"] = _proxy_ip(item.get("ip"))
        challenge = _proxy_challenge(item.get("challenge"))
        if challenge is not None:
            route["challenge"] = challenge
        routes.append(route)
    return routes


def _proxy_challenge(raw) -> dict | None:
    """The challenge conditions; a missing or empty list: no challenge."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise SettingsError("proxy: challenge must be a JSON object")
    triggers = raw.get("triggers", [])
    if not isinstance(triggers, list) or any(
        not isinstance(value, str) or value not in PROXY_CHALLENGE_TRIGGERS
        for value in triggers
    ):
        raise SettingsError("proxy: unknown challenge trigger")
    if len(set(triggers)) != len(triggers):
        raise SettingsError("proxy: duplicate challenge trigger")
    hours = raw.get("interval_hours", 24)
    if "interval" in triggers and (
        isinstance(hours, bool) or not isinstance(hours, int)
        or not 1 <= hours <= 720
    ):
        raise SettingsError("proxy: the challenge interval must be between 1 and 720 hours")
    if not triggers:
        return None
    return {
        "triggers": triggers,
        "interval_hours": hours if "interval" in triggers else 24,
    }


def _portal_domain(raw, domains, routes) -> str:
    """The Dropjak UI's own Caddy domain, or "" (root domains)."""
    if not isinstance(raw, str):
        raise SettingsError("portal_domain: must be a string")
    value = raw.strip().lower()
    # We also accept a full URL pasted from the browser.
    value = value.split("://", 1)[-1].split("/", 1)[0]
    value = value.rsplit("@", 1)[-1].split(":", 1)[0].rstrip(".")
    if not value:
        return ""
    if not _FQDN_RE.match(value):
        raise SettingsError(
            "portal_domain: a valid lowercase domain name is required "
            "(e.g. dropjak.z1.example.com)"
        )
    if value in domains:
        raise SettingsError(
            "portal_domain: the Dropjak address cannot be a root domain"
        )
    if not any(value.endswith("." + root) for root in domains):
        raise SettingsError(
            "portal_domain: the Dropjak address must be under a root domain "
            "(e.g. dropjak.z1.example.com)"
        )
    if any(route_host(route) == value for route in routes):
        raise SettingsError(
            "portal_domain: a proxy entry with this hostname already exists"
        )
    return value


def _tunnel_service_domain(value, domains, routes, portal_domain) -> str:
    """The full hostname of a domain-mode tunnel service, or "".

    The domain can only be a strict subdomain of a configured root domain,
    and must not collide with the root, the portal's own address, a proxy
    entry, or another service's domain (the latter is checked by the caller).
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        raise SettingsError("tunnel: the domain must be a string")
    value = value.strip().lower()
    if not value:
        return ""
    if not _FQDN_RE.match(value):
        raise SettingsError(
            "tunnel: a valid lowercase domain name is required (e.g. mc.example.com)"
        )
    # We reject equality with the root separately too: with several roots,
    # the root could also look like a subdomain of a longer root.
    if value in domains:
        raise SettingsError(
            "tunnel: the service domain cannot be a root domain"
        )
    if not any(value.endswith("." + root) for root in domains):
        raise SettingsError(
            "tunnel: the service domain must be under a proxy root domain"
        )
    if portal_domain and value == portal_domain:
        raise SettingsError(
            "tunnel: the service domain cannot be the Dropjak address"
        )
    if any(route_host(route) == value for route in routes):
        raise SettingsError("tunnel: a proxy entry with this hostname already exists")
    return value


def _proxy_ip(value) -> str:
    """Forward proxy target: a single private-network (RFC 1918) IPv4 address."""
    try:
        address = ipaddress.IPv4Address(
            value.strip() if isinstance(value, str) else ""
        )
    except ValueError:
        address = None
    # The three RFC 1918 ranges exclude loopback, link-local, multicast and
    # 0.0.0.0 as well.
    if address is None or not any(
        address in network for network in PROXY_PRIVATE_NETS
    ):
        raise SettingsError(
            "proxy: a forward target requires a private-network IPv4 address "
            "(10/8, 172.16/12, 192.168/16)"
        )
    return str(address)


def _port_value(value, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) \
            or not 1 <= value <= 65535:
        raise SettingsError(f"port proxy: the {field} must be between 1 and 65535")
    return value


def _port_proxy(item) -> dict:
    """Validate and normalize a port proxy entry."""
    if not isinstance(item, dict):
        raise SettingsError("port proxy: the entry must be a JSON object")
    entry_id = item.get("id")
    if entry_id in (None, ""):
        entry_id = secrets.token_hex(4)
    if not isinstance(entry_id, str) or not _ID_RE.match(entry_id):
        raise SettingsError("invalid entry ID")
    label = _text(item.get("label"), "label")
    proto = item.get("proto")
    if proto not in ("tcp", "udp", "both"):
        raise SettingsError("port proxy: the protocol must be tcp, udp or both")
    kind = item.get("type")
    if kind not in ("input", "forward"):
        raise SettingsError("port proxy: the type must be input or forward")
    listen = _port_value(item.get("listen_port"), "listen port")
    if listen in PORT_PROXY_RESERVED_LISTEN or listen == PORTAL_PORT:
        raise SettingsError(
            "port proxy: reserved listen port "
            "(portal, 22, 53, 67, 80, 443, 2019)"
        )
    target = _port_value(item.get("target_port"), "target port")
    ifaces = item.get("ifaces", "both")
    if ifaces not in ("wan", "lan", "both"):
        raise SettingsError("port proxy: the interface must be wan, lan or both")
    enabled = item.get("enabled", True)
    snat = item.get("snat", False)
    if not isinstance(enabled, bool) or not isinstance(snat, bool):
        raise SettingsError("the enabled/snat fields must be true/false")
    target_ip = ""
    if kind == "forward":
        try:
            target_ip = _proxy_ip(item.get("target_ip"))
        except SettingsError:
            raise SettingsError(
                "port proxy: a forward target requires a private-network IPv4 address "
                "(10/8, 172.16/12, 192.168/16)"
            ) from None
    else:
        if target in PORT_PROXY_RESERVED_INPUT_TARGET or target == PORTAL_PORT:
            raise SettingsError(
                "port proxy: the input target port cannot be 22, 2019 or the portal"
            )
        if target == listen:
            # A redirect on the same port does nothing: the host (input)
            # rule opens it by itself; no proxy is needed for this.
            raise SettingsError(
                "port proxy: the input proxy target port cannot be the listen "
                "port (a host rule is enough for this)"
            )
        snat = False
    return {
        "id": entry_id, "label": label, "proto": proto, "type": kind,
        "listen_port": listen, "target_ip": target_ip, "target_port": target,
        "ifaces": ifaces, "snat": snat, "enabled": enabled,
    }


def _port_proxies(raw) -> list[dict]:
    """The port proxy list; the (protocol, listen port) pair is unique."""
    if not isinstance(raw, list):
        raise SettingsError("port_proxies: must be a list")
    if len(raw) > MAX_PORT_PROXIES:
        raise SettingsError(
            f"port_proxies: at most {MAX_PORT_PROXIES} entries are allowed"
        )
    entries: list[dict] = []
    ids: set[str] = set()
    keys: set[tuple[str, int]] = set()
    for item in raw:
        entry = _port_proxy(item)
        if entry["id"] in ids:
            raise SettingsError(f"duplicate entry ID: {entry['id']}")
        ids.add(entry["id"])
        # A disabled entry also reserves the port, so enabling it cannot
        # collide.
        protos = ("tcp", "udp") if entry["proto"] == "both" else (entry["proto"],)
        for proto in protos:
            key = (proto, entry["listen_port"])
            if key in keys:
                raise SettingsError(
                    "port proxy: the listen port is already in use: "
                    f"{proto.upper()} {entry['listen_port']}"
                )
            keys.add(key)
        entries.append(entry)
    return entries


def default_tunnels() -> dict:
    """The WireGuard tunnel section's default (without agents)."""
    return {
        "port": TUNNEL_DEFAULT_PORT,
        "endpoint": "",
        "server_private_key": "",
        "server_public_key": "",
        "agents": [],
    }


def _wg_key(value, field: str, required: bool = False) -> str:
    """WireGuard key: base64, exactly 32 bytes (in canonical form)."""
    if value is None or value == "":
        if required:
            raise SettingsError(f"{field}: missing WireGuard key")
        return ""
    if not isinstance(value, str):
        raise SettingsError(f"{field}: invalid WireGuard key")
    try:
        raw = base64.b64decode(value.strip().encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        raw = b""
    if len(raw) != _WG_KEY_BYTES:
        raise SettingsError(
            f"{field}: invalid WireGuard key (base64, 32 bytes required)"
        )
    return base64.b64encode(raw).decode("ascii")


def wg_key(value, field: str) -> str:
    """A required WireGuard key in canonical form (SettingsError otherwise)."""
    return _wg_key(value, field, True)


def token_hash(token: str) -> str:
    """SHA-256 hex digest under which enrollment and sync tokens are stored."""
    return hashlib.sha256(token.encode("utf-8", "replace")).hexdigest()


def tunnel_agent_legacy(agent: dict) -> bool:
    """Whether the agent still has gateway-generated keys (pre-enrollment)."""
    return bool(agent.get("private_key"))


def _token_hash_field(value, field: str) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or not _TOKEN_HASH_RE.match(value):
        raise SettingsError(f"{field}: a SHA-256 hex digest is required")
    return value


def _tunnel_agent_keys(item) -> dict:
    """The key and token fields of an agent, in one of two shapes.

    Legacy: the gateway generated the agent's key pair, PSK and sync token
    and stores them in clear. Enrollment (DJ-08/DJ-25): the agent generates
    its own keys; the gateway keeps only the public key, the PSK the agent
    sent and SHA-256 digests of the one-time enrollment token and the sync
    token. ``public_key`` is null until the agent enrolls.
    """
    legacy_fields = ("private_key", "token")
    enroll_fields = ("sync_token_hash", "enroll_token_hash", "enroll_expires")
    if any(item.get(name) not in (None, "") for name in legacy_fields):
        if any(item.get(name) not in (None, "", 0) for name in enroll_fields):
            raise SettingsError(
                "tunnel: an agent has either stored keys or an enrollment, "
                "not both"
            )
        token = item.get("token")
        if not isinstance(token, str) or not _TUNNEL_TOKEN_RE.match(token):
            raise SettingsError(
                "tunnel: invalid agent token (32+ URL-safe characters are "
                "required)"
            )
        return {
            "private_key": _wg_key(
                item.get("private_key"), "tunnel: the agent's private key",
                True,
            ),
            "public_key": _wg_key(
                item.get("public_key"), "tunnel: the agent's public key", True
            ),
            "preshared_key": _wg_key(
                item.get("preshared_key"), "tunnel: the preshared key", True
            ),
            "token": token,
        }
    public_key = _wg_key(
        item.get("public_key"), "tunnel: the agent's public key"
    ) or None
    preshared_key = _wg_key(
        item.get("preshared_key"), "tunnel: the preshared key"
    )
    sync_hash = _token_hash_field(
        item.get("sync_token_hash"), "tunnel: the sync token hash"
    )
    enroll_hash = _token_hash_field(
        item.get("enroll_token_hash"), "tunnel: the enrollment token hash"
    )
    expires = item.get("enroll_expires", 0)
    if expires is None:
        expires = 0
    if isinstance(expires, bool) or not isinstance(expires, int) \
            or expires < 0:
        raise SettingsError(
            "tunnel: the enrollment expiry must be a non-negative integer"
        )
    if public_key:
        if not (preshared_key and sync_hash):
            raise SettingsError(
                "tunnel: an enrolled agent needs a preshared key and a sync "
                "token hash"
            )
        if enroll_hash:
            raise SettingsError(
                "tunnel: an enrolled agent cannot have an open enrollment"
            )
        expires = 0
    elif preshared_key or sync_hash:
        raise SettingsError(
            "tunnel: an agent waiting for enrollment has no preshared key or "
            "sync token"
        )
    if not enroll_hash:
        expires = 0
    return {
        "public_key": public_key,
        "preshared_key": preshared_key,
        "sync_token_hash": sync_hash,
        "enroll_token_hash": enroll_hash,
        "enroll_expires": expires,
    }


def tunnel_enrollment_state(agent: dict, now: float | None = None) -> str:
    """legacy, enrolled, pending (open token), expired or none."""
    if tunnel_agent_legacy(agent):
        return "legacy"
    if agent.get("public_key"):
        return "enrolled"
    if not agent.get("enroll_token_hash"):
        return "none"
    now = time.time() if now is None else now
    return "pending" if now < int(agent.get("enroll_expires") or 0) \
        else "expired"


def _tunnel_address(value) -> str:
    """The agent's address on the 10.77.0.0/24 network, 10.77.0.2–254."""
    try:
        address = ipaddress.IPv4Address(value if isinstance(value, str) else "")
    except ValueError:
        address = None
    if address is None or address not in TUNNEL_SUBNET \
            or not 2 <= address.packed[-1] <= 254:
        raise SettingsError(
            "tunnel: the agent address must be an IPv4 address between 10.77.0.2 and 10.77.0.254"
        )
    return str(address)


def _tunnel_host(value, field: str) -> str:
    if not isinstance(value, str):
        raise SettingsError(f"{field}: must be a string")
    value = value.strip()
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        pass
    if not _TUNNEL_HOST_RE.match(value):
        raise SettingsError(f"{field}: a valid hostname or IPv4 address is required")
    return value


def _tunnel_endpoint(value) -> str:
    """The public endpoint hostname; when empty, the request's Host is used."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise SettingsError("tunnel: the endpoint must be a string")
    value = value.strip()
    if not value:
        return ""
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise SettingsError("tunnel: the endpoint must not contain whitespace")
    return _tunnel_host(value, "tunnel: the endpoint")


def _tunnel_target(value) -> str:
    """The target in ``host:port`` form (hostname or IPv4)."""
    if not isinstance(value, str) or ":" not in value:
        raise SettingsError("tunnel: the target must be in host:port form")
    host, _, port = value.strip().rpartition(":")
    if not host:
        raise SettingsError("tunnel: the target must be in host:port form")
    host = _tunnel_host(host, "tunnel: the target")
    try:
        number = int(port, 10)
    except ValueError:
        number = 0
    if not 1 <= number <= 65535:
        raise SettingsError("tunnel: the target port must be between 1 and 65535")
    return f"{host}:{number}"


def _parse_tunnel_port_token(value: str, field: str) -> tuple[int, int]:
    """A port or ``lo-hi`` range (inclusive interval)."""
    text = value.strip().replace("–", "-").replace("—", "-")
    match = re.fullmatch(r"(\d+)(?:\s*-\s*(\d+))?", text)
    if match is None:
        raise SettingsError(f"{field}: invalid port: {value!r}")
    low = int(match.group(1))
    high = int(match.group(2)) if match.group(2) else low
    if not 1 <= low <= 65535 or not 1 <= high <= 65535:
        raise SettingsError(f"{field}: the port must be between 1 and 65535: {value}")
    if low > high:
        raise SettingsError(
            f"{field}: the range start cannot be greater than the end: "
            f"{value}"
        )
    return low, high


def _tunnel_port_list(value, field: str,
                      maximum: int = MAX_TUNNEL_PORTS) -> tuple[int, ...]:
    """Port list preserving the entered order.

    Accepts an integer, a comma/space/semicolon separated string or a list;
    an item may be a port or a ``lo-hi`` range. A range expands in ascending
    order, but the list's item order stays unchanged: listen and target
    ports are paired by index in the same order. A duplicate port is an error
    only in the check after pairing. The limit applies to the number of
    resolved ports.
    """
    if value is None:
        raise SettingsError(f"{field}: a port list is required")
    if isinstance(value, str):
        value = [
            part for part in re.split(r"[\s,;]+", value.strip()) if part
        ]
    elif isinstance(value, int) and not isinstance(value, bool):
        value = [value]
    if not isinstance(value, (list, tuple)):
        raise SettingsError(f"{field}: a port list is required")
    intervals: list[tuple[int, int]] = []
    for part in value:
        if isinstance(part, str):
            part = part.strip()
            if not part:
                continue
            intervals.append(_parse_tunnel_port_token(part, field))
        elif isinstance(part, int) and not isinstance(part, bool):
            intervals.append(_parse_tunnel_port_token(str(part), field))
        else:
            raise SettingsError(f"{field}: invalid port: {part!r}")
    if not intervals:
        raise SettingsError(f"{field}: at least one port is required")
    total = sum(high - low + 1 for low, high in intervals)
    if total > maximum:
        raise SettingsError(f"{field}: at most {maximum} ports may be given")
    return tuple(
        port for low, high in intervals for port in range(low, high + 1)
    )


def _format_tunnel_port_sequence(ports) -> str:
    """The compact text of the ports in the given (pairing) order.

    It merges only consecutive, ascending ports into a range; it neither
    reorders nor deduplicates, so the listen and target port pairing is
    preserved on read-back.
    """
    parts: list[str] = []
    if not ports:
        return ""
    start = previous = ports[0]
    for port in ports[1:]:
        if port == previous + 1:
            previous = port
            continue
        parts.append(
            str(start) if start == previous else f"{start}-{previous}"
        )
        start = previous = port
    parts.append(str(start) if start == previous else f"{start}-{previous}")
    return ", ".join(parts)


def _pair_tunnel_ports(listen, target, proto: str) -> list[tuple[int, int]]:
    """Index-wise pairing and validation of the listen and target ports.

    A duplicate listen port could only occur with the same target and the same
    protocol, but that is an error too; a duplicate target port is allowed
    (several listen ports may point to the same place). The pairs are
    returned sorted by listen port, then target port.
    """
    pairs = list(zip(listen, target))
    seen: dict[int, int] = {}
    for listen_port, target_port in pairs:
        previous = seen.get(listen_port)
        if previous is not None:
            if previous != target_port:
                raise SettingsError(
                    "tunnel: the same listen port points to different target "
                    f"ports: {listen_port} ({previous} != {target_port})"
                )
            raise SettingsError(
                "tunnel: the listen port appears more than once: "
                f"{proto.upper()} {listen_port}"
            )
        seen[listen_port] = target_port
    return sorted(pairs)


def _normalize_tunnel_mappings(raw_mappings) -> list[dict]:
    """Validate the ``mappings`` list and write it into canonical form."""
    if not isinstance(raw_mappings, list):
        raise SettingsError("tunnel: mappings must be a list")
    if not raw_mappings:
        raise SettingsError("tunnel: at least one port mapping is required")
    mappings: list[dict] = []
    total = 0
    for index, raw in enumerate(raw_mappings, 1):
        if not isinstance(raw, dict):
            raise SettingsError(
                f"tunnel: port mapping #{index} must be a JSON object"
            )
        proto = raw.get("proto")
        if proto not in ("tcp", "udp", "both"):
            raise SettingsError("tunnel: the protocol must be tcp, udp or both")
        listen = _tunnel_port_list(
            raw.get("listen"), "tunnel: the listen port"
        )
        target = _tunnel_port_list(raw.get("target"), "tunnel: the target port")
        if len(target) != len(listen):
            if len(target) == 1 and len(listen) > 1:
                raise SettingsError(
                    "tunnel: one target port cannot correspond to several listen ports"
                )
            raise SettingsError(
                "tunnel: the number of target ports does not match the number of listen ports: "
                f"{len(listen)} != {len(target)}"
            )
        pairs = _pair_tunnel_ports(listen, target, proto)
        for port in listen:
            if port in PORT_PROXY_RESERVED_LISTEN or port == PORTAL_PORT:
                raise SettingsError(
                    "tunnel: reserved listen port "
                    "(portal, 22, 53, 67, 80, 443, 2019)"
                )
        for port in target:
            if port in TUNNEL_RESERVED_TARGET_PORTS:
                raise SettingsError(
                    "tunnel: the target port cannot be 22 or 2019"
                )
        total += len(pairs)
        if total > MAX_TUNNEL_PORTS:
            raise SettingsError(
                f"tunnel: at most {MAX_TUNNEL_PORTS} ports "
                "can be mapped per service"
            )
        # The canonical form sorts the pairs (listen, then target port) and
        # writes both sides in the same pair order so that read-back pairs
        # them the same way.
        mappings.append({
            "proto": proto,
            "listen": _format_tunnel_port_sequence(
                [listen_port for listen_port, _ in pairs]
            ),
            "target": _format_tunnel_port_sequence(
                [target_port for _, target_port in pairs]
            ),
        })
    return mappings


def _normalize_tunnel_domain_mappings(raw_mappings) -> list[dict]:
    """Validate the single TCP mapping of a domain-mode service.

    A domain-mode service is served by Caddy over HTTPS, so only one TCP
    mapping is meaningful. The listen (internal tunnel) port may be omitted:
    in that case ``_tunnels`` assigns it. The target port must be a single
    port as usual.
    """
    if not isinstance(raw_mappings, list):
        raise SettingsError("tunnel: mappings must be a list")
    if len(raw_mappings) != 1:
        raise SettingsError(
            "tunnel: a domain-mode service requires exactly one port mapping"
        )
    raw = raw_mappings[0]
    if not isinstance(raw, dict):
        raise SettingsError(
            "tunnel: the port mapping must be a JSON object"
        )
    if raw.get("proto") != "tcp":
        raise SettingsError("tunnel: a domain-mode service can only be TCP")
    listen_text = ""
    listen_raw = raw.get("listen")
    if listen_raw not in (None, ""):
        listen = _tunnel_port_list(listen_raw, "tunnel: the listen port")
        if len(listen) != 1:
            raise SettingsError(
                "tunnel: a domain-mode service requires a single internal port"
            )
        if listen[0] in PORT_PROXY_RESERVED_LISTEN or listen[0] == PORTAL_PORT:
            raise SettingsError(
                "tunnel: reserved internal port "
                "(portal, 22, 53, 67, 80, 443, 2019)"
            )
        listen_text = str(listen[0])
    target = _tunnel_port_list(raw.get("target"), "tunnel: the target port")
    if len(target) != 1:
        raise SettingsError(
            "tunnel: a domain-mode service requires a single target port"
        )
    if target[0] in TUNNEL_RESERVED_TARGET_PORTS:
        raise SettingsError("tunnel: the target port cannot be 22 or 2019")
    return [{
        "proto": "tcp", "listen": listen_text, "target": str(target[0]),
    }]


def _mapping_ports(mappings) -> list[dict]:
    """The effective, per-port list of a service's mappings.

    tcp and udp for the same listen/target port pair merge into ``both``; a
    different target port or a duplicate protocol raises an error.
    """
    effective: dict[int, dict] = {}
    for mapping in mappings or []:
        proto = mapping.get("proto")
        listen = _tunnel_port_list(
            mapping.get("listen"), "tunnel: the listen port"
        )
        target = _tunnel_port_list(mapping.get("target"), "tunnel: the target port")
        if len(target) != len(listen):
            raise SettingsError(
                "tunnel: the number of target ports does not match the number of listen ports"
            )
        for listen_port, target_port in zip(listen, target):
            current = effective.get(listen_port)
            if current is None:
                effective[listen_port] = {
                    "proto": proto, "listen_port": listen_port,
                    "target_port": target_port, "tunnel_port": listen_port,
                }
                continue
            if current["target_port"] != target_port:
                raise SettingsError(
                    "tunnel: the same listen port points to different target ports: "
                    f"{listen_port} ({current['target_port']} != {target_port})"
                )
            if {current["proto"], proto} == {"tcp", "udp"}:
                current["proto"] = "both"
                continue
            raise SettingsError(
                "tunnel: the listen port appears more than once: "
                f"{proto.upper()} {listen_port}"
            )
    return sorted(
        effective.values(),
        key=lambda item: (item["listen_port"], item["proto"]),
    )


def tunnel_service_ports(service) -> list[dict]:
    """The effective ports of a service.

    Each returned item is ``{proto, listen_port, target_port, tunnel_port}``,
    where the tunnel port always equals the listen port. The list is sorted
    by listen port.
    """
    if not isinstance(service, dict):
        raise SettingsError("tunnel: the service must be a JSON object")
    return _mapping_ports(service.get("mappings", []))


def _agent_effective_ports(agent, enabled_only: bool) -> list[dict]:
    """The combined, per-port list of the agent's services."""
    if not isinstance(agent, dict):
        return []
    effective: dict[int, dict] = {}
    for service in agent.get("services", []):
        if not isinstance(service, dict):
            continue
        if enabled_only and not service.get("enabled", True):
            continue
        for item in tunnel_service_ports(service):
            listen_port = item["listen_port"]
            current = effective.get(listen_port)
            if current is None:
                effective[listen_port] = {
                    "service_id": service.get("id", ""),
                    "label": service.get("label", ""),
                    "target_host": service.get("target_host", ""),
                    "domain": service.get("domain", ""),
                    "public": bool(service.get("public", False)),
                    **item,
                }
                continue
            if item["target_port"] != current["target_port"]:
                raise SettingsError(
                    "tunnel: the same listen port points to different target ports: "
                    f"{listen_port}"
                )
            if item["proto"] == current["proto"] \
                    or "both" in (item["proto"], current["proto"]):
                raise SettingsError(
                    "tunnel: the listen port appears more than once on the "
                    f"agent: {listen_port}"
                )
            if service.get("target_host", "") != current["target_host"]:
                raise SettingsError(
                    "tunnel: the same listen port points to different target hosts: "
                    f"{listen_port}"
                )
            current["proto"] = "both"
    if len(effective) > MAX_TUNNEL_PORTS:
        raise SettingsError(
            f"tunnel: at most {MAX_TUNNEL_PORTS} ports "
            "can be mapped per agent"
        )
    return sorted(
        effective.values(),
        key=lambda item: (item["listen_port"], item["proto"]),
    )


def agent_services_expanded(agent) -> list[dict]:
    """The effective ports of enabled services, deterministically.

    Item: ``{service_id, label, target_host, proto, listen_port,
    target_port, tunnel_port}``. tcp+udp mappings pointing to the same
    listen/target port pair merge into ``both``; within the agent a single
    effective entry remains per listen port.
    """
    return _agent_effective_ports(agent, enabled_only=True)


def tunnel_service_index(tunnels) -> dict[str, dict]:
    """Index of enabled tunnel services by reference.

    Key: ``"<agent ID>/<service ID>"``. Value: ``{agent_id, service_id,
    label, target_host, domain, public, tcp, udp}``, where ports are ordered
    tuples. A disabled agent or service is not included, so a missing
    reference yields empty ports when the rule is resolved (fail-closed).
    ``tcp``/``udp`` are filled in for the ``both`` protocol too. For a
    domain-mode service both are empty (no WAN port), but ``signature``
    contains the mapping.
    """
    index: dict[str, dict] = {}
    if not isinstance(tunnels, dict):
        return index
    for agent in tunnels.get("agents", []):
        if not isinstance(agent, dict) or not agent.get("enabled", True):
            continue
        try:
            expanded = agent_services_expanded(agent)
        except SettingsError:
            # A faulty agent must not break the whole resolution; its faulty
            # services simply cannot be resolved.
            continue
        for item in expanded:
            ref = f"{agent.get('id', '')}/{item['service_id']}"
            entry = index.setdefault(ref, {
                "agent_id": agent.get("id", ""),
                "service_id": item["service_id"],
                "label": item.get("label", ""),
                "target_host": item.get("target_host", ""),
                "domain": item.get("domain", ""),
                "public": bool(item.get("public", False)),
                "tcp": set(),
                "udp": set(),
                # The full per-protocol mapping (listen port, target host,
                # target port). The rule's decision-time check compares this
                # so that a target host/port redirect invalidates the old
                # authorization even if the listen ports did not change.
                "signature": set(),
            })
            if item.get("domain"):
                # Domain-mode service: there is no WAN listen port, so the
                # service rule cannot open a port either, but it opens its
                # domain through the proxy gateway. Besides the mapping, the
                # signature also contains the domain name so that a rename
                # invalidates the earlier decision.
                entry["signature"].add((
                    "domain", 0, item.get("domain", ""), 0,
                ))
                entry["signature"].add((
                    "tcp", item["listen_port"],
                    item.get("target_host", ""), item["target_port"],
                ))
                continue
            if item["proto"] in ("tcp", "both"):
                entry["tcp"].add(item["listen_port"])
                entry["signature"].add((
                    "tcp", item["listen_port"],
                    item.get("target_host", ""), item["target_port"],
                ))
            if item["proto"] in ("udp", "both"):
                entry["udp"].add(item["listen_port"])
                entry["signature"].add((
                    "udp", item["listen_port"],
                    item.get("target_host", ""), item["target_port"],
                ))
    return {
        ref: {
            **entry,
            "tcp": tuple(sorted(entry["tcp"])),
            "udp": tuple(sorted(entry["udp"])),
            "signature": tuple(sorted(entry["signature"])),
        }
        for ref, entry in index.items()
    }


def _tunnel_service(item, domains=(), routes=(), portal_domain="",
                    seen_domains=None) -> dict:
    """Validate and normalize a tunnel service.

    Legacy (single-port) form: ``listen_port`` + ``tunnel_port`` +
    ``target: host:port``. This is automatically converted to the new
    ``mappings`` form; the old ``tunnel_port`` is lost (the listen port
    becomes the tunnel port too).

    In domain mode (``domain != ""``) the service may contain only one TCP
    mapping; the listen port is the internal tunnel port, which ``_tunnels``
    assigns when the value is missing.
    """
    if not isinstance(item, dict):
        raise SettingsError("tunnel: the service must be a JSON object")
    service_id = item.get("id")
    if service_id in (None, ""):
        service_id = secrets.token_hex(4)
    if not isinstance(service_id, str) or not _ID_RE.match(service_id):
        raise SettingsError("tunnel: invalid service ID")
    label = _text(item.get("label"), "tunnel: label")
    enabled = item.get("enabled", True)
    if not isinstance(enabled, bool):
        raise SettingsError("the enabled field must be true/false")
    public = item.get("public", False)
    if not isinstance(public, bool):
        raise SettingsError("the public field must be true/false")
    domain = _tunnel_service_domain(
        item.get("domain"), domains, routes, portal_domain
    )
    if domain and seen_domains is not None:
        if domain in seen_domains:
            raise SettingsError(
                f"tunnel: duplicate service domain: {domain}"
            )
        seen_domains.add(domain)
    # A challenge is meaningful only for a domain-mode service: Caddy queries
    # on this host, and the synthetic target forwards the conditions.
    challenge = _proxy_challenge(item.get("challenge"))
    if challenge is not None and not domain:
        raise SettingsError(
            "tunnel: a challenge can only be given for a domain-mode service"
        )
    if "mappings" in item:
        if domain and not (
            isinstance(item.get("target_host"), str)
            and item["target_host"].strip()
        ):
            raise SettingsError(
                "tunnel: a domain-mode service requires a target host"
            )
        target_host = _tunnel_host(
            item.get("target_host"), "tunnel: the target host"
        )
        if domain:
            mappings = _normalize_tunnel_domain_mappings(item.get("mappings"))
        else:
            mappings = _normalize_tunnel_mappings(item.get("mappings"))
    else:
        if domain:
            raise SettingsError(
                "tunnel: a domain-mode service requires a mappings list"
            )
        # Legacy form migration.
        proto = item.get("proto")
        if proto not in ("tcp", "udp", "both"):
            raise SettingsError("tunnel: the protocol can only be tcp, udp or both")
        listen = item.get("listen_port")
        if isinstance(listen, bool) or not isinstance(listen, int) \
                or not 1 <= listen <= 65535:
            raise SettingsError(
                "tunnel: the listen port must be between 1 and 65535"
            )
        old_target = _tunnel_target(item.get("target"))
        target_host, _, target_port = old_target.rpartition(":")
        mappings = _normalize_tunnel_mappings([{
            "proto": proto, "listen": str(listen), "target": target_port,
        }])
    if not domain:
        _mapping_ports(mappings)
    service = {
        "id": service_id, "label": label, "target_host": target_host,
        "enabled": enabled, "public": public, "domain": domain,
        "mappings": mappings,
    }
    if challenge is not None:
        service["challenge"] = challenge
    return service


def _tunnel_agent(item, domains=(), routes=(), portal_domain="",
                  seen_domains=None) -> dict:
    """Validate an agent (keys or enrollment, address, services)."""
    if not isinstance(item, dict):
        raise SettingsError("tunnel: the agent must be a JSON object")
    agent_id = item.get("id")
    if agent_id in (None, ""):
        agent_id = secrets.token_hex(4)
    if not isinstance(agent_id, str) or not _ID_RE.match(agent_id):
        raise SettingsError("tunnel: invalid agent ID")
    label = _text(item.get("label"), "tunnel: label")
    address = _tunnel_address(item.get("address"))
    keys = _tunnel_agent_keys(item)
    enabled = item.get("enabled", True)
    if not isinstance(enabled, bool):
        raise SettingsError("the enabled field must be true/false")
    raw_services = item.get("services", [])
    if not isinstance(raw_services, list):
        raise SettingsError("tunnel: services must be a list")
    if len(raw_services) > MAX_TUNNEL_SERVICES:
        raise SettingsError(
            f"tunnel: at most {MAX_TUNNEL_SERVICES} "
            "services per agent"
        )
    services: list[dict] = []
    service_ids: set[str] = set()
    for raw_service in raw_services:
        service = _tunnel_service(
            raw_service, domains, routes, portal_domain, seen_domains
        )
        if service["id"] in service_ids:
            raise SettingsError(
                "tunnel: duplicate service ID: "
                f"{service['id']}"
            )
        service_ids.add(service["id"])
        services.append(service)
    return {
        "id": agent_id, "label": label, "address": address,
        **keys,
        "enabled": enabled, "services": services,
    }


def _assign_tunnel_domain_ports(agents, wg_port: int) -> None:
    """Assign the internal tunnel ports of domain-mode services.

    The assignment is deterministic: in agent, then service order, the
    lowest free port in the 41000-60999 range. The reserved set contains
    every explicit (numeric) listen port, the WireGuard port, the reserved
    listen ports and the portal port, plus the previously assigned internal
    ports. A saved explicit internal port stays unchanged on revalidation.
    """
    explicit: set[int] = set()
    for agent in agents:
        for service in agent.get("services", []):
            if service.get("domain"):
                continue
            for item in tunnel_service_ports(service):
                explicit.add(item["listen_port"])
    reserved = set(PORT_PROXY_RESERVED_LISTEN)
    reserved.add(PORTAL_PORT)
    reserved.add(wg_port)
    used = set(explicit) | reserved
    assigned: set[int] = set()
    # Collision check of the already saved internal ports.
    for agent in agents:
        for service in agent.get("services", []):
            if not service.get("domain"):
                continue
            listen = str(service["mappings"][0].get("listen", "")).strip()
            if not listen:
                continue
            port = int(listen)
            if port in assigned or port in explicit or port in reserved:
                raise SettingsError(
                    "tunnel: the internal (tunnel) port is already taken: "
                    f"{port}"
                )
            assigned.add(port)
            used.add(port)
    # Assign the missing internal ports.
    for agent in agents:
        for service in agent.get("services", []):
            if not service.get("domain"):
                continue
            mapping = service["mappings"][0]
            if str(mapping.get("listen", "")).strip():
                continue
            for port in range(
                TUNNEL_DOMAIN_PORT_LOW, TUNNEL_DOMAIN_PORT_HIGH + 1
            ):
                if port in used:
                    continue
                mapping["listen"] = str(port)
                assigned.add(port)
                used.add(port)
                break
            else:
                raise SettingsError(
                    "tunnel: no free internal tunnel port "
                    f"({TUNNEL_DOMAIN_PORT_LOW}–{TUNNEL_DOMAIN_PORT_HIGH})"
                )


def _tunnels(raw, domains=(), routes=(), portal_domain="") -> dict:
    """The WireGuard tunnel section; a missing key means defaults."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise SettingsError("tunnels: a JSON object is required")
    port = raw.get("port", TUNNEL_DEFAULT_PORT)
    if isinstance(port, bool) or not isinstance(port, int) \
            or not 1024 <= port <= 65535:
        raise SettingsError(
            "tunnel: the WireGuard port must be between 1024 and 65535"
        )
    if port in PORT_PROXY_RESERVED_LISTEN or port == PORTAL_PORT:
        raise SettingsError(
            "tunnel: reserved WireGuard port "
            "(portal, 22, 53, 67, 80, 443, 2019)"
        )
    raw_agents = raw.get("agents", [])
    if not isinstance(raw_agents, list):
        raise SettingsError("tunnel: agents must be a list")
    if len(raw_agents) > MAX_TUNNEL_AGENTS:
        raise SettingsError(
            f"tunnel: at most {MAX_TUNNEL_AGENTS} agents"
        )
    agents: list[dict] = []
    agent_ids: set[str] = set()
    addresses: set[str] = set()
    seen_domains: set[str] = set()
    for raw_agent in raw_agents:
        agent = _tunnel_agent(
            raw_agent, domains, routes, portal_domain, seen_domains
        )
        if agent["id"] in agent_ids:
            raise SettingsError(
                f"tunnel: duplicate agent ID: {agent['id']}"
            )
        agent_ids.add(agent["id"])
        if agent["address"] in addresses:
            raise SettingsError(
                f"tunnel: duplicate agent address: {agent['address']}"
            )
        addresses.add(agent["address"])
        agents.append(agent)
    server_private_key = _wg_key(
        raw.get("server_private_key"), "tunnel: the server private key"
    )
    server_public_key = _wg_key(
        raw.get("server_public_key"), "tunnel: the server public key"
    )
    if agents and not (server_private_key and server_public_key):
        raise SettingsError(
            "tunnel: a server WireGuard key pair is required to save agents"
        )
    _assign_tunnel_domain_ports(agents, port)
    # Collisions within the agent and the limit on effective ports. The
    # internal port of domain-mode services is part of the agent's namespace.
    for agent in agents:
        _agent_effective_ports(agent, enabled_only=False)
    return {
        "port": port,
        "endpoint": _tunnel_endpoint(raw.get("endpoint", "")),
        "server_private_key": server_private_key,
        "server_public_key": server_public_key,
        "agents": agents,
    }


def _check_tunnel_listen_ports(port_proxies, tunnels) -> None:
    """The shared namespace of listen ports with port proxies (``both`` claims two)."""
    keys: set[tuple[str, int]] = set()
    # With an enabled agent the WireGuard UDP port carries inbound traffic;
    # a listen port on the same number would send the handshake to the proxy.
    wg_port = tunnels["port"] if any(
        agent["enabled"] for agent in tunnels["agents"]
    ) else None
    if wg_port is not None:
        for entry in port_proxies:
            if entry["listen_port"] == wg_port \
                    and entry["proto"] in ("udp", "both"):
                raise SettingsError(
                    "port proxy: the listen port collides with the WireGuard port: "
                    f"UDP {wg_port}"
                )
        for agent in tunnels["agents"]:
            for item in _agent_effective_ports(agent, enabled_only=False):
                if item.get("domain"):
                    # The internal port of a domain-mode service is not a WAN
                    # listen port, so it cannot collide with the WireGuard port.
                    continue
                if item["listen_port"] == wg_port \
                        and item["proto"] in ("udp", "both"):
                    raise SettingsError(
                        "tunnel: the listen port collides with the WireGuard port: "
                        f"UDP {wg_port}"
                    )
    for entry in port_proxies:
        for proto in (
            ("tcp", "udp") if entry["proto"] == "both" else (entry["proto"],)
        ):
            keys.add((proto, entry["listen_port"]))
    for agent in tunnels["agents"]:
        for item in _agent_effective_ports(agent, enabled_only=False):
            if item.get("domain"):
                # The internal tunnel port is not part of the WAN listen port namespace.
                continue
            for proto in (
                ("tcp", "udp") if item["proto"] == "both"
                else (item["proto"],)
            ):
                key = (proto, item["listen_port"])
                if key in keys:
                    raise SettingsError(
                        "tunnel: the listen port is already taken: "
                        f"{proto.upper()} {item['listen_port']}"
                    )
                keys.add(key)


def _normalize_dst(raw, warnings: list[str] | None = None) -> str:
    """Normalize a destination (IP or CIDR) of a pre-auth or block entry.

    New and edited entries are strict: ``10.0.0.5/8`` is a typo, not a
    request for all of 10/8, so it is rejected. With ``warnings`` (loading
    a stored file) a destination with host bits is instead normalized to
    its network and a warning is appended, so one hand-edited entry does
    not invalidate the whole file (which would clear every pre-auth entry).
    """
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise SettingsError("destination: a string is required (IP or CIDR)")
    raw = raw.strip()
    if not raw:
        return ""
    try:
        network = ipaddress.ip_network(raw, strict=True)
    except ValueError as exc:
        host_bits = "has host bits set" in str(exc)
        if not host_bits or warnings is None:
            raise SettingsError(
                f"invalid destination (host bits must be zero): {raw}"
                if host_bits
                else f"invalid destination: {raw}"
            ) from exc
        network = ipaddress.ip_network(raw, strict=False)
        warnings.append(
            f"destination {raw} has host bits set; loaded as {network}"
        )
    if network.version != 4:
        raise SettingsError(f"only an IPv4 destination can be given: {raw}")
    if network.is_multicast:
        raise SettingsError(f"a multicast destination cannot be used: {raw}")
    if network.prefixlen == 32 and network.network_address.is_unspecified:
        raise SettingsError("the 0.0.0.0/32 destination cannot be used")
    if network.prefixlen == 32 and str(network.network_address) == "255.255.255.255":
        raise SettingsError("a broadcast destination cannot be used")
    if network.prefixlen == 32:
        return str(network.network_address)
    return str(network)


def _normalize_direction(raw) -> str:
    """The direction of a pre-auth entry: ``forward`` (default) or ``input``."""
    if raw is None:
        return "forward"
    if not isinstance(raw, str):
        raise SettingsError("the direction can only be forward or input")
    value = raw.strip()
    if not value:
        return "forward"
    if value not in ("forward", "input"):
        raise SettingsError(f"invalid direction: {raw!r}")
    return value


PREAUTH_SCOPES = ("lan", "any")


def _normalize_scope(raw) -> str:
    """The scope of an input pre-auth entry: ``lan`` (default) or ``any``.

    ``lan`` opens the host port only to traffic arriving on the LAN
    interface; ``any`` also to the WAN (and every other interface). Older
    entries have no scope: they load as ``lan``.
    """
    if raw is None:
        return "lan"
    if not isinstance(raw, str):
        raise SettingsError("the scope can only be lan or any")
    value = raw.strip().lower()
    if not value:
        return "lan"
    if value not in PREAUTH_SCOPES:
        raise SettingsError(f"invalid scope: {raw!r}")
    return value


def _normalize_ports(raw) -> list[int]:
    if not isinstance(raw, list):
        raise SettingsError("ports: a list is required")
    if len(raw) > MAX_PORTS:
        raise SettingsError(f"ports: at most {MAX_PORTS} ports can be given")
    ports: list[int] = []
    for value in raw:
        if isinstance(value, bool):
            raise SettingsError(f"invalid port: {value!r}")
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
            try:
                value = int(value, 10)
            except ValueError as exc:
                raise SettingsError(f"invalid port: {value}") from exc
        if not isinstance(value, int):
            raise SettingsError(f"invalid port: {value!r}")
        if value < 1 or value > 65535:
            raise SettingsError(f"the port must be between 1 and 65535: {value}")
        if value not in ports:
            ports.append(value)
    if not ports:
        raise SettingsError("at least one port is required")
    return sorted(ports)


def normalize_entry(
    kind: str, entry, entry_id: str = "", warnings: list[str] | None = None
) -> dict:
    """Validate one pre-auth or block entry.

    ``warnings`` is only passed when a stored file is loaded: see
    :func:`_normalize_dst`.
    """
    if kind not in ("preauth", "block"):
        raise SettingsError(f"unknown settings type: {kind!r}")
    if not isinstance(entry, dict):
        raise SettingsError("the entry must be a JSON object")
    if entry_id:
        if not _ID_RE.match(entry_id):
            raise SettingsError("invalid entry ID")
    else:
        entry_id = secrets.token_hex(4)
        while not _ID_RE.match(entry_id):
            entry_id = secrets.token_hex(4)
    # The type is not stored in the entry; the list carries it.
    label = _text(entry.get("label"), "label")
    dst = _normalize_dst(entry.get("dst", ""), warnings)
    proto = str(entry.get("proto", "")).strip().lower()
    if proto not in ("tcp", "udp"):
        raise SettingsError(f"invalid protocol: {entry.get('proto')!r}")
    ports = _normalize_ports(entry.get("ports"))
    enabled = entry.get("enabled", True)
    if not isinstance(enabled, bool):
        raise SettingsError("the enabled field must be true/false")
    if kind == "block" and proto == "tcp" and 80 in ports and not dst:
        # Prerouting sends port 80 to the portal; without a destination the
        # block would not take effect, so we do not allow this silently.
        raise SettingsError(
            "blocking TCP port 80 requires a destination "
            "(otherwise the portal redirect takes precedence)"
        )
    direction = ""
    scope = ""
    if kind == "preauth":
        # Older entries have no direction: those are forward.
        direction = _normalize_direction(entry.get("direction"))
        # The scope only applies to the input direction; it is still
        # validated, so a typo is not silently dropped.
        scope = _normalize_scope(entry.get("scope"))
    normalized = {
        "id": entry_id,
        "label": label,
        "dst": dst,
        "proto": proto,
        "ports": ports,
        "enabled": enabled,
    }
    if kind == "preauth":
        normalized["direction"] = direction
        if direction == "input":
            normalized["scope"] = scope
    return normalized


def check_preauth_input_ports(entry: dict) -> None:
    """Reject an input pre-auth entry that would open a reserved host port.

    Called for new and edited entries only. A stored entry from an older
    version must not invalidate the whole settings file on load (that
    would drop every block entry); the firewall renderer skips its
    reserved ports instead.
    """
    if entry.get("direction") != "input":
        return
    reserved = sorted(
        set(entry.get("ports") or ()) & set(preauth_reserved_input_ports())
    )
    if reserved:
        raise SettingsError(
            "an input pre-auth entry cannot open these host ports: "
            + ", ".join(str(port) for port in reserved)
            + " (SSH needs a host rule and a session)"
        )


def legacy_proxy_domain(data) -> str:
    """The single pre-3.6 ``proxy_domain`` (empty for the new format)."""
    if not isinstance(data, dict) or "proxy_domains" in data:
        return ""
    return _proxy_domain(data.get("proxy_domain", ""))


def validate_state(data, warnings: list[str] | None = None) -> dict:
    """Validate a whole settings state.

    ``warnings`` is passed only by :meth:`SettingsStore.load`: then a
    pre-auth or block destination with host bits is normalized (and
    reported there) instead of invalidating the file. Saving, import and
    export stay strict.
    """
    if not isinstance(data, dict):
        raise SettingsError("settings must be a JSON object")
    registration_enabled = data.get("registration_enabled", False)
    if not isinstance(registration_enabled, bool):
        raise SettingsError(
            "the registration_enabled field must be true/false"
        )
    # A file without the key (legacy) gets the previous behaviour: ACME on.
    proxy_acme = data.get("proxy_acme", True)
    if not isinstance(proxy_acme, bool):
        raise SettingsError("the proxy_acme field must be true/false")
    legacy = legacy_proxy_domain(data)
    if "proxy_domains" in data:
        domains = _proxy_domains(data["proxy_domains"])
    else:
        # Legacy format: the single root becomes a list, and rootless entries
        # receive it. Without a root those entries had no effect, so they are
        # dropped (the old key disappears on the next write).
        domains = [legacy] if legacy else []
    raw_routes = data.get("proxy_routes", [])
    if "proxy_domains" not in data and not legacy:
        raw_routes = []
    routes = _proxy_routes(raw_routes, domains, legacy)
    portal_domain = _portal_domain(data.get("portal_domain", ""), domains, routes)
    # A root entry is only possible when the portal already runs on its own
    # address; otherwise the root serves the portal.
    if not portal_domain and any(not route["name"] for route in routes):
        raise SettingsError(
            "proxy: a root entry requires a dedicated portal address"
        )
    port_proxies = _port_proxies(data.get("port_proxies", []))
    tunnels = _tunnels(
        data.get("tunnels"), domains, routes, portal_domain
    )
    # The listen ports share a namespace with port proxies; this can only be
    # checked here, where both lists are visible.
    _check_tunnel_listen_ports(port_proxies, tunnels)
    result = {
        "site_name": _site_name(data.get("site_name", "")),
        "motd_text": _motd_text(data.get("motd_text", "")),
        "motd_expires_at": _motd_expires(data.get("motd_expires_at", "")),
        "registration_enabled": registration_enabled,
        "proxy_domains": domains,
        "proxy_routes": routes,
        "proxy_acme": proxy_acme,
        # The Dropjak UI's own address and its challenge; with an empty
        # address the root domains serve the portal.
        "portal_domain": portal_domain,
        "portal_challenge": (
            _proxy_challenge(data.get("portal_challenge"))
            if portal_domain else None
        ),
        # A file without the key (legacy) has no port proxy and no tunnel.
        "port_proxies": port_proxies,
        "tunnels": tunnels,
        "preauth": [],
        "block": [],
    }
    for kind in ("preauth", "block"):
        raw_list = data.get(kind, [])
        if not isinstance(raw_list, list):
            raise SettingsError(f"{kind}: a list is required")
        if len(raw_list) > MAX_ENTRIES:
            raise SettingsError(
                f"{kind}: at most {MAX_ENTRIES} entries are allowed"
            )
        seen: set[str] = set()
        for raw_entry in raw_list:
            if not isinstance(raw_entry, dict):
                raise SettingsError(f"{kind}: the entry must be a JSON object")
            entry_id = raw_entry.get("id")
            if entry_id is not None and not isinstance(entry_id, str):
                raise SettingsError("invalid entry ID")
            entry = normalize_entry(kind, raw_entry, entry_id or "", warnings)
            if entry["id"] in seen:
                raise SettingsError(
                    f"duplicate entry ID: {entry['id']}"
                )
            seen.add(entry["id"])
            result[kind].append(entry)
    return result


class SettingsStore:
    """Loading, modifying and atomically writing firewall-settings.json."""

    def __init__(
        self,
        path: str = SETTINGS_PATH,
        logger=_default_log,
    ) -> None:
        self.path = os.path.abspath(path)
        self.log = logger
        self._lock = threading.Lock()
        self._data = self._defaults()
        self._error = ""
        # The legacy, single root domain of the loaded file (empty otherwise):
        # the rule store uses this to resolve old, dotless domain references.
        self.legacy_proxy_domain = ""
        self.load()

    def _defaults(self) -> dict:
        return {
            "site_name": "",
            "motd_text": "",
            "motd_expires_at": "",
            "registration_enabled": False,
            "proxy_domains": [],
            "proxy_routes": [],
            "proxy_acme": True,
            "portal_domain": "",
            "portal_challenge": None,
            "port_proxies": [],
            "tunnels": default_tunnels(),
            "preauth": [],
            "block": [],
        }

    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            warnings: list[str] = []
            data = validate_state(raw, warnings)
            legacy = legacy_proxy_domain(raw)
        except FileNotFoundError:
            with self._lock:
                self._data = self._defaults()
                self._error = ""
            return
        except (OSError, ValueError, SettingsError) as exc:
            with self._lock:
                # With a corrupt file pre-auth must be empty in any case.
                self._data = self._defaults()
                self._error = str(exc)
            self.log(
                f"[settings] WARNING: {self.path} cannot be read, "
                f"customization falls back to defaults: {exc}"
            )
            return
        for warning in warnings:
            # A hand-edited file; the portal writes normalized networks.
            self.log(f"[settings] WARNING: {self.path}: {warning}")
        if isinstance(raw, dict) and "proxy_domains" not in raw \
                and raw.get("proxy_routes") and not legacy:
            self.log(
                "[settings] dropping legacy proxy entries without a root "
                "domain (they had no effect)"
            )
        with self._lock:
            self._data = data
            self._error = ""
            self.legacy_proxy_domain = legacy

    def snapshot(self) -> dict:
        with self._lock:
            data = copy.deepcopy(self._data)
            data["error"] = self._error
            return data

    def _copy_locked(self) -> dict:
        return copy.deepcopy(self._data)

    def prepare(
        self,
        action: str,
        kind: str = "",
        entry_id: str = "",
        entry=None,
    ) -> dict:
        """Validate the change and produce the new state.

        Does not write a file and does not modify the in-memory state; the
        caller first applies it to nftables, then saves with commit().
        """
        with self._lock:
            data = self._copy_locked()
        action = str(action or "").strip().lower()
        if kind not in ("preauth", "block"):
            raise SettingsError(f"unknown settings type: {kind!r}")
        entries = data[kind]
        if action == "create":
            if len(entries) >= MAX_ENTRIES:
                raise SettingsError(
                    f"{kind}: at most {MAX_ENTRIES} entries are allowed"
                )
            normalized = normalize_entry(kind, entry)
            if kind == "preauth":
                check_preauth_input_ports(normalized)
            if any(item["id"] == normalized["id"] for item in entries):
                raise SettingsError("duplicate entry ID")
            entries.append(normalized)
        elif action in ("update", "delete", "toggle"):
            if not isinstance(entry_id, str) or not entry_id:
                raise SettingsError("missing entry ID")
            index = next(
                (
                    pos for pos, item in enumerate(entries)
                    if item["id"] == entry_id
                ),
                None,
            )
            if index is None:
                raise SettingsError(f"no such entry: {entry_id}")
            if action == "delete":
                del entries[index]
            elif action == "toggle":
                enabled = entry.get("enabled") if isinstance(entry, dict) else None
                if not isinstance(enabled, bool):
                    raise SettingsError("the enabled field must be true/false")
                entries[index]["enabled"] = enabled
            else:
                normalized = normalize_entry(kind, entry, entry_id)
                if kind == "preauth":
                    check_preauth_input_ports(normalized)
                entries[index] = normalized
        else:
            raise SettingsError(f"unknown operation: {action!r}")
        return validate_state(data)

    def prepare_port_proxies(self, entries) -> dict:
        """Validate the new port proxy list (without writing a file).

        A port proxy requires nftables chains, so the caller applies it
        first (Gateway.apply_settings) and only then commits.
        """
        with self._lock:
            data = self._copy_locked()
        data["port_proxies"] = _port_proxies(entries)
        return validate_state(data)

    def prepare_tunnels(self, tunnels) -> dict:
        """Validate the tunnel section (without writing a file)."""
        with self._lock:
            data = self._copy_locked()
        data["tunnels"] = _tunnels(
            tunnels,
            data.get("proxy_domains", []),
            data.get("proxy_routes", []),
            data.get("portal_domain", ""),
        )
        return validate_state(data)

    def commit(self, data: dict) -> dict:
        checked = validate_state(data)
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=directory, prefix=".firewall-settings-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(
                    checked, fh, ensure_ascii=False, indent=2, sort_keys=False
                )
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self.path)
            try:
                dir_fd = os.open(directory, os.O_RDONLY)
            except OSError:
                dir_fd = -1
            if dir_fd >= 0:
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        with self._lock:
            self._data = copy.deepcopy(checked)
            self._error = ""
        return copy.deepcopy(checked)

    def reset(self) -> None:
        """Delete the settings file and reset the state."""
        with self._lock:
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self._data = self._defaults()
            self._error = ""
            self.legacy_proxy_domain = ""

    def set_registration_enabled(self, enabled: bool) -> dict:
        """Enable or disable registration (account requests).

        Only writes the settings file atomically; does not touch nftables.
        """
        if not isinstance(enabled, bool):
            raise SettingsError(
                "the registration_enabled field must be true/false"
            )
        with self._lock:
            data = self._copy_locked()
        data["registration_enabled"] = enabled
        return self.commit(data)

    def set_site_name(self, name: str) -> dict:
        """Save the firewall's name.

        An empty value restores the built-in ``Dropjak`` name. Only writes
        the settings file atomically; does not touch nftables.
        """
        value = _site_name(name)
        with self._lock:
            data = self._copy_locked()
        data["site_name"] = value
        return self.commit(data)

    def set_motd(self, text: str, expires_at: str = "") -> dict:
        """Save the post-login announcement.

        Empty text disables it; an empty expiry means it never expires.
        Only writes the settings file atomically; does not touch nftables.
        """
        with self._lock:
            data = self._copy_locked()
        data["motd_text"] = text
        data["motd_expires_at"] = expires_at
        return self.commit(data)

    def set_proxy_acme(self, enabled: bool) -> dict:
        """Enable or disable automatic (on-demand ACME) certificate requests."""
        if not isinstance(enabled, bool):
            raise SettingsError("the proxy_acme field must be true/false")
        with self._lock:
            data = self._copy_locked()
        data["proxy_acme"] = enabled
        return self.commit(data)

    def set_portal_domain(self, domain: str) -> dict:
        """The Dropjak UI's own Caddy domain (empty: the root domains).

        Disabling it also clears its challenge. Only writes the settings
        file atomically; does not touch nftables.
        """
        if not isinstance(domain, str):
            raise SettingsError("portal_domain: a string is required")
        with self._lock:
            data = self._copy_locked()
        data["portal_domain"] = domain
        if not domain.strip():
            data["portal_challenge"] = None
        return self.commit(data)

    def seed_proxy(self, domains, portal_domain="") -> dict:
        """One-time initial proxy configuration from the environment.

        Only for the first start, while the settings file does not exist
        yet: ``configure.sh``'s HTTPS mode passes the root domain(s) in
        ``HV_PROXY_DOMAINS`` and the Dropjak subdomain in
        ``HV_PORTAL_DOMAIN``. Once the file exists the admin interface
        (Admin → Settings → Proxy) is authoritative; a later start must not
        overwrite it. The values go through the same normalizers as
        :meth:`set_proxy` and the whole state is committed atomically.
        """
        domains = _proxy_domains(list(domains or []))
        with self._lock:
            data = self._copy_locked()
        data["proxy_domains"] = domains
        data["portal_domain"] = portal_domain
        return self.commit(data)

    def set_proxy(self, domains, routes, referenced=(), portal_challenge=UNSET) -> dict:
        """Save the proxy root domains and routes.

        ``referenced`` holds the full host names referenced by domain
        rules: those must not disappear (deletion, rename or moving under
        another root). Only writes the settings file atomically; does not
        touch nftables.
        """
        domains = _proxy_domains(domains)
        routes = _proxy_routes(routes, domains)
        missing = sorted(
            set(referenced)
            - {route_host(route) for route in routes}
        )
        if missing:
            raise SettingsError(
                "proxy: a domain rule references it, so it cannot be deleted "
                f"or renamed: {', '.join(missing)}; remove it from the "
                "rule first"
            )
        with self._lock:
            data = self._copy_locked()
        data["proxy_domains"] = domains
        data["proxy_routes"] = routes
        if portal_challenge is not UNSET:
            data["portal_challenge"] = portal_challenge
        return self.commit(data)


# ------------------------------------------------------------ certificates

CERT_DIR = os.path.join(STATE_DIR, "certs")
MAX_CERT_PEM = 64 * 1024
CERT_WARN_DAYS = 14
_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----"
)


def _pem(value, field: str) -> str:
    """Basic validation of an uploaded PEM text (size, ASCII)."""
    if not isinstance(value, str):
        raise SettingsError(f"{field}: a PEM string is required")
    if len(value.encode("utf-8")) > MAX_CERT_PEM:
        raise SettingsError(f"{field}: at most {MAX_CERT_PEM // 1024} KiB")
    value = value.strip()
    if not value or not value.isascii():
        raise SettingsError(f"{field}: invalid PEM")
    return value + "\n"


def _decode_cert(path: str) -> dict:
    """The data of the first certificate (stdlib, but a private API: empty on error)."""
    decode = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decode is None:
        return {}
    try:
        return decode(path) or {}
    except (ssl.SSLError, OSError, ValueError):
        return {}


def _name_of(rdns, key: str = "commonName") -> str:
    for rdn in rdns or ():
        for name, value in rdn:
            if name == key:
                return str(value)
    return ""


def cert_covers(name: str, sans) -> bool:
    """Does the SAN list cover the name (exact or single-label wildcard)."""
    if name in sans:
        return True
    label, _, parent = name.partition(".")
    return bool(label and parent) and f"*.{parent}" in sans


def _write_private(path: str, data: bytes) -> None:
    """Atomic write with 0600 permissions (like the settings file)."""
    directory = os.path.dirname(path)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".cert-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


class CertStore:
    """Uploaded certificate chain and private key per root domain.

    ``<dir>/<root>.pem`` (chain) and ``<root>.key`` (key), directory 0700,
    files 0600. The key and the PEM never end up in an API response or in
    the log; only metadata goes out (public()). Caddy receives the chain
    and the key at the loopback-only /api/proxy/cert endpoint (bundle()).
    """

    def __init__(self, directory: str = CERT_DIR, logger=_default_log) -> None:
        self.directory = os.path.abspath(directory)
        self.log = logger
        self._lock = threading.Lock()
        # root -> {"bundle": bytes, "meta": dict}
        self._certs: dict[str, dict] = {}
        self.load()

    def _paths(self, root: str) -> tuple[str, str]:
        base = os.path.join(self.directory, root)
        return base + ".pem", base + ".key"

    def _check(
        self,
        root: str,
        chain: str,
        key: str,
        now: float,
        directory: str | None = None,
    ) -> dict:
        """Check the pair on temporary 0600 files; returns the metadata."""
        directory = self.directory if directory is None else directory
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        paths = []
        try:
            for data in (chain, key):
                fd, path = tempfile.mkstemp(
                    dir=directory, prefix=".check-", suffix=".pem"
                )
                paths.append(path)
                with os.fdopen(fd, "w", encoding="ascii") as fh:
                    fh.write(data)
            try:
                # For an encrypted key the password callback returns an
                # error instead of prompting on the tty.
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
                    paths[0], paths[1], password=lambda: b""
                )
            except ssl.SSLError as exc:
                raise SettingsError(
                    "the certificate and the key cannot be read, or do not "
                    "belong together"
                ) from exc
            info = _decode_cert(paths[0])
        finally:
            for path in paths:
                try:
                    os.unlink(path)
                except OSError:
                    pass
        try:
            not_before = ssl.cert_time_to_seconds(info["notBefore"])
            not_after = ssl.cert_time_to_seconds(info["notAfter"])
        except (KeyError, ValueError) as exc:
            raise SettingsError("the certificate data cannot be read") from exc
        if not_after <= now:
            raise SettingsError("the certificate has expired")
        sans = [
            str(value).lower()
            for kind, value in info.get("subjectAltName", ())
            if kind == "DNS"
        ]
        if root not in sans and f"*.{root}" not in sans:
            raise SettingsError(
                f"the certificate's SAN list does not cover: {root} / *.{root}"
            )
        issuer = info.get("issuer")
        return {
            "subject_cn": _name_of(info.get("subject")),
            "issuer": _name_of(issuer) or _name_of(issuer, "organizationName"),
            "sans": sans,
            "not_before": int(not_before),
            "not_after": int(not_after),
            "fingerprint": hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(_PEM_CERT_RE.findall(chain)[0])
            ).hexdigest(),
        }

    def load(self) -> None:
        """Load the stored pairs; a faulty pair is skipped (and logged)."""
        certs: dict[str, dict] = {}
        try:
            names = sorted(os.listdir(self.directory))
        except FileNotFoundError:
            names = []
        except OSError as exc:
            self.log(f"[certificates] the directory cannot be read: {exc}")
            names = []
        for name in names:
            root = name[:-4]
            if not name.endswith(".pem") or not _FQDN_RE.match(root):
                continue
            pem_path, key_path = self._paths(root)
            try:
                with open(pem_path, encoding="ascii") as fh:
                    chain = fh.read()
                with open(key_path, encoding="ascii") as fh:
                    key = fh.read()
                # An expired stored certificate is also loaded (the UI
                # reports it), but bundle() does not hand it out.
                meta = self._check(root, chain, key, 0)
            except (OSError, ValueError) as exc:
                self.log(f"[certificates] {root} skipped: {exc}")
                continue
            certs[root] = {"bundle": (chain + key).encode("ascii"), "meta": meta}
        with self._lock:
            self._certs = certs

    def _validate_pair(
        self,
        root: str,
        chain,
        key,
        now: float | None = None,
        directory: str | None = None,
    ) -> tuple[str, str, str, dict]:
        """Full validation of a PEM pair without writing (import and save)."""
        root = _proxy_domain(root)
        if not root:
            raise SettingsError("missing root domain")
        chain = _pem(chain, "certificate chain")
        key = _pem(key, "private key")
        if "PRIVATE KEY" in chain or not _PEM_CERT_RE.search(chain):
            raise SettingsError(
                "certificate chain: only CERTIFICATE PEM block(s) are allowed"
            )
        if "PRIVATE KEY-----" not in key or "CERTIFICATE" in key \
                or "ENCRYPTED" in key:
            raise SettingsError(
                "private key: a single, unencrypted PRIVATE KEY PEM block"
            )
        meta = self._check(
            root, chain, key,
            time.time() if now is None else now,
            directory,
        )
        return root, chain, key, meta

    def validate_import(self, root: str, chain, key) -> dict:
        """Validate a pair to be imported without touching the store.

        An expired pair is also accepted (the UI reports it and Caddy does
        not serve it), so a previous state can be restored from a backup.
        """
        with tempfile.TemporaryDirectory(prefix="hv-cert-import-") as tmp:
            return self._validate_pair(
                root, chain, key, now=0, directory=tmp
            )[3]

    def export_all(self) -> dict[str, dict]:
        """Every stored pair (PEM + key) for the configuration bundle."""
        with self._lock:
            roots = sorted(self._certs)
        out: dict[str, dict] = {}
        for root in roots:
            pem_path, key_path = self._paths(root)
            try:
                with open(pem_path, encoding="ascii") as fh:
                    chain = fh.read()
                with open(key_path, encoding="ascii") as fh:
                    key = fh.read()
            except OSError as exc:
                raise SettingsError(
                    f"the certificate pair for {root} cannot be read: {exc}"
                ) from exc
            out[root] = {"cert": chain, "key": key}
        return out

    def replace_all(self, certs) -> None:
        """Replace all pairs; every pair is validated first."""
        if not isinstance(certs, dict):
            raise SettingsError("the certs section must be a JSON object")
        checked: dict[str, tuple[str, str]] = {}
        for raw_root, item in certs.items():
            if not isinstance(item, dict):
                raise SettingsError(f"{raw_root}: invalid certificate entry")
            root, chain, key, _meta = self._validate_pair(
                raw_root, item.get("cert"), item.get("key"), now=0
            )
            if root in checked:
                raise SettingsError(f"duplicate root domain: {root}")
            checked[root] = (chain, key)
        with self._lock:
            old = set(self._certs)
        for root in old - set(checked):
            self.delete(root)
        for root, (chain, key) in checked.items():
            self.install(root, chain, key, now=0)

    def reset(self) -> None:
        """Delete every stored pair (factory reset)."""
        try:
            names = os.listdir(self.directory)
        except FileNotFoundError:
            names = []
        except OSError as exc:
            raise SettingsError(
                f"the certificate directory cannot be read: {exc}"
            ) from exc
        for name in names:
            ext = os.path.splitext(name)[1]
            if ext not in (".pem", ".key"):
                continue
            try:
                os.unlink(os.path.join(self.directory, name))
            except FileNotFoundError:
                pass
        with self._lock:
            self._certs = {}
        try:
            os.rmdir(self.directory)
        except OSError:
            pass

    def install(self, root: str, chain, key, now: float | None = None) -> dict:
        """Save a valid pair (also replacing one); returns the metadata."""
        root, chain, key, meta = self._validate_pair(root, chain, key, now)
        pem_path, key_path = self._paths(root)
        # Key first: an interrupted replacement is filtered out by load()
        # through the pair check.
        _write_private(key_path, key.encode("ascii"))
        _write_private(pem_path, chain.encode("ascii"))
        with self._lock:
            self._certs[root] = {
                "bundle": (chain + key).encode("ascii"), "meta": meta,
            }
        return dict(meta)

    def delete(self, root: str) -> dict | None:
        """Delete the pair; returns the removed metadata (or None if absent)."""
        with self._lock:
            entry = self._certs.pop(root, None)
        for path in self._paths(root) if _FQDN_RE.match(root or "") else ():
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        return dict(entry["meta"]) if entry else None

    def prune(self, roots) -> dict[str, dict]:
        """Delete the pairs of root domains that no longer exist."""
        with self._lock:
            orphans = [root for root in self._certs if root not in roots]
        return {root: self.delete(root) for root in orphans}

    def bundle(self, name: str, root: str, now: float | None = None):
        """For Caddy: chain + key when the root's pair validly covers the name."""
        with self._lock:
            entry = self._certs.get(root)
        if entry is None:
            return None
        meta = entry["meta"]
        if meta["not_after"] <= (time.time() if now is None else now):
            return None
        return entry["bundle"] if cert_covers(name, meta["sans"]) else None

    def public(self, settings: dict, now: float | None = None) -> list[dict]:
        """Metadata and the covered/uncovered names per root domain."""
        now = time.time() if now is None else now
        with self._lock:
            metas = {root: dict(e["meta"]) for root, e in self._certs.items()}
        out = []
        for root in settings.get("proxy_domains", []):
            item = {"root": root, "installed": root in metas}
            meta = metas.get(root)
            if meta is not None:
                hosts = [root] + [
                    route_host(route)
                    for route in settings.get("proxy_routes", [])
                    if route["root"] == root and route["name"]
                ]
                days = (meta["not_after"] - now) / 86400
                item.update(meta)
                item["covered"] = [h for h in hosts if cert_covers(h, meta["sans"])]
                item["uncovered"] = [
                    h for h in hosts if not cert_covers(h, meta["sans"])
                ]
                item["expires_in_days"] = int(days)
                item["warning"] = (
                    "expired" if days <= 0
                    else "expiring" if days < CERT_WARN_DAYS else ""
                )
            out.append(item)
        return out
