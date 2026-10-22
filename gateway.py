#!/usr/bin/env python3
"""
Dropjak — a kapu magja.

Ez a modul nem foglalkozik HTTP-vel. Felhasználók, jelszó-hashelés,
munkamenetek, captcha és nftables-integráció vannak benne. A HTTP-réteg
a server.py-ban él.

Biztonsági alapelv: a jelszó önmagában csak választási lehetőséget ad, és
hálózati hozzáférés CSAK akkor jön létre, ha az nftables-szabály tényleg
érvénybe lépett. Ha a tűzfal nem frissíthető, nincs engedély.
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


# --------------------------------------------------------------- konfiguráció

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
    """Az induláskori ürítés döntése.

    ``flush``: a kezelő kérte a tiszta indulást.
    ``reconcile``: az ürítés ki van kapcsolva, de az árva engedélyek nem
    maradhatnak a kernelben; a dinamikus halmazokat a memóriabeli (üres)
    munkamenet-táblához igazítjuk.
    ``stale_allowed``: kifejezett, nem biztonságos opt-in; a korábbi
    engedélyek a kernel TTL-ig életben maradhatnak.
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

# Fenntartott, régi szabály-azonosító. A korábbi beépített teljes
# hozzáférésű szabály azonosítója; ma már nem létezik szabály, de az
# azonosítót soha nem adjuk ki és nem lehet felvenni, hogy egy régi
# rules.json/users.json/groups.json ne keltsen új életre rejtett
# jogosultságot.
LEGACY_ADMIN_RULE_ID = "admin-full"
ROLE_ADMIN = "admin"
ROLE_USER = "user"

# Induláskori admin fiók a Docker Compose környezetéből. Kikapcsolt
# állapotban a portál nem nyúl a felhasználókhoz.
ADMIN_ENABLED = _env_bool("HV_ADMIN_ENABLED", False)
ADMIN_USER = os.environ.get("HV_ADMIN_USER", "").strip()
ADMIN_PASSWORD = os.environ.get("HV_ADMIN_PASSWORD", "")
# A jelszó környezeti változó helyett fájlból is jöhet (Docker secret,
# csak root által olvasható fájl). Ha mindkettő meg van adva, a közvetlen
# változó az elsődleges.
ADMIN_PASSWORD_FILE = os.environ.get("HV_ADMIN_PASSWORD_FILE", "").strip()
if not ADMIN_PASSWORD and ADMIN_PASSWORD_FILE:
    try:
        with open(ADMIN_PASSWORD_FILE, "r", encoding="utf-8") as _admin_pw_file:
            ADMIN_PASSWORD = _admin_pw_file.read().rstrip("\r\n")
    except (OSError, UnicodeError):
        ADMIN_PASSWORD = ""

PORT = _env_int("PORT", 8100, 1)
CHALLENGE_TTL = _env_int("HV_CHALLENGE_TTL", 600, 30)   # másodperc

# A belépés után a felhasználó választja ki a hozzáférés hosszát. A termék
# szintű korlát 1 perc – 30 nap; a HV_MIN_TTL/HV_MAX_TTL csak szűkítheti.
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
# A jelszó megadása és a szolgáltatásválasztás közötti ablak.
AUTH_TTL = min(max(_env_int("HV_AUTH_TTL", 600, 1), 60), 3600)
# Visszafelé kompatibilitás: a régi név az alapértelmezett hozzáférési idő.
SESSION_TTL = DEFAULT_TTL

SERVICES_PATH = (
    os.environ.get("HV_SERVICES_FILE", "").strip()
    or os.path.join(BASE, "services.json")
)
# Az eredeti POW_DIFFICULTY nevet is elfogadjuk a visszafelé kompatibilitásért.
POW_DIFFICULTY = min(
    6, _env_int("HV_POW_DIFFICULTY", _env_int("POW_DIFFICULTY", 4, 1), 1)
)
PBKDF2_ITERATIONS = _env_int("HV_PBKDF2_ITERATIONS", 600_000, 10_000)

RATE_WINDOW = _env_int("HV_RATE_WINDOW", 60, 1)
RATE_MAX = _env_int("HV_RATE_MAX", 10, 1)

NFT_BIN = os.environ.get("HV_NFT_BIN", "").strip() or shutil.which("nft") or "/usr/sbin/nft"
NFT_TABLE = os.environ.get("HV_NFT_TABLE", "hatarvedelem").strip()
NFT_SET = os.environ.get("HV_NFT_SET", "allowed_v4").strip()
CONNTRACK_BIN = os.environ.get("HV_CONNTRACK_BIN", "").strip() or shutil.which("conntrack") or ""
# A forward-lánc által megjelölt csomagok azonosítója. A Docker-védelem
# csak ezt a jelölést engedi át. A sablon és a portál ugyanezt használja.
FWD_MARK = os.environ.get("HV_FWD_MARK", "0x44524a4b").strip().lower()
if not re.match(r"^0x[0-9a-f]{1,8}$", FWD_MARK):
    FWD_MARK = "0x44524a4b"
# A pre-auth port 80-as forgalma a preroutingban conntrack-jelölést kap,
# hogy a portál-átirányítás ne térítse el. Ez nem hozzáférési jelölés.
PREAUTH_CT_MARK = "0x50524541"
CUSTOM_CHAINS = (
    "preauth",
    "preauth_input",
    "block",
    "preauth_nat",
    "block_nat",
)
# A port proxy (nftables DNAT) futásidejű láncai. A sablon csak a rájuk
# ugró szabályokat tartalmazza, a tartalmukat a portál tölti fel:
#   portproxy_nat:   DNAT/redirect (a -101-es prerouting láncból, a Docker
#                    DNAT-je előtt)
#   portproxy_input: a redirectelt (input) proxy engedélyezése
#   portproxy_snat:  a kért forward bejegyzések masquerade-je
PORTPROXY_CHAINS = ("portproxy_nat", "portproxy_input", "portproxy_snat")
# A WireGuard-alagút UDP-portjának fogadó lánca. A portál tölti fel; ügynök
# nélkül üres marad, ezért a WireGuard port zárva van.
TUNNEL_CHAIN = "tunnel_input"

# Drop-alapú fail2ban: csak a valódi, engedély nélküli TCP-forgalom számít.
# A MAC/spoof/ipv6/fail2ban/dns/ssh okok kimaradnak (hamis forrás-IP vagy
# szabályos, lejárt munkamenet), és a szabályos kliens UDP-háttérzaja
# (mDNS, LLMNR, NetBIOS, DNS) sem tiltás.
DROP_BAN_REASONS = frozenset(
    {"no-grant", "wan-drop", "input-wan", "input-lan", "portproxy"}
)
DROP_BAN_SKIP_TCP_PORTS = frozenset({53})
# Az admin Tűzfal nézet nyers (iptables -L -n jellegű) kiírásában megjelenő
# láncok sorrendje. A custom láncok a forward után következnek, hogy a
# pre-auth és a blokk szabályai egy helyen, olvasható sorrendben legyenek.
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
    """Csak az engedélyezett, jól formált pre-auth/blokk bejegyzések.

    A felületen kikapcsolt (``enabled: false``) bejegyzés nem kerülhet a
    kernelbe: a kapcsoló a szabály tényleges eltávolítását jelenti, nem
    csak a felületi elrejtését. A nem szótár alakú elemek kimaradnak, mert
    azokat az nft szabály-összeállítás úgysem tudná értelmezni.
    """
    return [
        entry for entry in entries
        if isinstance(entry, dict) and entry.get("enabled", True)
    ]


def tunnel_proxy_entries(tunnels) -> list[dict]:
    """A bekapcsolt alagút-szolgáltatások szintetikus port proxy bejegyzései.

    A DNAT a felhő hallgató portjáról az ügynök WireGuard-címére mutat; a
    forward engedélyezést a forward lánc meglévő ct original szabálya adja,
    ezért a bejegyzés ``forward`` típusú. A ``_tunnel`` jelölés választja el
    a felhasználói port proxy bejegyzésektől (figyelmeztetés, conntrack).
    """
    entries: list[dict] = []
    if not isinstance(tunnels, dict):
        return entries
    for agent in tunnels.get("agents", []):
        if not isinstance(agent, dict) or not agent.get("enabled"):
            continue
        for item in settings_store.agent_services_expanded(agent):
            if item.get("domain"):
                # Domaines szolgáltatás: nincs WAN-hallgató port és DNAT; a
                # forgalom a Caddyn át, a WireGuard-alagúton megy.
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
    """A nyilvános, portos alagút-szolgáltatások WAN pre-auth párjai.

    Csak bekapcsolt ügynök bekapcsolt, ``public`` szolgáltatásai kerülnek
    bele, és csak a port-módúak: a domaines szolgáltatásnak nincs WAN-
    hallgató portja. Elem: ``(proto, listen_port)``; a ``both`` két
    protokollra bomlik. A lista determinisztikusan rendezett.
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
# Ugyanazt a megengedő logikát használjuk, mint a többi logikai változónál:
# 1/true/yes/on (kis/nagybetűtől és környező szóköztől függetlenül). A régi
# ``== "1"`` összehasonlítás a ``true``/``yes``/``on`` értékeket csendben
# kikapcsolta, ami induláskor a kernelben maradt engedélyeket jelentett.
FLUSH_ON_START = _env_bool("HV_FLUSH_ON_START", True)
# Kifejezett, NEM biztonságos opt-in: ha a kezelő kikapcsolta az induláskori
# ürítést, ezzel engedélyezheti, hogy a korábbi folyamat kernelben maradt
# engedélyei a TTL-ig életben maradjanak. Alapértelmezésben tiltott: ilyenkor
# a portál a memóriabeli (üres) munkamenet-táblához igazítja a dinamikus
# halmazokat, és eltávolítja az árva engedélyeket.
ALLOW_STALE_GRANTS_ON_START = _env_bool(
    "HV_ALLOW_STALE_GRANTS_ON_START", False
)

# A LAN interfész és hálózat. Ha mindkettő ismert, a portál a kliens
# engedélyezett IP-jéhez az ARP-táblából származó MAC-címet is rögzíti, és
# a tűzfal a LAN-on csak ezzel a MAC-címmel engedi át a forgalmat. Ez zárja
# ki, hogy egy kliens egy másik engedélyezett kliens IP-címét használja.
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
# A Caddy domain proxy be van-e kapcsolva (HV_PROXY=1): ekkor a portál a
# gyökérdomaineken HTTPS-en is elérhető.
PROXY_ENABLED = _env_bool("HV_PROXY", False)
# A Caddy admin API-ja (Unix socket a közös caddy-admin köteten); a portál
# ezen keresztül üríti a Caddy tanúsítvány-gyorsítótárát. Üresen kikapcsolva.
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

# Időalapú egyszeri jelszó (TOTP, RFC 6238) a kétfaktoros belépéshez.
TOTP_ISSUER = os.environ.get("HV_TOTP_ISSUER", "").strip() or "Dropjak"
TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1
_TOTP_RECOVERY_RE = re.compile(r"^[0-9a-f]{64}$")

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
# E-mail-cím a fiók-kéréshez. A 254 karakter az RFC 5321 gyakorlati felső
# határa; a minta egyszerű, de a nyilvánvalóan hibás alakokat kiszűri.
MAX_EMAIL = 254
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_NFT_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$")
_SERVICE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
# Szolgáltatás-szabály hivatkozása: "<ügynök-azonosító>/<szolgáltatás-azonosító>".
_SERVICE_REF_RE = re.compile(
    r"^[a-z0-9][a-z0-9_-]{0,31}/[a-z0-9][a-z0-9_-]{0,31}$"
)


def normalize_email(raw, strict=True) -> str:
    """Az e-mail-cím egységes alakja: körbevágott, kisbetűs.

    ``strict`` esetén hibás bemenetre ``ValueError``-t dob; különben üres
    sztringet ad vissza, hogy a hívó fail-safe módon kezelhesse.
    """
    if not isinstance(raw, str):
        if strict:
            raise ValueError("érvénytelen e-mail-cím")
        return ""
    value = raw.strip().lower()
    if not value:
        if strict:
            raise ValueError("az e-mail-cím kötelező")
        return ""
    if (
        len(value) > MAX_EMAIL
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or not EMAIL_RE.match(value)
    ):
        if strict:
            raise ValueError("érvénytelen e-mail-cím")
        return ""
    return value


_log_lock = threading.Lock()


def log(message: str) -> None:
    with _log_lock:
        print(message, flush=True)


# ------------------------------------------------------------------ IP-segéd

def normalize_ip(raw: str) -> str:
    """Az IPv4-mapped IPv6 címeket sima IPv4-re hozza."""
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
    """A LAN-kliens MAC-címe az ARP-táblából.

    Csak teljes (``0x2``) bejegyzést fogadunk el, és ha ismert az interfész,
    csak azon a bejegyzést. Bármilyen hiba esetén ``None``-t adunk, mert a
    hívó ilyenkor fail-closed módon megtagadja az engedélyt.
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


# --------------------------------------------------------------- szolgáltatások

class CatalogError(ValueError):
    """A szolgáltatáskatalógus hiányzik vagy hibás."""


class AccessError(ValueError):
    """A kért hozzáférés érvénytelen (szolgáltatás vagy időtartam)."""


@dataclass(frozen=True)
class Ports:
    """Egy szabály által engedélyezett célportok.

    A szabályok portokból állnak: több TCP- és UDP-port, opcionálisan ICMP,
    illetve teljes hozzáférés. A port a kliens által kért, DNAT előtti
    célport, ezért Docker által publikált konténerport esetén a host portját
    kell megadni.
    """

    tcp: tuple[int, ...] = ()
    udp: tuple[int, ...] = ()
    icmp: bool = False
    full: bool = False
    # forward: a kapu továbbítja a forgalmat (internet, Docker-konténer).
    # input: a portálgép saját szolgáltatását nyitja meg a kliens IP-jének.
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
    """Egy munkamenet által kiválasztott szabály és annak engedélyei.

    A munkamenet több szabályt is választhat; a tényleges tűzfalengedély a
    választások grantjeinek irányonkénti uniója. A ``rule_id``/``label`` a
    részleges visszavonásnál és a megjelenítésnél azonosítja a választást.
    """

    rule_id: str
    label: str
    grants: tuple[Ports, ...]
    # A választás által engedélyezett proxy-hostnevek (explicit domain
    # szabály és domain-módú szolgáltatás együtt).
    domains: tuple[str, ...] = ()
    # A választáshoz tartozó szolgáltatás-hivatkozások és a belőlük feloldott
    # domainek; a megjelenítéshez (választott szolgáltatás címkéje) kellenek.
    service_refs: tuple[str, ...] = ()
    service_domains: tuple[str, ...] = ()


def union_grants(parts) -> tuple[Ports, ...]:
    """Ports-engedélyek irányonkénti uniója.

    A ``full`` engedély egy irányban minden portot és ICMP-t lefed, ezért
    az adott irány többi része eltűnik az unióból. Egyébként a TCP/UDP
    portok halmazként egyesülnek (növekvő sorrendben), az ICMP pedig
    VAGY-kapcsolatot kap. Az eredmény determinisztikus: ``forward``, majd
    ``input`` sorrendben, az üres részek nélkül.

    Ismeretlen irány ``FirewallError``, összhangban a
    :meth:`Firewall._elements` viselkedésével.
    """

    combined: dict[str, dict] = {}
    for part in parts:
        direction = part.direction
        if direction not in ("forward", "input"):
            raise FirewallError(
                f"érvénytelen szabályirány: {direction!r}"
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
    """Egy választható szolgáltatás és a hozzá tartozó célportok.

    A katalógus csak a kezdő szabályok létrehozásához és a régi,
    szolgáltatás-alapú rules.json átalakításához kell. A futó rendszerben a
    szabályok már portokat tartalmaznak.
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
    """Kész szolgáltatás-csomag a gyors választáshoz."""

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
    """Admin által kezelt hozzáférési szabály.

    A szabály egy vagy több célportot tartalmaz (TCP és/vagy UDP), opcionális
    ICMP-t, illetve teljes hozzáférést. A felhasználó csak a neki
    (közvetlenül vagy csoporton keresztül) kiosztott szabályok közül
    választhat, és a szabály a kiválasztott ideig él.
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
    # Gyűjtőszabály: egyedi szabály-azonosítók, amelyek portjai unióként
    # érvényesek. A tárolt portmezők ilyenkor üresek; a feloldott nézet
    # számolja ki az uniót.
    members: tuple[str, ...] = ()
    # forward: továbbított (internet/Docker) forgalom; input: a portálgép
    # saját szolgáltatása. Egyedi szabálynál ez a saját iránya; a
    # gyűjtőszabálynak nincs saját iránya, az engedélyeket a tagjaiból
    # származtatjuk (lásd grants). A feloldott gyűjtőnél a megjelenítési
    # érték "mixed" is lehet, ha a tagok iránya vegyes.
    direction: str = "forward"
    # A gyűjtő feloldott input (host) uniója. A tcp/udp/icmp mezők a
    # forward uniót tárolják; a kettő együtt adja a megjelenítési uniót.
    input_tcp: tuple[int, ...] = ()
    input_udp: tuple[int, ...] = ()
    # Domain szabály: teljes proxy-hostnevek, portok nélkül; az nftables-hez
    # nem nyúl. Gyűjtőnél a tagok domainjeinek feloldott uniója.
    domains: tuple[str, ...] = ()
    # Szolgáltatás-szabály: "<ügynök-azonosító>/<szolgáltatás-azonosító>"
    # hivatkozások. A "services" kulcsot szándékosan nem használjuk, mert az
    # a régi szolgáltatás-alapú szabályokat jelöli (_is_legacy).
    service_refs: tuple[str, ...] = ()
    # A hivatkozásokból feloldott forward portok; nem perzisztált értékek.
    # Hiányzó/letiltott szolgáltatásnál üresek maradnak (fail-closed).
    service_tcp: tuple[int, ...] = ()
    service_udp: tuple[int, ...] = ()
    # A hivatkozásokból feloldott proxy-hostnevek (csak domain-módú
    # szolgáltatások); nem perzisztált, a session_domains része.
    service_domains: tuple[str, ...] = ()
    # A hivatkozásokból feloldott, teljes leképezés-aláírás:
    # ``(ref, proto, listen_port, target_host, target_port)`` tuple-ök
    # rendezett uniója; domain-módú szolgáltatásnál ``proto="domain"`` sor
    # is szerepel, hogy az átnevezés is érvénytelenítsen. Nem perzisztált,
    # mint a service_tcp/service_udp. A döntéskori ellenőrzés ezzel észleli
    # a célhost/célport átirányítást akkor is, ha a hallgató portok
    # változatlanok.
    service_signature: tuple[tuple[str, str, int, str, int], ...] = ()

    @property
    def ports(self) -> Ports:
        """Megjelenítési unió; a tűzfal-kényszerítéshez a grants mérvadó.

        Egyedi szabálynál a saját portjai. Gyűjtőnél a forward és az input
        portok egyesítése, hogy a meglévő megjelenítő kód a teljes uniót
        mutassa; az irány csak megjelenítési érték.
        """
        if self.service_refs and not self.collection:
            # A szolgáltatás-szabály mindig forward irányú; a portokat a
            # hivatkozott szolgáltatások hallgató portjai adják.
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
        """A tényleges hozzáférési engedélyek, irányonként.

        Egyedi szabály: pontosan a saját portjai. Gyűjtő: a forward unió
        egy forward, az input unió egy input Ports-ban. A tűzfal mindig
        ezt használja, soha nem a megjelenítési ports mezőt.
        """
        if self.service_refs and not self.collection:
            # Szolgáltatás-szabály: csak akkor ad engedélyt, ha legalább egy
            # port feloldódott. A hiányzó hivatkozás így nem nyit semmit.
            if not (self.service_tcp or self.service_udp):
                return ()
            return (self.ports,)
        if not self.collection:
            # A domain szabály a proxy-kapun hat, tűzfalengedélye nincs.
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
        """A munkamenetben megnyíló proxy-hostnevek.

        Az explicit domain szabály hostnevei és a domain-módú
        szolgáltatásokból feloldott nevek uniója, az első előfordulás
        sorrendjében, ismétlődés nélkül.
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
        """A szolgáltatás-hivatkozások megjelenítési alakja.

        A címkét a szerver tölti ki a beállításokból. Egyetlen hivatkozásnál
        a feloldott portok is ide kerülnek; többnél a feloldás unió, ezért
        az egyedi portokat a szerver oldja fel.
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
            # A gyűjtőnek nincs saját iránya: a payloadból szándékosan
            # kimarad a direction kulcs, a portok pedig a megjelenítési
            # uniót mutatják.
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
            # A szolgáltatás-szabály nem domain és nem gyűjtő: ezeket a
            # mezőket szándékosan nem adjuk ki. A portok a hivatkozásokból
            # feloldott, nem perzisztált értékek, ezért a tcp/udp mezők is
            # ezeket mutatják (a gyűjtő feloldott nézetéhez hasonlóan).
            ports = self.ports
            payload["tcp"] = list(ports.tcp)
            payload["udp"] = list(ports.udp)
            payload["ports_label"] = ports.label()
            payload.pop("members", None)
            payload.pop("domains", None)
        return payload


@dataclass(frozen=True)
class Group:
    """Felhasználócsoport, amely szabályokat fog össze."""

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


# A naplóbejegyzések súlyossága. A központi térkép teszi lehetővé, hogy a
# felület és a szűrők ugyanazt a besorolást lássák, mint a naplóíró.
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
    "session_ip_changed": "warn", "session_ended": "warn",
    "fail2ban_unban": "warn", "fail2ban_bans_released": "warn",
    "fail2ban_ban_evicted": "warn",
    "fail2ban_ban_evict_failed": "warn",
    "fail2ban_bans_release_failed": "warn",
    "fail2ban_ban_restore_failed": "warn",
    "admin_request_rejected": "warn",
    "admin_session_terminate_failed": "warn",
    "portal_host_redirect": "warn", "proxy_challenge_failed": "warn",
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

# Ezek az értékek soha nem kerülhetnek a naplóba. Pontos kulcs-egyezés:
# a ``ticket_hash``, ``session`` és ``sid`` megengedett.
SENSITIVE_AUDIT_KEYS = {
    "pass", "password", "password_hash", "hash", "secret", "totp_secret",
    "code", "recovery", "recovery_code", "cookie", "token", "ticket",
    "otpauth_uri",
}


def audit_severity(event: str) -> str:
    return AUDIT_SEVERITY.get(str(event), DEFAULT_SEVERITY)


def _search_key(value) -> str:
    """Kereséshez normalizált szöveg: kisbetű, elválasztók szóközzé.

    Az aláhúzás és a kötőjel ugyanazt a szóhatárt jelöli, mint a szóköz,
    ezért az ``access_granted``, ``ACCESS-GRANTED`` és ``Access granted``
    alakok ugyanarra a kulcsra jutnak. Az ismételt whitespace összevonva.
    """
    text = str(value).lower().replace("_", " ").replace("-", " ")
    return " ".join(text.split())


def _search_values(value):
    """Az audit-bejegyzés értékei rekurzívan, a kulcsok nélkül.

    A szabadszöveges keresés csak látható értékekre illeszkedhet: a JSON
    kulcsnevei (``event``, ``user``) ne találjanak minden sorra.
    """
    if isinstance(value, dict):
        for nested in value.values():
            yield from _search_values(nested)
    elif isinstance(value, (list, tuple, set)):
        for nested in value:
            yield from _search_values(nested)
    elif value is not None:
        yield value


# Az IP-szűrő ezekben a mezőkben keres: a kliens (ip), illetve a művelet
# tárgya (pl. az admin által tiltott/feloldott cím a target mezőben).
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
    """JSON Lines napló a portál minden lényeges eseményéről.

    A napló a state-kötetben marad meg, méretkorláttal rotálva. A bejegyzések
    soha nem tartalmaznak jelszót vagy jelszó-hash-t. Írási hiba nem
    akaszthatja meg a belépést: a hiba a folyamat naplójába kerül.
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
                self.log(f"[napló] rotáció nem sikerült: {exc}")
                return
        try:
            os.replace(self.path, f"{self.path}.1")
        except OSError as exc:
            self.log(f"[napló] rotáció nem sikerült: {exc}")

    def write(self, event: str, **fields) -> dict:
        now = time.time()
        # Az explicit súlyosság felülírja a központi besorolást.
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
                # Csak a kulcs nevét naplózzuk a folyamatnaplóba, az értéket
                # soha. Az érzékeny mező kimarad az audit-bejegyzésből.
                self.log(f"[napló] érzékeny mező elhagyva: {key}")
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
            self.log(f"[napló] írási hiba: {exc}")
        else:
            user = entry.get("user", "")
            ip = entry.get("ip", "")
            detail = " ".join(
                f"{key}={entry[key]}"
                for key in ("rule", "ttl", "reason", "target", "action")
                if key in entry
            )
            self.log(
                f"[esemény] {entry['event']}"
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
        """Az ``ip`` egy ipaddress-hálózat (egy cím: /32 vagy /128) vagy None.

        Az ``events`` pontos eseménykódok halmaza (többes szűrő); az
        ``event`` a régi, részleges egyezésű egyes szűrő.
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
                            # A nyers eseménykód részleges egyezése marad az
                            # eddigi viselkedés (pl. ``admin_`` család), a
                            # normalizált alak pedig a megjelenített,
                            # szóközös/kötőjeles címkéket is megtalálja.
                            if event_raw not in raw_event and (
                                not event_key
                                or event_key not in _search_key(raw_event)
                            ):
                                continue
                        if user and user not in str(item.get("user", "")).lower():
                            continue
                        if ip is not None and not _audit_ip_match(item, ip):
                            continue
                        # A régi bejegyzésekben nincs severity mező: ezek
                        # alapértelmezésként "info" szintűek.
                        if severity and str(
                            item.get("severity", DEFAULT_SEVERITY)
                        ).lower() != severity:
                            continue
                        if q:
                            # Csak az értékek számítanak: a kulcsnevek nem,
                            # különben ``q=event`` vagy ``q=user`` minden
                            # sorra illeszkedne. A nyers és a normalizált
                            # alakot is próbáljuk, hogy az aláhúzásos kód és
                            # a szóközös címke is találjon.
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
                self.log(f"[napló] olvasási hiba ({path}): {exc}")
        rows.sort(key=lambda item: float(item.get("ts", 0)), reverse=True)
        return rows[:limit]


class ServiceCatalog:
    """A services.json által leírt szolgáltatások és scenariók.

    A katalógus portjai határozzák meg, milyen célportokra nyílik meg a
    forward-lánc. A fájl induláskor töltődik be; hibás katalógussal a portál
    nem indul el (fail-closed).
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
            raise CatalogError(f"{sid}: a(z) {field} mező lista kell legyen")
        ports: list[int] = []
        for value in raw:
            if isinstance(value, bool) or not isinstance(value, int):
                raise CatalogError(
                    f"{sid}: érvénytelen port a(z) {field} listában: {value!r}"
                )
            if not 1 <= value <= 65535:
                raise CatalogError(
                    f"{sid}: a port 1 és 65535 között lehet: {value}"
                )
            if value not in ports:
                ports.append(value)
        return tuple(sorted(ports))

    @classmethod
    def from_data(cls, data: dict, source: str = "") -> "ServiceCatalog":
        if not isinstance(data, dict):
            raise CatalogError("a katalógus gyökere JSON-objektum kell legyen")
        raw_services = data.get("services")
        if not isinstance(raw_services, list) or not raw_services:
            raise CatalogError(
                "a katalógusban legalább egy szolgáltatás kell legyen"
            )

        services: list[Service] = []
        seen: set[str] = set()
        full_count = 0
        for item in raw_services:
            if not isinstance(item, dict):
                raise CatalogError(
                    "minden szolgáltatás JSON-objektum kell legyen"
                )
            sid = item.get("id")
            if not isinstance(sid, str) or not _SERVICE_ID_RE.match(sid):
                raise CatalogError(
                    f"érvénytelen szolgáltatás-azonosító: {sid!r}"
                )
            if sid in seen:
                raise CatalogError(f"duplikált szolgáltatás-azonosító: {sid}")
            seen.add(sid)
            label = item.get("label", sid)
            description = item.get("description", "")
            if not isinstance(label, str) or not label.strip() or len(label) > 80:
                raise CatalogError(f"{sid}: a címke 1–80 karakter kell legyen")
            if not isinstance(description, str) or len(description) > 240:
                raise CatalogError(
                    f"{sid}: a leírás legfeljebb 240 karakter lehet"
                )
            tcp = cls._ports(item.get("tcp"), "tcp", sid)
            udp = cls._ports(item.get("udp"), "udp", sid)
            icmp = item.get("icmp", False)
            full = item.get("all", False)
            if not isinstance(icmp, bool) or not isinstance(full, bool):
                raise CatalogError(
                    f"{sid}: az icmp/all mező logikai érték kell legyen"
                )
            if full:
                full_count += 1
                if tcp or udp or icmp:
                    raise CatalogError(
                        f"{sid}: a teljes hozzáféréshez nem adható port vagy icmp"
                    )
            if not (tcp or udp or icmp or full):
                raise CatalogError(
                    f"{sid}: legalább egy port, icmp vagy all szükséges"
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
                "legfeljebb egy teljes hozzáférésű szolgáltatás lehet"
            )

        raw_scenarios = data.get("scenarios", [])
        if not isinstance(raw_scenarios, list):
            raise CatalogError("a scenarios mező lista kell legyen")
        scenarios: list[Scenario] = []
        scenario_ids: set[str] = set()
        default_count = 0
        for item in raw_scenarios:
            if not isinstance(item, dict):
                raise CatalogError("minden scenario JSON-objektum kell legyen")
            scn_id = item.get("id")
            if not isinstance(scn_id, str) or not _SERVICE_ID_RE.match(scn_id):
                raise CatalogError(
                    f"érvénytelen scenario-azonosító: {scn_id!r}"
                )
            if scn_id in scenario_ids:
                raise CatalogError(
                    f"duplikált scenario-azonosító: {scn_id}"
                )
            scenario_ids.add(scn_id)
            label = item.get("label", scn_id)
            description = item.get("description", "")
            if not isinstance(label, str) or not label.strip() or len(label) > 80:
                raise CatalogError(
                    f"{scn_id}: a címke 1–80 karakter kell legyen"
                )
            if not isinstance(description, str) or len(description) > 240:
                raise CatalogError(
                    f"{scn_id}: a leírás legfeljebb 240 karakter lehet"
                )
            raw_ids = item.get("services")
            if not isinstance(raw_ids, list) or not raw_ids:
                raise CatalogError(
                    f"{scn_id}: legalább egy szolgáltatás kell legyen"
                )
            scn_services: list[str] = []
            for value in raw_ids:
                if not isinstance(value, str) or value not in seen:
                    raise CatalogError(
                        f"{scn_id}: ismeretlen szolgáltatás: {value!r}"
                    )
                if value not in scn_services:
                    scn_services.append(value)
            ttl = item.get("default_ttl", DEFAULT_TTL)
            if isinstance(ttl, bool) or not isinstance(ttl, int):
                raise CatalogError(
                    f"{scn_id}: a default_ttl egész szám kell legyen"
                )
            ttl = min(max(ttl, MIN_TTL), MAX_TTL)
            is_default = item.get("default", False)
            if not isinstance(is_default, bool):
                raise CatalogError(
                    f"{scn_id}: a default mező logikai érték kell legyen"
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
                "legfeljebb egy alapértelmezett scenario lehet"
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
                f"hiányzó szolgáltatáskatalógus: {path}"
            ) from exc
        except OSError as exc:
            raise CatalogError(
                f"a szolgáltatáskatalógus nem olvasható: {path}: {exc}"
            ) from exc
        except ValueError as exc:
            raise CatalogError(
                f"a szolgáltatáskatalógus nem érvényes JSON: {path}: {exc}"
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
        """A kliens által küldött azonosítók ellenőrzése és feloldása.

        Ha a teljes hozzáférés szerepel a választásban, az minden mást
        magába foglal, ezért csak azt adjuk vissza.
        """
        if not isinstance(ids, (list, tuple)):
            raise AccessError("a szolgáltatások listája hiányzik")
        if len(ids) > 32:
            raise AccessError("túl sok szolgáltatás")
        chosen: list[str] = []
        for raw in ids:
            if not isinstance(raw, str):
                raise AccessError("érvénytelen szolgáltatás-azonosító")
            sid = raw.strip()
            if sid not in self.services:
                raise AccessError(f"ismeretlen szolgáltatás: {sid}")
            if sid not in chosen:
                chosen.append(sid)
        if not chosen:
            raise AccessError("válassz legalább egy szolgáltatást")
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
    """A másodpercben megadott időtartam emberi alakja."""
    value = max(0, int(seconds))
    if value > 0 and value % 3600 == 0:
        return f"{value // 3600} óra"
    if value % 60 == 0:
        return f"{value // 60} perc"
    return f"{value} másodperc"


def validate_ttl(raw) -> int:
    """A választott hozzáférési idő ellenőrzése (másodperc)."""
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise AccessError("a hozzáférés hossza egész másodperc kell legyen")
    if raw < MIN_TTL or raw > MAX_TTL:
        raise AccessError(
            f"a hozzáférés hossza {format_duration(MIN_TTL)} és "
            f"{format_duration(MAX_TTL)} között lehet"
        )
    return raw


# ------------------------------------------------------------- szabályok/csoportok

class RuleStoreError(RuntimeError):
    """A szabálytár hibás vagy nem írható."""


class GroupStoreError(RuntimeError):
    """A csoporttár hibás vagy nem írható."""


def _clean_text(raw, field: str, maximum: int, required: bool = True) -> str:
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ValueError(f"{field}: szöveg kell")
    value = raw.strip()
    if required and not value:
        raise ValueError(f"{field}: nem lehet üres")
    if len(value) > maximum:
        raise ValueError(f"{field}: legfeljebb {maximum} karakter lehet")
    return value


def _copy_label(label: str, suffix: str = " (copy)", maximum: int = 80) -> str:
    """Másolatnév úgy, hogy az utótag a hosszkorlátba is beleférjen.

    A törzset az utótag hosszával rövidítjük, így hosszú forrásnév esetén
    sem tűnik el a másolat jelölése, és a két név nem lesz azonos.
    """
    if len(label) + len(suffix) <= maximum:
        return label + suffix
    return label[: max(0, maximum - len(suffix))] + suffix


def _clean_id(raw, field: str = "azonosító") -> str:
    if not isinstance(raw, str) or not _SERVICE_ID_RE.match(raw.strip()):
        raise ValueError(
            f"{field}: 1–32 karakter, kisbetű, szám, kötőjel vagy aláhúzás"
        )
    return raw.strip()


def _clean_str_list(raw, field: str, pattern=None, maximum: int = 64) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > maximum:
        raise ValueError(f"{field}: legfeljebb {maximum} elemű lista kell")
    out: list[str] = []
    for value in raw:
        if not isinstance(value, str):
            raise ValueError(f"{field}: érvénytelen elem")
        value = value.strip()
        if not value:
            continue
        if pattern is not None and not pattern.match(value):
            raise ValueError(f"{field}: érvénytelen elem: {value!r}")
        if value not in out:
            out.append(value)
    return tuple(out)


def _clean_rule_members(raw, field: str = "members") -> tuple[str, ...]:
    """Gyűjtőszabály tagjainak ellenőrzése.

    A tagok egyedi szabály-azonosítók; az ismétlődést nem csendben vonjuk
    össze, mert az elgépelt szabálylista így láthatatlanul megváltozna.
    """
    if not isinstance(raw, list):
        raise ValueError(
            f"{field}: 1–64 szabály-azonosítóból álló lista kell"
        )
    values = [
        value.strip() for value in raw
        if isinstance(value, str) and value.strip()
    ]
    cleaned = _clean_str_list(
        raw, field, pattern=_SERVICE_ID_RE, maximum=64
    )
    if len(values) != len(cleaned):
        raise ValueError(f"{field}: ismétlődő szabály-azonosító")
    if not 1 <= len(cleaned) <= 64:
        raise ValueError(
            f"{field}: legalább 1 és legfeljebb 64 egyedi szabály kell"
        )
    return cleaned


def _clean_rule_domains(raw, known=None) -> tuple[str, ...]:
    """Domain szabály proxy-bejegyzései: 1–64 egyedi teljes hostnév.

    ``known`` megadásakor (mentéskor) csak létező bejegyzésre hivatkozhat;
    betöltéskor csak az alakot ellenőrizzük.
    """
    if not isinstance(raw, list):
        raise ValueError("domains: 1–64 proxy-bejegyzésből álló lista kell")
    cleaned = _clean_str_list(
        [value.lower() if isinstance(value, str) else value for value in raw],
        "domains", pattern=settings_store._FQDN_RE, maximum=64,
    )
    if not cleaned:
        raise ValueError("domains: legalább egy proxy-bejegyzést válassz")
    if known is not None:
        missing = [name for name in cleaned if name not in known]
        if missing:
            raise ValueError(
                f"ismeretlen proxy-bejegyzés: {', '.join(missing)}"
            )
    return cleaned


def _clean_service_refs(raw, field: str = "service_refs") -> tuple[str, ...]:
    """Szolgáltatás-szabály hivatkozásai: 1–64 egyedi ``ügynök/szolgáltatás``.

    Az alakot szigorúan ellenőrizzük; a létezést és a bekapcsolt állapotot a
    hívó (mentéskor a visszahívás) ellenőrzi. Betöltéskor a hiányzó hivatkozás
    nem dobja el a szabályt, csak üres feloldott portokat ad (fail-closed).
    """
    if not isinstance(raw, list):
        raise ValueError(
            f"{field}: 1–64 szolgáltatás-hivatkozásból álló lista kell"
        )
    values = [
        value.strip() for value in raw
        if isinstance(value, str) and value.strip()
    ]
    cleaned = _clean_str_list(
        raw, field, pattern=_SERVICE_REF_RE, maximum=64
    )
    if len(values) != len(cleaned):
        raise ValueError(f"{field}: ismétlődő szolgáltatás-hivatkozás")
    if not 1 <= len(cleaned) <= 64:
        raise ValueError(
            f"{field}: legalább 1 és legfeljebb 64 egyedi szolgáltatás kell"
        )
    return cleaned


def merge_port_intervals(values) -> list[tuple[int, int]]:
    """Portok összefüggő intervallumai; az átfedő és szomszédos részek egyesülnek."""
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
    """Portok tömör szövege; a szomszédos portok tartományként jelennek meg."""
    return separator.join(
        format_port_interval(lo, hi, dash)
        for lo, hi in merge_port_intervals(values)
    )


def _parse_port_token(value, field: str) -> tuple[int, int]:
    """Egy port vagy ``lo-hi`` tartomány értelmezése (mindkettő zárt)."""
    text = value.strip().replace("–", "-").replace("—", "-")
    match = re.fullmatch(r"(\d+)(?:\s*-\s*(\d+))?", text)
    if match is None:
        raise ValueError(f"{field}: érvénytelen port: {value!r}")
    low = int(match.group(1))
    high = int(match.group(2)) if match.group(2) else low
    if not 1 <= low <= 65535 or not 1 <= high <= 65535:
        raise ValueError(f"{field}: a port 1 és 65535 között lehet: {value}")
    if low > high:
        raise ValueError(
            f"{field}: a tartomány kezdete nem lehet nagyobb a végénél: {value}"
        )
    return low, high


def _clean_ports(raw, field: str, maximum: int = 256) -> tuple[int, ...]:
    """Portlista normalizálása.

    Elfogad JSON-listát (a felület ezt küldi), egyetlen egész számot, vagy
    vessző/szóköz elválasztású szöveget. Az elem lehet egy port vagy
    ``lo-hi`` tartomány. Az átfedő tartományokat összevonjuk, majd a
    belső, visszafelé kompatibilis alakhoz egyedi, növekvő portokra
    bontjuk. A korlát a felbontott portok számára vonatkozik.
    """
    if raw is None:
        return ()
    if isinstance(raw, str):
        raw = [part for part in re.split(r"[\s,;]+", raw.strip()) if part]
    elif isinstance(raw, int) and not isinstance(raw, bool):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        raise ValueError(f"{field}: portlista kell")
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
            raise ValueError(f"{field}: érvénytelen port: {value!r}")
    # Előbb összevonunk, hogy egy átfedő listát ne számoljunk kétszer.
    merged: list[tuple[int, int]] = []
    for low, high in sorted(intervals):
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    total = sum(high - low + 1 for low, high in merged)
    if total > maximum:
        raise ValueError(f"{field}: legfeljebb {maximum} port adható meg")
    ports: list[int] = []
    for low, high in merged:
        ports.extend(range(low, high + 1))
    return tuple(ports)


def _clean_direction(raw) -> str:
    """A szabály iránya: ``forward`` (alapértelmezett) vagy ``input``."""
    if raw is None:
        return "forward"
    if not isinstance(raw, str):
        raise ValueError("direction: forward vagy input érték kell")
    value = raw.strip()
    if not value:
        return "forward"
    if value not in ("forward", "input"):
        raise ValueError("direction: forward vagy input érték kell")
    return value


def _validate_host_ports(direction: str, ports: Ports) -> None:
    """Host (input) szabály megkötései; forward szabályt nem érint.

    A host szabály csak explicit TCP/UDP portot nyithat: teljes hozzáférés,
    ICMP és szolgáltatáslista nem megengedett. Egyedül a portál (8100)
    portja fenntartott. A 22-es TCP-port (SSH) közönséges host-portként
    nyitható meg; ez az egyetlen út a host SSH-hoz, ezért a szabályt
    adminisztrátor hozza létre és rendeli a felhasználóhoz. Az UDP 22 nem
    SSH, hanem közönséges host-port.
    """
    if direction != "input":
        return
    if ports.full:
        raise ValueError("host szabály nem lehet teljes hozzáférésű")
    if ports.icmp:
        raise ValueError("host szabály nem tartalmazhat ICMP-t")
    if not (ports.tcp or ports.udp):
        raise ValueError(
            "host szabályhoz legalább egy TCP vagy UDP port kell"
        )
    if 8100 in ports.tcp or 8100 in ports.udp:
        raise ValueError(
            "a 8100-as port (portál) nem nyitható meg host szabállyal"
        )


def _validate_host_payload(data: dict, direction: str) -> None:
    """A host szabály nyers mezőinek ellenőrzése a portok előállítása előtt.

    Az üres portlista általános hibaüzenete helyett itt a host szabályra
    vonatkozó üzenetet adjuk, és a teljes/ICMP mezőket is hamarabb
    utasítjuk el, mint az általános ``_ports_from_payload``.
    """
    if direction != "input":
        return
    tcp = _clean_ports(data.get("tcp"), "tcp")
    udp = _clean_ports(data.get("udp"), "udp")
    icmp = data.get("icmp", False)
    full = data.get("full", False)
    if not isinstance(icmp, bool):
        raise ValueError("icmp: logikai érték kell")
    if not isinstance(full, bool):
        raise ValueError("full: logikai érték kell")
    _validate_host_ports(
        direction, Ports(tcp, udp, icmp, full, direction)
    )


def _ports_from_payload(data: dict) -> Ports:
    """A szabály portmezőinek ellenőrzése és Ports előállítása."""
    tcp = _clean_ports(data.get("tcp"), "tcp")
    udp = _clean_ports(data.get("udp"), "udp")
    icmp = data.get("icmp", False)
    full = data.get("full", False)
    if not isinstance(icmp, bool):
        raise ValueError("icmp: logikai érték kell")
    if not isinstance(full, bool):
        raise ValueError("full: logikai érték kell")
    if full and (tcp or udp or icmp):
        raise ValueError(
            "teljes hozzáféréshez nem adható meg port vagy ICMP"
        )
    if not (tcp or udp or icmp or full):
        raise ValueError(
            "legalább egy portot, ICMP-t vagy teljes hozzáférést válassz"
        )
    return Ports(tcp, udp, icmp, full)


class RuleStore:
    """rules.json: admin által létrehozott hozzáférési szabályok.

    A mindenkori szabályok kizárólag a fájlból származnak; nincs beépített
    vagy szintetikus szabály. A LEGACY_ADMIN_RULE_ID fenntartott, régi
    azonosító: nem hozható létre, nem rendelhető hozzá, és a betöltés
    kiszűri a fájlból. Ha a fájl még nem létezik, a services.json
    scenariói induló szabályokként létrejönnek, így a korábbi telepítés
    viselkedése megmarad.
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
        # Visszahívás: a létező proxy-bejegyzések teljes hostnevei. Nélküle
        # domain szabály nem menthető (fail-closed).
        self.domain_names = domain_names
        # Visszahívás: "<ügynök>/<szolgáltatás>" -> {"tcp": (...), "udp": (...)}
        # vagy None, ha a szolgáltatás hiányzik/le van tiltva. Nélküle a
        # szolgáltatás-szabály feloldott portjai üresek (fail-closed).
        self.service_ports = service_ports
        # Visszahívás: "<ügynök>/<szolgáltatás>" -> feloldott bejegyzés vagy
        # None (hiányzó/letiltott). A domain-módú szolgáltatások hostnevét
        # ebből oldjuk fel; nélküle ilyen szolgáltatás nem ad domaint.
        self.service_domains = service_domains
        # A régi, egyetlen proxy-gyökér: a pont nélküli régi hivatkozások
        # betöltéskor ez alá kerülnek (lásd _resolve_bare_domains).
        self.legacy_proxy_domain = ""
        # RLock: a _locked() ugyanabban a szálban beágyazható (például egy
        # zárt szakaszból hívott create()), és a _load() is újra beléphet.
        self._lock = threading.RLock()
        self._lock_state = threading.local()
        self._rules: dict[str, Rule] = {}
        self._loaded = False

    # -- fájlkezelés -----------------------------------------------------------

    @contextmanager
    def _locked(self):
        """Kizárólagos szabálytár-zár (folyamaton belül és fájlszinten).

        A belső hívások ugyanazt a zárat használják: a flockot csak a
        legkülső _locked() nyitja meg, így a beágyazott hívás nem akad meg
        önmagán. A folyamaton belüli RLock a _load()/_rules konzisztenciáját
        is biztosítja a fájllock alatt.
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
            raise RuleStoreError(f"a szabálytár nem olvasható: {exc}") from exc
        if not isinstance(data, dict):
            raise RuleStoreError("a szabálytár formátuma hibás")
        raw_rules = data.get("rules", data)
        if not isinstance(raw_rules, dict):
            raise RuleStoreError("a szabálytár rules mezője hibás")
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
            self.log(f"[szabályok] hibás fájl félretéve: {target} ({why})")
        except OSError as exc:
            self.log(f"[szabályok] a hibás fájl félretétele nem sikerült: {exc}")

    # -- betöltés --------------------------------------------------------------

    def _ports_from_services(self, services) -> Ports:
        """Régi, szolgáltatás-alapú szabály átalakítása portokra."""
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
        """Régi (3.6 előtti) domain szabály pont nélküli bejegyzésnevei.

        A név a régi, egyetlen gyökérdomain alá kerül (igaz: átírandó).
        Gyökér nélkül nem oldható fel: naplózva kimarad, a fájl változatlan.
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
                        f"[szabályok] {rule_id}: gyökérdomain nélkül fel nem "
                        f"oldható proxy-bejegyzés elhagyva: {value.strip()}"
                    )
                    continue
                value = f"{value.strip().lower()}.{root}"
            domains.append(value)
        return {**item, "domains": domains}, bool(root)

    def _resolve_service_ports(
        self, refs
    ) -> tuple[tuple[int, ...], tuple[int, ...]]:
        """Hivatkozások feloldott TCP/UDP hallgató portjainak uniója.

        Hiányzó vagy letiltott hivatkozásnál a visszahívás ``None``-t ad:
        az adott ref kimarad, a szabály viszont megmarad (fail-closed).
        """
        resolver = self.service_ports
        tcp: set[int] = set()
        udp: set[int] = set()
        if resolver is None:
            return (), ()
        for ref in refs:
            try:
                resolved = resolver(ref)
            except Exception as exc:  # a hibás konfiguráció ne nyisson portot
                self.log(
                    f"[szabályok] a(z) {ref} szolgáltatás feloldása nem "
                    f"sikerült: {exc}"
                )
                continue
            if not resolved:
                continue
            tcp.update(resolved.get("tcp") or ())
            udp.update(resolved.get("udp") or ())
        return tuple(sorted(tcp)), tuple(sorted(udp))

    def _resolve_service_domains(self, refs) -> tuple[str, ...]:
        """Hivatkozások feloldott proxy-hostnevei.

        Csak a domain-módú szolgáltatások adnak nevet; a port-szolgáltatás
        bejegyzésében üres a ``domain``. Hiányzó vagy letiltott
        hivatkozásnál a visszahívás ``None``-t ad, az adott ref kimarad
        (fail-closed).
        """
        resolver = self.service_domains
        names: list[str] = []
        if resolver is None:
            return ()
        for ref in refs:
            try:
                resolved = resolver(ref)
            except Exception as exc:  # a hibás konfiguráció ne adjon domaint
                self.log(
                    f"[szabályok] a(z) {ref} szolgáltatás domainje nem "
                    f"oldható fel: {exc}"
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
        """Egy feloldott hivatkozás aláírás-sorai.

        A ``tunnel_service_index`` a teljes leképezést ``signature``
        kulcsban adja; a csak portokat ismerő visszahívásoknál (tesztek,
        régi integrációk) a hallgató portokból és a célhostból képzünk
        konzervatív, de döntéskor ugyanúgy összevethető sorokat.
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
        # A régi/egyszerű visszahívások nem adnak signature-t; a domain-
        # módú szolgáltatás nevét ilyenkor is a signature részeként
        # vesszük, hogy az átnevezés érvénytelenítsen.
        domain = str(resolved.get("domain", "") or "")
        if domain:
            out.append((ref, "domain", 0, domain, 0))
        for proto, key in (("tcp", "tcp"), ("udp", "udp")):
            for port in resolved.get(key) or ():
                port = int(port)
                out.append((ref, proto, port, host, port))
        return tuple(out)

    def _resolve_service_signature(self, refs) -> tuple:
        """A hivatkozások feloldott, rendezett leképezés-aláírása.

        Hiányzó/letiltott hivatkozás kimarad; a külön ``service_tcp``/
        ``service_udp`` ellenőrzés ilyenkor külön fail-closed.
        """
        resolver = self.service_ports
        rows: set[tuple] = set()
        if resolver is None:
            return ()
        for ref in refs:
            try:
                resolved = resolver(ref)
            except Exception as exc:  # a hibás konfiguráció ne nyisson portot
                self.log(
                    f"[szabályok] a(z) {ref} szolgáltatás aláírása nem "
                    f"sikerült: {exc}"
                )
                continue
            if not resolved:
                continue
            rows.update(self._signature_rows(ref, resolved))
        return tuple(sorted(rows))

    def service_signature(self, refs) -> tuple:
        """A döntéskori összehasonlításhoz használt nyilvános aláírás."""
        return self._resolve_service_signature(refs)

    def _parse_rule(self, rule_id: str, item: dict) -> Rule:
        if not isinstance(item, dict):
            raise RuleStoreError(f"{rule_id}: hibás bejegyzés")
        members: tuple[str, ...] = ()
        domains: tuple[str, ...] = ()
        service_refs: tuple[str, ...] = ()
        service_tcp: tuple[int, ...] = ()
        service_udp: tuple[int, ...] = ()
        service_domains: tuple[str, ...] = ()
        service_signature: tuple = ()
        if "members" in item:
            # A gyűjtőszabály tárolt portmezői és iránya nem mérvadók: a
            # portokat és az irányokat a tagokból számoljuk. A fájlban csak
            # a taglista marad meg. Az esetleges elavult direction mezőt
            # szándékosan nem validáljuk.
            try:
                members = _clean_rule_members(item.get("members"))
            except ValueError as exc:
                raise RuleStoreError(f"{rule_id}: {exc}") from exc
            ports = Ports()
            direction = "forward"
        elif "domains" in item:
            # Domain szabály: a tárolt portmezők nem mérvadók.
            try:
                domains = _clean_rule_domains(item.get("domains"))
            except ValueError as exc:
                raise RuleStoreError(f"{rule_id}: {exc}") from exc
            ports = Ports()
            direction = "forward"
        elif "service_refs" in item:
            # Szolgáltatás-szabály: a tárolt portmezők nem mérvadók; a
            # portokat a hivatkozott szolgáltatások hallgató portjai adják.
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
                        f"{rule_id}: host szabály nem használhat "
                        "szolgáltatáslistát"
                    )
                services = _clean_str_list(
                    item.get("services"), f"{rule_id}.services", maximum=32
                )
                if not services:
                    raise RuleStoreError(
                        f"{rule_id}: legalább egy port vagy szolgáltatás kell"
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
            raise RuleStoreError(f"{rule_id}: hibás default_ttl")
        if isinstance(max_ttl, bool) or not isinstance(max_ttl, int):
            raise RuleStoreError(f"{rule_id}: hibás max_ttl")
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
        """A gyűjtőszabály hivatkozási hibája, vagy üres szöveg.

        Egy szintű gyűjtést engedünk: a tagok létező, egyedi, nem teljes
        hozzáférésű szabályok lehetnek, másik gyűjtő nem. A tagok iránya
        vegyes is lehet; minden tag a saját irányában ad engedélyt.
        Szolgáltatás-szabály (service_refs) szándékosan LEHET gyűjtőtag: a
        feloldott portjai a forward unióba kerülnek.
        """
        if not rule.members:
            return ""
        for member_id in rule.members:
            if member_id == rule.id:
                return "a gyűjtőszabály nem tartalmazhatja önmagát"
            if member_id == LEGACY_ADMIN_RULE_ID:
                return (
                    "ez egy fenntartott, régi azonosító, nem lehet "
                    "gyűjtőszabály tagja"
                )
            member = rules.get(member_id)
            if member is None:
                return f"ismeretlen szabály a gyűjtőszabályban: {member_id}"
            if member.members:
                return (
                    "a gyűjtőszabály nem tartalmazhat másik "
                    f"gyűjtőszabályt: {member_id}"
                )
            if member.full:
                return (
                    "a gyűjtőszabály nem tartalmazhat teljes hozzáférésű "
                    f"szabályt: {member_id}"
                )
        return ""

    def _seed(self) -> dict[str, Rule]:
        seeded: dict[str, Rule] = {}
        for sid in self.catalog.scenario_order:
            scn = self.catalog.scenarios[sid]
            try:
                ports = self._ports_from_services(scn.services)
            except RuleStoreError as exc:
                self.log(f"[szabályok] a(z) {sid} kezdő szabály kimaradt: {exc}")
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
                self.log(f"[szabályok] {exc}")
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
                    # Az azonosítót a fenntartott azonosító ellenőrzése
                    # ELŐTT normalizáljuk: a "admin-full " / " admin-full"
                    # / "admin-full\t" változatok sem kerülhetnek be.
                    clean_id = _clean_id(raw_id, "szabály-azonosító")
                except ValueError as exc:
                    parse_failed = True
                    self.log(f"[szabályok] kihagyott hibás szabály: {exc}")
                    continue
                if clean_id == LEGACY_ADMIN_RULE_ID:
                    # Fenntartott, régi azonosító (bármilyen whitespace-szel
                    # is írták): sosem lesz belőle szabály; a fájlból
                    # lentebb, hiba nélkül kiszűrjük.
                    legacy_admin_found = True
                    continue
                if clean_id in seen_ids:
                    # Két különböző nyers kulcs normalizálódott ugyanarra
                    # az azonosítóra. Nem írjuk felül csendben az első
                    # bejegyzést: ez ugyanolyan hibás fájl, mint bármely
                    # más parse hiba, ezért nem írjuk át automatikusan.
                    parse_failed = True
                    self.log(
                        "[szabályok] kihagyott ismétlődő szabály-azonosító: "
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
                    self.log(f"[szabályok] kihagyott hibás szabály: {exc}")
            # A gyűjtőszabályok hivatkozásait csak azután tudjuk ellenőrizni,
            # hogy az összes szabály beolvasódott. A hibás gyűjtőket kihagyjuk;
            # így az admin felület és a hozzáférés sem lát csonka uniót.
            for collection_id in list(rules):
                issue = self._collection_issue(rules[collection_id], rules)
                if issue:
                    parse_failed = True
                    self.log(
                        "[szabályok] kihagyott hibás gyűjtőszabály: "
                        f"{collection_id}: {issue}"
                    )
                    del rules[collection_id]
            # A gyűjtők feloldott szolgáltatás-portjai a tagokból számolt
            # értékek (nem perzisztáltak). Erre a reflect_services() és a
            # döntéskori újraellenőrzés is támaszkodik.
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
            # Csak az első induláskor (amikor még nincs szabályfájl) seedingelünk.
            # Ha az admin később minden szabályt töröl, az üres fájl megmarad,
            # és a szabályok nem kelnek újra életre a következő indításnál.
            if not rules and not existed:
                rules = self._seed()
                if rules:
                    try:
                        self._write_raw(
                            {rid: self._rule_storage(rule) for rid, rule in rules.items()}
                        )
                        self.log(
                            f"[szabályok] kezdő szabályok létrehozva: "
                            f"{', '.join(rules)}"
                        )
                    except OSError as exc:
                        self.log(f"[szabályok] a kezdő szabályok mentése nem sikerült: {exc}")
            elif existed and not parse_failed and (
                legacy_admin_found or legacy_found or domains_migrated
            ):
                # Régi fájl: előbb 0600 biztonsági másolat, majd a
                # megtisztított, új formátum kiírása. A fenntartott
                # admin-full kulcs kikerül; ha csak az volt benne, az
                # eredmény üres szabálytár, és nem seedelünk újra.
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
                            "[szabályok] a fenntartott, régi admin-full "
                            "bejegyzés eltávolítva; biztonsági másolat: "
                            f"{backup}"
                        )
                    if legacy_found:
                        self.log(
                            "[szabályok] a régi szolgáltatás-alapú szabályok "
                            f"portokra átalakítva; biztonsági másolat: {backup}"
                        )
                    if domains_migrated:
                        self.log(
                            "[szabályok] a régi domain szabályok teljes "
                            f"hostnévre átalakítva; biztonsági másolat: {backup}"
                        )
                except OSError as exc:
                    self.log(
                        "[szabályok] a régi szabályfájl tisztítása nem "
                        f"sikerült: {exc}"
                    )
            elif existed and parse_failed and (
                legacy_admin_found or legacy_found or domains_migrated
            ):
                self.log(
                    "[szabályok] FIGYELEM: a régi szabályfájl hibás bejegyzést "
                    "tartalmaz, ezért nem írom át automatikusan"
                )
            self._rules = rules
            self._loaded = True

    @staticmethod
    def _rule_storage(rule: Rule) -> dict:
        if rule.members:
            # Gyűjtőnél a portok és az irány is számított értékek: soha nem
            # perzisztáljuk őket, különben a tagok későbbi módosítása
            # elavult uniót vagy irányt adna. A gyűjtőnek nincs saját
            # iránya, ezért a direction mező sem kerül a fájlba.
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
            # A feloldott portok és az irány számított értékek: nem kerülnek
            # a fájlba, különben a szolgáltatás későbbi módosítása elavult
            # engedélyt hagyna hátra.
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
            # Az egyes portok változatlan egészek; a tartományokat
            # visszafelé kompatibilis "lo-hi" szövegként tároljuk.
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

    # -- konfigurációs csomag --------------------------------------------------

    def export_records(self) -> dict:
        """Az aktuális szabályok tárolási alakja a konfigurációs csomaghoz."""
        self._load()
        with self._lock:
            return {
                rule_id: self._rule_storage(rule)
                for rule_id, rule in self._rules.items()
            }

    def validate_import_records(self, raw) -> dict[str, Rule]:
        """A rules szakasz szigorú, írás nélküli ellenőrzése."""
        if not isinstance(raw, dict):
            raise RuleStoreError("a rules szakasz JSON-objektum kell")
        rules: dict[str, Rule] = {}
        for raw_id, item in raw.items():
            if not isinstance(raw_id, str):
                raise RuleStoreError("érvénytelen szabály-azonosító")
            try:
                clean_id = _clean_id(raw_id, "szabály-azonosító")
            except ValueError as exc:
                raise RuleStoreError(str(exc)) from exc
            if clean_id != raw_id:
                raise RuleStoreError(
                    f"a szabály-azonosító nem normalizált: {raw_id!r}"
                )
            if clean_id == LEGACY_ADMIN_RULE_ID:
                raise RuleStoreError(
                    "a fenntartott szabály-azonosító nem importálható"
                )
            if not isinstance(item, dict):
                raise RuleStoreError(f"{clean_id}: hibás bejegyzés")
            if self._is_legacy(item):
                raise RuleStoreError(
                    f"{clean_id}: a régi szolgáltatáslista nem importálható"
                )
            if "members" in item and "domains" in item:
                raise RuleStoreError(
                    f"{clean_id}: a members és a domains egyszerre nem lehet jelen"
                )
            if "service_refs" in item:
                mixed = [
                    key for key in ("members", "domains", "tcp", "udp",
                                    "icmp", "full")
                    if key in item
                ]
                if mixed:
                    raise RuleStoreError(
                        f"{clean_id}: a service_refs nem kombinálható a "
                        f"következő mezőkkel: {', '.join(mixed)}"
                    )
                # Csak az alakot ellenőrizzük: a hivatkozott alagutak
                # ugyanabban a csomagban is importálhatók, ezért a
                # létezést itt szándékosan nem követeljük meg.
            rules[clean_id] = self._parse_rule(clean_id, item)
        for rule in rules.values():
            issue = self._collection_issue(rule, rules)
            if issue:
                raise RuleStoreError(f"{rule.id}: {issue}")
        return rules

    def replace_all(self, rules: dict[str, Rule]) -> None:
        """A teljes szabálytár cseréje (a hívó már ellenőrizte)."""
        with self._locked():
            self._write_raw({
                rule_id: self._rule_storage(rule)
                for rule_id, rule in rules.items()
            })
            self._rules = dict(rules)
            self._loaded = True

    def reset(self) -> None:
        """A fájl törlése és a memóriabeli szabálytár ürítése."""
        with self._locked():
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self._rules = {}
            # Ne seedeljünk újra a folyamatban a leállás előtt.
            self._loaded = True

    # -- olvasás ---------------------------------------------------------------

    def _resolve_rule(
        self,
        rule: Rule,
        _seen: set[str] | None = None,
        _cache: dict[str, Rule] | None = None,
    ) -> Rule:
        """A gyűjtőszabály feloldott nézete, irányonkénti engedélyekkel.

        A tagok portjai a saját irányuk szerint különülnek el: a forward
        tagok a forward, a host (input) tagok az input halmazokba kerülnek.
        A tagok teljes hozzáférését szándékosan nem vesszük át: gyűjtő sosem
        adhat teljes hozzáférést. Körkörös vagy hiányzó hivatkozás esetén
        inkább hibát dobunk, mint részleges jogosultságot.
        """
        if not rule.members:
            return rule
        cache = {} if _cache is None else _cache
        if rule.id in cache:
            return cache[rule.id]
        seen = set() if _seen is None else set(_seen)
        if rule.id in seen:
            raise RuleStoreError(
                f"körkörös gyűjtőszabály-hivatkozás: {rule.id}"
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
                    f"hiányzó gyűjtőszabály-tag: {member_id}"
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
                # Védelmi réteg: a validáció már kizárja a teljes
                # hozzáférésű tagot, de a feloldás se engedje át.
                if parts.full:
                    raise RuleStoreError(
                        "a gyűjtőszabály nem tartalmazhat teljes "
                        f"hozzáférésű szabályt: {member_id}"
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
            # Üres gyűjtő: nincs engedély, a megjelenítési irány semleges.
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
            # A "mixed" csak megjelenítési/audit érték; a Ports soha nem
            # kapja meg, a ports property normalizálja.
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
                f"[szabályok] a(z) {rule.id} gyűjtőszabály nem oldható fel: "
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
        """Adhat-e a szabály host (input) hozzáférést?

        A régi, kiosztás nélküli (nem admin) fiókok visszafelé
        kompatibilisen csak a forward szabályokat örökölhetik. Host
        hozzáféréshez mindig kifejezett kiosztás kell, ezért a fallback
        kizárja az input irányú szabályokat, és azokat a gyűjtőket is,
        amelyeknek legalább egy input irányú tagja van. A gyűjtők
        egy szintűek, ezért a közvetlen tagok vizsgálata elég. A domain
        szabály (és az azt tartalmazó gyűjtő) is kifejezett kiosztást kér,
        akárcsak a szolgáltatás-szabály.
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
        """A domain szabályok által hivatkozott teljes proxy-hostnevek."""
        self._load()
        return {
            name for rule in self._rules.values() for name in rule.domains
        }

    def service_references(self) -> dict[str, tuple[str, ...]]:
        """Szolgáltatás-hivatkozás -> az őt tartalmazó szabályok azonosítói.

        A gyűjtőszabályokra is kiterjed: ha egy gyűjtő tagja szolgáltatás-
        szabály, a gyűjtő azonosítója is szerepel a hivatkozó szabályok
        között. Így a törlés/letiltás előtti ellenőrzés a közvetett
        hivatkozásokat is látja.
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
        """A feloldott szolgáltatás-portok újraszámítása (fájlírás nélkül).

        A szolgáltatás-leképezés módosítása után hívjuk: a szolgáltatás-
        szabályok és az őket tartalmazó gyűjtők feloldott portjai a
        visszahívásból frissülnek. Visszaadja a megváltozott szabályok
        rendezett azonosítóit, hogy a hívó a munkameneteiket visszavonhassa.
        """
        self._load()
        changed: set[str] = set()
        with self._lock:
            # Először a közvetlen szolgáltatás-szabályok, hogy a gyűjtők
            # már a friss tagértékekből számoljanak.
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
        """A felhasználó által választható szabályok.

        Mindenki, az admin is, csak a neki (közvetlenül vagy csoporton
        keresztül) kiosztott szabályokat kapja. Az admin sem kap beépített
        vagy szintetikus szabályt: kiosztás nélkül üres listát kap. Ha egy
        régi, nem admin felhasználóhoz még nem rendeltek szabályt (a
        users.json-ban nincs rules mező), visszafelé kompatibilisen a
        forward irányú szabályokat kapja meg. Host (input) szabályt és
        input tagot tartalmazó gyűjtőt csak kifejezett kiosztással kaphat,
        mert a host hozzáféréshez mindig kiosztás kell. Új, explicit módon
        üresre állított felhasználó viszont semmit nem kap, amíg az admin
        nem rendel hozzá.
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
            # Régi, kiosztás nélküli fiók: csak forward szabályokat
            # örökölhet. Host (input) hozzáféréshez kifejezett kiosztás
            # kell, ezért az input szabályok és az input tagot tartalmazó
            # gyűjtők itt nem választhatók.
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
            raise AccessError("válassz hozzáférési szabályt")
        rule = next(
            (item for item in self.effective_for(user, groups)
             if item.id == rule_id.strip()),
            None,
        )
        if rule is None:
            raise AccessError("ez a szabály nem tartozik hozzád")
        return rule

    # -- írás ------------------------------------------------------------------

    def _validate_payload(self, data: dict, rule_id: str) -> Rule:
        if not isinstance(data, dict):
            raise RuleStoreError("hibás szabály-adat")
        collection_flag = data.get("collection")
        if collection_flag is not None and not isinstance(collection_flag, bool):
            raise RuleStoreError("collection: logikai érték kell")
        members_raw = data.get("members")
        if "members" in data and not isinstance(members_raw, list):
            raise RuleStoreError(
                "members: 1–64 szabály-azonosítóból álló lista kell"
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
                "a szolgáltatás-szabály nem lehet gyűjtőszabály"
            )
        if is_collection:
            # A gyűjtőnek nincs saját iránya: a payload direction mezőjét
            # szándékosan figyelmen kívül hagyjuk (nem is validáljuk).
            direction = "forward"
            tcp = _clean_ports(data.get("tcp"), "tcp")
            udp = _clean_ports(data.get("udp"), "udp")
            icmp = data.get("icmp", False)
            full = data.get("full", False)
            if not isinstance(icmp, bool):
                raise RuleStoreError("icmp: logikai érték kell")
            if not isinstance(full, bool):
                raise RuleStoreError("full: logikai érték kell")
            if tcp or udp or icmp or full:
                raise RuleStoreError(
                    "gyűjtőszabályhoz nem adható meg port, ICMP vagy "
                    "teljes hozzáférés"
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
            # Domain szabály: nincs iránya és portja, csak proxy-bejegyzései.
            direction = "forward"
            if any(data.get(key) for key in ("tcp", "udp", "icmp", "full")):
                raise RuleStoreError(
                    "domain szabályhoz nem adható meg port, ICMP vagy "
                    "teljes hozzáférés"
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
            # Szolgáltatás-szabály: kizárólag a kiválasztott alagút-
            # szolgáltatások hallgató portjai, forward irányban.
            direction = "forward"
            mixed = [
                key for key in ("members", "domains", "tcp", "udp",
                                "icmp", "full")
                if key in data
            ]
            if mixed:
                raise RuleStoreError(
                    "szolgáltatás-szabályhoz nem adható meg "
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
                        f"ismeretlen vagy letiltott szolgáltatás: {ref}"
                    )
                tcp.update(resolved.get("tcp") or ())
                udp.update(resolved.get("udp") or ())
            # A domain-módú szolgáltatásnak nincs hallgató portja, de a
            # proxy-gapun keresztül a domainjét megnyitja; ilyenkor a
            # szabály portok nélkül is érvényes.
            service_domains = self._resolve_service_domains(service_refs)
            if not tcp and not udp and not service_domains:
                raise RuleStoreError(
                    "a kiválasztott szolgáltatásokhoz nincs elérhető port "
                    "vagy domain"
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
                # Régi API-hívók még szolgáltatásneveket küldhetnek.
                if direction == "input":
                    raise RuleStoreError(
                        "host szabály nem használhat szolgáltatáslistát"
                    )
                services = _clean_str_list(
                    data.get("services"), "services", maximum=32
                )
                if not services:
                    raise RuleStoreError("legalább egy portot válassz")
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
                raise RuleStoreError(f"{name}: egész másodperc kell")
            if not (MIN_TTL <= value <= MAX_TTL):
                raise RuleStoreError(
                    f"{name}: {format_duration(MIN_TTL)}–"
                    f"{format_duration(MAX_TTL)} lehet"
                )
        if default_ttl > max_ttl:
            raise RuleStoreError(
                "az alapértelmezett idő nem lehet hosszabb a maximumnál"
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
        rule_id = _clean_id(rule_id, "szabály-azonosító")
        if rule_id == LEGACY_ADMIN_RULE_ID:
            raise RuleStoreError(
                "ez egy fenntartott, régi azonosító, nem használható"
            )
        # A betöltés, a létezés-ellenőrzés, a taghivatkozások validálása és
        # a commit ugyanazon zár alatt történik. Így egy párhuzamos
        # delete()/update() nem teheti érvénytelenné a már validált
        # gyűjtőszabályt a mentés előtt.
        with self._locked():
            self._load()
            if rule_id in self._rules:
                raise RuleStoreError(f"már létezik ilyen szabály: {rule_id}")
            rule = self._validate_payload(data, rule_id)
            raw = {
                rid: self._rule_storage(item)
                for rid, item in {**self._rules, rule_id: rule}.items()
            }
            self._write_raw(raw)
            self._rules[rule_id] = rule
            return self._resolve_rule(rule)

    def _update_locked(self, rule_id: str, data: dict) -> tuple[Rule, list[str]]:
        """Módosítás a hívó által tartott _locked() alatt.

        Visszatérés: (feloldott szabály, a commit pontján függő gyűjtők).
        A függő gyűjtőket ugyanabban a zárt szakaszban olvassuk, mint a
        mentést: egy közben létrehozott gyűjtő is belekerül, ezért a
        munkamenet-visszavonás nem maradhat el.
        """
        self._load()
        existing = self._rules.get(rule_id)
        if existing is None:
            raise RuleStoreError(f"nincs ilyen szabály: {rule_id}")
        updated = self._validate_payload(data, rule_id)
        # A szülő gyűjtők listáját a commit pontján, ugyanazon zár alatt
        # olvassuk. Mivel a create() is a commitig tartja a zárat, a soron
        # lévő gyűjtő már itt látszik.
        parents = [
            rid for rid, item in self._rules.items()
            if rid != rule_id and rule_id in item.members
        ]
        # A tag iránya megváltozhat: a gyűjtő a tagok aktuális irányából
        # számolja az engedélyeket. A függő gyűjtők a visszatérési listában
        # szerepelnek, így a szerver a munkameneteiket is visszavonja.
        if updated.members or updated.full:
            # Egy gyűjtő tagja nem válhat gyűjtővé vagy teljes
            # hozzáférésűvé: azzal a szülő gyűjtő két szintűvé, illetve
            # érvénytelenné válna. Előbb ki kell venni a szülőkből.
            if parents:
                raise RuleStoreError(
                    f"a(z) {rule_id} szabály tagja a következő "
                    f"gyűjtőszabályoknak: {', '.join(parents)}; előbb "
                    "vedd ki a tagok közül"
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
        rule_id = _clean_id(rule_id, "szabály-azonosító")
        if rule_id == LEGACY_ADMIN_RULE_ID:
            raise RuleStoreError(
                "ez egy fenntartott, régi azonosító, nem módosítható"
            )
        with self._locked():
            resolved, _ = self._update_locked(rule_id, data)
            return resolved

    def update_with_dependents(
        self, rule_id: str, data: dict
    ) -> tuple[Rule, list[str]]:
        """Szabály módosítása és a tőle függő gyűjtők egy záron belül.

        A szervernek a szabály saját és a függő gyűjtők munkameneteit is
        vissza kell vonnia. Ha a függőlistát a módosítás előtt, külön
        zárral olvasnánk, egy közben létrehozott gyűjtő kimaradhatna, és a
        munkamenete a lejáratig a régi portokkal élvezne hozzáférést.
        """
        rule_id = _clean_id(rule_id, "szabály-azonosító")
        if rule_id == LEGACY_ADMIN_RULE_ID:
            raise RuleStoreError(
                "ez egy fenntartott, régi azonosító, nem módosítható"
            )
        with self._locked():
            return self._update_locked(rule_id, data)

    def duplicate(
        self,
        rule_id: str,
        new_id: str | None = None,
        label: str | None = None,
    ) -> Rule:
        """Meglévő szabály másolása új azonosítóval.

        A másolat nem ad önmagában hozzáférést: csak a szabálytárba kerül,
        ugyanúgy, mint bármely új szabály.
        """
        source_id = _clean_id(rule_id, "szabály-azonosító")
        if source_id == LEGACY_ADMIN_RULE_ID:
            raise RuleStoreError(
                "ez egy fenntartott, régi azonosító, nem duplikálható"
            )
        self._load()
        with self._locked():
            source = self._rules.get(source_id)
            if source is None:
                raise RuleStoreError(f"nincs ilyen szabály: {source_id}")
            if new_id is None:
                target_id = self._unique_copy_id(source_id)
            else:
                target_id = _clean_id(new_id, "szabály-azonosító")
                if target_id == LEGACY_ADMIN_RULE_ID:
                    raise RuleStoreError(
                        "ez egy fenntartott, régi azonosító, nem használható"
                    )
                if target_id in self._rules:
                    raise RuleStoreError(
                        f"már létezik ilyen szabály: {target_id}"
                    )
            # Az utótag helyét mindig foglaljuk le: 80 karakteres forrásnév
            # esetén a puszta végvágás eltüntetné a másolat jelölését, és a
            # két szabály neve azonos lenne.
            default_label = _copy_label(source.label)
            raw_label = label if label is not None else default_label
            # Az explicit címkét a hívó (a felület) már az utótaggal együtt,
            # a korláton belül küldi; a biztonság kedvéért itt is vágunk.
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
        """Azon gyűjtőszabályok azonosítói, amelyek tagként hivatkoznak rá."""
        self._load()
        return [
            rid for rid, item in self._rules.items()
            if rule_id in item.members
        ]

    def delete(self, rule_id: str) -> Rule:
        rule_id = _clean_id(rule_id, "szabály-azonosító")
        if rule_id == LEGACY_ADMIN_RULE_ID:
            raise RuleStoreError(
                "ez egy fenntartott, régi azonosító, nem törölhető"
            )
        self._load()
        with self._locked():
            existing = self._rules.get(rule_id)
            if existing is None:
                raise RuleStoreError(f"nincs ilyen szabály: {rule_id}")
            parents = [
                rid for rid, item in self._rules.items()
                if rule_id in item.members
            ]
            if parents:
                raise RuleStoreError(
                    f"a(z) {rule_id} szabály nem törölhető, mert tagja a "
                    f"következő gyűjtőszabályoknak: {', '.join(parents)}; "
                    "előbb vedd ki a tagok közül"
                )
            rules = dict(self._rules)
            del rules[rule_id]
            self._write_raw(
                {rid: self._rule_storage(item) for rid, item in rules.items()}
            )
            self._rules = rules
        return existing


class GroupStore:
    """groups.json: csoportok, azok szabályai és tagjai."""

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
            raise GroupStoreError(f"a csoporttár nem olvasható: {exc}") from exc
        if not isinstance(data, dict):
            raise GroupStoreError("a csoporttár formátuma hibás")
        raw_groups = data.get("groups", data)
        if not isinstance(raw_groups, dict):
            raise GroupStoreError("a csoporttár groups mezője hibás")
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
            raise GroupStoreError(f"{group_id}: hibás bejegyzés")
        # A fenntartott, régi admin-full azonosítót a csoport szabályai
        # közül is kiszűrjük, hogy egy régi groups.json ne adjon rejtett
        # jogosultságot, és a csoport szerkesztése se akadjon el miatta.
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
                self.log(f"[csoportok] {exc}")
                stamp = int(time.time())
                target = f"{self.path}.corrupt-{stamp}"
                try:
                    os.replace(self.path, target)
                    self.log(f"[csoportok] hibás fájl félretéve: {target}")
                except OSError:
                    pass
                raw = {}
            groups: dict[str, Group] = {}
            for group_id, item in raw.items():
                try:
                    clean_id = _clean_id(group_id, "csoport-azonosító")
                    groups[clean_id] = self._parse(clean_id, item)
                except (ValueError, GroupStoreError) as exc:
                    self.log(f"[csoportok] kihagyott hibás csoport: {exc}")
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
        group_id = _clean_id(group_id, "csoport-azonosító")
        group = self._parse(group_id, {**data, "created": int(time.time())})
        self._load()
        with self._locked():
            if group_id in self._groups:
                raise GroupStoreError(f"már létezik ilyen csoport: {group_id}")
            groups = dict(self._groups)
            groups[group_id] = group
            self._write_raw({gid: self._storage(item) for gid, item in groups.items()})
            self._groups = groups
        return group

    def update(self, group_id: str, data: dict) -> Group:
        group_id = _clean_id(group_id, "csoport-azonosító")
        self._load()
        with self._locked():
            existing = self._groups.get(group_id)
            if existing is None:
                raise GroupStoreError(f"nincs ilyen csoport: {group_id}")
            updated = self._parse(group_id, {**data, "created": existing.created})
            groups = dict(self._groups)
            groups[group_id] = updated
            self._write_raw({gid: self._storage(item) for gid, item in groups.items()})
            self._groups = groups
        return updated

    def delete(self, group_id: str) -> Group:
        group_id = _clean_id(group_id, "csoport-azonosító")
        self._load()
        with self._locked():
            existing = self._groups.get(group_id)
            if existing is None:
                raise GroupStoreError(f"nincs ilyen csoport: {group_id}")
            groups = dict(self._groups)
            del groups[group_id]
            self._write_raw({gid: self._storage(item) for gid, item in groups.items()})
            self._groups = groups
        return existing

    def set_memberships(self, user: str, group_ids) -> None:
        """A felhasználó csoporttagságainak beállítása egy írással."""
        if not USERNAME_RE.match(user):
            raise GroupStoreError("érvénytelen felhasználónév")
        wanted = set(_clean_str_list(group_ids, "groups", maximum=64))
        self._load()
        with self._locked():
            known = set(self._groups)
            missing = wanted - known
            if missing:
                raise GroupStoreError(
                    f"ismeretlen csoport: {', '.join(sorted(missing))}"
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
        """A szabály közvetlen csoport-kiosztásainak beállítása egy írással.

        Minden csoportra pontosan akkor kerül bele a szabály, ha a kért
        halmazban szerepel. A többi szabály és a csoportok tagsága változatlan.
        Visszatérés: (hozzáadott, eltávolított) csoport-azonosítók.
        """
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise GroupStoreError("hiányzó szabály-azonosító")
        rule_id = rule_id.strip()
        if rule_id == LEGACY_ADMIN_RULE_ID:
            raise GroupStoreError(
                "a fenntartott szabály-azonosító nem rendelhető hozzá"
            )
        wanted = set(_clean_str_list(group_ids, "groups", maximum=64))
        self._load()
        with self._locked():
            groups = dict(self._groups)
            missing = wanted - set(groups)
            if missing:
                raise GroupStoreError(
                    f"ismeretlen csoport: {', '.join(sorted(missing))}"
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

    # -- konfigurációs csomag --------------------------------------------------

    def export_records(self) -> dict:
        """Az aktuális csoportok tárolási alakja a konfigurációs csomaghoz."""
        self._load()
        with self._lock:
            return {
                group_id: self._storage(group)
                for group_id, group in self._groups.items()
            }

    def validate_import_records(self, raw) -> dict[str, Group]:
        """A groups szakasz szigorú, írás nélküli ellenőrzése."""
        if not isinstance(raw, dict):
            raise GroupStoreError("a groups szakasz JSON-objektum kell")
        groups: dict[str, Group] = {}
        for raw_id, item in raw.items():
            if not isinstance(raw_id, str):
                raise GroupStoreError("érvénytelen csoport-azonosító")
            try:
                clean_id = _clean_id(raw_id, "csoport-azonosító")
            except ValueError as exc:
                raise GroupStoreError(str(exc)) from exc
            if clean_id != raw_id:
                raise GroupStoreError(
                    f"a csoport-azonosító nem normalizált: {raw_id!r}"
                )
            raw_rules = item.get("rules") if isinstance(item, dict) else None
            if isinstance(raw_rules, list) and LEGACY_ADMIN_RULE_ID in raw_rules:
                raise GroupStoreError(
                    f"{clean_id}: a fenntartott szabály-azonosító nem importálható"
                )
            groups[clean_id] = self._parse(clean_id, item)
        return groups

    def replace_all(self, groups: dict[str, Group]) -> None:
        """A teljes csoporttár cseréje (a hívó már ellenőrizte)."""
        with self._locked():
            self._write_raw({
                group_id: self._storage(group)
                for group_id, group in groups.items()
            })
            self._groups = dict(groups)
            self._loaded = True

    def reset(self) -> None:
        """A fájl törlése és a memóriabeli csoporttár ürítése."""
        with self._locked():
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self._groups = {}
            self._loaded = True


# --------------------------------------------------------------------- tűzfal

class FirewallError(RuntimeError):
    """Az nftables nem tudta végrehajtani a kért műveletet."""


class Firewall:
    """A dinamikus engedélyezőhalmazok kezelése.

    A halmazok elemei kerneloldali timeouttal rendelkeznek, így a hozzáférés
    akkor is lejár, ha ez a folyamat közben leáll.

    A teljes hozzáférés az allowed_v4 halmazban van (egy IP-elem). A
    portokhoz kötött hozzáférés két összetett halmazban: allowed_tcp és
    allowed_udp (IP . DNAT előtti célport), illetve allowed_icmp.
    A host (input) szabályok külön halmazokba kerülnek (allowed_input_tcp
    és allowed_input_udp), a munkamenet TTL-jével. A host SSH is ilyen
    közönséges TCP 22-es host-engedély; nincs külön SSH-halmaz.
    """

    # A port proxy input céljának felderítése (a tesztek felülírják).
    proc_net = "/proc/net"
    sysctl_conf = "/proc/sys/net/ipv4/conf"
    # Az utoljára telepített port proxy szabályok (None: még semmi).
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
                raise ValueError(f"érvénytelen nftables név: {name!r}")
        fwd_mark = str(fwd_mark or "").strip().lower()
        if not re.match(r"^0x[0-9a-f]{1,8}$", fwd_mark):
            raise ValueError(f"érvénytelen nftables mark: {fwd_mark!r}")
        if lan_if and not _LAN_IF_RE.match(lan_if):
            raise ValueError(f"érvénytelen LAN interfész: {lan_if!r}")
        if wan_if and not _LAN_IF_RE.match(wan_if):
            raise ValueError(f"érvénytelen WAN interfész: {wan_if!r}")
        self.fwd_mark = fwd_mark
        self.drop_log_group = max(1, min(65535, int(drop_log_group)))
        self.table = table
        self.set_name = set_name
        self.tcp_set = "allowed_tcp"
        self.udp_set = "allowed_udp"
        # A portálgép saját szolgáltatásai (host/input szabály): csak a
        # munkamenet IP-jének, a TTL-ig.
        self.input_tcp_set = "allowed_input_tcp"
        self.input_udp_set = "allowed_input_udp"
        # A host (input) szabályokban valaha deklarált célportok. Az input
        # lánc ezekkel vágja el a meglévő kapcsolatokat, ha az engedély
        # eltűnik; a portál csak hozzáad, ezért egy törölt szabály nem
        # nyithatja meg újra a folyamatot.
        self.service_tcp_set = "host_service_tcp"
        self.service_udp_set = "host_service_udp"
        self.icmp_set = "allowed_icmp"
        self.mac_set = "client_mac"
        self.ban_set = "banned_v4"
        # fail2ban proxy-tiltás: csak a host TCP 80/443-át zárja.
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
        # IP -> a munkamenet alatt rögzített MAC. A halmaz listázásából is
        # pótolható, ezért ez csak gyorsítás és pontos törlés.
        self._macs: dict[str, str] = {}
        # A host_service_* takarításnál a hiányzó/hibás conntrack eszközt
        # csak egyszer naplózzuk, ne minden szinkronnál.
        self._prune_conntrack_warned = False

    # -- alacsony szintű hívás -------------------------------------------------

    def _run(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess:
        cmd = [self.binary, *args]
        if self.dry_run:
            self.log(f"[tűzfal] DRY-RUN: {' '.join(cmd)}")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=10)
        except FileNotFoundError as exc:
            raise FirewallError(f"az nft nem található: {self.binary}") from exc
        except PermissionError as exc:
            raise FirewallError("nincs jogosultság az nft futtatásához (CAP_NET_ADMIN)") from exc
        except subprocess.TimeoutExpired as exc:
            raise FirewallError("az nft nem válaszolt időben") from exc
        if check and result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            raise FirewallError(detail or f"az nft kilépési kódja: {result.returncode}")
        return result

    def _run_script(self, script: str) -> None:
        """Egy nft-parancsfájl futtatása a szabványos bemeneten.

        Az elemhozzáadásokat egy tranzakcióban adjuk át az nft-nek, így nem
        indul külön folyamat minden egyes porthoz.
        """
        if self.dry_run:
            for line in script.splitlines():
                if line.strip():
                    self.log(f"[tűzfal] DRY-RUN: {line}")
            return
        try:
            result = subprocess.run(
                [self.binary, "-f", "-"],
                input=script.encode("utf-8"),
                capture_output=True,
                timeout=10,
            )
        except FileNotFoundError as exc:
            raise FirewallError(f"az nft nem található: {self.binary}") from exc
        except PermissionError as exc:
            raise FirewallError("nincs jogosultság az nft futtatásához (CAP_NET_ADMIN)") from exc
        except subprocess.TimeoutExpired as exc:
            raise FirewallError("az nft nem válaszolt időben") from exc
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            raise FirewallError(detail or f"az nft kilépési kódja: {result.returncode}")

    # -- admin testreszabás ----------------------------------------------------

    @staticmethod
    def _port_set(ports: list[int]) -> str:
        values = [str(int(port)) for port in ports]
        if len(values) == 1:
            return values[0]
        return "{ " + ", ".join(values) + " }"

    @staticmethod
    def _custom_ports(entry: dict, kind: str) -> list[int]:
        """A pre-auth/blokk bejegyzés érvényes, egyedi portjai.

        A korábbi ``int(port)`` konverzió a hibás típusokat ``TypeError``/
        ``ValueError`` formájában engedte tovább, a ``"80"`` sztringet pedig
        karakterenként alakította. Minden érvénytelen érték ``FirewallError``,
        hogy a hívó fail-closed módon elutasíthassa a beállítást.
        """
        raw = entry.get("ports", [])
        if not isinstance(raw, (list, tuple)) or not raw:
            raise FirewallError(f"érvénytelen {kind}-bejegyzés")
        ports: list[int] = []
        for port in raw:
            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
            ):
                raise FirewallError(f"érvénytelen {kind}-port: {port!r}")
            if port not in ports:
                ports.append(port)
        return ports

    @staticmethod
    def _custom_dst(entry: dict, kind: str) -> str:
        """Normalizált IPv4 cél; IPv6 a ``ct original ip daddr`` miatt hiba."""
        dst = str(entry.get("dst", "")).strip()
        if not dst:
            return ""
        try:
            network = ipaddress.ip_network(dst, strict=False)
        except ValueError as exc:
            raise FirewallError(f"érvénytelen {kind}-cél: {dst}") from exc
        if network.version != 4:
            raise FirewallError(
                f"a {kind}-cél csak IPv4 lehet: {dst}"
            )
        return str(network)

    def _log_statement(self, reason: str, rate: str = "30/minute") -> str:
        """Rate-limited NFLOG log kifejezés (önálló, nem eldobó szabályhoz)."""
        return (
            f"limit rate {rate} burst 60 packets log prefix "
            f'"dropjak-drop reason={reason} " group {self.drop_log_group}'
        )

    def clear_custom(self) -> None:
        """A pre-auth és blokk láncok ürítése (a láncok létrehozásával).

        Külön tranzakcióban fut az alkalmazás előtt: ha az új szabályok
        érvénytelenek, a régi pre-auth engedélyek nem maradnak életben.
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
        """A pre-auth és blokk szabályok renderelése (végrehajtás nélkül).

        A pre-auth cél üresen minden célra érvényes. A ``forward`` irány a
        LAN felől a megadott célra/portra nyit; a WAN felől csak DNAT-olt
        (publikált) forgalomra, így nem válik nyílt továbbítóvá. Az ``input``
        irány a portálgép saját portjait nyitja meg a bejelentkezés előtt,
        ezért közvetlenül fogadja el a csomagot (nincs forward-jelölés és
        ``preauth_nat`` sem). A blokk a LAN felől induló forgalmat dobja el,
        a 80-as TCP-portnál a portál-átirányítás előtt is. A kikapcsolt
        (``enabled: false``) bejegyzések kimaradnak.

        ``include_block=False`` esetén a blokk-szabályok nem renderelődnek:
        a hívó a meglévő block/block_nat láncokat érintetlenül hagyja.
        Bármely érvénytelen bejegyzés ``FirewallError``, még a végrehajtás
        előtt; így részleges szabálykészlet nem kerülhet a kernelbe.
        """
        block = _enabled_custom_entries(block) if include_block else []
        preauth = _enabled_custom_entries(preauth)
        forward_preauth: list[dict] = []
        input_preauth: list[dict] = []
        for entry in preauth:
            # A régi bejegyzésekben nincs direction: azok forward irányúak.
            direction = str(entry.get("direction") or "forward").strip()
            if direction not in ("forward", "input"):
                raise FirewallError("érvénytelen pre-auth irány")
            if direction == "input":
                input_preauth.append(entry)
            else:
                forward_preauth.append(entry)
        if forward_preauth and not self.lan_if:
            raise FirewallError(
                "pre-auth szabály csak ismert LAN interfésszel alkalmazható"
            )
        # Az input irány a host felé menő forgalom: a bejelentkezés előtt
        # elérhető host-portok a lényeg, ezért a WAN is számít. Ismert
        # interfész nélkül a szabály nem lenne biztonságosan korlátozható.
        input_ifaces: list[str] = []
        for name in (self.lan_if, self.wan_if):
            if name and name not in input_ifaces:
                input_ifaces.append(name)
        if input_preauth and not input_ifaces:
            raise FirewallError(
                "input pre-auth szabály csak ismert LAN vagy WAN interfésszel "
                "alkalmazható"
            )
        lines: list[str] = []
        # A tiltott forrás a pre-auth lánc első szabályaként is eldobódik.
        # A base forward láncban a banned_v4 drop már a pre-auth ugrás előtt
        # fut; ez a szabály akkor is véd, ha a láncok sorrendje később
        # megváltozik, vagy egy pre-auth bejegyzés established kapcsolatra
        # illeszkedne. A tiltás ezzel minden engedélyezett/pre-auth portot
        # felülír; csak a portál és a DHCP marad elérhető.
        lines.append(
            f"add rule inet {self.table} preauth "
            f"ip saddr @{self.ban_set} drop"
        )
        # Az input pre-auth lánc első szabálya ugyanígy a tiltott forrásokat
        # dobja el, hogy a tiltás a host-portokat se nyissa meg.
        lines.append(
            f"add rule inet {self.table} preauth_input "
            f"ip saddr @{self.ban_set} drop"
        )
        for entry in block:
            proto = str(entry.get("proto", "")).strip().lower()
            if proto not in ("tcp", "udp"):
                raise FirewallError("érvénytelen blokk-bejegyzés")
            ports = self._custom_ports(entry, "blokk")
            dst = self._custom_dst(entry, "blokk")
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
                raise FirewallError("érvénytelen pre-auth bejegyzés")
            ports = self._custom_ports(entry, "pre-auth")
            dst = self._custom_dst(entry, "pre-auth")
            match = f"meta l4proto {proto}"
            if dst:
                match += f" ct original ip daddr {dst}"
            match += f" ct original proto-dst {self._port_set(ports)}"
            # A LAN felől a pre-auth a megadott célra/portra nyit. A WAN
            # felől csak DNAT-olt (publikált) forgalomra: így a szabály
            # nem válik nyílt továbbítóvá tetszőleges külső cél felé.
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
                # Cél nélküli pre-auth esetén ezt kihagyjuk: a related
                # szabály cél nélkül minden kapcsolódó forgalmat átengedne.
                lines.append(
                    f"add rule inet {self.table} preauth ct state related "
                    f"ct original ip daddr {dst} "
                    f"meta mark set {self.fwd_mark} accept"
                )
            if proto == "tcp" and 80 in ports:
                # A prerouting a 80-as TCP-t a portálra irányítja. A
                # conntrack-jelölés ezt a láncot kikerülteti a base chain
                # return szabályával; a forward pre-auth szabály továbbra is
                # külön dönt a csomagról. Cél nélkül ez minden LAN-oldali
                # HTTP-t kivesz a portál-átirányítás alól.
                nat = "meta l4proto tcp"
                if dst:
                    nat += f" ct original ip daddr {dst}"
                nat += " ct original proto-dst 80"
                lines.append(
                    f"add rule inet {self.table} preauth_nat {nat} "
                    f"ct mark set {PREAUTH_CT_MARK}"
                )
        # A nyilvános, port-módú alagút-szolgáltatások WAN-only pre-auth
        # elfogadásai. A bejegyzések minden alkalmazáskor az élő
        # beállításokból származnak, ezért a szolgáltatás letiltásakor,
        # törlésekor vagy priváttá válásakor automatikusan eltűnnek. A LAN
        # irányt szándékosan nem nyitjuk meg, és a ``related`` szabályt
        # cél nélkül nem tesszük be (az minden kapcsolódó forgalmat
        # átengedne). A blokk lánc a base chainben előbb fut, ezért a
        # tiltás továbbra is felülírja ezeket.
        if tunnel_public and not self.wan_if:
            raise FirewallError(
                "nyilvános alagút-szolgáltatás csak ismert WAN "
                "interfésszel alkalmazható"
            )
        for proto, port in tunnel_public:
            if proto not in ("tcp", "udp") or isinstance(port, bool) \
                    or not isinstance(port, int) or not 1 <= port <= 65535:
                raise FirewallError("érvénytelen nyilvános alagút-port")
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
        for entry in input_preauth:
            proto = str(entry.get("proto", "")).strip().lower()
            if proto not in ("tcp", "udp"):
                raise FirewallError("érvénytelen pre-auth bejegyzés")
            ports = self._custom_ports(entry, "pre-auth")
            dst = self._custom_dst(entry, "pre-auth")
            match = f"meta l4proto {proto}"
            if dst:
                match += f" ct original ip daddr {dst}"
            match += f" ct original proto-dst {self._port_set(ports)}"
            # A csomag a host felé megy, ezért közvetlen accept kell: nincs
            # forward-jelölés, és a DNAT-os WAN-feltétel sem értelmezhető.
            # A forrás a bejelentkezés előtt bármely ismert interfész lehet.
            for iface in input_ifaces:
                lines.append(
                    f'add rule inet {self.table} preauth_input '
                    f'iifname "{iface}" {match} accept'
                )
            # A meglévő kapcsolat a szabály élettartama alatt is maradjon
            # életben (a host_service_* őrök ezt a láncot nem érik el).
            lines.append(
                f"add rule inet {self.table} preauth_input "
                f"ct state established {match} accept"
            )
        return lines

    def _portproxy_ifaces(self, value) -> list[str]:
        """A bejegyzés interfészei; ismeretlen interfész FirewallError."""
        wanted = {"wan": ("wan",), "lan": ("lan",), "both": ("lan", "wan")}
        if value not in wanted:
            raise FirewallError("érvénytelen port proxy interfész")
        names: list[str] = []
        for side in wanted[value]:
            name = self.lan_if if side == "lan" else self.wan_if
            if not name:
                raise FirewallError(
                    f"port proxy csak ismert {side.upper()} interfésszel "
                    "alkalmazható"
                )
            if name not in names:
                names.append(name)
        return names

    def _portproxy_loopback(self, proto: str, port: int, ifaces) -> str | None:
        """A loopback DNAT címe, ha a cél csak loopbacken figyel."""
        address = loopback_target(proto, port, self.proc_net)
        if address and route_localnet(ifaces, self.sysctl_conf):
            return address
        return None

    def _portproxy_input_nat(self, proto: str, port: int, ifaces) -> str:
        """Input proxy NAT: a csak 127.0.0.1-en figyelő célhoz DNAT, különben redirect.

        A redirect a bejövő interfész elsődleges címére (WAN/LAN IP) ír át;
        a csak loopbacken figyelő szolgáltatás (például a Docker
        127.0.0.1-re publikált portja) ott nem válaszol, a kernel RST-t
        küld. A 127.0.0.1-es DNAT-hoz a route_localnet kell az
        interfészeken; a sablon loopback_guard lánca minden más, kívülről
        érkező 127/8 csomagot eldob.
        """
        address = self._portproxy_loopback(proto, port, ifaces)
        if address:
            return f"dnat ip to {address}:{port}"
        return f"redirect to :{port}"

    def portproxy_localnet_blocked(self, entries) -> list[tuple[str, int]]:
        """(protokoll, hallgató port): loopback cél, de a route_localnet ki van kapcsolva."""
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
        """A port proxy láncok szabályai (végrehajtás nélkül).

        Csak a hostnak címzett (``fib daddr type local``) forgalom kerül
        DNAT-ra: egy LAN-kliens külső szerverre menő, azonos portú
        forgalmát a proxy nem téríti el. A forward engedélyt a forward
        lánc meglévő ``ct original`` szabálya adja (kliens IP . hallgató
        port az allowed_tcp/udp halmazban, FWD_MARK-kal); az input proxyt a
        portproxy_input lánc engedélyezi (kliens IP . hallgató port az
        allowed_input_* halmazban), és ott a nem engedélyezett folyam
        csomagonként eldobódik, így a visszavonás a meglévő kapcsolatot is
        elvágja. Bármely hibás bejegyzés FirewallError a végrehajtás előtt.
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
                raise FirewallError("érvénytelen port proxy bejegyzés")
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
                    raise FirewallError("érvénytelen port proxy cél")
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
        """Az alagút-szolgáltatások forrásmaszkolása a dropjak0 felé.

        A forward engedélyt nem itt adjuk: a szintetikus bejegyzések a
        forward lánc meglévő ``ct original`` szabályán mennek át, tehát a
        portál-engedély ugyanúgy kötelező, mint a port proxynál. (Aki
        nyilvános alagutat akar, explicit pre-auth szabályt ad.)
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
                # Az ügynök allowed-ips-e csak 10.77.0.0/24, ezért a kliens
                # forrását a szerver címére kell maszkolni, különben a
                # válasz nem az alagúton jön vissza.
                lines.append(
                    f"add rule inet {self.table} portproxy_snat "
                    f"meta l4proto {proto} ct status dnat "
                    f"ct original proto-dst {entry.get('listen_port')} "
                    f"ip daddr {address} {proto} dport {target} masquerade"
                )
        return lines

    def _tunnel_rules(self, tunnels=()) -> list[str]:
        """Az alagút fogadó szabályai, ha van bekapcsolt ügynök.

        A WireGuard UDP-port mellett a portál szinkron-végpontja is
        elérhető az alagútból; a portál input lánca egyébként csak a LAN és
        a portál-hálózat felől engedné, ezért az ügynök nem tudna
        szolgáltatáslistát frissíteni.
        """
        if not isinstance(tunnels, dict):
            return []
        if not any(
            agent.get("enabled") for agent in tunnels.get("agents", [])
        ):
            return []
        if not self.wan_if:
            raise FirewallError(
                "alagút csak ismert WAN interfésszel alkalmazható"
            )
        port = tunnels.get("port")
        if isinstance(port, bool) or not isinstance(port, int) \
                or not 1 <= port <= 65535:
            raise FirewallError("érvénytelen WireGuard port")
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
        """A Docker által DNAT-olt (publikált) host portok; hiba: üres."""
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
        """A pre-auth és blokk szabályok telepítése ürítés nélkül.

        Ez a láncok tartalmát hozzáadja a meglévőkhöz; a teljes, atomikus
        cseréhez a :meth:`replace_custom` használatos.
        """
        lines = self._custom_rules(preauth, block)
        self._run_script("\n".join(lines) + ("\n" if lines else ""))

    def replace_custom(
        self, preauth=(), block=(), *, keep_block: bool = False,
        port_proxies=(), tunnels=None,
    ) -> None:
        """A pre-auth/blokk láncok cseréje egyetlen nft-tranzakcióban.

        A láncok létrehozása, ürítése és az új szabályok telepítése egy
        ``nft -f -`` bemenetben történik, ezért nincs olyan köztes állapot,
        amelyben a régi blokk már nincs, az új pedig még nem érvényes. A
        renderelés a végrehajtás előtt megtörténik; érvénytelen bejegyzés
        esetén a kernel állapota változatlan marad.

        ``keep_block=True`` esetén csak a pre-auth láncokat cseréli: a
        block/block_nat láncok érintetlenek maradnak (hibás beállításfájl
        esetén az utolsó ismert jó blokkolás nem tűnhet el).

        A port proxy láncok ugyanebben a tranzakcióban cserélődnek. Az
        alagút-szolgáltatások szintetikus forward bejegyzésként kerülnek a
        port proxy szabályok közé; a WireGuard UDP-port külön láncba.
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
        """Nem létező elem törlése nem hiba (a kernel már lejárattathatta)."""
        result = self._run(
            ["delete", "element", "inet", self.table, set_name, "{", element, "}"],
            check=False,
        )
        if result.returncode == 0:
            return
        detail = result.stderr.decode("utf-8", "replace")
        if "No such file or directory" in detail or "does not exist" in detail:
            return
        raise FirewallError(detail.strip() or "az nft törlés sikertelen")

    def _elements(
        self, address: str, ports: Ports
    ) -> list[tuple[str, str]]:
        """(halmaz, elem) párok a kért portokhoz.

        A host (input) szabály a portálgép saját szolgáltatásait nyitja
        meg, ezért külön halmazba kerül; sosem az ``allowed_tcp``/
        ``allowed_udp`` forward halmazokba.
        """
        direction = ports.direction
        if direction not in ("forward", "input"):
            # Belső hiba: ismeretlen irányhoz nem rendelünk halmazt.
            raise FirewallError(
                f"érvénytelen szabályirány: {direction!r}"
            )
        if ports.full:
            if direction == "input":
                raise FirewallError(
                    "host szabály nem lehet teljes hozzáférésű"
                )
            # A teljes hozzáférés minden mást magába foglal.
            return [(self.set_name, address)]
        tcp_set = (
            self.input_tcp_set if direction == "input" else self.tcp_set
        )
        udp_set = (
            self.input_udp_set if direction == "input" else self.udp_set
        )
        elements: list[tuple[str, str]] = []
        # Az nft interval halmazban a szomszédos portok egy tartományként
        # kerülnek be; így egy 8000-8100 szabály egyetlen elemet ad.
        for set_name, values in ((tcp_set, ports.tcp), (udp_set, ports.udp)):
            for low, high in merge_port_intervals(values):
                elements.append(
                    (set_name, f"{address} . {format_port_interval(low, high)}")
                )
        if ports.icmp:
            if direction == "input":
                raise FirewallError(
                    "host szabály nem tartalmazhat ICMP-t"
                )
            elements.append((self.icmp_set, address))
        return list(dict.fromkeys(elements))

    # -- MAC-kötés -------------------------------------------------------------

    def binds_mac(self, address: str) -> bool:
        """Kell-e ehhez az IP-hez MAC-kötés (LAN-kliens esetén igen)."""
        if not self.mac_binding:
            return False
        try:
            return ipaddress.ip_address(address) in self.lan_network
        except ValueError:
            return False

    @staticmethod
    def parse_mac_json(raw: bytes | str, address: str) -> list[str]:
        """A ``client_mac`` halmaz JSON-jéből az adott IP-hez tartozó MAC-ek.

        A hibás vagy hiányos kimenet ``FirewallError``, nem üres lista: egy
        listázási hiba nem jelentheti azt, hogy nincs MAC-kötés, különben a
        kötés/oldás a valós kernelállapot ismerete nélkül futna.
        """
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise FirewallError(
                    "a client_mac halmaz kimenete nem UTF-8"
                ) from exc
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise FirewallError(
                "a client_mac halmaz kimenete érvénytelen JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise FirewallError(
                "a client_mac halmaz kimenete nem JSON-objektum"
            )
        raw_items = payload.get("nftables")
        if not isinstance(raw_items, list):
            raise FirewallError(
                "a client_mac halmaz kimenetéből hiányzik az nftables lista"
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
        """Az adott IP-hez tartozó ``ip . mac`` elemek a kernelből.

        ``strict=True`` esetén a listázás bármilyen hibája ``FirewallError``
        (a MAC-kötést igénylő engedélyezés így fail-closed marad). Az
        oldás/takarítás nem szakadhat meg egy listázási hiba miatt, ezért
        ott a memóriabeli ismert értékekkel dolgozunk és naplózunk.
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
                    detail or "a client_mac halmaz listázása nem sikerült"
                )
            return values
        try:
            macs = self.parse_mac_json(result.stdout, address)
        except FirewallError as exc:
            if strict:
                raise
            self.log(
                f"[tűzfal] a client_mac halmaz listázása nem sikerült: {exc}"
            )
            return values
        for mac in macs:
            value = f"{address} . {mac}"
            if value not in values:
                values.append(value)
        return values

    def _bind_mac_locked(self, address: str, ttl: int) -> str:
        """A kliens MAC-címének rögzítése; ha nem tudható, hiba (fail-closed)."""
        mac = arp_mac(address, self.lan_if, self.arp_path)
        if mac is None:
            raise FirewallError(
                f"a(z) {address} kliens MAC-címe nem állapítható meg az "
                "ARP-táblából; a hozzáférés biztonsági okból nem engedélyezhető"
            )
        # A korábbi, esetleg kézzel vagy összeomlás után maradt bejegyzéseket
        # is töröljük, hogy egy IP-hez egyszerre csak egy MAC tartozzon.
        for value in self._mac_values_locked(address, strict=True):
            self._delete_quiet(self.mac_set, value)
        self._run_script(
            f"add element inet {self.table} {self.mac_set} "
            f"{{ {address} . {mac} timeout {ttl}s }}\n"
        )
        self._macs[address] = mac
        return mac

    def _unbind_mac_locked(self, address: str) -> None:
        """Az IP-hez tartozó, esetleg maradt MAC-bejegyzés törlése.

        Akkor is törlünk, ha az IP jelenleg nem LAN-kliens: a MAC-kötés
        beállítása vagy a hálózat változhatott, és a régi elem a TTL-ig
        másként maradhatna a kernelben.
        """
        for value in self._mac_values_locked(address):
            self._delete_quiet(self.mac_set, value)
        self._macs.pop(address, None)

    def _mac_delete_elements(self, address: str) -> list[tuple[str, str]]:
        """A tiltandó IP MAC-elemei; nem-LAN címnél is kitakarít."""
        with self._lock:
            values = self._mac_values_locked(address)
        return [(self.mac_set, value) for value in values]

    def _port_set_values_locked(self, set_name: str, address: str) -> list[str]:
        """Az adott IP ``ip . port`` elemei egy portos halmazból.

        A MAC-listázáshoz hasonlóan a kernel JSON-kimenetét dolgozza fel. A
        listázás hibája nem akaszthatja meg a tiltást: ilyenkor üres listát
        adunk, a többi halmaz törlése így is megtörténik.
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
                f"[tűzfal] a(z) {set_name} halmaz listázása nem sikerült: {exc}"
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
        """Az IP élő ``(lo, hi, hátralévő)`` portintervallumai.

        Listázási vagy értelmezési hiba esetén ``None``; ilyenkor a hívó a
        régi, pontos elemtörlésre esik vissza. A hiányzó halmaz üres.
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
                f"[tűzfal] a(z) {set_name} halmaz listázása nem sikerült: {exc}"
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
        """Portintervallumok kiadása átfedésbiztos módon.

        A meglévő elemhez nem nyúlunk vakon: csak a még nem fedett részeket
        adjuk hozzá, az átfedő meglévő elem timeoutját pedig a hosszabbikra
        állítjuk. Így egy szűkebb új grant nem törli a nagyobb, aktív
        tartományt, és nem rövidíti le a hosszabb élettartamot.
        """
        existing = self._list_port_elements_locked(set_name, address)
        if existing is None:
            # Listázási hiba: nem törhetünk vakon, mert az egy nagyobb,
            # aktív tartományt is elvenne. Az új elem hozzáadása biztonságos
            # (az átfedő intervallumot a kernel kezeli); ha nem sikerül, a
            # grant hibát ad, de a meglévő hozzáférés megmarad.
            self.log(
                f"[tűzfal] a(z) {set_name} halmaz listázása nem sikerült; "
                "a meglévő elemek érintetlenek maradnak"
            )
            existing = []
        elif not existing:
            # Nincs mit egyeztetni: a régi viselkedés (törlés, majd
            # hozzáadás) indítja újra a timeoutot, és a tesztek is ezt
            # várják.
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
        # Csak az átfedő elemeket írjuk újra. A fedetlen részeket a
        # korábbi, rövidebb timeoutjukkal tartjuk meg; az új grant csak a
        # saját tartományában hosszabbít. Így egy szűkebb grant nem ad
        # hosszabb élettartamot a nagyobb, régi tartomány többi portjának.
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
        # Az érintett elemek határait és az új tartomány határait
        # szegmenshatárokká alakítjuk.
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
        """A tiltandó IP összes host (input) halmazeleme."""
        elements: list[tuple[str, str]] = []
        with self._lock:
            for set_name in (self.input_tcp_set, self.input_udp_set):
                elements.extend(
                    (set_name, value)
                    for value in self._port_set_values_locked(set_name, address)
                )
        return elements

    def _forward_delete_elements(self, address: str) -> list[tuple[str, str]]:
        """A tiltandó IP összes forward (``ip . port``) halmazeleme.

        Csak akkor használjuk, ha az IP-hez nem tartozik munkamenet. A
        portál egy IP-hez egyszerre egy munkamenetet tart nyilván, ezért a
        kernelben talált, ehhez az IP-hez tartozó dinamikus elemek a mi
        korábbi engedélyeink (esetleg összeomlás után árva elemek). A
        listázás IP szerint szűr, más kliens elemét nem érinti.
        """
        elements: list[tuple[str, str]] = []
        with self._lock:
            for set_name in (self.tcp_set, self.udp_set):
                elements.extend(
                    (set_name, value)
                    for value in self._port_set_values_locked(set_name, address)
                )
        return elements

    # -- nyilvános műveletek ---------------------------------------------------

    def allow(self, ip: str, ttl: int) -> None:
        """Visszafelé kompatibilis belépési pont: teljes hozzáférés."""
        self.grant(ip, Ports(full=True), ttl)

    def grant(self, ip: str, ports: Ports, ttl: int) -> None:
        """Egyetlen engedély kiadása; visszafelé kompatibilis burkoló."""
        self.grant_all(ip, (ports,), ttl)

    def grant_all(self, ip: str, grants, ttl: int) -> None:
        """Több, akár eltérő irányú engedély kiadása egy tranzakcióban.

        A gyűjtőszabály egyszerre forward és host (input) engedélyt is
        adhat; a halmazelemeket irányonként állítjuk elő, majd
        deduplikáljuk. Üres engedélyhalmaz esetén nincs teendő (és MAC-kötés
        sem történik).
        """
        if not is_ipv4(ip):
            raise FirewallError("csak IPv4-cím engedélyezhető")
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
            # A MAC-kötés a portok előtt történik: ha a kliens MAC-címe nem
            # állapítható meg, semmilyen engedély nem kerül a kernelbe.
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
            # A teljes és ICMP elemeknél marad a törlés + hozzáadás, mert
            # azoknak nincs átfedő tartományuk.
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
        """Forrás-IP felvétele a ``banned_v4`` (vagy a megadott) halmazba.

        A tiltás kerneloldali timeouttal rendelkezik. Újra hozzáadás előtt
        töröljük, így a tiltás meghosszabbításakor a timeout újraindul.
        """
        if not is_ipv4(ip):
            raise FirewallError("csak IPv4-cím tiltható le")
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
        """Forrás-IP törlése a ``banned_v4`` (vagy a megadott) halmazból.

        A hiányzó elem nem hiba.
        """
        if not is_ipv4(ip):
            return
        self._delete_elements([(set_name or self.ban_set, normalize_ip(ip))])

    def sync_bans(self, elements, set_name: str = "") -> None:
        """A tiltott IP-k és hátralévő idejük betöltése a halmazba.

        Induláskor hívjuk a dinamikus halmazok ürítése után. A halmazt előbb
        kiürítjük, hogy a kernel és a mentett nyilvántartás biztosan egyezzen.
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

    # A proxy-tiltás (TCP 80/443) ugyanígy, a proxy_banned_v4 halmazzal.
    def proxy_ban(self, ip: str, ttl: int) -> None:
        self.ban(ip, ttl, self.proxy_ban_set)

    def proxy_unban(self, ip: str) -> None:
        self.unban(ip, self.proxy_ban_set)

    def sync_proxy_bans(self, elements) -> None:
        self.sync_bans(elements, self.proxy_ban_set)

    def _delete_elements(self, elements: list[tuple[str, str]]) -> None:
        """Elemek törlése; a nem létező elem nem hiba.

        A portos halmazokban a törlés intervallumtudatos: ha egy kért
        tartomány csak részben fed egy meglévő elemet, az elemet kivágjuk,
        és a megmaradó részt a hátralévő timeouttal visszatesszük. Így egy
        részleges visszavonás nem törli a másik aktív szabály nagyobb
        tartományát. Listázási hiba esetén a régi, pontos törlés fut.
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
        """Portintervallumok törlése, a részben fedett elemek megőrzésével."""
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
        # A teljes és az ICMP halmazból mindenképpen törlünk; a portokat a
        # megadott engedélyből tudjuk.
        elements: list[tuple[str, str]] = [
            (self.set_name, address),
            (self.icmp_set, address),
        ]
        if ports is not None:
            elements.extend(self._elements(address, ports))
        # A port megadása nélküli tiltás a host (input) halmazokból is
        # töröljön minden elemet, ne csak a forward halmazokból.
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
        """A kliens engedélyeinek törlése.

        A teljes és az ICMP halmazból mindig törlünk. A portokat a megadott
        engedélyekből (Ports) vesszük: a szabályok tetszőleges portokat
        tartalmazhatnak, ezért nem lehet a katalógusból kiolvasni őket. A
        hívók a munkamenetből ismerik a kiadott engedélyt. A host TCP 22
        engedély is a grantokból, az ``allowed_input_tcp`` halmazból
        törlődik.

        ``only_grants=True`` esetén kizárólag a megadott grantokhoz tartozó
        elemeket töröljük; a teljes (``allowed_v4``), ICMP és MAC elemekhez
        nem nyúlunk. Ezt akkor használjuk, amikor ugyanahhoz az IP-hez aktív
        munkamenet tartozik, és csak a régi, nem átfedő grantokat szabad
        eltávolítani.

        A host (input) engedélyek a grantokból törlődnek (a TCP 22 is az
        ``allowed_input_tcp`` halmazból). ``discover=True`` esetén az IP-hez
        tartozó összes host és forward ``ip . port`` elemet felderítjük,
        így egy hiányos grantlista vagy egy korábbi összeomlás árva elemét
        is eltávolítjuk. Ezt a felderítő utat csak akkor szabad használni,
        ha az IP-hez nem tartozik munkamenet (a SessionManager egy-IP-egy-
        munkamenet szabálya miatt az IP-hez tartozó dinamikus elemek
        biztonságosan a mieink); a normál visszavonás a pontos grantokat
        használja.
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
        """Pontosan a megadott grantokhoz tartozó elemek törlése.

        A ``revoke_all(..., only_grants=True)`` csak a port- és ICMP-
        elemeket törli; ez a művelet a ``full`` engedélyhez tartozó
        ``allowed_v4`` elemet is eltávolítja, ha a grant azt tartalmazza.
        A MAC-kötéshez soha nem nyúl, mert ugyanahhoz az IP-hez tartozó,
        továbbra is aktív munkamenetnek szüksége lehet rá. Nem IPv4-cím
        esetén nincs teendő.
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
        """A host (input) szabályok portjainak betöltése a kernelbe.

        A ``host_service_tcp``/``host_service_udp`` halmazok a valaha
        deklarált host portokat tartalmazzák; az input lánc ezekkel vágja el
        a meglévő kapcsolatokat, ha az engedély eltűnik. A normál szinkron
        csak hozzáad, soha nem ürít: egy szabály törlése így nem nyithatja
        meg újra a már meglévő kapcsolatot. Az elavult portok ártalmatlanok,
        mert csak szigorúbbá teszik az established forgalom ellenőrzését; a
        feleslegeseket külön, biztonságos takarítás
        (:meth:`prune_host_service_ports`) törli, csak hivatkozás és élő
        conntrack nélküli portot.
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
                # Az interval halmazban az átfedő hozzáadás hibát ad, ezért
                # csak a még nem fedett részeket adjuk hozzá.
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
        """Egy ``inet_service`` halmazelem ``(lo, hi)`` párja."""
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
        """Egy ``inet_service`` halmaz (host_service_*) portjainak kiolvasása.

        A :meth:`parse_set_json` csak ``ipv4_addr`` és
        ``ipv4_addr . inet_service`` elemeket ismer, ezért a sima
        portszámokat külön dolgozzuk fel. Az értelmezhetetlen elemeket
        csendben kihagyjuk: takarításkor soha nem törölünk azért, mert egy
        idegen formátumú elemet nem értünk.
        """
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise FirewallError(
                    f"a(z) {set_name} halmaz kimenete nem UTF-8"
                ) from exc
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise FirewallError(
                f"a(z) {set_name} halmaz JSON-kimenete hibás: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise FirewallError(f"a(z) {set_name} halmaz kimenete hibás")
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
        """Egy ``inet_service`` halmaz intervallumai, összevonva."""
        ports = Firewall.parse_service_set_json(raw, set_name)
        return Firewall._merge_interval_list(
            [(port, port) for port in sorted(ports)]
        )

    def _list_service_ports_locked(self, set_name: str) -> set[int] | None:
        """A host_service_* halmaz elemei; listázási hiba esetén ``None``.

        A hiányzó tábla/halmaz üres halmaznak számít (a telepítés előtt is
        működik). Minden más hiba ``None``: ilyenkor a hívó nem töröl.
        """
        try:
            result = self._run(
                ["-j", "list", "set", "inet", self.table, set_name],
                check=False,
            )
        except FirewallError as exc:
            # Hiányzó nft, jogosultság vagy időtúllépés: nem törlünk.
            self.log(
                f"[tűzfal] a(z) {set_name} halmaz listázása nem sikerült: "
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
                f"[tűzfal] a(z) {set_name} halmaz listázása nem sikerült: "
                f"{detail or result.returncode}"
            )
            return None
        try:
            return self.parse_service_set_json(result.stdout, set_name)
        except FirewallError as exc:
            self.log(
                f"[tűzfal] a(z) {set_name} halmaz kimenete nem értelmezhető: "
                f"{exc}"
            )
            return None

    def _list_service_ranges_locked(
        self, set_name: str
    ) -> list[tuple[int, int]] | None:
        """A host_service_* halmaz intervallumai; hiba esetén ``None``."""
        try:
            result = self._run(
                ["-j", "list", "set", "inet", self.table, set_name],
                check=False,
            )
        except FirewallError as exc:
            self.log(
                f"[tűzfal] a(z) {set_name} halmaz listázása nem sikerült: "
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
                f"[tűzfal] a(z) {set_name} halmaz listázása nem sikerült: "
                f"{detail or result.returncode}"
            )
            return None
        try:
            return self.parse_service_set_intervals_json(
                result.stdout, set_name
            )
        except FirewallError as exc:
            self.log(
                f"[tűzfal] a(z) {set_name} halmaz kimenete nem értelmezhető: "
                f"{exc}"
            )
            return None

    def _warn_prune_conntrack(self, reason: str) -> None:
        """A conntrack hiányát/hibáját csak egyszer naplózza."""
        if self._prune_conntrack_warned:
            return
        self._prune_conntrack_warned = True
        self.log(f"[tűzfal] host port takarítás kihagyva: {reason}")

    def _live_conntrack_ports(self, candidates: set[int]) -> set[int] | None:
        """A jelöltek közül az élő conntrack-bejegyzésekben szereplő portok.

        ``None`` azt jelenti, hogy a conntrack nem listázható, ezért a hívó
        egyetlen portot sem törölhet. A keresés szándékosan konzervatív:
        bármely ``dport=<port>`` vagy ``sport=<port>`` találat megtartja a
        portot, akár a kliens, akár a host oldalán szerepel.
        """
        if not CONNTRACK_BIN:
            self._warn_prune_conntrack("a conntrack eszköz nem érhető el")
            return None
        try:
            result = subprocess.run(
                [CONNTRACK_BIN, "-L"], capture_output=True, timeout=10
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._warn_prune_conntrack(
                f"a conntrack listázása nem sikerült: {exc}"
            )
            return None
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            self._warn_prune_conntrack(
                "a conntrack listázása hibakóddal tért vissza "
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
        """Portok törlése a halmazból; a már eltűnt elem nem hiba."""
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
            # Csak a közben eltűnt elemeket toleráljuk egyenként; tartós
            # nft-hiba esetén nem indítunk ezernyi külön folyamatot.
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
        except Exception as exc:  # a naplózás soha ne blokkoljon
            self.log(
                f"[napló] host_ports_prune írása nem sikerült: {exc}"
            )

    def prune_host_service_ports(
        self, referenced_tcp, referenced_udp, audit=None
    ) -> dict:
        """A host_service_* halmazok biztonságos takarítása.

        Portot csak akkor törlünk, ha (a) egyetlen perzisztált szabály
        sem hivatkozik rá (bármely irányú vagy gyűjtőtag portja véd), és
        (b) nincs hozzá élő conntrack-bejegyzés. Ha a
        conntrack eszköz hiányzik vagy nem listázható, egyetlen portot sem
        törlünk: a megmaradó őrök csak szigorúbbá teszik az ellenőrzést.
        Ugyanígy járunk el, ha az nft halmazlistázás nem sikerül; a
        takarítás hibája soha nem akaszthatja meg az engedélyezést.

        A normál szinkron továbbra is add-only; egyedül ez az út töröl, a
        fenti két feltétellel. Induláskor a halmazok szándékosan nem
        ürülnek, hogy a törölt portok régi folyamai továbbra is el legyenek
        vágva. A 65536-os halmazméret miatt a portok száma legfeljebb
        65535 lehet, ezért a halmaz nem telhet meg.
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
                    "a host_service_* halmaz listázása nem sikerült, "
                    "a takarítás kimaradt"
                )
                summary["errors"].append(reason)
                self.log(f"[tűzfal] {reason}")
                self._audit_prune(audit, reason)
                return summary
            # Csak az egyportos elemeket takarítjuk: egy tartomány részleges
            # törlése a teljes elemet vinné, ezért azok biztonságosan
            # megmaradnak (ez csak szigorúbb, nem nyit hozzáférést).
            members_tcp = {low for low, high in ranges_tcp if low == high}
            members_udp = {low for low, high in ranges_udp if low == high}
            candidates_tcp = members_tcp - ref_tcp
            candidates_udp = members_udp - ref_udp
            candidates = candidates_tcp | candidates_udp
            if not candidates:
                return summary
            # A conntrack listázása a tűzfal-zár alatt fut, hogy a
            # döntés és a törlés közé ne ékelődhessen párhuzamos grant.
            live = self._live_conntrack_ports(candidates)
            if live is None:
                # Nincs conntrack-információ: egyetlen jelölt sem törölhető.
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
                    "[tűzfal] a host port takarítás részben nem sikerült: "
                    f"{reason}"
                )
                self._audit_prune(audit, reason)
        if summary["removed_tcp"] or summary["removed_udp"]:
            self.log(
                "[tűzfal] host port őrök takarítva: "
                f"TCP {summary['removed_tcp']}, UDP {summary['removed_udp']}; "
                f"élő conntrack miatt megtartva: {summary['live_kept']}"
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
                    detail.strip() or f"a(z) {set_name} halmaz ürítése sikertelen"
                )
            if not errors:
                self._macs.clear()
        if errors:
            raise FirewallError("; ".join(errors))

    @staticmethod
    def parse_set_json(raw: bytes | str, set_name: str) -> list[dict]:
        """Egy ``nft -j list set`` kimenetének feldolgozása.

        Az nft JSON-ben a timeoutos elem így néz ki::

            {"elem": {"val": {"concat": ["192.0.2.5", 80]},
                      "timeout": 90, "expires": 89}}

        Az időértékek másodpercek. A ``timeout`` az eredeti élettartam, az
        ``expires`` a hátralévő idő. A visszaadott lista elemei:
        ``{"address", "port", "expires_in", "timeout"}``; a port csak az
        összetett (IP . port) halmazoknál szerepel.
        """
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise FirewallError(
                    f"a(z) {set_name} halmaz kimenete nem UTF-8"
                ) from exc
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise FirewallError(
                f"a(z) {set_name} halmaz JSON-kimenete hibás: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise FirewallError(f"a(z) {set_name} halmaz kimenete hibás")
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
        """A dinamikus halmazok pillanatképe, a hátralévő időkkel.

        Csak olvas, ezért az admin Tűzfal nézet biztonságosan hívhatja.
        A nem létező halmaz üresnek számít (a telepítés előtt is működik).
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
                                f"{detail or 'az nft nem tudta listázni a halmazt'}"
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
        """A láncok nyers nftables kiírása az admin Tűzfal nézethez.

        Csak olvas, ezért az admin nézet biztonságosan hívhatja. A dinamikus
        halmazok tartalmát szándékosan nem tartalmazza (azokat a snapshot()
        mutatja); így a kimenet az ``iptables -L -n``-hez hasonló, rövid
        szabálylista marad. A hiányzó lánc nem hiba: a tábla a telepítés
        előtt még nem létezhet.
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
                            f"{detail or 'az nft nem tudta listázni a láncot'}"
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
        """Eltávolítja az ``nft list chain`` körüli tábla-burkot.

        Az újabb nft verziók a láncot is ``table inet <név> { ... }`` blokkba
        ágyazva írják ki. A nézetben a tábla csak egyszer szerepeljen, ezért
        a burkot levágjuk, és a plusz behúzást is megszüntetjük.
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


def _audit_conntrack_failure(
    audit, ip: str, returncode: int, detail: str, operation: str = "flush"
) -> None:
    """A conntrack-törlés hibája (nem kötelező, nem blokkoló naplózás)."""
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
        log(f"[napló] conntrack_failed írása nem sikerült: {exc}")


def conntrack_flush(ip: str, audit=None) -> bool:
    """Megszünteti az adott kliens meglévő kapcsolatait.

    A visszatérési érték jelzi, hogy a törlés ténylegesen lefutott-e. A
    hívók ezt naplózzák; a tűzfalhalmazok lejárata ettől függetlenül
    érvényesül az új kapcsolatokra. Valódi hiba esetén opcionális
    auditnapló-bejegyzés is készül (soha nem blokkol).
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
        log(f"[tűzfal] conntrack törlés nem sikerült ({ip}): {exc}")
        _audit_conntrack_failure(audit, ip, -1, str(exc))
        return False
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        # Az 1-es kód a conntrack esetében gyakran "nincs ilyen bejegyzés";
        # ez nem hiba, ilyenkor nincs mit törölni.
        if result.returncode != 1 or detail:
            log(
                f"[tűzfal] conntrack törlés hibakóddal tért vissza "
                f"({ip}): {result.returncode} {detail}".strip()
            )
            _audit_conntrack_failure(audit, ip, result.returncode, detail)
        return False
    return True


# Egyszerre legfeljebb ennyi célzott conntrack-törlést indítunk. Afölött a
# teljes IP-s ürítés olcsóbb és megbízhatóbb, mint több tucat folyamat.
CONNTRACK_REMOVED_LIMIT = 16


def conntrack_flush_removed(
    ip: str, removed, remaining=(), audit=None
) -> bool:
    """Csak az eltávolított engedélyekhez tartozó kapcsolatok törlése.

    ``removed`` a távozó, ``remaining`` a továbbra is érvényes grantok
    (jellemzően a munkamenet új uniója). A conntrack nem tud irány szerint
    szűrni, ezért a döntés az összes irány együttes unióján alapul:

    * Egy eltávolított ``full`` engedélyhez csak akkor végzünk teljes IP-s
      ürítést, ha ``remaining`` üres (semmi nem maradt engedélyezve). Ha
      maradt még engedély, a csomagszintű nft-szabályok állítják meg a
      távozó forgalmat; a teljes ürítés a maradó engedély élő kapcsolatait
      is megszakítaná (például a 22-es input SSH-t, amikor egy teljes
      forward hozzáférést input-22 vált fel).
    * Ha bármely maradó rész ``full`` (bármely irányban), célzott
      port/ICMP törlést egyáltalán nem indítunk: a conntrack irányvak, és
      a parancs a maradó teljes hozzáférés kapcsolatait is megszakítaná.
    * Egyébként a maradó TCP/UDP portok és az ICMP az összes irány
      uniójaként számítanak, mert a ``conntrack -D -s IP -p tcp --dport N``
      iránytól függetlenül töröl. Egy másik irányban még engedélyezett
      port kapcsolatai így érintetlenek maradnak.

    A művelet legfeljebb :data:`CONNTRACK_REMOVED_LIMIT` egyedi parancsot
    indít. Ennél több parancs esetén csak akkor váltunk teljes IP-s
    ürítésre, ha ``remaining`` üres; különben a maradó engedélyek védelme
    miatt kihagyjuk a tisztítást és ``False``-t adunk vissza. A
    ``DRY_RUN``/``CONNTRACK_BIN``/IPv4 feltételek ugyanazok, mint a
    :func:`conntrack_flush` esetében. A függvény soha nem dob kivételt;
    a hibák opcionális auditbejegyzést kapnak.
    """

    if DRY_RUN or not CONNTRACK_BIN or not is_ipv4(ip):
        return False
    address = normalize_ip(ip)
    removed = tuple(removed or ())
    remaining = tuple(remaining or ())
    if not remaining and any(part.full for part in removed):
        # Eltávolított teljes hozzáférés, és semmi nem maradt engedélyezve:
        # a legbiztosabb teljes IP-s ürítés.
        return conntrack_flush(ip, audit)
    if any(part.full for part in remaining):
        # A maradó teljes hozzáférés (bármely irányban) minden portot és
        # ICMP-t lefed. A conntrack nem tud irány szerint szűrni, ezért
        # bármely célzott törlés az ő élő kapcsolatait is megszakítaná.
        return False

    # A conntrack -D -s feltétel irányvak: a maradó portokat az összes
    # irány uniójaként kell számítani.
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
            # A távozó full elemét a fenti ág kezeli; maradó engedély
            # mellett szándékosan nem törlünk rá semmit.
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
                f"[tűzfal] a(z) {ip} célzott conntrack törlése "
                f"{len(commands)} parancsot igényelne; a maradó "
                "engedélyek védelme miatt kihagyjuk"
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
                f"[tűzfal] célzott conntrack törlés nem sikerült "
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
            # Az 1-es kód gyakran "nincs ilyen bejegyzés"; ilyenkor nincs
            # mit törölni, de a hívás nem tekinthető sikeresnek.
            if result.returncode != 1 or detail:
                log(
                    f"[tűzfal] célzott conntrack törlés hibakóddal tért "
                    f"vissza ({ip}, {proto}"
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
    """Bekapcsolt bejegyzések: (protokoll, hallgató port) -> a hatásuk.

    A szintetikus alagút-bejegyzések kimaradnak: nem felhasználói port
    proxyk, ezért nem adnak figyelmeztetést és conntrack-törlést sem.
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
    """Azok a (protokoll, port) párok, amelyek NAT-célja megváltozott.

    A conntrack a régi NAT-kötést a folyam végéig megtartja, ezért ezek
    meglévő kapcsolatait törölni kell (új, eltávolított vagy módosított
    bejegyzés egyaránt).
    """
    old = _port_proxy_keys(old_entries)
    new = _port_proxy_keys(new_entries)
    return sorted(
        key for key in set(old) | set(new) if old.get(key) != new.get(key)
    )


def conntrack_flush_port(proto: str, port: int, audit=None) -> bool:
    """A megadott eredeti célportú (DNAT előtti) kapcsolatok törlése."""
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
        log(f"[tűzfal] conntrack törlés nem sikerült ({target}): {exc}")
        _audit_conntrack_failure(
            audit, target, -1, str(exc), operation="flush_port"
        )
        return False
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        # Az 1-es kód üres hibaszöveggel: nincs ilyen bejegyzés.
        if result.returncode != 1 or detail:
            log(
                f"[tűzfal] conntrack törlés hibakóddal tért vissza "
                f"({target}): {result.returncode} {detail}".strip()
            )
            _audit_conntrack_failure(
                audit, target, result.returncode, detail,
                operation="flush_port",
            )
        return False
    return True


def _proc_sockets(proc_dir: str = "/proc/net"):
    """(protokoll, helyi cím, port) a hoston figyelő TCP / kötött UDP socketekre.

    A portál host-hálózaton fut, ezért a /proc/net a host socketjeit
    mutatja (például a docker-proxy publikált portjait is). A cím
    ``ipaddress`` objektum; a v4-leképezett IPv6 cím IPv4-ként jön.
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
                        # TCP-nél csak a LISTEN (0A), UDP-nél a kötött (07).
                        if fields[3] != ("0A" if proto == "tcp" else "07"):
                            continue
                        try:
                            raw, port = fields[1].rsplit(":", 1)
                            # A kernel a címet 32 bites, natív sorrendű
                            # szavakként írja ki.
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
    """A hoston figyelő TCP (LISTEN) és kötött UDP portok."""
    return {(proto, port) for proto, _, port in _proc_sockets(proc_dir)}


def loopback_target(proto: str, port: int, proc_dir: str = "/proc/net") -> str | None:
    """A csak loopbacken figyelő célport címe, egyébként None.

    Ha a porton csak 127.0.0.0/8 címre kötött socket van, a ``redirect``
    (a bejövő interfész elsődleges címe) üres portra érkezne: ilyenkor a
    DNAT célja ez a loopback cím. Wildcard (0.0.0.0 / ::) vagy más
    címre kötött socket mellett marad a redirect: a wildcard UDP-szerver
    a válasz forráscímét az útvonalból választja (az interfész címe), ezért
    127.0.0.1-re DNAT-olva a válasz nem illeszkedne a conntrackre.
    """
    addresses = set()
    for sock_proto, address, sock_port in _proc_sockets(proc_dir):
        if sock_proto != proto or sock_port != port:
            continue
        if address.version == 6:
            if address.is_unspecified:
                return None  # a dual-stack [::] az IPv4-et is fogadja
            continue  # a ::1 / más IPv6 cím az IPv4 proxyt nem érinti
        addresses.add(address)
    if not addresses or not all(address.is_loopback for address in addresses):
        return None
    preferred = ipaddress.IPv4Address("127.0.0.1")
    return str(preferred if preferred in addresses else min(addresses))


def route_localnet(ifaces, conf_dir: str = "/proc/sys/net/ipv4/conf") -> bool:
    """Engedi-e a kernel a 127/8 célt a megadott interfészeken.

    A kernel az ``all`` és az interfész értékét VAGY-kapcsolattal veszi.
    A portál konténerében a /proc/sys csak olvasható; a hoston a
    docker/setup-host.sh állítja be.
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
    """Figyelmeztetés a bekapcsolt bejegyzések már foglalt hallgató portjaira.

    Nem tiltás: a proxy DNAT-je (-101) a Docker DNAT-je (-100) előtt fut,
    ezért a beállított interfészeken a proxy nyer, és a helyi socket / a
    Docker-publikálás onnan nem érhető el. A ``localnet`` (protokoll,
    hallgató port) párjainál a cél csak loopbacken figyel, de a hoston ki
    van kapcsolva a route_localnet, ezért a proxy nem érheti el.
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
    """A kerneloldali halmazok és a portál-munkamenetek összefésülése.

    Egy IP-címhez egy csoport tartozik, benne a tényleges (kernelben lévő)
    engedélyekkel, a hozzájuk tartozó munkamenetekkel és a hátralévő
    időkkel. Az ``in_sync`` jelzi, ha a kernel és a munkamenet nyilvántartása
    eltér (például egy port nem került be, vagy kézzel bekerült egy másik).
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
        # A host (input) engedélyek ugyanabba a megjelenítési listába
        # kerülnek, irányjelöléssel; így egy IP csoportjában látszik minden
        # kerneloldali engedély, és az irány szerinti összevetés is helyes.
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
        # Elsődlegesen port szerint rendezünk; azonos portnál a forward
        # bejegyzés előrébb kerül, hogy a megjelenítés stabil legyen.
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
            # A host (input) munkamenet portjait a host halmazokhoz kell
            # hasonlítani, különben egy engedélyezett host szabály téves
            # „hiányzó TCP” eltérést adna. A gyűjtőszabály munkamenete
            # irányonként több engedélyt is tartalmazhat: ilyenkor a
            # snapshot "grants" listája adja a pontos bontást.
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
                mismatch.append(f"hiányzó {label} {port}")
            for port in sorted(actual - expected):
                mismatch.append(f"váratlan {label} {port}")
        if expected_full and not actual_full:
            mismatch.append("hiányzó teljes hozzáférés")
        if actual_full and not expected_full:
            mismatch.append("váratlan teljes hozzáférés")
        if expected_icmp and not actual_icmp:
            mismatch.append("hiányzó ICMP")
        if actual_icmp and not expected_icmp:
            mismatch.append("váratlan ICMP")

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
            # A host (input) portokat „Host” előtaggal jelöljük, hogy a
            # forward és a host engedély azonos portszám mellett is
            # megkülönböztethető legyen.
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

# A base32 ábécé a helyreállítási kódokhoz (nincs 0/1/8/9, hogy ne
# lehessen összetéveszteni őket betűkkel).
_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_RECOVERY_CODE_LENGTH = 10


def generate_totp_secret() -> str:
    """20 bájtos, padding nélküli base32 TOTP-titok (32 nagybetű)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_key(secret: str) -> bytes:
    """A base32 titokból képzett HMAC-kulcs; hibás titoknál ValueError."""
    if not isinstance(secret, str):
        raise ValueError("érvénytelen TOTP-titok")
    raw = secret.strip().replace(" ", "").upper()
    if not raw:
        raise ValueError("üres TOTP-titok")
    padding = "=" * ((8 - len(raw) % 8) % 8)
    try:
        key = base64.b32decode(raw + padding, casefold=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("érvénytelen TOTP-titok") from exc
    if not key:
        raise ValueError("üres TOTP-titok")
    return key


def hotp_code(secret: str, counter: int) -> str:
    """RFC 4226 HOTP-kód (HMAC-SHA1, 6 számjegy, nullával kipótolva)."""
    key = _totp_key(secret)
    try:
        counter = int(counter)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("érvénytelen számláló") from exc
    if counter < 0:
        raise ValueError("érvénytelen számláló")
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{value % (10 ** TOTP_DIGITS):0{TOTP_DIGITS}d}"


def totp_code(secret: str, now: float | None = None) -> str:
    """Az aktuális (vagy megadott időponthoz tartozó) TOTP-kód."""
    current = time.time() if now is None else float(now)
    return hotp_code(secret, int(current // TOTP_PERIOD))


def totp_match(secret: str, code: str, now: float | None = None) -> int | None:
    """A kódhoz tartozó számláló, ha érvényes; különben ``None``.

    Pontosan 6 ASCII számjegyet fogad el, és a ``TOTP_WINDOW`` szerinti
    szomszédos lépéseket is ellenőrzi (óra-eltérés miatt). A visszatérési
    érték a ténylegesen egyező számláló, amit a hívó a visszajátszás
    kiszűrésére használhat.
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
    """Authentikátor-alkalmazásnak átadható ``otpauth://`` URI.

    Az ``issuer`` a címkében és a query paraméterben is megjelenik; üresen
    a beépített :data:`TOTP_ISSUER` értékre esik vissza.
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
    """A helyreállítási kód egységes alakja: nagybetű, szóköz/kötőjel nélkül."""
    if not isinstance(code, str):
        return ""
    return code.upper().replace(" ", "").replace("\t", "").replace("-", "")


def hash_recovery_code(code: str) -> str:
    """A helyreállítási kód SHA-256 hash-e (kisbetűs hex)."""
    normalized = normalize_recovery_code(code)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def generate_recovery_codes(count: int = 10) -> list[str]:
    """Egyszer használatos, egyedi helyreállítási kódok listája."""
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


# --------------------------------------------------------------- felhasználók

class UserStoreError(RuntimeError):
    """A felhasználói adatbázis hibás vagy nem írható."""


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
        """Van-e beállított TOTP-titok (a kötelező jelzőtől függetlenül)."""
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
    """users.json: jelszó-hashek PBKDF2-HMAC-SHA256-tal, atomikus írással."""

    MIN_PASSWORD = 8
    MAX_PASSWORD = 1024

    def __init__(self, path: str = USERS_PATH, iterations: int = PBKDF2_ITERATIONS) -> None:
        self.path = os.path.abspath(path)
        self.iterations = max(10_000, int(iterations))
        self._lock = threading.Lock()
        self._cache: dict[str, UserRecord] | None = None
        self._cache_key: tuple[int, int, int] | None = None
        # Ismeretlen felhasználónál is ugyanannyi munkát végzünk.
        self._dummy_salt = b"\x00" * 16
        self._dummy_digest = hashlib.pbkdf2_hmac(
            "sha256", b"hatarvedelem-dummy", self._dummy_salt, self.iterations
        )

    # -- olvasás ---------------------------------------------------------------

    def _read_raw(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise UserStoreError(f"a felhasználói adatbázis nem olvasható: {exc}") from exc
        if not isinstance(data, dict):
            raise UserStoreError("a felhasználói adatbázis formátuma hibás")
        return data

    def _load(self) -> dict[str, UserRecord]:
        try:
            stat = os.stat(self.path)
            # Az inode is kell: egy atomikus os.replace ugyanazzal a
            # mérettel és mtime-mal új fájlt hoz létre, amit a régi
            # kulcs nem vett észre.
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
                # Hiányzó kulcs = örökölt, nem kötelező beállítás. Bármilyen
                # hibás érték viszont kötelezővé tesz (fail closed), hogy egy
                # elrontott fájl ne kapcsolhassa ki észrevétlenül a 2FA-t.
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
                # Hiányzó kulcs = nem függő fiók. Bármilyen hibás érték
                # viszont függőnek számít (fail closed), akárcsak a
                # totp_required esetében.
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
                log(f"[felhasználók] kihagyott hibás bejegyzés: {name!r}")
        with self._lock:
            self._cache = records
            self._cache_key = key
        return records

    def verify(self, name: str, password: str) -> bool:
        try:
            record = self._load().get(name)
        except UserStoreError as exc:
            log(f"[felhasználók] {exc}")
            return False
        # A függő fiók is bizonyíthassa a jelszavát, hogy a HTTP-réteg
        # megkülönböztetett választ adhasson neki.
        if record is None or (not record.enabled and not record.pending):
            digest = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), self._dummy_salt, self.iterations
            )
            hmac.compare_digest(digest, self._dummy_digest)
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), record.salt, record.iterations
        )
        return hmac.compare_digest(digest, record.digest)

    def names(self) -> list[str]:
        return sorted(self._load().keys())

    def record(self, name: str) -> UserRecord | None:
        return self._load().get(name)

    def provisioned_from(self, name: str) -> str:
        """A Compose-ból származó jelszó determinisztikus jelölője."""
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
        """A jóváhagyásra váró fiókok névsor szerint."""
        return sorted(
            (rec for rec in self._load().values() if rec.pending),
            key=lambda rec: rec.name,
        )

    # -- írás ------------------------------------------------------------------

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
            # A CLI rootként is futtatható: őrizzük meg a fájl tulajdonosát,
            # különben a szolgáltatás a következő belépésnél nem tudná olvasni.
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
                "a felhasználónév 1–32 karakter lehet: betű, szám, pont, kötőjel, aláhúzás"
            )
        if not isinstance(password, str) or not (
            self.MIN_PASSWORD <= len(password) <= self.MAX_PASSWORD
        ):
            raise UserStoreError(
                f"a jelszó {self.MIN_PASSWORD}–{self.MAX_PASSWORD} karakter legyen"
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
            # A függő fiók jóváhagyásig nem aktív, és nem kap szabályokat;
            # a hívó által esetleg átadott értékektől függetlenül.
            role = ROLE_USER
            enabled = False
            rules = ()
            must_change_password = False
            if not normalized_email:
                raise UserStoreError(
                    "a függő fiókhoz e-mail-cím kötelező"
                )
        if role not in (ROLE_USER, ROLE_ADMIN):
            raise UserStoreError("érvénytelen szerepkör")
        with self._locked():
            data = self._read_raw()
            if name in data:
                raise UserStoreError(f"már létezik ilyen felhasználó: {name}")
            data[name] = self._new_record(
                name, password, role=role, enabled=enabled, rules=rules,
                must_change_password=must_change_password,
                pending=pending, email=normalized_email,
            )
            self._write_raw(data)

    def approve_user(self, name: str) -> bool:
        """Függő fiók aktiválása.

        A jelszó-hash, a szabályok, az e-mail, a szerepkör és a létrehozási
        idő változatlan marad; szabályt ez a metódus nem rendel. Ismeretlen
        felhasználónál ``False``.
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
        """Függő fiók elutasítása: a bejegyzés törlése.

        Ismeretlen felhasználónál ``False``.
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
                raise UserStoreError(f"nincs ilyen felhasználó: {name}")
            salt = secrets.token_bytes(16)
            digest = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, self.iterations
            )
            # Helyben frissítünk, hogy a jelszótól független mezők
            # (szerepkör, csoportok, provisioning-jelölő) megmaradjanak.
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
        """Egy korábban kiolvasott jelszó-állapot visszaállítása.

        Kizárólag arra szolgál, hogy egy több lépéses admin-módosítás
        közbeni hiba után a jelszó-hash és a ``must_change_password`` jelző
        pontosan az eredeti értékre térjen vissza. Új jelszót a
        :meth:`set_password` állít be; ez a metódus nem fogad el nyílt
        jelszót, ezért a naplóba sem kerülhet titok.
        """
        with self._locked():
            data = self._read_raw()
            item = data.get(name)
            if not isinstance(item, dict):
                raise UserStoreError(f"nincs ilyen felhasználó: {name}")
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
            raise UserStoreError("érvénytelen szerepkör")
        with self._locked():
            data = self._read_raw()
            if name not in data:
                raise UserStoreError(f"nincs ilyen felhasználó: {name}")
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
                # Csak a jelzőt írjuk: a titokhoz és a helyreállítási
                # kódokhoz kizárólag a dedikált metódusok nyúlnak.
                item["totp_required"] = bool(totp_required)
            if rules is not None:
                clean: list[str] = []
                for value in rules:
                    if not isinstance(value, str) or not value.strip():
                        raise UserStoreError("érvénytelen szabály-azonosító")
                    value = value.strip()
                    if value not in clean:
                        clean.append(value)
                item["rules"] = clean
            data[name] = item
            self._write_raw(data)

    # -- kétfaktoros azonosítás ------------------------------------------------

    def set_totp_required(self, name: str, required: bool) -> bool:
        """A kétfaktoros belépés kötelezővé tétele vagy feloldása.

        A titkot, a számlálót és a helyreállítási kódokat nem érinti.
        Ismeretlen felhasználónál ``False``, egyébként ``True``.
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
        """TOTP-titok és helyreállítási kód-hashek rögzítése.

        A korábbi ``totp_required`` jelzőt megtartja. Érvényes, nem negatív
        egész ``last_step`` esetén a belépéskor már elfogadott időlépést
        rögzíti, így a beiratkozást megerősítő kód később nem játszható
        vissza; egyébként a számláló -1 lesz. A helyreállítási hasheket
        kanonikus (kisbetűs, 64 hex) alakban tároljuk; a nem megfelelő
        elemek kimaradnak. Ismeretlen felhasználónál ``False``.
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
        """TOTP-kód ellenőrzése visszajátszás elleni védelemmel.

        Az olvasás, az ellenőrzés és az írás egyetlen zárolt szakaszban fut,
        így két párhuzamos kérés közül legfeljebb az egyik fogadhatja el
        ugyanazt az időlépést. A meglévőnél nem nagyobb lépés érvénytelen.
        A ``totp_required`` jelzőt ez a metódus nem vizsgálja; azt a hívó
        (a HTTP-réteg) kényszeríti ki.
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
            log(f"[felhasználók] {exc}")
            return False

    def verify_recovery(self, name: str, code: str) -> bool:
        """Helyreállítási kód ellenőrzése és egyszer használatos törlése.

        A kódot normalizáljuk, hash-eljük, majd állandó idejű összehasonlítással
        keressük a tárolt hashek között. Sikertelen kísérlet nem fogyasztja
        a kódot. Ismeretlen vagy kikapcsolt felhasználónál ``False``.
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
                # Végigmegyünk az összes elemen, hogy a futásidő ne árulja
                # el, hányadik hash egyezett (a törlés a végén történik).
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
            log(f"[felhasználók] {exc}")
            return False

    def reset_totp(self, name: str) -> bool:
        """A TOTP-titok, a számláló és a helyreállítási kódok törlése.

        A ``totp_required`` jelzőt szándékosan megtartja: az admin döntése
        arról, hogy a belépéshez kétfaktoros azonosítás kell, nem változik.
        Ismeretlen felhasználónál ``False``.
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
        """A szabály közvetlen felhasználói kiosztásainak beállítása.

        Minden users.json-beli felhasználónál pontosan akkor szerepel a
        szabály, ha a kért halmazban van. A többi szabály, a csoporttagság
        és a többi mező változatlan. Egyetlen atomikus fájlírással dolgozik
        (0600), és (hozzáadott, eltávolított) felhasználóneveket ad vissza.
        """
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise UserStoreError("hiányzó szabály-azonosító")
        rule_id = rule_id.strip()
        if rule_id == LEGACY_ADMIN_RULE_ID:
            raise UserStoreError(
                "a fenntartott szabály-azonosító nem rendelhető hozzá"
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
                    f"ismeretlen felhasználó: {', '.join(sorted(missing))}"
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

    # -- konfigurációs csomag --------------------------------------------------

    @staticmethod
    def _clean_import_records(raw) -> dict:
        """A users szakasz szigorú, írás nélküli ellenőrzése."""
        if not isinstance(raw, dict):
            raise UserStoreError("a users szakasz JSON-objektum kell")
        clean: dict[str, dict] = {}
        for name, item in raw.items():
            if not isinstance(name, str) or not USERNAME_RE.match(name):
                raise UserStoreError(f"érvénytelen felhasználónév: {name!r}")
            if not isinstance(item, dict):
                raise UserStoreError(f"{name}: hibás felhasználói bejegyzés")
            try:
                salt = bytes.fromhex(str(item["salt"]))
                digest = bytes.fromhex(str(item["hash"]))
                iterations = int(item.get("iterations", PBKDF2_ITERATIONS))
                created = int(item.get("created", 0) or 0)
            except (KeyError, TypeError, ValueError) as exc:
                raise UserStoreError(f"{name}: hibás jelszó-adat") from exc
            # 5 millió feletti iteráció már szolgáltatásmegtagadás lenne.
            if len(salt) != 16 or len(digest) != 32 or not 1 <= iterations <= 5_000_000:
                raise UserStoreError(f"{name}: hibás jelszó-adat")
            if created < 0:
                raise UserStoreError(f"{name}: hibás létrehozási idő")
            role = item.get("role", ROLE_USER)
            if role not in (ROLE_USER, ROLE_ADMIN):
                raise UserStoreError(f"{name}: érvénytelen szerepkör")
            flags = {}
            for key in ("enabled", "must_change_password", "pending"):
                value = item.get(key, False)
                if not isinstance(value, bool):
                    raise UserStoreError(f"{name}: a(z) {key} mező igaz/hamis kell")
                flags[key] = value
            if "totp_required" in item:
                if not isinstance(item["totp_required"], bool):
                    raise UserStoreError(
                        f"{name}: a totp_required mező igaz/hamis kell"
                    )
            secret = item.get("totp_secret", "")
            if not isinstance(secret, str):
                raise UserStoreError(f"{name}: hibás TOTP-titok")
            if secret:
                try:
                    _totp_key(secret)
                except ValueError as exc:
                    raise UserStoreError(f"{name}: hibás TOTP-titok") from exc
            try:
                last_step = int(item.get("totp_last_step", -1))
            except (TypeError, ValueError, OverflowError) as exc:
                raise UserStoreError(f"{name}: hibás TOTP-lépés") from exc
            if last_step < -1:
                raise UserStoreError(f"{name}: hibás TOTP-lépés")
            recovery_raw = item.get("totp_recovery", [])
            if not isinstance(recovery_raw, list) or any(
                not isinstance(value, str) or not _TOTP_RECOVERY_RE.match(value)
                for value in recovery_raw
            ):
                raise UserStoreError(f"{name}: hibás helyreállítási kód")
            email_raw = item.get("email", "")
            email = normalize_email(email_raw, strict=False)
            if email_raw and not email:
                raise UserStoreError(f"{name}: érvénytelen e-mail-cím")
            if flags["pending"] and (
                role != ROLE_USER or flags["enabled"] or flags["must_change_password"]
            ):
                raise UserStoreError(
                    f"{name}: a függő fiók nem lehet aktív admin"
                )
            rules = item.get("rules")
            if rules is not None:
                if not isinstance(rules, list):
                    raise UserStoreError(f"{name}: a rules mező lista kell")
                try:
                    rules = list(_clean_str_list(
                        rules, f"{name}.rules", _SERVICE_ID_RE, maximum=64
                    ))
                except ValueError as exc:
                    raise UserStoreError(f"{name}: {exc}") from exc
                if LEGACY_ADMIN_RULE_ID in rules:
                    raise UserStoreError(
                        f"{name}: a fenntartott szabály-azonosító nem importálható"
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
                    raise UserStoreError(f"{name}: hibás provisioning-jelölő")
                record["provisioned_from"] = provisioned
            clean[name] = record
        return clean

    def export_records(self) -> dict:
        """Az aktuális felhasználói rekordok a konfigurációs csomaghoz."""
        return self._clean_import_records(self._read_raw())

    def validate_import_records(self, raw) -> dict:
        return self._clean_import_records(raw)

    def replace_all(self, raw) -> None:
        """A teljes felhasználói nyilvántartás cseréje."""
        clean = self._clean_import_records(raw)
        with self._locked():
            self._write_raw(clean)
        with self._lock:
            self._cache = None
            self._cache_key = None

    def reset(self) -> None:
        """A fájl törlése és a memóriabeli állapot ürítése (factory reset)."""
        with self._lock, self._locked():
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self._cache = None
            self._cache_key = None


_PROVISION_SALT = b"hatarvedelem-provision-v1"


def provision_marker(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Jelölő, amivel felismerjük, hogy a .env-ből származó jelszó változatlan.

    Így a felületen át történt jelszócsere nem „áll vissza” a következő
    konténer-indításnál, viszont a .env-ben megadott új jelszó érvényesül.
    """
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), _PROVISION_SALT,
        max(10_000, int(iterations)),
    )
    return digest.hex()


def provision_admin(store: UserStore) -> str:
    """A Compose-ból beállított admin fiók létrehozása vagy frissítése.

    Visszatérési érték: ``disabled``, ``created``, ``updated`` vagy
    ``unchanged``. Kikapcsolt állapotban szándékosan nem töröl felhasználót:
    a korábban létrehozott fiók megmarad, és a CLI-vel kezelhető tovább.
    """
    if not ADMIN_ENABLED:
        return "disabled"
    if not ADMIN_USER or not ADMIN_PASSWORD:
        raise UserStoreError(
            "a HV_ADMIN_ENABLED be van kapcsolva, de a HV_ADMIN_USER és a "
            "HV_ADMIN_PASSWORD közül valamelyik hiányzik"
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
        # Régi (jelölő nélküli) bejegyzés. Ha még a seed-jelszó van érvényben,
        # azt első belépéskor kötelező lecserélni; ha nem, akkor a .env-ben
        # megadott jelszó az irányadó.
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
    if stored_marker != marker:
        # A .env-ben megváltozott a jelszó: az az irányadó, és első
        # belépéskor ezt is le kell cserélni.
        store.set_password(ADMIN_USER, ADMIN_PASSWORD, must_change_password=True)
        store.set_metadata(ADMIN_USER, role=ROLE_ADMIN, enabled=True,
                           provisioned_from=marker)
        return "updated"
    return "updated" if changed else "unchanged"


# ---------------------------------------------------------------- munkamenetek

# A munkamenet lezárásának okai és a felhasználónak mutatott magyarázat.
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
    # A visszavonáskor a megfelelő (forward vagy input) halmazokból kell
    # törölni, ezért a munkamenet megőrzi az engedély irányát. Gyűjtőszabály
    # esetén ez "mixed" is lehet: a tényleges, irányonkénti bontást a
    # grant_parts tartalmazza, a direction csak megjelenítési/audit érték.
    direction: str = "forward"
    # Az engedélyezéskor kiadott Ports-részek irányonként. Üres esetén a
    # régi viselkedés érvényes: egyetlen engedély a ports mezőkből.
    grant_parts: tuple[Ports, ...] = ()
    # A kiválasztott szabályok azonosítói, illetve a teljes választás. A
    # ``rule``/``rule_label`` az első választás kompatibilitási nézete.
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
        """A visszavonáshoz szükséges, irányonkénti engedélyek."""
        return self.grant_parts or (self.ports,)

    def selections(self) -> tuple[RuleSelection, ...]:
        """A munkamenet választásai; a régi, egy-szabályos alak is támogatott."""
        if self.rule_parts:
            return self.rule_parts
        if self.rule:
            return (
                RuleSelection(self.rule, self.rule_label, self.grants),
            )
        return ()

    @property
    def ports(self) -> Ports:
        # A "mixed" csak megjelenítési érték; a Ports mindig egyetlen
        # irányt ismer. Az uniót a megjelenítéshez forwardként adjuk át.
        direction = "input" if self.direction == "input" else "forward"
        return Ports(
            self.tcp, self.udp, self.icmp, self.full, direction
        )

    def snapshot(self) -> dict:
        """Adminlistához: nyers adatok, a felület számol vele."""
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
    """Egy sikertelen tűzfal-visszavonás a korlátozott újrapróbálkozó sorban."""

    ip: str
    grants: tuple[Ports, ...]
    discover: bool
    attempts: int = 0
    next_at: float = 0.0
    first_failed: float = 0.0
    last_error: str = ""
    in_flight: bool = False


class SessionManager:
    """IP-hez kötött, memóriabeli munkamenetek + tűzfalengedély.

    A belépés két lépcsős: a jelszó ellenőrzése után a munkamenet még nem
    ad hálózati hozzáférést. A kliens ezután szabályt és időtartamot választ;
    a forward-lánc csak ekkor nyílik meg, a szabály portjaira. A host SSH
    (TCP 22) is csak akkor nyílik meg, ha a választott, felhasználóhoz
    rendelt host (input) szabály kifejezetten tartalmazza a TCP 22-t; a
    teljes hozzáférésű és a gyűjtőszabályok ezt nem adják meg külön.

    A munkamenet lejárta és az nftables-elemek timeoutja ugyanaz az érték.
    Ha a folyamat leáll, a kernel a timeoutnál magától törli az engedélyt.

    A tűzfal-visszavonás hiba esetén nem vész el: egy korlátozott méretű,
    szálbiztos sorba kerül, és a takarítószál növekvő várakozással próbálja
    újra. A munkamenet ilyenkor is azonnal megszűnik; a sor csak a kernelben
    maradt engedélyt takarítja.
    """

    # Első hiba után 5 mp, majd 15, 60, 300, végül legfeljebb 600 mp.
    PENDING_BACKOFF = (5, 15, 60, 300, 600)
    # A sor mérete korlátozott; beteltekor hangos napló/audit mellett sem
    # nőhet tovább (a hiba továbbra is hiba marad, nem jelentünk sikert).
    PENDING_LIMIT = 4096
    # Az első hibát mindig naplózzuk; az újrapróbálkozások közül csak minden
    # tizediket, hogy egy tartós nft-hiba ne árassza el a naplót 5 mp-enként.
    PENDING_AUDIT_EVERY = 10

    def __init__(
        self,
        firewall: Firewall,
        ttl: int = SESSION_TTL,
        pending_ttl: int = AUTH_TTL,
        audit: AuditLog | None = None,
        rule_check=None,
        guard_check=None,
    ) -> None:
        self.firewall = firewall
        self.ttl = max(MIN_TTL, min(int(ttl), MAX_TTL))
        self.pending_ttl = max(1, int(pending_ttl))
        self.audit = audit
        # Visszahívás: a szabály a döntés pillanatában is a felhasználóé-e.
        # Ezzel zárjuk be azt a versenyhelyzetet, amikor az admin a szabály
        # törlése után, de a grant előtt érkező kérést engedélyezne.
        self.rule_check = rule_check
        # Visszahívás: a host (input) portőr-halmaz egészséges-e. Ha a
        # hívó megadja, input irányú engedély csak akkor adható, ha ez
        # igazat ad. A None (alapértelmezés) a korábbi viselkedést tartja
        # meg azoknak a hívóknak, amelyek nem használnak portőrt.
        self.guard_check = guard_check
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        # IP -> (időbélyeg, ok): a legutóbb lezárult munkamenet magyarázata.
        self._last_end: dict[str, tuple[float, str]] = {}
        # (IP, pontos grant-tuple) -> függő visszavonás. Külön zár: a
        # _revoke_access() a munkamenet-zár alatt is hívható (authorize).
        self._pending_lock = threading.Lock()
        self._pending_revocations: dict[
            tuple[str, tuple[Ports, ...]], _PendingRevocation
        ] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- belső -----------------------------------------------------------------

    def _remember_end_locked(self, ip: str, reason: str, now: float | None = None) -> None:
        self._last_end[ip] = (time.time() if now is None else now, reason)
        # Ne hízzon korlátlanul: a legrégebbi bejegyzéseket eldobjuk.
        if len(self._last_end) > 2048:
            cutoff = time.time() - 86400
            for key, (when, _) in list(self._last_end.items()):
                if when < cutoff:
                    del self._last_end[key]

    def _write_audit(self, event: str, **fields) -> None:
        """Nem kötelező naplóírás: hiba esetén sem akaszthatja meg a műveletet."""
        if self.audit is None:
            return
        try:
            self.audit.write(event, **fields)
        except Exception as exc:  # a naplózás soha ne blokkoljon
            log(f"[napló] {event} írása nem sikerült: {exc}")

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
        """A legutóbb lezárult munkamenet oka az adott IP-hez (ha van)."""
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
        """Az összes élő munkamenet pillanatképe (admin felülethez)."""
        now = time.time()
        with self._lock:
            current = [
                session for session in self._sessions.values()
                if session.expires > now
            ]
        current.sort(key=lambda item: (not item.authorized, item.logged_in or item.created))
        return [session.snapshot() for session in current]

    def allows_domain(self, ip: str, name: str) -> bool:
        """Engedi-e az IP élő munkamenete a proxy-bejegyzést (proxy-kapu).

        Csak kifejezetten választott domain szabály számít: a teljes
        hozzáférés és az admin szerepkör sem nyit domaint.
        """
        return self.domain_user(ip, name) is not None

    def domain_user(self, ip: str, name: str) -> str | None:
        """Az allows_domain() munkamenetének felhasználója (vagy None)."""
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
        """A visszavonás pontos azonosítója; az ismétlődések kimaradnak."""
        return tuple(dict.fromkeys(grants or ()))

    def pending_count(self) -> int:
        """A függő (még sikertelen) visszavonások száma."""
        with self._pending_lock:
            return len(self._pending_revocations)

    def _pending_delay(self, attempts: int) -> int:
        """Következő újrapróbálkozás késleltetése másodpercben."""
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
        """Egy sikertelen visszavonás felvétele a sorból.

        Visszatérés: (bejegyzés, új-e, tele-van-e). Meglévő (IP, grant)
        kulcsnál csak frissítjük az utolsó hibát és a discovery igényt; így
        egy ismételt hívás nem növeli a sort és nem naplóz újra.
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
            # Fail-closed: a visszavonás nem sikerült, és a sor is tele van.
            # Nem állítjuk, hogy sikerült; hangosan naplózunk és auditálunk.
            log(
                f"[tűzfal] HIBA: a függő visszavonások sora tele van "
                f"({self.PENDING_LIMIT}); a(z) {ip} engedélye a kernel TTL-ig "
                "érvényben maradhat"
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
        """Sikeres visszavonás után a lefedett függő bejegyzés törlése.

        Ha a függő bejegyzés forward-felderítést is kért, egy grant-alapú
        (nem felderítő) sikeres törlés nem feltétlenül fedi le az összes
        árva elemet; ilyenkor a bejegyzés marad, és később a teljes
        felderítéssel tisztul.
        """
        with self._pending_lock:
            entry = self._pending_revocations.get((ip, grants))
            if entry is not None and (discover or not entry.discover):
                del self._pending_revocations[(ip, grants)]

    def _revoke_exact(self, ip: str, grants) -> None:
        """Pontos elemszintű törlés, a régi tűzfal-hamisítók kompatibilitásával.

        A valódi :class:`Firewall` ``revoke_exact`` metódusát használjuk,
        amely a ``full`` és ICMP elemeket is törli. A régi tesztek egyszerű
        hamis tűzfalai csak ``revoke_all``-t ismernek; náluk az
        ``only_grants=True`` a legközelebbi kompatibilis művelet.
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
        """Hozzáférés visszavonása; hiba esetén a sorból újrapróbáljuk.

        A visszatérési érték a tűzfal-művelet sikerét jelzi. A munkamenet
        eltávolítása a hívók dolga és hiba esetén is megtörténik; így nem
        marad munkamenet olyan engedélyre hivatkozva, amelyet egy későbbi
        újrapróbálkozás eltávolíthat. A conntrack-törlést hiba esetén is
        elvégezzük, mert a meglévő kapcsolatokat azonnal meg kell szakítani.

        ``only_grants=True`` esetén kizárólag a megadott grant-elemeket
        töröljük (lásd :meth:`Firewall.revoke_all`), és conntrack-ürítést
        sem siker, sem hiba esetén nem végzünk. Ilyenkor ugyanis az IP-hez
        aktív munkamenet tartozik, amely osztozhat a conntrack-bejegyzéseken;
        az ürítés az ő élő kapcsolatait is megszakítaná.

        ``exact=True`` esetén :meth:`Firewall.revoke_exact` fut, amely a
        ``full`` és ICMP elemeket is pontosan a megadott grantok szerint
        törli. Conntrack-ürítés ilyenkor sem siker, sem hiba esetén nem
        történik: a hívó dönti el, milyen (részleges) kapcsolattisztítás
        szükséges. A hibakezelés és a függő sorba állítás azonos a többi
        úttal.
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
            log(f"[tűzfal] a(z) {ip} visszavonása nem sikerült: {exc}")
            _entry, is_new, _overflow = self._queue_pending(
                ip, grants, discover, exc
            )
            if is_new:
                # Az első hibát azonnal auditáljuk; az újrapróbálkozások
                # közül csak minden PENDING_AUDIT_EVERY. ediket.
                self._write_audit(
                    "firewall_error",
                    ip=ip,
                    operation="revoke_all",
                    reason=str(exc),
                    pending=True,
                    attempts=0,
                )
            # only_grants/exact esetén szándékosan NINCS conntrack-ürítés:
            # az IP-hez tartozó aktív munkamenet kapcsolatai is
            # megszakadnának. A függő bejegyzés csak a pontos, nem átfedő
            # grantokat tartalmazza, így az újrapróbálkozás sem nyúl az
            # aktív munkamenethez.
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
        """A visszavonandó grantok mínusz az aktív munkamenetek grantjai.

        A ``covered`` az ugyanahhoz az IP-hez tartozó aktív, engedélyezett
        munkamenetek grantjainak uniója. Csak azok az elemek maradnak a
        maradékban, amelyeket egyetlen aktív munkamenet sem igényel. A
        számítás kernel-elem szintű: a ``full`` engedély az ``allowed_v4``
        egyetlen elemét használja, a portos engedélyek pedig az
        ``allowed_tcp``/``allowed_udp`` elemeit. Ezért egy régi ``full``
        grant csak akkor marad meg, ha egy aktív munkamenet szintén teljes
        hozzáférésű ugyanabban az irányban; ha az aktív munkamenet csak
        portokat engedélyez, a régi ``allowed_v4`` elem törölhető anélkül,
        hogy az aktív munkamenet hozzáférését érintenénk.

        Az aktív ``full`` engedély az adott irányban lefedi a portos és
        ICMP-hozzáférést, de nem pótolja a kernel-elemek előzményét: a
        távozó nem ``full`` részhez tartozó ``allowed_tcp``/``allowed_udp``/
        ``allowed_icmp`` elem továbbra is létezik, miközben a munkamenet
        összevont ``grant_parts``-ában már nem szerepel. Ezért az ilyen
        részt a maradékban meg kell tartani, hogy a pontos törlés
        (``revoke_exact``) eltávolítsa; különben később, a teljes
        hozzáférés visszavonásakor újra előbukkanhat. Csak a távozó
        ``full`` rész hagyható ki, ha ugyanabban az irányban aktív
        ``full`` fedi.
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
                # Az aktív teljes hozzáférés ugyanabban az irányban a
                # távozó teljes hozzáférés kernel-elemét (allowed_v4) fedi,
                # ezért azt nem kell külön törölni. A nem teljes részeket
                # viszont a fenti docstring szerint meg kell tartani.
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
        """Hozzáférés visszavonása a munkamenet-zár tartása mellett.

        A hívónak a ``self._lock`` zárat kell tartania. A tűzfal-mutáció
        ugyanazon zár alatt fut, mint a munkamenet eltávolítása, ezért egy
        párhuzamos ``authorize()`` nem tud az eltávolítás és a visszavonás
        közé ékelődni, és nem veszítheti el az új engedélyét.

        Ha az IP-hez a visszavonás után is tartozik aktív, engedélyezett
        munkamenet, csak a régi grantok azon részeit töröljük, amelyeket az
        aktív munkamenet nem igényel (``_subtract_grants``). Ilyen részleges
        törlésnél a conntrack-ot nem ürítjük, mert az az aktív munkamenet
        élő kapcsolatait is megszakítaná. Ha a maradó munkamenet minden
        elemet lefed, a tűzfalhoz egyáltalán nem megy hívás.

        Zárolási invariáns: ``self._lock`` -> tűzfal -> ``_pending_lock``
        (levélzár); a fordított sorrend tilos.
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
                # A maradó munkamenet minden érintett elemet igényel; nincs
                # mit törölni, és a conntrack-hoz sem szabad nyúlni.
                return True
            # Pontos elemszintű törlés: a teljes (allowed_v4) és ICMP
            # elemek is eltűnnek, ha a távozó grant tartalmazta őket,
            # miközben a maradó portos engedélyek érintetlenek maradnak.
            return self._revoke_access(ip, remainder, exact=True)
        return self._revoke_access(ip, grants)

    def _remove_selections_locked(
        self, sessions, rule_ids, reason: str, now: float
    ) -> int:
        """A megadott szabályválasztások eltávolítása a munkamenetekből.

        A hívónak a ``self._lock`` zárat kell tartania. Egy munkamenetből
        csak a ``rule_ids`` közé tartozó választások tűnnek el; a többi
        választás grantjei érvényben maradnak. Ha nem marad választás, a
        munkamenet teljesen megszűnik. Részleges eltávolításnál a távozó
        választás által hozott, más választással nem fedett elemeket
        ``revoke_exact`` törli, majd a conntrackból is csak a távozó
        portokhoz tartozó bejegyzések tűnnek el.

        Tűzfalhiba esetén fail-closed: a munkamenet megszűnik, és a teljes
        régi unió visszavonása (szükség esetén a függő sorba állítva)
        megtörténik. Minden érintett (részben vagy teljesen eltávolított)
        munkamenet számít a visszatérési értékben.

        A lejárt munkamenetet nem frissítjük részlegesen: a maradó
        választások grantjeinek újrakiadása egy másodpercre visszaadná a
        lejárt hozzáférést. Helyette a teljes eltávolítás útjára kerül.

        ``sessions`` elemei ``(token, session)`` párok vagy ``Session``
        objektumok lehetnek.
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
                # A lejárt munkamenet nem kaphat vissza semmit: a részleges
                # frissítés a maradó választások grantjeit újra kiadná,
                # vagyis a lejárt hozzáférés egy másodpercig még élne.
                # Helyette teljes eltávolítás, mint a ``kept`` üres esetben.
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
            # A dataclass szándékosan módosítható: a lejárat változatlan,
            # csak a választások és a belőlük származtatott mezők frissülnek.
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
                # Ha a távozó választás egy teljes hozzáférést adott, a
                # maradó portok eddig nem feltétlenül voltak külön
                # kernel-elemek (az allowed_v4 fedte őket). A távozó
                # allowed_v4 törlése után ezért a maradó uniót újra ki kell
                # adni, különben a munkamenet a papíron élne, de a portjai
                # nem lennének engedélyezve.
                self.firewall.grant_all(
                    session.ip, new_union, remaining_ttl
                )
            except FirewallError as exc:
                log(
                    f"[tűzfal] a(z) {session.ip} kiválasztás "
                    f"visszavonása nem sikerült: {exc}"
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
        """A lejárt visszavonások újrapróbálása; a sikereseket törli.

        A tűzfal-hívást a munkamenet-zár alatt végezzük, hogy egy
        párhuzamos authorize() ne adhasson új engedélyt ugyanarra az IP-re
        a visszavonás közben.

        Ha az IP-hez aktív, engedélyezett munkamenet tartozik, nem
        halasztjuk el a teljes bejegyzést: kiszámítjuk az aktív
        munkamenetek grantjainak unióját, és csak a régi grantok azon
        elemeit töröljük, amelyeket az új munkamenet nem igényel
        (``_subtract_grants``). Az átfedő elemek az új munkamenet
        életciklusához tartoznak, azokat annak visszavonása törli. Ha a
        maradék üres, a bejegyzés törlődik. Ilyen részleges törlésnél a
        conntrack-ot nem ürítjük, mert az az új munkamenet élő
        kapcsolatait is megszakítaná.

        A ``discover=True`` bejegyzés (a ``revoke_ip``/fail2ban út) csak
        akkor futtat teljes felderítést, ha nincs aktív munkamenet az
        IP-hez. Aktív munkamenet mellett a felderítés az ő elemeit is
        törölné, ezért csak a nem átfedő pontos grantokat töröljük, és a
        bejegyzés ``discover=True`` jelöléssel a sorban marad. Amikor a
        munkamenet megszűnik, a felderítés újra lefut, és az árva elemeket
        is eltakarítja.
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
            # Zárolási invariáns: a grant-unió kiszámítása, a
            # firewall.revoke_all() mutáció ÉS a conntrack_flush() is a
            # munkamenet-zár alatt fut. Így egy párhuzamos authorize() nem
            # tud a döntés és a törlés közé ékelődni: nem kaphat olyan
            # grantot, amelyet a részleges törlés vagy a discovery azonnal
            # eltávolítana. A conntrack-ürítés szándékosan a zár alatt
            # marad, hogy a mutáció után engedélyező új munkamenet
            # kapcsolatait ne szakítsuk meg. A _pending_lock levélzár:
            # soha nem szerezzük meg a _lock után fordított sorrendben.
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
                    # Nincs nem átfedő elem. Nem felderítő bejegyzésnél az
                    # átfedő elemeket az aktív munkamenet életciklusa
                    # törli, ezért a bejegyzés megszűnik. Felderítő
                    # bejegyzésnél a teljes felderítés még hátravan, ezért
                    # az a munkamenet végéig a sorban marad. Ha nincs
                    # aktív munkamenet és a grantlista üres, a hívás alább
                    # lefut: a teljes/ICMP/MAC elemek törlését is újra kell
                    # próbálni.
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
                        # Csak a régi, nem átfedő elemeket töröljük pontos,
                        # elemszintű törléssel. A maradó aktív grantok által
                        # fedett portokhoz és a MAC-kötéshez nem nyúlunk;
                        # a távozó full/ICMP elem viszont így nem marad a
                        # kernelben.
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
                                # A pontos grantok törölve; a teljes
                                # felderítés a munkamenet végére vár.
                                entry.in_flight = False
                                entry.next_at = now + self._pending_delay(
                                    entry.attempts
                                )
                            else:
                                del self._pending_revocations[key]
                    if not partial:
                        conntrack_flush(entry.ip, self.audit)
                        log(
                            f"[tűzfal] a(z) {entry.ip} függő visszavonása "
                            "végül sikerült"
                        )
        return retried

    # -- nyilvános műveletek ---------------------------------------------------

    def login(
        self, user: str, ip: str, role: str = ROLE_USER, ua: str = ""
    ) -> Session:
        """Jelszó után: még NINCS hálózati hozzáférés, csak választás."""
        ip = normalize_ip(ip)
        if not is_ipv4(ip):
            raise FirewallError("csak IPv4-címről lehet belépni")
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
                # A régi hozzáférést előbb visszavonjuk. Ha ez nem sikerül,
                # a visszavonás a sorból később lefuthat, ezért a régi
                # munkamenet nem maradhat engedélyre hivatkozva: eldobjuk,
                # és az új belépés sem jön létre (fail-closed).
                if not self._revoke_access(ip, previous_grants):
                    self._drop_ip_locked(ip, "revoke_failed")
                    raise FirewallError(
                        "a korábbi hozzáférés visszavonása nem sikerült; "
                        "jelentkezz be újra"
                    )
                revoked_access = True
            # Egy IP-hez egyszerre egy munkamenet tartozzon. A korábbi
            # munkamenet lezárásának okát megjegyezzük a felületnek.
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
        # Minden ugyanerről az IP-ről leváltott munkamenet (a függőben lévő
        # is) külön eseményt kap; az engedély-visszavonás ténye marad az
        # összesített access_revoked esemény.
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
            # A conntrack-törlést a _revoke_access már elvégezte.
            self._write_audit(
                "access_revoked",
                user=user,
                ip=ip,
                reason="új belépés ugyanerről az IP-ről",
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
                # A cookie másik IP-ről érkezett: a munkamenet IP-hez kötött.
                # A munkamenetet és a hozzá tartozó tűzfalengedélyt is
                # megszüntetjük, nem hagyjuk a TTL-ig érvényben.
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
                # A visszavonás ugyanazon zár alatt fut, mint a munkamenet
                # törlése, hogy egy párhuzamos, ugyanerről az IP-ről induló
                # authorize() ne tudjon a kettő közé ékelődni és elveszíteni
                # a frissen kiadott engedélyét.
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
        """A kiválasztott szabály(ok) és időtartam érvényesítése.

        ``rules`` egyetlen :class:`Rule` (a régi hívók kompatibilitása) vagy
        nem üres szabálysorozat lehet. A munkamenet a választott szabályok
        grantjeinek unióját kapja; az azonosítók szerinti ismétlődések
        kimaradnak.
        """
        ip = normalize_ip(ip)
        if not is_ipv4(ip):
            raise AccessError("csak IPv4-címről lehet hozzáférést kérni")
        if isinstance(rules, Rule):
            candidates = [rules]
        elif rules is None or isinstance(rules, (str, bytes)):
            raise AccessError("érvénytelen hozzáférési szabály")
        else:
            try:
                candidates = list(rules)
            except TypeError:
                raise AccessError("érvénytelen hozzáférési szabály")
        if not candidates or not all(
            isinstance(rule, Rule) for rule in candidates
        ):
            raise AccessError("érvénytelen hozzáférési szabály")
        # Deduplikáció az azonosító szerint, az első előfordulás sorrendjében.
        selected: list[Rule] = []
        seen_ids: set[str] = set()
        for rule in candidates:
            if rule.id in seen_ids:
                continue
            seen_ids.add(rule.id)
            selected.append(rule)
        rules = tuple(selected)

        # Minden választott szabálynak adnia kell hozzáférést
        # (fail-closed), és a kért TTL nem haladhatja meg a legszigorúbb
        # szabály max_ttl értékét. V1: egyetlen munkamenet-TTL, a kérést
        # elutasítjuk a csonkítás helyett.
        for rule in rules:
            grants = rule.grants
            if not rule.session_domains and (not grants or all(
                not (part.tcp or part.udp or part.icmp or part.full)
                for part in grants
            )):
                raise AccessError("ez a szabály nem ad hozzáférést")
        ttl = validate_ttl(ttl)
        if len(rules) == 1:
            rule = rules[0]
            if ttl > rule.max_ttl:
                raise AccessError(
                    f"ez a szabály legfeljebb "
                    f"{format_duration(rule.max_ttl)} "
                    "időtartamra engedélyez"
                )
        else:
            strictest = min(rules, key=lambda rule: rule.max_ttl)
            if ttl > strictest.max_ttl:
                raise AccessError(
                    f"a(z) {strictest.label} szabály miatt legfeljebb "
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
        # A megjelenítéshez a munkamenet az engedélyek unióját tárolja; a
        # tényleges, irányonkénti bontás a grant_parts mezőben van.
        tcp = tuple(
            sorted({port for part in new_union for port in part.tcp})
        )
        udp = tuple(
            sorted({port for part in new_union for port in part.udp})
        )
        icmp = any(part.icmp for part in new_union)
        full = any(part.full for part in new_union)
        directions = {part.direction for part in new_union}
        # Csak domain szabály esetén nincs engedély, így irány sem.
        direction = (
            next(iter(directions)) if len(directions) == 1
            else ("mixed" if directions else "forward")
        )
        now = time.time()
        with self._lock:
            session = self._sessions.get(token)
            if session is None or session.ip != ip:
                raise AccessError("érvénytelen vagy lejárt munkamenet")
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
                    # A lejárt munkamenet engedélyét is azonnal vonjuk
                    # vissza, ne várjunk a takarítószálra.
                    self._revoke_access(ip, session.grants)
                raise AccessError("lejárt a munkamenet")

            for rule in rules:
                if self.rule_check is not None and not self.rule_check(
                    session.user, rule
                ):
                    raise AccessError("ez a szabály már nem elérhető")

            # A host (input) portőr-halmaz nélkül egy későbbi visszavonás
            # után az established kapcsolat életben maradhatna, ezért az
            # ilyen engedélyt a védőhalmaz egészsége nélkül nem adjuk ki
            # (fail-closed). A visszahívás csak a szabálytár/tűzfal zárait
            # szerzi meg, a munkamenet-zárat soha; mivel itt a
            # munkamenet-zár alatt futunk, a zársorrend mindig
            # SessionManager -> RuleStore/Firewall, fordított sorrend nem
            # alakulhat ki.
            if any(
                part.direction == "input" for part in new_union
            ) and (self.guard_check is not None):
                try:
                    guard_ok = bool(self.guard_check())
                except FirewallError:
                    raise
                except Exception as exc:
                    raise FirewallError(
                        "a host-port védőhalmaz állapota nem ellenőrizhető; "
                        "a host-hozzáférés biztonságosan le van tiltva"
                    ) from exc
                if not guard_ok:
                    raise FirewallError(
                        "a host-port védőhalmaz nem épült fel; "
                        "a host-hozzáférés biztonságosan le van tiltva"
                    )

            old_union = self._grant_tuple(session.grants)
            removed: tuple[Ports, ...] = ()
            if session.authorized:
                # Módosításnál csak a távozó elemeket töröljük, a közös
                # portok az új grant életciklusához tartoznak. Ha a pontos
                # törlés nem sikerül, a régi munkamenet NEM maradhat
                # engedélyre hivatkozva: a visszavonás a sorból később is
                # lefuthat, ezért a munkamenetet eldobjuk, és a
                # felhasználónak újra kell engedélyeznie. Új engedélyt
                # ilyenkor nem adunk (fail-closed).
                removed = self._subtract_grants(old_union, new_union)
                if removed:
                    try:
                        self._revoke_exact(ip, removed)
                    except FirewallError as exc:
                        self._sessions.pop(token, None)
                        self._remember_end_locked(ip, "revoke_failed", now)
                        # A _revoke_access már auditál, de a
                        # re-authorization kontextusát külön esemény
                        # rögzíti (nem tartalmaz titkot).
                        self._write_audit(
                            "firewall_error",
                            ip=ip,
                            operation="authorize_revoke",
                            reason=(
                                "a korábbi hozzáférés visszavonása nem "
                                "sikerült; a munkamenet megszűnt, újra kell "
                                f"engedélyezni ({exc})"
                            ),
                            pending=True,
                        )
                        # A régi és az új grant uniója: mivel új
                        # engedélyt nem adunk, minden elem törölhető.
                        self._revoke_access(
                            ip, (*old_union, *new_union)
                        )
                        # A visszavonás tűzfalhiba, nem klienshiba: a
                        # szerver ilyenkor 503-mal válaszol, nem 400-zal.
                        raise FirewallError(
                            "a korábbi hozzáférés visszavonása nem sikerült; "
                            "a munkamenet megszűnt, jelentkezz be újra"
                        )

            try:
                # Sikeres módosításnál is újraadjuk: a kerneloldali timeout
                # így az új munkamenet-TTL-re frissül.
                self.firewall.grant_all(ip, new_union, ttl)
            except FirewallError:
                # Részleges engedély ne maradjon. A takarítás hibája is a
                # újrapróbálkozó sorba kerül, nem vész el.
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

            # Csak a távozó portok kapcsolatait szakítjuk meg; az új
            # engedélyhez tartozó, közös portok élő kapcsolatai maradnak.
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
                # A tűzfal-mutáció ugyanazon zár alatt fut, mint az
                # eltávolítás: egy párhuzamos authorize() így nem kaphat
                # olyan grantot, amelyet ez a visszavonás azonnal törölne.
                self._revoke_access_locked(ip, session.grants)
        return session

    def terminate(self, sid: str, reason: str = "admin_terminated") -> Session | None:
        """Egy konkrét munkamenet lezárása az admin felületről."""
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
                        # A tűzfal-hívás a munkamenet-zár alatt fut (lásd
                        # a logout() megjegyzését).
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
        """Egy felhasználó összes munkamenetének és engedélyének bontása.

        Szándékosan nem írunk munkamenetenkénti eseményt: a kiváltó
        művelet (admin módosítás/törlés, jelszócsere, fail2ban-tiltás)
        összesített eseménye már tartalmazza a bontott munkamenetek
        számát. Így a napló nem duzzad fel tömeges visszavonáskor.
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
                # A tűzfal-hívás ugyanazon zár alatt fut, mint az
                # eltávolítás; így a párhuzamos authorize() nem tud a kettő
                # közé ékelődni.
                self._revoke_access_locked(ip, ports)
        return len(revoked)

    def revoke_user_rules(
        self, user: str, rule_ids, reason: str = "revoked"
    ) -> int:
        """A felhasználó munkameneteiből csak a megadott választások bontása.

        Egy szabály módosításakor így a többi kiválasztott szabály
        hozzáférése érvényben marad. A visszatérési érték az érintett
        (részben vagy teljesen eltávolított) munkamenetek száma.
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
        """A megadott szabályválasztás eltávolítása az érintett munkamenetekből.

        Ha a munkamenet csak ezt a szabályt választotta (a régi, egy-
        szabályos munkamenetek mindig ilyenek), a teljes munkamenet
        megszűnik. Több választás esetén csak a szabály grantjei tűnnek
        el, a munkamenet és a többi választás megmarad.

        A revoke_user()hoz hasonlóan nem írunk munkamenetenkénti eseményt:
        az admin szabály-módosítás/törlés összesített eseménye fedi le.
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
        """Több szabályválasztás eltávolítása egyetlen zárolás alatt.

        Egy szabály és az őt tartalmazó gyűjtők egyidejű módosításakor a
        külön ``revoke_rule()`` hívások két lépésben frissítenék ugyanazt a
        munkamenetet: az első lépés részleges állapotot hozna létre, és a
        köztes maradó grantot újra kiadná, mielőtt a második lépés
        eltávolítja. Itt a teljes halmaz egyszerre tűnik el. A visszatérési
        érték az érintett munkamenetek száma.
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
        """Egy forrás-IP összes munkamenetének és engedélyének bontása.

        Fail2ban-tiltáskor hívjuk: a tiltott kliens ne használhassa a már
        megnyitott hozzáférést, és a meglévő kapcsolatai is szakadjanak meg.

        Az összes, ehhez az IP-hez tartozó munkamenetet eldobjuk, majd a
        nemrég sikertelen visszavonások grantjait is a törléshez adjuk. Mivel
        a zárolás alatt az IP-hez nem marad munkamenet (és az
        egy-IP-egy-munkamenet szabály miatt más munkamenet sem örökölhette
        ezeket az elemeket), az IP-hez tartozó host (input) és forward
        ``ip . port`` elemek biztonságosan felderíthetők és törölhetők; így
        az összeomlás vagy korábbi hiba után árva engedélyek sem maradnak a
        kernelben. A listázás pontos IP-egyezést használ, más kliens elemét
        nem érinti.
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
            # A tűzfal-hívás a munkamenet-zár alatt fut, hogy egy
            # párhuzamos authorize() ne adjon új engedélyt az IP-re a
            # felderítés és a törlés között.
            ok = self._revoke_access(ip, grants, discover=True)
            if ok:
                self._clear_pending_keys([key for key, _entry in pending])
        # A conntrack-t akkor is ürítjük, ha nem volt portál-munkamenet:
        # egy pre-auth vagy korábbi kapcsolat is élhet a tiltás pillanatában.
        return len(revoked)

    def reap_once(self, now: float | None = None) -> int:
        """Lejárt munkamenetek törlése; a megüresedett IP-k tiltása."""
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
                # A tűzfal-hívás ugyanazon zár alatt fut, mint a lejárt
                # munkamenet eltávolítása. A helper a maradó aktív
                # munkamenetek grantjaihoz igazítja a törlést, és szükség
                # esetén conntrack-ürítés nélkül csak a nem átfedő
                # elemeket törli.
                self._revoke_access_locked(ip, grants, now=now)
        to_revoke = len(set(expired_authorized) - active_ips)
        # A validate()/authorize() már eltávolított munkamenetek nincsenek a
        # listában, így azokra nem íródik második esemény.
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
        # A korábban sikertelen tűzfal-visszavonások újrapróbálása. Ez a
        # takarítószálban fut, ezért a hívóknál nem kell külön szálat
        # indítani; a visszavonás így sem vész el, ha az nft átmenetileg
        # hibázott.
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
                except Exception as exc:  # a reaper soha ne haljon meg
                    log(f"[munkamenet] takarítási hiba: {exc}")
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

    def shutdown(self, reason: str = "service_stop") -> int:
        """Minden munkamenet és tűzfalengedély azonnali visszavonása.

        Leállítás előtt hívjuk, hogy a leállás ne hagyja a TTL-ig nyitva a
        hozzáféréseket. Összeomlás esetén a kerneloldali timeout véd.
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
    """Csúszóablakos korlát (IP-nként)."""

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


# ------------------------------------------------------------------- captcha

# Folyamatonkénti kulcs: újraindítás után a régi feladványok érvénytelenek.
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
        return False, "hibás captcha-csomag"
    try:
        challenge = str(payload["challenge"])
        salt = str(payload["salt"])
        algorithm = str(payload["algorithm"])
        difficulty = int(payload["difficulty"])
        expires = int(payload["expires"])
        signature = str(payload["signature"])
        number = int(payload["number"])
    except (KeyError, TypeError, ValueError):
        return False, "hibás captcha-csomag"

    if not (0 <= number < 2 ** 64):
        return False, "hibás megoldás"

    # A kliens nem írhatta át a nehézséget / lejáratot.
    expected = hmac.new(
        _POW_SECRET, _canon(challenge, salt, algorithm, difficulty, expires), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False, "érvénytelen aláírás"

    if time.time() > expires:
        return False, "lejárt captcha"

    digest = hashlib.sha256(f"{salt}{number}".encode()).hexdigest()
    if not digest.startswith("0" * difficulty):
        return False, "rossz megoldás"

    now = time.time()
    with _seen_lock:
        for key, exp in list(_seen.items()):
            if exp < now:
                _seen.pop(key, None)
        if challenge in _seen:
            return False, "a captcha már fel volt használva"
        _seen[challenge] = expires

    return True, "ok"


def verify_turnstile(token: str, remote_ip: str) -> tuple[bool, str]:
    if not TURNSTILE_ON:
        return False, "a Turnstile nincs bekapcsolva"
    if not token:
        return False, "hiányzó token"
    data = urllib.parse.urlencode(
        {"secret": TURNSTILE_SECRET, "response": token, "remoteip": remote_ip}
    ).encode()
    try:
        with urllib.request.urlopen(TURNSTILE_VERIFY_URL, data=data, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # hálózati hiba = biztonságos elutasítás
        return False, f"ellenőrzés nem elérhető ({type(exc).__name__})"
    if body.get("success") is True:
        return True, "ok"
    return False, "a captcha érvénytelen"


# ------------------------------------------------------------------- gyökér

class Gateway:
    """A HTTP-réteg által használt komponensek egy csomagban."""

    # A beállítás-telepítés és a port proxy frissítő sorosítása: a frissítő
    # ne írhassa vissza egy régi snapshot szabályait egy admin mentés után.
    _custom_lock = threading.RLock()
    PORTPROXY_REFRESH_SECONDS = 10

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
        # A feltöltött tanúsítványok a beállításfájl mellett, a certs/ alatt.
        self.certs = certs if certs is not None else settings_store.CertStore(
            os.path.join(
                os.path.dirname(
                    getattr(self.settings, "path", settings_store.SETTINGS_PATH)
                ),
                "certs",
            )
        )
        # A WireGuard-alagút (dropjak0) a host hálózati névterében; a
        # beállításváltozás után a signature egyezése esetén nem nyúl hozzá.
        self.tunnels = tunnel_mod.TunnelManager(logger=log)
        # Az ügynök-szinkron (GET /api/tunnel/config) ügynökönkénti
        # minimális időköze; a token soha nem kerül ide vagy a naplóba.
        self.tunnel_sync_times: dict[str, float] = {}
        self.tunnel_sync_lock = threading.Lock()
        # A domain szabály csak létező proxy-bejegyzésre vagy domaines
        # alagút-szolgáltatásra hivatkozhat.
        if getattr(self.rules, "domain_names", False) is None:
            self.rules.domain_names = self._domain_names
            self.rules.legacy_proxy_domain = getattr(
                self.settings, "legacy_proxy_domain", ""
            )
        # A szolgáltatás-szabály hivatkozásait a beállításokból oldjuk fel
        # minden híváskor, hogy a leképzés módosítása azonnal érvényesüljön.
        # A visszahívás kötése az első lusta _load() előtt történik.
        self.rules.service_ports = self._service_ports_for
        # A domain-módú szolgáltatások hostnevét ugyanebből az indexből
        # oldjuk fel; a szolgáltatás-szabály így domain-hozzáférést is adhat.
        self.rules.service_domains = self._service_domains_for
        self.drops = (
            drops if drops is not None else droplog.DropLogService()
        )
        # A host (input) portőr-halmaz állapota. Konzervatívan hamis, amíg
        # az első sikeres sync_host_ports() be nem állítja: a host
        # engedélyek így akkor sem adhatók ki, ha a szinkron még nem futott
        # le (fail-closed). A prepare() a kiszolgálás előtt szinkronizál.
        self._host_ports_ok = False
        # A szinkron+ takarítás egy zár alatt fut: egy elavult
        # hivatkozáslistával induló takarítás ne törölhesse egy közben
        # létrehozott szabály frissen hozzáadott portját.
        self._host_ports_lock = threading.Lock()
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
                on_ban=self._on_fail2ban_ban,
            )
        )
        if self.fail2ban.audit is None:
            self.fail2ban.audit = self.audit
        # Az automatikus (login/drop) tiltások is jussanak el a közös
        # utókezeléshez, ha a példányt kívülről adták át.
        if getattr(self.fail2ban, "_on_ban", None) is None:
            self.fail2ban._on_ban = self._on_fail2ban_ban
        # A drop log minden rögzített csomagját átadjuk a fail2bannak; az
        # dönti el, hogy az adott ok/protokoll alapján tiltás jár-e.
        setter = getattr(self.drops, "set_on_drop", None)
        if setter is not None:
            setter(self._on_drop)
        self.login_rate = (
            rate_limiter if rate_limiter is not None else RateLimiter()
        )
        # A fiók-kérések saját korlátja: a belépési keretet ne fogyassza.
        self.register_rate = RateLimiter(window=600, maximum=3)
        # A proxy 401-ek drop log sorai az nft log-szabályok mintájára
        # (30/perc) korlátozva, globálisan.
        self.proxy_drop_rate = RateLimiter(window=60, maximum=30)
        # Külön korlát a jelszóváltásnak, hogy a belépési próbákat ne
        # fogyassza, és fordítva.
        self.password_rate = RateLimiter(window=300, maximum=10)
        # A hozzáférés-módosítás nft-tranzakciókat indít; a sűrű váltogatás
        # ne terhelhesse a tűzfalat és ne fogyassza a belépési keretet.
        self.access_rate = RateLimiter(window=60, maximum=20)
        # Az admin-módosítások (utolsó admin ellenőrzése + írás) sorosítása.
        self.admin_lock = threading.Lock()

    def _write_audit(self, event: str, **fields) -> None:
        """Nem kötelező naplóírás a portál életciklus-eseményeihez."""
        try:
            self.audit.write(event, **fields)
        except Exception as exc:  # a naplózás soha ne blokkoljon
            log(f"[napló] {event} írása nem sikerült: {exc}")

    def _domain_names(self) -> set[str]:
        """A domain szabály által hivatkozható teljes hostnevek.

        A proxy-bejegyzések mellett az engedélyezett alagút-ügynökök domaines
        szolgáltatásai is ide tartoznak, hogy hozzájuk privát domain szabály
        készülhessen. A letiltott szolgáltatás domainje is látszik: a
        törlés/letiltás életciklus-korlátja így tud rá hivatkozni.
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
        """Egy szolgáltatás-hivatkozás index-bejegyzése a beállításokból.

        ``None``, ha a hivatkozás ismeretlen vagy a szolgáltatás/ügynök le
        van tiltva. Így a szabály mentése és a döntéskori ellenőrzés is
        fail-closed módon viselkedik.
        """
        tunnels = self.settings.snapshot().get("tunnels")
        if not isinstance(tunnels, dict):
            return None
        return settings_store.tunnel_service_index(tunnels).get(ref)

    def _service_ports_for(self, ref: str):
        """Egy szolgáltatás-hivatkozás feloldott portjai a beállításokból."""
        return self._service_entry_for(ref)

    def _service_domains_for(self, ref: str):
        """Egy szolgáltatás-hivatkozás feloldott domainje.

        Ugyanaz az index-bejegyzés, mint a portoknál; a ``domain`` mező
        csak domain-módú szolgáltatásnál nem üres.
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
        """A szabály a döntés pillanatában is a felhasználóhoz tartozik-e."""
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
            # A szolgáltatás-szabály (vagy az ilyet tartalmazó gyűjtő)
            # engedélye a döntés pillanatában is a jelenlegi alagút-
            # leképzésből számoljon. Hiányzó/letiltott hivatkozás vagy
            # eltérő portok esetén a munkamenet nem maradhat érvényben.
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
            # A hallgató portok változatlanok lehetnek, miközben a célhost
            # vagy a célport átirányítása más engedélyt jelentene: a teljes
            # leképezés-aláírást is össze kell vetni (fail-closed).
            if self.rules.service_signature(rule.service_refs) != (
                rule.service_signature
            ):
                return False
        return (
            current.grants == rule.grants
            and current.session_domains == rule.session_domains
        )

    def _host_ports_healthy(self) -> bool:
        """A host-port őrhalmaz állapota; hiba után egyszer újrapróbál.

        Ezt a ``SessionManager.authorize()`` hívja a munkamenet-zár alatt,
        input irányú engedély kiadása előtt. A ``sync_host_ports()`` a
        Gateway host-port zárát, valamint a RuleStore és a Firewall zárait
        szerzi meg, a munkamenet-zárat soha, ezért a zársorrend mindig
        SessionManager -> Gateway -> RuleStore/Firewall, és nem alakulhat
        ki holtpont. A hamis állapot egyetlen retry-val gyógyulhat, hogy
        egy átmeneti nft-hiba ne blokkolja a további belépéseket.
        """
        if not self._host_ports_ok:
            self.sync_host_ports()
        return self._host_ports_ok

    def sync_host_ports(self) -> None:
        """A host (input) szabályok portjainak átvezetése a kernelbe.

        A teljes szabálytárból gyűjtjük a feloldott portokat, ezért egy
        gyűjtőszabály módosítása után is helyes a halmaz tartalma. A
        ``host_service_*`` halmazok normál szinkronnál csak bővülnek (a
        Firewall add-only módon tölti fel őket), így egy törölt szabály nem
        nyitja meg újra a meglévő kapcsolatokat. Sikeres feltöltés után a
        Firewall biztonságos takarítást futtat: csak olyan portot töröl,
        amelyre egyetlen perzisztált szabály sem hivatkozik, és amelyhez
        nem tartozik élő conntrack-bejegyzés.

        Hiba esetén a ``_host_ports_ok`` hamis marad, és a hiba naplózva,
        auditálva van. A host (input) engedélyek ilyenkor 503-mal
        elutasításra kerülnek (fail-closed); a csak forward irányú
        engedélyezés továbbra is működik, mert azt nem ez a halmaz védi.

        Induláskor a halmazok szándékosan nem ürülnek: a törölt portok régi
        folyamai így továbbra is el vannak vágva. A 65536-os méret miatt a
        legfeljebb 65535 érvényes port mind elfér, ezért a halmaz nem
        telhet meg, és nem veszhet el csendben egy őrelem.
        """
        # A szabálytár olvasása, a portok hozzáadása és a takarítás egy
        # zár alatt fut. Enélkül egy korábbi, elavult hivatkozáslistával
        # induló takarítás törölhetné egy közben létrehozott szabály
        # frissen hozzáadott portját (a takarítás csak töröl, nem pótol).
        with self._host_ports_lock:
            self._sync_host_ports_locked()

    def _sync_host_ports_locked(self) -> None:
        # Konzervatív: bármely hiba (vagy nem várt kivétel) után hamis
        # marad, és a host engedélyek zárva lesznek.
        self._host_ports_ok = False
        try:
            rules = self.rules.persisted_rules()
        except RuleStoreError as exc:
            log(f"[tűzfal] a host portok gyűjtése nem sikerült: {exc}")
            self._write_audit(
                "firewall_error",
                operation="host_ports",
                reason=str(exc),
                healthy=False,
            )
            return
        host_tcp: set[int] = set()
        host_udp: set[int] = set()
        # A takarítás hivatkozáslistája szándékosan szélesebb, mint a
        # szinkroné: bármely perzisztált szabály bármely portja véd, nem
        # csak az input részeké. Így egy forward szabály portja sem
        # törlődhet ki az őrhalmazból.
        referenced_tcp: set[int] = set()
        referenced_udp: set[int] = set()
        for rule in rules:
            # A gyűjtőszabály engedélyei irányonként külön részek; a
            # host_service_* halmazba csak az input részek portjai kellenek.
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
            log(f"[tűzfal] a host portok szinkronizálása nem sikerült: {exc}")
            self._write_audit(
                "firewall_error",
                operation="host_ports",
                reason=str(exc),
                healthy=False,
            )
            return
        self._host_ports_ok = True
        # A takarítás csak a teljes, sikeres feltöltés után fut, és a hibája
        # nem ronthatja el az egészséget: a védőhalmaz ekkor már teljes.
        prune = getattr(self.firewall, "prune_host_service_ports", None)
        if prune is None:
            return
        try:
            prune(sorted(referenced_tcp), sorted(referenced_udp),
                  audit=self.audit)
        except Exception as exc:  # a takarítás soha ne akassza meg a grantet
            log(f"[tűzfal] a host port takarítás nem sikerült: {exc}")
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
        """Egy eldobott csomag átadása a fail2bannak.

        Csak az engedély nélküli TCP-forgalmat számoljuk. A portszkennerek
        és botok jellemzően TCP-n próbálkoznak; a szabályos kliens UDP-
        háttérzaja (mDNS, LLMNR, NetBIOS, DNS) nem eredményez tiltást.
        A DNS és a portál saját portja kimarad.
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
            # A WAN-felőli forgalom számít a csomagszám-küszöbhöz is; a
            # LAN-felőli no-grant/input-lan csak a portdiverzitáshoz, mert
            # egy kijelentkezett böngésző is sok TCP-próbát indít.
            self.fail2ban.record_drop(
                src, proto="tcp", dport=dport, reason=reason,
                count_total=reason in ("wan-drop", "input-wan"),
            )
        except Exception as exc:
            log(f"[fail2ban] a(z) {src} drop-alapú tiltása nem sikerült: {exc}")

    def record_proxy_drop(self, ip: str, host: str, path: str) -> None:
        """Egy proxy 401 (tiltóoldal) sora a drop logban.

        Közvetlenül a tárba ír, nem az NFLOG-visszahíváson át: a drop- és
        portszám-jelzést nem táplálja (a 401-eket a proxy-jelzés számolja).
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
            log(f"[proxy] a drop log bejegyzés nem sikerült: {exc}")

    def _on_fail2ban_ban(self, record: dict) -> None:
        """Egy friss tiltás utókezelése.

        A tűzfalban már érvényes a tiltás; itt bontjuk a kliens meglévő
        munkameneteit és kapcsolatait, naplózzuk az eseményt, és beírjuk a
        drop logba a tiltás tényét. A hibák nem vonják vissza a tiltást.
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
            # A proxy-tiltás csak a TCP 80/443-at zárja: a munkamenet és a
            # többi kapcsolat marad, a sima portál elérhető. A meglévő
            # 80/443 kapcsolatokat az input lánc állapotfüggetlen dropja
            # vágja el, ezért conntrack-ürítés sem kell (az irányvak lenne,
            # és a kliens továbbított webforgalmát is bontaná). A drop log
            # tiltás-eseménye a teljes tiltásé, ide nem írjuk.
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
                f"[fail2ban] proxy-tiltás (csak HTTP/HTTPS): {ip} "
                f"({attempts} jogosulatlan proxykérés)"
            )
            return
        revoked = 0
        try:
            revoked = self.sessions.revoke_ip(ip, reason="fail2ban")
        except Exception as exc:
            log(f"[fail2ban] a(z) {ip} munkameneteinek bontása nem sikerült: {exc}")
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
            log(f"[fail2ban] a drop log bejegyzés nem sikerült: {exc}")
        if source == "manual":
            log(f"[fail2ban] kézi tiltás: {ip} ({until - int(time.time())} mp)")
        elif source == "drop":
            log(
                f"[fail2ban] automatikus tiltás: {ip} "
                f"({attempts} eldobott csomag, ok={detail or 'drop'})"
            )
        else:
            log(
                f"[fail2ban] automatikus tiltás: {ip} "
                f"({attempts} sikertelen belépés, {user!r})"
            )

    def _startup_flush(self) -> None:
        """Induláskori ürítés/egyeztetés az effektív környezeti érték szerint.

        A ``HV_FLUSH_ON_START`` ugyanazt az igaz/hamis értelmezést használja,
        mint a többi logikai változó (1/true/yes/on). Ha kikapcsolták, az
        alapértelmezett (biztonságos) viselkedés az árva engedélyek
        egyeztetése: a dinamikus halmazok a memóriabeli, üres
        munkamenet-táblához igazodnak. Csak a kifejezett, nem biztonságos
        ``HV_ALLOW_STALE_GRANTS_ON_START=1`` opt-in engedi, hogy a korábbi
        engedélyek a kernel TTL-ig életben maradjanak; ezt hangosan
        naplózzuk. A ``host_service_*`` halmazokhoz nem nyúlunk.
        """
        mode = _startup_flush_mode(
            FLUSH_ON_START, ALLOW_STALE_GRANTS_ON_START
        )
        effective = "1" if FLUSH_ON_START else "0"
        log(f"[tűzfal] HV_FLUSH_ON_START hatásos értéke: {effective}")
        if mode == "stale_allowed":
            log(
                "[tűzfal] FIGYELEM: HV_FLUSH_ON_START ki van kapcsolva, és "
                "HV_ALLOW_STALE_GRANTS_ON_START=1 van beállítva. A korábbi "
                "folyamat kernelben maradt engedélyei a TTL-ig (akár 30 "
                "napig) érvényben maradhatnak, munkamenet nélkül!"
            )
            return
        try:
            self.firewall.flush()
        except FirewallError as exc:
            # Egy sikertelen induláskori ürítés azt jelentheti, hogy a
            # korábbi folyamat engedélyei tovább élnének. Ilyenkor nem
            # indulunk el: a fail-closed elv fontosabb az elérhetőségnél.
            log(
                "[tűzfal] HIBA: a korábbi engedélyek törlése nem "
                f"sikerült, az indulás leáll: {exc}"
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
                "[tűzfal] FIGYELEM: HV_FLUSH_ON_START ki van kapcsolva, de "
                "az árva engedélyek nem maradhatnak a kernelben; a dinamikus "
                "halmazok a memóriabeli (üres) munkamenet-táblához igazítva."
            )
        else:
            log("[tűzfal] a korábbi engedélyek törölve (tiszta indulás)")

    def prepare(self) -> None:
        """Induláskori tűzfal-ellenőrzés és a régi engedélyek törlése."""
        self.rules.all_rules()
        log(
            f"[katalógus] {len(self.catalog.service_order)} szolgáltatás, "
            f"{len(self.catalog.scenario_order)} forgatókönyv "
            f"({self.catalog.source})"
        )
        log(
            f"[szabályok] {len(self.rules.persisted_rules())} admin szabály, "
            f"{len(self.groups.all_groups())} csoport"
        )
        log(
            "[hozzáférés] választható idő: "
            f"{format_duration(MIN_TTL)}–{format_duration(MAX_TTL)}; "
            f"alapértelmezett: {format_duration(self.sessions.ttl)}"
        )
        # Tiszta indulás, vagy ha az ürítés ki van kapcsolva, biztonságos
        # egyeztetés a memóriabeli (üres) munkamenet-táblához. Az árva
        # engedélyek csak kifejezett, nem biztonságos opt-innal maradhatnak
        # életben; erről a _startup_flush dönt és naplóz.
        self._startup_flush()
        # A host szabályokban deklarált portok betöltése az established
        # forgalmat vágó host_service_* halmazokba. Az induláskori ürítés
        # ezeket szándékosan nem érinti (a törölt portok régi folyamai
        # maradjanak elvágva), ezért itt pótoljuk a tartalmukat. Ez még a
        # kiszolgálás és a health check előtt fut, így a _host_ports_ok
        # állapota már a valós induláskori sync eredményét tükrözi: ha az
        # nem sikerült, a host engedélyek az első authorize-nál egyszer
        # újrapróbálnak, és továbbra is fail-closed módon zárva maradnak.
        self.sync_host_ports()
        ok, why = self.firewall.healthy()
        if ok:
            log(
                f"[tűzfal] rendben: inet {self.firewall.table} "
                f"/ {self.firewall.set_name}, {self.firewall.tcp_set}, "
                f"{self.firewall.udp_set}, {self.firewall.icmp_set}, "
                f"{self.firewall.input_tcp_set}, "
                f"{self.firewall.input_udp_set}, {self.firewall.mac_set}, "
                f"{self.firewall.ban_set}"
            )
        else:
            log(
                "[tűzfal] FIGYELEM: a dinamikus halmazok nem érhetők el "
                f"({why}). A belépések a hiba elhárításáig nem fognak működni."
            )
            self._write_audit(
                "firewall_error", operation="health", reason=str(why)
            )
        # A felületen beállított tiltások visszatöltése az esetleges
        # induláskori ürítés után. Ha ez nem sikerül, a portál elindul, de
        # a védelem gyengébb; az admin a felületen látja a hibát.
        if self.fail2ban.sync():
            status = self.fail2ban.status()
            log(
                "[fail2ban] belépés-figyelés: "
                f"{'aktív' if status['enabled'] else 'kikapcsolva'}; "
                f"drop-mérőszámok: "
                f"csomagszám={'be' if status['drop_count_enabled'] else 'ki'}, "
                f"portok={'be' if status['drop_ports_enabled'] else 'ki'}, "
                f"proxy={'be' if status['proxy_enabled'] else 'ki'}; "
                f"{status['banned']} tiltott IP, küszöb: "
                f"{status['max_attempts']} próbálkozás / "
                f"{status['window_seconds']} mp, tiltás: "
                f"{status['ban_seconds']} mp"
            )
        else:
            log(
                "[fail2ban] FIGYELEM: a mentett tiltásokat nem sikerült "
                "visszatölteni a tűzfalba"
            )
            status = self.fail2ban.status()
            self._write_audit(
                "fail2ban_sync_failed",
                reason=str(status.get("error") or "a visszatöltés nem sikerült"),
            )
        # A settings-fájl pre-auth és blokk szabályainak telepítése.
        self._apply_custom_settings()

    def _apply_custom_settings(self, snapshot: dict | None = None) -> None:
        """A pre-auth és blokk szabályok telepítése az nftables-be.

        Előbb ürítünk, aztán alkalmazunk. Ha az alkalmazás nem sikerül, a
        pre-auth engedélyek nem maradnak életben (fail-closed).
        """
        with Gateway._custom_lock:
            snapshot = snapshot if snapshot is not None else self.settings.snapshot()
            invalid = bool(snapshot.get("error"))
            if invalid:
                log(
                    "[beállítások] FIGYELEM: a beállításfájl hibás; a pre-auth "
                    "lista ürül, a blokk láncok utolsó ismert jó tartalma "
                    f"változatlan marad: {snapshot['error']}"
                )
                self._write_audit(
                    "settings_invalid", reason=str(snapshot["error"])
                )
            try:
                if invalid:
                    # Fail-closed: a pre-auth engedélyek nem maradhatnak életben
                    # egy hibás fájlból, de a blokkolás nem tűnhet el.
                    self.firewall.replace_custom((), (), keep_block=True)
                else:
                    self.firewall.replace_custom(
                        snapshot.get("preauth", []), snapshot.get("block", []),
                        port_proxies=snapshot.get("port_proxies", []),
                        tunnels=snapshot.get("tunnels", {}),
                    )
            except FirewallError as exc:
                log(
                    "[beállítások] HIBA: a testreszabott szabályok telepítése "
                    f"nem sikerült: {exc}"
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
                f"[beállítások] {len(active_preauth)} pre-auth, "
                f"{len(active_block)} blokk, {len(active_proxies)} port proxy "
                "bejegyzés"
            )

    def _restore_custom_settings(self, old: dict) -> None:
        """A korábbi pre-auth/blokk állapot visszaállítása egy tranzakcióban."""
        if old.get("error"):
            # A régi snapshot hibás, ezért a blokk láncok utolsó ismert jó
            # tartalmát nem ismerjük; azokat érintetlenül hagyjuk.
            self.firewall.replace_custom((), (), keep_block=True)
        else:
            self.firewall.replace_custom(
                old.get("preauth", []), old.get("block", []),
                port_proxies=old.get("port_proxies", []),
                tunnels=old.get("tunnels", {}),
            )

    def apply_settings(self, new_data: dict) -> None:
        """Az admin által előkészített beállítások telepítése és mentése.

        Sorrend: nft alkalmazás -> atomi fájlírás. Ha a mentés nem sikerül,
        a korábbi nft-szabályokat visszaállítjuk.
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
                        "[beállítások] a korábbi szabályok visszaállítása sem "
                        f"sikerült: {rollback_exc}"
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
                        "[beállítások] mentési hiba után a korábbi szabályok "
                        f"visszaállítása nem sikerült: {rollback_exc}"
                    )
                    self._write_audit(
                        "firewall_error",
                        operation="rollback_commit",
                        reason=str(rollback_exc),
                    )
                raise
            # A WireGuard-szinkron a mentés után fut; hibája csak az
            # állapotban látszik, a beállításmentést nem rontja el.
            try:
                self.tunnels.reconcile(tunnels)
            except Exception as exc:
                log(f"[alagút] a WireGuard szinkron nem sikerült: {exc}")

    def refresh_port_proxies(self) -> list[tuple[str, int]]:
        """Újrarenderelés, ha egy input cél kötése vagy a route_localnet változott.

        A loopback / redirect döntés a cél socketjétől függ, amely a portál
        után is elindulhat (bootkor a Docker később publikál). Változásnál a
        láncok atomikusan cserélődnek, és az érintett hallgató portok
        conntrack-bejegyzései törlődnek (a régi NAT-kötésű UDP-folyam
        különben a kliens forgalmával életben maradna).
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
            "[port proxy] a cél kötése változott, szabályok frissítve: "
            + ", ".join(f"{p}/{n}" for p, n in changed)
        )
        for proto, port in changed:
            conntrack_flush_port(proto, port, audit=self.audit)
        return changed

    def _portproxy_loop(self) -> None:
        while not self._portproxy_stop.wait(self.PORTPROXY_REFRESH_SECONDS):
            try:
                self.refresh_port_proxies()
            except Exception as exc:  # a szál soha ne haljon meg
                log(f"[port proxy] frissítési hiba: {exc}")

    def start(self) -> None:
        self.sessions.start_reaper()
        # A WireGuard-interfész és a peerek szinkronja induláskor. A hiba
        # csak a státuszban látszik; a portál elindul.
        try:
            self.tunnels.reconcile(
                self.settings.snapshot().get("tunnels", {})
            )
        except Exception as exc:
            log(f"[alagút] az induló WireGuard szinkron nem sikerült: {exc}")
        self._portproxy_stop = threading.Event()
        threading.Thread(
            target=self._portproxy_loop, name="hv-portproxy", daemon=True
        ).start()
        try:
            fail2ban_enabled = bool(self.fail2ban.snapshot().get("enabled"))
        except Exception:
            fail2ban_enabled = False
        self._write_audit(
            "service_start",
            reason="portál folyamat elindult",
            users_count=len(self.users.names()),
            rules_count=len(self.rules.persisted_rules()),
            groups_count=len(self.groups.all_groups()),
            ttl=self.sessions.ttl,
            fail2ban_enabled=fail2ban_enabled,
            dry_run=bool(self.firewall.dry_run),
        )
        if not self.drops.start():
            status = self.drops.status()
            log(f"[drop log] nem aktív: {status.get('error') or 'ismeretlen ok'}")

    def stop(self) -> None:
        stop_event = getattr(self, "_portproxy_stop", None)
        if stop_event is not None:
            stop_event.set()
        try:
            self.drops.stop()
        except Exception as exc:  # a leállás ne akadjon el a naplózón
            log(f"[drop log] leállítási hiba: {exc}")
        self.sessions.stop_reaper()
        # Leállításkor ne maradjon nyitva egyetlen engedély sem a TTL-ig.
        before_shutdown = self.sessions.count()
        try:
            revoked = self.sessions.shutdown()
        except Exception as exc:  # a leállás ne akadjon el a takarításon
            log(f"[tűzfal] leálláskori visszavonás nem sikerült: {exc}")
            self._write_audit(
                "session_shutdown_error", reason=str(exc)
            )
            # A shutdown a munkameneteket már a tűzfal-műveletek előtt
            # törli, ezért a valóságos darabszám a hívás előtti érték.
            revoked = before_shutdown
        self._write_audit(
            "service_stop",
            reason="portál folyamat leállt",
            sessions_revoked=revoked,
        )
