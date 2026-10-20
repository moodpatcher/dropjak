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


# --------------------------------------------------------------- konfiguráció

BASE = os.path.dirname(os.path.abspath(__file__))


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

# A beépített, nem törölhető teljes hozzáférésű szabály. Az admin szerepkör
# mindig megkapja, így az admin soha nem zárhatja ki magát a portálról.
ADMIN_RULE_ID = "admin-full"
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
# szintű korlát 1 perc – 24 óra; a HV_MIN_TTL/HV_MAX_TTL csak szűkítheti.
ABSOLUTE_MIN_TTL = 60
ABSOLUTE_MAX_TTL = 24 * 60 * 60
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
CUSTOM_CHAINS = ("preauth", "block", "preauth_nat", "block_nat")

# Drop-alapú fail2ban: csak a valódi, engedély nélküli TCP-forgalom számít.
# A MAC/spoof/ipv6/fail2ban/dns/ssh okok kimaradnak (hamis forrás-IP vagy
# szabályos, lejárt munkamenet), és a szabályos kliens UDP-háttérzaja
# (mDNS, LLMNR, NetBIOS, DNS) sem tiltás.
DROP_BAN_REASONS = frozenset(
    {"no-grant", "wan-drop", "input-wan", "input-lan"}
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
    "block",
    "preauth_nat",
    "block_nat",
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


_LAN_IF_RE = re.compile(r"^[A-Za-z0-9_.:@+-]{1,15}$")
DRY_RUN = os.environ.get("HV_DRY_RUN", "0") == "1"
FLUSH_ON_START = os.environ.get("HV_FLUSH_ON_START", "1") == "1"

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

    def public(self) -> dict:
        return {
            "tcp": list(self.tcp),
            "udp": list(self.udp),
            "icmp": self.icmp,
            "full": self.full,
            "label": self.label(),
        }

    def label(self) -> str:
        if self.full:
            return "Minden port"
        parts: list[str] = []
        if self.tcp:
            parts.append("TCP " + ", ".join(str(port) for port in self.tcp))
        if self.udp:
            parts.append("UDP " + ", ".join(str(port) for port in self.udp))
        if self.icmp:
            parts.append("ICMP")
        return " · ".join(parts) or "Nincs port"


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

    @property
    def ports(self) -> Ports:
        return Ports(self.tcp, self.udp, self.icmp, self.full)

    @property
    def collection(self) -> bool:
        return bool(self.members)

    def public(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "tcp": list(self.tcp),
            "udp": list(self.udp),
            "icmp": self.icmp,
            "full": self.full,
            "ports_label": self.ports.label(),
            "default_ttl": self.default_ttl,
            "max_ttl": self.max_ttl,
            "builtin": self.builtin,
            "created": self.created,
            "members": list(self.members),
            "collection": self.collection,
        }


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
        entry = {
            "ts": now,
            "time": _utc_iso(now),
            "event": str(event),
        }
        for key, value in fields.items():
            if value is None:
                continue
            if isinstance(value, (str, int, float, bool)) or value is None:
                entry[key] = value
            else:
                entry[key] = str(value)
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
    ) -> list[dict]:
        limit = max(1, min(2000, int(limit)))
        event = (event or "").strip().lower()
        user = (user or "").strip().lower()
        q = (q or "").strip().lower()
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
                        if event and event not in str(item.get("event", "")).lower():
                            continue
                        if user and user not in str(item.get("user", "")).lower():
                            continue
                        if q and q not in json.dumps(
                            item, ensure_ascii=False, sort_keys=True
                        ).lower():
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


def validate_ttl(raw) -> int:
    """A választott hozzáférési idő ellenőrzése (másodperc)."""
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise AccessError("a hozzáférés hossza egész másodperc kell legyen")
    if raw < MIN_TTL or raw > MAX_TTL:
        low = (MIN_TTL + 59) // 60
        high = MAX_TTL // 60
        raise AccessError(
            f"a hozzáférés hossza {low} és {high} perc között lehet"
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
        raise ValueError(f"{field}: 2–64 szabály-azonosítóból álló lista kell")
    values = [
        value.strip() for value in raw
        if isinstance(value, str) and value.strip()
    ]
    cleaned = _clean_str_list(
        raw, field, pattern=_SERVICE_ID_RE, maximum=64
    )
    if len(values) != len(cleaned):
        raise ValueError(f"{field}: ismétlődő szabály-azonosító")
    if not 2 <= len(cleaned) <= 64:
        raise ValueError(
            f"{field}: legalább 2 és legfeljebb 64 egyedi szabály kell"
        )
    return cleaned


def _clean_ports(raw, field: str, maximum: int = 256) -> tuple[int, ...]:
    """Portlista normalizálása.

    Elfogad JSON-listát (a felület ezt küldi), egyetlen egész számot, vagy
    vessző/szóköz elválasztású szöveget. A portok egyediek és növekvő
    sorrendűek lesznek.
    """
    if raw is None:
        return ()
    if isinstance(raw, str):
        raw = [part for part in re.split(r"[\s,;]+", raw.strip()) if part]
    elif isinstance(raw, int) and not isinstance(raw, bool):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        raise ValueError(f"{field}: portlista kell")
    if len(raw) > maximum:
        raise ValueError(f"{field}: legfeljebb {maximum} port adható meg")
    ports: list[int] = []
    for value in raw:
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
            if not value.isdigit():
                raise ValueError(f"{field}: érvénytelen port: {value!r}")
            value = int(value)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{field}: érvénytelen port: {value!r}")
        if not 1 <= value <= 65535:
            raise ValueError(f"{field}: a port 1 és 65535 között lehet: {value}")
        if value not in ports:
            ports.append(value)
    return tuple(sorted(ports))


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

    A beépített ADMIN_RULE_ID szabály nem része a fájlnak, és nem törölhető.
    Ha a fájl még nem létezik, a services.json scenariói induló szabályokként
    létrejönnek, így a korábbi telepítés viselkedése megmarad.
    """

    def __init__(
        self,
        path: str = RULES_PATH,
        catalog: ServiceCatalog | None = None,
        logger=log,
    ) -> None:
        self.path = os.path.abspath(path)
        self.catalog = catalog if catalog is not None else ServiceCatalog.load()
        self.log = logger
        # RLock: a _locked() ugyanabban a szálban beágyazható (például egy
        # zárt szakaszból hívott create()), és a _load() is újra beléphet.
        self._lock = threading.RLock()
        self._lock_state = threading.local()
        self._rules: dict[str, Rule] = {}
        self._order: list[str] = []
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

    def _builtin(self) -> Rule:
        return Rule(
            id=ADMIN_RULE_ID,
            label="Admin – teljes hozzáférés",
            description="Beépített, korlátozás nélküli szabály az adminisztrátoroknak.",
            full=True,
            default_ttl=DEFAULT_TTL,
            max_ttl=MAX_TTL,
            builtin=True,
            created=0,
        )

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

    def _parse_rule(self, rule_id: str, item: dict) -> Rule:
        if not isinstance(item, dict):
            raise RuleStoreError(f"{rule_id}: hibás bejegyzés")
        members: tuple[str, ...] = ()
        if "members" in item:
            # A gyűjtőszabály tárolt portmezői nem mérvadók: a portokat a
            # tagokból számoljuk. A fájlban csak a taglista marad meg.
            try:
                members = _clean_rule_members(item.get("members"))
            except ValueError as exc:
                raise RuleStoreError(f"{rule_id}: {exc}") from exc
            ports = Ports()
        elif self._is_legacy(item):
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
        )

    @staticmethod
    def _collection_issue(
        rule: Rule, rules: dict[str, Rule]
    ) -> str:
        """A gyűjtőszabály hivatkozási hibája, vagy üres szöveg.

        Egy szintű gyűjtést engedünk: a tagok létező, egyedi, nem teljes
        hozzáférésű szabályok lehetnek, másik gyűjtő nem.
        """
        if not rule.members:
            return ""
        for member_id in rule.members:
            if member_id == rule.id:
                return "a gyűjtőszabály nem tartalmazhatja önmagát"
            if member_id == ADMIN_RULE_ID:
                return (
                    "a beépített admin szabály nem lehet gyűjtőszabály tagja"
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
            parse_failed = False
            for rule_id, item in raw.items():
                if rule_id == ADMIN_RULE_ID:
                    continue
                try:
                    clean_id = _clean_id(rule_id, "szabály-azonosító")
                    if isinstance(item, dict) and self._is_legacy(item):
                        legacy_found = True
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
            elif legacy_found and existed and not parse_failed:
                # Régi, szolgáltatás-alapú fájl: előbb biztonsági másolat,
                # majd az új, port-alapú formátum kiírása.
                backup = f"{self.path}.services-backup-{int(time.time())}"
                try:
                    shutil.copy2(self.path, backup)
                    os.chmod(backup, 0o600)
                    self._write_raw(
                        {rid: self._rule_storage(rule) for rid, rule in rules.items()}
                    )
                    self.log(
                        "[szabályok] a régi szolgáltatás-alapú szabályok "
                        f"portokra átalakítva; biztonsági másolat: {backup}"
                    )
                except OSError as exc:
                    self.log(
                        "[szabályok] a port-alapú átalakítás mentése nem "
                        f"sikerült: {exc}"
                    )
            elif legacy_found and parse_failed:
                self.log(
                    "[szabályok] FIGYELEM: a régi szabályfájl hibás bejegyzést "
                    "tartalmaz, ezért nem írom át automatikusan"
                )
            self._rules = rules
            self._order = [ADMIN_RULE_ID, *rules.keys()]
            self._loaded = True

    @staticmethod
    def _rule_storage(rule: Rule) -> dict:
        if rule.members:
            # Gyűjtőnél a portok számított értékek: soha nem perzisztáljuk
            # őket, különben a tagok későbbi módosítása elavult uniót adna.
            return {
                "label": rule.label,
                "description": rule.description,
                "members": list(rule.members),
                "default_ttl": rule.default_ttl,
                "max_ttl": rule.max_ttl,
                "created": rule.created,
            }
        return {
            "label": rule.label,
            "description": rule.description,
            "tcp": list(rule.tcp),
            "udp": list(rule.udp),
            "icmp": rule.icmp,
            "full": rule.full,
            "default_ttl": rule.default_ttl,
            "max_ttl": rule.max_ttl,
            "created": rule.created,
        }

    # -- olvasás ---------------------------------------------------------------

    def _resolve_rule(
        self,
        rule: Rule,
        _seen: set[str] | None = None,
        _cache: dict[str, Rule] | None = None,
    ) -> Rule:
        """A gyűjtőszabály feloldott nézete: a tagok portjainak uniója.

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
        tcp: set[int] = set()
        udp: set[int] = set()
        icmp = False
        for member_id in rule.members:
            member = self._rules.get(member_id)
            if member is None:
                raise RuleStoreError(
                    f"hiányzó gyűjtőszabály-tag: {member_id}"
                )
            resolved = self._resolve_rule(member, seen, cache)
            tcp.update(resolved.tcp)
            udp.update(resolved.udp)
            icmp = icmp or resolved.icmp
        resolved_rule = replace(
            rule,
            tcp=tuple(sorted(tcp)),
            udp=tuple(sorted(udp)),
            icmp=icmp,
            full=False,
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
        if rule_id == ADMIN_RULE_ID:
            return self._builtin()
        rule = self._rules.get(rule_id)
        if rule is None:
            return None
        return self._resolved_or_none(rule)

    def all_rules(self) -> list[Rule]:
        self._load()
        cache: dict[str, Rule] = {}
        resolved = [
            item for item in (
                self._resolved_or_none(rule, cache)
                for rule in self._rules.values()
            ) if item is not None
        ]
        return [self._builtin(), *resolved]

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

    def effective_for(self, user, groups: list[Group] | tuple[Group, ...]) -> list[Rule]:
        """A felhasználó által választható szabályok.

        Admin mindig megkapja a beépített teljes szabályt. Ha egy régi
        felhasználóhoz még nem rendeltek szabályt (a users.json-ban nincs
        rules mező), visszafelé kompatibilisen az összes nem beépített
        szabályt megkapja. Új, explicit módon üresre állított felhasználó
        viszont semmit nem kap, amíg az admin nem rendel hozzá.
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
            assigned_rules = [
                item for item in (resolved(rule_id) for rule_id in assigned)
                if item is not None
            ]
            return [self._builtin(), *assigned_rules]
        if not assigned and not getattr(user, "rules_set", False):
            return [
                item for item in (
                    self._resolved_or_none(raw, cache)
                    for raw in self._rules.values()
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
                "members: 2–64 szabály-azonosítóból álló lista kell"
            )
        is_collection = collection_flag is True or bool(members_raw)
        members: tuple[str, ...] = ()
        ports = Ports()
        if is_collection:
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
                Rule(id=rule_id, label="", description="", members=members),
                self._rules,
            )
            if issue:
                raise RuleStoreError(issue)
        elif self._is_legacy(data):
            # Régi API-hívók még szolgáltatásneveket küldhetnek.
            services = _clean_str_list(
                data.get("services"), "services", maximum=32
            )
            if not services:
                raise RuleStoreError("legalább egy portot válassz")
            ports = self._ports_from_services(services)
        else:
            try:
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
                    f"{name}: {(MIN_TTL + 59) // 60}–{MAX_TTL // 60} perc lehet"
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
        )

    def create(self, rule_id: str, data: dict) -> Rule:
        rule_id = _clean_id(rule_id, "szabály-azonosító")
        if rule_id == ADMIN_RULE_ID:
            raise RuleStoreError("ez a szabály-azonosító foglalt")
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
            self._order.append(rule_id)
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
        if updated.members or updated.full:
            # Egy gyűjtő tagja nem válhat gyűjtővé vagy teljes
            # hozzáférésűvé: azzal a szülő gyűjtő két szintűvé, illetve
            # érvénytelenné válna. Előbb ki kell venni a szülőkből.
            # Mivel a create() is a commitig tartja a zárat, a soron lévő
            # gyűjtő már itt látszik.
            parents = [
                rid for rid, item in self._rules.items()
                if rid != rule_id and rule_id in item.members
            ]
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
        if rule_id == ADMIN_RULE_ID:
            raise RuleStoreError("a beépített admin szabály nem módosítható")
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
        if rule_id == ADMIN_RULE_ID:
            raise RuleStoreError("a beépített admin szabály nem módosítható")
        with self._locked():
            return self._update_locked(rule_id, data)

    def duplicate(
        self,
        rule_id: str,
        new_id: str | None = None,
        label: str | None = None,
    ) -> Rule:
        """Meglévő szabály másolása új azonosítóval.

        A másolat sosem lesz beépített, és nem ad önmagában hozzáférést:
        csak a szabálytárba kerül, ugyanúgy, mint bármely új szabály.
        """
        source_id = _clean_id(rule_id, "szabály-azonosító")
        if source_id == ADMIN_RULE_ID:
            raise RuleStoreError("a beépített admin szabály nem duplikálható")
        self._load()
        with self._locked():
            source = self._rules.get(source_id)
            if source is None:
                raise RuleStoreError(f"nincs ilyen szabály: {source_id}")
            if new_id is None:
                target_id = self._unique_copy_id(source_id)
            else:
                target_id = _clean_id(new_id, "szabály-azonosító")
                if target_id == ADMIN_RULE_ID:
                    raise RuleStoreError("ez a szabály-azonosító foglalt")
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
            self._order.append(target_id)
            return self._resolve_rule(copied)

    def _unique_copy_id(self, source_id: str) -> str:
        def build(suffix: str) -> str:
            room = max(1, 32 - len(suffix))
            return f"{source_id[:room]}{suffix}"

        candidate = build("-copy")
        if candidate != ADMIN_RULE_ID and candidate not in self._rules:
            return candidate
        counter = 2
        while True:
            candidate = build(f"-{counter}")
            if candidate != ADMIN_RULE_ID and candidate not in self._rules:
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
        if rule_id == ADMIN_RULE_ID:
            raise RuleStoreError("a beépített admin szabály nem törölhető")
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
            self._order = [rid for rid in self._order if rid != rule_id]
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
        return Group(
            id=group_id,
            label=_clean_text(item.get("label", group_id), f"{group_id}.label", 80),
            description=_clean_text(
                item.get("description", ""), f"{group_id}.description", 240,
                required=False,
            ),
            rules=_clean_str_list(item.get("rules"), f"{group_id}.rules", maximum=64),
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
    A host SSH-t a host_ssh_v4 halmaz nyitja meg; ide csak a beépített
    ``admin-full`` szabályt választó, engedélyezett portál-munkamenet
    kerül, a munkamenet TTL-jével.
    """

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
        self.icmp_set = "allowed_icmp"
        self.ssh_set = "host_ssh_v4"
        self.mac_set = "client_mac"
        self.ban_set = "banned_v4"
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

    def apply_custom(self, preauth=(), block=()) -> None:
        """A bejelentkezés előtti engedélyek és a blokkolt célok telepítése.

        A pre-auth cél üresen minden célra érvényes. A LAN felől a megadott
        célra/portra nyit; a WAN felől csak DNAT-olt (publikált) forgalomra,
        így nem válik nyílt továbbítóvá. A blokk a LAN felől induló forgalmat
        dobja el, a 80-as TCP-portnál a portál-átirányítás előtt is. A
        kikapcsolt (``enabled: false``) bejegyzések kimaradnak.
        """
        block = _enabled_custom_entries(block)
        preauth = _enabled_custom_entries(preauth)
        if preauth and not self.lan_if:
            raise FirewallError(
                "pre-auth szabály csak ismert LAN interfésszel alkalmazható"
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
        for entry in block:
            dst = str(entry.get("dst", "")).strip()
            proto = str(entry.get("proto", "")).strip().lower()
            ports = [int(port) for port in entry.get("ports", [])]
            if proto not in ("tcp", "udp") or not ports:
                raise FirewallError("érvénytelen blokk-bejegyzés")
            if dst:
                try:
                    dst = str(
                        ipaddress.ip_network(dst, strict=False)
                    )
                except ValueError as exc:
                    raise FirewallError(f"érvénytelen blokk-cél: {dst}") from exc
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
        for entry in preauth:
            dst = str(entry.get("dst", "")).strip()
            proto = str(entry.get("proto", "")).strip().lower()
            ports = [int(port) for port in entry.get("ports", [])]
            if proto not in ("tcp", "udp") or not ports:
                raise FirewallError("érvénytelen pre-auth bejegyzés")
            if dst:
                try:
                    dst = str(ipaddress.ip_network(dst, strict=False))
                except ValueError as exc:
                    raise FirewallError(
                        f"érvénytelen pre-auth cél: {dst}"
                    ) from exc
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
        self._run_script("\n".join(lines) + ("\n" if lines else ""))

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
        """(halmaz, elem) párok a kért portokhoz."""
        if ports.full:
            # A teljes hozzáférés minden mást magába foglal.
            return [(self.set_name, address)]
        elements: list[tuple[str, str]] = []
        for port in ports.tcp:
            elements.append((self.tcp_set, f"{address} . {port}"))
        for port in ports.udp:
            elements.append((self.udp_set, f"{address} . {port}"))
        if ports.icmp:
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
        """A ``client_mac`` halmaz JSON-jéből az adott IP-hez tartozó MAC-ek."""
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError:
                return []
        try:
            payload = json.loads(raw)
        except ValueError:
            return []
        if not isinstance(payload, dict):
            return []
        macs: list[str] = []
        for top in payload.get("nftables", []):
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

    def _mac_values_locked(self, address: str) -> list[str]:
        """Az adott IP-hez tartozó ``ip . mac`` elemek a kernelből."""
        values: list[str] = []
        known = self._macs.get(address)
        if known:
            values.append(f"{address} . {known}")
        result = self._run(
            ["-j", "list", "set", "inet", self.table, self.mac_set],
            check=False,
        )
        if result.returncode == 0:
            for mac in self.parse_mac_json(result.stdout, address):
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
        for value in self._mac_values_locked(address):
            self._delete_quiet(self.mac_set, value)
        self._run_script(
            f"add element inet {self.table} {self.mac_set} "
            f"{{ {address} . {mac} timeout {ttl}s }}\n"
        )
        self._macs[address] = mac
        return mac

    def _unbind_mac_locked(self, address: str) -> None:
        """Nem LAN-klienshez tartozó, esetleg maradt MAC-bejegyzés törlése."""
        if not self.binds_mac(address):
            return
        for value in self._mac_values_locked(address):
            self._delete_quiet(self.mac_set, value)
        self._macs.pop(address, None)

    def _mac_delete_elements(self, address: str) -> list[tuple[str, str]]:
        if not self.binds_mac(address):
            return []
        with self._lock:
            values = self._mac_values_locked(address)
        return [(self.mac_set, value) for value in values]

    # -- nyilvános műveletek ---------------------------------------------------

    def allow(self, ip: str, ttl: int) -> None:
        """Visszafelé kompatibilis belépési pont: teljes hozzáférés."""
        self.grant(ip, Ports(full=True), ttl)

    def grant(self, ip: str, ports: Ports, ttl: int) -> None:
        if not is_ipv4(ip):
            raise FirewallError("csak IPv4-cím engedélyezhető")
        address = normalize_ip(ip)
        ttl = max(1, int(ttl))
        elements = self._elements(address, ports)
        if not elements:
            return
        with self._lock:
            # A MAC-kötés a portok előtt történik: ha a kliens MAC-címe nem
            # állapítható meg, semmilyen engedély nem kerül a kernelbe.
            if self.binds_mac(address):
                self._bind_mac_locked(address, ttl)
            else:
                self._unbind_mac_locked(address)
            # Újra hozzáadás előtt töröljük: így a timeout újraindul.
            for set_name, element in elements:
                self._delete_quiet(set_name, element)
            script = "".join(
                f"add element inet {self.table} {set_name} "
                f"{{ {element} timeout {ttl}s }}\n"
                for set_name, element in elements
            )
            self._run_script(script)

    def grant_host_ssh(self, ip: str, ttl: int) -> None:
        """A host SSH megnyitása a portál-munkamenet idejére.

        Csak a beépített ``admin-full`` szabály engedélyezése hívja meg;
        szűk szolgáltatási szabály vagy gyűjtőszabály nem nyit SSH-t.
        A MAC-kötés itt is érvényes a LAN-on.
        """
        if not is_ipv4(ip):
            raise FirewallError("csak IPv4-cím engedélyezhető")
        address = normalize_ip(ip)
        ttl = max(1, int(ttl))
        with self._lock:
            if self.binds_mac(address):
                self._bind_mac_locked(address, ttl)
            else:
                self._unbind_mac_locked(address)
            # Újra hozzáadás előtt töröljük: így a timeout újraindul.
            self._delete_quiet(self.ssh_set, address)
            self._run_script(
                f"add element inet {self.table} {self.ssh_set} "
                f"{{ {address} timeout {ttl}s }}\n"
            )

    def revoke_host_ssh(self, ip: str) -> None:
        if not is_ipv4(ip):
            return
        self._delete_elements(
            [(self.ssh_set, normalize_ip(ip))]
        )

    def ban(self, ip: str, ttl: int) -> None:
        """Forrás-IP felvétele a ``banned_v4`` halmazba.

        A tiltás kerneloldali timeouttal rendelkezik. Újra hozzáadás előtt
        töröljük, így a tiltás meghosszabbításakor a timeout újraindul.
        """
        if not is_ipv4(ip):
            raise FirewallError("csak IPv4-cím tiltható le")
        address = normalize_ip(ip)
        ttl = max(1, int(ttl))
        with self._lock:
            self._delete_quiet(self.ban_set, address)
            self._run_script(
                f"add element inet {self.table} {self.ban_set} "
                f"{{ {address} timeout {ttl}s }}\n"
            )

    def unban(self, ip: str) -> None:
        """Forrás-IP törlése a ``banned_v4`` halmazból (hiányzó elem nem hiba)."""
        if not is_ipv4(ip):
            return
        self._delete_elements([(self.ban_set, normalize_ip(ip))])

    def sync_bans(self, elements) -> None:
        """A tiltott IP-k és hátralévő idejük betöltése a halmazba.

        Induláskor hívjuk a dinamikus halmazok ürítése után. A halmazt előbb
        kiürítjük, hogy a kernel és a mentett nyilvántartás biztosan egyezzen.
        """
        lines = [f"flush set inet {self.table} {self.ban_set}"]
        for ip, ttl in elements:
            if not is_ipv4(ip):
                continue
            lines.append(
                f"add element inet {self.table} {self.ban_set} "
                f"{{ {normalize_ip(ip)} timeout {max(1, int(ttl))}s }}"
            )
        self._run_script("\n".join(lines) + "\n")

    def _delete_elements(self, elements: list[tuple[str, str]]) -> None:
        """Elemek törlése; a nem létező elem nem hiba."""
        errors: list[str] = []
        with self._lock:
            for set_name, element in elements:
                try:
                    self._delete_quiet(set_name, element)
                except FirewallError as exc:
                    errors.append(str(exc))
                else:
                    if set_name == self.mac_set:
                        address = element.split(" . ", 1)[0]
                        self._macs.pop(address, None)
        if errors:
            raise FirewallError("; ".join(errors))

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
            (self.ssh_set, address),
        ]
        if ports is not None:
            elements.extend(self._elements(address, ports))
        elements.extend(self._mac_delete_elements(address))
        self._delete_elements(list(dict.fromkeys(elements)))

    def revoke_all(self, ip: str, grants=()) -> None:
        """A kliens engedélyeinek törlése.

        A teljes és az ICMP halmazból, valamint a host SSH halmazból mindig
        törölünk. A portokat a megadott engedélyekből (Ports) vesszük: a
        szabályok tetszőleges portokat tartalmazhatnak, ezért nem lehet a
        katalógusból kiolvasni őket. A hívók a munkamenetből ismerik a
        kiadott engedélyt.
        """
        if not is_ipv4(ip):
            return
        address = normalize_ip(ip)
        elements: list[tuple[str, str]] = [
            (self.set_name, address),
            (self.icmp_set, address),
            (self.ssh_set, address),
        ]
        for ports in grants:
            elements.extend(self._elements(address, ports))
        elements.extend(self._mac_delete_elements(address))
        self._delete_elements(list(dict.fromkeys(elements)))

    def flush(self) -> None:
        errors: list[str] = []
        with self._lock:
            for set_name in (
                self.set_name, self.tcp_set, self.udp_set, self.icmp_set,
                self.ssh_set, self.mac_set, self.ban_set,
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
        if mac is not None:
            entry["mac"] = mac
        return entry

    def snapshot(self) -> dict:
        """A dinamikus halmazok pillanatképe, a hátralévő időkkel.

        Csak olvas, ezért az admin Tűzfal nézet biztonságosan hívhatja.
        A nem létező halmaz üresnek számít (a telepítés előtt is működik).
        """
        names = (
            self.set_name, self.tcp_set, self.udp_set, self.icmp_set,
            self.ssh_set, self.mac_set, self.ban_set,
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
                    self.set_name, self.tcp_set, self.udp_set, self.icmp_set,
                    self.ssh_set, self.mac_set, self.ban_set,
                ):
                    self._run(["list", "set", "inet", self.table, set_name])
        except FirewallError as exc:
            return False, str(exc)
        return True, "ok"


def conntrack_flush(ip: str) -> bool:
    """Megszünteti az adott kliens meglévő kapcsolatait.

    A visszatérési érték jelzi, hogy a törlés ténylegesen lefutott-e. A
    hívók ezt naplózzák; a tűzfalhalmazok lejárata ettől függetlenül
    érvényesül az új kapcsolatokra.
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
        return False
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        # Az 1-es kód a conntrack esetében gyakran "nincs ilyen bejegyzés".
        if result.returncode != 1 or detail:
            log(
                f"[tűzfal] conntrack törlés hibakóddal tért vissza "
                f"({ip}): {result.returncode} {detail}".strip()
            )
        return False
    return True


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
                "host_ssh": None,
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
    add_simple("host_ssh_v4", "host_ssh")

    for set_name, field in (("allowed_tcp", "tcp"), ("allowed_udp", "udp")):
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
            item = {"port": port, **entry_time(entry)}
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
        item["tcp"].sort(key=lambda entry: entry["port"])
        item["udp"].sort(key=lambda entry: entry["port"])
        item["sessions"].sort(
            key=lambda row: (
                row.get("user") or "",
                row.get("logged_in") or 0,
            )
        )

        actual_tcp = {entry["port"] for entry in item["tcp"]}
        actual_udp = {entry["port"] for entry in item["udp"]}
        expected_tcp: set[int] = set()
        expected_udp: set[int] = set()
        expected_icmp = False
        expected_full = False
        for row in item["sessions"]:
            expected_tcp.update(
                value for value in (row.get("tcp") or [])
                if isinstance(value, int) and not isinstance(value, bool)
            )
            expected_udp.update(
                value for value in (row.get("udp") or [])
                if isinstance(value, int) and not isinstance(value, bool)
            )
            expected_icmp = expected_icmp or bool(row.get("icmp"))
            expected_full = expected_full or bool(row.get("full"))

        actual_icmp = item["icmp"] is not None
        actual_full = item["full"] is not None
        actual_ssh = item["host_ssh"] is not None
        expected_ssh = any(
            row.get("rule") == ADMIN_RULE_ID for row in item["sessions"]
        )

        mismatch: list[str] = []
        for label, expected, actual in (
            ("TCP", expected_tcp, actual_tcp),
            ("UDP", expected_udp, actual_udp),
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
        if expected_ssh and not actual_ssh:
            mismatch.append("hiányzó host SSH")
        if actual_ssh and not expected_ssh:
            mismatch.append("váratlan host SSH")

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

        ports = Ports(
            tuple(sorted(actual_tcp)),
            tuple(sorted(actual_udp)),
            actual_icmp,
            actual_full,
        )
        timed = [
            item["full"], item["icmp"], item["host_ssh"],
            *item["tcp"], *item["udp"],
        ]
        deadlines = [
            entry.get("expires_in")
            for entry in timed
            if isinstance(entry, dict)
            and isinstance(entry.get("expires_in"), int)
        ]
        item["users"] = users
        item["rules"] = rules
        item["ports_label"] = ports.label()
        item["expires_in"] = min(deadlines) if deadlines else None
        item["entry_count"] = (
            int(actual_full) + int(actual_icmp) + int(actual_ssh)
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


def build_otpauth_uri(username: str, secret: str) -> str:
    """Authentikátor-alkalmazásnak átadható ``otpauth://`` URI."""
    label = urllib.parse.quote(f"{TOTP_ISSUER}:{username}", safe="")
    query = urllib.parse.urlencode(
        {
            "secret": secret,
            "issuer": TOTP_ISSUER,
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
        self._cache_key: tuple[int, int] | None = None
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
            key = (stat.st_mtime_ns, stat.st_size)
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
                    if value
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

    def remove(self, name: str) -> bool:
        with self._locked():
            data = self._read_raw()
            if name not in data:
                return False
            del data[name]
            self._write_raw(data)
            return True


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
            rules=None, must_change_password=True,
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


@dataclass(frozen=True)
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

    @property
    def expires_in(self) -> int:
        return max(0, int(self.expires - time.time()))

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    @property
    def ports(self) -> Ports:
        return Ports(self.tcp, self.udp, self.icmp, self.full)

    def snapshot(self) -> dict:
        """Adminlistához: nyers adatok, a felület számol vele."""
        return {
            "id": self.sid,
            "user": self.user,
            "role": self.role,
            "ip": self.ip,
            "authorized": self.authorized,
            "rule": self.rule,
            "rule_label": self.rule_label,
            "tcp": list(self.tcp),
            "udp": list(self.udp),
            "icmp": self.icmp,
            "full": self.full,
            "ports_label": self.ports.label(),
            "logged_in": int(self.logged_in or self.created),
            "created": int(self.created),
            "expires": int(self.expires),
            "expires_in": self.expires_in,
            "ttl": max(0, int(self.expires - self.created)),
            "ua": self.ua,
        }


class SessionManager:
    """IP-hez kötött, memóriabeli munkamenetek + tűzfalengedély.

    A belépés két lépcsős: a jelszó ellenőrzése után a munkamenet még nem
    ad hálózati hozzáférést. A kliens ezután szabályt és időtartamot választ;
    a forward-lánc csak ekkor nyílik meg, a szabály portjaira. A host SSH
    csak akkor nyílik meg, ha a munkamenet a beépített ``admin-full``
    szabályt engedélyezte; egyedi teljes hozzáférésű és gyűjtőszabályok
    nem nyitják meg.

    A munkamenet lejárta és az nftables-elemek timeoutja ugyanaz az érték.
    Ha a folyamat leáll, a kernel a timeoutnál magától törli az engedélyt.
    """

    def __init__(
        self,
        firewall: Firewall,
        ttl: int = SESSION_TTL,
        pending_ttl: int = AUTH_TTL,
        audit: AuditLog | None = None,
        rule_check=None,
    ) -> None:
        self.firewall = firewall
        self.ttl = max(MIN_TTL, min(int(ttl), MAX_TTL))
        self.pending_ttl = max(1, int(pending_ttl))
        self.audit = audit
        # Visszahívás: a szabály a döntés pillanatában is a felhasználóé-e.
        # Ezzel zárjuk be azt a versenyhelyzetet, amikor az admin a szabály
        # törlése után, de a grant előtt érkező kérést engedélyezne.
        self.rule_check = rule_check
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        # IP -> (időbélyeg, ok): a legutóbb lezárult munkamenet magyarázata.
        self._last_end: dict[str, tuple[float, str]] = {}
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

    def _active_authorized_ips_locked(self) -> set[str]:
        return {
            session.ip
            for session in self._sessions.values()
            if session.authorized
        }

    def _revoke_access(self, ip: str, grants=()) -> None:
        try:
            self.firewall.revoke_all(ip, grants)
        except FirewallError as exc:
            log(f"[tűzfal] a(z) {ip} visszavonása nem sikerült: {exc}")
            if self.audit is not None:
                self.audit.write(
                    "firewall_error", ip=ip, operation="revoke_all", reason=str(exc)
                )
        conntrack_flush(ip)

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
                session.ports for session in previous if session.authorized
            ]
            if previous_grants:
                # A régi hozzáférést előbb visszavonjuk. Ha ez nem sikerül,
                # a régi munkamenet érintetlen marad, és az új belépés sem
                # jön létre (fail-closed).
                self.firewall.revoke_all(ip, previous_grants)
                revoked_access = True
            # Egy IP-hez egyszerre egy munkamenet tartozzon. A korábbi
            # munkamenet lezárásának okát megjegyezzük a felületnek.
            self._drop_ip_locked(ip, "replaced")
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
        if revoked_access:
            conntrack_flush(ip)
            if self.audit is not None:
                self.audit.write(
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
                if session.authorized:
                    revoke = session
            elif session.expires <= now:
                del self._sessions[token]
                self._remember_end_locked(ip, "expired", now)
                if session.authorized:
                    revoke = session
            else:
                return session
        if revoke is not None:
            self._revoke_access(revoke.ip, (revoke.ports,))
        return None

    def authorize(
        self, token: str, ip: str, rule: Rule, ttl: int
    ) -> Session:
        """A kiválasztott szabály és időtartam érvényesítése."""
        ip = normalize_ip(ip)
        if not is_ipv4(ip):
            raise AccessError("csak IPv4-címről lehet hozzáférést kérni")
        if not isinstance(rule, Rule):
            raise AccessError("érvénytelen hozzáférési szabály")
        ports = rule.ports
        ttl = validate_ttl(ttl)
        if ttl > rule.max_ttl:
            raise AccessError(
                f"ez a szabály legfeljebb {rule.max_ttl // 60} percet engedélyez"
            )
        now = time.time()
        flushed = False
        with self._lock:
            session = self._sessions.get(token)
            if session is None or session.ip != ip:
                raise AccessError("érvénytelen vagy lejárt munkamenet")
            if session.expires <= now:
                del self._sessions[token]
                self._remember_end_locked(ip, "expired", now)
                if session.authorized:
                    # A lejárt munkamenet engedélyét is azonnal vonjuk
                    # vissza, ne várjunk a takarítószálra.
                    self._revoke_access(ip, (session.ports,))
                raise AccessError("lejárt a munkamenet")

            if self.rule_check is not None and not self.rule_check(
                session.user, rule
            ):
                raise AccessError("ez a szabály már nem elérhető")

            want_ssh = rule.id == ADMIN_RULE_ID
            if session.authorized:
                # Módosításnál előbb töröljük a régi engedélyeket. Ha ez nem
                # sikerül, a régi hozzáférés marad érvényben, és hibát
                # jelzünk; nem adunk hozzá véletlenül új portokat.
                self.firewall.revoke_all(ip, (session.ports,))
                flushed = True

            try:
                if not want_ssh:
                    self.firewall.revoke_host_ssh(ip)
                self.firewall.grant(ip, ports, ttl)
                if want_ssh:
                    self.firewall.grant_host_ssh(ip, ttl)
            except FirewallError:
                # Részleges engedély ne maradjon.
                try:
                    self.firewall.revoke_all(ip, (session.ports, ports))
                except FirewallError as exc:
                    log(f"[tűzfal] a(z) {ip} takarítása nem sikerült: {exc}")
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

            authorized = Session(
                token=session.token,
                user=session.user,
                ip=ip,
                created=now,
                expires=now + ttl,
                tcp=ports.tcp,
                udp=ports.udp,
                icmp=ports.icmp,
                full=ports.full,
                authorized=True,
                role=session.role,
                rule=rule.id,
                rule_label=rule.label,
                logged_in=session.logged_in,
                ua=session.ua,
                sid=session.sid,
            )
            self._sessions[token] = authorized
        if flushed:
            conntrack_flush(ip)
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
            self._revoke_access(ip, (session.ports,))
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
                    break
        if found is not None and found.authorized:
            self._revoke_access(found.ip, (found.ports,))
        return found

    def revoke_user(
        self,
        user: str,
        *,
        except_token: str | None = None,
        reason: str = "revoked",
    ) -> int:
        """Egy felhasználó összes munkamenetének és engedélyének bontása."""
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
                grants.setdefault(session.ip, []).append(session.ports)
        for ip, ports in grants.items():
            self._revoke_access(ip, ports)
        return len(revoked)

    def revoke_rule(self, rule_id: str, reason: str = "revoked") -> int:
        """A megadott szabállyal engedélyezett munkamenetek bontása."""
        revoked: list[Session] = []
        with self._lock:
            for token, session in list(self._sessions.items()):
                if session.authorized and session.rule == rule_id:
                    del self._sessions[token]
                    revoked.append(session)
                    self._remember_end_locked(session.ip, reason)
        grants: dict[str, list[Ports]] = {}
        for session in revoked:
            grants.setdefault(session.ip, []).append(session.ports)
        for ip, ports in grants.items():
            self._revoke_access(ip, ports)
        return len(revoked)

    def revoke_ip(self, ip: str, reason: str = "fail2ban") -> int:
        """Egy forrás-IP összes munkamenetének és engedélyének bontása.

        Fail2ban-tiltáskor hívjuk: a tiltott kliens ne használhassa a már
        megnyitott hozzáférést, és a meglévő kapcsolatai is szakadjanak meg.
        """
        try:
            ip = normalize_ip(ip)
        except ValueError:
            return 0
        revoked: list[Session] = []
        with self._lock:
            revoked = self._drop_ip_locked(ip, reason)
        # A conntrack-t akkor is ürítjük, ha nem volt portál-munkamenet:
        # egy pre-auth vagy korábbi kapcsolat is élhet a tiltás pillanatában.
        self._revoke_access(ip, [session.ports for session in revoked])
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
                        expired_authorized.setdefault(session.ip, []).append(
                            session.ports
                        )
            active = self._active_authorized_ips_locked()
        for ip in set(expired_authorized) - active:
            self._revoke_access(ip, expired_authorized[ip])
        to_revoke = len(set(expired_authorized) - active)
        if self.audit is not None:
            for session in expired_sessions:
                if session.authorized:
                    self.audit.write(
                        "session_expired",
                        user=session.user,
                        ip=session.ip,
                        rule=session.rule,
                        rule_label=session.rule_label,
                        ports=session.ports.label(),
                        duration=max(0, int(now - session.created)),
                        authorized=True,
                    )
                else:
                    self.audit.write(
                        "session_expired",
                        user=session.user,
                        ip=session.ip,
                        duration=max(0, int(now - session.created)),
                        authorized=False,
                        reason="a hozzáférés-választás nem történt meg",
                    )
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
                grants.setdefault(session.ip, []).append(session.ports)
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
        self.drops = (
            drops if drops is not None else droplog.DropLogService()
        )
        self.sessions = (
            sessions
            if sessions is not None
            else SessionManager(
                self.firewall,
                ttl=DEFAULT_TTL,
                pending_ttl=AUTH_TTL,
                audit=self.audit,
                rule_check=self._rule_available,
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
        # Külön korlát a jelszóváltásnak, hogy a belépési próbákat ne
        # fogyassza, és fordítva.
        self.password_rate = RateLimiter(window=300, maximum=10)
        # A hozzáférés-módosítás nft-tranzakciókat indít; a sűrű váltogatás
        # ne terhelhesse a tűzfalat és ne fogyassza a belépési keretet.
        self.access_rate = RateLimiter(window=60, maximum=20)
        # Az admin-módosítások (utolsó admin ellenőrzése + írás) sorosítása.
        self.admin_lock = threading.Lock()

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
        return current.ports == rule.ports

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
        if source not in ("manual", "login", "drop"):
            source = "manual" if manual else "login"
        detail = str(record.get("detail") or "")[:64]
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
            f"{(MIN_TTL + 59) // 60}–{MAX_TTL // 60} perc; "
            f"alapértelmezett: {self.sessions.ttl // 60} perc"
        )
        if FLUSH_ON_START:
            try:
                self.firewall.flush()
                log("[tűzfal] a korábbi engedélyek törölve (tiszta indulás)")
            except FirewallError as exc:
                # Egy sikertelen induláskori ürítés azt jelentheti, hogy a
                # korábbi folyamat engedélyei tovább élnének. Ilyenkor nem
                # indulunk el: a fail-closed elv fontosabb az elérhetőségnél.
                log(
                    "[tűzfal] HIBA: a korábbi engedélyek törlése nem "
                    f"sikerült, az indulás leáll: {exc}"
                )
                raise
        ok, why = self.firewall.healthy()
        if ok:
            log(
                f"[tűzfal] rendben: inet {self.firewall.table} "
                f"/ {self.firewall.set_name}, {self.firewall.tcp_set}, "
                f"{self.firewall.udp_set}, {self.firewall.icmp_set}, "
                f"{self.firewall.ssh_set}, {self.firewall.mac_set}, "
                f"{self.firewall.ban_set}"
            )
        else:
            log(
                "[tűzfal] FIGYELEM: a dinamikus halmazok nem érhetők el "
                f"({why}). A belépések a hiba elhárításáig nem fognak működni."
            )
        # A felületen beállított tiltások visszatöltése az esetleges
        # induláskori ürítés után. Ha ez nem sikerül, a portál elindul, de
        # a védelem gyengébb; az admin a felületen látja a hibát.
        if self.fail2ban.sync():
            status = self.fail2ban.status()
            log(
                f"[fail2ban] {'aktív' if status['enabled'] else 'kikapcsolva'}; "
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
        # A settings-fájl pre-auth és blokk szabályainak telepítése.
        self._apply_custom_settings()

    def _apply_custom_settings(self, snapshot: dict | None = None) -> None:
        """A pre-auth és blokk szabályok telepítése az nftables-be.

        Előbb ürítünk, aztán alkalmazunk. Ha az alkalmazás nem sikerül, a
        pre-auth engedélyek nem maradnak életben (fail-closed).
        """
        snapshot = snapshot if snapshot is not None else self.settings.snapshot()
        if snapshot.get("error"):
            log(
                "[beállítások] FIGYELEM: a beállításfájl hibás, a pre-auth "
                f"és blokk listák üresek: {snapshot['error']}"
            )
        try:
            self.firewall.clear_custom()
            self.firewall.apply_custom(
                snapshot.get("preauth", []), snapshot.get("block", [])
            )
        except FirewallError as exc:
            log(
                "[beállítások] HIBA: a testreszabott szabályok telepítése "
                f"nem sikerült: {exc}"
            )
            raise
        active_preauth = _enabled_custom_entries(snapshot.get("preauth", []))
        active_block = _enabled_custom_entries(snapshot.get("block", []))
        log(
            f"[beállítások] {len(active_preauth)} pre-auth, "
            f"{len(active_block)} blokk bejegyzés"
        )

    def apply_settings(self, new_data: dict) -> None:
        """Az admin által előkészített beállítások telepítése és mentése.

        Sorrend: nft alkalmazás -> atomi fájlírás. Ha a mentés nem sikerül,
        a korábbi nft-szabályokat visszaállítjuk.
        """
        old = self.settings.snapshot()
        try:
            self.firewall.clear_custom()
            self.firewall.apply_custom(
                new_data.get("preauth", []), new_data.get("block", [])
            )
        except FirewallError:
            try:
                self.firewall.clear_custom()
                self.firewall.apply_custom(
                    old.get("preauth", []), old.get("block", [])
                )
            except FirewallError as rollback_exc:
                log(
                    "[beállítások] a korábbi szabályok visszaállítása sem "
                    f"sikerült: {rollback_exc}"
                )
            raise
        try:
            self.settings.commit(new_data)
        except Exception:
            try:
                self.firewall.clear_custom()
                self.firewall.apply_custom(
                    old.get("preauth", []), old.get("block", [])
                )
            except FirewallError as rollback_exc:
                log(
                    "[beállítások] mentési hiba után a korábbi szabályok "
                    f"visszaállítása nem sikerült: {rollback_exc}"
                )
            raise

    def start(self) -> None:
        self.sessions.start_reaper()
        self.audit.write("service_start", reason="portál folyamat elindult")
        if not self.drops.start():
            status = self.drops.status()
            log(f"[drop log] nem aktív: {status.get('error') or 'ismeretlen ok'}")

    def stop(self) -> None:
        try:
            self.drops.stop()
        except Exception as exc:  # a leállás ne akadjon el a naplózón
            log(f"[drop log] leállítási hiba: {exc}")
        self.sessions.stop_reaper()
        # Leállításkor ne maradjon nyitva egyetlen engedély sem a TTL-ig.
        try:
            revoked = self.sessions.shutdown()
        except Exception as exc:  # a leállás ne akadjon el a takarításon
            log(f"[tűzfal] leálláskori visszavonás nem sikerült: {exc}")
            revoked = 0
        self.audit.write(
            "service_stop",
            reason="portál folyamat leállt",
            sessions_revoked=revoked,
        )
