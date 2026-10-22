#!/usr/bin/env python3
"""
Dropjak — a tűzfal adminisztrátori testreszabása.

Két, a portálon kezelhető szabálytípust tárol:

* ``preauth``: bejelentkezés előtt is nyitva lévő célok és portok. Ezeket
  a forward lánc a portál-munkamenet nélkül is átengedi (és megjelöli a
  Docker-védelemhez). Üres cél esetén minden célra érvényes. Csak akkor
  használható, ha a cél és a port tudatosan nyilvános.
* ``block``: mindig eldobott célok és portok. A blokk a pre-auth szabályt
  is felülbírálja.

A ``site_name`` a tűzfal/portál megjelenített neve (üresen a beépített
``Dropjak`` név érvényes); a portál fejlécében, a böngésző címében és az új
2FA-beiratkozások issuer/címkéjeként jelenik meg.

A ``proxy_domains`` és a ``proxy_routes`` a Caddy-alapú aldomain-proxy
beállításai (üres gyökérlista = kikapcsolva): ``<név>.<root>`` (a ``root``
a gyökérdomainek egyike) a host (``input``) vagy egy mögötte álló
magánhálózati gép (``forward``, ``ip``) ``<port>`` portjára mutat. A
``visibility`` ``private`` (domain szabály kell) vagy ``public`` (bárki). A
``challenge`` (``{"triggers": [...], "interval_hours": n}``, elhagyható) a
proxy challenge (captcha) feltételeit adja; nélküle nincs challenge. A régi,
egyetlen ``proxy_domain`` betöltéskor egyelemű listává alakul. A Caddy a portál loopback-végpontjait kérdezi
kérésenként, ezért a módosításhoz nincs újratöltés és nftables-művelet.
A ``proxy_acme`` (alapértelmezés: igaz) kikapcsolva megtiltja az on-demand
ACME-tanúsítványkérést; ekkor csak a feltöltött tanúsítványok (CertStore,
gyökérdomainenként a ``certs/`` könyvtárban) szolgálnak ki.

A ``port_proxies`` a kernelszintű (nftables DNAT) port proxy bejegyzései: a
host ``listen_port`` portjára érkező TCP/UDP forgalom a hostra (``input``,
``redirect``) vagy egy magánhálózati gépre (``forward``, ``target_ip``)
kerül. Ezeket a Gateway nftables-láncokba rendereli, ezért ez az egyetlen
proxy-beállítás, amely tűzfalműveletet igényel.

A beállítások a state-kötetben, 0600 jogosultságú JSON-fájlban maradnak
meg. A fájl sérülése esetén a pre-auth lista üres marad (fail-closed);
az admin a felületen felülírhatja.

A modul szándékosan nem nyúl az nftables-hez: a Gateway alkalmazza a
szabályokat, és csak siker esetén commitálja a fájlt.
"""

from __future__ import annotations

import copy
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
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
MAX_PROXY_ROUTES = 64
MAX_PROXY_DOMAINS = 16
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
# Legalább kétcímkés, kisbetűs FQDN (gyökérdomain és teljes proxy-hostnév).
_FQDN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
try:
    PORTAL_PORT = int(os.environ.get("PORT", "").strip() or 8100)
except ValueError:
    PORTAL_PORT = 8100
# Proxy-célként tiltott portok. A portál a loopbackről érkező kérést a
# Caddynak hiszi, ezért a portálra mutató útvonal megkerülné az ellenőrzést;
# a 80/443 maga a Caddy (önmagára mutató hurok), a többi host-szolgáltatás.
PROXY_RESERVED_PORTS = (22, 53, 67, 80, 443, 2019)
PROXY_PRIVATE_NETS = tuple(
    ipaddress.IPv4Network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
# Port proxy (nftables DNAT). A hallgató port nem lehet a host saját
# szolgáltatása (SSH, DNS, DHCP, a portál-átirányítás/Caddy 80/443, a Caddy
# admin 2019) és a portál portja sem: ezeket a prerouting elvenné tőlük.
MAX_PORT_PROXIES = 64
PORT_PROXY_RESERVED_LISTEN = (22, 53, 67, 80, 443, 2019)
# Input proxy célja nem lehet az SSH (az csak explicit TCP 22 host
# szabállyal nyílhat), a Caddy admin és a portál.
PORT_PROXY_RESERVED_INPUT_TARGET = (22, 2019)
# A bejegyzés challenge-feltételei (lásd README: Challenge).
PROXY_CHALLENGE_TRIGGERS = (
    "always", "interval", "daily", "after_401", "fail2ban", "suspicious",
    "new_ip", "burst",
)


def _default_log(message: str) -> None:
    print(message, flush=True)


class SettingsError(ValueError):
    """Érvénytelen beállítás vagy bejegyzés."""


def _text(value, field: str, maximum: int = MAX_LABEL) -> str:
    if not isinstance(value, str):
        raise SettingsError(f"{field}: szöveg kell")
    value = value.strip()
    if not value:
        raise SettingsError(f"{field}: nem lehet üres")
    if len(value) > maximum:
        raise SettingsError(f"{field}: legfeljebb {maximum} karakter")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise SettingsError(f"{field}: vezérlőkaraktert nem tartalmazhat")
    return value


def _site_name(value) -> str:
    """A tűzfal neve: szöveg, körbevágva; üres is lehet."""
    if not isinstance(value, str):
        raise SettingsError("site_name: szöveg kell")
    value = value.strip()
    if len(value) > MAX_SITE_NAME:
        raise SettingsError(
            f"site_name: legfeljebb {MAX_SITE_NAME} karakter"
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise SettingsError("site_name: vezérlőkaraktert nem tartalmazhat")
    return value


def _proxy_domain(value) -> str:
    """Egy gyökérdomain: kisbetűs FQDN, vagy üres."""
    if not isinstance(value, str):
        raise SettingsError("proxy_domains: szöveg kell")
    value = value.strip().lower()
    if value and not _FQDN_RE.match(value):
        raise SettingsError(
            "proxy_domains: érvényes, kisbetűs domainnév kell "
            "(pl. z1.example.com)"
        )
    return value


def _proxy_domains(raw) -> list[str]:
    """A proxy gyökérdomainjei: egyedi FQDN-ek; üres lista = kikapcsolva."""
    if not isinstance(raw, list):
        raise SettingsError("proxy_domains: lista kell")
    if len(raw) > MAX_PROXY_DOMAINS:
        raise SettingsError(
            f"proxy_domains: legfeljebb {MAX_PROXY_DOMAINS} gyökérdomain lehet"
        )
    domains = [_proxy_domain(value) for value in raw]
    if "" in domains:
        raise SettingsError(
            "proxy_domains: érvényes, kisbetűs domainnév kell "
            "(pl. z1.example.com)"
        )
    if len(set(domains)) != len(domains):
        raise SettingsError("proxy: duplikált gyökérdomain")
    return domains


def _proxy_routes(raw, domains=(), default_root: str = "") -> list[dict]:
    """A bejegyzések; a ``default_root`` a gyökér nélküli régi bejegyzésé."""
    if not isinstance(raw, list):
        raise SettingsError("proxy_routes: lista kell")
    if len(raw) > MAX_PROXY_ROUTES:
        raise SettingsError(
            f"proxy_routes: legfeljebb {MAX_PROXY_ROUTES} útvonal lehet"
        )
    routes: list[dict] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise SettingsError("proxy: az útvonal JSON-objektum kell")
        name = item.get("name")
        if isinstance(name, str):
            name = name.strip().lower()
        if not isinstance(name, str) or not _DNS_LABEL_RE.match(name):
            raise SettingsError(
                "proxy: az aldomain egyetlen DNS-címke kell "
                "(a–z, 0–9, kötőjel)"
            )
        root = item.get("root", default_root)
        if isinstance(root, str):
            root = root.strip().lower()
        if root not in domains:
            raise SettingsError(
                f"proxy: ismeretlen gyökérdomain: {root or '—'}; gyökérdomain "
                "csak a bejegyzései törlése vagy áthelyezése után törölhető"
            )
        host = f"{name}.{root}"
        if len(host) > 253:
            raise SettingsError("proxy: a teljes hostnév legfeljebb 253 karakter")
        if host in seen:
            raise SettingsError("proxy: duplikált teljes hostnév")
        if host in domains:
            raise SettingsError(
                f"proxy: a teljes hostnév nem lehet gyökérdomain: {host}"
            )
        port = item.get("port")
        if isinstance(port, bool) or not isinstance(port, int) \
                or not 1 <= port <= 65535:
            raise SettingsError("proxy: a port 1 és 65535 között lehet")
        # A típus nélküli (régi) bejegyzés a host saját szolgáltatása.
        kind = item.get("type", "input")
        if kind not in ("input", "forward"):
            raise SettingsError("proxy: a típus input vagy forward lehet")
        if kind == "input" and (
            port in PROXY_RESERVED_PORTS or port == PORTAL_PORT
        ):
            raise SettingsError(
                "proxy: fenntartott port (portál, 22, 53, 67, 80, 443, 2019)"
            )
        enabled = item.get("enabled", True)
        if not isinstance(enabled, bool):
            raise SettingsError("az enabled mező igaz/hamis érték kell")
        # A láthatóság nélküli (régi) bejegyzés privát marad.
        visibility = item.get("visibility", "private")
        if visibility not in ("private", "public"):
            raise SettingsError("proxy: a láthatóság private vagy public lehet")
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
    """A challenge-feltételek; hiányzó vagy üres lista: nincs challenge."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise SettingsError("proxy: a challenge JSON-objektum kell")
    triggers = raw.get("triggers", [])
    if not isinstance(triggers, list) or any(
        not isinstance(value, str) or value not in PROXY_CHALLENGE_TRIGGERS
        for value in triggers
    ):
        raise SettingsError("proxy: ismeretlen challenge-feltétel")
    if len(set(triggers)) != len(triggers):
        raise SettingsError("proxy: duplikált challenge-feltétel")
    hours = raw.get("interval_hours", 24)
    if "interval" in triggers and (
        isinstance(hours, bool) or not isinstance(hours, int)
        or not 1 <= hours <= 720
    ):
        raise SettingsError("proxy: a challenge-időköz 1 és 720 óra között lehet")
    if not triggers:
        return None
    return {
        "triggers": triggers,
        "interval_hours": hours if "interval" in triggers else 24,
    }


def _proxy_ip(value) -> str:
    """Forward proxy-cél: egyetlen magánhálózati (RFC 1918) IPv4-cím."""
    try:
        address = ipaddress.IPv4Address(
            value.strip() if isinstance(value, str) else ""
        )
    except ValueError:
        address = None
    # A három RFC 1918 tartomány kizárja a loopbacket, a link-local,
    # multicast és 0.0.0.0 címet is.
    if address is None or not any(
        address in network for network in PROXY_PRIVATE_NETS
    ):
        raise SettingsError(
            "proxy: a forward célhoz magánhálózati IPv4-cím kell "
            "(10/8, 172.16/12, 192.168/16)"
        )
    return str(address)


def _port_value(value, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) \
            or not 1 <= value <= 65535:
        raise SettingsError(f"port proxy: a {field} 1 és 65535 között lehet")
    return value


def _port_proxy(item) -> dict:
    """Egy port proxy bejegyzés ellenőrzése és normalizálása."""
    if not isinstance(item, dict):
        raise SettingsError("port proxy: a bejegyzés JSON-objektum kell")
    entry_id = item.get("id")
    if entry_id in (None, ""):
        entry_id = secrets.token_hex(4)
    if not isinstance(entry_id, str) or not _ID_RE.match(entry_id):
        raise SettingsError("érvénytelen bejegyzés-azonosító")
    label = _text(item.get("label"), "címke")
    proto = item.get("proto")
    if proto not in ("tcp", "udp", "both"):
        raise SettingsError("port proxy: a protokoll tcp, udp vagy both lehet")
    kind = item.get("type")
    if kind not in ("input", "forward"):
        raise SettingsError("port proxy: a típus input vagy forward lehet")
    listen = _port_value(item.get("listen_port"), "hallgató port")
    if listen in PORT_PROXY_RESERVED_LISTEN or listen == PORTAL_PORT:
        raise SettingsError(
            "port proxy: fenntartott hallgató port "
            "(portál, 22, 53, 67, 80, 443, 2019)"
        )
    target = _port_value(item.get("target_port"), "célport")
    ifaces = item.get("ifaces", "both")
    if ifaces not in ("wan", "lan", "both"):
        raise SettingsError("port proxy: az interfész wan, lan vagy both lehet")
    enabled = item.get("enabled", True)
    snat = item.get("snat", False)
    if not isinstance(enabled, bool) or not isinstance(snat, bool):
        raise SettingsError("az enabled/snat mező igaz/hamis érték kell")
    target_ip = ""
    if kind == "forward":
        try:
            target_ip = _proxy_ip(item.get("target_ip"))
        except SettingsError:
            raise SettingsError(
                "port proxy: a forward célhoz magánhálózati IPv4-cím kell "
                "(10/8, 172.16/12, 192.168/16)"
            ) from None
    else:
        if target in PORT_PROXY_RESERVED_INPUT_TARGET or target == PORTAL_PORT:
            raise SettingsError(
                "port proxy: az input célport nem lehet 22, 2019 vagy a portál"
            )
        if target == listen:
            # Azonos porton a redirect semmit nem tesz: ezt a host (input)
            # szabály önmagában megnyitja, proxy nem kell hozzá.
            raise SettingsError(
                "port proxy: input proxy célportja nem lehet a hallgató port "
                "(ehhez elég egy host szabály)"
            )
        snat = False
    return {
        "id": entry_id, "label": label, "proto": proto, "type": kind,
        "listen_port": listen, "target_ip": target_ip, "target_port": target,
        "ifaces": ifaces, "snat": snat, "enabled": enabled,
    }


def _port_proxies(raw) -> list[dict]:
    """A port proxy lista; a (protokoll, hallgató port) pár egyedi."""
    if not isinstance(raw, list):
        raise SettingsError("port_proxies: lista kell")
    if len(raw) > MAX_PORT_PROXIES:
        raise SettingsError(
            f"port_proxies: legfeljebb {MAX_PORT_PROXIES} bejegyzés lehet"
        )
    entries: list[dict] = []
    ids: set[str] = set()
    keys: set[tuple[str, int]] = set()
    for item in raw:
        entry = _port_proxy(item)
        if entry["id"] in ids:
            raise SettingsError(f"duplikált bejegyzés-azonosító: {entry['id']}")
        ids.add(entry["id"])
        # A kikapcsolt bejegyzés is foglalja a portot, hogy a bekapcsolása
        # ne ütközhessen.
        protos = ("tcp", "udp") if entry["proto"] == "both" else (entry["proto"],)
        for proto in protos:
            key = (proto, entry["listen_port"])
            if key in keys:
                raise SettingsError(
                    "port proxy: a hallgató port már foglalt: "
                    f"{proto.upper()} {entry['listen_port']}"
                )
            keys.add(key)
        entries.append(entry)
    return entries


def _normalize_dst(raw) -> str:
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise SettingsError("cél: szöveg kell (IP vagy CIDR)")
    raw = raw.strip()
    if not raw:
        return ""
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise SettingsError(f"érvénytelen cél: {raw}") from exc
    if network.version != 4:
        raise SettingsError(f"csak IPv4 cél adható meg: {raw}")
    if network.is_multicast:
        raise SettingsError(f"multicast cél nem használható: {raw}")
    if network.prefixlen == 32 and network.network_address.is_unspecified:
        raise SettingsError("a 0.0.0.0/32 cél nem használható")
    if network.prefixlen == 32 and str(network.network_address) == "255.255.255.255":
        raise SettingsError("a broadcast cél nem használható")
    if network.prefixlen == 32:
        return str(network.network_address)
    return str(network)


def _normalize_ports(raw) -> list[int]:
    if not isinstance(raw, list):
        raise SettingsError("portok: lista kell")
    if len(raw) > MAX_PORTS:
        raise SettingsError(f"portok: legfeljebb {MAX_PORTS} port adható meg")
    ports: list[int] = []
    for value in raw:
        if isinstance(value, bool):
            raise SettingsError(f"érvénytelen port: {value!r}")
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
            try:
                value = int(value, 10)
            except ValueError as exc:
                raise SettingsError(f"érvénytelen port: {value}") from exc
        if not isinstance(value, int):
            raise SettingsError(f"érvénytelen port: {value!r}")
        if value < 1 or value > 65535:
            raise SettingsError(f"a port 1 és 65535 között lehet: {value}")
        if value not in ports:
            ports.append(value)
    if not ports:
        raise SettingsError("legalább egy port szükséges")
    return sorted(ports)


def normalize_entry(kind: str, entry, entry_id: str = "") -> dict:
    if kind not in ("preauth", "block"):
        raise SettingsError(f"ismeretlen beállítás-típus: {kind!r}")
    if not isinstance(entry, dict):
        raise SettingsError("a bejegyzés JSON-objektum kell")
    if entry_id:
        if not _ID_RE.match(entry_id):
            raise SettingsError("érvénytelen bejegyzés-azonosító")
    else:
        entry_id = secrets.token_hex(4)
        while not _ID_RE.match(entry_id):
            entry_id = secrets.token_hex(4)
    # A típus nem szerepel a bejegyzésben; a lista hordozza.
    label = _text(entry.get("label"), "címke")
    dst = _normalize_dst(entry.get("dst", ""))
    proto = str(entry.get("proto", "")).strip().lower()
    if proto not in ("tcp", "udp"):
        raise SettingsError(f"érvénytelen protokoll: {entry.get('proto')!r}")
    ports = _normalize_ports(entry.get("ports"))
    enabled = entry.get("enabled", True)
    if not isinstance(enabled, bool):
        raise SettingsError("az enabled mező igaz/hamis érték kell")
    if kind == "block" and proto == "tcp" and 80 in ports and not dst:
        # A 80-as portot a prerouting a portálra irányítja; cél nélkül a
        # blokk nem érvényesülne, ezért ezt nem engedjük csendben.
        raise SettingsError(
            "a 80-as TCP-port blokkolásához cél szükséges "
            "(különben a portál-átirányítás megelőzi)"
        )
    return {
        "id": entry_id,
        "label": label,
        "dst": dst,
        "proto": proto,
        "ports": ports,
        "enabled": enabled,
    }


def legacy_proxy_domain(data) -> str:
    """A 3.6 előtti, egyetlen ``proxy_domain`` (új formátumnál üres)."""
    if not isinstance(data, dict) or "proxy_domains" in data:
        return ""
    return _proxy_domain(data.get("proxy_domain", ""))


def validate_state(data) -> dict:
    if not isinstance(data, dict):
        raise SettingsError("a beállítások JSON-objektum kell")
    registration_enabled = data.get("registration_enabled", False)
    if not isinstance(registration_enabled, bool):
        raise SettingsError(
            "a registration_enabled mező igaz/hamis érték kell"
        )
    # A kulcs nélküli (régi) fájl a korábbi viselkedést kapja: ACME be.
    proxy_acme = data.get("proxy_acme", True)
    if not isinstance(proxy_acme, bool):
        raise SettingsError("a proxy_acme mező igaz/hamis érték kell")
    legacy = legacy_proxy_domain(data)
    if "proxy_domains" in data:
        domains = _proxy_domains(data["proxy_domains"])
    else:
        # Régi formátum: az egyetlen gyökér listává alakul, a gyökér nélküli
        # bejegyzések azt kapják. Gyökér nélkül a bejegyzések hatástalanok
        # voltak, ezért elmaradnak (a régi kulcs a következő írással eltűnik).
        domains = [legacy] if legacy else []
    raw_routes = data.get("proxy_routes", [])
    if "proxy_domains" not in data and not legacy:
        raw_routes = []
    result = {
        "site_name": _site_name(data.get("site_name", "")),
        "registration_enabled": registration_enabled,
        "proxy_domains": domains,
        "proxy_routes": _proxy_routes(raw_routes, domains, legacy),
        "proxy_acme": proxy_acme,
        # A kulcs nélküli (régi) fájlban nincs port proxy.
        "port_proxies": _port_proxies(data.get("port_proxies", [])),
        "preauth": [],
        "block": [],
    }
    for kind in ("preauth", "block"):
        raw_list = data.get(kind, [])
        if not isinstance(raw_list, list):
            raise SettingsError(f"{kind}: lista kell")
        if len(raw_list) > MAX_ENTRIES:
            raise SettingsError(
                f"{kind}: legfeljebb {MAX_ENTRIES} bejegyzés lehet"
            )
        seen: set[str] = set()
        for raw_entry in raw_list:
            if not isinstance(raw_entry, dict):
                raise SettingsError(f"{kind}: a bejegyzés JSON-objektum kell")
            entry_id = raw_entry.get("id")
            if entry_id is not None and not isinstance(entry_id, str):
                raise SettingsError("érvénytelen bejegyzés-azonosító")
            entry = normalize_entry(kind, raw_entry, entry_id or "")
            if entry["id"] in seen:
                raise SettingsError(
                    f"duplikált bejegyzés-azonosító: {entry['id']}"
                )
            seen.add(entry["id"])
            result[kind].append(entry)
    return result


class SettingsStore:
    """A firewall-settings.json betöltése, módosítása és atomi írása."""

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
        # A betöltött fájl régi, egyetlen gyökérdomainje (különben üres): a
        # szabálytár ezzel oldja fel a régi, pont nélküli domain-hivatkozást.
        self.legacy_proxy_domain = ""
        self.load()

    def _defaults(self) -> dict:
        return {
            "site_name": "",
            "registration_enabled": False,
            "proxy_domains": [],
            "proxy_routes": [],
            "proxy_acme": True,
            "port_proxies": [],
            "preauth": [],
            "block": [],
        }

    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            data = validate_state(raw)
            legacy = legacy_proxy_domain(raw)
        except FileNotFoundError:
            with self._lock:
                self._data = self._defaults()
                self._error = ""
            return
        except (OSError, ValueError, SettingsError) as exc:
            with self._lock:
                # Sérült fájlnál a pre-auth mindenképp legyen üres.
                self._data = self._defaults()
                self._error = str(exc)
            self.log(
                f"[beállítások] FIGYELEM: a(z) {self.path} nem olvasható, "
                f"a testreszabás alapértelmezésre áll: {exc}"
            )
            return
        if isinstance(raw, dict) and "proxy_domains" not in raw \
                and raw.get("proxy_routes") and not legacy:
            self.log(
                "[beállítások] gyökérdomain nélküli régi proxy-bejegyzések "
                "elhagyva (hatástalanok voltak)"
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
        """A módosítás érvényesítése és az új állapot előállítása.

        Nem ír fájlt és nem módosítja a memóriabeli állapotot; a hívó
        előbb az nftables-re alkalmazza, majd commit()-tal menti.
        """
        with self._lock:
            data = self._copy_locked()
        action = str(action or "").strip().lower()
        if kind not in ("preauth", "block"):
            raise SettingsError(f"ismeretlen beállítás-típus: {kind!r}")
        entries = data[kind]
        if action == "create":
            if len(entries) >= MAX_ENTRIES:
                raise SettingsError(
                    f"{kind}: legfeljebb {MAX_ENTRIES} bejegyzés lehet"
                )
            normalized = normalize_entry(kind, entry)
            if any(item["id"] == normalized["id"] for item in entries):
                raise SettingsError("duplikált bejegyzés-azonosító")
            entries.append(normalized)
        elif action in ("update", "delete", "toggle"):
            if not isinstance(entry_id, str) or not entry_id:
                raise SettingsError("hiányzó bejegyzés-azonosító")
            index = next(
                (
                    pos for pos, item in enumerate(entries)
                    if item["id"] == entry_id
                ),
                None,
            )
            if index is None:
                raise SettingsError(f"nincs ilyen bejegyzés: {entry_id}")
            if action == "delete":
                del entries[index]
            elif action == "toggle":
                enabled = entry.get("enabled") if isinstance(entry, dict) else None
                if not isinstance(enabled, bool):
                    raise SettingsError("az enabled mező igaz/hamis érték kell")
                entries[index]["enabled"] = enabled
            else:
                normalized = normalize_entry(kind, entry, entry_id)
                entries[index] = normalized
        else:
            raise SettingsError(f"ismeretlen művelet: {action!r}")
        return validate_state(data)

    def prepare_port_proxies(self, entries) -> dict:
        """Az új port proxy lista érvényesítése (fájlírás nélkül).

        A port proxy nftables-láncokat igényel, ezért a hívó előbb
        alkalmazza (Gateway.apply_settings), és csak utána commitál.
        """
        with self._lock:
            data = self._copy_locked()
        data["port_proxies"] = _port_proxies(entries)
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

    def set_registration_enabled(self, enabled: bool) -> dict:
        """A regisztráció (fiók-kérés) engedélyezése vagy tiltása.

        Csak a beállításfájlt írja atomikusan; az nftables-hez nem nyúl.
        """
        if not isinstance(enabled, bool):
            raise SettingsError(
                "a registration_enabled mező igaz/hamis érték kell"
            )
        with self._lock:
            data = self._copy_locked()
        data["registration_enabled"] = enabled
        return self.commit(data)

    def set_site_name(self, name: str) -> dict:
        """A tűzfal nevének mentése.

        Üres érték a beépített ``Dropjak`` névre állítja vissza. Csak a
        beállításfájlt írja atomikusan; az nftables-hez nem nyúl.
        """
        value = _site_name(name)
        with self._lock:
            data = self._copy_locked()
        data["site_name"] = value
        return self.commit(data)

    def set_proxy_acme(self, enabled: bool) -> dict:
        """Az automatikus (on-demand ACME) tanúsítványkérés be/ki."""
        if not isinstance(enabled, bool):
            raise SettingsError("a proxy_acme mező igaz/hamis érték kell")
        with self._lock:
            data = self._copy_locked()
        data["proxy_acme"] = enabled
        return self.commit(data)

    def set_proxy(self, domains, routes, referenced=()) -> dict:
        """A proxy gyökérdomainjeinek és útvonalainak mentése.

        A ``referenced`` a domain szabályok által hivatkozott teljes
        hostnevek: ezek nem tűnhetnek el (törlés, átnevezés vagy másik
        gyökér alá helyezés). Csak a beállításfájlt írja atomikusan; az
        nftables-hez nem nyúl.
        """
        domains = _proxy_domains(domains)
        routes = _proxy_routes(routes, domains)
        missing = sorted(
            set(referenced)
            - {f"{route['name']}.{route['root']}" for route in routes}
        )
        if missing:
            raise SettingsError(
                "proxy: domain szabály hivatkozik rá, ezért nem törölhető "
                f"és nem nevezhető át: {', '.join(missing)}; előbb vedd ki "
                "a szabályból"
            )
        with self._lock:
            data = self._copy_locked()
        data["proxy_domains"] = domains
        data["proxy_routes"] = routes
        return self.commit(data)


# ----------------------------------------------------------- tanúsítványok

CERT_DIR = os.path.join(STATE_DIR, "certs")
MAX_CERT_PEM = 64 * 1024
CERT_WARN_DAYS = 14
_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----"
)


def _pem(value, field: str) -> str:
    """Egy feltöltött PEM-szöveg alapellenőrzése (méret, ASCII)."""
    if not isinstance(value, str):
        raise SettingsError(f"{field}: PEM szöveg kell")
    if len(value.encode("utf-8")) > MAX_CERT_PEM:
        raise SettingsError(f"{field}: legfeljebb {MAX_CERT_PEM // 1024} KiB")
    value = value.strip()
    if not value or not value.isascii():
        raise SettingsError(f"{field}: érvénytelen PEM")
    return value + "\n"


def _decode_cert(path: str) -> dict:
    """Az első tanúsítvány adatai (stdlib, de privát API: hibánál üres)."""
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
    """Lefedi-e a SAN-lista a nevet (pontos vagy egycímkés wildcard)."""
    if name in sans:
        return True
    label, _, parent = name.partition(".")
    return bool(label and parent) and f"*.{parent}" in sans


def _write_private(path: str, data: bytes) -> None:
    """Atomi, 0600 jogosultságú írás (a beállításfájl mintájára)."""
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
    """Gyökérdomainenként feltöltött tanúsítványlánc és titkos kulcs.

    ``<dir>/<root>.pem`` (lánc) és ``<root>.key`` (kulcs), könyvtár 0700,
    fájlok 0600. A kulcs és a PEM soha nem kerül API-válaszba vagy naplóba;
    kifelé csak a metaadat megy (public()). A Caddy a loopback-only
    /api/proxy/cert végponton kapja meg a láncot és a kulcsot (bundle()).
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

    def _check(self, root: str, chain: str, key: str, now: float) -> dict:
        """A pár ellenőrzése ideiglenes 0600 fájlokon; a metaadatot adja."""
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        os.chmod(self.directory, 0o700)
        paths = []
        try:
            for data in (chain, key):
                fd, path = tempfile.mkstemp(
                    dir=self.directory, prefix=".check-", suffix=".pem"
                )
                paths.append(path)
                with os.fdopen(fd, "w", encoding="ascii") as fh:
                    fh.write(data)
            try:
                # A jelszóvisszahívás a titkosított kulcsnál a tty-prompt
                # helyett hibát ad.
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
                    paths[0], paths[1], password=lambda: b""
                )
            except ssl.SSLError as exc:
                raise SettingsError(
                    "a tanúsítvány és a kulcs nem olvasható, vagy nem "
                    "tartozik össze"
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
            raise SettingsError("a tanúsítvány adatai nem olvashatók") from exc
        if not_after <= now:
            raise SettingsError("a tanúsítvány lejárt")
        sans = [
            str(value).lower()
            for kind, value in info.get("subjectAltName", ())
            if kind == "DNS"
        ]
        if root not in sans and f"*.{root}" not in sans:
            raise SettingsError(
                f"a tanúsítvány SAN-listája nem fedi le: {root} / *.{root}"
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
        """A tárolt párok betöltése; a hibás pár kimarad (naplózva)."""
        certs: dict[str, dict] = {}
        try:
            names = sorted(os.listdir(self.directory))
        except FileNotFoundError:
            names = []
        except OSError as exc:
            self.log(f"[tanúsítványok] a könyvtár nem olvasható: {exc}")
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
                # A lejárt tárolt tanúsítvány is betöltődik (a felület
                # jelzi), de a bundle() nem adja ki.
                meta = self._check(root, chain, key, 0)
            except (OSError, ValueError) as exc:
                self.log(f"[tanúsítványok] {root} kihagyva: {exc}")
                continue
            certs[root] = {"bundle": (chain + key).encode("ascii"), "meta": meta}
        with self._lock:
            self._certs = certs

    def install(self, root: str, chain, key, now: float | None = None) -> dict:
        """Érvényes pár mentése (csere is); a metaadatot adja vissza."""
        root = _proxy_domain(root)
        if not root:
            raise SettingsError("hiányzó gyökérdomain")
        chain = _pem(chain, "tanúsítványlánc")
        key = _pem(key, "titkos kulcs")
        if "PRIVATE KEY" in chain or not _PEM_CERT_RE.search(chain):
            raise SettingsError(
                "tanúsítványlánc: csak CERTIFICATE PEM-blokk(ok) lehet(nek)"
            )
        if "PRIVATE KEY-----" not in key or "CERTIFICATE" in key \
                or "ENCRYPTED" in key:
            raise SettingsError(
                "titkos kulcs: egyetlen, jelszó nélküli PRIVATE KEY PEM-blokk"
            )
        meta = self._check(root, chain, key, time.time() if now is None else now)
        pem_path, key_path = self._paths(root)
        # A kulcs előbb: a félbeszakadt cserét a load() a párellenőrzéssel
        # kiszűri.
        _write_private(key_path, key.encode("ascii"))
        _write_private(pem_path, chain.encode("ascii"))
        with self._lock:
            self._certs[root] = {
                "bundle": (chain + key).encode("ascii"), "meta": meta,
            }
        return dict(meta)

    def delete(self, root: str) -> dict | None:
        """A pár törlése; a törölt metaadat (vagy None, ha nem volt)."""
        with self._lock:
            entry = self._certs.pop(root, None)
        for path in self._paths(root) if _FQDN_RE.match(root or "") else ():
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        return dict(entry["meta"]) if entry else None

    def prune(self, roots) -> dict[str, dict]:
        """A már nem létező gyökérdomainek párjainak törlése."""
        with self._lock:
            orphans = [root for root in self._certs if root not in roots]
        return {root: self.delete(root) for root in orphans}

    def bundle(self, name: str, root: str, now: float | None = None):
        """A Caddynak: lánc + kulcs, ha a root párja érvényesen fedi a nevet."""
        with self._lock:
            entry = self._certs.get(root)
        if entry is None:
            return None
        meta = entry["meta"]
        if meta["not_after"] <= (time.time() if now is None else now):
            return None
        return entry["bundle"] if cert_covers(name, meta["sans"]) else None

    def public(self, settings: dict, now: float | None = None) -> list[dict]:
        """Gyökérdomainenként a metaadat és a lefedett/nem fedett nevek."""
        now = time.time() if now is None else now
        with self._lock:
            metas = {root: dict(e["meta"]) for root, e in self._certs.items()}
        out = []
        for root in settings.get("proxy_domains", []):
            item = {"root": root, "installed": root in metas}
            meta = metas.get(root)
            if meta is not None:
                hosts = [root] + [
                    f"{route['name']}.{route['root']}"
                    for route in settings.get("proxy_routes", [])
                    if route["root"] == root
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
