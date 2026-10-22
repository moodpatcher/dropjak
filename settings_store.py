#!/usr/bin/env python3
"""
Dropjak — a tűzfal adminisztrátori testreszabása.

Két, a portálon kezelhető szabálytípust tárol:

* ``preauth``: bejelentkezés előtt is nyitva lévő célok és portok. A
  ``direction`` mezőjük ``forward`` (alapértelmezett: továbbított forgalom,
  a forward láncban) vagy ``input`` (a portálgép saját szolgáltatása, a
  ``preauth_input`` láncban) lehet; a hiányzó mező betöltéskor ``forward``.
  A forward irány a portál-munkamenet nélkül is átengedi a forgalmat (és
  megjelöli a Docker-védelemhez). Üres cél esetén minden célra érvényes.
  Csak akkor használható, ha a cél és a port tudatosan nyilvános; az
  ``input`` irány a portál kapuját megkerülve nyit host-portot.
* ``block``: mindig eldobott célok és portok. A blokk a pre-auth szabályt
  is felülbírálja.

A ``site_name`` a tűzfal/portál megjelenített neve (üresen a beépített
``Dropjak`` név érvényes); a portál fejlécében, a böngésző címében és az új
2FA-beiratkozások issuer/címkéjeként jelenik meg.

A ``motd_text`` és ``motd_expires_at`` a bejelentkezés utáni közlemény
(MOTD): a szöveg üresen kikapcsolja, az ISO-8601 UTC lejárat üresen
állandó. A lejárt közleményt a portál már nem kapja meg.

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
# A set_proxy() jelölése arra, hogy a hívó nem adott challenge-et.
UNSET = object()
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
# WireGuard-alagút (felhő oldal): az ügynökök a 10.77.0.0/24 hálózaton
# kapnak címet, a szerver a 10.77.0.1. A belső (alagút) portok ügynökönként
# egyediek; a hallgató portok a port proxykkal közös névtérben vannak.
MAX_TUNNEL_AGENTS = 16
MAX_TUNNEL_SERVICES = 64
TUNNEL_SUBNET = ipaddress.IPv4Network("10.77.0.0/24")
TUNNEL_SERVER_ADDRESS = "10.77.0.1"
TUNNEL_DEFAULT_PORT = 51820
# Egy portleképezés, egy szolgáltatás és egy ügynök hatékony (portonkénti)
# bejegyzései is legfeljebb ennyi portra bomolhatnak ki.
MAX_TUNNEL_PORTS = 256
TUNNEL_RESERVED_TARGET_PORTS = (22, 2019)
# A domaines (Caddy → ügynök → cél) alagút-szolgáltatás belső portja ebből a
# tartományból kap automatikus, determinisztikus értéket. Ez a port a WAN-on
# nem jelenik meg, csak a wg0 felől a Caddy felé.
TUNNEL_DOMAIN_PORT_LOW = 41000
TUNNEL_DOMAIN_PORT_HIGH = 60999
_WG_KEY_BYTES = 32
# A token URL-safe, legalább 32 karakter (a secrets.token_urlsafe(32) 43).
_TUNNEL_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
# Cél-hostnév: a Docker-szolgáltatásnevek aláhúzást is tartalmazhatnak.
_TUNNEL_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$"
)
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


def _motd_text(value) -> str:
    """A bejelentkezés utáni közlemény szövege; üres = kikapcsolva."""
    if not isinstance(value, str):
        raise SettingsError("motd: szöveg kell")
    value = value.strip()
    if len(value) > MAX_MOTD:
        raise SettingsError(f"motd: legfeljebb {MAX_MOTD} karakter")
    return value


def _motd_expires(value) -> str:
    """A közlemény lejárata ISO-8601 UTC-ben; üres = állandó."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise SettingsError("motd: a lejárat szöveg kell")
    text = value.strip()
    if not text:
        return ""
    try:
        parsed = datetime.datetime.fromisoformat(
            text[:-1] + "+00:00" if text.endswith("Z") else text
        )
    except ValueError:
        raise SettingsError(
            "motd: érvénytelen lejárat (ISO-8601 időpont kell)"
        ) from None
    if parsed.tzinfo is None:
        raise SettingsError(
            "motd: a lejáratnak időzónát is tartalmaznia kell"
        )
    return parsed.astimezone(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def active_motd(settings: dict, now: float | None = None) -> str:
    """A még érvényes közlemény szövege; lejárt vagy üres esetén ""."""
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


def route_host(route: dict) -> str:
    """A bejegyzés teljes hostneve; az üres aldomainnév a gyökérdomain maga."""
    return f"{route['name']}.{route['root']}" if route["name"] else route["root"]


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
        # Üres név: maga a gyökérdomain (csak saját portálcím mellett).
        if not isinstance(name, str) or (name and not _DNS_LABEL_RE.match(name)):
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
        host = f"{name}.{root}" if name else root
        if len(host) > 253:
            raise SettingsError("proxy: a teljes hostnév legfeljebb 253 karakter")
        if host in seen:
            raise SettingsError("proxy: duplikált teljes hostnév")
        if name and host in domains:
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


def _portal_domain(raw, domains, routes) -> str:
    """A Dropjak felület saját Caddy-domainje, vagy "" (gyökérdomainek)."""
    if not isinstance(raw, str):
        raise SettingsError("portal_domain: szöveg kell")
    value = raw.strip().lower()
    # A böngészőből bemásolt teljes URL-t is elfogadjuk.
    value = value.split("://", 1)[-1].split("/", 1)[0]
    value = value.rsplit("@", 1)[-1].split(":", 1)[0].rstrip(".")
    if not value:
        return ""
    if not _FQDN_RE.match(value):
        raise SettingsError(
            "portal_domain: érvényes, kisbetűs domainnév kell "
            "(pl. dropjak.z1.example.com)"
        )
    if value in domains:
        raise SettingsError(
            "portal_domain: a Dropjak címe nem lehet gyökérdomain"
        )
    if not any(value.endswith("." + root) for root in domains):
        raise SettingsError(
            "portal_domain: a Dropjak címe csak gyökérdomain alatt lehet "
            "(pl. dropjak.z1.example.com)"
        )
    if any(route_host(route) == value for route in routes):
        raise SettingsError(
            "portal_domain: már van ilyen proxy-bejegyzés"
        )
    return value


def _tunnel_service_domain(value, domains, routes, portal_domain) -> str:
    """A domaines alagút-szolgáltatás teljes hostneve, vagy "".

    A domain csak egy beállított gyökérdomain szigorú aldomainje lehet, és
    nem ütközhet a gyökérrel, a portál saját címével, egy proxy-bejegyzéssel
    vagy egy másik szolgáltatás domainjével (az utóbbit a hívó ellenőrzi).
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        raise SettingsError("tunnel: a domain szöveg kell")
    value = value.strip().lower()
    if not value:
        return ""
    if not _FQDN_RE.match(value):
        raise SettingsError(
            "tunnel: érvényes, kisbetűs domainnév kell (pl. mc.example.com)"
        )
    # A gyökérrel való egyezést külön is elutasítjuk: több gyökér esetén a
    # gyökér egy hosszabb gyökér aldomainjének is látszhatna.
    if value in domains:
        raise SettingsError(
            "tunnel: a szolgáltatás domainje nem lehet gyökérdomain"
        )
    if not any(value.endswith("." + root) for root in domains):
        raise SettingsError(
            "tunnel: a szolgáltatás domainje csak proxy gyökérdomain alatt "
            "lehet"
        )
    if portal_domain and value == portal_domain:
        raise SettingsError(
            "tunnel: a szolgáltatás domainje nem lehet a Dropjak címe"
        )
    if any(route_host(route) == value for route in routes):
        raise SettingsError("tunnel: már van ilyen proxy-bejegyzés")
    return value


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


def default_tunnels() -> dict:
    """A WireGuard-alagút szakasz alapértelmezése (ügynök nélkül)."""
    return {
        "port": TUNNEL_DEFAULT_PORT,
        "endpoint": "",
        "server_private_key": "",
        "server_public_key": "",
        "agents": [],
    }


def _wg_key(value, field: str, required: bool = False) -> str:
    """WireGuard-kulcs: base64, pontosan 32 bájt (kanonikus alakban)."""
    if value is None or value == "":
        if required:
            raise SettingsError(f"{field}: hiányzó WireGuard-kulcs")
        return ""
    if not isinstance(value, str):
        raise SettingsError(f"{field}: érvénytelen WireGuard-kulcs")
    try:
        raw = base64.b64decode(value.strip().encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        raw = b""
    if len(raw) != _WG_KEY_BYTES:
        raise SettingsError(
            f"{field}: érvénytelen WireGuard-kulcs (base64, 32 bájt kell)"
        )
    return base64.b64encode(raw).decode("ascii")


def _tunnel_address(value) -> str:
    """Az ügynök címe a 10.77.0.0/24 hálózatban, 10.77.0.2–254."""
    try:
        address = ipaddress.IPv4Address(value if isinstance(value, str) else "")
    except ValueError:
        address = None
    if address is None or address not in TUNNEL_SUBNET \
            or not 2 <= address.packed[-1] <= 254:
        raise SettingsError(
            "tunnel: az ügynök címe 10.77.0.2 és 10.77.0.254 közötti IPv4 kell"
        )
    return str(address)


def _tunnel_host(value, field: str) -> str:
    if not isinstance(value, str):
        raise SettingsError(f"{field}: szöveg kell")
    value = value.strip()
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        pass
    if not _TUNNEL_HOST_RE.match(value):
        raise SettingsError(f"{field}: érvényes hostnév vagy IPv4-cím kell")
    return value


def _tunnel_endpoint(value) -> str:
    """A nyilvános végpont hostneve; üresen a kérés Hostja érvényes."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise SettingsError("tunnel: a végpont szöveg kell")
    value = value.strip()
    if not value:
        return ""
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise SettingsError("tunnel: a végpont nem tartalmazhat szóközt")
    return _tunnel_host(value, "tunnel: a végpont")


def _tunnel_target(value) -> str:
    """A cél ``host:port`` alakban (hostnév vagy IPv4)."""
    if not isinstance(value, str) or ":" not in value:
        raise SettingsError("tunnel: a cél host:port alakú kell")
    host, _, port = value.strip().rpartition(":")
    if not host:
        raise SettingsError("tunnel: a cél host:port alakú kell")
    host = _tunnel_host(host, "tunnel: a cél")
    try:
        number = int(port, 10)
    except ValueError:
        number = 0
    if not 1 <= number <= 65535:
        raise SettingsError("tunnel: a célport 1 és 65535 között lehet")
    return f"{host}:{number}"


def _parse_tunnel_port_token(value: str, field: str) -> tuple[int, int]:
    """Egy port vagy ``lo-hi`` tartomány (zárt intervallum)."""
    text = value.strip().replace("–", "-").replace("—", "-")
    match = re.fullmatch(r"(\d+)(?:\s*-\s*(\d+))?", text)
    if match is None:
        raise SettingsError(f"{field}: érvénytelen port: {value!r}")
    low = int(match.group(1))
    high = int(match.group(2)) if match.group(2) else low
    if not 1 <= low <= 65535 or not 1 <= high <= 65535:
        raise SettingsError(f"{field}: a port 1 és 65535 között lehet: {value}")
    if low > high:
        raise SettingsError(
            f"{field}: a tartomány kezdete nem lehet nagyobb a végénél: "
            f"{value}"
        )
    return low, high


def _tunnel_port_list(value, field: str,
                      maximum: int = MAX_TUNNEL_PORTS) -> tuple[int, ...]:
    """Portlista a beírt sorrend megtartásával.

    Elfogad egész számot, vessző/szóköz/pontosvessző elválasztású szöveget
    vagy listát; az elem lehet port vagy ``lo-hi`` tartomány. A tartomány
    növekvő sorrendben bővül, a lista elemrendje viszont változatlan marad:
    a hallgató és a célport párosítása indexenként, ugyanabban a sorrendben
    történik. Ismétlődő port csak a párosítás utáni ellenőrzésnél hiba.
    A korlát a felbontott portok számára vonatkozik.
    """
    if value is None:
        raise SettingsError(f"{field}: portlista kell")
    if isinstance(value, str):
        value = [
            part for part in re.split(r"[\s,;]+", value.strip()) if part
        ]
    elif isinstance(value, int) and not isinstance(value, bool):
        value = [value]
    if not isinstance(value, (list, tuple)):
        raise SettingsError(f"{field}: portlista kell")
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
            raise SettingsError(f"{field}: érvénytelen port: {part!r}")
    if not intervals:
        raise SettingsError(f"{field}: legalább egy port kell")
    total = sum(high - low + 1 for low, high in intervals)
    if total > maximum:
        raise SettingsError(f"{field}: legfeljebb {maximum} port adható meg")
    return tuple(
        port for low, high in intervals for port in range(low, high + 1)
    )


def _format_tunnel_port_sequence(ports) -> str:
    """A portok tömör szövege a megadott (párosítási) sorrendben.

    Csak az egymás után következő, növekvő portokat vonja össze
    tartománnyá; a sorrendet nem rendezi át és nem is deduplikálja, így a
    hallgató és a célportok párosítása a visszaolvasáskor is megmarad.
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
    """A hallgató és célportok indexenkénti párosítása és ellenőrzése.

    Ismétlődő hallgató port csak azonos céllal és azonos protokollal
    fordulhatna elő, de az is hiba; a célport ismétlődése viszont
    megengedett (több hallgató port mutathat ugyanoda). A párok
    hallgató, majd célport szerint rendezve térnek vissza.
    """
    pairs = list(zip(listen, target))
    seen: dict[int, int] = {}
    for listen_port, target_port in pairs:
        previous = seen.get(listen_port)
        if previous is not None:
            if previous != target_port:
                raise SettingsError(
                    "tunnel: ugyanaz a hallgató port eltérő célportra "
                    f"mutat: {listen_port} ({previous} != {target_port})"
                )
            raise SettingsError(
                "tunnel: a hallgató port többször szerepel: "
                f"{proto.upper()} {listen_port}"
            )
        seen[listen_port] = target_port
    return sorted(pairs)


def _normalize_tunnel_mappings(raw_mappings) -> list[dict]:
    """A ``mappings`` lista ellenőrzése és kanonikus alakba írása."""
    if not isinstance(raw_mappings, list):
        raise SettingsError("tunnel: a mappings lista kell")
    if not raw_mappings:
        raise SettingsError("tunnel: legalább egy portleképezés kell")
    mappings: list[dict] = []
    total = 0
    for index, raw in enumerate(raw_mappings, 1):
        if not isinstance(raw, dict):
            raise SettingsError(
                f"tunnel: a(z) {index}. portleképezés JSON-objektum kell"
            )
        proto = raw.get("proto")
        if proto not in ("tcp", "udp", "both"):
            raise SettingsError("tunnel: a protokoll tcp, udp vagy both lehet")
        listen = _tunnel_port_list(
            raw.get("listen"), "tunnel: a hallgató port"
        )
        target = _tunnel_port_list(raw.get("target"), "tunnel: a célport")
        if len(target) != len(listen):
            if len(target) == 1 and len(listen) > 1:
                raise SettingsError(
                    "tunnel: egy célport nem felel meg több hallgató portnak"
                )
            raise SettingsError(
                "tunnel: a célportok száma nem egyezik a hallgató portokéval: "
                f"{len(listen)} != {len(target)}"
            )
        pairs = _pair_tunnel_ports(listen, target, proto)
        for port in listen:
            if port in PORT_PROXY_RESERVED_LISTEN or port == PORTAL_PORT:
                raise SettingsError(
                    "tunnel: fenntartott hallgató port "
                    "(portál, 22, 53, 67, 80, 443, 2019)"
                )
        for port in target:
            if port in TUNNEL_RESERVED_TARGET_PORTS:
                raise SettingsError(
                    "tunnel: a célport nem lehet 22 vagy 2019"
                )
        total += len(pairs)
        if total > MAX_TUNNEL_PORTS:
            raise SettingsError(
                f"tunnel: szolgáltatásonként legfeljebb {MAX_TUNNEL_PORTS} "
                "port képezhető le"
            )
        # A kanonikus alak a párokat rendezi (hallgató, majd célport), és
        # mindkét oldalt ugyanabban a pár-sorrendben írja ki, hogy a
        # visszaolvasás ugyanígy párosítson.
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
    """A domaines szolgáltatás egyetlen TCP-leképezésének ellenőrzése.

    A domaines szolgáltatást a Caddy szolgálja ki HTTPS-en, ezért csak egy
    TCP-leképezés értelmezett. A hallgató (belső alagút) port elhagyható:
    ilyenkor a ``_tunnels`` osztja ki. A célport a megszokott módon egyetlen
    port kell legyen.
    """
    if not isinstance(raw_mappings, list):
        raise SettingsError("tunnel: a mappings lista kell")
    if len(raw_mappings) != 1:
        raise SettingsError(
            "tunnel: domaines szolgáltatáshoz pontosan egy portleképezés kell"
        )
    raw = raw_mappings[0]
    if not isinstance(raw, dict):
        raise SettingsError(
            "tunnel: a portleképezés JSON-objektum kell"
        )
    if raw.get("proto") != "tcp":
        raise SettingsError("tunnel: domaines szolgáltatás csak TCP lehet")
    listen_text = ""
    listen_raw = raw.get("listen")
    if listen_raw not in (None, ""):
        listen = _tunnel_port_list(listen_raw, "tunnel: a hallgató port")
        if len(listen) != 1:
            raise SettingsError(
                "tunnel: domaines szolgáltatáshoz egyetlen belső port kell"
            )
        if listen[0] in PORT_PROXY_RESERVED_LISTEN or listen[0] == PORTAL_PORT:
            raise SettingsError(
                "tunnel: fenntartott belső port "
                "(portál, 22, 53, 67, 80, 443, 2019)"
            )
        listen_text = str(listen[0])
    target = _tunnel_port_list(raw.get("target"), "tunnel: a célport")
    if len(target) != 1:
        raise SettingsError(
            "tunnel: domaines szolgáltatáshoz egyetlen célport kell"
        )
    if target[0] in TUNNEL_RESERVED_TARGET_PORTS:
        raise SettingsError("tunnel: a célport nem lehet 22 vagy 2019")
    return [{
        "proto": "tcp", "listen": listen_text, "target": str(target[0]),
    }]


def _mapping_ports(mappings) -> list[dict]:
    """A szolgáltatás leképezéseinek hatékony, portonkénti listája.

    A tcp és udp ugyanarra a hallgató/cél portpárra ``both``-ra olvad össze;
    eltérő célportnál és ismétlődő protokollnál hibát ad.
    """
    effective: dict[int, dict] = {}
    for mapping in mappings or []:
        proto = mapping.get("proto")
        listen = _tunnel_port_list(
            mapping.get("listen"), "tunnel: a hallgató port"
        )
        target = _tunnel_port_list(mapping.get("target"), "tunnel: a célport")
        if len(target) != len(listen):
            raise SettingsError(
                "tunnel: a célportok száma nem egyezik a hallgató portokéval"
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
                    "tunnel: ugyanaz a hallgató port eltérő célportra mutat: "
                    f"{listen_port} ({current['target_port']} != {target_port})"
                )
            if {current["proto"], proto} == {"tcp", "udp"}:
                current["proto"] = "both"
                continue
            raise SettingsError(
                "tunnel: a hallgató port többször szerepel: "
                f"{proto.upper()} {listen_port}"
            )
    return sorted(
        effective.values(),
        key=lambda item: (item["listen_port"], item["proto"]),
    )


def tunnel_service_ports(service) -> list[dict]:
    """Egy szolgáltatás hatékony portjai.

    Visszaadott elem: ``{proto, listen_port, target_port, tunnel_port}``,
    ahol az alagút portja mindig a hallgató porttal egyezik. A lista a
    hallgató port szerint rendezett.
    """
    if not isinstance(service, dict):
        raise SettingsError("tunnel: a szolgáltatás JSON-objektum kell")
    return _mapping_ports(service.get("mappings", []))


def _agent_effective_ports(agent, enabled_only: bool) -> list[dict]:
    """Az ügynök szolgáltatásainak összevont, portonkénti listája."""
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
                    "tunnel: ugyanaz a hallgató port eltérő célportra mutat: "
                    f"{listen_port}"
                )
            if item["proto"] == current["proto"] \
                    or "both" in (item["proto"], current["proto"]):
                raise SettingsError(
                    "tunnel: a hallgató port többször szerepel az "
                    f"ügynökön: {listen_port}"
                )
            if service.get("target_host", "") != current["target_host"]:
                raise SettingsError(
                    "tunnel: ugyanaz a hallgató port eltérő célhostra mutat: "
                    f"{listen_port}"
                )
            current["proto"] = "both"
    if len(effective) > MAX_TUNNEL_PORTS:
        raise SettingsError(
            f"tunnel: ügynökönként legfeljebb {MAX_TUNNEL_PORTS} port "
            "képezhető le"
        )
    return sorted(
        effective.values(),
        key=lambda item: (item["listen_port"], item["proto"]),
    )


def agent_services_expanded(agent) -> list[dict]:
    """A bekapcsolt szolgáltatások hatékony portjai, determinisztikusan.

    Elem: ``{service_id, label, target_host, proto, listen_port,
    target_port, tunnel_port}``. Az azonos hallgató/cél portpárra mutató
    tcp+udp leképezések ``both``-ra olvadnak össze; az ügynökön belül
    hallgató portonként egyetlen hatékony bejegyzés marad.
    """
    return _agent_effective_ports(agent, enabled_only=True)


def tunnel_service_index(tunnels) -> dict[str, dict]:
    """Engedélyezett alagút-szolgáltatások indexe hivatkozás szerint.

    Kulcs: ``"<ügynök-azonosító>/<szolgáltatás-azonosító>"``. Érték:
    ``{agent_id, service_id, label, target_host, domain, public, tcp, udp}``,
    ahol a portok rendezett tuple-ök. Letiltott ügynök vagy szolgáltatás nem
    kerül bele, így a hiányzó hivatkozás a szabály feloldásakor üres
    portokat ad (fail-closed). A ``tcp``/``udp`` a ``both`` protokollnál is
    kitöltődik. Domaines szolgáltatásnál mindkettő üres (nincs WAN-port),
    de a ``signature`` tartalmazza a leképezést.
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
            # Egy hibás ügynök ne akassza meg a teljes feloldást; a hibás
            # szolgáltatásai egyszerűen nem oldhatók fel.
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
                # A teljes, protokollonkénti leképezés (hallgató port,
                # célhost, célport). A szabály döntéskori ellenőrzése ezt
                # hasonlítja össze, hogy egy célhost/célport átirányítás
                # akkor is érvénytelenítse a régi engedélyt, ha a hallgató
                # portok nem változtak.
                "signature": set(),
            })
            if item.get("domain"):
                # Domaines szolgáltatás: nincs WAN-hallgató port, ezért a
                # szolgáltatás-szabály sem nyithat portot, de a proxy-gapun
                # a domainjét megnyitja. Az aláírás a leképezés mellett a
                # domain-nevet is tartalmazza, hogy az átnevezés
                # érvénytelenítse a korábbi döntést.
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
    """Egy alagút-szolgáltatás ellenőrzése és normalizálása.

    Régi (egyetlen portos) alak: ``listen_port`` + ``tunnel_port`` +
    ``target: host:port``. Ezt automatikusan az új ``mappings`` alakra
    alakítjuk; a régi ``tunnel_port`` elveszik (a hallgató port lesz az
    alagút portja is).

    Domaines módban (``domain != ""``) a szolgáltatás csak egy TCP-
    leképezést tartalmazhat; a hallgató port a belső alagút port, amelyet
    hiányzó értéknél a ``_tunnels`` oszt ki.
    """
    if not isinstance(item, dict):
        raise SettingsError("tunnel: a szolgáltatás JSON-objektum kell")
    service_id = item.get("id")
    if service_id in (None, ""):
        service_id = secrets.token_hex(4)
    if not isinstance(service_id, str) or not _ID_RE.match(service_id):
        raise SettingsError("tunnel: érvénytelen szolgáltatás-azonosító")
    label = _text(item.get("label"), "tunnel: címke")
    enabled = item.get("enabled", True)
    if not isinstance(enabled, bool):
        raise SettingsError("az enabled mező igaz/hamis érték kell")
    public = item.get("public", False)
    if not isinstance(public, bool):
        raise SettingsError("a public mező igaz/hamis érték kell")
    domain = _tunnel_service_domain(
        item.get("domain"), domains, routes, portal_domain
    )
    if domain and seen_domains is not None:
        if domain in seen_domains:
            raise SettingsError(
                f"tunnel: duplikált szolgáltatás-domain: {domain}"
            )
        seen_domains.add(domain)
    # A challenge csak domaines szolgáltatásnál értelmes: a Caddy ezen a
    # hoston kérdez, és a szintetikus cél viszi tovább a feltételeket.
    challenge = _proxy_challenge(item.get("challenge"))
    if challenge is not None and not domain:
        raise SettingsError(
            "tunnel: challenge csak domaines szolgáltatáshoz adható"
        )
    if "mappings" in item:
        if domain and not (
            isinstance(item.get("target_host"), str)
            and item["target_host"].strip()
        ):
            raise SettingsError(
                "tunnel: domaines szolgáltatáshoz célhost kell"
            )
        target_host = _tunnel_host(
            item.get("target_host"), "tunnel: a célhost"
        )
        if domain:
            mappings = _normalize_tunnel_domain_mappings(item.get("mappings"))
        else:
            mappings = _normalize_tunnel_mappings(item.get("mappings"))
    else:
        if domain:
            raise SettingsError(
                "tunnel: domaines szolgáltatáshoz mappings lista kell"
            )
        # Régi alak migrációja.
        proto = item.get("proto")
        if proto not in ("tcp", "udp", "both"):
            raise SettingsError("tunnel: a protokoll tcp, udp vagy both lehet")
        listen = item.get("listen_port")
        if isinstance(listen, bool) or not isinstance(listen, int) \
                or not 1 <= listen <= 65535:
            raise SettingsError(
                "tunnel: a hallgató port 1 és 65535 között lehet"
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
    """Egy ügynök ellenőrzése (kulcsok, token, cím, szolgáltatások)."""
    if not isinstance(item, dict):
        raise SettingsError("tunnel: az ügynök JSON-objektum kell")
    agent_id = item.get("id")
    if agent_id in (None, ""):
        agent_id = secrets.token_hex(4)
    if not isinstance(agent_id, str) or not _ID_RE.match(agent_id):
        raise SettingsError("tunnel: érvénytelen ügynök-azonosító")
    label = _text(item.get("label"), "tunnel: címke")
    address = _tunnel_address(item.get("address"))
    private_key = _wg_key(
        item.get("private_key"), "tunnel: az ügynök privát kulcsa", True
    )
    public_key = _wg_key(
        item.get("public_key"), "tunnel: az ügynök nyilvános kulcsa", True
    )
    preshared_key = _wg_key(
        item.get("preshared_key"), "tunnel: a megosztott kulcs", True
    )
    token = item.get("token")
    if not isinstance(token, str) or not _TUNNEL_TOKEN_RE.match(token):
        raise SettingsError(
            "tunnel: érvénytelen ügynök-token (32+ URL-safe karakter kell)"
        )
    enabled = item.get("enabled", True)
    if not isinstance(enabled, bool):
        raise SettingsError("az enabled mező igaz/hamis érték kell")
    raw_services = item.get("services", [])
    if not isinstance(raw_services, list):
        raise SettingsError("tunnel: a services lista kell")
    if len(raw_services) > MAX_TUNNEL_SERVICES:
        raise SettingsError(
            f"tunnel: ügynökönként legfeljebb {MAX_TUNNEL_SERVICES} "
            "szolgáltatás lehet"
        )
    services: list[dict] = []
    service_ids: set[str] = set()
    for raw_service in raw_services:
        service = _tunnel_service(
            raw_service, domains, routes, portal_domain, seen_domains
        )
        if service["id"] in service_ids:
            raise SettingsError(
                "tunnel: duplikált szolgáltatás-azonosító: "
                f"{service['id']}"
            )
        service_ids.add(service["id"])
        services.append(service)
    return {
        "id": agent_id, "label": label, "address": address,
        "private_key": private_key, "public_key": public_key,
        "preshared_key": preshared_key, "token": token,
        "enabled": enabled, "services": services,
    }


def _assign_tunnel_domain_ports(agents, wg_port: int) -> None:
    """A domaines szolgáltatások belső alagút-portjainak kiosztása.

    A kiosztás determinisztikus: ügynök-, majd szolgáltatássorrendben a
    legkisebb szabad port a 41000–60999 tartományból. A foglaltak közé
    tartozik minden explicit (portos) hallgató port, a WireGuard port, a
    fenntartott hallgató portok és a portál portja, valamint a korábban
    kiosztott belső port. A mentett, már explicit belső port revalidáláskor
    változatlan marad.
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
    # A már mentett belső portok ütközésvizsgálata.
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
                    "tunnel: a belső (alagút) port már foglalt: "
                    f"{port}"
                )
            assigned.add(port)
            used.add(port)
    # A hiányzó belső portok kiosztása.
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
                    "tunnel: nincs szabad belső alagút-port "
                    f"({TUNNEL_DOMAIN_PORT_LOW}–{TUNNEL_DOMAIN_PORT_HIGH})"
                )


def _tunnels(raw, domains=(), routes=(), portal_domain="") -> dict:
    """A WireGuard-alagút szakasz; hiányzó kulcs = alapértelmezés."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise SettingsError("tunnels: JSON-objektum kell")
    port = raw.get("port", TUNNEL_DEFAULT_PORT)
    if isinstance(port, bool) or not isinstance(port, int) \
            or not 1024 <= port <= 65535:
        raise SettingsError(
            "tunnel: a WireGuard port 1024 és 65535 között lehet"
        )
    if port in PORT_PROXY_RESERVED_LISTEN or port == PORTAL_PORT:
        raise SettingsError(
            "tunnel: fenntartott WireGuard port "
            "(portál, 22, 53, 67, 80, 443, 2019)"
        )
    raw_agents = raw.get("agents", [])
    if not isinstance(raw_agents, list):
        raise SettingsError("tunnel: az agents lista kell")
    if len(raw_agents) > MAX_TUNNEL_AGENTS:
        raise SettingsError(
            f"tunnel: legfeljebb {MAX_TUNNEL_AGENTS} ügynök lehet"
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
                f"tunnel: duplikált ügynök-azonosító: {agent['id']}"
            )
        agent_ids.add(agent["id"])
        if agent["address"] in addresses:
            raise SettingsError(
                f"tunnel: duplikált ügynökcím: {agent['address']}"
            )
        addresses.add(agent["address"])
        agents.append(agent)
    server_private_key = _wg_key(
        raw.get("server_private_key"), "tunnel: a szerver privát kulcsa"
    )
    server_public_key = _wg_key(
        raw.get("server_public_key"), "tunnel: a szerver nyilvános kulcsa"
    )
    if agents and not (server_private_key and server_public_key):
        raise SettingsError(
            "tunnel: ügynökök mentéséhez szerver WireGuard-kulcspár kell"
        )
    _assign_tunnel_domain_ports(agents, port)
    # Az ügynökön belüli ütközések és a hatékony portok korlátja. A domaines
    # szolgáltatások belső portja is része az ügynök névterének.
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
    """A hallgató portok közös névtere a port proxykkal (a ``both`` kettőt foglal)."""
    keys: set[tuple[str, int]] = set()
    # Bekapcsolt ügynöknél a WireGuard UDP-port a bejövő forgalomé; egy
    # ugyanilyen hallgató port a handshake-et a proxyhoz irányítaná.
    wg_port = tunnels["port"] if any(
        agent["enabled"] for agent in tunnels["agents"]
    ) else None
    if wg_port is not None:
        for entry in port_proxies:
            if entry["listen_port"] == wg_port \
                    and entry["proto"] in ("udp", "both"):
                raise SettingsError(
                    "port proxy: a hallgató port a WireGuard porttal "
                    f"ütközik: UDP {wg_port}"
                )
        for agent in tunnels["agents"]:
            for item in _agent_effective_ports(agent, enabled_only=False):
                if item.get("domain"):
                    # A domaines szolgáltatás belső portja nem WAN-hallgató
                    # port, ezért nem ütközhet a WireGuard porttal.
                    continue
                if item["listen_port"] == wg_port \
                        and item["proto"] in ("udp", "both"):
                    raise SettingsError(
                        "tunnel: a hallgató port a WireGuard porttal "
                        f"ütközik: UDP {wg_port}"
                    )
    for entry in port_proxies:
        for proto in (
            ("tcp", "udp") if entry["proto"] == "both" else (entry["proto"],)
        ):
            keys.add((proto, entry["listen_port"]))
    for agent in tunnels["agents"]:
        for item in _agent_effective_ports(agent, enabled_only=False):
            if item.get("domain"):
                # A belső alagút-port nem a WAN hallgató-port névtere.
                continue
            for proto in (
                ("tcp", "udp") if item["proto"] == "both"
                else (item["proto"],)
            ):
                key = (proto, item["listen_port"])
                if key in keys:
                    raise SettingsError(
                        "tunnel: a hallgató port már foglalt: "
                        f"{proto.upper()} {item['listen_port']}"
                    )
                keys.add(key)


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


def _normalize_direction(raw) -> str:
    """A pre-auth bejegyzés iránya: ``forward`` (alap) vagy ``input``."""
    if raw is None:
        return "forward"
    if not isinstance(raw, str):
        raise SettingsError("az irány csak forward vagy input lehet")
    value = raw.strip()
    if not value:
        return "forward"
    if value not in ("forward", "input"):
        raise SettingsError(f"érvénytelen irány: {raw!r}")
    return value


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
    direction = ""
    if kind == "preauth":
        # A régi bejegyzésekben nincs direction: azok forward irányúak.
        direction = _normalize_direction(entry.get("direction"))
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
    return normalized


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
    routes = _proxy_routes(raw_routes, domains, legacy)
    portal_domain = _portal_domain(data.get("portal_domain", ""), domains, routes)
    # Gyökérre szóló bejegyzés csak akkor lehet, ha a portál már saját címen
    # fut; különben a gyökér a portált szolgálja ki.
    if not portal_domain and any(not route["name"] for route in routes):
        raise SettingsError(
            "proxy: gyökérre szóló bejegyzés csak saját portálcím mellett lehet"
        )
    port_proxies = _port_proxies(data.get("port_proxies", []))
    tunnels = _tunnels(
        data.get("tunnels"), domains, routes, portal_domain
    )
    # A hallgató portok a port proxykkal közös névtérben vannak; ezt csak
    # itt lehet ellenőrizni, ahol mindkét lista látszik.
    _check_tunnel_listen_ports(port_proxies, tunnels)
    result = {
        "site_name": _site_name(data.get("site_name", "")),
        "motd_text": _motd_text(data.get("motd_text", "")),
        "motd_expires_at": _motd_expires(data.get("motd_expires_at", "")),
        "registration_enabled": registration_enabled,
        "proxy_domains": domains,
        "proxy_routes": routes,
        "proxy_acme": proxy_acme,
        # A Dropjak felület saját címe és a hozzá tartozó challenge; üres
        # címnél a gyökérdomainek szolgálják ki a portált.
        "portal_domain": portal_domain,
        "portal_challenge": (
            _proxy_challenge(data.get("portal_challenge"))
            if portal_domain else None
        ),
        # A kulcs nélküli (régi) fájlban nincs port proxy és alagút.
        "port_proxies": port_proxies,
        "tunnels": tunnels,
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

    def prepare_tunnels(self, tunnels) -> dict:
        """Az alagút szakasz érvényesítése (fájlírás nélkül)."""
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
        """A beállításfájl törlése és az állapot alaphelyzetbe állítása."""
        with self._lock:
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self._data = self._defaults()
            self._error = ""
            self.legacy_proxy_domain = ""

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

    def set_motd(self, text: str, expires_at: str = "") -> dict:
        """A bejelentkezés utáni közlemény mentése.

        Üres szöveg kikapcsolja; üres lejárat állandó érvényességet jelent.
        Csak a beállításfájlt írja atomikusan; az nftables-hez nem nyúl.
        """
        with self._lock:
            data = self._copy_locked()
        data["motd_text"] = text
        data["motd_expires_at"] = expires_at
        return self.commit(data)

    def set_proxy_acme(self, enabled: bool) -> dict:
        """Az automatikus (on-demand ACME) tanúsítványkérés be/ki."""
        if not isinstance(enabled, bool):
            raise SettingsError("a proxy_acme mező igaz/hamis érték kell")
        with self._lock:
            data = self._copy_locked()
        data["proxy_acme"] = enabled
        return self.commit(data)

    def set_portal_domain(self, domain: str) -> dict:
        """A Dropjak felület saját Caddy-domainje (üres: a gyökérdomainek).

        Kikapcsoláskor a hozzá tartozó challenge is törlődik. Csak a
        beállításfájlt írja atomikusan; az nftables-hez nem nyúl.
        """
        if not isinstance(domain, str):
            raise SettingsError("portal_domain: szöveg kell")
        with self._lock:
            data = self._copy_locked()
        data["portal_domain"] = domain
        if not domain.strip():
            data["portal_challenge"] = None
        return self.commit(data)

    def set_proxy(self, domains, routes, referenced=(), portal_challenge=UNSET) -> dict:
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
            - {route_host(route) for route in routes}
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
        if portal_challenge is not UNSET:
            data["portal_challenge"] = portal_challenge
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

    def _check(
        self,
        root: str,
        chain: str,
        key: str,
        now: float,
        directory: str | None = None,
    ) -> dict:
        """A pár ellenőrzése ideiglenes 0600 fájlokon; a metaadatot adja."""
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

    def _validate_pair(
        self,
        root: str,
        chain,
        key,
        now: float | None = None,
        directory: str | None = None,
    ) -> tuple[str, str, str, dict]:
        """A PEM-pár teljes ellenőrzése írás nélkül (import és mentés)."""
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
        meta = self._check(
            root, chain, key,
            time.time() if now is None else now,
            directory,
        )
        return root, chain, key, meta

    def validate_import(self, root: str, chain, key) -> dict:
        """Egy importálandó pár ellenőrzése a tároló érintése nélkül.

        A lejárt pár is átkerül (a felület jelzi, a Caddy nem szolgálja ki);
        így egy korábbi állapot biztonsági mentésből visszaállítható.
        """
        with tempfile.TemporaryDirectory(prefix="hv-cert-import-") as tmp:
            return self._validate_pair(
                root, chain, key, now=0, directory=tmp
            )[3]

    def export_all(self) -> dict[str, dict]:
        """Az összes tárolt pár (PEM + kulcs) a konfigurációs csomaghoz."""
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
                    f"a(z) {root} tanúsítványpárja nem olvasható: {exc}"
                ) from exc
            out[root] = {"cert": chain, "key": key}
        return out

    def replace_all(self, certs) -> None:
        """Az összes pár cseréje; minden pár előbb ellenőrizve van."""
        if not isinstance(certs, dict):
            raise SettingsError("a certs szakasz JSON-objektum kell")
        checked: dict[str, tuple[str, str]] = {}
        for raw_root, item in certs.items():
            if not isinstance(item, dict):
                raise SettingsError(f"{raw_root}: hibás tanúsítványbejegyzés")
            root, chain, key, _meta = self._validate_pair(
                raw_root, item.get("cert"), item.get("key"), now=0
            )
            if root in checked:
                raise SettingsError(f"duplikált gyökérdomain: {root}")
            checked[root] = (chain, key)
        with self._lock:
            old = set(self._certs)
        for root in old - set(checked):
            self.delete(root)
        for root, (chain, key) in checked.items():
            self.install(root, chain, key, now=0)

    def reset(self) -> None:
        """Minden tárolt pár törlése (factory reset)."""
        try:
            names = os.listdir(self.directory)
        except FileNotFoundError:
            names = []
        except OSError as exc:
            raise SettingsError(
                f"a tanúsítványkönyvtár nem olvasható: {exc}"
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
        """Érvényes pár mentése (csere is); a metaadatot adja vissza."""
        root, chain, key, meta = self._validate_pair(root, chain, key, now)
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
