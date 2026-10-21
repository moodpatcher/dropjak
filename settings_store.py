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
``visibility`` ``private`` (domain szabály kell) vagy ``public`` (bárki). A régi,
egyetlen ``proxy_domain`` betöltéskor egyelemű listává alakul. A Caddy a portál loopback-végpontjait kérdezi
kérésenként, ezért a módosításhoz nincs újratöltés és nftables-művelet.

A beállítások a state-kötetben, 0600 jogosultságú JSON-fájlban maradnak
meg. A fájl sérülése esetén a pre-auth lista üres marad (fail-closed);
az admin a felületen felülírhatja.

A modul szándékosan nem nyúl az nftables-hez: a Gateway alkalmazza a
szabályokat, és csak siker esetén commitálja a fájlt.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import secrets
import tempfile
import threading


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
        routes.append(route)
    return routes


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
