#!/usr/bin/env python3
"""
Dropjak — a tűzfal adminisztrátori testreszabása.

Két, a portálon kezelhető szabálytípust tárol:

* ``preauth``: bejelentkezés előtt is nyitva lévő célok és portok. Ezeket
  a forward lánc a portál-munkamenet nélkül is átengedi (és megjelöli a
  Docker-védelemhez). Csak akkor használható, ha a cél és a port tudatosan
  nyilvános.
* ``block``: mindig eldobott célok és portok. A blokk a pre-auth szabályt
  is felülbírálja.

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

HOST_SSH_MODES = ("admin", "any", "off")
DEFAULT_HOST_SSH = os.environ.get("HV_HOST_SSH", "admin").strip().lower()
if DEFAULT_HOST_SSH not in HOST_SSH_MODES:
    DEFAULT_HOST_SSH = "admin"

MAX_ENTRIES = 64
MAX_PORTS = 64
MAX_LABEL = 64
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


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


def _normalize_dst(raw, required: bool) -> str:
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise SettingsError("cél: szöveg kell (IP vagy CIDR)")
    raw = raw.strip()
    if not raw:
        if required:
            raise SettingsError("a pre-auth bejegyzéshez cél szükséges")
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
    dst = _normalize_dst(entry.get("dst", ""), required=(kind == "preauth"))
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


def validate_state(data) -> dict:
    if not isinstance(data, dict):
        raise SettingsError("a beállítások JSON-objektum kell")
    host_ssh = str(data.get("host_ssh", DEFAULT_HOST_SSH)).strip().lower()
    if host_ssh not in HOST_SSH_MODES:
        raise SettingsError(
            "a host SSH szabály értéke admin, any vagy off lehet"
        )
    result = {"host_ssh": host_ssh, "preauth": [], "block": []}
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
        default_host_ssh: str = DEFAULT_HOST_SSH,
    ) -> None:
        self.path = os.path.abspath(path)
        self.log = logger
        self.default_host_ssh = (
            default_host_ssh
            if default_host_ssh in HOST_SSH_MODES
            else "admin"
        )
        self._lock = threading.Lock()
        self._data = {
            "host_ssh": self.default_host_ssh,
            "preauth": [],
            "block": [],
        }
        self._error = ""
        self.load()

    def _defaults(self) -> dict:
        return {
            "host_ssh": self.default_host_ssh,
            "preauth": [],
            "block": [],
        }

    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            data = validate_state(raw)
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
        with self._lock:
            self._data = data
            self._error = ""

    def snapshot(self) -> dict:
        with self._lock:
            data = copy.deepcopy(self._data)
            data["error"] = self._error
            return data

    @property
    def host_ssh(self) -> str:
        with self._lock:
            return self._data["host_ssh"]

    def _copy_locked(self) -> dict:
        return copy.deepcopy(self._data)

    def prepare(
        self,
        action: str,
        kind: str = "",
        entry_id: str = "",
        entry=None,
        host_ssh: str = "",
    ) -> dict:
        """A módosítás érvényesítése és az új állapot előállítása.

        Nem ír fájlt és nem módosítja a memóriabeli állapotot; a hívó
        előbb az nftables-re alkalmazza, majd commit()-tal menti.
        """
        with self._lock:
            data = self._copy_locked()
        action = str(action or "").strip().lower()
        if action == "host_ssh":
            mode = str(host_ssh or "").strip().lower()
            if mode not in HOST_SSH_MODES:
                raise SettingsError(
                    "a host SSH szabály értéke admin, any vagy off lehet"
                )
            data["host_ssh"] = mode
            return validate_state(data)
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
