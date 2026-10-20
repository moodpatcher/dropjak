#!/usr/bin/env python3
"""
Dropjak — bejelentkezési brute-force védelem (fail2ban).

A portál a sikertelen jelszavas belépéseket forrás-IP szerint számolja egy
csúszóablakban. Ha egy IP eléri a beállított küszöböt, a tűzfal a
``banned_v4`` halmazba teszi: a forrás csomagjai a forward-láncban és a
host input láncában is eldobódnak. A portál és a DHCP kivétel: a tiltott
kliens még látja a tiltás okát, és a címe nem veszik el.

A tiltás a beállított ideig tart; a kernel timeoutja akkor is lejáratja,
ha a portál közben leáll. A tiltások a state-kötetben, 0600 jogosultságú
JSON-fájlban maradnak meg, és induláskor visszatöltődnek. A folyamatban
lévő próbálkozások csak memóriában vannak: egy újraindítás után a számláló
nulláról indul, ami nem gyengíti a védelmet (a tiltás megmarad).

A modul szándékosan nem nyúl közvetlenül az nftables-hez: a Firewall
objektumon keresztül dolgozik, és a tartós állapotot csak a sikeres
kernelművelet után írja.
"""

from __future__ import annotations

import ipaddress
import json
import os
import tempfile
import threading
import time


BASE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.environ.get("HV_STATE_DIR", "").strip() or BASE
FAIL2BAN_PATH = (
    os.environ.get("HV_FAIL2BAN_STATE", "").strip()
    or os.path.join(STATE_DIR, "fail2ban.json")
)

MIN_ATTEMPTS = 1
MAX_ATTEMPTS = 100
MIN_WINDOW = 30
MAX_WINDOW = 24 * 60 * 60
MIN_BAN = 60
MAX_BAN = 30 * 24 * 60 * 60
MAX_BANS = 4096
MAX_TRACKED_IPS = 4096


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


def _clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, int(value)))


DEFAULT_ENABLED = _env_bool("HV_FAIL2BAN", True)
DEFAULT_MAX_ATTEMPTS = _clamp(
    _env_int("HV_FAIL2BAN_MAX", 5, MIN_ATTEMPTS), MIN_ATTEMPTS, MAX_ATTEMPTS
)
DEFAULT_WINDOW = _clamp(
    _env_int("HV_FAIL2BAN_WINDOW", 600, MIN_WINDOW), MIN_WINDOW, MAX_WINDOW
)
DEFAULT_BAN = _clamp(
    _env_int("HV_FAIL2BAN_BAN", 3600, MIN_BAN), MIN_BAN, MAX_BAN
)

# A portál saját, helyi forgalmát (healthcheck, helyi adminisztráció) nem
# tiltjuk le automatikusan. A 127.0.0.0/8 többi címe (tesztkörnyezet) marad.
_AUTO_EXEMPT = {"127.0.0.1"}


def _default_log(message: str) -> None:
    print(message, flush=True)


class Fail2banError(ValueError):
    """Érvénytelen beállítás, cím vagy sikertelen tűzfal-művelet."""


def normalize_ip(value) -> str:
    """A tiltható IPv4-cím ellenőrzése és kanonikus alakja.

    A portál saját loopback címe (127.0.0.1), a 0.0.0.0, a multicast és a
    broadcast cím nem tiltható: ezek vagy a portál saját forgalmát érintenék,
    vagy nem értelmezhető források. A többi 127.0.0.0/8 cím (pl. teszt-
    források) tiltható marad.
    """
    if not isinstance(value, str):
        raise Fail2banError("érvénytelen IP-cím")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise Fail2banError(f"érvénytelen IP-cím: {value.strip()[:64]}") from exc
    if address.version != 4:
        raise Fail2banError("csak IPv4-cím tiltható le")
    if str(address) == "127.0.0.1":
        raise Fail2banError("a helyi (loopback) cím nem tiltható le")
    if address.is_unspecified:
        raise Fail2banError("a 0.0.0.0 cím nem tiltható le")
    if address.is_multicast:
        raise Fail2banError("a multicast cím nem tiltható le")
    if str(address) == "255.255.255.255":
        raise Fail2banError("a broadcast cím nem tiltható le")
    return str(address)


def validate_config(data, current: dict | None = None) -> dict:
    """A fail2ban-beállítások ellenőrzése; hiányzó mező a jelenlegi marad."""
    if not isinstance(data, dict):
        raise Fail2banError("a beállítás JSON-objektum kell")
    current = current or {
        "enabled": DEFAULT_ENABLED,
        "max_attempts": DEFAULT_MAX_ATTEMPTS,
        "window_seconds": DEFAULT_WINDOW,
        "ban_seconds": DEFAULT_BAN,
    }
    enabled = data.get("enabled", current["enabled"])
    if not isinstance(enabled, bool):
        raise Fail2banError("az enabled mező igaz/hamis érték kell")

    def integer(name: str, label: str, minimum: int, maximum: int) -> int:
        raw = data.get(name, current[name])
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise Fail2banError(f"{label}: egész szám kell")
        if raw < minimum or raw > maximum:
            raise Fail2banError(
                f"{label}: {minimum} és {maximum} között lehet"
            )
        return raw

    return {
        "enabled": enabled,
        "max_attempts": integer(
            "max_attempts", "a próbálkozások száma", MIN_ATTEMPTS, MAX_ATTEMPTS
        ),
        "window_seconds": integer(
            "window_seconds", "az időablak", MIN_WINDOW, MAX_WINDOW
        ),
        "ban_seconds": integer(
            "ban_seconds", "a tiltás hossza", MIN_BAN, MAX_BAN
        ),
    }


def _ban_view(record: dict, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    return {
        "ip": record["ip"],
        "since": int(record["since"]),
        "until": int(record["until"]),
        "remaining": max(0, int(record["until"] - now)),
        "attempts": int(record.get("attempts", 0)),
        "user": record.get("user", ""),
        "manual": bool(record.get("manual", False)),
        "reason": "manual" if record.get("manual") else "auto",
    }


class Fail2ban:
    """A sikertelen belépések számlálása és a forrás-IP-k tiltása."""

    def __init__(
        self,
        firewall,
        path: str = FAIL2BAN_PATH,
        audit=None,
        logger=_default_log,
        enabled: bool = DEFAULT_ENABLED,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        window_seconds: int = DEFAULT_WINDOW,
        ban_seconds: int = DEFAULT_BAN,
        on_ban=None,
    ) -> None:
        self.firewall = firewall
        self.path = os.path.abspath(path)
        self.audit = audit
        self.log = logger
        self._on_ban = on_ban
        self._lock = threading.RLock()
        self._config = {
            "enabled": bool(enabled),
            "max_attempts": _clamp(max_attempts, MIN_ATTEMPTS, MAX_ATTEMPTS),
            "window_seconds": _clamp(window_seconds, MIN_WINDOW, MAX_WINDOW),
            "ban_seconds": _clamp(ban_seconds, MIN_BAN, MAX_BAN),
        }
        # IP -> {"times": [timestamp, ...], "user": str}; nem perzisztált.
        self._attempts: dict[str, dict] = {}
        # IP -> ban rekord; perzisztált.
        self._bans: dict[str, dict] = {}
        self._error = ""
        # A legutóbb látott fájl-azonosító. A CLI külön folyamatként írja a
        # fail2ban.json-t; ha a fájl megváltozott, a portál a következő
        # műveletnél újratölti, hogy a felület ne mutasson elavult listát.
        self._disk_stamp: tuple[int, int, int] | None = None
        self.load()

    # -- állapot ---------------------------------------------------------------

    def _file_stamp(self) -> tuple[int, int, int] | None:
        try:
            info = os.stat(self.path)
        except OSError:
            return None
        return (info.st_ino, info.st_mtime_ns, info.st_size)

    def _refresh_locked(self) -> None:
        """A fájl külső (CLI) módosításának átvétele a memóriába.

        A portál minden saját mentés után frissíti a pecsétet, ezért ez a
        normál működésben nem tölt újra. Ha a CLI rootként módosítja a
        tiltáslistát, a következő snapshot/művelet már a fájl szerinti
        állapotot látja. Sérült vagy eltűnt fájlnál a memóriabeli állapot
        marad (a kernelben lévő tiltások ettől még élnek).
        """
        if self._file_stamp() != self._disk_stamp:
            self.load()

    def load(self) -> None:
        """A fail2ban.json betöltése.

        Sérült fájl esetén a konfiguráció a környezeti alapértékre áll, a
        tiltáslista üres lesz. Ez nem nyit utat: a hozzáférés továbbra is
        fail-closed, csak a korábbi tiltások nem töltődnek vissza.
        """
        stamp = self._file_stamp()
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except FileNotFoundError:
            with self._lock:
                self._error = ""
                self._disk_stamp = None
            return
        except (OSError, ValueError) as exc:
            with self._lock:
                self._error = str(exc)
                self._disk_stamp = stamp
            self.log(
                f"[fail2ban] FIGYELEM: a(z) {self.path} nem olvasható, "
                f"a tiltáslista üres: {exc}"
            )
            return
        if not isinstance(raw, dict):
            with self._lock:
                self._error = "a fájl JSON-objektum kell"
                self._disk_stamp = stamp
            self.log(
                f"[fail2ban] FIGYELEM: a(z) {self.path} formátuma hibás, "
                "a tiltáslista üres"
            )
            return
        config = dict(self._config)
        raw_config = raw.get("config")
        if isinstance(raw_config, dict):
            try:
                config = validate_config(raw_config, config)
            except Fail2banError as exc:
                self.log(
                    f"[fail2ban] FIGYELEM: érvénytelen mentett beállítás, "
                    f"alapértelmezés használata: {exc}"
                )
        now = time.time()
        bans: dict[str, dict] = {}
        raw_bans = raw.get("bans", [])
        if not isinstance(raw_bans, list):
            raw_bans = []
        for item in raw_bans:
            record = self._parse_record(item, now)
            if record is None:
                continue
            if len(bans) >= MAX_BANS:
                break
            bans[record["ip"]] = record
        with self._lock:
            self._config = config
            self._bans = bans
            self._error = ""
            self._disk_stamp = stamp

    @staticmethod
    def _parse_record(item, now: float) -> dict | None:
        if not isinstance(item, dict):
            return None
        try:
            ip = normalize_ip(item.get("ip"))
        except Fail2banError:
            return None
        try:
            since = float(item.get("since", 0))
            until = float(item.get("until", 0))
        except (TypeError, ValueError):
            return None
        if until <= now or since <= 0:
            return None
        attempts = item.get("attempts", 0)
        if isinstance(attempts, bool) or not isinstance(attempts, int):
            attempts = 0
        user = item.get("user", "")
        if not isinstance(user, str):
            user = ""
        return {
            "ip": ip,
            "since": since,
            "until": min(until, now + MAX_BAN),
            "attempts": max(0, attempts),
            "user": user[:64],
            "manual": bool(item.get("manual", False)),
        }

    def _payload_locked(self) -> dict:
        return {
            "version": 1,
            "config": dict(self._config),
            "bans": [
                {
                    "ip": record["ip"],
                    "since": record["since"],
                    "until": record["until"],
                    "attempts": record["attempts"],
                    "user": record["user"],
                    "manual": record["manual"],
                }
                for record in sorted(
                    self._bans.values(), key=lambda row: row["since"]
                )
            ],
        }

    def _state_owner(self, directory: str) -> tuple[int, int] | None:
        """A mentett fájl tulajdonosa.

        A portál a state-köteten a szolgáltatásfelhasználóval fut, a CLI
        viszont rootként indul. Ha a root CLI felülírná a fájlt, az a root
        tulajdonába kerülne, és a futó portál a következő mentésnél már nem
        tudná írni. Ezért a meglévő fájl (vagy új fájlnál a könyvtár)
        tulajdonosát megtartjuk.
        """
        for candidate in (self.path, directory):
            try:
                info = os.stat(candidate)
            except OSError:
                continue
            return info.st_uid, info.st_gid
        return None

    def _save_locked(self, raise_errors: bool = False) -> bool:
        payload = self._payload_locked()
        directory = os.path.dirname(self.path) or "."
        try:
            os.makedirs(directory, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(
                dir=directory, prefix=".fail2ban-", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, ensure_ascii=False, indent=2)
                    fh.write("\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                os.chmod(tmp_path, 0o600)
                owner = self._state_owner(directory)
                if owner is not None and os.geteuid() == 0:
                    try:
                        os.chown(tmp_path, owner[0], owner[1])
                    except OSError:
                        pass
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
                self._disk_stamp = self._file_stamp()
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except OSError as exc:
            self._error = str(exc)
            self.log(f"[fail2ban] FIGYELEM: a(z) {self.path} mentése nem sikerült: {exc}")
            if raise_errors:
                raise Fail2banError(f"a tiltáslista mentése nem sikerült: {exc}") from exc
            return False
        self._error = ""
        return True

    # -- számlálás -------------------------------------------------------------

    def _prune_attempts_locked(self, now: float) -> None:
        window = self._config["window_seconds"]
        for ip, entry in list(self._attempts.items()):
            times = [stamp for stamp in entry["times"] if now - stamp <= window]
            if times:
                entry["times"] = times
            else:
                del self._attempts[ip]
        if len(self._attempts) > MAX_TRACKED_IPS:
            ordered = sorted(
                self._attempts.items(),
                key=lambda pair: pair[1]["times"][-1],
            )
            for ip, _ in ordered[: len(self._attempts) - MAX_TRACKED_IPS]:
                del self._attempts[ip]

    def _notify(self, record: dict) -> None:
        if self._on_ban is None:
            return
        try:
            self._on_ban(record)
        except Exception as exc:  # a tiltás akkor is érvényes marad
            self.log(f"[fail2ban] a tiltás utókezelése nem sikerült: {exc}")

    def record_failure(self, ip: str, user: str = "") -> dict | None:
        """Sikertelen belépés rögzítése; tiltás esetén a rekordot adja vissza."""
        try:
            address = normalize_ip(ip)
        except Fail2banError:
            return None
        if address in _AUTO_EXEMPT:
            return None
        record = None
        with self._lock:
            self._refresh_locked()
            if not self._config["enabled"]:
                return None
            now = time.time()
            existing = self._bans.get(address)
            if existing is not None:
                if existing["until"] > now:
                    return _ban_view(existing, now)
                del self._bans[address]
            entry = self._attempts.get(address) or {"times": [], "user": ""}
            times = [
                stamp
                for stamp in entry["times"]
                if now - stamp <= self._config["window_seconds"]
            ]
            times.append(now)
            user = (user or entry.get("user") or "").strip()[:64]
            self._attempts[address] = {"times": times, "user": user}
            self._prune_attempts_locked(now)
            if len(times) < self._config["max_attempts"]:
                return None
            record = self._ban_locked(
                address,
                self._config["ban_seconds"],
                manual=False,
                user=user,
                attempts=len(times),
            )
            view = _ban_view(record, time.time())
        self._notify(view)
        return view

    def record_success(self, ip: str) -> None:
        """Sikeres belépés után a próbálkozások nullázása (a tiltás marad)."""
        try:
            address = normalize_ip(ip)
        except Fail2banError:
            return
        with self._lock:
            self._attempts.pop(address, None)

    def banned(self, ip: str) -> dict | None:
        """Az IP aktív tiltása, vagy None."""
        try:
            address = normalize_ip(ip)
        except Fail2banError:
            return None
        now = time.time()
        with self._lock:
            self._refresh_locked()
            record = self._bans.get(address)
            if record is None:
                return None
            if record["until"] <= now:
                del self._bans[address]
                return None
            return _ban_view(record, now)

    def _ban_locked(
        self,
        address: str,
        seconds: int,
        *,
        manual: bool,
        user: str = "",
        attempts: int = 0,
    ) -> dict:
        seconds = _clamp(int(seconds), MIN_BAN, MAX_BAN)
        now = time.time()
        try:
            self.firewall.ban(address, seconds)
        except Exception as exc:
            raise Fail2banError(
                f"a(z) {address} tűzfal-tiltása nem sikerült: {exc}"
            ) from exc
        existing = self._bans.get(address)
        since = existing["since"] if existing is not None else now
        record = {
            "ip": address,
            "since": since,
            "until": now + seconds,
            "attempts": max(int(attempts or 0), (existing or {}).get("attempts", 0)),
            "user": (user or (existing or {}).get("user", ""))[:64],
            "manual": bool(manual or (existing or {}).get("manual", False)),
        }
        if len(self._bans) >= MAX_BANS and address not in self._bans:
            oldest = min(
                self._bans.values(), key=lambda row: row["since"]
            )
            del self._bans[oldest["ip"]]
            self.log(
                f"[fail2ban] a tiltáslista megtelt; a legrégebbi bejegyzés "
                f"({oldest['ip']}) kikerült a nyilvántartásból"
            )
        self._bans[address] = record
        self._attempts.pop(address, None)
        self._save_locked(raise_errors=False)
        return record

    def ban(
        self,
        ip: str,
        seconds: int = 0,
        *,
        manual: bool = True,
        user: str = "",
    ) -> dict:
        """Kézi tiltás; a tiltás a megadott vagy az alapértelmezett ideig tart."""
        address = normalize_ip(ip)
        if seconds in (None, ""):
            seconds = 0
        if isinstance(seconds, bool) or not isinstance(seconds, int):
            raise Fail2banError("a tiltás hossza egész szám (másodperc) kell")
        if seconds <= 0:
            seconds = self._config["ban_seconds"]
        if seconds < MIN_BAN or seconds > MAX_BAN:
            raise Fail2banError(
                f"a tiltás hossza {MIN_BAN} és {MAX_BAN} másodperc között lehet"
            )
        with self._lock:
            self._refresh_locked()
            record = self._ban_locked(
                address, seconds, manual=manual, user=user
            )
            view = _ban_view(record, time.time())
        self._notify(view)
        return view

    def unban(self, ip: str) -> bool:
        """Egy tiltás feloldása a kernelben és a nyilvántartásban."""
        address = normalize_ip(ip)
        with self._lock:
            self._refresh_locked()
            known = address in self._bans
            try:
                self.firewall.unban(address)
            except Exception as exc:
                raise Fail2banError(
                    f"a(z) {address} tiltásának feloldása nem sikerült: {exc}"
                ) from exc
            if known:
                del self._bans[address]
                self._save_locked(raise_errors=False)
        return known

    def unban_all(self) -> int:
        """Minden tiltás feloldása; a feloldott bejegyzések számát adja."""
        removed = 0
        with self._lock:
            self._refresh_locked()
            for address in list(self._bans):
                try:
                    self.firewall.unban(address)
                except Exception as exc:
                    self.log(
                        f"[fail2ban] a(z) {address} feloldása nem sikerült: {exc}"
                    )
                    continue
                del self._bans[address]
                removed += 1
            if removed:
                self._save_locked(raise_errors=False)
        return removed

    def configure(self, data: dict) -> dict:
        """Beállítások módosítása.

        Kikapcsoláskor az automatikus tiltások azonnal felszabadulnak, a
        kézi tiltások megmaradnak. A sorrend: kernel -> mentés -> memória;
        ha a mentés nem sikerül, a felszabadított automatikus tiltásokat
        visszaállítjuk.
        """
        with self._lock:
            self._refresh_locked()
            new_config = validate_config(data, self._config)
            was_enabled = self._config["enabled"]
            released: list[dict] = []
            if was_enabled and not new_config["enabled"]:
                for address, record in list(self._bans.items()):
                    if record["manual"]:
                        continue
                    try:
                        self.firewall.unban(address)
                    except Exception as exc:
                        raise Fail2banError(
                            f"a(z) {address} tiltásának feloldása nem sikerült: {exc}"
                        ) from exc
                    released.append(dict(record))
                    del self._bans[address]
            previous = dict(self._config)
            self._config = new_config
            try:
                self._save_locked(raise_errors=True)
            except Fail2banError:
                self._config = previous
                for record in released:
                    try:
                        remaining = max(MIN_BAN, int(record["until"] - time.time()))
                        self.firewall.ban(record["ip"], remaining)
                        self._bans[record["ip"]] = record
                    except Exception as exc:
                        self.log(
                            f"[fail2ban] a(z) {record['ip']} visszaállítása "
                            f"nem sikerült: {exc}"
                        )
                raise
            if not new_config["enabled"]:
                self._attempts.clear()
            return self.snapshot()

    # -- indulás és nézet ------------------------------------------------------

    def sync(self) -> bool:
        """A mentett tiltások visszatöltése a (frissen ürített) nft halmazba."""
        now = time.time()
        with self._lock:
            expired = [
                address
                for address, record in self._bans.items()
                if record["until"] <= now
            ]
            for address in expired:
                del self._bans[address]
            elements = [
                (record["ip"], max(MIN_BAN, int(record["until"] - now)))
                for record in self._bans.values()
            ]
            try:
                self.firewall.sync_bans(elements)
            except Exception as exc:
                self._error = str(exc)
                self.log(
                    "[fail2ban] FIGYELEM: a mentett tiltások visszatöltése "
                    f"nem sikerült: {exc}"
                )
                return False
            if expired:
                self._save_locked(raise_errors=False)
            return True

    def snapshot(self) -> dict:
        now = time.time()
        with self._lock:
            self._refresh_locked()
            expired = [
                address
                for address, record in self._bans.items()
                if record["until"] <= now
            ]
            for address in expired:
                del self._bans[address]
            self._prune_attempts_locked(now)
            bans = [
                _ban_view(record, now)
                for record in sorted(
                    self._bans.values(),
                    key=lambda row: (row["until"], row["ip"]),
                )
            ]
            pending = []
            for address, entry in self._attempts.items():
                times = entry.get("times") or []
                if not times:
                    continue
                pending.append(
                    {
                        "ip": address,
                        "count": len(times),
                        "max_attempts": self._config["max_attempts"],
                        "user": entry.get("user", ""),
                        "first_at": int(times[0]),
                        "expires_at": int(
                            times[0] + self._config["window_seconds"]
                        ),
                    }
                )
            pending.sort(key=lambda row: row["count"], reverse=True)
            config = dict(self._config)
            error = self._error
        return {
            "enabled": config["enabled"],
            "max_attempts": config["max_attempts"],
            "window_seconds": config["window_seconds"],
            "ban_seconds": config["ban_seconds"],
            "limits": {
                "min_attempts": MIN_ATTEMPTS,
                "max_attempts": MAX_ATTEMPTS,
                "min_window": MIN_WINDOW,
                "max_window": MAX_WINDOW,
                "min_ban": MIN_BAN,
                "max_ban": MAX_BAN,
            },
            "bans": bans,
            "banned_count": len(bans),
            "pending": pending,
            "server_time": now,
            "error": error,
        }

    def status(self) -> dict:
        """Rövid állapot a naplózáshoz."""
        snapshot = self.snapshot()
        return {
            "enabled": snapshot["enabled"],
            "banned": snapshot["banned_count"],
            "pending": len(snapshot["pending"]),
            "max_attempts": snapshot["max_attempts"],
            "window_seconds": snapshot["window_seconds"],
            "ban_seconds": snapshot["ban_seconds"],
            "error": snapshot["error"],
        }
