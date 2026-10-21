#!/usr/bin/env python3
"""
Dropjak — bejelentkezési brute-force védelem (fail2ban).

A portál a sikertelen jelszavas belépéseket forrás-IP szerint számolja egy
csúszóablakban. Ha egy IP eléri a beállított küszöböt, a tűzfal a
``banned_v4`` halmazba teszi: a forrás csomagjai a forward-láncban és a
host input láncában is eldobódnak. A portál és a DHCP kivétel: a tiltott
kliens még látja a tiltás okát, és a címe nem veszik el.

Ugyanez a számláló a bejelentkezés nélküli, engedély nélküli TCP-forgalmat
is figyeli (``record_drop``). A portszkennerek és botok így akkor is
tiltás alá kerülnek, ha soha nem próbálnak belépni: a tiltás a csúszóablakban
összegyűlt eldobott csomagok száma vagy a különböző célportok száma alapján
indul. A DNS és a portál forgalma nem számít.

A három figyelt jelzés egymástól függetlenül kapcsolható: a sikertelen
belépéseké (``enabled``), az eldobott csomagoké (``drop_count_enabled``) és
a különböző célportoké (``drop_ports_enabled``). Egyik kapcsoló sem függ a
másiktól, és a küszöbök nem lehetnek nullák: a kikapcsolás egyetlen módja a
kapcsoló. A ``drop_enabled`` mező csak visszamenőleges kompatibilitás miatt
szerepel a kimenetben; értéke a két drop-mérőszám VAGY kapcsolata.

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
# A küszöbök nem lehetnek nullák: a mérőszámot kizárólag a saját
# kapcsolója kapcsolja ki. A számláló legfeljebb MAX_DROP_EVENTS eseményt
# tárol IP-nként; ennél nagyobb küszöböt nem lehet elérni, ezért a maximum
# ugyanaz.
MIN_DROP_MAX = 1
MAX_DROP_MAX = 10000
MIN_DROP_PORTS = 1
MAX_DROP_PORTS = 4096
MIN_DROP_WINDOW = 30
MAX_DROP_WINDOW = 24 * 60 * 60
MAX_BANS = 4096
MAX_TRACKED_IPS = 4096
MAX_DROP_EVENTS = 10000
# Az evictionkor sikertelenül feloldott kernel-elemek újrapróbálási sora
# legfeljebb ennyi címet tart. A sor nem perzisztált, és nem nőhet
# korlátlanul: ha megtelik, a legrégebbi árva elem a TTL lejártáig marad.
MAX_ORPHAN_UNBANS = 256


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, value)


def _env_int_in_range(
    name: str, default: int, minimum: int, maximum: int
) -> int:
    """Egész környezeti érték; érvénytelen vagy tartományon kívüli -> default.

    A küszöböknél a 0 érvénytelen: a mérőszámot csak a saját kapcsolója
    kapcsolhatja ki. Ezért a nulla (és a negatív) értéket nem szabad
    átengedni vagy 0-ra vágni, mert az csendben kikapcsolná a védelmet;
    ilyenkor az alapérték marad.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value < minimum or value > maximum:
        return default
    return value


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


def _drop_metric_state(config: dict) -> tuple[bool, bool]:
    """A két drop-mérőszám aktív állapota (csomagszám, különböző portok).

    Mindkét mérőszám kizárólag a saját kapcsolójától függ; a ``drop_enabled``
    csak számított kompatibilitási mező, ezért itt nem kapuz. A küszöb
    védőfeltétel: érvényes konfigurációban sosem 0, de egy korábbról
    betöltött vagy kézzel módosított érték se kapcsolhasson be mérőszámot
    nulla küszöbbel.
    """
    count_active = (
        bool(config.get("drop_count_enabled", True))
        and int(config.get("drop_max", 0)) > 0
    )
    ports_active = (
        bool(config.get("drop_ports_enabled", True))
        and int(config.get("drop_ports", 0)) > 0
    )
    return count_active, ports_active


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
# Hálózati forgalom alapú tiltás: a portál a drop logból számolja az
# engedély nélküli csomagokat. A küszöböt vagy a különböző portok számát
# elérve az IP bekerül a banned_v4 halmazba. A portszám-alapú feltétel a
# portszkennereket fogja meg, a darabszám-alapú az ismételt próbálkozásokat.
DEFAULT_DROP_ENABLED = _env_bool("HV_FAIL2BAN_DROP", True)
DEFAULT_DROP_COUNT_ENABLED = _env_bool(
    "HV_FAIL2BAN_DROP_COUNT_ENABLED", True
)
DEFAULT_DROP_PORTS_ENABLED = _env_bool(
    "HV_FAIL2BAN_DROP_PORTS_ENABLED", True
)
DEFAULT_DROP_MAX = _env_int_in_range(
    "HV_FAIL2BAN_DROP_MAX", 120, MIN_DROP_MAX, MAX_DROP_MAX
)
DEFAULT_DROP_PORTS = _env_int_in_range(
    "HV_FAIL2BAN_DROP_PORTS", 12, MIN_DROP_PORTS, MAX_DROP_PORTS
)
DEFAULT_DROP_WINDOW = _clamp(
    _env_int("HV_FAIL2BAN_DROP_WINDOW", 180, MIN_DROP_WINDOW),
    MIN_DROP_WINDOW,
    MAX_DROP_WINDOW,
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
    defaults = {
        "enabled": DEFAULT_ENABLED,
        "max_attempts": DEFAULT_MAX_ATTEMPTS,
        "window_seconds": DEFAULT_WINDOW,
        "ban_seconds": DEFAULT_BAN,
        "drop_enabled": DEFAULT_DROP_ENABLED,
        "drop_count_enabled": DEFAULT_DROP_COUNT_ENABLED,
        "drop_ports_enabled": DEFAULT_DROP_PORTS_ENABLED,
        "drop_max": DEFAULT_DROP_MAX,
        "drop_ports": DEFAULT_DROP_PORTS,
        "drop_window_seconds": DEFAULT_DROP_WINDOW,
    }
    # A mentett fájlból hiányzó új mezők az alapértéket kapják; a
    # jelenlegi konfiguráció értékei maradnak, ha a kérés nem írja felül.
    current = {**defaults, **(current or {})}
    enabled = data.get("enabled", current["enabled"])
    if not isinstance(enabled, bool):
        raise Fail2banError("az enabled mező igaz/hamis érték kell")
    # A drop_enabled csak visszamenőleges kompatibilitási bemenet: a régi
    # API/gyorsítótárazott UI a false értékkel kapcsolta ki a drop-alapú
    # tiltást. Ilyenkor mindkét mérőszám-kapcsolót kikényszerítjük; a true
    # érték nem kapcsol be semmit, mert a mérőszámok külön kapcsolhatók.
    legacy_drop = None
    if "drop_enabled" in data:
        legacy_drop = data["drop_enabled"]
        if not isinstance(legacy_drop, bool):
            raise Fail2banError("a drop_enabled mező igaz/hamis érték kell")
    drop_count_enabled = data.get(
        "drop_count_enabled", current["drop_count_enabled"]
    )
    if not isinstance(drop_count_enabled, bool):
        raise Fail2banError(
            "a drop_count_enabled mező igaz/hamis érték kell"
        )
    drop_ports_enabled = data.get(
        "drop_ports_enabled", current["drop_ports_enabled"]
    )
    if not isinstance(drop_ports_enabled, bool):
        raise Fail2banError(
            "a drop_ports_enabled mező igaz/hamis érték kell"
        )
    if legacy_drop is False:
        drop_count_enabled = False
        drop_ports_enabled = False

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
        "drop_enabled": drop_count_enabled or drop_ports_enabled,
        "drop_count_enabled": drop_count_enabled,
        "drop_ports_enabled": drop_ports_enabled,
        "drop_max": integer(
            "drop_max", "a hálózati küszöb", MIN_DROP_MAX, MAX_DROP_MAX
        ),
        "drop_ports": integer(
            "drop_ports", "a különböző portok száma",
            MIN_DROP_PORTS, MAX_DROP_PORTS,
        ),
        "drop_window_seconds": integer(
            "drop_window_seconds", "a hálózati időablak",
            MIN_DROP_WINDOW, MAX_DROP_WINDOW,
        ),
    }


def _ban_view(record: dict, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    manual = bool(record.get("manual", False))
    source = record.get("source")
    if source not in ("manual", "login", "drop"):
        source = "manual" if manual else "login"
    return {
        "ip": record["ip"],
        "since": int(record["since"]),
        "until": int(record["until"]),
        "remaining": max(0, int(record["until"] - now)),
        "attempts": int(record.get("attempts", 0)),
        "user": record.get("user", ""),
        "manual": manual,
        "source": source,
        "detail": record.get("detail", ""),
        "reason": "manual" if manual else "auto",
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
        drop_enabled: bool = DEFAULT_DROP_ENABLED,
        drop_count_enabled: bool = DEFAULT_DROP_COUNT_ENABLED,
        drop_ports_enabled: bool = DEFAULT_DROP_PORTS_ENABLED,
        drop_max: int = DEFAULT_DROP_MAX,
        drop_ports: int = DEFAULT_DROP_PORTS,
        drop_window_seconds: int = DEFAULT_DROP_WINDOW,
        on_ban=None,
    ) -> None:
        self.firewall = firewall
        self.path = os.path.abspath(path)
        self.audit = audit
        self.log = logger
        self._on_ban = on_ban
        self._lock = threading.RLock()
        # A drop_enabled paraméter csak első indulású kapu: a HV_FAIL2BAN_DROP
        # (vagy a programozott konstruktorhívás) false értéke mindkét
        # mérőszámot kikapcsolja. Futásidőben a mérőszámok egymástól
        # függetlenül kapcsolhatók.
        if not drop_enabled:
            drop_count_enabled = False
            drop_ports_enabled = False
        self._config = {
            "enabled": bool(enabled),
            "max_attempts": _clamp(max_attempts, MIN_ATTEMPTS, MAX_ATTEMPTS),
            "window_seconds": _clamp(window_seconds, MIN_WINDOW, MAX_WINDOW),
            "ban_seconds": _clamp(ban_seconds, MIN_BAN, MAX_BAN),
            "drop_enabled": bool(drop_count_enabled or drop_ports_enabled),
            "drop_count_enabled": bool(drop_count_enabled),
            "drop_ports_enabled": bool(drop_ports_enabled),
            "drop_max": _clamp(drop_max, MIN_DROP_MAX, MAX_DROP_MAX),
            "drop_ports": _clamp(drop_ports, MIN_DROP_PORTS, MAX_DROP_PORTS),
            "drop_window_seconds": _clamp(
                drop_window_seconds, MIN_DROP_WINDOW, MAX_DROP_WINDOW
            ),
        }
        # IP -> {"times": [timestamp, ...], "user": str}; nem perzisztált.
        self._attempts: dict[str, dict] = {}
        # IP -> {"events": [(timestamp, "proto/port"), ...], "reason": str};
        # nem perzisztált, mint a belépési próbálkozások.
        self._drop_events: dict[str, dict] = {}
        self._drop_event_count = 0
        # IP -> ban rekord; perzisztált.
        self._bans: dict[str, dict] = {}
        # Az evictionkor sikertelenül feloldott kernel-elemek címei. Nem
        # perzisztált; a következő műveleteknél újrapróbáljuk a törlést,
        # hogy ne maradjon láthatatlan, akár 30 napig élő tiltás.
        self._orphan_unbans: list[str] = []
        self._error = ""
        # A legutóbb látott fájl-azonosító. A CLI külön folyamatként írja a
        # fail2ban.json-t; ha a fájl megváltozott, a portál a következő
        # műveletnél újratölti, hogy a felület ne mutasson elavult listát.
        self._disk_stamp: tuple[int, int, int] | None = None
        self.load()

    # -- állapot ---------------------------------------------------------------

    def _write_audit(self, event: str, **fields) -> None:
        """Nem kötelező naplóbejegyzés; hiba esetén sem blokkol."""
        if self.audit is None:
            return
        try:
            self.audit.write(event, **fields)
        except Exception as exc:
            self.log(f"[napló] {event} írása nem sikerült: {exc}")

    def _queue_orphan_unban_locked(
        self, address: str, exc: Exception
    ) -> bool:
        """Egy sikertelen eviction-feloldás felvétele a korlátozott sorba.

        Visszaadja, hogy a cím bekerült-e a sorba. A sor tele lehet, mert
        nem nőhet korlátlanul; ilyenkor hangosan naplózunk és auditálunk,
        mert az árva kernel-elem a timeout lejártáig érvényben maradhat.
        """
        if address in self._orphan_unbans:
            return True
        if len(self._orphan_unbans) >= MAX_ORPHAN_UNBANS:
            self.log(
                f"[fail2ban] HIBA: az árva tiltás-feloldási sor tele van "
                f"({MAX_ORPHAN_UNBANS}); a(z) {address} kernel-eleme a "
                "timeout lejártáig érvényben maradhat"
            )
            self._write_audit(
                "fail2ban_ban_evict_failed",
                ip=address,
                reason=str(exc),
                queued=False,
                queue_limit=int(MAX_ORPHAN_UNBANS),
            )
            return False
        self._orphan_unbans.append(address)
        self._write_audit(
            "fail2ban_ban_evict_failed",
            ip=address,
            reason=str(exc),
            queued=True,
        )
        return True

    def _discard_orphan_locked(self, address: str) -> None:
        """A cím törlése az árva-sorból egy sikeres ban után.

        A ``Firewall.ban`` előbb törli, majd újra létrehozza a kernel-
        elemet, ezért a korábbi árva elem ezzel megszűnt.
        """
        try:
            self._orphan_unbans.remove(address)
        except ValueError:
            pass

    def _retry_orphan_unbans_locked(self) -> None:
        """A korábban sikertelen eviction-feloldások újrapróbálása.

        A sor elejéről haladunk, és az első hibánál megállunk: egy tartósan
        hibás tűzfal mellett így nem pörög folyamatosan a hívási lánc. A
        sikertelen cím a sorban marad. Ha a cím közben újra tiltás alá
        került, a kernel-elem már élő, ezért csak a sort tisztítjuk.
        """
        while self._orphan_unbans:
            address = self._orphan_unbans[0]
            if address in self._bans:
                self._orphan_unbans.pop(0)
                continue
            try:
                self.firewall.unban(address)
            except Exception as exc:
                self.log(
                    f"[fail2ban] a(z) {address} árva tiltásának feloldása "
                    f"még nem sikerült: {exc}"
                )
                return
            self._orphan_unbans.pop(0)

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
            self._write_audit("fail2ban_load_error", reason=str(exc))
            return
        if not isinstance(raw, dict):
            with self._lock:
                self._error = "a fájl JSON-objektum kell"
                self._disk_stamp = stamp
            self.log(
                f"[fail2ban] FIGYELEM: a(z) {self.path} formátuma hibás, "
                "a tiltáslista üres"
            )
            self._write_audit(
                "fail2ban_load_error", reason="a fájl JSON-objektum kell"
            )
            return
        config = dict(self._config)
        raw_config = raw.get("config")
        if isinstance(raw_config, dict):
            migrated = dict(raw_config)
            # Régi állapot migrálása: a 0 küszöb korábban az adott mérőszámot
            # kapcsolta ki. Ilyenkor ne az egész konfiguráció essen vissza az
            # alapértékre: csak azt a mérőszámot kapcsoljuk ki, és a küszöbét
            # állítjuk vissza az alapértékre. A kifejezetten mentett
            # drop_enabled=false továbbra is mindkét mérőszámot kikapcsolja.
            for threshold_key, flag_key, default_threshold in (
                ("drop_max", "drop_count_enabled", DEFAULT_DROP_MAX),
                ("drop_ports", "drop_ports_enabled", DEFAULT_DROP_PORTS),
            ):
                value = migrated.get(threshold_key)
                if (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value == 0
                ):
                    migrated[flag_key] = False
                    migrated[threshold_key] = default_threshold
            if migrated.get("drop_enabled") is False:
                migrated["drop_count_enabled"] = False
                migrated["drop_ports_enabled"] = False
            try:
                config = validate_config(migrated, config)
            except Fail2banError as exc:
                self.log(
                    f"[fail2ban] FIGYELEM: érvénytelen mentett beállítás, "
                    f"alapértelmezés használata: {exc}"
                )
                self._write_audit(
                    "fail2ban_load_error", reason=str(exc)
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
        manual = bool(item.get("manual", False))
        source = item.get("source", "")
        if source not in ("manual", "login", "drop"):
            source = "manual" if manual else "login"
        detail = item.get("detail", "")
        if not isinstance(detail, str):
            detail = ""
        return {
            "ip": ip,
            "since": since,
            "until": min(until, now + MAX_BAN),
            "attempts": max(0, attempts),
            "user": user[:64],
            "manual": manual,
            "source": source,
            "detail": detail[:64],
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
                    "source": record.get("source", ""),
                    "detail": record.get("detail", ""),
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

    def _prune_drop_events_locked(
        self, now: float, only: str | None = None
    ) -> None:
        """A hálózati események csúszóablakának karbantartása."""
        window = self._config["drop_window_seconds"]
        targets = [only] if only is not None else list(self._drop_events)
        for ip in targets:
            entry = self._drop_events.get(ip)
            if entry is None:
                continue
            events = [
                event for event in entry["events"]
                if now - event[0] <= window
            ]
            if events:
                entry["events"] = events
            else:
                del self._drop_events[ip]
        if only is None and len(self._drop_events) > MAX_TRACKED_IPS:
            ordered = sorted(
                self._drop_events.items(),
                key=lambda pair: pair[1]["events"][-1][0],
            )
            for ip, _ in ordered[: len(self._drop_events) - MAX_TRACKED_IPS]:
                del self._drop_events[ip]

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
                source="login",
            )
            view = _ban_view(record, time.time())
        self._notify(view)
        return view

    def record_drop(
        self,
        ip: str,
        *,
        proto: str = "",
        dport=None,
        reason: str = "",
        count_total: bool = True,
    ) -> dict | None:
        """Egy engedély nélküli/gyanús csomag rögzítése.

        A portál a drop logból hívja minden olyan eldobott csomagra, amely
        nem a portál saját forgalma. A tiltás akkor indul, ha az IP a
        beállított időablakban eléri a csomagszám-küszöböt, vagy elegendő
        különböző célportot próbál elérni (portszkennelés).

        A ``count_total=False`` események csak a különböző portok számához
        járulnak hozzá. A LAN-felőli ``no-grant``/``input-lan`` forgalomnál
        ez a helyes: egy kijelentkezett böngésző is sok TCP-próbát indít,
        de jellemzően csak néhány célporton.
        """
        try:
            address = normalize_ip(ip)
        except Fail2banError:
            return None
        if address in _AUTO_EXEMPT:
            return None
        proto = str(proto or "").strip().lower()[:16]
        port = 0
        if not isinstance(dport, bool):
            try:
                port = int(dport)
            except (TypeError, ValueError):
                port = 0
        if port < 1 or port > 65535:
            port = 0
        key = f"{proto}/{port}" if port else (proto or "?")
        reason = str(reason or "").strip()[:32] or "drop"
        with self._lock:
            self._refresh_locked()
            count_active, ports_active = _drop_metric_state(self._config)
            if not count_active and not ports_active:
                return None
            now = time.time()
            existing = self._bans.get(address)
            if existing is not None:
                if existing["until"] > now:
                    return None
                del self._bans[address]
            # Csak olyan eseményt tárolunk, amely valamelyik aktív
            # mérőszámhoz hozzá tud járulni. Kikapcsolt portmérőnél a
            # portinformációt sem őrizzük meg, és a LAN-esemény (amely nem
            # számít a csomagküszöbhöz) semleges.
            counted = bool(count_total) and count_active
            port_key = key if ports_active and "/" in key else ""
            if not counted and not port_key:
                return None
            self._prune_drop_events_locked(now, only=address)
            entry = self._drop_events.get(address) or {
                "events": [], "reason": "",
            }
            events = entry["events"]
            events.append((now, port_key, counted))
            # A korlátot mindkét aktív küszöbhöz méretezzük, hogy egy kicsi
            # drop_max ne vágja le a nagy drop_ports által igényelt
            # eseménysort.
            cap = min(
                max(
                    count_active * (self._config["drop_max"] + 1),
                    ports_active * (self._config["drop_ports"] + 1),
                    512,
                ),
                MAX_DROP_EVENTS,
            )
            if len(events) > cap:
                del events[:-cap]
            entry["reason"] = reason
            self._drop_events[address] = entry
            self._drop_event_count += 1
            if self._drop_event_count % 256 == 0:
                self._prune_drop_events_locked(now)
            ports = {
                event_key for _, event_key, _ in events if "/" in event_key
            }
            total = sum(1 for _, _, counted in events if counted)
            if not (
                (count_active and total >= self._config["drop_max"])
                or (ports_active and len(ports) >= self._config["drop_ports"])
            ):
                return None
            record = self._ban_locked(
                address,
                self._config["ban_seconds"],
                manual=False,
                user="",
                attempts=len(events),
                source="drop",
                detail=reason,
            )
            self._drop_events.pop(address, None)
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
            self._retry_orphan_unbans_locked()
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
        source: str = "",
        detail: str = "",
    ) -> dict:
        seconds = _clamp(int(seconds), MIN_BAN, MAX_BAN)
        now = time.time()
        # Előbb a korábbi evictionökből visszamaradt árva elemeket
        # próbáljuk törölni; ez nem blokkolhatja az új védő tiltást.
        self._retry_orphan_unbans_locked()
        try:
            self.firewall.ban(address, seconds)
        except Exception as exc:
            raise Fail2banError(
                f"a(z) {address} tűzfal-tiltása nem sikerült: {exc}"
            ) from exc
        # A ban() a kernelben felülírja az esetleges korábbi elemet, ezért
        # az ehhez a címhez tartozó árva bejegyzés már nem takarítható.
        self._discard_orphan_locked(address)
        existing = self._bans.get(address)
        since = existing["since"] if existing is not None else now
        is_manual = bool(manual or (existing or {}).get("manual", False))
        if is_manual:
            source = "manual"
        elif source not in ("login", "drop"):
            source = (existing or {}).get("source") or "login"
        if source == "manual":
            detail = ""
        elif not detail:
            detail = (existing or {}).get("detail", "")
        record = {
            "ip": address,
            "since": since,
            "until": now + seconds,
            "attempts": max(int(attempts or 0), (existing or {}).get("attempts", 0)),
            "user": (user or (existing or {}).get("user", ""))[:64],
            "manual": is_manual,
            "source": source,
            "detail": str(detail or "")[:64],
        }
        if len(self._bans) >= MAX_BANS and address not in self._bans:
            oldest = min(
                self._bans.values(), key=lambda row: row["since"]
            )
            # A memóriarekord eldobása előtt a kernel-elemet is fel kell
            # oldani, különben egy láthatatlan tiltás maradna a TTL-ig.
            kernel_released = True
            try:
                self.firewall.unban(oldest["ip"])
            except Exception as exc:
                kernel_released = False
                self._queue_orphan_unban_locked(oldest["ip"], exc)
                self.log(
                    f"[fail2ban] FIGYELEM: a(z) {oldest['ip']} kikerülő "
                    f"tiltásának kernel-feloldása nem sikerült: {exc}; "
                    "a következő műveleteknél újrapróbáljuk"
                )
            del self._bans[oldest["ip"]]
            self.log(
                f"[fail2ban] a tiltáslista megtelt; a legrégebbi bejegyzés "
                f"({oldest['ip']}) kikerült a nyilvántartásból"
            )
            self._write_audit(
                "fail2ban_ban_evicted",
                ip=oldest["ip"],
                reason="max_bans",
                kernel_released=kernel_released,
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
            self._retry_orphan_unbans_locked()
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

        A három jelzés független: a sikertelen belépés figyelésének
        kikapcsolása csak a belépés-alapú, a két drop-mérőszám együttes
        kikapcsolása csak a drop-alapú automatikus tiltásokat szabadítja
        fel. A kézi tiltások mindig megmaradnak. A sorrend:
        kernel -> mentés -> memória.

        A felszabadítás best-effort: minden szükséges feloldást
        megkísérlünk. Ha bármelyik nem sikerült, a beállítás változatlan
        marad; a már felszabadított tiltásokat a pontos hátralévő idővel
        visszaállítjuk, és a memóriarekordjaikat akkor is visszatesszük,
        ha az újratiltás nem sikerült. Így nem marad néma, részleges
        állapot. A mentés hibája esetén ugyanez a visszaállítás fut.
        """
        with self._lock:
            self._refresh_locked()
            new_config = validate_config(data, self._config)
            was_enabled = self._config["enabled"]
            was_drop = self._config["drop_enabled"]
            released: list[dict] = []
            failed: list[tuple[dict, Exception]] = []
            release_login = was_enabled and not new_config["enabled"]
            release_drop = was_drop and not new_config["drop_enabled"]
            if release_login or release_drop:
                for address, record in list(self._bans.items()):
                    if record["manual"]:
                        continue
                    source = record.get("source")
                    if release_login and source != "drop":
                        pass
                    elif release_drop and source == "drop":
                        pass
                    else:
                        continue
                    try:
                        self.firewall.unban(address)
                    except Exception as exc:
                        failed.append((dict(record), exc))
                        self.log(
                            f"[fail2ban] a(z) {address} feloldása nem "
                            f"sikerült: {exc}"
                        )
                        continue
                    released.append(dict(record))
                    del self._bans[address]
            if failed:
                # A konfiguráció nem változott. A már felszabadított
                # tiltásokat a pontos hátralévő idővel állítjuk vissza; a
                # memóriarekord mindenképp visszakerül.
                restored = 0
                for record in released:
                    remaining = max(1, int(record["until"] - time.time()))
                    try:
                        self.firewall.ban(record["ip"], remaining)
                        restored += 1
                    except Exception as exc:
                        self._error = str(exc)
                        self.log(
                            f"[fail2ban] a(z) {record['ip']} visszaállítása "
                            f"nem sikerült: {exc}"
                        )
                        self._write_audit(
                            "fail2ban_ban_restore_failed",
                            ip=record["ip"],
                            reason=str(exc),
                        )
                    self._bans[record["ip"]] = record
                self._write_audit(
                    "fail2ban_bans_release_failed",
                    count=len(failed),
                    reason=str(failed[0][1]),
                    restored=restored,
                )
                raise Fail2banError(
                    "a tiltások felszabadítása nem sikerült "
                    f"({len(failed)} cím); a beállítás változatlan maradt"
                )
            previous = dict(self._config)
            self._config = new_config
            try:
                self._save_locked(raise_errors=True)
            except Fail2banError:
                self._config = previous
                for record in released:
                    remaining = max(1, int(record["until"] - time.time()))
                    try:
                        self.firewall.ban(record["ip"], remaining)
                    except Exception as exc:
                        self._error = str(exc)
                        self.log(
                            f"[fail2ban] a(z) {record['ip']} visszaállítása "
                            f"nem sikerült: {exc}"
                        )
                        self._write_audit(
                            "fail2ban_ban_restore_failed",
                            ip=record["ip"],
                            reason=str(exc),
                        )
                    # A rekordot a sikertelen újratiltás után is vissza kell
                    # tenni: a felület ne felejtse el a tiltást.
                    self._bans[record["ip"]] = record
                raise
            if not new_config["enabled"]:
                self._attempts.clear()
            # A drop mesterállapota, bármelyik mérőszám-kapcsoló vagy a
            # küszöbök változása után a régi számlálók nem érvényesek az új
            # konfiguráció alatt. A belépés-figyelés kikapcsolása önmagában
            # nem érinti a drop-számlálókat.
            if (
                previous["drop_enabled"] != new_config["drop_enabled"]
                or previous["drop_count_enabled"]
                != new_config["drop_count_enabled"]
                or previous["drop_ports_enabled"]
                != new_config["drop_ports_enabled"]
                or previous["drop_max"] != new_config["drop_max"]
                or previous["drop_ports"] != new_config["drop_ports"]
            ):
                self._drop_events.clear()
                self._drop_event_count = 0
            if released:
                # A naplóban a forrás szerinti bontás is szerepel, hogy a
                # belépés és a drop együttes kikapcsolása ne veszítse el
                # a drop-rész információját.
                login_count = sum(
                    1 for record in released
                    if release_login and record.get("source") != "drop"
                )
                drop_count = sum(
                    1 for record in released
                    if release_drop and record.get("source") == "drop"
                )
                self._write_audit(
                    "fail2ban_bans_released",
                    count=len(released),
                    reason="disabled" if release_login else "drop_disabled",
                    login_count=login_count,
                    drop_count=drop_count,
                )
            return self.snapshot()

    # -- indulás és nézet ------------------------------------------------------

    def sync(self) -> bool:
        """A mentett tiltások visszatöltése a (frissen ürített) nft halmazba.

        A hátralévő időt pontosan, egész másodpercre vágva adjuk át; a
        ``MIN_BAN`` csak alsó korlát, nem kerekítés. A lejárt rekordokat
        kihagyjuk, a nulla vagy negatív hátralévő idő nem kerül a kernelbe.
        """
        with self._lock:
            self._retry_orphan_unbans_locked()
            now = time.time()
            expired = [
                address
                for address, record in self._bans.items()
                if record["until"] <= now
            ]
            for address in expired:
                del self._bans[address]
            elements = []
            for record in self._bans.values():
                remaining = int(record["until"] - now)
                if remaining <= 0:
                    continue
                elements.append((record["ip"], max(1, remaining)))
            try:
                self.firewall.sync_bans(elements)
            except Exception as exc:
                self._error = str(exc)
                self.log(
                    "[fail2ban] FIGYELEM: a mentett tiltások visszatöltése "
                    f"nem sikerült: {exc}"
                )
                self._write_audit(
                    "fail2ban_sync_failed",
                    reason=str(exc),
                    count=len(elements),
                )
                return False
            # A sync_bans() a halmazt teljesen üríti, és csak az ismert
            # tiltásokat teszi vissza; az árva elemek ezzel eltűntek.
            self._orphan_unbans.clear()
            if expired:
                self._save_locked(raise_errors=False)
            return True

    def snapshot(self) -> dict:
        now = time.time()
        with self._lock:
            self._refresh_locked()
            self._retry_orphan_unbans_locked()
            expired = [
                address
                for address, record in self._bans.items()
                if record["until"] <= now
            ]
            for address in expired:
                del self._bans[address]
            self._prune_attempts_locked(now)
            self._prune_drop_events_locked(now)
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
            count_active, ports_active = _drop_metric_state(config)
            config_drop_max = config["drop_max"]
            config_drop_ports = config["drop_ports"]
            config_drop_window = config["drop_window_seconds"]
            drop_pending = []
            for address, entry in self._drop_events.items():
                events = entry.get("events") or []
                if not events:
                    continue
                ports = [
                    event_key.split("/", 1)[1]
                    for _, event_key, _ in events
                    if "/" in event_key
                ]
                distinct = sorted({int(port) for port in ports})
                drop_pending.append(
                    {
                        "ip": address,
                        "count": sum(1 for _, _, counted in events if counted),
                        "events": len(events),
                        "distinct_ports": len(set(distinct)),
                        "ports": distinct[:24],
                        "reason": entry.get("reason", ""),
                        "first_at": int(events[0][0]),
                        "expires_at": int(
                            events[0][0] + config_drop_window
                        ),
                        "max_drops": config_drop_max,
                        "max_ports": config_drop_ports,
                        "drop_count_enabled": config["drop_count_enabled"],
                        "drop_ports_enabled": config["drop_ports_enabled"],
                        "drop_count_active": count_active,
                        "drop_ports_active": ports_active,
                    }
                )
            drop_pending.sort(
                key=lambda row: (row["count"], row["distinct_ports"]),
                reverse=True,
            )
            error = self._error
        return {
            "enabled": config["enabled"],
            "max_attempts": config["max_attempts"],
            "window_seconds": config["window_seconds"],
            "ban_seconds": config["ban_seconds"],
            "drop_enabled": config["drop_enabled"],
            "drop_count_enabled": config["drop_count_enabled"],
            "drop_ports_enabled": config["drop_ports_enabled"],
            "drop_count_active": count_active,
            "drop_ports_active": ports_active,
            "drop_max": config["drop_max"],
            "drop_ports": config["drop_ports"],
            "drop_window_seconds": config["drop_window_seconds"],
            "limits": {
                "min_attempts": MIN_ATTEMPTS,
                "max_attempts": MAX_ATTEMPTS,
                "min_window": MIN_WINDOW,
                "max_window": MAX_WINDOW,
                "min_ban": MIN_BAN,
                "max_ban": MAX_BAN,
                "min_drop_max": MIN_DROP_MAX,
                "max_drop_max": MAX_DROP_MAX,
                "min_drop_ports": MIN_DROP_PORTS,
                "max_drop_ports": MAX_DROP_PORTS,
                "min_drop_window": MIN_DROP_WINDOW,
                "max_drop_window": MAX_DROP_WINDOW,
            },
            "bans": bans,
            "banned_count": len(bans),
            "pending": pending,
            "drop_pending": drop_pending,
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
            "drop_enabled": snapshot["drop_enabled"],
            "drop_count_enabled": snapshot["drop_count_enabled"],
            "drop_ports_enabled": snapshot["drop_ports_enabled"],
            "drop_count_active": snapshot["drop_count_active"],
            "drop_ports_active": snapshot["drop_ports_active"],
            "drop_pending": len(snapshot["drop_pending"]),
            "drop_max": snapshot["drop_max"],
            "drop_ports": snapshot["drop_ports"],
            "drop_window_seconds": snapshot["drop_window_seconds"],
            "error": snapshot["error"],
        }
