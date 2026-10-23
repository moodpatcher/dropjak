#!/usr/bin/env python3
"""
Dropjak — login brute-force protection (fail2ban).

The portal counts failed password logins per source IP in a sliding window.
When an IP reaches the configured threshold, the firewall places it in the
``banned_v4`` set: the source's packets are dropped in the forward chain
and in the host input chain as well. The portal and DHCP are exceptions: a
banned client still sees the reason for the ban, and its address is not
taken away.

The same counter also watches unauthenticated, unauthorized TCP traffic
(``record_drop``). Port scanners and bots thus fall under a ban even if they
never try to log in: the ban starts based on the number of dropped packets
collected in the sliding window or on the number of distinct destination
ports. DNS and portal traffic is not counted.

The fourth signal counts unauthorized (401) responses of the domain proxy
(``record_proxy_unauthorized``). Its ban is narrower: the IP is placed in
the ``proxy_banned_v4`` set, which only closes the host's TCP 80/443
(everything Caddy serves). The portal's own port and every other access
remain, so the client can still log in through the plain portal. The proxy
ban lives in a separate registry: it can coexist with a full ban, and
releasing one does not affect the other.

The watched signals can be toggled independently: failed logins
(``enabled``), dropped packets (``drop_count_enabled``), distinct
destination ports (``drop_ports_enabled``) and unauthorized proxy requests
(``proxy_enabled``). No toggle depends on another, and thresholds cannot be
zero: the only way to disable is the toggle. The ``drop_enabled`` field
appears in the output only for backward compatibility; its value is the OR
of the two drop metrics.

A ban lasts for the configured time; the kernel timeout expires it even if
the portal stops in the meantime. Bans persist in the state volume, in a
0600 JSON file, and are reloaded on startup. In-flight attempts are kept in
memory only: after a restart the counter starts from zero, which does not
weaken protection (the ban remains).

The module deliberately does not touch nftables directly: it works through
the Firewall object and writes persistent state only after a successful
kernel operation.
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
# Thresholds cannot be zero: a metric is disabled only by its own toggle.
# The counter stores at most MAX_DROP_EVENTS events per IP; a larger
# threshold can never be reached, hence the maximum is the same.
MIN_DROP_MAX = 1
MAX_DROP_MAX = 10000
MIN_DROP_PORTS = 1
MAX_DROP_PORTS = 4096
MIN_DROP_WINDOW = 30
MAX_DROP_WINDOW = 24 * 60 * 60
# Unauthorized (401) responses of the domain proxy; the time window has the
# same range as for logins.
MIN_PROXY_MAX = 1
MAX_PROXY_MAX = 10000
MAX_BANS = 4096
MAX_TRACKED_IPS = 4096
MAX_DROP_EVENTS = 10000
# The retry queue for kernel elements that failed to release during
# eviction holds at most this many addresses. The queue is not persisted
# and cannot grow without bound: if it fills up, the oldest orphan element
# remains until its TTL expires.
MAX_ORPHAN_UNBANS = 256
# Drop signals come from the first packet of a connection that never
# completed, so their source address is not verified and can be forged.
# Addresses in these networks are never banned on drop signals alone; the
# admin list holds at most this many entries.
MAX_DROP_EXEMPT = 64


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
    """Integer environment value; invalid or out of range -> default.

    For thresholds 0 is invalid: a metric can only be disabled by its own
    toggle. Therefore zero (and negative) values must not be accepted or
    clamped to 0, because that would silently disable protection; in such
    cases the default remains.
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
    """Active state of the two drop metrics (packet count, distinct ports).

    Both metrics depend solely on their own toggle; ``drop_enabled`` is only
    a computed compatibility field, so it does not gate here. The threshold
    is a safety guard: it is never 0 in a valid configuration, but a value
    loaded from an earlier version or edited by hand must not enable a
    metric with a zero threshold either.
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
# Network traffic based ban: the portal counts unauthorized packets from
# the drop log. On reaching the threshold or the number of distinct ports,
# the IP enters the banned_v4 set. The port-count condition catches port
# scanners, the packet-count condition catches repeated attempts.
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
# Proxy based ban: 401 responses of /api/proxy/auth by real client IP.
# It only closes the host's TCP 80/443 (proxy_banned_v4).
DEFAULT_PROXY_ENABLED = _env_bool("HV_FAIL2BAN_PROXY", True)
DEFAULT_PROXY_MAX = _env_int_in_range(
    "HV_FAIL2BAN_PROXY_MAX", 20, MIN_PROXY_MAX, MAX_PROXY_MAX
)
DEFAULT_PROXY_WINDOW = _clamp(
    _env_int("HV_FAIL2BAN_PROXY_WINDOW", 600, MIN_WINDOW),
    MIN_WINDOW,
    MAX_WINDOW,
)

# The portal's own local traffic (healthcheck, local administration) is not
# banned automatically. The rest of 127.0.0.0/8 (test environment) remains.
_AUTO_EXEMPT = {"127.0.0.1"}


def normalize_exempt(value) -> list[str]:
    """Validate the drop-signal allowlist: IPv4 addresses or CIDRs.

    Returns the canonical, de-duplicated network strings in input order.
    Host bits are allowed (``192.0.2.7/24`` becomes ``192.0.2.0/24``), so
    an admin can paste an interface address with its prefix.
    """
    if not isinstance(value, list):
        raise Fail2banError("the drop_exempt field must be a list")
    if len(value) > MAX_DROP_EXEMPT:
        raise Fail2banError(
            f"the drop_exempt list holds at most {MAX_DROP_EXEMPT} entries"
        )
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise Fail2banError("drop_exempt entries must be strings")
        try:
            network = ipaddress.ip_network(item.strip(), strict=False)
        except ValueError as exc:
            raise Fail2banError(
                f"invalid drop_exempt entry: {item.strip()[:64]}"
            ) from exc
        if network.version != 4:
            raise Fail2banError("drop_exempt takes IPv4 entries only")
        if str(network) not in result:
            result.append(str(network))
    return result


def _env_exempt() -> tuple:
    """Built-in drop-signal allowlist from the environment.

    ``HV_MGMT_NET`` (the admin's management network) is always exempt, plus
    the comma-separated ``HV_FAIL2BAN_DROP_EXEMPT`` list (agent endpoints,
    upstream resolvers, other infrastructure). Invalid entries are skipped:
    the environment must not stop the portal from starting.
    """
    raw = ",".join(
        os.environ.get(name, "")
        for name in ("HV_MGMT_NET", "HV_FAIL2BAN_DROP_EXEMPT")
    )
    networks = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        if network.version == 4 and network not in networks:
            networks.append(network)
    return tuple(networks)


def _default_log(message: str) -> None:
    print(message, flush=True)


class Fail2banError(ValueError):
    """Invalid configuration, address or failed firewall operation."""


def normalize_ip(value) -> str:
    """Validate and canonicalize a bannable IPv4 address.

    The portal's own loopback address (127.0.0.1), 0.0.0.0, multicast and
    broadcast addresses cannot be banned: they would either affect the
    portal's own traffic or are uninterpretable sources. The rest of
    127.0.0.0/8 (e.g. test sources) remains bannable.
    """
    if not isinstance(value, str):
        raise Fail2banError("invalid IP address")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise Fail2banError(f"invalid IP address: {value.strip()[:64]}") from exc
    if address.version != 4:
        raise Fail2banError("only IPv4 addresses can be banned")
    if str(address) == "127.0.0.1":
        raise Fail2banError("the local (loopback) address cannot be banned")
    if address.is_unspecified:
        raise Fail2banError("the 0.0.0.0 address cannot be banned")
    if address.is_multicast:
        raise Fail2banError("the multicast address cannot be banned")
    if str(address) == "255.255.255.255":
        raise Fail2banError("the broadcast address cannot be banned")
    return str(address)


def validate_config(data, current: dict | None = None) -> dict:
    """Validate fail2ban settings; a missing field keeps the current value."""
    if not isinstance(data, dict):
        raise Fail2banError("settings must be a JSON object")
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
        "proxy_enabled": DEFAULT_PROXY_ENABLED,
        "proxy_max": DEFAULT_PROXY_MAX,
        "proxy_window_seconds": DEFAULT_PROXY_WINDOW,
        "drop_exempt": [],
    }
    # New fields missing from the saved file get the default value; current
    # configuration values remain unless the request overrides them.
    current = {**defaults, **(current or {})}
    enabled = data.get("enabled", current["enabled"])
    if not isinstance(enabled, bool):
        raise Fail2banError("the enabled field must be a boolean")
    # drop_enabled is only a backward-compatibility input: the old API or a
    # cached UI used the false value to disable drop-based banning. In that
    # case both metric toggles are forced off; a true value does not enable
    # anything, because the metrics are toggled separately.
    legacy_drop = None
    if "drop_enabled" in data:
        legacy_drop = data["drop_enabled"]
        if not isinstance(legacy_drop, bool):
            raise Fail2banError("the drop_enabled field must be a boolean")
    drop_count_enabled = data.get(
        "drop_count_enabled", current["drop_count_enabled"]
    )
    if not isinstance(drop_count_enabled, bool):
        raise Fail2banError(
            "the drop_count_enabled field must be a boolean"
        )
    drop_ports_enabled = data.get(
        "drop_ports_enabled", current["drop_ports_enabled"]
    )
    if not isinstance(drop_ports_enabled, bool):
        raise Fail2banError(
            "the drop_ports_enabled field must be a boolean"
        )
    if legacy_drop is False:
        drop_count_enabled = False
        drop_ports_enabled = False
    proxy_enabled = data.get("proxy_enabled", current["proxy_enabled"])
    if not isinstance(proxy_enabled, bool):
        raise Fail2banError("the proxy_enabled field must be a boolean")

    def integer(name: str, label: str, minimum: int, maximum: int) -> int:
        raw = data.get(name, current[name])
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise Fail2banError(f"{label}: must be an integer")
        if raw < minimum or raw > maximum:
            raise Fail2banError(
                f"{label}: must be between {minimum} and {maximum}"
            )
        return raw

    return {
        "enabled": enabled,
        "max_attempts": integer(
            "max_attempts", "number of attempts", MIN_ATTEMPTS, MAX_ATTEMPTS
        ),
        "window_seconds": integer(
            "window_seconds", "the time window", MIN_WINDOW, MAX_WINDOW
        ),
        "ban_seconds": integer(
            "ban_seconds", "the ban duration", MIN_BAN, MAX_BAN
        ),
        "drop_enabled": drop_count_enabled or drop_ports_enabled,
        "drop_count_enabled": drop_count_enabled,
        "drop_ports_enabled": drop_ports_enabled,
        "drop_max": integer(
            "drop_max", "the network threshold", MIN_DROP_MAX, MAX_DROP_MAX
        ),
        "drop_ports": integer(
            "drop_ports", "the number of distinct ports",
            MIN_DROP_PORTS, MAX_DROP_PORTS,
        ),
        "drop_window_seconds": integer(
            "drop_window_seconds", "the network time window",
            MIN_DROP_WINDOW, MAX_DROP_WINDOW,
        ),
        "proxy_enabled": proxy_enabled,
        "proxy_max": integer(
            "proxy_max", "the number of unauthorized proxy requests",
            MIN_PROXY_MAX, MAX_PROXY_MAX,
        ),
        "proxy_window_seconds": integer(
            "proxy_window_seconds", "the proxy time window",
            MIN_WINDOW, MAX_WINDOW,
        ),
        "drop_exempt": normalize_exempt(
            data.get("drop_exempt", current["drop_exempt"])
        ),
    }


def _ban_view(record: dict, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    manual = bool(record.get("manual", False))
    source = record.get("source")
    if source not in ("manual", "login", "drop", "proxy"):
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
    """Count failed logins and ban source IPs."""

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
        proxy_enabled: bool = DEFAULT_PROXY_ENABLED,
        proxy_max: int = DEFAULT_PROXY_MAX,
        proxy_window_seconds: int = DEFAULT_PROXY_WINDOW,
        drop_exempt=None,
        exempt=(),
        on_ban=None,
    ) -> None:
        self.firewall = firewall
        self.path = os.path.abspath(path)
        self.audit = audit
        self.log = logger
        self._on_ban = on_ban
        self._lock = threading.RLock()
        # The drop_enabled parameter is only an initial-startup gate: a false
        # value of HV_FAIL2BAN_DROP (or of a programmatic constructor call)
        # disables both metrics. At runtime the metrics can be toggled
        # independently.
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
            "proxy_enabled": bool(proxy_enabled),
            "proxy_max": _clamp(proxy_max, MIN_PROXY_MAX, MAX_PROXY_MAX),
            "proxy_window_seconds": _clamp(
                proxy_window_seconds, MIN_WINDOW, MAX_WINDOW
            ),
            "drop_exempt": normalize_exempt(list(drop_exempt or [])),
        }
        # Built-in drop-signal allowlist: the environment plus the
        # infrastructure addresses the caller passes in (``exempt``). It is
        # not stored in the file and the admin cannot remove it.
        builtin = list(_env_exempt())
        for item in exempt or ():
            try:
                network = ipaddress.ip_network(str(item).strip(), strict=False)
            except ValueError:
                continue
            if network.version == 4 and network not in builtin:
                builtin.append(network)
        self._builtin_exempt = tuple(builtin)
        # IP -> {"times": [timestamp, ...], "user": str}; not persisted.
        self._attempts: dict[str, dict] = {}
        # IP -> {"events": [(timestamp, "proto/port"), ...], "reason": str};
        # not persisted, like login attempts.
        self._drop_events: dict[str, dict] = {}
        self._drop_event_count = 0
        # IP -> ban record; persisted.
        self._bans: dict[str, dict] = {}
        # IP -> timestamps of 401 proxy responses; not persisted.
        self._proxy_hits: dict[str, list[float]] = {}
        # IP -> proxy ban record (TCP 80/443 only); persisted, a registry
        # independent of the full ban.
        self._proxy_bans: dict[str, dict] = {}
        # Addresses of kernel elements that failed to release during
        # eviction. Not persisted; deletion is retried on the next
        # operations, so that no invisible ban lives for up to 30 days.
        self._orphan_unbans: list[str] = []
        self._error = ""
        # The most recently seen file identifier. The CLI writes fail2ban.json
        # as a separate process; if the file changed, the portal reloads it on
        # the next operation so the UI does not show a stale list.
        self._disk_stamp: tuple[int, int, int] | None = None
        self.load()

    # -- state -----------------------------------------------------------------

    def _write_audit(self, event: str, **fields) -> None:
        """Optional audit entry; does not block even on error."""
        if self.audit is None:
            return
        try:
            self.audit.write(event, **fields)
        except Exception as exc:
            self.log(f"[audit] failed to write {event}: {exc}")

    def _queue_orphan_unban_locked(
        self, address: str, exc: Exception
    ) -> bool:
        """Add a failed eviction release to the bounded queue.

        Returns whether the address was added to the queue. The queue may be
        full because it cannot grow without bound; in that case we log and
        audit loudly, because the orphan kernel element may remain in force
        until the timeout expires.
        """
        if address in self._orphan_unbans:
            return True
        if len(self._orphan_unbans) >= MAX_ORPHAN_UNBANS:
            self.log(
                f"[fail2ban] ERROR: the orphan unban queue is full "
                f"({MAX_ORPHAN_UNBANS}); the kernel element of {address} may "
                "remain in force until the timeout expires"
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
        """Remove the address from the orphan queue after a successful ban.

        ``Firewall.ban`` deletes and then recreates the kernel element, so the
        former orphan element is gone.
        """
        try:
            self._orphan_unbans.remove(address)
        except ValueError:
            pass

    def _retry_orphan_unbans_locked(self) -> None:
        """Retry previously failed eviction releases.

        We proceed from the head of the queue and stop at the first error: with
        a persistently failing firewall this keeps the call chain from
        spinning. The failed address stays in the queue. If the address has
        been banned again in the meantime, the kernel element is already live,
        so only the queue is cleaned.
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
                    f"[fail2ban] failed to release orphan ban of {address}: "
                    f"{exc}"
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
        """Adopt external (CLI) file modifications into memory.

        The portal updates the stamp after each of its own saves, so this does
        not reload in normal operation. If the CLI (as root) modifies the ban
        list, the next snapshot/operation already sees the file's state. With
        a corrupt or missing file the in-memory state remains (bans in the
        kernel still live regardless).
        """
        if self._file_stamp() != self._disk_stamp:
            self.load()

    def load(self) -> None:
        """Load fail2ban.json.

        With a corrupt file the configuration falls back to the environment
        defaults and the ban list becomes empty. This does not open a way in:
        access remains fail-closed, only earlier bans are not reloaded.
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
                f"[fail2ban] WARNING: {self.path} cannot be read, "
                f"the ban list is empty: {exc}"
            )
            self._write_audit("fail2ban_load_error", reason=str(exc))
            return
        if not isinstance(raw, dict):
            with self._lock:
                self._error = "the file must be a JSON object"
                self._disk_stamp = stamp
            self.log(
                f"[fail2ban] WARNING: {self.path} has an invalid format, "
                "the ban list is empty"
            )
            self._write_audit(
                "fail2ban_load_error", reason="the file must be a JSON object"
            )
            return
        config = dict(self._config)
        raw_config = raw.get("config")
        if isinstance(raw_config, dict):
            migrated = dict(raw_config)
            # Migrate old state: a threshold of 0 used to disable the given
            # metric. In that case do not fall the whole configuration back to
            # defaults: disable only that metric and restore its threshold to
            # the default. An explicitly saved drop_enabled=false still
            # disables both metrics.
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
                    f"[fail2ban] WARNING: invalid saved settings, "
                    f"using defaults: {exc}"
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
        # The old file has no proxy_bans: empty list.
        proxy_bans: dict[str, dict] = {}
        raw_proxy = raw.get("proxy_bans", [])
        if not isinstance(raw_proxy, list):
            raw_proxy = []
        for item in raw_proxy:
            record = self._parse_record(item, now)
            if record is None:
                continue
            if len(proxy_bans) >= MAX_BANS:
                break
            record.update(source="proxy", manual=False, detail="")
            proxy_bans[record["ip"]] = record
        with self._lock:
            self._config = config
            self._bans = bans
            self._proxy_bans = proxy_bans
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
        def rows(bans: dict[str, dict]) -> list[dict]:
            return [
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
                    bans.values(), key=lambda row: row["since"]
                )
            ]

        return {
            "version": 1,
            "config": dict(self._config),
            "bans": rows(self._bans),
            "proxy_bans": rows(self._proxy_bans),
        }

    def _state_owner(self, directory: str) -> tuple[int, int] | None:
        """Owner of the saved file.

        The portal runs as the service user on the state volume, while the CLI
        starts as root. If the root CLI overwrote the file, it would become
        root-owned and the running portal could no longer write it on the next
        save. Therefore we keep the owner of the existing file (or, for a new
        file, of the directory).
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
            self.log(f"[fail2ban] WARNING: failed to save {self.path}: {exc}")
            if raise_errors:
                raise Fail2banError(f"failed to save the ban list: {exc}") from exc
            return False
        self._error = ""
        return True

    # -- counting --------------------------------------------------------------

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
        """Maintain the sliding window of network events."""
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

    def drop_exempt(self, ip: str) -> bool:
        """True if drop signals from this address must never ban it."""
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if any(address in network for network in self._builtin_exempt):
            return True
        with self._lock:
            listed = list(self._config.get("drop_exempt") or ())
        return any(
            address in ipaddress.ip_network(item) for item in listed
        )

    def _notify(self, record: dict) -> None:
        if self._on_ban is None:
            return
        try:
            self._on_ban(record)
        except Exception as exc:  # the ban remains valid regardless
            self.log(f"[fail2ban] failed to post-process the ban: {exc}")

    def record_failure(self, ip: str, user: str = "") -> dict | None:
        """Record a failed login; returns the record if it caused a ban."""
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
        """Record an unauthorized/suspicious packet.

        The portal calls this from the drop log for every dropped packet that
        is not the portal's own traffic. The ban starts when the IP reaches
        the packet-count threshold within the configured time window, or
        tries enough distinct destination ports (port scanning).

        Events with ``count_total=False`` only contribute to the distinct port
        count. This is correct for LAN-side ``no-grant``/``input-lan``
        traffic: even a logged-out browser makes many TCP attempts, but
        typically on only a few destination ports.
        """
        try:
            address = normalize_ip(ip)
        except Fail2banError:
            return None
        if address in _AUTO_EXEMPT:
            return None
        # The source of a dropped first packet is unverified. Allowlisted
        # infrastructure (management network, agent endpoints, upstream
        # resolvers, admin list) is never counted, so a forged packet cannot
        # get it banned. The drop log still records the packet.
        if self.drop_exempt(address):
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
            # Store only events that can contribute to an active metric. With
            # the port metric disabled, port information is not kept either,
            # and the LAN event (which does not count toward the packet
            # threshold) is neutral.
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
            # Size the cap to both active thresholds so that a small drop_max
            # does not truncate the event sequence required by a large
            # drop_ports.
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

    def record_proxy_unauthorized(self, ip: str) -> dict | None:
        """Record an unauthorized (401) domain-proxy response.

        ``/api/proxy/auth`` calls this with the real client IP (Caddy's XFF
        value), only on a 401 response for a private entry. An IP that is
        fully or proxy banned is no longer counted. A successful proxy request
        does not reset the counter: like the drop counters, only the sliding
        window forgets. At the threshold the ban closes only TCP 80/443.
        """
        try:
            address = normalize_ip(ip)
        except Fail2banError:
            return None
        with self._lock:
            self._refresh_locked()
            if not self._config["proxy_enabled"]:
                return None
            now = time.time()
            for bans in (self._bans, self._proxy_bans):
                existing = bans.get(address)
                if existing is not None:
                    if existing["until"] > now:
                        return None
                    del bans[address]
            window = self._config["proxy_window_seconds"]
            times = [
                stamp for stamp in self._proxy_hits.get(address, ())
                if now - stamp <= window
            ]
            times.append(now)
            self._proxy_hits[address] = times
            if len(times) < self._config["proxy_max"]:
                if len(self._proxy_hits) > MAX_TRACKED_IPS:
                    self._prune_proxy_hits_locked(now)
                return None
            record = self._proxy_ban_locked(
                address, self._config["ban_seconds"], attempts=len(times)
            )
            view = _ban_view(record, time.time())
        self._notify(view)
        return view

    def _prune_proxy_hits_locked(self, now: float) -> None:
        window = self._config["proxy_window_seconds"]
        for ip, times in list(self._proxy_hits.items()):
            times = [stamp for stamp in times if now - stamp <= window]
            if times:
                self._proxy_hits[ip] = times
            else:
                del self._proxy_hits[ip]
        if len(self._proxy_hits) > MAX_TRACKED_IPS:
            ordered = sorted(
                self._proxy_hits.items(), key=lambda pair: pair[1][-1]
            )
            for ip, _ in ordered[: len(self._proxy_hits) - MAX_TRACKED_IPS]:
                del self._proxy_hits[ip]

    def _proxy_ban_locked(
        self, address: str, seconds: int, attempts: int = 0
    ) -> dict:
        """Proxy ban (proxy_banned_v4): kernel -> memory -> save."""
        seconds = _clamp(int(seconds), MIN_BAN, MAX_BAN)
        now = time.time()
        existing = self._proxy_bans.get(address)
        # Proxy bans are all automatic: on a full registry the one that
        # expires soonest makes room (it would be released first anyway).
        victim = None
        if len(self._proxy_bans) >= MAX_BANS and existing is None:
            victim = min(
                self._proxy_bans.values(),
                key=lambda row: (row["until"], row["since"]),
            )
        try:
            self.firewall.proxy_ban(address, seconds)
        except Exception as exc:
            raise Fail2banError(
                f"failed to proxy-ban {address}: {exc}"
            ) from exc
        if victim is not None:
            oldest = victim
            # shortcut: a failed kernel release is not put on the retry queue
            # (the timeout expires it); if that matters, the orphan queue is needed.
            try:
                self.firewall.proxy_unban(oldest["ip"])
            except Exception as exc:
                self.log(
                    f"[fail2ban] kernel release failed for expiring proxy "
                    f"ban of {oldest['ip']}: {exc}"
                )
            del self._proxy_bans[oldest["ip"]]
            self._write_audit(
                "fail2ban_ban_evicted", ip=oldest["ip"], reason="max_bans",
                source="proxy",
            )
        record = {
            "ip": address,
            "since": existing["since"] if existing is not None else now,
            "until": now + seconds,
            "attempts": max(
                int(attempts or 0), (existing or {}).get("attempts", 0)
            ),
            "user": "",
            "manual": False,
            "source": "proxy",
            "detail": "",
        }
        self._proxy_bans[address] = record
        self._proxy_hits.pop(address, None)
        self._save_locked(raise_errors=False)
        return record

    def proxy_banned(self, ip: str) -> dict | None:
        """The IP's active proxy ban (TCP 80/443 only), or None."""
        try:
            address = normalize_ip(ip)
        except Fail2banError:
            return None
        now = time.time()
        with self._lock:
            self._refresh_locked()
            record = self._proxy_bans.get(address)
            if record is None:
                return None
            if record["until"] <= now:
                del self._proxy_bans[address]
                return None
            return _ban_view(record, now)

    def last_hit(self, ip: str, proxy_only: bool = False) -> float:
        """Latest hit of the IP's pending (within-window) counters.

        Read-only (for the proxy challenge conditions); 0 if no active counter
        applies. ``proxy_only``: only proxy 401s.
        """
        try:
            address = normalize_ip(ip)
        except Fail2banError:
            return 0.0
        now = time.time()
        with self._lock:
            self._refresh_locked()
            config = self._config
            stamps = []
            if config["proxy_enabled"]:
                stamps += [
                    stamp for stamp in self._proxy_hits.get(address, ())
                    if now - stamp <= config["proxy_window_seconds"]
                ]
            if not proxy_only:
                if config["enabled"]:
                    stamps += [
                        stamp for stamp in
                        (self._attempts.get(address) or {}).get("times", ())
                        if now - stamp <= config["window_seconds"]
                    ]
                if any(_drop_metric_state(config)):
                    stamps += [
                        event[0] for event in
                        (self._drop_events.get(address) or {}).get("events", ())
                        if now - event[0] <= config["drop_window_seconds"]
                    ]
        return max(stamps, default=0.0)

    def _kernel_ban(self, record: dict, ttl: int) -> None:
        """Restore a released record into its own set."""
        if record.get("source") == "proxy":
            self.firewall.proxy_ban(record["ip"], ttl)
        else:
            self.firewall.ban(record["ip"], ttl)

    def _bans_of(self, record: dict) -> dict[str, dict]:
        return (
            self._proxy_bans if record.get("source") == "proxy"
            else self._bans
        )

    def record_success(self, ip: str) -> None:
        """Reset attempts after a successful login (the ban remains)."""
        try:
            address = normalize_ip(ip)
        except Fail2banError:
            return
        with self._lock:
            self._attempts.pop(address, None)

    def banned(self, ip: str) -> dict | None:
        """The IP's active ban, or None."""
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
        # First try to delete orphan elements left over from earlier
        # evictions; this must not block the new protective ban.
        self._retry_orphan_unbans_locked()
        # On a full registry only an automatic ban can make room, the one
        # that expires soonest. Manual bans are never evicted: if only manual
        # bans remain, the new ban is refused before it reaches the kernel.
        victim = None
        if len(self._bans) >= MAX_BANS and address not in self._bans:
            automatic = [
                row for row in self._bans.values() if not row["manual"]
            ]
            if not automatic:
                self.log(
                    "[fail2ban] WARNING: ban list is full of manual bans; "
                    f"the new ban of {address} was refused"
                )
                self._write_audit(
                    "fail2ban_ban_refused", ip=address, reason="max_bans",
                    manual=bool(manual), source=source,
                )
                raise Fail2banError(
                    "the ban list is full of manual bans; release one first"
                )
            victim = min(
                automatic, key=lambda row: (row["until"], row["since"])
            )
        try:
            self.firewall.ban(address, seconds)
        except Exception as exc:
            raise Fail2banError(
                f"firewall ban failed for {address}: {exc}"
            ) from exc
        # ban() overwrites any earlier element in the kernel, so the orphan
        # entry for this address is no longer recoverable.
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
        if victim is not None:
            oldest = victim
            # The kernel element must be released before dropping the memory
            # record, otherwise an invisible ban would remain until the TTL.
            kernel_released = True
            try:
                self.firewall.unban(oldest["ip"])
            except Exception as exc:
                kernel_released = False
                self._queue_orphan_unban_locked(oldest["ip"], exc)
                self.log(
                    f"[fail2ban] WARNING: kernel release failed for expiring "
                    f"ban of {oldest['ip']}: {exc}; "
                    "will retry on the next operations"
                )
            del self._bans[oldest["ip"]]
            self.log(
                f"[fail2ban] ban list is full; the automatic ban expiring "
                f"soonest ({oldest['ip']}) was evicted from the registry"
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
        """Manual ban; the ban lasts for the given or the default duration."""
        address = normalize_ip(ip)
        if seconds in (None, ""):
            seconds = 0
        if isinstance(seconds, bool) or not isinstance(seconds, int):
            raise Fail2banError("the ban duration must be an integer (seconds)")
        if seconds <= 0:
            seconds = self._config["ban_seconds"]
        if seconds < MIN_BAN or seconds > MAX_BAN:
            raise Fail2banError(
                f"the ban duration must be between {MIN_BAN} and {MAX_BAN} seconds"
            )
        with self._lock:
            self._refresh_locked()
            record = self._ban_locked(
                address, seconds, manual=manual, user=user
            )
            view = _ban_view(record, time.time())
        self._notify(view)
        return view

    def unban(self, ip: str, proxy: bool = False) -> bool:
        """Release a ban in the kernel and in the registry.

        ``proxy=True`` releases only the proxy ban (TCP 80/443), otherwise
        only the full ban; the other kind remains untouched.
        """
        address = normalize_ip(ip)
        with self._lock:
            self._refresh_locked()
            bans = self._proxy_bans if proxy else self._bans
            known = address in bans
            try:
                if proxy:
                    self.firewall.proxy_unban(address)
                else:
                    self.firewall.unban(address)
            except Exception as exc:
                raise Fail2banError(
                    f"failed to release the ban of {address}: {exc}"
                ) from exc
            if known:
                del bans[address]
                self._save_locked(raise_errors=False)
        return known

    def unban_all(self) -> int:
        """Release all bans; returns the number of released entries."""
        removed = 0
        with self._lock:
            self._refresh_locked()
            self._retry_orphan_unbans_locked()
            for address in list(self._bans):
                try:
                    self.firewall.unban(address)
                except Exception as exc:
                    self.log(
                        f"[fail2ban] failed to release {address}: {exc}"
                    )
                    continue
                del self._bans[address]
                removed += 1
            for address in list(self._proxy_bans):
                try:
                    self.firewall.proxy_unban(address)
                except Exception as exc:
                    self.log(
                        f"[fail2ban] proxy release failed for {address}: {exc}"
                    )
                    continue
                del self._proxy_bans[address]
                removed += 1
            if removed:
                self._save_locked(raise_errors=False)
        return removed

    def reset(self) -> None:
        """Delete the ban state and the file (factory reset)."""
        with self._lock:
            self._bans.clear()
            self._proxy_bans.clear()
            self._attempts.clear()
            self._drop_events.clear()
            self._proxy_hits.clear()
            self._orphan_unbans.clear()
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self._disk_stamp = None
            self._error = ""

    def configure(self, data: dict) -> dict:
        """Modify settings.

        The three signals are independent: disabling failed-login monitoring
        releases only login-based bans, disabling both drop metrics together
        releases only drop-based automatic bans. Manual bans always remain.
        The order is: kernel -> save -> memory.

        Release is best-effort: every necessary release is attempted. If any
        of them fails, the setting remains unchanged; bans already released
        are restored with the exact remaining time, and their memory records
        are put back even if the re-ban fails. Thus no silent, partial state
        remains. If saving fails, the same rollback runs.
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
            release_proxy = (
                self._config["proxy_enabled"]
                and not new_config["proxy_enabled"]
            )
            if release_proxy:
                for address, record in list(self._proxy_bans.items()):
                    try:
                        self.firewall.proxy_unban(address)
                    except Exception as exc:
                        failed.append((dict(record), exc))
                        self.log(
                            f"[fail2ban] proxy release failed for {address}: {exc}"
                        )
                        continue
                    released.append(dict(record))
                    del self._proxy_bans[address]
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
                            f"[fail2ban] failed to release {address}: {exc}"
                        )
                        continue
                    released.append(dict(record))
                    del self._bans[address]
            if failed:
                # The configuration did not change. Bans already released
                # are restored with the exact remaining time; the memory
                # record is always put back.
                restored = 0
                for record in released:
                    remaining = max(1, int(record["until"] - time.time()))
                    try:
                        self._kernel_ban(record, remaining)
                        restored += 1
                    except Exception as exc:
                        self._error = str(exc)
                        self.log(
                            f"[fail2ban] failed to restore {record['ip']}: {exc}"
                        )
                        self._write_audit(
                            "fail2ban_ban_restore_failed",
                            ip=record["ip"],
                            reason=str(exc),
                        )
                    self._bans_of(record)[record["ip"]] = record
                self._write_audit(
                    "fail2ban_bans_release_failed",
                    count=len(failed),
                    reason=str(failed[0][1]),
                    restored=restored,
                )
                raise Fail2banError(
                    "failed to release bans "
                    f"({len(failed)} addresses); the setting remains unchanged"
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
                        self._kernel_ban(record, remaining)
                    except Exception as exc:
                        self._error = str(exc)
                        self.log(
                            f"[fail2ban] failed to restore {record['ip']}: {exc}"
                        )
                        self._write_audit(
                            "fail2ban_ban_restore_failed",
                            ip=record["ip"],
                            reason=str(exc),
                        )
                    # The record must be put back even after a failed re-ban:
                    # the UI must not forget the ban.
                    self._bans_of(record)[record["ip"]] = record
                raise
            if not new_config["enabled"]:
                self._attempts.clear()
            # After a change to the drop master state, any metric toggle or
            # the thresholds, the old counters are not valid under the new
            # configuration. Disabling login monitoring alone does not affect
            # the drop counters.
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
            elif previous["drop_exempt"] != new_config["drop_exempt"]:
                # Pending counters of newly allowlisted addresses are dropped;
                # an existing ban stays until the admin releases it.
                for address in list(self._drop_events):
                    if self.drop_exempt(address):
                        del self._drop_events[address]
            if any(
                previous[key] != new_config[key]
                for key in ("proxy_enabled", "proxy_max", "proxy_window_seconds")
            ):
                self._proxy_hits.clear()
            if released:
                # The audit includes the breakdown by source so that disabling
                # login and drop together does not lose the information about
                # the drop part.
                login_count = sum(
                    1 for record in released
                    if release_login
                    and record.get("source") not in ("drop", "proxy")
                )
                drop_count = sum(
                    1 for record in released
                    if release_drop and record.get("source") == "drop"
                )
                proxy_count = sum(
                    1 for record in released if record.get("source") == "proxy"
                )
                self._write_audit(
                    "fail2ban_bans_released",
                    count=len(released),
                    reason=(
                        "disabled" if release_login
                        else "drop_disabled" if release_drop
                        else "proxy_disabled"
                    ),
                    login_count=login_count,
                    drop_count=drop_count,
                    proxy_count=proxy_count,
                )
            return self.snapshot()

    # -- startup and view ------------------------------------------------------

    def sync(self) -> bool:
        """Restore saved bans into the (freshly flushed) nft set.

        The remaining time is passed exactly, truncated to whole seconds;
        ``MIN_BAN`` is only a lower bound, not rounding. Expired records are
        skipped, and a zero or negative remaining time is not put into the
        kernel.
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
            proxy_expired = [
                address
                for address, record in self._proxy_bans.items()
                if record["until"] <= now
            ]
            for address in proxy_expired:
                del self._proxy_bans[address]
            expired += proxy_expired

            def elements_of(bans: dict[str, dict]) -> list[tuple[str, int]]:
                return [
                    (record["ip"], max(1, int(record["until"] - now)))
                    for record in bans.values()
                    if int(record["until"] - now) > 0
                ]

            elements = elements_of(self._bans)
            try:
                self.firewall.sync_bans(elements)
                self.firewall.sync_proxy_bans(elements_of(self._proxy_bans))
            except Exception as exc:
                self._error = str(exc)
                self.log(
                    "[fail2ban] WARNING: failed to restore saved bans: "
                    f"{exc}"
                )
                self._write_audit(
                    "fail2ban_sync_failed",
                    reason=str(exc),
                    count=len(elements),
                )
                return False
            # sync_bans() empties the set completely and puts back only the
            # known bans; orphan elements are gone with this.
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
            for address in [
                address for address, record in self._proxy_bans.items()
                if record["until"] <= now
            ]:
                del self._proxy_bans[address]
            self._prune_attempts_locked(now)
            self._prune_drop_events_locked(now)
            self._prune_proxy_hits_locked(now)
            # Proxy bans (source="proxy") appear in the same list; the same IP
            # can appear twice alongside a full ban.
            bans = [
                _ban_view(record, now)
                for record in sorted(
                    [*self._bans.values(), *self._proxy_bans.values()],
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
            proxy_pending = len(self._proxy_hits)
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
            "proxy_enabled": config["proxy_enabled"],
            "proxy_max": config["proxy_max"],
            "proxy_window_seconds": config["proxy_window_seconds"],
            "proxy_pending": proxy_pending,
            "drop_exempt": list(config["drop_exempt"]),
            "drop_exempt_builtin": [
                str(network) for network in self._builtin_exempt
            ],
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
                "min_proxy_max": MIN_PROXY_MAX,
                "max_proxy_max": MAX_PROXY_MAX,
                "max_drop_exempt": MAX_DROP_EXEMPT,
            },
            "bans": bans,
            "banned_count": len(bans),
            "pending": pending,
            "drop_pending": drop_pending,
            "server_time": now,
            "error": error,
        }

    def status(self) -> dict:
        """Brief status for logging."""
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
            "proxy_enabled": snapshot["proxy_enabled"],
            "error": snapshot["error"],
        }
