#!/usr/bin/env python3
"""Dropjak privileged helper (DJ-20).

The web-facing portal runs without CAP_NET_ADMIN. This small process, root
with only CAP_NET_ADMIN (docker/entrypoint.sh, or dropjak-helper.service on
a native install), owns every privileged network operation: nft, conntrack,
the dropjak0 WireGuard interface (``ip``/``wg``) and binding the NFLOG
drop-log group.

It listens on a Unix socket (``/run/dropjak/helper.sock``: directory 0750
root:hatarvedelem, socket 0660) and serves a fixed JSON command set; there
is no "run this command" verb. Every request:

* comes from an allowed uid (SO_PEERCRED: the portal user, or root),
* is a single newline-terminated JSON object of at most 1 MiB, read within
  5 seconds,
* names a known operation, and carries exactly the arguments that operation
  takes, each checked with the same validators the portal uses.

The operations run the portal's own Firewall/TunnelManager code, so what is
executed is unchanged; only who executes it moved. Custom chain rules are
rendered by the portal and re-checked here line by line before they reach
nft. The answer is one JSON line; ``nflog_open`` also passes the bound
netlink socket (SCM_RIGHTS), which the portal can only read.
"""

from __future__ import annotations

import array
import ipaddress
import json
import os
import pwd
import re
import signal
import socket
import stat
import struct
import sys
import threading
import time

# This process executes; it is never a client of itself. The secrets the
# portal needs never reach the helper.
SOCKET_PATH = os.environ.pop("HV_PRIV_HELPER", "").strip()
for _name in (
    "HV_ADMIN_PASSWORD", "HV_ADMIN_PASSWORD_FILE", "HV_PROXY_KEY",
    "TURNSTILE_SECRET",
):
    os.environ.pop(_name, None)

import droplog  # noqa: E402
import fail2ban as fail2ban_mod  # noqa: E402
import gateway  # noqa: E402
import settings_store  # noqa: E402
import tunnel as tunnel_mod  # noqa: E402

SOCKET_PATH = SOCKET_PATH or gateway.PRIV_HELPER_DEFAULT_SOCKET
APP_USER = os.environ.get("HV_APP_USER", "").strip() or "hatarvedelem"
MAX_REQUEST = gateway.PRIV_HELPER_MAX_REQUEST
# Reading the request; the operation itself has the nft timeouts.
REQUEST_TIMEOUT = 5.0
# Concurrent connections; beyond this a request is refused at once.
MAX_CLIENTS = 16
# A session or a ban lasts at most 30 days; some slack for rounding.
MAX_TTL = 2 * gateway.ABSOLUTE_MAX_TTL
MAX_GRANTS = 256
MAX_BAN_ELEMENTS = 4 * fail2ban_mod.MAX_BANS
MAX_RULES = 8192
MAX_RULE_LENGTH = 4096
_PEERCRED = struct.Struct("3i")
# A rendered rule is printable ASCII; these never occur in one, but each
# would let a single "line" carry a second command or hide the rest.
_RULE_CHARS_RE = re.compile(r"^[\x20-\x7e]+$")
_RULE_FORBIDDEN = (";", "#", "\\", "`")
_RULE_FORBIDDEN_WORDS = ("include", "ruleset")


def log(message: str) -> None:
    gateway.log(f"[helper] {message}")


class RequestError(ValueError):
    """The request does not fit the command set; nothing was executed."""


# ------------------------------------------------------------- validation

def _expect(args, required=(), optional=()) -> dict:
    """Exactly the named arguments: no unknown or missing ones."""
    if not isinstance(args, dict):
        raise RequestError("args must be a JSON object")
    unknown = sorted(set(args) - set(required) - set(optional))
    if unknown:
        raise RequestError(f"unexpected argument: {unknown[0]}")
    missing = [name for name in required if name not in args]
    if missing:
        raise RequestError(f"missing argument: {missing[0]}")
    return args


def _ipv4(value) -> str:
    if not isinstance(value, str) or len(value) > 64 \
            or not gateway.is_ipv4(value):
        raise RequestError("an IPv4 address is required")
    return gateway.normalize_ip(value)


def _int(value, field: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) \
            or not low <= value <= high:
        raise RequestError(f"{field}: an integer {low}-{high} is required")
    return value


def _bool(value, field: str) -> bool:
    if not isinstance(value, bool):
        raise RequestError(f"{field}: a boolean is required")
    return value


def _ports(value) -> gateway.Ports:
    try:
        return gateway.ports_from_wire(value)
    except ValueError as exc:
        raise RequestError(str(exc)) from None


def _grants(value) -> tuple[gateway.Ports, ...]:
    if not isinstance(value, list) or len(value) > MAX_GRANTS:
        raise RequestError(f"grants: a list of at most {MAX_GRANTS} is required")
    return tuple(_ports(item) for item in value)


def _port_list(value, field: str) -> list[int]:
    if not isinstance(value, list) or len(value) > 65535:
        raise RequestError(f"{field}: a port list is required")
    return [_int(port, field, 1, 65535) for port in value]


def _ban_set(firewall, value) -> str:
    if value not in (firewall.ban_set, firewall.proxy_ban_set):
        raise RequestError("set: only the ban sets are allowed")
    return value


def _ban_elements(value) -> list[tuple[str, int]]:
    if not isinstance(value, list) or len(value) > MAX_BAN_ELEMENTS:
        raise RequestError("elements: a list of [ip, ttl] pairs is required")
    elements = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            raise RequestError("elements: a list of [ip, ttl] pairs is required")
        elements.append((_ipv4(item[0]), _int(item[1], "ttl", 0, MAX_TTL)))
    return elements


def check_custom_rules(rules, table: str, chains) -> list[str]:
    """Re-check the portal's rendered custom-chain rules (replace_custom).

    Every line must be one ``add rule inet <table> <chain> ...`` statement
    for a chain this replacement recreates, in printable ASCII, with no
    command separator, comment, escape, ``include`` or ``ruleset``.
    """
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise RequestError(f"rules: a list of at most {MAX_RULES} lines is required")
    prefixes = tuple(f"add rule inet {table} {chain} " for chain in chains)
    checked = []
    for line in rules:
        if not isinstance(line, str) or not 0 < len(line) <= MAX_RULE_LENGTH:
            raise RequestError("rules: invalid line")
        if not _RULE_CHARS_RE.match(line):
            raise RequestError("rules: only printable ASCII on one line")
        if any(token in line for token in _RULE_FORBIDDEN):
            raise RequestError("rules: forbidden character in a rule")
        lowered = line.lower()
        if any(word in lowered for word in _RULE_FORBIDDEN_WORDS):
            raise RequestError("rules: forbidden keyword in a rule")
        if not line.startswith(prefixes):
            raise RequestError(
                "rules: every line must add a rule to a replaced custom chain"
            )
        checked.append(line)
    return checked


def _wg_key(value, field: str) -> str:
    if value == "":
        return ""
    try:
        return settings_store.wg_key(value, field)
    except settings_store.SettingsError as exc:
        raise RequestError(str(exc)) from None


def _agent_id(value) -> str:
    if not isinstance(value, str) or not settings_store._ID_RE.match(value):
        raise RequestError("agents: invalid agent id")
    return value


def _tunnels(value) -> dict:
    """The kernel-relevant part of the tunnel settings (tunnel_reconcile)."""
    args = _expect(value, ("port", "server_private_key", "agents"))
    port = args["port"]
    if port is not None:
        port = _int(port, "port", 1, 65535)
    agents_raw = args["agents"]
    if not isinstance(agents_raw, list) \
            or len(agents_raw) > settings_store.MAX_TUNNEL_AGENTS:
        raise RequestError("agents: too many agents")
    agents = []
    for raw in agents_raw:
        agent = _expect(
            raw, ("id", "address", "public_key", "preshared_key", "enabled")
        )
        address = _ipv4(agent["address"])
        if ipaddress.IPv4Address(address) not in \
                settings_store.TUNNEL_SUBNET \
                or address == settings_store.TUNNEL_SERVER_ADDRESS:
            raise RequestError("agents: the address must be in the tunnel subnet")
        agents.append({
            "id": _agent_id(agent["id"]),
            "address": address,
            "public_key": _wg_key(agent["public_key"], "public_key"),
            "preshared_key": _wg_key(agent["preshared_key"], "preshared_key"),
            "enabled": _bool(agent["enabled"], "enabled"),
        })
    return {
        "port": port,
        "server_private_key": _wg_key(
            args["server_private_key"], "server_private_key"
        ),
        "agents": agents,
    }


def _tunnel_status_input(value) -> tuple[dict, float | None]:
    args = _expect(value, ("configured", "agents"), ("now",))
    agents_raw = args["agents"]
    if not isinstance(agents_raw, list) \
            or len(agents_raw) > settings_store.MAX_TUNNEL_AGENTS:
        raise RequestError("agents: too many agents")
    agents = []
    for raw in agents_raw:
        agent = _expect(raw, ("id", "public_key", "enabled"))
        agents.append({
            "id": _agent_id(agent["id"]),
            "public_key": _wg_key(agent["public_key"], "public_key"),
            "enabled": _bool(agent["enabled"], "enabled"),
        })
    now = args.get("now")
    if now is not None and (
        isinstance(now, bool) or not isinstance(now, (int, float))
    ):
        raise RequestError("now: a number is required")
    # TunnelManager.status() only asks whether a server key exists; the key
    # itself is not sent for a status read.
    tunnels = {
        "server_private_key": "configured" if _bool(
            args["configured"], "configured"
        ) else "",
        "agents": agents,
    }
    return tunnels, None if now is None else float(now)


# ------------------------------------------------------------- operations

class _AuditRecorder:
    """Collects the audit events of one request for the portal's audit log."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def write(self, event: str, **fields) -> None:
        if event in gateway.PRIV_HELPER_AUDIT_EVENTS:
            self.events.append({"event": event, "fields": fields})


class _NullStore:
    """Drop-log store stand-in while the helper binds the NFLOG group."""

    path = ""

    def write(self, entry, sync: bool = True) -> dict:
        return {}

    def sync(self) -> None:
        pass


def open_nflog_socket() -> socket.socket:
    """Bind and configure the NFLOG drop-log group (needs CAP_NET_ADMIN)."""
    listener = droplog.DropLogListener(
        _NullStore(), group=droplog.DROP_LOG_GROUP, enabled=True,
        logger=log,
    )
    return listener._open_socket()


class Helper:
    """The fixed command set; transport-independent (tests call dispatch)."""

    def __init__(
        self, firewall=None, tunnels=None, nflog_opener=None,
        allowed_uids=None,
    ) -> None:
        self.firewall = (
            firewall if firewall is not None else gateway.Firewall()
        )
        self.tunnels = (
            tunnels if tunnels is not None
            else tunnel_mod.TunnelManager(logger=log)
        )
        self.nflog_opener = nflog_opener or open_nflog_socket
        self.allowed_uids = frozenset(
            allowed_uids if allowed_uids is not None else default_uids()
        )
        # op -> handler(args, audit) -> JSON result
        self.ops = {
            "ping": self._ping,
            "grant_all": self._grant_all,
            "revoke": self._revoke,
            "deny": self._deny,
            "revoke_all": self._revoke_all,
            "revoke_exact": self._revoke_exact,
            "ban": self._ban,
            "unban": self._unban,
            "sync_bans": self._sync_bans,
            "sync_host_ports": self._sync_host_ports,
            "prune_host_service_ports": self._prune,
            "flush": self._flush,
            "replace_custom": self._replace_custom,
            "docker_published_ports": self._docker_published_ports,
            "snapshot": self._snapshot,
            "ruleset": self._ruleset,
            "state_token": self._state_token,
            "healthy": self._healthy,
            "input_chain_consistent": self._input_chain_consistent,
            "conntrack_flush": self._conntrack_flush,
            "conntrack_flush_removed": self._conntrack_flush_removed,
            "conntrack_flush_port": self._conntrack_flush_port,
            "tunnel_reconcile": self._tunnel_reconcile,
            "tunnel_remove_all": self._tunnel_remove_all,
            "tunnel_status": self._tunnel_status,
            # nflog_open is handled in dispatch(): it answers with a socket.
        }

    # -- handlers --------------------------------------------------------------

    @staticmethod
    def _ping(args, audit):
        _expect(args)
        return "pong"

    def _grant_all(self, args, audit):
        _expect(args, ("ip", "grants", "ttl"))
        self.firewall.grant_all(
            _ipv4(args["ip"]), _grants(args["grants"]),
            _int(args["ttl"], "ttl", 1, MAX_TTL),
        )

    def _revoke(self, args, audit):
        _expect(args, ("ip", "ports"))
        self.firewall.revoke(_ipv4(args["ip"]), _ports(args["ports"]))

    def _deny(self, args, audit):
        _expect(args, ("ip", "ports"))
        ports = None if args["ports"] is None else _ports(args["ports"])
        self.firewall.deny(_ipv4(args["ip"]), ports)

    def _revoke_all(self, args, audit):
        _expect(args, ("ip", "grants", "discover", "only_grants"))
        self.firewall.revoke_all(
            _ipv4(args["ip"]), _grants(args["grants"]),
            discover=_bool(args["discover"], "discover"),
            only_grants=_bool(args["only_grants"], "only_grants"),
        )

    def _revoke_exact(self, args, audit):
        _expect(args, ("ip", "grants"))
        self.firewall.revoke_exact(_ipv4(args["ip"]), _grants(args["grants"]))

    def _ban(self, args, audit):
        _expect(args, ("ip", "ttl", "set"))
        self.firewall.ban(
            _ipv4(args["ip"]), _int(args["ttl"], "ttl", 1, MAX_TTL),
            _ban_set(self.firewall, args["set"]),
        )

    def _unban(self, args, audit):
        _expect(args, ("ip", "set"))
        self.firewall.unban(
            _ipv4(args["ip"]), _ban_set(self.firewall, args["set"])
        )

    def _sync_bans(self, args, audit):
        _expect(args, ("elements", "set"))
        self.firewall.sync_bans(
            _ban_elements(args["elements"]),
            _ban_set(self.firewall, args["set"]),
        )

    def _sync_host_ports(self, args, audit):
        _expect(args, ("tcp", "udp"))
        self.firewall.sync_host_ports(
            _port_list(args["tcp"], "tcp"), _port_list(args["udp"], "udp")
        )

    def _prune(self, args, audit):
        _expect(args, ("tcp", "udp"))
        return self.firewall.prune_host_service_ports(
            _port_list(args["tcp"], "tcp"), _port_list(args["udp"], "udp"),
            audit=audit,
        )

    def _flush(self, args, audit):
        _expect(args)
        self.firewall.flush()

    def _replace_custom(self, args, audit):
        _expect(args, ("rules", "keep_block"))
        keep_block = _bool(args["keep_block"], "keep_block")
        chains = self.firewall.replaced_chains(keep_block)
        rules = check_custom_rules(args["rules"], self.firewall.table, chains)
        self.firewall._replace_custom_rules(rules, keep_block)

    def _docker_published_ports(self, args, audit):
        _expect(args)
        return sorted(
            [proto, port]
            for proto, port in self.firewall.docker_published_ports()
        )

    def _snapshot(self, args, audit):
        _expect(args)
        return self.firewall.snapshot()

    def _ruleset(self, args, audit):
        _expect(args)
        return self.firewall.ruleset()

    def _state_token(self, args, audit):
        _expect(args)
        return self.firewall.state_token()

    def _healthy(self, args, audit):
        _expect(args)
        return list(self.firewall.healthy())

    def _input_chain_consistent(self, args, audit):
        _expect(args, ("port",))
        return list(self.firewall.input_chain_consistent(
            _int(args["port"], "port", 1, 65535)
        ))

    def _conntrack_flush(self, args, audit):
        _expect(args, ("ip",))
        return gateway.conntrack_flush(_ipv4(args["ip"]), audit)

    def _conntrack_flush_removed(self, args, audit):
        _expect(args, ("ip", "removed", "remaining"))
        return gateway.conntrack_flush_removed(
            _ipv4(args["ip"]), _grants(args["removed"]),
            _grants(args["remaining"]), audit,
        )

    def _conntrack_flush_port(self, args, audit):
        _expect(args, ("proto", "port"))
        if args["proto"] not in ("tcp", "udp"):
            raise RequestError("proto: tcp or udp is required")
        return gateway.conntrack_flush_port(
            args["proto"], _int(args["port"], "port", 1, 65535), audit
        )

    def _tunnel_reconcile(self, args, audit):
        _expect(args, ("tunnels",))
        applied = self.tunnels.reconcile(_tunnels(args["tunnels"]))
        return {"applied": applied, "error": self.tunnels.error}

    def _tunnel_remove_all(self, args, audit):
        _expect(args)
        self.tunnels.remove_all()
        if self.tunnels.error:
            raise gateway.FirewallError(self.tunnels.error)

    def _tunnel_status(self, args, audit):
        _expect(args, ("tunnels",))
        tunnels, now = _tunnel_status_input(args["tunnels"])
        return self.tunnels.status(tunnels, now)

    # -- dispatch --------------------------------------------------------------

    @staticmethod
    def _error(kind: str, message: str) -> dict:
        return {"ok": False, "type": kind, "error": message}

    def dispatch(self, raw: bytes, peer_uid: int | None):
        """One request -> (answer dict, descriptor to pass or None)."""
        if peer_uid is None or peer_uid not in self.allowed_uids:
            return self._error("denied", "peer not allowed"), None
        if len(raw) > MAX_REQUEST:
            return self._error("invalid", "request too large"), None
        try:
            request = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return self._error("invalid", "malformed request"), None
        if not isinstance(request, dict) or set(request) != {"op", "args"} \
                or not isinstance(request["op"], str):
            return self._error("invalid", "malformed request"), None
        op, args = request["op"], request["args"]
        if op == "nflog_open":
            try:
                _expect(args)
                sock = self.nflog_opener()
            except RequestError as exc:
                return self._error("invalid", str(exc)), None
            except OSError as exc:
                return self._error("firewall", f"NFLOG: {exc}"), None
            return {"ok": True, "result": None}, sock
        handler = self.ops.get(op)
        if handler is None:
            return self._error("invalid", "unknown operation"), None
        audit = _AuditRecorder()
        try:
            result = handler(args, audit)
        except RequestError as exc:
            return self._error("invalid", f"{op}: {exc}"), None
        except gateway.FirewallError as exc:
            return self._error("firewall", str(exc)), None
        except Exception as exc:  # the helper must keep serving
            log(f"{op} failed: {exc!r}")
            return self._error("internal", f"{op}: internal error"), None
        answer = {"ok": True, "result": result}
        if audit.events:
            answer["audit"] = audit.events
        return answer, None


# ------------------------------------------------------------- transport

def default_uids() -> set[int]:
    """The portal user and root (HV_RUN_AS_ROOT=1 runs the portal as root)."""
    uids = {0}
    try:
        uids.add(pwd.getpwnam(APP_USER).pw_uid)
    except KeyError:
        pass
    return uids


def peer_uid(conn) -> int | None:
    try:
        raw = conn.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED.size
        )
        _pid, uid, _gid = _PEERCRED.unpack(raw[:_PEERCRED.size])
    except (OSError, struct.error, AttributeError):
        return None
    return uid


def read_request(
    conn, limit: int = MAX_REQUEST, timeout: float = REQUEST_TIMEOUT
) -> bytes:
    """Bytes up to the first newline; RequestError if longer than the limit.

    The whole request must arrive within ``timeout`` seconds (a trickling
    client cannot hold a connection slot); socket.timeout otherwise.
    """
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("request timed out")
        conn.settimeout(remaining)
        data = conn.recv(65536)
        if not data:
            break
        newline = data.find(b"\n")
        if newline >= 0:
            chunks.append(data[:newline])
            total += newline
            break
        chunks.append(data)
        total += len(data)
        if total > limit:
            raise RequestError("request too large")
    if total > limit:
        raise RequestError("request too large")
    return b"".join(chunks)


def send_answer(conn, answer: dict, sock=None) -> None:
    data = (json.dumps(answer, separators=(",", ":")) + "\n").encode("utf-8")
    if sock is None:
        conn.sendall(data)
        return
    # The descriptor travels with the first byte; the rest follows.
    fds = array.array("i", [sock.fileno()])
    conn.sendmsg(
        [data[:1]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds.tobytes())]
    )
    conn.sendall(data[1:])


class HelperServer:
    def __init__(self, helper: Helper, path: str = SOCKET_PATH) -> None:
        self.helper = helper
        self.path = path
        self.sock: socket.socket | None = None
        self._slots = threading.BoundedSemaphore(MAX_CLIENTS)

    def bind(self) -> None:
        try:
            state = os.lstat(self.path)
        except FileNotFoundError:
            state = None
        if state is not None:
            if not stat.S_ISSOCK(state.st_mode):
                raise SystemExit(f"{self.path} exists and is not a socket")
            os.unlink(self.path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o117)
        try:
            sock.bind(self.path)
        finally:
            os.umask(old_umask)
        # Owner root, group = this process's group (the portal's group, set
        # by setpriv or systemd's Group=); nobody else may connect.
        os.chmod(self.path, 0o660)
        sock.listen(32)
        self.sock = sock
        log(
            f"listening on {self.path} (allowed uids: "
            f"{', '.join(str(uid) for uid in sorted(self.helper.allowed_uids))})"
        )

    def handle(self, conn) -> None:
        sock = None
        try:
            conn.settimeout(REQUEST_TIMEOUT)
            uid = peer_uid(conn)
            if uid is None or uid not in self.helper.allowed_uids:
                log(f"refused a connection from uid {uid}")
                send_answer(conn, Helper._error("denied", "peer not allowed"))
                return
            try:
                raw = read_request(conn)
            except RequestError as exc:
                conn.settimeout(REQUEST_TIMEOUT)
                send_answer(conn, Helper._error("invalid", str(exc)))
                return
            answer, sock = self.helper.dispatch(raw, uid)
            conn.settimeout(REQUEST_TIMEOUT)
            try:
                send_answer(conn, answer, sock)
            except (TypeError, ValueError) as exc:  # not JSON-serializable
                log(f"cannot encode the answer: {exc}")
                send_answer(conn, Helper._error("internal", "internal error"))
        except OSError as exc:
            log(f"connection error: {exc}")
        finally:
            if sock is not None:
                sock.close()
            conn.close()
            self._slots.release()

    def serve_forever(self) -> None:
        assert self.sock is not None
        while True:
            conn, _addr = self.sock.accept()
            if not self._slots.acquire(blocking=False):
                try:
                    conn.settimeout(1.0)
                    send_answer(conn, Helper._error("busy", "helper busy"))
                except OSError:
                    pass
                conn.close()
                continue
            threading.Thread(
                target=self.handle, args=(conn,), name="dropjak-helper",
                daemon=True,
            ).start()

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None
        try:
            if stat.S_ISSOCK(os.lstat(self.path).st_mode):
                os.unlink(self.path)
        except OSError:
            pass


def main(argv: list[str]) -> int:
    allowed = None
    path = SOCKET_PATH
    args = list(argv)
    while args:
        flag = args.pop(0)
        if flag == "--socket" and args:
            path = args.pop(0)
        elif flag == "--allow-uid" and args:
            allowed = (allowed or set()) | {int(args.pop(0))}
        else:
            print(
                "Usage: privhelper.py [--socket PATH] [--allow-uid UID ...]",
                file=sys.stderr,
            )
            return 2
    helper = Helper(allowed_uids=allowed)
    server = HelperServer(helper, path)

    def stop(_signum, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    server.bind()
    try:
        server.serve_forever()
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
