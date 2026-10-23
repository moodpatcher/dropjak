#!/usr/bin/env python3
"""Dropjak home-side tunnel agent.

Like the playit.gg agent, the container joins the same *normal* Docker bridge
network(s) as the user's services and reaches them by container name over the
runtime's embedded DNS. There is no separate internal/egress pair and no
manual network setup: the installer attaches the agent to every bridge
network it finds and a systemd timer connects newly created ones later.

The agent terminates WireGuard in its *own* network namespace and DNATs the
tunnel ports to the application containers. Every target must resolve to an
address inside one of the attached bridge subnets; the interface whose subnet
contains that address carries the forwarded traffic and gets the masquerade
rule. Targets outside all attached subnets are rejected fail-closed.

Usage (the image entrypoint is ``python3 /agent.py``)::

    DROJAK_AGENT_CONFIG=/etc/dropjak/agent.json python3 agent.py

``DROJAK_AGENT_CONFIG`` overrides the config path
(default ``/etc/dropjak/agent.json``). The config is mounted read-only::

    {"format": "dropjak-agent", "version": 1,
     "agent": {"id": "home-1", "label": "Home", "address": "10.77.0.2"},
     "wireguard": {
       "private_key": "...", "address": "10.77.0.2/24",
       "peer_public_key": "...", "preshared_key": "...",
       "endpoint": "203.0.113.7:51820",
       "allowed_ips": ["10.77.0.1/32"], "persistent_keepalive": 25,
       "interface": "wg0", "listen_port": 0},
     "sync": {"url": "http://10.77.0.1:8100/api/tunnel/config",
              "token": "...", "interval_seconds": 30},
     "services": [{"id": "mc", "label": "Minecraft", "proto": "tcp|udp|both",
                   "tunnel_port": 41001, "target": "mc:25565",
                   "enabled": true}]}

``interface`` and ``listen_port`` are optional (``wg0`` / ``0``). The agent
applies the nftables ruleset *before* the tunnel is created, then loops:
GET the sync URL with ``Authorization: Bearer <token>``, re-resolve every
target (container restarts change IPs), render and apply the complete
ruleset atomically. Any failure keeps the previous rules and is logged.

The last successfully applied service list is written to
``/var/lib/dropjak-agent/last-config.json`` (mode 0600). On restart it is
applied before the first sync, so a cloud outage does not take the tunnel
down. Logs are one compact JSON object per line on stderr (never secrets).
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Iterable
from pathlib import Path

CONFIG_PATH = "/etc/dropjak/agent.json"
STATE_DIR = "/var/lib/dropjak-agent"
STATE_FILE = "last-config.json"
STATE_FORMAT = "dropjak-agent-state"
TABLE = "inet dropjak_agent"
WG_MTU = 1420
SYNC_TIMEOUT = 5
MAX_RESPONSE = 1_000_000
TUNNEL_NET = ipaddress.ip_network("10.77.0.0/24")
SERVER_IP = ipaddress.ip_address("10.77.0.1")

KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
IFACE_ADDR_RE = re.compile(
    r"^\s*\d+:\s+([^@\s:]+)(?:@[^:\s]+)?\s+inet\s+"
    r"(\d+\.\d+\.\d+\.\d+)/(\d+)\b")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,252}[A-Za-z0-9])?$")
ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
TOKEN_RE = re.compile(r"^[!-~]+$")


class ConfigError(ValueError):
    """The config (or a synced service list) is not safe to apply."""


class ApplyError(RuntimeError):
    """Resolving or applying the ruleset failed; the old rules are intact."""


class CommandError(RuntimeError):
    """A helper command exited non-zero."""


def log(level: str, event: str, **fields: object) -> None:
    """One parseable JSON line per event; never pass secrets here."""
    record: dict[str, object] = {"ts": int(time.time()), "level": level,
                                 "event": event}
    record.update(fields)
    print(json.dumps(record, sort_keys=True, separators=(",", ":")),
          file=sys.stderr, flush=True)


def run_command(argv: list[str], *, stdin: str | None = None,
                check: bool = True) -> subprocess.CompletedProcess:
    """Run a helper with an argument list, never a shell."""
    result = subprocess.run(argv, input=stdin, capture_output=True, text=True,
                            timeout=30)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:300]
        raise CommandError(f"{argv[0]} failed (rc={result.returncode}): {detail}")
    return result


# --------------------------------------------------------------------------
# Config validation. Never start WireGuard or forwarding with bad input.

def _obj(value: object, field: str, allowed: set[str],
         strict: bool = True) -> dict:
    if not isinstance(value, dict):
        raise ConfigError(f"{field}: object expected")
    if strict:
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ConfigError(f"{field}: unknown keys {unknown}")
    return value


def _text(value: object, field: str, *, pattern: re.Pattern | None = None,
          max_len: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ConfigError(f"{field}: non-empty string expected")
    if pattern is not None and not pattern.match(value):
        raise ConfigError(f"{field}: invalid format")
    return value


def _integer(value: object, field: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ConfigError(f"{field}: integer {low}..{high} expected")
    return value


def _ipv4(value: object, field: str) -> ipaddress.IPv4Address:
    try:
        addr = ipaddress.ip_address(value)  # type: ignore[arg-type]
    except ValueError as exc:
        raise ConfigError(f"{field}: IPv4 address expected") from exc
    if addr.version != 4:
        raise ConfigError(f"{field}: IPv4 address expected")
    return addr


def _wg_key(value: object, field: str) -> str:
    key = _text(value, field, pattern=KEY_RE, max_len=44)
    try:
        decoded = base64.b64decode(key, validate=True)
    except ValueError as exc:
        raise ConfigError(f"{field}: base64 key expected") from exc
    if len(decoded) != 32:
        raise ConfigError(f"{field}: 32-byte key expected")
    return key


def _host(value: object, field: str) -> str:
    text = _text(value, field, max_len=253)
    if ":" in text:
        raise ConfigError(f"{field}: IPv4 or hostname expected")
    try:
        ipaddress.ip_address(text)
    except ValueError:
        if not HOST_RE.match(text):
            raise ConfigError(f"{field}: IPv4 or hostname expected") from None
    return text


def _host_port(value: object, field: str) -> tuple[str, int]:
    if not isinstance(value, str):
        raise ConfigError(f"{field}: host:port expected")
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise ConfigError(f"{field}: host:port expected")
    return (_host(host, f"{field}.host"),
            _integer(int(port) if port.isdigit() else None,
                     f"{field}.port", 1, 65535))


def _url(value: object, field: str) -> tuple[str, int, int]:
    """Return (url, host, port); http(s) only, no embedded credentials."""
    url = _text(value, field, max_len=2048)
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(f"{field}: http(s) URL expected")
    if parts.username or parts.password:
        raise ConfigError(f"{field}: credentials are not allowed in the URL")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise ConfigError(f"{field}: invalid port") from exc
    return url, _host(parts.hostname, f"{field}.host"), port


def _service(value: object, field: str, strict: bool = True) -> dict:
    svc = _obj(value, field,
               {"id", "label", "proto", "tunnel_port", "target", "enabled"},
               strict=strict)
    sid = _text(svc.get("id"), f"{field}.id", pattern=ID_RE, max_len=64)
    return {
        "id": sid,
        # The cloud may omit the display label; the id is a safe fallback.
        "label": _text(svc.get("label", sid), f"{field}.label", max_len=128),
        "proto": _one_of(svc.get("proto"), f"{field}.proto",
                         ("tcp", "udp", "both")),
        "tunnel_port": _integer(svc.get("tunnel_port"),
                                f"{field}.tunnel_port", 1, 65535),
        "target": "%s:%d" % _host_port(svc.get("target"), f"{field}.target"),
        "enabled": _bool(svc.get("enabled"), f"{field}.enabled"),
    }


def _one_of(value: object, field: str, choices: tuple[str, ...]) -> str:
    if value not in choices:
        raise ConfigError(f"{field}: one of {', '.join(choices)} expected")
    return value  # type: ignore[return-value]


def _bool(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise ConfigError(f"{field}: boolean expected")
    return value


def validate_services(value: object, *, strict: bool = True) -> list[dict]:
    """Validate a service list; ids and tunnel ports must be unique."""
    if not isinstance(value, list):
        raise ConfigError("services: list expected")
    services = [_service(item, f"services[{i}]", strict=strict)
                for i, item in enumerate(value)]
    if len(services) > 256:
        raise ConfigError("services: at most 256 entries")
    ids = [s["id"] for s in services]
    ports = [s["tunnel_port"] for s in services]
    if len(set(ids)) != len(ids):
        raise ConfigError("services: duplicate id")
    if len(set(ports)) != len(ports):
        raise ConfigError("services: duplicate tunnel_port")
    return services


def validate_config(raw: object) -> dict:
    """Validate and normalise the whole agent config."""
    cfg = _obj(raw, "config", {"format", "version", "agent", "wireguard",
                               "sync", "services"})
    if cfg.get("format") != "dropjak-agent":
        raise ConfigError("format: dropjak-agent expected")
    if cfg.get("version") != 1 or type(cfg["version"]) is not int:
        raise ConfigError("version: 1 expected")

    agent = _obj(cfg.get("agent"), "agent", {"id", "label", "address"})
    agent_id = _text(agent.get("id"), "agent.id", pattern=ID_RE, max_len=64)
    agent_label = _text(agent.get("label"), "agent.label", max_len=128)
    agent_addr = _ipv4(agent.get("address"), "agent.address")
    if agent_addr not in TUNNEL_NET or agent_addr == SERVER_IP:
        raise ConfigError("agent.address: must be a client address in 10.77.0.0/24")

    wg = _obj(cfg.get("wireguard"), "wireguard",
              {"private_key", "address", "peer_public_key", "preshared_key",
               "endpoint", "allowed_ips", "persistent_keepalive", "interface",
               "listen_port"})
    private_key = _wg_key(wg.get("private_key"), "wireguard.private_key")
    peer_key = _wg_key(wg.get("peer_public_key"), "wireguard.peer_public_key")
    psk = _wg_key(wg.get("preshared_key"), "wireguard.preshared_key")
    address = wg.get("address")
    if not isinstance(address, str):
        raise ConfigError("wireguard.address: CIDR expected")
    try:
        iface_addr = ipaddress.ip_interface(address)
    except ValueError as exc:
        raise ConfigError("wireguard.address: CIDR expected") from exc
    if (iface_addr.version != 4 or iface_addr.ip != agent_addr
            or iface_addr.network != TUNNEL_NET):
        raise ConfigError("wireguard.address: must be agent.address/24")
    endpoint_host, endpoint_port = _host_port(wg.get("endpoint"),
                                              "wireguard.endpoint")
    allowed_raw = wg.get("allowed_ips")
    if not isinstance(allowed_raw, list) or not allowed_raw:
        raise ConfigError("wireguard.allowed_ips: non-empty list expected")
    allowed: list[str] = []
    for i, item in enumerate(allowed_raw):
        try:
            net = ipaddress.ip_network(item, strict=True)
        except (ValueError, TypeError) as exc:
            raise ConfigError(
                f"wireguard.allowed_ips[{i}]: IPv4 CIDR expected") from exc
        if net.version != 4 or not net.subnet_of(TUNNEL_NET):
            raise ConfigError(
                f"wireguard.allowed_ips[{i}]: must be inside 10.77.0.0/24")
        allowed.append(str(net))
    if not any(SERVER_IP in ipaddress.ip_network(net) for net in allowed):
        raise ConfigError("wireguard.allowed_ips: must route 10.77.0.1/32")
    keepalive = _integer(wg.get("persistent_keepalive", 25),
                         "wireguard.persistent_keepalive", 0, 65535)
    wg_iface = wg.get("interface", "wg0")
    if (not isinstance(wg_iface, str) or not IFACE_RE.match(wg_iface)
            or wg_iface in ("lo", "..", ".")):
        raise ConfigError("wireguard.interface: invalid interface name")
    listen_port = _integer(wg.get("listen_port", 0),
                           "wireguard.listen_port", 0, 65535)

    sync = _obj(cfg.get("sync"), "sync",
                {"url", "token", "interval_seconds"})
    sync_url, _, _ = _url(sync.get("url"), "sync.url")
    token = _text(sync.get("token"), "sync.token", pattern=TOKEN_RE,
                  max_len=4096)
    interval = _integer(sync.get("interval_seconds"), "sync.interval_seconds",
                        5, 86400)

    services = validate_services(cfg.get("services"), strict=True)

    return {
        "format": "dropjak-agent",
        "version": 1,
        "agent": {"id": agent_id, "label": agent_label,
                  "address": str(agent_addr)},
        "wireguard": {
            "private_key": private_key,
            "address": str(iface_addr),
            "peer_public_key": peer_key,
            "preshared_key": psk,
            "endpoint": f"{endpoint_host}:{endpoint_port}",
            "endpoint_host": endpoint_host,
            "endpoint_port": endpoint_port,
            "allowed_ips": allowed,
            "persistent_keepalive": keepalive,
            "interface": wg_iface,
            "listen_port": listen_port,
        },
        "sync": {"url": sync_url, "token": token,
                 "interval_seconds": interval},
        "services": services,
    }


def load_config(path: str) -> dict:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise ConfigError("config is not valid JSON") from exc
    return validate_config(raw)


# --------------------------------------------------------------------------
# nftables rendering. Everything is rendered from validated values; the
# loader passes this text to ``nft -f -`` as one atomic transaction. The
# input chain only accepts replies to flows the agent itself opened, which is
# enough because the persistent keepalive opens the WireGuard UDP flow.

def _protocols(proto: str) -> tuple[str, ...]:
    return ("tcp", "udp") if proto == "both" else (proto,)


def _sync_port(config: dict) -> int:
    return urllib.parse.urlsplit(config["sync"]["url"]).port or (
        443 if config["sync"]["url"].startswith("https:") else 80)


def _resolver_ips(path: str = "/etc/resolv.conf") -> list[str]:
    """The container's DNS servers (the nftables output allows these).

    In Docker this is 127.0.0.11, in rootless Podman the network gateway
    (for example 10.89.1.1); /proc/sys is read-only, but resolv.conf
    is readable, so the addresses are taken from here.
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    ips: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] != "nameserver":
            continue
        try:
            ip = ipaddress.ip_address(parts[1])
        except ValueError:
            continue
        if ip.version == 4:
            ips.append(str(ip))
    return ips


def _normalise_ifaces(value: str | Iterable[str] | None) -> list[str]:
    """Accept None, one interface name or an iterable; deterministic order."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    return sorted({str(item) for item in value if item})


def render_ruleset(config: dict, services: list[dict], endpoint_ips: list[str],
                   internal_ifaces: str | Iterable[str] | None,
                   sync_ips: list[str], dns_ips: list[str]) -> str:
    """Render the complete ``inet dropjak_agent`` ruleset.

    ``internal_ifaces`` is the set of attached bridge interfaces (a single
    name is accepted for backwards compatibility). Each service may carry its
    own ``iface``: the interface whose subnet contains the resolved target
    address. Forward accept, the return established rule and masquerade are
    rendered per interface, so targets on several networks work together.
    """
    wg = config["wireguard"]["interface"]
    endpoint_port = config["wireguard"]["endpoint_port"]
    sync_port = _sync_port(config)
    tunnel_net = str(ipaddress.ip_interface(
        config["wireguard"]["address"]).network)
    ifaces = _normalise_ifaces(internal_ifaces)
    ordered = sorted(services, key=lambda s: (s["tunnel_port"], s["id"]))
    routed: list[tuple[dict, str]] = []
    for svc in ordered:
        iface = svc.get("iface")
        if not iface and len(ifaces) == 1:
            iface = ifaces[0]
        if not iface:
            raise ValueError(
                f"service {svc['id']}: no interface for target")
        routed.append((svc, str(iface)))
    used_ifaces = sorted({iface for _, iface in routed})
    lines = [
        "# generated by dropjak-tunnel-agent; do not edit",
        f"add table {TABLE}",
        f"flush table {TABLE}",
        f"table {TABLE} {{",
        "\tchain input {",
        "\t\ttype filter hook input priority filter; policy drop;",
        "\t\tct state established,related accept",
        '\t\tiifname "lo" accept',
        "\t}",
        "\tchain forward {",
        "\t\ttype filter hook forward priority filter; policy drop;",
    ]
    for svc, iface in routed:
        for proto in _protocols(svc["proto"]):
            lines.append(
                f'\t\tiifname "{wg}" oifname "{iface}" '
                f'ip daddr {svc["ip"]} {proto} dport '
                f'{svc["target_port"]} accept')
    for iface in used_ifaces:
        lines.append(f'\t\tiifname "{iface}" oifname "{wg}" '
                     "ct state established,related accept")
    lines += [
        "\t}",
        "\tchain output {",
        "\t\ttype filter hook output priority filter; policy drop;",
        '\t\toifname "lo" accept',
    ]
    # Docker's built-in DNS and the resolv.conf name servers (Podman gateway).
    for ip in sorted(set(dns_ips) | {"127.0.0.11"}):
        lines.append(f"\t\tip daddr {ip} udp dport 53 accept")
        lines.append(f"\t\tip daddr {ip} tcp dport 53 accept")
    lines.append("\t\tct state established,related accept")
    for ip in sorted(set(endpoint_ips)):
        lines.append(f"\t\tip daddr {ip} udp dport {endpoint_port} accept")
    for ip in sorted(set(sync_ips)):
        # The service-list fetch itself: outbound TCP to the sync endpoint.
        lines.append(f"\t\tip daddr {ip} tcp dport {sync_port} accept")
    lines += [
        "\t}",
        "\tchain prerouting {",
        "\t\ttype nat hook prerouting priority dstnat; policy accept;",
    ]
    for svc, _ in routed:
        for proto in _protocols(svc["proto"]):
            lines.append(
                f'\t\tiifname "{wg}" {proto} dport {svc["tunnel_port"]} '
                f'dnat ip to {svc["ip"]}:{svc["target_port"]}')
    lines += [
        "\t}",
        "\tchain postrouting {",
        "\t\ttype nat hook postrouting priority srcnat; policy accept;",
    ]
    # Source NAT: the service sees the agent's address on that network, and
    # replies return through this namespace (the bridge network has no route
    # back to 10.77.0.0/24). Client IPs are therefore not preserved. One rule
    # per distinct attached interface, so several networks can be used.
    for iface in used_ifaces:
        lines.append(f'\t\toifname "{iface}" '
                     f"ip saddr {tunnel_net} masquerade")
    lines += ["\t}", "}"]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------

def _split_target(target: str) -> tuple[str, int]:
    host, _, port = target.rpartition(":")
    return host, int(port)


class Agent:
    """Owns the WireGuard interface and the nftables ruleset in this netns."""

    def __init__(self, config: dict, *, state_dir: str | os.PathLike = STATE_DIR,
                 runner=run_command, getaddrinfo=socket.getaddrinfo,
                 urlopen=urllib.request.urlopen, logger=log) -> None:
        self.config = config
        self.state_dir = Path(state_dir)
        self.run = runner
        self.getaddrinfo = getaddrinfo
        self.urlopen = urlopen
        self.log = logger
        self._stop = threading.Event()
        self._endpoint_ips: list[str] = []
        self._sync_ips: list[str] = []
        self._internal_ifaces: list[str] = []
        self._services: list[dict] = []

    @property
    def wireguard(self) -> dict:
        return self.config["wireguard"]

    # -- setup ------------------------------------------------------------

    def _set_ip_forward(self) -> None:
        path = Path("/proc/sys/net/ipv4/ip_forward")
        try:
            # The compose sysctls may set it in advance; under rootless Podman
            # /proc/sys is read-only, so writing would fail with EROFS.
            if path.read_text(encoding="ascii").strip() == "1":
                return
            path.write_text("1\n")
        except OSError as exc:
            raise ApplyError(
                f"cannot enable ip_forward in this netns: {exc.strerror}") from exc

    def _resolve_ipv4(self, host: str, port: int, socktype: int,
                      field: str) -> str:
        try:
            infos = self.getaddrinfo(host, port, socket.AF_INET, socktype)
        except OSError as exc:
            raise ApplyError(f"{field}: cannot resolve {host}: {exc}") from exc
        for info in infos:
            if info[0] == socket.AF_INET:
                return info[4][0]
        raise ApplyError(f"{field}: no IPv4 address for {host}")

    def _resolve_endpoint(self) -> list[str]:
        wg = self.wireguard
        ips: list[str] = []
        try:
            infos = self.getaddrinfo(wg["endpoint_host"], wg["endpoint_port"],
                                     socket.AF_INET, socket.SOCK_DGRAM)
        except OSError as exc:
            raise ApplyError(
                f"wireguard.endpoint: cannot resolve {wg['endpoint_host']}: "
                f"{exc}") from exc
        for info in infos:
            if info[0] == socket.AF_INET and info[4][0] not in ips:
                ips.append(info[4][0])
        if not ips:
            raise ApplyError("wireguard.endpoint: no IPv4 address")
        return ips

    def _resolve_sync(self) -> list[str]:
        parts = urllib.parse.urlsplit(self.config["sync"]["url"])
        port = parts.port or (443 if parts.scheme == "https" else 80)
        try:
            infos = self.getaddrinfo(parts.hostname, port,
                                     socket.AF_INET, socket.SOCK_STREAM)
        except OSError as exc:
            raise ApplyError(
                f"sync.url: cannot resolve {parts.hostname}: {exc}") from exc
        ips: list[str] = []
        for info in infos:
            if info[0] == socket.AF_INET and info[4][0] not in ips:
                ips.append(info[4][0])
        if not ips:
            raise ApplyError("sync.url: no IPv4 address")
        return ips

    def list_interfaces(self) -> list[dict]:
        """Attached IPv4 bridge interfaces with their subnets.

        ``lo`` and the WireGuard interface are never targets. The result is
        sorted, so two syncs render identical rules for identical input.
        """
        result = self.run(["ip", "-4", "-o", "addr", "show"])
        found: list[dict] = []
        for line in (result.stdout or "").splitlines():
            match = IFACE_ADDR_RE.match(line)
            if not match:
                continue
            dev = match.group(1)
            if dev in ("lo", self.wireguard["interface"]):
                continue
            if not IFACE_RE.match(dev):
                continue
            try:
                iface = ipaddress.IPv4Interface(
                    f"{match.group(2)}/{match.group(3)}")
            except ValueError:
                continue
            found.append({"dev": dev, "network": iface.network,
                          "ip": iface.ip,
                          "prefixlen": iface.network.prefixlen})
        found.sort(key=lambda item: (item["dev"], item["prefixlen"]))
        return found

    def detect_interface(self, ip: str) -> str:
        """Interface whose attached subnet contains ``ip``.

        More than one bridge network is normal: the target decides. The
        longest-prefix match wins (then the interface name), so the choice is
        stable and overlapping Docker subnets do not flip between syncs.
        """
        try:
            address = ipaddress.IPv4Address(ip)
        except ValueError as exc:
            raise ApplyError(f"invalid target address {ip}") from exc
        candidates = [
            item for item in self.list_interfaces()
            if address in item["network"]
        ]
        if not candidates:
            raise ApplyError(
                f"{ip} is not on any attached Docker bridge network")
        candidates.sort(key=lambda item: (-item["prefixlen"], item["dev"]))
        return str(candidates[0]["dev"])

    def check_target(self, service_id: str, ip: str, dev: str) -> None:
        """Only container addresses on the chosen bridge subnet are targets.

        The Docker bridge gateway (by default the network's .1 address) represents the host,
        so it cannot be a tunnel target: otherwise the host's services
        (for example SSH) would be reachable from the cloud. The network/broadcast address and the agent's
        own address are forbidden in the same way. The check runs on the selected interface's
        subnet that contains the target.
        """
        address = ipaddress.IPv4Address(ip)
        candidates = [
            item for item in self.list_interfaces()
            if item["dev"] == dev and address in item["network"]
        ]
        if not candidates:
            raise ApplyError(
                f"service {service_id}: {ip} is not on {dev}")
        candidates.sort(key=lambda item: (-item["prefixlen"], item["dev"]))
        network = candidates[0]["network"]
        own = candidates[0]["ip"]
        gateway = network.network_address + 1
        if address in (network.network_address,
                       network.broadcast_address, own, gateway):
            raise ApplyError(
                f"service {service_id}: {ip} is not a container address "
                f"on {dev}"
            )

    def resolve_services(self, services: list[dict]) -> tuple[list[dict],
                                                               list[str]]:
        """Resolve targets and pick each service's bridge interface.

        Every target must fall inside one attached bridge subnet; the target
        address itself decides the interface, so services may live on several
        networks at once. A target outside every attached subnet fails the
        whole sync, keeping the last good ruleset.
        """
        entries: list[dict] = []
        ifaces: set[str] = set()
        for svc in services:
            if not svc["enabled"]:
                continue
            host, port = _split_target(svc["target"])
            ip = self._resolve_ipv4(host, port, socket.SOCK_STREAM,
                                    f"service {svc['id']}")
            dev = self.detect_interface(ip)
            self.check_target(svc["id"], ip, dev)
            ifaces.add(dev)
            entries.append({"id": svc["id"], "proto": svc["proto"],
                            "tunnel_port": svc["tunnel_port"], "ip": ip,
                            "target_port": port, "iface": dev})
        ordered_ifaces = sorted(ifaces)
        self._internal_ifaces = ordered_ifaces
        return entries, ordered_ifaces

    def apply_services(self, services: list[dict]) -> str:
        """Resolve, render and atomically load the complete ruleset."""
        entries, ifaces = self.resolve_services(services)
        rules = render_ruleset(self.config, entries, self._endpoint_ips,
                               ifaces, self._sync_ips, _resolver_ips())
        self.run(["nft", "-f", "-"], stdin=rules)
        self._services = [dict(s) for s in services if s["enabled"]]
        return rules

    def _with_secret_file(self, secret: str, action) -> None:
        # WireGuard tools only take key *files*, never keys on the command
        # line (visible in /proc/*/cmdline). /tmp is a tmpfs in the image.
        fd, path = tempfile.mkstemp(prefix="dropjak-wg-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(secret.encode("ascii"))
            fd = -1
            action(path)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(path)
            except OSError:
                pass

    def bring_up_tunnel(self) -> None:
        wg = self.wireguard
        iface = wg["interface"]
        self.run(["ip", "link", "del", iface], check=False)
        self.run(["ip", "link", "add", iface, "type", "wireguard"])

        def set_private(path: str) -> None:
            self.run(["wg", "set", iface, "private-key", path,
                      "listen-port", str(wg["listen_port"])])

        self._with_secret_file(wg["private_key"], set_private)
        self.run(["ip", "addr", "add", wg["address"], "dev", iface])
        self.run(["ip", "link", "set", "dev", iface, "mtu", str(WG_MTU), "up"])

        def set_peer(path: str) -> None:
            self.run(["wg", "set", iface, "peer", wg["peer_public_key"],
                      "preshared-key", path,
                      "allowed-ips", ",".join(wg["allowed_ips"]),
                      "persistent-keepalive",
                      str(wg["persistent_keepalive"]),
                      "endpoint",
                      f"{self._endpoint_ips[0]}:{wg['endpoint_port']}"])

        self._with_secret_file(wg["preshared_key"], set_peer)

    # -- state ------------------------------------------------------------

    def load_state(self) -> list[dict] | None:
        path = self.state_dir / STATE_FILE
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if (not isinstance(raw, dict) or raw.get("format") != STATE_FORMAT
                or raw.get("version") != 1):
            return None
        try:
            return validate_services(raw.get("services"), strict=True)
        except ConfigError:
            return None

    def save_state(self, services: list[dict]) -> None:
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        payload = {"format": STATE_FORMAT, "version": 1,
                   "saved_at": int(time.time()), "services": services}
        fd, tmp = tempfile.mkstemp(dir=self.state_dir, prefix=".last-config-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.state_dir / STATE_FILE)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # -- sync -------------------------------------------------------------

    def fetch_services(self) -> list[dict]:
        sync = self.config["sync"]
        request = urllib.request.Request(
            sync["url"], method="GET",
            headers={"Authorization": f"Bearer {sync['token']}",
                     "Accept": "application/json"})
        with self.urlopen(request, timeout=SYNC_TIMEOUT) as response:
            status = getattr(response, "status", None) or response.getcode()
            if status != 200:
                raise ApplyError(f"sync HTTP status {status}")
            body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise ApplyError("sync response too large")
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ApplyError("sync response is not valid JSON") from exc
        raw = data.get("services") if isinstance(data, dict) else data
        if not isinstance(raw, list):
            raise ApplyError("sync response has no services list")
        return validate_services(raw, strict=False)

    def sync_once(self) -> bool:
        try:
            services = self.fetch_services()
            self.apply_services(services)
            try:
                self.save_state(self._services)
            except OSError as exc:
                # Rules are live; only the outage fallback could not persist.
                self.log("warning", "state_save_failed",
                         error=type(exc).__name__)
            self.log("info", "sync_ok", services=len(self._services),
                     internal_ifaces=self._internal_ifaces)
            return True
        except Exception as exc:
            # Any failure (network, JSON, validation, resolution, nft) keeps
            # the previous rules: the nft transaction is atomic.
            self.log("warning", "sync_failed", error=type(exc).__name__,
                     detail=str(exc)[:300])
            return False

    def startup(self) -> None:
        self._set_ip_forward()
        self._endpoint_ips = self._resolve_endpoint()
        self._sync_ips = self._resolve_sync()
        services = self.load_state()
        source = "state"
        if services is None:
            services = self.config["services"]
            source = "config"
        self.apply_services(services)
        self.bring_up_tunnel()
        self.log("info", "startup", source=source,
                 services=len(self._services),
                 internal_ifaces=self._internal_ifaces,
                 endpoint=f"{self.wireguard['endpoint_host']}:"
                          f"{self.wireguard['endpoint_port']}")

    def run_forever(self) -> None:
        interval = self.config["sync"]["interval_seconds"]
        while not self._stop.is_set():
            self.sync_once()
            if self._stop.wait(interval):
                break

    def stop(self) -> None:
        self._stop.set()

    def shutdown(self) -> None:
        """Stop the loop and remove tunnel and rules together."""
        self._stop.set()
        for argv in (["ip", "link", "del", self.wireguard["interface"]],
                     ["nft", "delete", "table", *TABLE.split()]):
            try:
                self.run(argv, check=False)
            except Exception:
                # The netns is going away; cleanup is best effort.
                pass


def main() -> int:
    path = os.environ.get("DROJAK_AGENT_CONFIG", CONFIG_PATH)
    try:
        config = load_config(path)
    except ConfigError as exc:
        log("error", "config_invalid", path=path, error=str(exc)[:300])
        return 2
    agent = Agent(config)

    def on_signal(signum, _frame) -> None:
        log("info", "signal", signal=signum)
        agent.stop()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    try:
        agent.startup()
    except Exception as exc:  # startup must never leave half-configured state
        log("error", "startup_failed", error=type(exc).__name__,
            detail=str(exc)[:300])
        agent.shutdown()
        return 1
    try:
        agent.run_forever()
    except Exception as exc:
        log("error", "fatal", error=type(exc).__name__, detail=str(exc)[:300])
        agent.shutdown()
        return 1
    agent.shutdown()
    log("info", "stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
