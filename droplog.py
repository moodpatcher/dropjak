#!/usr/bin/env python3
"""
Dropjak — log of dropped packets via NFLOG.

The nftables ``log ... group N`` rules send the packet header and payload
through the kernel NFLOG (nfnetlink_log) mechanism. This module binds the
given group on a raw NETLINK_NETFILTER socket, processes the packets and
writes them to a JSON Lines file.

Why NFLOG: the container runs only with NET_ADMIN and has no CAP_SYSLOG, so
the kernel dmesg / /dev/kmsg log cannot be used. NFLOG requires only
NET_ADMIN, and the kernel sends packets directly to the portal process.

The log does not contain the whole packet: only the IPv4 header, the
transport ports, the interface, the source MAC and the nft prefix (reason)
go into the file. The file is created with 0600 permissions and is rotated
with a size limit.
"""

from __future__ import annotations

import errno
import json
import os
import re
import socket
import struct
import threading
import time
from datetime import datetime, timezone


BASE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.environ.get("HV_STATE_DIR", "").strip() or BASE


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


DROP_LOG_PATH = (
    os.environ.get("HV_DROP_LOG_PATH", "").strip()
    or os.path.join(STATE_DIR, "drops.jsonl")
)
DROP_LOG_MAX_BYTES = _env_int(
    "HV_DROP_LOG_MAX_BYTES", 10 * 1024 * 1024, 256 * 1024
)
DROP_LOG_KEEP = min(20, _env_int("HV_DROP_LOG_KEEP", 5, 1))
DROP_LOG_GROUP = min(
    65535, max(1, _env_int("HV_DROP_LOG_GROUP", 5, 1))
)
DROP_LOG_ENABLED = _env_bool("HV_DROP_LOG", True)
# Bytes of each packet the kernel copies to us. The parser needs only the
# IPv4 header (at most 60 bytes) and the first 4 bytes of TCP/UDP; copying
# whole packets (up to 64 KiB) fills the netlink buffer much sooner.
DROP_LOG_COPY_RANGE = 128
# After a fatal socket error the listener reopens the socket, waiting
# 1, 2, 4 ... seconds between attempts, at most 60.
DROP_LOG_RESTART_MIN_DELAY = 1.0
DROP_LOG_RESTART_MAX_DELAY = 60.0
# The listener fsyncs the log file at most this often, not per packet.
DROP_LOG_SYNC_INTERVAL = 1.0
# One read() scans at most this many lines across all files, newest first,
# so an admin page refresh stays cheap even when the log is full.
DROP_LOG_READ_MAX_LINES = 200_000


def _utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def _default_log(message: str) -> None:
    print(message, flush=True)


_REASON_RE = re.compile(r"reason=([A-Za-z0-9_.:-]+)")
_MAX_STRING = 256

# The portal writes the fact of a fail2ban ban to the log as a single event
# (reason=fail2ban, event=ban). Packets dropped during the ban are logged by
# the firewall on a sampled basis (reason=fail2ban), but read() attaches
# these to the single ban row, so the UI does not get one row per packet.
BAN_EVENT_REASON = "fail2ban"
BAN_EVENT_KIND = "ban"

# The UI distinguishes two row types: ordinary drops get "DROP", sources
# banned by fail2ban (and attempts after the ban) get the "fail2ban" label.
# The raw kernel reasons stay unchanged and are visible in the detailed
# JSON.
BAN_GROUP = "ban"
DROP_GROUP = "drop"
# The proxy block page (401): an application-level row, not a packet; the
# portal writes it directly to the store, so it does not feed fail2ban's
# drop signals.
PROXY_DROP_REASON = "proxy-unauthorized"
PROXY_GROUP = "proxy"


def reason_group(reason: str) -> str:
    """The row's UI category: fail2ban, proxy or DROP."""
    reason = str(reason or "").strip().lower()
    if reason == BAN_EVENT_REASON:
        return BAN_GROUP
    if reason == PROXY_DROP_REASON:
        return PROXY_GROUP
    return DROP_GROUP


# --------------------------------------------------------------- NFLOG constants

NETLINK_NETFILTER = 12
NFNL_SUBSYS_ULOG = 4
NFULNL_MSG_PACKET = 0
NFULNL_MSG_CONFIG = 1

NFULNL_CFG_CMD_BIND = 1
NFULNL_CFG_CMD_UNBIND = 2
NFULNL_CFG_CMD_PF_BIND = 3
NFULNL_CFG_CMD_PF_UNBIND = 4

NFULA_CFG_CMD = 1
NFULA_CFG_MODE = 2
NFULA_CFG_NLBUFSIZ = 3
NFULA_CFG_TIMEOUT = 4
NFULA_CFG_QTHRESH = 5
NFULA_CFG_FLAGS = 6

NFULNL_COPY_NONE = 0
NFULNL_COPY_META = 1
NFULNL_COPY_PACKET = 2

NFULA_PACKET_HDR = 1
NFULA_MARK = 2
NFULA_TIMESTAMP = 3
NFULA_IFINDEX_INDEV = 4
NFULA_IFINDEX_OUTDEV = 5
NFULA_IFINDEX_PHYSINDEV = 6
NFULA_IFINDEX_PHYSOUTDEV = 7
NFULA_HWADDR = 8
NFULA_PAYLOAD = 9
NFULA_PREFIX = 10
NFULA_UID = 11
NFULA_SEQ = 12
NFULA_SEQ_GLOBAL = 13
NFULA_GID = 14
NFULA_HWTYPE = 15
NFULA_HWHEADER = 16
NFULA_HWLEN = 17
NFULA_CT = 18
NFULA_CT_INFO = 19
NFULA_VLAN = 20
NFULA_L2HDR = 21

NLMSG_NOOP = 1
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04
NFNETLINK_V0 = 0

_NLMSG_HDRLEN = 16
_NLA_HDRLEN = 4
_NLMSG_ALIGNTO = 4
_NLA_ALIGNTO = 4

_PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp"}
_IFNAME_CACHE: dict[int, str] = {}
_IFNAME_LOCK = threading.Lock()


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _nlmsg(msg_type: int, flags: int, seq: int, payload: bytes) -> bytes:
    length = _NLMSG_HDRLEN + len(payload)
    # The netlink header and attribute headers are native-endian
    # (__u32/__u16), NOT network byte order. Using "!" on x86 silently
    # causes dropped messages: the kernel reads the length field byte-swapped.
    header = struct.pack("=IHHII", length, msg_type, flags, seq, 0)
    return header + payload


def _nfgenmsg(family: int, res_id: int) -> bytes:
    # The struct nfgenmsg res_id field is __be16 (network byte order).
    return struct.pack("=BB", family, NFNETLINK_V0) + struct.pack(
        "!H", res_id & 0xFFFF
    )


def _nla(attr_type: int, payload: bytes) -> bytes:
    length = _NLA_HDRLEN + len(payload)
    raw = struct.pack("=HH", length, attr_type) + payload
    return raw + b"\x00" * (_align(length, _NLA_ALIGNTO) - length)


def _ifname(index: int) -> str:
    if not index:
        return ""
    with _IFNAME_LOCK:
        cached = _IFNAME_CACHE.get(index)
    if cached is not None:
        return cached
    try:
        name = socket.if_indextoname(index)
    except OSError:
        name = str(index)
    with _IFNAME_LOCK:
        if len(_IFNAME_CACHE) > 512:
            _IFNAME_CACHE.clear()
        _IFNAME_CACHE[index] = name
    return name


def _parse_ipv4(packet: bytes) -> dict:
    """Parse the IPv4 header and TCP/UDP ports from the payload."""
    if len(packet) < 20:
        return {}
    version = packet[0] >> 4
    ihl = (packet[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(packet) < ihl:
        return {}
    total_length = struct.unpack_from("!H", packet, 2)[0]
    protocol = packet[9]
    fragment_offset = struct.unpack_from("!H", packet, 6)[0] & 0x1FFF
    result = {
        "src": socket.inet_ntoa(packet[12:16]),
        "dst": socket.inet_ntoa(packet[16:20]),
        "proto": _PROTO_NAMES.get(protocol, f"ip-{protocol}"),
        "length": total_length or len(packet),
    }
    # Non-first fragments have no parsable transport ports.
    if fragment_offset:
        return result
    if protocol in (6, 17) and len(packet) >= ihl + 4:
        sport, dport = struct.unpack_from("!HH", packet, ihl)
        result["sport"] = sport
        result["dport"] = dport
    elif protocol == 1 and len(packet) > ihl:
        result["icmp_type"] = packet[ihl]
    return result


def _parse_attrs(payload: bytes, offset: int) -> dict[int, bytes]:
    attrs: dict[int, bytes] = {}
    while offset + _NLA_HDRLEN <= len(payload):
        length, attr_type = struct.unpack_from("=HH", payload, offset)
        if length < _NLA_HDRLEN or offset + length > len(payload):
            break
        attrs.setdefault(attr_type, payload[offset + _NLA_HDRLEN:offset + length])
        offset += _align(length, _NLA_ALIGNTO)
    return attrs


def parse_packet_message(payload: bytes, now: float | None = None) -> dict | None:
    """Process the body of an NFULNL_MSG_PACKET message.

    The input is the part AFTER the nlmsghdr (nfgenmsg + attributes). The
    returned dictionary can be written directly to the drop log file.
    """
    if len(payload) < 4:
        return None
    # nfgenmsg: nfgen_family, version, res_id. The group is in res_id.
    attrs = _parse_attrs(payload, 4)
    raw_payload = attrs.get(NFULA_PAYLOAD, b"")
    ip = _parse_ipv4(raw_payload)

    reason = ""
    raw_prefix = attrs.get(NFULA_PREFIX, b"")
    if raw_prefix:
        prefix = raw_prefix.split(b"\x00", 1)[0].decode("utf-8", "replace")
        match = _REASON_RE.search(prefix)
        if match:
            reason = match.group(1)
        else:
            reason = prefix.strip()
    record: dict = {
        "reason": (reason or "unknown")[:_MAX_STRING],
        "src": ip.get("src", ""),
        "dst": ip.get("dst", ""),
        "proto": ip.get("proto", ""),
    }
    for key in ("sport", "dport", "icmp_type"):
        if key in ip:
            record[key] = ip[key]
    if "length" in ip:
        record["length"] = ip["length"]

    raw_ts = attrs.get(NFULA_TIMESTAMP)
    if raw_ts and len(raw_ts) >= 16:
        try:
            seconds, useconds = struct.unpack_from("!QQ", raw_ts, 0)
            ts = float(seconds) + float(useconds) / 1_000_000.0
        except (struct.error, ValueError):
            ts = time.time() if now is None else now
    else:
        ts = time.time() if now is None else now
    if ts <= 0 or ts > time.time() + 86400:
        ts = time.time() if now is None else now
    record["ts"] = ts
    record["time"] = _utc_iso(ts)

    for attr, key in (
        (NFULA_IFINDEX_INDEV, "if_in"),
        (NFULA_IFINDEX_OUTDEV, "if_out"),
        (NFULA_IFINDEX_PHYSINDEV, "if_phys_in"),
        (NFULA_IFINDEX_PHYSOUTDEV, "if_phys_out"),
    ):
        raw = attrs.get(attr)
        if raw and len(raw) >= 4:
            name = _ifname(struct.unpack_from("!I", raw, 0)[0])
            if name:
                record[key] = name

    raw_mark = attrs.get(NFULA_MARK)
    if raw_mark and len(raw_mark) >= 4:
        record["mark"] = struct.unpack_from("!I", raw_mark, 0)[0]

    raw_hwaddr = attrs.get(NFULA_HWADDR)
    if raw_hwaddr and len(raw_hwaddr) >= 4:
        # struct nfulnl_msg_packet_hw: __be16 hw_addrlen; __u16 _pad; __u8 hw_addr[8]
        hw_len = struct.unpack_from("!H", raw_hwaddr, 0)[0]
        hw = raw_hwaddr[4:4 + min(hw_len, 8)]
        if len(hw) == 6:
            record["mac"] = ":".join(f"{byte:02x}" for byte in hw)

    raw_hdr = attrs.get(NFULA_PACKET_HDR)
    if raw_hdr and len(raw_hdr) >= 4:
        record["hook"] = raw_hdr[2]

    return record


def parse_netlink_buffer(data: bytes, now: float | None = None) -> list[dict]:
    """Process the messages in one netlink recv() buffer.

    Returned items:
      {"kind": "packet", "record": {...}}
      {"kind": "ack", "error": 0 or a negative errno}
      {"kind": "done"}
    """
    items: list[dict] = []
    offset = 0
    while offset + _NLMSG_HDRLEN <= len(data):
        length, msg_type, flags, seq, pid = struct.unpack_from(
            "=IHHII", data, offset
        )
        if length < _NLMSG_HDRLEN or offset + length > len(data):
            break
        body = data[offset + _NLMSG_HDRLEN:offset + length]
        if msg_type == NLMSG_ERROR:
            error = 0
            if len(body) >= 4:
                error = struct.unpack_from("=i", body, 0)[0]
            items.append({"kind": "ack", "error": error, "seq": seq})
        elif msg_type == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET:
            record = parse_packet_message(body, now=now)
            if record is not None:
                items.append({"kind": "packet", "record": record})
        elif msg_type == NLMSG_DONE:
            items.append({"kind": "done"})
        elif msg_type == NLMSG_NOOP:
            pass
        offset += _align(length, _NLMSG_ALIGNTO)
    return items


def _config_message(
    command: int, group: int, seq: int, family: int = 0
) -> bytes:
    msg_type = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG
    payload = _nfgenmsg(family, group) + _nla(
        NFULA_CFG_CMD, struct.pack("!B", command)
    )
    return _nlmsg(msg_type, NLM_F_REQUEST | NLM_F_ACK, seq, payload)


def _mode_message(
    group: int,
    seq: int,
    copy_range: int = DROP_LOG_COPY_RANGE,
    qthreshold: int = 1,
    timeout: int = 100,
) -> bytes:
    msg_type = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG
    mode = struct.pack("!IBB", copy_range, NFULNL_COPY_PACKET, 0)
    # qthreshold=1 forwards every packet immediately, so the log appears in
    # real time; the timeout (1/100 s) is only a safety net.
    payload = (
        _nfgenmsg(0, group)
        + _nla(NFULA_CFG_MODE, mode)
        + _nla(NFULA_CFG_TIMEOUT, struct.pack("!I", timeout))
        + _nla(NFULA_CFG_QTHRESH, struct.pack("!I", qthreshold))
    )
    return _nlmsg(msg_type, NLM_F_REQUEST | NLM_F_ACK, seq, payload)


# ------------------------------------------------------------------ log store

class DropLog:
    """JSON Lines drop log, rotated following the AuditLog pattern."""

    def __init__(
        self,
        path: str = DROP_LOG_PATH,
        max_bytes: int = DROP_LOG_MAX_BYTES,
        keep: int = DROP_LOG_KEEP,
        logger=_default_log,
    ) -> None:
        self.path = os.path.abspath(path)
        self.max_bytes = max(256 * 1024, int(max_bytes))
        self.keep = max(1, min(20, int(keep)))
        self.log = logger
        self._lock = threading.Lock()
        # Written without fsync since the last sync() (listener path).
        self._unsynced = False

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
                self.log(f"[drop log] rotation failed: {exc}")
                return
        try:
            os.replace(self.path, f"{self.path}.1")
        except OSError as exc:
            self.log(f"[drop log] rotation failed: {exc}")
        else:
            # The rotated file was closed after its last write; what has not
            # been synced yet is flushed by the kernel's writeback.
            self._unsynced = False

    @staticmethod
    def _clean(entry: dict) -> dict:
        out: dict = {}
        for key, value in entry.items():
            if value is None:
                continue
            if isinstance(value, bool):
                out[key] = value
            elif isinstance(value, (int, float)):
                out[key] = value
            elif isinstance(value, str):
                out[key] = value[:_MAX_STRING]
        if "ts" not in out:
            out["ts"] = time.time()
        if "time" not in out:
            out["time"] = _utc_iso(float(out["ts"]))
        if "reason" not in out or not str(out.get("reason", "")).strip():
            out["reason"] = "unknown"
        return out

    def write(self, entry: dict, sync: bool = True) -> dict:
        """Append one record.

        ``sync=False`` skips the fsync; the caller must call sync()
        periodically. The NFLOG listener does this, so a packet flood does
        not turn into one fsync per packet.
        """
        record = self._clean(entry)
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
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
                    if sync:
                        os.fsync(fd)
                    else:
                        self._unsynced = True
                finally:
                    os.close(fd)
        except OSError as exc:
            self.log(f"[drop log] write error: {exc}")
        return record

    def sync(self) -> None:
        """fsync the records written with ``sync=False``."""
        with self._lock:
            if not self._unsynced:
                return
            self._unsynced = False
            try:
                fd = os.open(self.path, os.O_RDONLY)
            except OSError:
                return
            try:
                os.fsync(fd)
            except OSError as exc:
                self.log(f"[drop log] sync error: {exc}")
            finally:
                os.close(fd)

    @staticmethod
    def _lines_newest_first(path: str, block: int = 64 * 1024):
        """The file's lines from the end backwards, read in blocks.

        Splitting on the newline byte is safe for UTF-8: it never occurs
        inside a multi-byte character.
        """
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            position = fh.tell()
            rest = b""
            while position > 0:
                size = min(block, position)
                position -= size
                fh.seek(position)
                parts = (fh.read(size) + rest).split(b"\n")
                rest = parts[0]
                for raw in reversed(parts[1:]):
                    yield raw.decode("utf-8", "replace")
            yield rest.decode("utf-8", "replace")

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
        src: str = "",
        dst: str = "",
        proto: str = "",
        port: int | None = None,
        reason: str = "",
        group: str = "",
        q: str = "",
        before: float | None = None,
    ) -> list[dict]:
        limit = max(1, min(2000, int(limit)))
        src = (src or "").strip().lower()
        dst = (dst or "").strip().lower()
        proto = (proto or "").strip().lower()
        reason = (reason or "").strip().lower()
        group = (group or "").strip().lower()
        q = (q or "").strip().lower()
        rows: list[dict] = []
        # Files and lines are read newest first. The scan stops once it has
        # ``limit`` rows that survive the fail2ban folding (packets during a
        # ban fold into their ban row), or after DROP_LOG_READ_MAX_LINES
        # lines, so one request never parses every rotated file.
        shown = 0
        scanned = 0
        for path in self._files():
            if shown >= limit or scanned >= DROP_LOG_READ_MAX_LINES:
                break
            try:
                for line in self._lines_newest_first(path):
                    scanned += 1
                    if scanned > DROP_LOG_READ_MAX_LINES:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(item, dict):
                        continue
                    item_group = reason_group(item.get("reason"))
                    if group and item_group != group:
                        continue
                    item["group"] = item_group
                    if before is not None:
                        try:
                            if float(item.get("ts", 0)) >= before:
                                continue
                        except (TypeError, ValueError):
                            continue
                    if src and src not in str(item.get("src", "")).lower():
                        continue
                    if dst and dst not in str(item.get("dst", "")).lower():
                        continue
                    if proto and proto != str(item.get("proto", "")).lower():
                        continue
                    if reason and reason not in str(
                        item.get("reason", "")
                    ).lower():
                        continue
                    if port is not None:
                        if port not in (
                            item.get("sport"), item.get("dport")
                        ):
                            continue
                    if q and q not in json.dumps(
                        item, ensure_ascii=False, sort_keys=True
                    ).lower():
                        continue
                    rows.append(item)
                    if (
                        str(item.get("reason", "")).strip().lower()
                        != BAN_EVENT_REASON
                        or str(item.get("event", "")).strip().lower()
                        == BAN_EVENT_KIND
                    ):
                        shown += 1
                        if shown >= limit:
                            break
            except FileNotFoundError:
                continue
            except OSError as exc:
                self.log(f"[drop log] read error ({path}): {exc}")
        rows = self._collapse_fail2ban(rows)
        rows.sort(key=lambda item: float(item.get("ts", 0)), reverse=True)
        return rows[:limit]

    @staticmethod
    def _collapse_fail2ban(rows: list[dict]) -> list[dict]:
        """Fold packets from during a ban into the single ban row.

        The firewall logs on a sampled basis during a ban so that continued
        attempts from the banned source are visible. read() attributes these
        to the ban event and returns a single aggregated row. If the log has
        no ban event (older entries), one ``event=ban-drop`` row is created
        per source.
        """
        plain: list[dict] = []
        bans: list[dict] = []
        packets: list[dict] = []
        for row in rows:
            if str(row.get("reason", "")).strip().lower() != BAN_EVENT_REASON:
                plain.append(row)
            elif str(row.get("event", "")).strip().lower() == BAN_EVENT_KIND:
                bans.append(row)
            else:
                packets.append(row)
        if not bans and not packets:
            return plain

        def ts_of(row: dict) -> float:
            try:
                return float(row.get("ts", 0) or 0)
            except (TypeError, ValueError):
                return 0.0

        def until_of(row: dict) -> float:
            try:
                return float(row.get("ban_until", 0) or 0)
            except (TypeError, ValueError):
                return 0.0

        bans.sort(key=ts_of)
        packets.sort(key=ts_of)
        by_src: dict[str, list[dict]] = {}
        states: list[dict] = []
        for ban in bans:
            state = dict(ban)
            state["event"] = BAN_EVENT_KIND
            state["group"] = BAN_GROUP
            state["packets"] = 0
            state["first_drop"] = 0.0
            state["last_drop"] = 0.0
            states.append(state)
            by_src.setdefault(
                str(ban.get("src", "")).strip().lower(), []
            ).append(state)

        synthetic: dict[str, dict] = {}
        for packet in packets:
            src = str(packet.get("src", "")).strip().lower()
            when = ts_of(packet)
            target: dict | None = None
            for state in by_src.get(src, []):
                # The ban event is written after the nft operation, so with a
                # short grace period a packet from just before the boundary
                # can still be attached.
                if ts_of(state) - 5.0 <= when and (
                    not until_of(state) or when <= until_of(state) + 60.0
                ):
                    if target is None or ts_of(state) > ts_of(target):
                        target = state
            if target is None:
                target = synthetic.get(src)
                if target is None:
                    target = {
                        "reason": BAN_EVENT_REASON,
                        "event": "ban-drop",
                        "src": packet.get("src", ""),
                        "group": BAN_GROUP,
                        "packets": 0,
                        "first_drop": when,
                        "last_drop": 0.0,
                    }
                    synthetic[src] = target
            target["packets"] += 1
            if not target["first_drop"] or when < target["first_drop"]:
                target["first_drop"] = when
            if when >= target["last_drop"]:
                target["last_drop"] = when
                for key in ("dst", "proto", "sport", "dport", "if_in", "mac"):
                    if key in packet:
                        target["last_" + key] = packet[key]

        out = list(plain)
        for state in states + list(synthetic.values()):
            if state["packets"]:
                if state["event"] == BAN_EVENT_KIND:
                    state["ban_ts"] = ts_of(state)
                # The row is timestamped at the latest hit so that it moves
                # to the top on automatic refresh.
                state["ts"] = state["last_drop"]
                state["time"] = _utc_iso(state["ts"])
            else:
                state.pop("first_drop", None)
                state.pop("last_drop", None)
            out.append(state)
        return out


# ------------------------------------------------------------------- listener

class DropLogListener:
    """Thread listening on the NFLOG group.

    start() returns successfully only once the group has been bound. If the
    kernel does not support NFLOG, or the group is in use by another process,
    the error is visible in status(); the portal keeps working regardless
    (the firewall does not depend on logging).
    """

    def __init__(
        self,
        store: DropLog,
        group: int = DROP_LOG_GROUP,
        enabled: bool = DROP_LOG_ENABLED,
        logger=_default_log,
        socket_opener=None,
    ) -> None:
        self.store = store
        self.group = max(1, min(65535, int(group)))
        self.enabled = bool(enabled)
        self.log = logger
        # Binding the NFLOG group needs CAP_NET_ADMIN. The portal has none
        # (DJ-20): socket_opener returns the socket the privileged helper
        # bound and configured (OSError on failure); reading it needs no
        # capability.
        self.socket_opener = socket_opener
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._error = ""
        self._received = 0
        self._written = 0
        self._write_errors = 0
        # Receive-buffer overflows (ENOBUFS: the kernel dropped messages)
        # and automatic restarts after a socket error; shown in status().
        self._overruns = 0
        self._restarts = 0
        self._last_sync = 0.0
        self.on_drop = None

    def set_on_drop(self, callback) -> None:
        """Callback for every recorded drop event."""
        self.on_drop = callback

    def _count_packet(self, record: dict) -> None:
        with self._lock:
            self._received += 1
        try:
            self.store.write(record, sync=False)
        except Exception as exc:  # logging must not stop the listener
            with self._lock:
                self._write_errors += 1
                self._error = str(exc)
            self.log(f"[drop log] failed to write packet: {exc}")
        else:
            with self._lock:
                self._written += 1
        callback = self.on_drop
        if callback is not None:
            try:
                callback(record)
            except Exception as exc:  # the callback must not stop the listener
                self.log(f"[drop log] drop processing failed: {exc}")

    def _handle(self, data: bytes) -> None:
        for item in parse_netlink_buffer(data):
            if item["kind"] == "packet":
                self._count_packet(item["record"])
            elif item["kind"] == "ack" and item.get("error"):
                error = int(item["error"])
                with self._lock:
                    self._write_errors += 1
                    self._error = os.strerror(-error) if error < 0 else str(error)
                self.log(
                    "[drop log] netlink hiba: "
                    + (os.strerror(-error) if error < 0 else str(error))
                )

    def _send_config(self, sock: socket.socket) -> None:
        seq = int(time.time()) & 0x7FFFFFFF
        # PF_BIND is backwards compatible; the error is not fatal.
        pf_bind = _nlmsg(
            (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG,
            NLM_F_REQUEST,
            seq,
            _nfgenmsg(socket.AF_INET, 0)
            + _nla(NFULA_CFG_CMD, struct.pack("!B", NFULNL_CFG_CMD_PF_BIND)),
        )
        try:
            sock.send(pf_bind)
        except OSError:
            pass

        bind = _config_message(NFULNL_CFG_CMD_BIND, self.group, seq + 1)
        mode = _mode_message(self.group, seq + 2)
        sock.send(bind)
        sock.send(mode)

        deadline = time.time() + 1.0
        acks = 0
        while acks < 2 and time.time() < deadline:
            try:
                data = sock.recv(256 * 1024)
            except socket.timeout:
                break
            for item in parse_netlink_buffer(data):
                if item["kind"] == "packet":
                    self._count_packet(item["record"])
                elif item["kind"] == "ack":
                    error = int(item.get("error") or 0)
                    if error:
                        # A PF_BIND error (e.g. EINVAL on an old kernel) does
                        # not prevent binding the group.
                        if item.get("seq") == seq:
                            continue
                        raise OSError(
                            -error if error < 0 else error,
                            os.strerror(-error) if error < 0 else str(error),
                        )
                    acks += 1

    def _open_socket(self) -> socket.socket:
        """Open, bind and configure the NFLOG socket (raises OSError)."""
        if self.socket_opener is not None:
            sock = self.socket_opener()
            try:
                sock.settimeout(1.0)
            except OSError:
                sock.close()
                raise
            return sock
        sock = socket.socket(
            socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER
        )
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            # nl_pid=0 lets the kernel pick the unique port identifier.
            # getpid() cannot be used: in the host network view the
            # container's PID 1 may collide with the host systemd's netlink
            # sockets that use the same identifier (EADDRINUSE).
            sock.bind((0, 0))
            sock.settimeout(1.0)
            self._send_config(sock)
        except OSError:
            try:
                sock.close()
            except OSError:
                pass
            raise
        return sock

    def start(self) -> bool:
        if not self.enabled:
            self._error = "the drop log is disabled (HV_DROP_LOG=0)"
            return False
        if self._thread is not None and self._thread.is_alive():
            return True
        self._stop.clear()
        try:
            sock = self._open_socket()
        except OSError as exc:
            with self._lock:
                self._running = False
                self._error = str(exc)
            self.log(
                "[drop log] WARNING: the NFLOG listener did not start: "
                f"{exc}; retrying in the background"
            )
            # NFLOG may become available later (module loaded after boot,
            # the group released by another process): keep retrying with
            # the same back-off as after a socket error (DJ-07).
            thread = threading.Thread(
                target=self._retry_start, args=(exc,),
                name="dropjak-droplog", daemon=True,
            )
            self._thread = thread
            thread.start()
            return False
        with self._lock:
            self._sock = sock
            self._running = True
            self._error = ""
        thread = threading.Thread(
            target=self._loop, name="dropjak-droplog", daemon=True
        )
        self._thread = thread
        thread.start()
        self.log(
            f"[drop log] listening on NFLOG group {self.group} started "
            f"({self.store.path})"
        )
        return True

    def _retry_start(self, exc: OSError) -> None:
        """Open the socket with back-off after a failed start, then listen."""
        sock = self._reopen(exc, first=True)
        if sock is None:
            return
        self.log(
            f"[drop log] listening on NFLOG group {self.group} started "
            f"({self.store.path})"
        )
        self._loop()

    def _sync_store(self, force: bool = False) -> None:
        now = time.monotonic()
        if force or now - self._last_sync >= DROP_LOG_SYNC_INTERVAL:
            self._last_sync = now
            try:
                self.store.sync()
            except Exception as exc:  # syncing must not stop the listener
                self.log(f"[drop log] sync failed: {exc}")

    def _reopen(self, exc: OSError, first: bool = False) -> socket.socket | None:
        """Replace a failed socket, retrying with exponential back-off.

        Returns the new socket, or None if stop() was called meanwhile.
        With ``first`` the listener never ran (start() failed): the success
        is not counted as a restart.
        """
        with self._lock:
            old = self._sock
            self._sock = None
            self._running = False
            self._error = str(exc)
        if old is not None:
            try:
                old.close()
            except OSError:
                pass
        if not first:
            self.log(f"[drop log] listener error: {exc}; restarting")
        delay = DROP_LOG_RESTART_MIN_DELAY
        while not self._stop.wait(delay):
            try:
                sock = self._open_socket()
            except OSError as again:
                with self._lock:
                    self._error = str(again)
                delay = min(delay * 2, DROP_LOG_RESTART_MAX_DELAY)
                continue
            with self._lock:
                if self._stop.is_set():
                    sock.close()
                    return None
                self._sock = sock
                self._running = True
                if not first:
                    self._restarts += 1
                self._error = ""
            if not first:
                self.log("[drop log] listener restarted")
            return sock
        return None

    def _loop(self) -> None:
        sock = self._sock
        overrun_logged: float | None = None
        while sock is not None and not self._stop.is_set():
            try:
                data = sock.recv(256 * 1024)
            except socket.timeout:
                self._sync_store()
                continue
            except OSError as exc:
                if self._stop.is_set():
                    break
                if exc.errno == errno.ENOBUFS:
                    # The receive buffer overflowed and the kernel dropped
                    # log messages. The socket is still bound: count the
                    # loss, log it at most once a minute and go on.
                    with self._lock:
                        self._overruns += 1
                    if (
                        overrun_logged is None
                        or time.monotonic() - overrun_logged >= 60.0
                    ):
                        overrun_logged = time.monotonic()
                        self.log(
                            "[drop log] WARNING: receive buffer overflow, "
                            "log messages were lost"
                        )
                    continue
                sock = self._reopen(exc)
                continue
            self._handle(data)
            self._sync_store()
        self._sync_store(force=True)
        with self._lock:
            self._running = False

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=3.0)
        with self._lock:
            sock = self._sock
            self._sock = None
            self._running = False
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        self._thread = None

    def status(self) -> dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "running": self._running,
                "group": self.group,
                "path": self.store.path,
                "error": self._error,
                "received": self._received,
                "written": self._written,
                "errors": self._write_errors,
                "overruns": self._overruns,
                "restarts": self._restarts,
            }


class DropLogService:
    """The store and the listener together; used by the Gateway."""

    def __init__(
        self,
        path: str = DROP_LOG_PATH,
        max_bytes: int = DROP_LOG_MAX_BYTES,
        keep: int = DROP_LOG_KEEP,
        group: int = DROP_LOG_GROUP,
        enabled: bool = DROP_LOG_ENABLED,
        logger=_default_log,
        socket_opener=None,
    ) -> None:
        self.log = logger
        self.store = DropLog(
            path=path, max_bytes=max_bytes, keep=keep, logger=logger
        )
        self.listener = DropLogListener(
            self.store, group=group, enabled=enabled, logger=logger,
            socket_opener=socket_opener,
        )

    def set_on_drop(self, callback) -> None:
        self.listener.set_on_drop(callback)

    def start(self) -> bool:
        return self.listener.start()

    def stop(self) -> None:
        self.listener.stop()

    def status(self) -> dict:
        return self.listener.status()

    def read(self, **kwargs) -> list[dict]:
        return self.store.read(**kwargs)
