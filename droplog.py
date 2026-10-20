#!/usr/bin/env python3
"""
Dropjak — eldobott csomagok naplója NFLOG-on keresztül.

Az nftables ``log ... group N`` szabályai a kernel NFLOG (nfnetlink_log)
mechanizmusán keresztül küldik el a csomag fejlécét és payloadját. Ez a
modul egy nyers NETLINK_NETFILTER socketen köti be a megadott csoportot,
feldolgozza a csomagokat, és JSON Lines fájlba írja őket.

Miért NFLOG: a konténer csak NET_ADMIN képességgel fut, és nincs
CAP_SYSLOG-ja, ezért a kernel dmesg / /dev/kmsg naplója nem használható.
Az NFLOG-hoz csak NET_ADMIN kell, és a kernel a csomagokat közvetlenül a
portál folyamatának küldi.

A napló nem tartalmazza a teljes csomagot: csak az IPv4 fejléc, a
transzportportok, az interfész, a forrás-MAC és az nft prefix (ok) kerül
a fájlba. A fájl 0600 jogosultsággal készül, és méretkorláttal rotálódik.
"""

from __future__ import annotations

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


def _utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def _default_log(message: str) -> None:
    print(message, flush=True)


_REASON_RE = re.compile(r"reason=([A-Za-z0-9_.:-]+)")
_MAX_STRING = 256

# A fail2ban tiltás tényét a portál egyetlen eseményként írja a naplóba
# (reason=fail2ban, event=ban). A tiltás alatt eldobott csomagokat a tűzfal
# mintavételezve naplózza (reason=fail2ban), a read() viszont ezeket a tiltás
# egyetlen sorához kapcsolja, így a felület nem kap csomagonkénti sort.
BAN_EVENT_REASON = "fail2ban"
BAN_EVENT_KIND = "ban"

# A felület kétféle sort különböztet meg: a hétköznapi eldobások "DROP",
# a fail2ban által tiltott források (és a tiltás utáni kísérletek)
# "fail2ban" címkét kapnak. A nyers kernel-ok (reason) változatlanul
# megmaradnak, és a részletes JSON-ban láthatók.
BAN_GROUP = "ban"
DROP_GROUP = "drop"


def reason_group(reason: str) -> str:
    """A sor felületi kategóriája: fail2ban vagy DROP."""
    if str(reason or "").strip().lower() == BAN_EVENT_REASON:
        return BAN_GROUP
    return DROP_GROUP


# --------------------------------------------------------------- NFLOG állandók

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
    # A netlink fejléc és az attribútum-fejlécek natív bájtsorrendűek
    # (__u32/__u16), NEM hálózatiak. A "!" használata x86-on némán
    # eldobott üzeneteket okoz: a kernel a hossz-mezőt fordítva olvassa.
    header = struct.pack("=IHHII", length, msg_type, flags, seq, 0)
    return header + payload


def _nfgenmsg(family: int, res_id: int) -> bytes:
    # A struct nfgenmsg res_id mezője __be16 (hálózati bájtsorrendű).
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
    """Az IPv4 fejléc és a TCP/UDP portok kiolvasása a payloadból."""
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
    # A nem első töredékben nincsenek értelmezhető transzportportok.
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
    """Egy NFULNL_MSG_PACKET üzenet törzsének feldolgozása.

    A bemenet az nlmsghdr UTÁNI rész (nfgenmsg + attribútumok). A visszaadott
    szótár közvetlenül a drop log fájlba írható.
    """
    if len(payload) < 4:
        return None
    # nfgenmsg: nfgen_family, version, res_id. A csoport a res_id-ban van.
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
    """Egy netlink recv() pufferben lévő üzenetek feldolgozása.

    Visszaadott elemek:
      {"kind": "packet", "record": {...}}
      {"kind": "ack", "error": 0 vagy negatív errno}
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
    copy_range: int = 65535,
    qthreshold: int = 1,
    timeout: int = 100,
) -> bytes:
    msg_type = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG
    mode = struct.pack("!IBB", copy_range, NFULNL_COPY_PACKET, 0)
    # A qthreshold=1 minden csomagot azonnal továbbít, így a napló valós
    # időben látszik; a timeout (1/100 mp) csak biztonsági háló.
    payload = (
        _nfgenmsg(0, group)
        + _nla(NFULA_CFG_MODE, mode)
        + _nla(NFULA_CFG_TIMEOUT, struct.pack("!I", timeout))
        + _nla(NFULA_CFG_QTHRESH, struct.pack("!I", qthreshold))
    )
    return _nlmsg(msg_type, NLM_F_REQUEST | NLM_F_ACK, seq, payload)


# ------------------------------------------------------------------ naplótár

class DropLog:
    """JSON Lines drop-napló, az AuditLog mintájára rotálva."""

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
                self.log(f"[drop log] rotáció nem sikerült: {exc}")
                return
        try:
            os.replace(self.path, f"{self.path}.1")
        except OSError as exc:
            self.log(f"[drop log] rotáció nem sikerült: {exc}")

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

    def write(self, entry: dict) -> dict:
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
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except OSError as exc:
            self.log(f"[drop log] írási hiba: {exc}")
        return record

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
        for path in self._files():
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    for line in fh:
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
            except FileNotFoundError:
                continue
            except OSError as exc:
                self.log(f"[drop log] olvasási hiba ({path}): {exc}")
        rows = self._collapse_fail2ban(rows)
        rows.sort(key=lambda item: float(item.get("ts", 0)), reverse=True)
        return rows[:limit]

    @staticmethod
    def _collapse_fail2ban(rows: list[dict]) -> list[dict]:
        """A tiltás alatti csomagokat a tiltás egyetlen sorába vonja.

        A tűzfal a tiltás alatt mintavételezve naplóz, hogy látszódjon, ha a
        tiltott forrás tovább próbálkozik. A read() ezeket a tiltás
        eseményéhez rendeli, és egyetlen összesített sort ad vissza. Ha a
        naplóban nincs tiltás-esemény (régi bejegyzések), forrásonként egy
        ``event=ban-drop`` sor készül.
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
                # A tiltás-esemény a nft-művelet után íródik, ezért egy
                # rövid türelmi idővel a határ előtti csomag is hozzákapcsolható.
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
                # A sor a legutóbbi találat idejére kerül, hogy az
                # automatikus frissítésnél a tetejére kerüljön.
                state["ts"] = state["last_drop"]
                state["time"] = _utc_iso(state["ts"])
            else:
                state.pop("first_drop", None)
                state.pop("last_drop", None)
            out.append(state)
        return out


# ------------------------------------------------------------------- figyelő

class DropLogListener:
    """Az NFLOG csoportot figyelő szál.

    A start() akkor tér vissza sikeresen, ha a csoport kötése megtörtént.
    Ha a kernel nem támogatja az NFLOG-ot, vagy a csoportot más folyamat
    használja, a hiba a status()-ban látható; a portál ettől függetlenül
    működik tovább (a tűzfal nem függ a naplózástól).
    """

    def __init__(
        self,
        store: DropLog,
        group: int = DROP_LOG_GROUP,
        enabled: bool = DROP_LOG_ENABLED,
        logger=_default_log,
    ) -> None:
        self.store = store
        self.group = max(1, min(65535, int(group)))
        self.enabled = bool(enabled)
        self.log = logger
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._error = ""
        self._received = 0
        self._written = 0
        self._write_errors = 0
        self.on_drop = None

    def set_on_drop(self, callback) -> None:
        """Visszahívás minden egyes rögzített drop eseményhez."""
        self.on_drop = callback

    def _count_packet(self, record: dict) -> None:
        with self._lock:
            self._received += 1
        try:
            self.store.write(record)
        except Exception as exc:  # a naplózás ne állítsa meg a figyelőt
            with self._lock:
                self._write_errors += 1
                self._error = str(exc)
            self.log(f"[drop log] csomag írása nem sikerült: {exc}")
        else:
            with self._lock:
                self._written += 1
        callback = self.on_drop
        if callback is not None:
            try:
                callback(record)
            except Exception as exc:  # a visszahívás ne állítsa meg a figyelőt
                self.log(f"[drop log] drop-feldolgozás nem sikerült: {exc}")

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
        # A PF_BIND visszafelé kompatibilis; a hiba nem végzetes.
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
                        # A PF_BIND hibája (pl. EINVAL régi kernelnél) nem
                        # akadálya a csoport kötésének.
                        if item.get("seq") == seq:
                            continue
                        raise OSError(
                            -error if error < 0 else error,
                            os.strerror(-error) if error < 0 else str(error),
                        )
                    acks += 1

    def start(self) -> bool:
        if not self.enabled:
            self._error = "a drop log ki van kapcsolva (HV_DROP_LOG=0)"
            return False
        if self._thread is not None and self._thread.is_alive():
            return True
        self._stop.clear()
        sock: socket.socket | None = None
        try:
            sock = socket.socket(
                socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER
            )
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            # A nl_pid=0 a kernelre bízza az egyedi port-azonosítót. A
            # getpid() nem használható: host-hálózatnézetben a konténer
            # PID 1-je ütközhet a host systemd ugyanilyen azonosítójú
            # netlink socketjeivel (EADDRINUSE).
            sock.bind((0, 0))
            sock.settimeout(1.0)
            self._send_config(sock)
        except OSError as exc:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            with self._lock:
                self._running = False
                self._error = str(exc)
            self.log(
                "[drop log] FIGYELEM: az NFLOG figyelő nem indult el: " f"{exc}"
            )
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
            f"[drop log] NFLOG csoport {self.group} figyelése elindult "
            f"({self.store.path})"
        )
        return True

    def _loop(self) -> None:
        sock = self._sock
        if sock is None:
            return
        while not self._stop.is_set():
            try:
                data = sock.recv(256 * 1024)
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop.is_set():
                    break
                with self._lock:
                    self._running = False
                    self._error = str(exc)
                self.log(f"[drop log] figyelő hiba: {exc}")
                break
            self._handle(data)
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
            }


class DropLogService:
    """A tár és a figyelő együtt; ezt használja a Gateway."""

    def __init__(
        self,
        path: str = DROP_LOG_PATH,
        max_bytes: int = DROP_LOG_MAX_BYTES,
        keep: int = DROP_LOG_KEEP,
        group: int = DROP_LOG_GROUP,
        enabled: bool = DROP_LOG_ENABLED,
        logger=_default_log,
    ) -> None:
        self.log = logger
        self.store = DropLog(
            path=path, max_bytes=max_bytes, keep=keep, logger=logger
        )
        self.listener = DropLogListener(
            self.store, group=group, enabled=enabled, logger=logger
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
