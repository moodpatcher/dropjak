#!/usr/bin/env python3
"""A futó démon vezérlőcsatornájának és a CLI visszaesésének tesztjei.

Futtatás a projekt gyökeréből:

    python3 -m unittest discover -s tests -p 'test_live_cli.py' -v

A tesztek valódi Unix-domain socketet használnak egy ideiglenes
könyvtárban, és hamis nft/conntrack szkripteket, így a valódi rendszert
nem módosítják.
"""

from __future__ import annotations

import io
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import fail2ban as fail2ban_mod  # noqa: E402
import gateway  # noqa: E402
import server  # noqa: E402

CATALOG = gateway.ServiceCatalog.load(str(ROOT / "services.json"))
IP = "203.0.113.7"


# ------------------------------------------------------------------ segédek


def write_fake_tools(directory: str) -> tuple[str, str]:
    """Hamis nft és conntrack szkriptek az ideiglenes könyvtárban."""
    log = os.path.join(directory, "tools.log")
    nft = os.path.join(directory, "nft")
    with open(nft, "w", encoding="utf-8") as fh:
        fh.write(
            "#!/bin/sh\n"
            f'echo "nft $*" >> "{log}"\n'
            'if [ "$1" = "-f" ] && [ "$2" = "-" ]; then\n'
            "  while IFS= read -r line; do\n"
            f'    printf \'SCRIPT %s\\n\' "$line" >> "{log}"\n'
            "  done\n"
            "fi\n"
            'if [ "$1" = "-j" ]; then\n'
            '  printf \'{"nftables": []}\\n\'\n'
            "  exit 0\n"
            "fi\n"
            "exit 0\n"
        )
    conntrack = os.path.join(directory, "conntrack")
    with open(conntrack, "w", encoding="utf-8") as fh:
        fh.write(
            "#!/bin/sh\n"
            f'echo "conntrack $*" >> "{log}"\n'
            "exit 0\n"
        )
    os.chmod(nft, 0o755)
    os.chmod(conntrack, 0o755)
    return nft, conntrack


class _Settings:
    def snapshot(self) -> dict:
        return {}


class _Drops:
    def __init__(self) -> None:
        self.store = self
        self.rows: list[dict] = []

    def set_on_drop(self, callback) -> None:
        pass

    def write(self, row: dict) -> None:
        self.rows.append(row)


def build_gateway(directory: str):
    """Teljes, futó démonhoz hasonló Gateway a megadott könyvtárban."""
    nft, conntrack = write_fake_tools(directory)
    firewall = gateway.Firewall(binary=nft, logger=lambda *_: None)
    users = gateway.UserStore(
        os.path.join(directory, "users.json"), iterations=10_000
    )
    rules = gateway.RuleStore(
        os.path.join(directory, "rules.json"),
        catalog=CATALOG,
        logger=lambda *_: None,
    )
    groups = gateway.GroupStore(
        os.path.join(directory, "groups.json"), logger=lambda *_: None
    )
    audit = gateway.AuditLog(
        os.path.join(directory, "audit.jsonl"), logger=lambda *_: None
    )
    sessions = gateway.SessionManager(
        firewall, ttl=3600, pending_ttl=300, audit=audit
    )
    manager = fail2ban_mod.Fail2ban(
        firewall,
        path=os.path.join(directory, "fail2ban.json"),
        audit=audit,
        logger=lambda *_: None,
    )
    gw = gateway.Gateway(
        users=users,
        firewall=firewall,
        sessions=sessions,
        catalog=CATALOG,
        rules=rules,
        groups=groups,
        audit=audit,
        settings=_Settings(),
        drops=_Drops(),
        fail2ban=manager,
    )
    # A Gateway a hiányzó on_ban visszahívást maga köti be; ellenőrizzük,
    # hogy a tiltás utókezelése tényleg a démonhoz fut be.
    return types.SimpleNamespace(
        gw=gw,
        users=users,
        sessions=sessions,
        fail2ban=manager,
        audit=audit,
        firewall=firewall,
        nft=nft,
        conntrack=conntrack,
    )


def control_call(
    path: str,
    payload: dict | None = None,
    *,
    raw: bytes | None = None,
    timeout: float = 10.0,
) -> dict:
    """Egy kérés a vezérlőcsatornán; a válasz dekódolt JSON objektuma."""
    body = raw
    if body is None:
        body = (
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            .encode("utf-8")
            + b"\n"
        )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(path)
        try:
            sock.sendall(body)
        except (BrokenPipeError, ConnectionResetError):
            # A szerver a túl nagy kérést már elutasíthatta és lezárhatta.
            pass
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
    response_raw = b"".join(chunks)
    if not response_raw:
        raise AssertionError("a vezérlőcsatorna üres választ adott")
    return json.loads(response_raw.split(b"\n", 1)[0])


def audit_events(audit) -> list[dict]:
    return audit.read()


def control_path(state_dir: str) -> str:
    return os.path.join(
        state_dir, server.CONTROL_DIR_NAME, server.CONTROL_SOCKET_NAME
    )


def start_raw_control_server(state_dir: str, *, hold: float = 0.0):
    """Nyers Unix-socket szerver: elfogad, kiolvassa a kérést, majd vagy
    azonnal lezár (EOF), vagy ``hold`` másodpercig nem válaszol (timeout).

    Visszatérés: idempotens lezáró függvény.
    """
    path = control_path(state_dir)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    os.chmod(path, 0o600)
    listener.listen(1)
    listener.settimeout(5)

    def serve() -> None:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        try:
            conn.settimeout(5)
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            if hold:
                time.sleep(hold)
        except OSError:
            pass
        finally:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    def close() -> None:
        listener.close()
        thread.join(6)

    return close


class _FakePeerRequest:
    """SO_PEERCRED-et imitáló kérés a peer-uid ellenőrzéshez."""

    def __init__(self, uid: int) -> None:
        self.uid = uid
        self.timeout: float | None = None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def getsockopt(self, level: int, option: int, size: int | None = None):
        # struct ucred: pid, uid, gid
        return struct.pack("3i", 4242, self.uid, 0)


class _HandlerDouble:
    """A HTTP Handler azon metódusai, amelyeket az F7 teszt hív."""

    _ban_reply = server.Handler._ban_reply
    _session = server.Handler._session

    def __init__(
        self,
        gw,
        ip: str = IP,
        *,
        data: dict | None = None,
        token: str = "",
    ) -> None:
        self.server = types.SimpleNamespace(gateway=gw)
        self.client_address = (ip, 12345)
        self.headers: dict[str, str] = {}
        self.path = "/api/status"
        self._data = data if data is not None else {}
        self._token = token
        self.responses: list[tuple[int, dict, dict]] = []
        self.audits: list[tuple[str, dict]] = []

    @property
    def gw(self):
        return self.server.gateway

    def _client_ip(self) -> str:
        return self.client_address[0]

    def _ua(self) -> str:
        return ""

    def _read_json(self):
        return self._data

    def _origin_ok(self) -> bool:
        return True

    def _cookie_token(self) -> str:
        return self._token

    def _discard_body(self) -> None:
        pass

    def _json(self, code: int, obj: dict, headers=None) -> None:
        self.responses.append((code, obj, headers or {}))

    def _audit(self, event: str, **fields) -> None:
        fields.setdefault("ip", self._client_ip())
        fields.setdefault("ua", self._ua())
        self.audits.append((event, fields))
        self.gw.audit.write(event, **fields)


# ------------------------------------------------------- vezérlőcsatorna


class ControlServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ctx = build_gateway(self.tmp.name)
        self._old_conntrack = gateway.CONNTRACK_BIN
        gateway.CONNTRACK_BIN = self.ctx.conntrack
        self.addCleanup(
            lambda: setattr(gateway, "CONNTRACK_BIN", self._old_conntrack)
        )
        self.path = control_path(self.tmp.name)
        os.makedirs(os.path.dirname(self.path), mode=0o700)
        self.control = server.ControlServer(self.path, self.ctx.gw)
        self.control.start()
        self.addCleanup(self.control.stop)

    def add_user(self, name: str = "alice", password: str = "alice-password-1"):
        self.ctx.users.add(name, password)
        return self.ctx.users.record(name)

    def test_socket_mode_is_0600(self) -> None:
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertTrue(stat.S_ISSOCK(os.stat(self.path).st_mode))

    def test_status_is_read_only_and_exposes_no_secrets(self) -> None:
        self.add_user()
        response = control_call(self.path, {"action": "status"})
        self.assertTrue(response["ok"])
        self.assertEqual(response["user_names"], ["alice"])
        self.assertEqual(response["user_count"], 1)
        self.assertNotIn("password", json.dumps(response))
        self.assertNotIn("alice-password-1", json.dumps(response))

    def test_unknown_action_is_rejected(self) -> None:
        response = control_call(self.path, {"action": "ismeretlen.művelet"})
        self.assertFalse(response["ok"])
        self.assertEqual(response["status"], 1)
        self.assertIn("ismeretlen", response["error"])
        events = audit_events(self.ctx.audit)
        rejected = [e for e in events if e["event"] == "control_rejected"]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["reason"], "unknown_action")

    def test_malformed_json_is_rejected(self) -> None:
        response = control_call(self.path, raw=b"{ez nem json}\n")
        self.assertFalse(response["ok"])
        self.assertEqual(response["status"], 1)
        self.assertEqual(response["error"], "hibás kérés")
        rejected = [
            e for e in audit_events(self.ctx.audit)
            if e["event"] == "control_rejected"
        ]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["reason"], "bad_request")

    def test_request_without_newline_is_rejected(self) -> None:
        # A kliens lezárja az írást, hogy a szerver ne várjon időtúllépésig.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect(self.path)
            sock.sendall(b'{"action":"status"}')
            sock.shutdown(socket.SHUT_WR)
            response_raw = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response_raw += chunk
                if b"\n" in chunk:
                    break
        response = json.loads(response_raw.split(b"\n", 1)[0])
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"], "hibás kérés")

    def test_oversized_request_is_rejected(self) -> None:
        raw = b"x" * (server.CONTROL_MAX_REQUEST + 1)
        response = control_call(self.path, raw=raw)
        self.assertFalse(response["ok"])
        self.assertEqual(response["status"], 1)
        self.assertIn(response["error"], ("túl nagy kérés", "hibás kérés"))

    def test_user_add_via_socket_creates_user_and_audits(self) -> None:
        password = "dave-password-1"
        response = control_call(
            self.path,
            {
                "action": "user.add",
                "name": "dave",
                "password": password,
                "role": "user",
                "rules": [],
                "must_change_password": True,
            },
        )
        self.assertTrue(response["ok"], response)
        self.assertTrue(self.ctx.users.verify("dave", password))
        events = [e["event"] for e in audit_events(self.ctx.audit)]
        self.assertEqual(events.count("cli_user_created"), 1)
        with open(self.ctx.audit.path, "r", encoding="utf-8") as fh:
            dump = fh.read()
        self.assertNotIn(password, dump)

    def test_user_delete_via_socket_revokes_sessions_and_audits(self) -> None:
        self.add_user()
        session = self.ctx.sessions.login("alice", IP)
        response = control_call(
            self.path, {"action": "user.del", "name": "alice"}
        )
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["status"], 0)
        self.assertIsNone(self.ctx.users.record("alice"))
        self.assertIsNone(self.ctx.sessions.validate(session.token, IP))
        events = [e["event"] for e in audit_events(self.ctx.audit)]
        self.assertEqual(events.count("cli_user_deleted"), 1)

    def test_user_passwd_via_socket_revokes_sessions_and_audits(self) -> None:
        self.add_user()
        session = self.ctx.sessions.login("alice", IP)
        new_password = "alice-password-2"
        response = control_call(
            self.path,
            {
                "action": "user.passwd",
                "name": "alice",
                "password": new_password,
                "must_change_password": False,
            },
        )
        self.assertTrue(response["ok"], response)
        self.assertTrue(self.ctx.users.verify("alice", new_password))
        self.assertIsNone(self.ctx.sessions.validate(session.token, IP))
        events = [e["event"] for e in audit_events(self.ctx.audit)]
        self.assertEqual(events.count("cli_password_changed"), 1)
        # A jelszó soha nem kerülhet a naplóba.
        with open(self.ctx.audit.path, "r", encoding="utf-8") as fh:
            dump = fh.read()
        self.assertNotIn(new_password, dump)

    def test_fail2ban_ban_via_socket_revokes_ip_and_flushes_conntrack(
        self,
    ) -> None:
        self.add_user("bob", "bob-password-1")
        session = self.ctx.sessions.login("bob", IP)
        rule = gateway.Rule(
            id="web", label="web", description="", tcp=(80,)
        )
        self.ctx.sessions.authorize(session.token, IP, rule, 600)

        flushed: list[str] = []

        def fake_flush(ip: str, audit=None) -> bool:
            flushed.append(ip)
            return True

        with mock.patch.object(
            gateway, "conntrack_flush", side_effect=fake_flush
        ):
            response = control_call(
                self.path,
                {
                    "action": "fail2ban.ban",
                    "ip": IP,
                    "seconds": 120,
                },
            )
        self.assertTrue(response["ok"], response)
        self.assertIn(IP, flushed)
        self.assertIsNone(self.ctx.sessions.validate(session.token, IP))
        events = [e["event"] for e in audit_events(self.ctx.audit)]
        # Az on_ban írja a fail2ban_ban eseményt, a csatorna a cli_* párt.
        self.assertEqual(events.count("fail2ban_ban"), 1)
        self.assertEqual(events.count("cli_fail2ban_ban"), 1)

        response = control_call(
            self.path, {"action": "fail2ban.unban", "ip": IP}
        )
        self.assertTrue(response["ok"], response)
        self.assertIsNone(self.ctx.fail2ban.banned(IP))
        # A feloldás nem állítja vissza a korábbi hozzáférést.
        self.assertIsNone(self.ctx.sessions.validate(session.token, IP))

    def test_server_close_removes_socket_and_is_idempotent(self) -> None:
        self.control.stop()
        self.assertFalse(os.path.exists(self.path))
        # Második lezárás nem dobhat és nem hozhat létre új fájlt.
        self.control.server_close()
        self.assertFalse(os.path.exists(self.path))

    def test_stop_waits_for_inflight_handler(self) -> None:
        # A kezelőszálak nem daemon szálak: a stop() a lezárás előtt
        # megvárja a már elfogadott kérés feldolgozását.
        self.add_user()
        started = threading.Event()
        release = threading.Event()
        original = server.ControlHandler.handle

        def slow_handle(handler) -> None:
            started.set()
            release.wait(5)
            return original(handler)

        def client() -> None:
            try:
                control_call(self.path, {"action": "status"}, timeout=10)
            except OSError:
                pass

        with mock.patch.object(
            server.ControlHandler, "handle", slow_handle
        ):
            worker = threading.Thread(target=client, daemon=True)
            worker.start()
            self.assertTrue(started.wait(5))
            stopper = threading.Thread(
                target=self.control.stop, daemon=True
            )
            stopper.start()
            stopper.join(0.3)
            self.assertTrue(
                stopper.is_alive(),
                "a stop() nem várta meg a futó kezelőt",
            )
            release.set()
            stopper.join(5)
            self.assertFalse(stopper.is_alive())
            worker.join(5)
        self.assertFalse(os.path.exists(self.path))

    def test_socket_swap_during_chmod_is_detected(self) -> None:
        swap_dir = os.path.join(self.tmp.name, "swap")
        os.makedirs(swap_dir, mode=0o700)
        path = os.path.join(swap_dir, "swap.sock")
        real_chmod = os.chmod

        def swapping_chmod(target, mode) -> None:
            real_chmod(target, mode)
            if target == path:
                os.unlink(path)
                replacement = socket.socket(
                    socket.AF_UNIX, socket.SOCK_STREAM
                )
                replacement.bind(path)
                replacement.close()

        with mock.patch("server.os.chmod", side_effect=swapping_chmod):
            with self.assertRaises(server.ControlUnavailable):
                server.ControlServer(path, self.ctx.gw)
        # Az idegen, kicserélt socketet nem töröljük.
        self.assertTrue(stat.S_ISSOCK(os.lstat(path).st_mode))

    def test_stale_socket_is_replaced(self) -> None:
        stale_path = os.path.join(self.tmp.name, "stale.sock")
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(stale_path)
        stale.close()
        self.assertTrue(os.path.exists(stale_path))
        control = server.ControlServer(stale_path, self.ctx.gw)
        control.start()
        self.addCleanup(control.stop)
        self.assertEqual(
            stat.S_IMODE(os.stat(stale_path).st_mode), 0o600
        )
        response = control_call(stale_path, {"action": "status"})
        self.assertTrue(response["ok"])

    def test_non_socket_path_is_not_deleted(self) -> None:
        path = os.path.join(self.tmp.name, "not-a-socket")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("értékes fájl")
        with self.assertRaises(server.ControlUnavailable):
            server.ControlServer(path, self.ctx.gw)
        with open(path, "r", encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "értékes fájl")


class ControlPeerCredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ctx = build_gateway(self.tmp.name)

    def make_handler(self, uid: int):
        handler = object.__new__(server.ControlHandler)
        handler.request = _FakePeerRequest(uid)
        handler.server = types.SimpleNamespace(gateway=self.ctx.gw)
        handler.rfile = io.BytesIO(b'{"action":"status"}\n')
        handler.wfile = io.BytesIO()
        return handler

    def test_foreign_uid_is_rejected_generically(self) -> None:
        handler = self.make_handler(os.geteuid() + 1)
        handler.handle()
        response = json.loads(handler.wfile.getvalue())
        self.assertEqual(
            response, {"ok": False, "status": 1, "error": "elutasítva"}
        )
        events = audit_events(self.ctx.audit)
        denied = [e for e in events if e["event"] == "control_denied"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["reason"], "peer_uid")
        # A peer uid/pid nem kerülhet a naplóba.
        self.assertNotIn(str(os.geteuid() + 1), json.dumps(denied))

    def test_same_uid_is_accepted(self) -> None:
        handler = self.make_handler(os.geteuid())
        handler.handle()
        response = json.loads(handler.wfile.getvalue())
        self.assertTrue(response["ok"], response)


class ControlStartupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ctx = build_gateway(self.tmp.name)
        self._old_state = gateway.STATE_DIR
        gateway.STATE_DIR = self.tmp.name
        self.addCleanup(
            lambda: setattr(gateway, "STATE_DIR", self._old_state)
        )

    def test_world_writable_state_dir_refuses_control(self) -> None:
        os.chmod(self.tmp.name, 0o777)
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            control = server._start_control_server(self.ctx.gw)
        self.assertIsNone(control)
        self.assertIn("nem biztonságos", err.getvalue())
        self.assertIn("PID-fájl", err.getvalue())
        # A STATE_DIR jogosultságát nem változtatjuk meg, és a
        # vezérlőkönyvtárat/socketet sem hozzuk létre.
        self.assertEqual(
            stat.S_IMODE(os.stat(self.tmp.name).st_mode), 0o777
        )
        self.assertFalse(
            os.path.exists(control_path(self.tmp.name))
        )

    def test_secure_state_dir_starts_control_in_private_dir(self) -> None:
        os.chmod(self.tmp.name, 0o700)
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            control = server._start_control_server(self.ctx.gw)
        self.assertIsNotNone(control, err.getvalue())
        self.addCleanup(control.stop)
        socket_path = control_path(self.tmp.name)
        self.assertTrue(
            stat.S_ISSOCK(os.stat(socket_path).st_mode)
        )
        self.assertEqual(
            stat.S_IMODE(os.stat(socket_path).st_mode), 0o600
        )
        control_dir = os.path.dirname(socket_path)
        self.assertEqual(
            stat.S_IMODE(os.stat(control_dir).st_mode), 0o700
        )
        response = control_call(socket_path, {"action": "status"})
        self.assertTrue(response["ok"], response)

    def test_control_server_rejects_world_writable_parent(self) -> None:
        parent = os.path.join(self.tmp.name, "open")
        os.makedirs(parent)
        os.chmod(parent, 0o777)
        with self.assertRaises(server.ControlUnavailable):
            server.ControlServer(
                os.path.join(parent, "control.sock"), self.ctx.gw
            )

    def test_pidfile_is_0600_and_removed(self) -> None:
        inode = server._write_server_pid()
        self.assertIsNotNone(inode)
        path = os.path.join(self.tmp.name, server.SERVER_PID_NAME)
        state = os.stat(path)
        self.assertTrue(stat.S_ISREG(state.st_mode))
        self.assertEqual(stat.S_IMODE(state.st_mode), 0o600)
        with open(path, "r", encoding="ascii") as fh:
            self.assertEqual(fh.read(), f"{os.getpid()}\n")
        self.assertEqual(server._live_daemon_pid(), os.getpid())
        server._remove_server_pid(inode)
        self.assertFalse(os.path.exists(path))
        # Második eltávolítás nem dobhat.
        server._remove_server_pid(inode)

    def test_live_daemon_pid_ignores_stale_and_unsafe_pidfiles(self) -> None:
        path = os.path.join(self.tmp.name, server.SERVER_PID_NAME)
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait()
        with open(path, "w", encoding="ascii") as fh:
            fh.write(f"{dead.pid}\n")
        os.chmod(path, 0o600)
        self.assertIsNone(server._live_daemon_pid())

        # Csoport/más által írható PID-fájlból nem fogadunk el PID-et.
        with open(path, "w", encoding="ascii") as fh:
            fh.write(f"{os.getpid()}\n")
        os.chmod(path, 0o644)
        self.assertIsNone(server._read_server_pid())
        self.assertIsNone(server._live_daemon_pid())

        os.chmod(path, 0o600)
        self.assertEqual(server._live_daemon_pid(), os.getpid())


# ------------------------------------------------------------ CLI visszaesés


class CliFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.nft, self.conntrack = write_fake_tools(self.tmp.name)
        self.users_path = os.path.join(self.tmp.name, "cli-users.json")
        self.audit_path = os.path.join(self.tmp.name, "cli-audit.jsonl")
        self.state_dir = os.path.join(self.tmp.name, "state")
        os.makedirs(self.state_dir)

    def run_cli(
        self, *args: str, input_text: str = ""
    ) -> subprocess.CompletedProcess:
        env = {
            **os.environ,
            "HV_USERS": self.users_path,
            "HV_AUDIT_LOG": self.audit_path,
            "HV_STATE_DIR": self.state_dir,
            "HV_NFT_BIN": self.nft,
            "HV_CONNTRACK_BIN": self.conntrack,
        }
        return subprocess.run(
            [sys.executable, str(ROOT / "server.py"), *args],
            cwd=str(ROOT),
            env=env,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_user_add_falls_back_and_warns_when_socket_absent(self) -> None:
        password = "bob-password-1"
        result = self.run_cli(
            "user", "add", "bob", "--password-stdin",
            input_text=password + "\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Felhasználó létrehozva: bob", result.stdout)
        self.assertIn("FIGYELEM", result.stderr)
        self.assertIn("nincs vezérlőcsatorna", result.stderr)
        self.assertIn("NEM vonta vissza", result.stderr)
        self.assertNotIn(password, result.stdout)
        self.assertNotIn(password, result.stderr)
        store = gateway.UserStore(self.users_path)
        self.assertIsNotNone(store.record("bob"))
        with open(self.audit_path, "r", encoding="utf-8") as fh:
            dump = fh.read()
        self.assertIn("cli_user_created", dump)
        self.assertNotIn(password, dump)

    def test_fail2ban_ban_falls_back_and_warns_when_socket_absent(
        self,
    ) -> None:
        result = self.run_cli(
            "fail2ban", "ban", IP, "--seconds", "120"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"Letiltva: {IP}", result.stdout)
        self.assertIn("FIGYELEM", result.stderr)
        self.assertIn("NEM vonta vissza", result.stderr)
        manager = fail2ban_mod.Fail2ban(
            gateway.Firewall(binary=self.nft, logger=lambda *_: None),
            path=os.path.join(self.state_dir, "fail2ban.json"),
            logger=lambda *_: None,
        )
        self.assertIsNotNone(manager.banned(IP))
        with open(self.audit_path, "r", encoding="utf-8") as fh:
            dump = fh.read()
        self.assertIn("fail2ban_ban", dump)
        self.assertIn("cli_fail2ban_ban", dump)

    def test_daemon_error_does_not_fall_back(self) -> None:
        # A helyi fájlban van carol, a démon saját (üres) tárában nincs.
        gateway.UserStore(
            self.users_path, iterations=10_000
        ).add("carol", "carol-password-1")
        daemon_dir = os.path.join(self.tmp.name, "daemon")
        os.makedirs(daemon_dir)
        ctx = build_gateway(daemon_dir)
        path = control_path(daemon_dir)
        os.makedirs(os.path.dirname(path), mode=0o700)
        control = server.ControlServer(path, ctx.gw)
        control.start()
        self.addCleanup(control.stop)
        # A CLI ugyanazt a state könyvtárat lássa, ahol a socket van.
        self.state_dir = daemon_dir

        result = self.run_cli("user", "del", "carol")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Nincs ilyen felhasználó: carol", result.stdout)
        # Érvényes hibaüzenet érkezett: NEM szabad helyben is módosítani.
        self.assertNotIn("FIGYELEM", result.stderr)
        self.assertIsNotNone(
            gateway.UserStore(self.users_path).record("carol")
        )

    def test_valid_socket_runs_mutation_in_daemon(self) -> None:
        daemon_dir = os.path.join(self.tmp.name, "daemon")
        os.makedirs(daemon_dir)
        ctx = build_gateway(daemon_dir)
        ctx.users.add("carol", "carol-password-1")
        path = control_path(daemon_dir)
        os.makedirs(os.path.dirname(path), mode=0o700)
        control = server.ControlServer(path, ctx.gw)
        control.start()
        self.addCleanup(control.stop)
        self.state_dir = daemon_dir

        result = self.run_cli("user", "del", "carol")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Felhasználó törölve: carol", result.stdout)
        self.assertNotIn("FIGYELEM", result.stderr)
        # A démon élő tárából tűnt el a felhasználó; a CLI helyi fájlja
        # üres maradt (nem esett vissza helyi módra).
        self.assertIsNone(ctx.users.record("carol"))
        self.assertIsNone(
            gateway.UserStore(self.users_path).record("carol")
        )

    def test_presend_connection_refused_falls_back_with_warning(self) -> None:
        # Elavult socket: létezik, 0600, de senki nem figyel rajta.
        path = control_path(self.state_dir)
        os.makedirs(os.path.dirname(path), mode=0o700)
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(path)
        os.chmod(path, 0o600)
        stale.close()

        result = self.run_cli(
            "user", "add", "bob", "--password-stdin",
            input_text="bob-password-1\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Felhasználó létrehozva: bob", result.stdout)
        self.assertIn("FIGYELEM", result.stderr)
        self.assertIn("elavult socket", result.stderr)
        self.assertIsNotNone(
            gateway.UserStore(self.users_path).record("bob")
        )

    def test_post_send_eof_never_falls_back(self) -> None:
        close_server = start_raw_control_server(self.state_dir, hold=0.0)
        self.addCleanup(close_server)
        result = self.run_cli(
            "user", "add", "bob", "--password-stdin",
            input_text="bob-password-1\n",
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("NEM futtattam helyi módosítást", result.stderr)
        self.assertIn("megszakadt vagy üres", result.stderr)
        self.assertNotIn("Felhasználó létrehozva", result.stdout)
        self.assertIsNone(
            gateway.UserStore(self.users_path).record("bob")
        )

    def test_post_send_timeout_is_ambiguous_and_never_mutates_locally(
        self,
    ) -> None:
        old_state = gateway.STATE_DIR
        gateway.STATE_DIR = self.state_dir
        self.addCleanup(
            lambda: setattr(gateway, "STATE_DIR", old_state)
        )
        old_timeout = server.CONTROL_CLI_TIMEOUT
        server.CONTROL_CLI_TIMEOUT = 0.3
        self.addCleanup(
            lambda: setattr(
                server, "CONTROL_CLI_TIMEOUT", old_timeout
            )
        )
        close_server = start_raw_control_server(self.state_dir, hold=1.0)
        self.addCleanup(close_server)
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            handled, code = server._control_mutation(
                {
                    "action": "user.add",
                    "name": "timeout-bob",
                    "password": "timeout-password-1",
                }
            )
        self.assertTrue(handled)
        self.assertEqual(code, 1)
        self.assertIn("NEM futtattam helyi módosítást", err.getvalue())
        self.assertIn("időtúllépés", err.getvalue())
        self.assertIsNone(
            gateway.UserStore(self.users_path).record("timeout-bob")
        )

    def write_pidfile(self, pid: int, mode: int = 0o600) -> str:
        path = os.path.join(self.state_dir, server.SERVER_PID_NAME)
        with open(path, "w", encoding="ascii") as fh:
            fh.write(f"{pid}\n")
        os.chmod(path, mode)
        return path

    def test_stale_pidfile_allows_fallback(self) -> None:
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait()
        self.write_pidfile(dead.pid)
        result = self.run_cli(
            "user", "add", "bob", "--password-stdin",
            input_text="bob-password-1\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Felhasználó létrehozva: bob", result.stdout)
        self.assertIn("FIGYELEM", result.stderr)
        self.assertIsNotNone(
            gateway.UserStore(self.users_path).record("bob")
        )

    def test_live_pidfile_refuses_user_mutation(self) -> None:
        self.write_pidfile(os.getpid())
        result = self.run_cli(
            "user", "add", "bob", "--password-stdin",
            input_text="bob-password-1\n",
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("démon fut", result.stderr)
        self.assertIn("NEM futtattam", result.stderr)
        self.assertNotIn("Felhasználó létrehozva", result.stdout)
        self.assertIsNone(
            gateway.UserStore(self.users_path).record("bob")
        )

    def test_live_pidfile_refuses_fail2ban_mutation(self) -> None:
        self.write_pidfile(os.getpid())
        result = self.run_cli(
            "fail2ban", "ban", IP, "--seconds", "120"
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("démon fut", result.stderr)
        self.assertIn("NEM futtattam", result.stderr)
        self.assertNotIn(f"Letiltva: {IP}", result.stdout)
        manager = fail2ban_mod.Fail2ban(
            gateway.Firewall(binary=self.nft, logger=lambda *_: None),
            path=os.path.join(self.state_dir, "fail2ban.json"),
            logger=lambda *_: None,
        )
        self.assertIsNone(manager.banned(IP))


# ------------------------------------------------------ F7: versenyhelyzetek


class Fail2banRaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ctx = build_gateway(self.tmp.name)
        self._old_conntrack = gateway.CONNTRACK_BIN
        gateway.CONNTRACK_BIN = self.ctx.conntrack
        self.addCleanup(
            lambda: setattr(gateway, "CONNTRACK_BIN", self._old_conntrack)
        )
        self.ctx.users.add("alice", "alice-password-1")

    def ban_without_side_effects(self) -> None:
        # Szimulálja, hogy a tiltás már bekerült az állapotba, de a
        # visszahívás (még) nem bontotta a munkameneteket.
        with mock.patch.object(
            self.ctx.fail2ban, "_notify", lambda _record: None
        ):
            self.ctx.fail2ban.ban(
                IP, 120, manual=True, user="cli"
            )

    def test_login_session_creation_rechecks_ban(self) -> None:
        self.ban_without_side_effects()
        double = _HandlerDouble(self.ctx.gw)
        server.Handler._login_session_response(
            double, self.ctx.users.record("alice"), method="totp"
        )
        self.assertEqual(len(double.responses), 1)
        code, payload, headers = double.responses[0]
        self.assertEqual(code, 403)
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["banned"])
        self.assertEqual(payload["ban_source"], "manual")
        self.assertIn("Retry-After", headers)
        self.assertEqual(self.ctx.sessions.count(), 0)
        events = [e for e, _fields in double.audits]
        self.assertEqual(events.count("login_banned"), 1)
        fields = dict(double.audits[0][1])
        self.assertEqual(fields["user"], "alice")
        self.assertEqual(fields["method"], "totp")
        self.assertEqual(fields["source"], "manual")
        # A válasz nem tartalmazhat jelszót, tokent vagy sütit.
        dumped = json.dumps(payload)
        self.assertNotIn("alice-password-1", dumped)
        self.assertNotIn("Set-Cookie", headers)

    def test_ban_between_precheck_and_login_revokes_new_session(self) -> None:
        # A szimulált verseny: a login() sikeresen létrehozza a
        # munkamenetet, majd — még a válasz előtt — az IP tiltásra kerül.
        double = _HandlerDouble(self.ctx.gw)
        real_login = self.ctx.sessions.login

        def login_then_ban(*args, **kwargs):
            session = real_login(*args, **kwargs)
            self.ban_without_side_effects()
            return session

        with mock.patch.object(
            self.ctx.sessions, "login", side_effect=login_then_ban
        ):
            server.Handler._login_session_response(
                double, self.ctx.users.record("alice"), method="password"
            )
        self.assertEqual(len(double.responses), 1)
        code, payload, headers = double.responses[0]
        self.assertEqual(code, 403)
        self.assertTrue(payload["banned"])
        self.assertNotIn("Set-Cookie", headers)
        # A létrehozott munkamenet nem maradhat életben.
        self.assertEqual(self.ctx.sessions.count(), 0)
        self.assertEqual(
            self.ctx.sessions.active_sessions(), []
        )
        events = dict(double.audits)
        self.assertIn("login_banned", events)
        self.assertTrue(events["login_banned"]["post_login"])
        self.assertNotIn("login_success", events)
        dumped = json.dumps(payload)
        self.assertNotIn("alice-password-1", dumped)

    def test_session_rejects_banned_ip_despite_valid_token(self) -> None:
        session = self.ctx.sessions.login("alice", IP)
        self.assertIsNotNone(
            self.ctx.sessions.validate(session.token, IP)
        )
        self.ban_without_side_effects()
        double = _HandlerDouble(self.ctx.gw, token=session.token)
        self.assertIsNone(server.Handler._session(double))
        # A védelem mélységben nem vonja vissza a munkamenetet; azt a
        # belépési/hozzáférési út teszi meg.
        self.assertIsNotNone(
            self.ctx.sessions.validate(session.token, IP)
        )

    def test_status_returns_ban_payload_for_banned_ip(self) -> None:
        session = self.ctx.sessions.login("alice", IP)
        self.ban_without_side_effects()
        double = _HandlerDouble(self.ctx.gw, token=session.token)
        server.Handler._status(double)
        self.assertEqual(len(double.responses), 1)
        code, payload, headers = double.responses[0]
        self.assertEqual(code, 403)
        self.assertTrue(payload["banned"])
        self.assertFalse(payload["authenticated"])
        self.assertNotIn("user", payload)
        self.assertNotIn("rules", payload)
        self.assertIn("Retry-After", headers)
        self.assertNotIn(session.token, json.dumps(payload))

    def test_password_change_returns_ban_payload_for_banned_ip(self) -> None:
        session = self.ctx.sessions.login("alice", IP)
        self.ban_without_side_effects()
        double = _HandlerDouble(
            self.ctx.gw,
            data={
                "current": "alice-password-1",
                "new": "alice-password-2",
            },
            token=session.token,
        )
        server.Handler._password(double)
        self.assertEqual(len(double.responses), 1)
        code, payload, headers = double.responses[0]
        self.assertEqual(code, 403)
        self.assertTrue(payload["banned"])
        self.assertIn("Retry-After", headers)
        # A jelszó nem változott meg.
        self.assertTrue(
            self.ctx.users.verify("alice", "alice-password-1")
        )
        self.assertFalse(
            self.ctx.users.verify("alice", "alice-password-2")
        )
        failed = [
            fields for event, fields in double.audits
            if event == "password_change_failed"
            and fields.get("reason") == "fail2ban tiltás"
        ]
        self.assertEqual(len(failed), 1)
        self.assertNotIn(
            "alice-password-2", json.dumps(double.audits)
        )

    def test_admin_guard_rejects_banned_ip_without_data(self) -> None:
        session = self.ctx.sessions.login("alice", IP)
        self.ban_without_side_effects()
        double = _HandlerDouble(self.ctx.gw, token=session.token)
        double.path = "/api/admin/state"
        self.assertIsNone(server.Handler._admin_guard(double))
        self.assertEqual(len(double.responses), 1)
        code, payload, _headers = double.responses[0]
        self.assertEqual(code, 403)
        self.assertEqual(payload.get("code"), "admin_session")
        self.assertNotIn("users", payload)
        self.assertNotIn("sessions", payload)

    def test_access_denies_and_revokes_banned_ip(self) -> None:
        session = self.ctx.sessions.login("alice", IP)
        rule = gateway.Rule(
            id="web", label="web", description="", tcp=(80,)
        )
        self.ctx.sessions.authorize(session.token, IP, rule, 600)
        self.assertTrue(
            self.ctx.sessions.validate(session.token, IP).authorized
        )
        self.ban_without_side_effects()

        flushed: list[str] = []

        def fake_flush(ip: str, audit=None) -> bool:
            flushed.append(ip)
            return True

        double = _HandlerDouble(
            self.ctx.gw,
            data={"rule": "web", "ttl": 600},
            token=session.token,
        )
        with mock.patch.object(
            gateway, "conntrack_flush", side_effect=fake_flush
        ):
            server.Handler._access(double)
        self.assertEqual(len(double.responses), 1)
        code, payload, _headers = double.responses[0]
        self.assertEqual(code, 403)
        self.assertTrue(payload["banned"])
        self.assertIsNone(
            self.ctx.sessions.validate(session.token, IP)
        )
        self.assertIn(IP, flushed)
        denied = [
            fields for event, fields in double.audits
            if event == "access_denied" and fields.get("reason") == "fail2ban"
        ]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["source"], "manual")
        self.assertEqual(denied[0]["sessions_revoked"], 1)

    def test_access_logs_out_authorized_session_when_password_must_change(
        self,
    ) -> None:
        session = self.ctx.sessions.login("alice", IP)
        rule = gateway.Rule(
            id="web", label="web", description="", tcp=(80,)
        )
        self.ctx.sessions.authorize(session.token, IP, rule, 600)
        # Időközben egy másik folyamat kötelező jelszócserét állít be.
        self.ctx.users.set_password(
            "alice", "temp-password-1", must_change_password=True
        )
        double = _HandlerDouble(
            self.ctx.gw,
            data={"rule": "web", "ttl": 600},
            token=session.token,
        )
        server.Handler._access(double)
        self.assertEqual(len(double.responses), 1)
        code, payload, _headers = double.responses[0]
        self.assertEqual(code, 403)
        self.assertTrue(payload["must_change_password"])
        self.assertIsNone(
            self.ctx.sessions.validate(session.token, IP)
        )
        denied = [
            fields for event, fields in double.audits
            if event == "access_denied"
            and fields.get("reason") == "kötelező jelszócsere"
        ]
        self.assertEqual(len(denied), 1)
        self.assertTrue(denied[0]["access_revoked"])


if __name__ == "__main__":
    unittest.main()
