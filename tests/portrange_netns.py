#!/usr/bin/env python3
"""Port range packet-level test in a user+net namespace (without root).

Run:  unshare -rn python3 tests/portrange_netns.py

The outer namespace is the portal host (veth0 = 10.20.0.1), the child namespace
is the client (10.20.0.2). The host TCP/UDP listeners on 18005 and 18011
listen on 0.0.0.0. The real Firewall issues the 18000-18010 input range, then
revokes it. Output: JSON with the checks; exit code 0 if everything is fine.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CLIENT = r'''
import socket, sys
proto, port = sys.argv[1], int(sys.argv[2])
try:
    if proto == "tcp":
        s = socket.create_connection(("10.20.0.1", port), timeout=1)
        s.settimeout(1)
        print(s.recv(100).decode().strip())
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b"ping", ("10.20.0.1", port))
        print(s.recv(100).decode().strip())
except Exception as exc:
    print("ERR " + type(exc).__name__)
'''


def run(*args: str, check: bool = True, **kw) -> subprocess.CompletedProcess:
    result = subprocess.run(
        list(args), capture_output=True, text=True, timeout=60, **kw
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {result.stderr.strip()}")
    return result


def serve() -> None:
    def tcp(port: int) -> None:
        import socket
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(8)
        while True:
            conn, _peer = srv.accept()
            conn.sendall(f"ok-tcp-{port}".encode())
            conn.close()

    def udp(port: int) -> None:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", port))
        while True:
            _data, peer = sock.recvfrom(200)
            sock.sendto(f"ok-udp-{port}".encode(), peer)

    for port in (18005, 18011):
        threading.Thread(target=tcp, args=(port,), daemon=True).start()
        threading.Thread(target=udp, args=(port,), daemon=True).start()
    time.sleep(0.3)


def main() -> int:
    import gateway

    run("ip", "link", "set", "lo", "up")
    child = subprocess.Popen(["unshare", "-n", "sleep", "120"])
    try:
        run("ip", "link", "add", "veth0", "type", "veth",
            "peer", "name", "c0", "netns", str(child.pid))
        run("ip", "addr", "add", "10.20.0.1/24", "dev", "veth0")
        run("ip", "link", "set", "veth0", "up")
        for command in (
            ("ip", "link", "set", "lo", "up"),
            ("ip", "addr", "add", "10.20.0.2/24", "dev", "c0"),
            ("ip", "link", "set", "c0", "up"),
        ):
            run("nsenter", "-t", str(child.pid), "-n", *command)
        serve()
        run("nft", "-f", "-", input="""
add table inet hatarvedelem
add set inet hatarvedelem allowed_input_tcp {
    type ipv4_addr . inet_service
    flags interval,timeout
    size 16384
}
add set inet hatarvedelem allowed_input_udp {
    type ipv4_addr . inet_service
    flags interval,timeout
    size 16384
}
add chain inet hatarvedelem input {
    type filter hook input priority 0; policy drop;
}
add rule inet hatarvedelem input iifname "veth0" \\
    ip saddr . tcp dport @allowed_input_tcp accept
add rule inet hatarvedelem input iifname "veth0" \\
    ip saddr . udp dport @allowed_input_udp accept
""")
        fw = gateway.Firewall(
            table="hatarvedelem", dry_run=False, logger=lambda *_: None
        )
        grants = gateway.Ports(
            tcp=tuple(range(18000, 18011)),
            udp=tuple(range(18000, 18011)),
            direction="input",
        )

        def probe(proto: str, port: int) -> str:
            return run(
                "nsenter", "-t", str(child.pid), "-n", sys.executable,
                "-c", CLIENT, proto, str(port),
            ).stdout.strip()

        checks: dict[str, object] = {}
        ok = True

        def expect(name: str, condition: bool, detail) -> None:
            nonlocal ok
            checks[name] = {"ok": bool(condition), "detail": detail}
            ok = ok and bool(condition)

        before = {
            f"{proto}-18005": probe(proto, 18005)
            for proto in ("tcp", "udp")
        }
        expect("blocked_before_grant",
               all(value.startswith("ERR") for value in before.values()),
               before)
        fw.grant_all("10.20.0.2", (grants,), 60)
        accepted = {
            "tcp-18005": probe("tcp", 18005),
            "tcp-18011": probe("tcp", 18011),
            "udp-18005": probe("udp", 18005),
            "udp-18011": probe("udp", 18011),
        }
        expect("inside_range_works", accepted["tcp-18005"] == "ok-tcp-18005"
               and accepted["udp-18005"] == "ok-udp-18005", accepted)
        expect("outside_range_blocked",
               accepted["tcp-18011"].startswith("ERR")
               and accepted["udp-18011"].startswith("ERR"), accepted)
        fw.revoke_all("10.20.0.2", (grants,))
        revoked = {
            "tcp-18005": probe("tcp", 18005),
            "udp-18005": probe("udp", 18005),
        }
        expect("blocked_after_revoke",
               all(value.startswith("ERR") for value in revoked.values()),
               revoked)
        print(json.dumps({"ok": ok, "checks": checks}, ensure_ascii=False))
        return 0 if ok else 1
    finally:
        child.kill()


if __name__ == "__main__":
    raise SystemExit(main())
