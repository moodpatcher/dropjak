#!/usr/bin/env python3
"""Csomagszintű teszt az otthoni tunnel-ügynök nft szabályaihoz.

Futtatás:  unshare -rn python3 tests/tunnel_agent_netns.py

A gyökér-névtér az ügynök konténerét modellezi: ``wg0`` veth a "felhő"
kliens felé (10.77.0.2/24 <-> 10.77.0.3/24), ``int0`` veth a belső Docker
hálózat felé (172.30.0.1/24 <-> 172.30.0.2/24). A belső névtérben futó
szolgáltatás a 25565-ös TCP/UDP porton figyel; a felhő kliens a
10.77.0.2:41001-re csatlakozik. A valódi, renderelt szabálykészlet töltődik
be, majd ellenőrizzük:

* a leképezett TCP/UDP port elérhető (és a szolgáltatás az ügynök belső
  IP-jét látja a SNAT miatt),
* a nem leképezett port nem érhető el,
* a konténerből a tunnel felé (10.77.0.3:9999) és a felhő endpoint felé
  (198.51.100.7:51820) induló NEW kapcsolat eldobódik.

Kimenet: JSON a vizsgálatokkal; a kilépési kód 0, ha minden rendben.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT_PATH = ROOT / "deploy" / "tunnel-agent" / "agent.py"

CLIENT = r'''
import socket, sys
proto, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    if proto == "tcp":
        s = socket.create_connection((host, port), timeout=2)
        s.settimeout(2)
        print(s.recv(200).decode().strip())
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(b"ping", (host, port))
        print(s.recvfrom(200)[0].decode().strip())
except Exception as exc:
    print("ERR " + type(exc).__name__)
'''

SERVICE = r'''
import socket, threading, time
def tcp():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 25565)); srv.listen(8)
    while True:
        conn, peer = srv.accept()
        conn.sendall(f"svc-tcp peer={peer[0]}".encode()); conn.close()
def udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 25565))
    while True:
        data, peer = sock.recvfrom(200)
        sock.sendto(f"svc-udp peer={peer[0]}".encode(), peer)
threading.Thread(target=tcp, daemon=True).start()
threading.Thread(target=udp, daemon=True).start()
time.sleep(600)
'''

PEER_LISTENER = r'''
import socket, time
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 9999)); srv.listen(8)
while True:
    conn, _ = srv.accept()
    conn.sendall(b"peer-listener")
    conn.close()
'''

NETS = {  # névtér: (gyökér-if, gyermek-if, gyökér-cím, gyermek-cím, átjáró)
    "peer": ("wg0", "cwg", "10.77.0.2/24", "10.77.0.3/24", "10.77.0.2"),
    "svc": ("int0", "csvc", "172.30.0.1/24", "172.30.0.2/24", "172.30.0.1"),
}


def run(*args: str, check: bool = True, **kw) -> subprocess.CompletedProcess:
    result = subprocess.run(list(args), capture_output=True, text=True,
                            timeout=30, **kw)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {result.stderr.strip()}")
    return result


def ns(pid: int, *args: str, **kw) -> subprocess.CompletedProcess:
    return run("nsenter", "-t", str(pid), "-n", *args, **kw)


def load_agent():
    spec = importlib.util.spec_from_file_location("dropjak_tunnel_agent",
                                                  AGENT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def spawn_netns(spawned: list) -> subprocess.Popen:
    child = subprocess.Popen(["unshare", "-n", "sleep", "600"],
                             stdout=subprocess.DEVNULL)
    spawned.append(child)
    time.sleep(0.1)
    return child


def main() -> int:
    children: list[subprocess.Popen] = []
    try:
        return _main(children)
    finally:
        for child in children:
            child.kill()


def _main(spawned: list) -> int:
    ta = load_agent()
    run("ip", "link", "set", "lo", "up")
    ns_pids: dict[str, int] = {}
    for name, (gw_if, child_if, gw_addr, child_addr, gateway) in NETS.items():
        child = spawn_netns(spawned)
        ns_pids[name] = child.pid
        run("ip", "link", "add", gw_if, "type", "veth",
            "peer", "name", child_if, "netns", str(child.pid))
        run("ip", "addr", "add", gw_addr, "dev", gw_if)
        run("ip", "link", "set", gw_if, "up")
        ns(child.pid, "ip", "link", "set", "lo", "up")
        ns(child.pid, "ip", "addr", "add", child_addr, "dev", child_if)
        ns(child.pid, "ip", "link", "set", child_if, "up")
        ns(child.pid, "ip", "route", "add", "default", "via", gateway)

    # A "felhő" felé vezető út, hogy a forward-lánc foghassa a csomagot.
    run("ip", "route", "add", "198.51.100.0/24", "dev", "wg0")

    for name, script in (("svc", SERVICE), ("peer", PEER_LISTENER)):
        process = subprocess.Popen(
            ["nsenter", "-t", str(ns_pids[name]), "-n",
             sys.executable, "-c", script],
            stdout=subprocess.DEVNULL)
        spawned.append(process)

    Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
    config = ta.validate_config({
        "format": "dropjak-agent", "version": 1,
        "agent": {"id": "home-1", "label": "Home", "address": "10.77.0.2"},
        "wireguard": {
            "private_key": "A" * 43 + "=",
            "address": "10.77.0.2/24",
            "peer_public_key": "A" * 43 + "=",
            "preshared_key": "A" * 43 + "=",
            "endpoint": "198.51.100.7:51820",
            "allowed_ips": ["10.77.0.1/32"],
            "persistent_keepalive": 25,
        },
        "sync": {"url": "http://10.77.0.1:8100/api/tunnel/config",
                 "token": "test-token", "interval_seconds": 30},
        "services": [{"id": "mc", "label": "Minecraft", "proto": "both",
                      "tunnel_port": 41001, "target": "172.30.0.2:25565",
                      "enabled": True}],
    })
    entries = [{"id": "mc", "proto": "both", "tunnel_port": 41001,
                "ip": "172.30.0.2", "target_port": 25565, "iface": "int0"}]
    rules = ta.render_ruleset(config, entries, ["198.51.100.7"], ["int0"],
                              ["10.77.0.1"], [])
    run("nft", "-f", "-", input=rules)
    time.sleep(1.0)  # ARP és a szolgáltatás indulása

    checks: dict[str, object] = {}
    ok = True

    def probe(net: str, proto: str, host: str, port: int) -> str:
        return ns(ns_pids[net], sys.executable, "-c", CLIENT, proto, host,
                  str(port)).stdout.strip()

    def expect(label: str, condition: bool, detail) -> None:
        nonlocal ok
        checks[label] = {"ok": condition, "detail": detail}
        ok = ok and condition

    mapped_tcp = probe("peer", "tcp", "10.77.0.2", 41001)
    mapped_udp = probe("peer", "udp", "10.77.0.2", 41001)
    expect("mapped_tcp_reaches_service_with_agent_source_ip",
           mapped_tcp == "svc-tcp peer=172.30.0.1", mapped_tcp)
    expect("mapped_udp_reaches_service_with_agent_source_ip",
           mapped_udp == "svc-udp peer=172.30.0.1", mapped_udp)

    unmapped_tcp = probe("peer", "tcp", "10.77.0.2", 41002)
    unmapped_udp = probe("peer", "udp", "10.77.0.2", 41002)
    expect("unmapped_tcp_blocked", unmapped_tcp.startswith("ERR"),
           unmapped_tcp)
    expect("unmapped_udp_blocked", unmapped_udp.startswith("ERR"),
           unmapped_udp)

    to_tunnel = probe("svc", "tcp", "10.77.0.3", 9999)
    to_cloud = probe("svc", "udp", "198.51.100.7", 51820)
    expect("container_to_tunnel_blocked", to_tunnel.startswith("ERR"),
           to_tunnel)
    expect("container_to_cloud_endpoint_blocked", to_cloud.startswith("ERR"),
           to_cloud)

    print(json.dumps({"ok": ok, "checks": checks}, indent=1,
                     ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
