#!/usr/bin/env python3
"""Csomagszintű port proxy teszt egy user+net névtérben (root nélkül).

Futtatás:  unshare -rn python3 tests/portproxy_netns.py

A külső névtér a portálgép: eth0 = WAN (198.51.100.1), eth1 = LAN
(192.168.10.1), eth2 = konténer-híd (172.19.0.1). Három gyermek-névtér: WAN
kliens (198.51.100.2), LAN kliens (192.168.10.2) és a forward cél
(172.19.0.2). A valódi, renderelt sablon és a Firewall által generált port
proxy szabályok töltődnek be; a cél szolgáltatások CSAK a 127.0.0.1-en
figyelnek (TCP és UDP), mint a Docker 127.0.0.1-re publikált portja.

Kimenet: JSON a vizsgálatokkal; a kilépési kód 0, ha minden rendben.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

T = "inet hatarvedelem"
GW = {"eth0": "198.51.100.1/24", "eth1": "192.168.10.1/24", "eth2": "172.19.0.1/24"}
NETS = {  # gyermek: (portálgép interfész, saját cím, átjáró)
    "wan": ("eth0", "198.51.100.2/24", "198.51.100.1"),
    "lan": ("eth1", "192.168.10.2/24", "192.168.10.1"),
    "tgt": ("eth2", "172.19.0.2/24", "172.19.0.1"),
}

CLIENT = r'''
import socket, sys
proto, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    if proto == "tcp":
        s = socket.create_connection((host, port), timeout=1)
        s.settimeout(1)
        print(s.recv(200).decode().strip())
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect((host, port))
        s.send(b"ping")
        print(s.recv(200).decode().strip())
except Exception as exc:
    print("ERR " + type(exc).__name__)
'''

TARGET = r'''
import socket, threading, time
def tcp():
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 80)); srv.listen(8)
    while True:
        c, a = srv.accept(); c.sendall(f"fwd-tcp peer={a[0]}\n".encode()); c.close()
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 9000))
    while True:
        d, a = s.recvfrom(200); s.sendto(f"fwd-udp peer={a[0]}".encode(), a)
threading.Thread(target=tcp, daemon=True).start()
threading.Thread(target=udp, daemon=True).start()
time.sleep(600)
'''

# Hallgató port -> (protokoll, típus, célport, várt válasz előtag)
ENTRIES = {
    18084: ("tcp", "input", 8081, "lo-tcp"),
    18086: ("udp", "input", 9001, "lo-udp"),
    18088: ("tcp", "input", 8090, "any-tcp"),
    18087: ("udp", "input", 9002, "any-udp"),
    18085: ("tcp", "forward", 80, "fwd-tcp"),
    18089: ("udp", "forward", 9000, "fwd-udp"),
}
received: list[bytes] = []


def run(*args: str, check: bool = True, **kw) -> subprocess.CompletedProcess:
    result = subprocess.run(list(args), capture_output=True, text=True, timeout=30, **kw)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {result.stderr.strip()}")
    return result


def ns(pid: int, *args: str, **kw) -> subprocess.CompletedProcess:
    return run("nsenter", "-t", str(pid), "-n", *args, **kw)


def serve() -> None:
    def tcp(addr: str, port: int, tag: str) -> None:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((addr, port))
        srv.listen(8)
        while True:
            conn, peer = srv.accept()
            conn.sendall(f"{tag} peer={peer[0]}\n".encode())
            conn.close()

    def udp(addr: str, port: int, tag: str) -> None:
        # Szándékosan "naiv" szerver (nincs IP_PKTINFO), mint a Java/docker-proxy.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((addr, port))
        while True:
            data, peer = sock.recvfrom(200)
            received.append(data)
            sock.sendto(f"{tag} peer={peer[0]}".encode(), peer)

    for fn, args in (
        (tcp, ("127.0.0.1", 8081, "lo-tcp")), (udp, ("127.0.0.1", 9001, "lo-udp")),
        (tcp, ("0.0.0.0", 8090, "any-tcp")), (udp, ("0.0.0.0", 9002, "any-udp")),
    ):
        threading.Thread(target=fn, args=args, daemon=True).start()
    time.sleep(0.3)


def spoof_frame(pid: int, gw_mac: str, payload: bytes) -> None:
    """Nyers Ethernet-keret a LAN kliensből: 192.168.10.2 -> 127.0.0.1:9001 UDP."""
    code = r'''
import socket, struct, sys
gw_mac, payload = bytes.fromhex(sys.argv[1].replace(":", "")), sys.argv[2].encode()
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind(("c0", 0))
src_mac = s.getsockname()[4]
udp = struct.pack("!HHHH", 40000, 9001, 8 + len(payload), 0) + payload
hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                  socket.inet_aton("192.168.10.2"), socket.inet_aton("127.0.0.1"))
csum = sum(struct.unpack("!10H", hdr)); csum = (csum & 0xFFFF) + (csum >> 16)
hdr = hdr[:10] + struct.pack("!H", ~csum & 0xFFFF) + hdr[12:]
s.send(gw_mac + src_mac + b"\x08\x00" + hdr + udp)
'''
    ns(pid, sys.executable, "-c", code, gw_mac, payload.decode())


def step(text: str) -> None:
    print(f"[netns] {text}", file=sys.stderr, flush=True)


def main() -> int:
    children: list[subprocess.Popen] = []
    try:
        return _main(children)
    finally:
        for child in children:
            child.kill()


def _main(spawned: list) -> int:
    import gateway
    import test_port_proxy as tpp

    run("ip", "link", "set", "lo", "up")
    children: dict[str, subprocess.Popen] = {}
    for name, (gw_if, addr, gw_addr) in NETS.items():
        child = subprocess.Popen(["unshare", "-n", "sleep", "600"],
                                 stdout=subprocess.DEVNULL)
        children[name] = child
        spawned.append(child)
        time.sleep(0.1)
        run("ip", "link", "add", gw_if, "type", "veth", "peer", "name", "c0",
            "netns", str(child.pid))
        run("ip", "addr", "add", GW[gw_if], "dev", gw_if)
        run("ip", "link", "set", gw_if, "up")
        for cmd in (("ip", "link", "set", "lo", "up"),
                    ("ip", "addr", "add", addr, "dev", "c0"),
                    ("ip", "link", "set", "c0", "up"),
                    ("ip", "route", "add", "default", "via", gw_addr)):
            ns(child.pid, *cmd)
    pids = {name: child.pid for name, child in children.items()}
    target = subprocess.Popen(["nsenter", "-t", str(pids["tgt"]), "-n",
                               sys.executable, "-c", TARGET],
                              stdout=subprocess.DEVNULL)
    spawned.append(target)
    step("névterek kész")
    serve()
    for key in ("ip_forward", "conf/all/route_localnet"):
        Path(f"/proc/sys/net/ipv4/{key}").write_text("1\n")

    fw = gateway.Firewall(
        dry_run=False, logger=lambda *_: None, lan_if="eth1", wan_if="eth0",
        lan_network=gateway._parse_lan_network("192.168.10.0/24"),
    )
    entries = [
        {"id": str(port), "label": str(port), "proto": proto, "type": kind,
         "listen_port": port, "target_ip": "172.19.0.2" if kind == "forward" else "",
         "target_port": tport, "ifaces": "both", "snat": False, "enabled": True}
        for port, (proto, kind, tport, _) in ENTRIES.items()
    ]
    template = tpp.render_template()
    run("nft", "-f", "-", input=template)
    step("sablon betöltve")
    fw.replace_custom(port_proxies=entries)
    step("port proxy szabályok betöltve")
    nat_rules = run("nft", "list", "chain", *T.split(), "portproxy_nat").stdout

    time.sleep(1.0)  # IPv6 DAD / ARP rendeződése
    lan_mac = json.loads(ns(pids["lan"], "ip", "-j", "link", "show", "c0").stdout)[0]["address"]
    gw_lan_mac = json.loads(run("ip", "-j", "link", "show", "eth1").stdout)[0]["address"]
    checks: dict[str, object] = {"nat_rules": nat_rules.strip().splitlines()}
    ok = True

    def probe(client: str, port: int) -> str:
        proto = ENTRIES[port][0]
        host = NETS[client][2]
        return ns(pids[client], sys.executable, "-c", CLIENT, proto, host,
                  str(port)).stdout.strip()

    def grant(op: str, client: str) -> None:
        ip = NETS[client][1].split("/")[0]
        for port, (proto, kind, _, _) in ENTRIES.items():
            set_name = f"allowed_input_{proto}" if kind == "input" else f"allowed_{proto}"
            run("nft", op, "element", *T.split(), set_name, "{", f"{ip} . {port}", "}")
        if client == "lan":
            run("nft", op, "element", *T.split(), "client_mac", "{",
                f"{ip} . {lan_mac}", "}")

    def expect(label: str, condition: bool, detail) -> None:
        nonlocal ok
        checks[label] = {"ok": condition, "detail": detail}
        ok = ok and condition

    for client in ("wan", "lan"):
        ip = NETS[client][1].split("/")[0]
        step(f"{client} kliens")
        before = {port: probe(client, port) for port in ENTRIES}
        expect(f"{client}_blocked_before_grant",
               all(v.startswith("ERR") for v in before.values()), before)
        grant("add", client)
        after = {port: probe(client, port) for port in ENTRIES}
        expect(f"{client}_works_after_grant_with_client_ip", all(
            after[port] == f"{tag} peer={ip}"
            for port, (_, _, _, tag) in ENTRIES.items()
        ), after)
        grant("delete", client)
        revoked = {port: probe(client, port) for port in ENTRIES}
        expect(f"{client}_blocked_after_revoke",
               all(v.startswith("ERR") for v in revoked.values()), revoked)

    expect("loopback_targets_use_dnat", "dnat ip to 127.0.0.1:8081" in nat_rules
           and "dnat ip to 127.0.0.1:9001" in nat_rules
           and "redirect to :8090" in nat_rules and "redirect to :9002" in nat_rules,
           "lásd nat_rules")

    # Az élő hiba reprodukciója: redirect (route_localnet nélküli ág) esetén a
    # csak loopbacken figyelő cél nem érhető el, a wildcard igen.
    Path("/proc/sys/net/ipv4/conf/all/route_localnet").write_text("0\n")
    fw.replace_custom(port_proxies=entries)
    grant("add", "wan")
    old = {port: probe("wan", port) for port in (18084, 18086, 18088, 18087)}
    grant("delete", "wan")
    expect("redirect_misses_loopback_only_target",
           old[18084].startswith("ERR") and old[18086].startswith("ERR")
           and old[18088].startswith("any-tcp") and old[18087].startswith("any-udp"),
           old)
    Path("/proc/sys/net/ipv4/conf/all/route_localnet").write_text("1\n")
    fw.replace_custom(port_proxies=entries)

    # Loopback-őr: a LAN kliens közvetlenül 127.0.0.1:9001-re küld (nyers
    # keret), host engedéllyel a 9001-re. Őr nélkül ez eljutna a szerverhez.
    lan_ip = NETS["lan"][1].split("/")[0]
    run("nft", "add", "element", *T.split(), "allowed_input_udp", "{", f"{lan_ip} . 9001", "}")
    run("nft", "add", "element", *T.split(), "client_mac", "{", f"{lan_ip} . {lan_mac}", "}")
    spoof_frame(pids["lan"], gw_lan_mac, b"spoof-guarded")
    run("nft", "flush", "chain", *T.split(), "loopback_guard")
    spoof_frame(pids["lan"], gw_lan_mac, b"spoof-unguarded")
    time.sleep(0.5)
    expect("loopback_guard_drops_spoofed_127",
           b"spoof-guarded" not in received and b"spoof-unguarded" in received,
           [r.decode() for r in received if r.startswith(b"spoof")])

    print(json.dumps({"ok": ok, "checks": checks}, indent=1, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
