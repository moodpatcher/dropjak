#!/usr/bin/env python3
"""Port proxy élő végponttól végpontig teszt a VM-en (rootként, a hostról).

A hvclient névtér (192.168.10.2, LAN) egy ideiglenes felhasználóval lép be.
Ideiglenes port proxy bejegyzések, a felhasználó meglévő bejegyzéseit
megtartva (olvasás-módosítás-írás):
  TCP 18084 -> Input 8081   (a teszt1 nginx, Docker csak 127.0.0.1:8081)
  TCP 18085 -> Forward a teszt2 konténer híd-IP-jére, :80
  UDP 18086 -> Input 19086  (ideiglenes UDP echo, csak 127.0.0.1)
Ellenőrzés: belépés előtt tiltva; engedélyezés után a tartalom egyezik, a
UDP echo válaszol, a cél a kliens IP-jét látja; kilépés után tiltva. A
végén minden ideiglenes elem törlődik, és a takarítás is ellenőrzött.

Futtatás:  python3 tests/portproxy_e2e_vm.py   (a /root/hatarvedelem-ből)
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_vm as e2e  # noqa: E402

ADMIN = "pp-e2e-admin"
USER = "pp-e2e-user"
RULES = ("pp-e2e-in", "pp-e2e-fwd")
LABEL = "pp-e2e-"
COOKIE = "/root/pp_e2e_cookies.txt"
GW = "192.168.10.1"
UDP_TARGET = 19086
ECHO = (
    "import socket\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    f"s.bind(('127.0.0.1', {UDP_TARGET}))\n"
    "while True:\n"
    "    d, a = s.recvfrom(512)\n"
    "    s.sendto(b'echo peer=' + a[0].encode() + b' ' + d, a)\n"
)
UDP_PROBE = (
    "import socket, sys\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)\n"
    "s.connect((sys.argv[1], int(sys.argv[2]))); s.send(b'ping')\n"
    "try:\n    print(s.recv(512).decode())\n"
    "except Exception as exc:\n    print('ERR ' + type(exc).__name__)\n"
)


def sh(*args: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=60, **kw)


def tcp_probe(port: int) -> str:
    r = sh("ip", "netns", "exec", "hvclient", "curl", "-s", "--max-time", "4",
           f"http://{GW}:{port}/")
    return r.stdout if r.returncode == 0 else f"ERR curl={r.returncode}"


def udp_probe(port: int) -> str:
    return sh("ip", "netns", "exec", "hvclient", "python3", "-c", UDP_PROBE,
              GW, str(port)).stdout.strip()


def nat_chain() -> str:
    return sh("nft", "list", "chain", "inet", "hatarvedelem", "portproxy_nat").stdout


def proxies() -> list[dict]:
    data = e2e.admin_json("/api/admin/settings")
    return list((data.get("settings") or {}).get("port_proxies") or [])


def save_proxies(entries: list[dict]) -> dict:
    return e2e.admin_json("/api/admin/settings", {
        "action": "port_proxies", "port_proxies": entries,
    })


def main() -> int:
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"== port proxy e2e {started} ==", flush=True)
    print("route_localnet(all) =",
          open("/proc/sys/net/ipv4/conf/all/route_localnet").read().strip())
    teszt2_ip = sh("docker", "inspect", "-f",
                   "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                   "nginx-teszt-teszt2-1").stdout.strip()
    page1 = sh("curl", "-s", "--max-time", "4", "http://127.0.0.1:8081/").stdout
    page2 = sh("curl", "-s", "--max-time", "4", "http://127.0.0.1:8082/").stdout
    e2e.check("teszt1/teszt2 oldalak elérhetők a hostról", bool(page1 and page2))
    e2e.check("teszt2 konténer IP ismert", bool(teszt2_ip), teszt2_ip)
    original: list[dict] | None = None
    echo = None
    try:
        e2e.fail2ban_cli("unban", e2e.CLIENT_IP)
        admin_pw = secrets.token_urlsafe(18)
        e2e.user_cli("del", ADMIN)
        made = e2e.user_cli("add", ADMIN, "--role", "admin", "--no-must-change",
                            "--password-stdin", stdin=admin_pw + "\n")
        e2e.check("ideiglenes admin létrehozva", made.returncode == 0,
                  (made.stderr or made.stdout).strip()[-200:])
        e2e.USER = ADMIN
        e2e.ADMIN_COOKIE = "/root/pp_e2e_admin_cookies.txt"
        if not e2e.ensure_admin(admin_pw):
            e2e.check("admin belépés loopbackról", False)
            return 1
        for rule_id, direction, ports in (
            ("pp-e2e-in", "input", {"tcp": [18084], "udp": [18086]}),
            ("pp-e2e-fwd", "forward", {"tcp": [18085]}),
        ):
            ok, detail = e2e.ensure_rule(rule_id, {
                "label": rule_id, "direction": direction, **ports,
                "default_ttl": 3600, "max_ttl": 3600,
            })
            e2e.check(f"szabály {rule_id}", ok, detail)
        user_pw = secrets.token_urlsafe(18)
        ok, detail = e2e.ensure_temp_user(USER, user_pw, rules=list(RULES))
        e2e.check("ideiglenes felhasználó", ok, detail)

        echo = subprocess.Popen(["python3", "-c", ECHO])
        time.sleep(0.5)
        original = proxies()
        user_entries = [p for p in original if not str(p.get("label", "")).startswith(LABEL)]
        temp = [
            {"id": "ppe2e84", "label": LABEL + "tcp-input", "proto": "tcp",
             "type": "input", "listen_port": 18084, "target_ip": "",
             "target_port": 8081, "ifaces": "both", "snat": False, "enabled": True},
            {"id": "ppe2e85", "label": LABEL + "tcp-forward", "proto": "tcp",
             "type": "forward", "listen_port": 18085, "target_ip": teszt2_ip,
             "target_port": 80, "ifaces": "both", "snat": False, "enabled": True},
            {"id": "ppe2e86", "label": LABEL + "udp-input", "proto": "udp",
             "type": "input", "listen_port": 18086, "target_ip": "",
             "target_port": UDP_TARGET, "ifaces": "both", "snat": False, "enabled": True},
        ]
        saved = save_proxies(user_entries + temp)
        e2e.check("ideiglenes proxy bejegyzések mentve", bool(saved.get("ok")),
                  str(saved.get("error", ""))[:200])
        print("    figyelmeztetések:", json.dumps(saved.get("port_proxy_warnings")))
        after_save = proxies()
        e2e.check("a felhasználó bejegyzései megmaradtak",
                  all(p in after_save for p in user_entries), json.dumps(user_entries))
        nat = nat_chain()
        print(nat)
        e2e.check("nft: 18084 -> dnat 127.0.0.1:8081", "dport 18084 dnat ip to 127.0.0.1:8081" in nat)
        e2e.check(f"nft: 18086 -> dnat 127.0.0.1:{UDP_TARGET}",
                  f"dport 18086 dnat ip to 127.0.0.1:{UDP_TARGET}" in nat)
        e2e.check("nft: 18085 -> dnat teszt2:80", f"dport 18085 dnat ip to {teszt2_ip}:80" in nat)

        before = {"tcp-in": tcp_probe(18084), "tcp-fwd": tcp_probe(18085),
                  "udp-in": udp_probe(18086)}
        e2e.check("belépés előtt minden tiltva",
                  all(v.startswith("ERR") for v in before.values()), json.dumps(before))

        e2e.client_login(USER, user_pw, COOKIE, "pp-e2e")
        access = e2e.client_json("access", ",".join(RULES), "3600", cookie=COOKIE)
        e2e.check("engedélyezés (pp-e2e-in + pp-e2e-fwd)",
                  bool(access.get("ok")) and bool(access.get("body", {}).get("authorized")),
                  json.dumps(access.get("body"))[:300])
        time.sleep(1)
        got1, got2, gotu = tcp_probe(18084), tcp_probe(18085), udp_probe(18086)
        e2e.check("TCP input 18084 = teszt1 oldal", got1 == page1, got1[:120])
        e2e.check("TCP forward 18085 = teszt2 oldal", got2 == page2, got2[:120])
        e2e.check("UDP input 18086 echo, kliens IP látszik",
                  gotu == f"echo peer={e2e.CLIENT_IP} ping", gotu)
        logs2 = sh("docker", "logs", "--since", started, "nginx-teszt-teszt2-1")
        e2e.check("teszt2 nginx a kliens IP-t látja (forward)",
                  e2e.CLIENT_IP in logs2.stdout + logs2.stderr,
                  (logs2.stdout + logs2.stderr).strip().splitlines()[-1:].__str__()[:200])
        logs1 = sh("docker", "logs", "--since", started, "nginx-teszt-teszt1-1")
        print("    teszt1 napló (input, docker-proxy-n át):",
              (logs1.stdout + logs1.stderr).strip().splitlines()[-1:])

        out = e2e.client_json("logout", cookie=COOKIE)
        e2e.check("kilépés", bool(out.get("ok")))
        time.sleep(1)
        after = {"tcp-in": tcp_probe(18084), "tcp-fwd": tcp_probe(18085),
                 "udp-in": udp_probe(18086)}
        e2e.check("kilépés után minden tiltva",
                  all(v.startswith("ERR") for v in after.values()), json.dumps(after))
    finally:
        print("== takarítás ==", flush=True)
        if e2e._admin_portal is not None:
            current = proxies()
            if any(str(p.get("label", "")).startswith(LABEL) for p in current):
                kept = [p for p in current if not str(p.get("label", "")).startswith(LABEL)]
                saved = save_proxies(kept)
                e2e.check("ideiglenes proxy bejegyzések törölve", bool(saved.get("ok")),
                          str(saved.get("error", ""))[:200])
            e2e.admin_post("/api/admin/users", {"action": "delete", "name": USER})
            for rule_id in RULES:
                e2e.admin_post("/api/admin/rules", {"action": "delete", "id": rule_id})
            final = proxies()
            e2e.check("proxy lista: nincs ideiglenes elem",
                      not any(str(p.get("label", "")).startswith(LABEL) for p in final))
            if original is not None:
                e2e.check("proxy lista = az eredeti felhasználói lista",
                          final == [p for p in original
                                    if not str(p.get("label", "")).startswith(LABEL)],
                          json.dumps(final))
            state = e2e.admin_json("/api/admin/state")
            e2e.check("szabályok: nincs pp-e2e", state.get("_code") == 200 and not any(
                str(rule.get("id", "")).startswith("pp-e2e")
                for rule in state.get("rules", []) if isinstance(rule, dict)
            ))
        if echo is not None:
            echo.kill()
        e2e.user_cli("del", USER)
        e2e.user_cli("del", ADMIN)
        users = e2e.user_cli("list").stdout
        e2e.check("felhasználók: nincs pp-e2e", "pp-e2e" not in users)
        nat = nat_chain()
        e2e.check("nft: nincs 1808x szabály", "1808" not in nat)
        table = sh("nft", "list", "table", "inet", "hatarvedelem").stdout
        e2e.check("nft: nincs 192.168.10.2 engedély",
                  not any(e2e.set_has(table, name, e2e.CLIENT_IP) for name in e2e.GRANT_SETS))
        e2e.fail2ban_cli("unban", e2e.CLIENT_IP)
        for path in (COOKIE, "/root/pp_e2e_admin_cookies.txt"):
            if os.path.exists(path):
                os.remove(path)
        print("== a felhasználó 8084-es bejegyzése ==")
        print("\n".join(line.strip() for line in nat.splitlines() if "8084" in line))
        e2e.check("8084: dnat 127.0.0.1:8081 (nem redirect)",
                  "dport 8084 dnat ip to 127.0.0.1:8081" in nat)
    print(f"== eredmény: {e2e.passed} PASS, {len(e2e.failures)} FAIL ==")
    for title in e2e.failures:
        print(f"   FAIL: {title}")
    return 0 if not e2e.failures else 1


if __name__ == "__main__":
    sys.exit(main())
