#!/usr/bin/env python3
"""Dropjak végponttól végpontig teszt a teszt-VM-en.

A hoston futó mód létrehozza az ideiglenes felhasználót, majd a hvclient
hálózati névtérből hajtja végre a kliens-lépéseket. A tűzfalhalmazokat a
host névterében ellenőrzi. A szkript a végén törli a felhasználót.

Feltételek: root jogosultság, a projekt /root/hatarvedelem alatt, valamint
a hv-lan veth pár és a hvclient névtér (192.168.10.2) létezése.

Futtatás a VM-en:
    python3 tests/e2e_vm.py
"""

from __future__ import annotations

import hashlib
import http.cookiejar
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import gateway  # noqa: E402

BASE = "http://192.168.10.1:8100"
COOKIE = "/root/e2e_cookies.txt"
USER = os.environ.get("E2E_USER", "claudetest")
PASS_ENV = "E2E_PASS"
NEW_PASS_ENV = "E2E_NEW_PASS"
NFT_SETS = ("allowed_v4", "allowed_tcp", "allowed_udp", "allowed_icmp", "host_ssh_v4")
CLIENT_IP = "192.168.10.2"

failures: list[str] = []


# ------------------------------------------------------------------ kliens mód

class Portal:
    def __init__(self) -> None:
        jar = http.cookiejar.MozillaCookieJar(COOKIE)
        if os.path.exists(COOKIE):
            try:
                jar.load(ignore_discard=True, ignore_expires=True)
            except Exception:
                pass
        self.jar = jar
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar)
        )

    def request(self, path: str, payload: dict | None = None) -> tuple[int, str]:
        headers: dict[str, str] = {}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
            headers["Origin"] = BASE
        req = urllib.request.Request(
            BASE + path, data=body, headers=headers,
            method="POST" if body is not None else "GET",
        )
        try:
            with self.opener.open(req, timeout=10) as resp:
                code, text = resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            code, text = exc.code, exc.read().decode("utf-8", "replace")
        self.jar.save(ignore_discard=True, ignore_expires=True)
        return code, text


def solve_pow(challenge: dict) -> dict:
    prefix = "0" * int(challenge["difficulty"])
    number = 0
    while True:
        digest = hashlib.sha256(
            f"{challenge['salt']}{number}".encode()
        ).hexdigest()
        if digest.startswith(prefix):
            break
        number += 1
    captcha = {
        key: challenge[key]
        for key in ("challenge", "salt", "algorithm", "difficulty", "expires", "signature")
    }
    captcha["number"] = number
    return captcha


def safe_json(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return text[:300]


def cmd_login() -> int:
    portal = Portal()
    code, text = portal.request("/api/challenge")
    if code != 200:
        print(json.dumps({"ok": False, "step": "challenge", "code": code, "body": safe_json(text)}))
        return 1
    captcha = solve_pow(json.loads(text))
    password = os.environ.get(PASS_ENV, "")
    code, text = portal.request(
        "/api/login", {"user": USER, "pass": password, "captcha": captcha}
    )
    data = safe_json(text)
    print(json.dumps({"ok": code == 200, "code": code, "body": data}))
    return 0 if code == 200 and isinstance(data, dict) and data.get("authenticated") else 1


def cmd_password() -> int:
    portal = Portal()
    current = os.environ.get(PASS_ENV, "")
    new = os.environ.get(NEW_PASS_ENV, "")
    code, text = portal.request(
        "/api/password", {"current": current, "new": new}
    )
    data = safe_json(text)
    print(json.dumps({"ok": code == 200, "code": code, "body": data}))
    return 0 if code == 200 else 1


def cmd_access(rule: str, ttl: str) -> int:
    portal = Portal()
    code, text = portal.request(
        "/api/access", {"rule": rule, "ttl": int(ttl)}
    )
    data = safe_json(text)
    print(json.dumps({"ok": code == 200, "code": code, "body": data}))
    return 0 if code == 200 else 1


def cmd_logout() -> int:
    portal = Portal()
    code, text = portal.request("/api/logout", {})
    print(json.dumps({"ok": code == 200, "code": code, "body": safe_json(text)}))
    return 0 if code == 200 else 1


def cmd_status() -> int:
    portal = Portal()
    code, text = portal.request("/api/status")
    print(json.dumps({"code": code, "body": safe_json(text)}))
    return 0 if code == 200 else 1


def curl(url: str, extra: tuple[str, ...] = ()) -> tuple[str, str]:
    proc = subprocess.run(
        ["curl", "-sS", "-m", "8", "-o", "-", "-w", "\n__CODE__%{http_code}", *extra, url],
        capture_output=True, text=True,
    )
    body = proc.stdout
    code = "000"
    if "\n__CODE__" in body:
        body, code = body.rsplit("\n__CODE__", 1)
    return code.strip(), body


def dns_works() -> bool:
    tid = secrets.randbelow(65535) + 1
    query = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for label in "example.com".split("."):
        query += bytes([len(label)]) + label.encode()
    query += b"\x00" + struct.pack("!HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(query, ("1.1.1.1", 53))
        data, _ = sock.recvfrom(512)
        return len(data) > 12 and data[:2] == struct.pack("!H", tid)
    except OSError:
        return False
    finally:
        sock.close()


def ping_works() -> bool:
    proc = subprocess.run(
        ["ping", "-c", "1", "-W", "2", "1.1.1.1"],
        capture_output=True, text=True,
    )
    return proc.returncode == 0


def host_ssh_works() -> bool:
    """A host SSH portja elérhető-e a kliens névtérből."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect(("192.168.10.1", 22))
        return sock.recv(64).startswith(b"SSH-")
    except OSError:
        return False
    finally:
        sock.close()


def cmd_check() -> int:
    http_code, http_body = curl("http://1.1.1.1/")
    https_code, _ = curl("https://1.1.1.1/", ("-k",))
    portal_page = "Dropjak" in http_body
    result = {
        "http_code": http_code,
        "http_portal": portal_page,
        "http_external": http_code in ("200", "301", "302") and not portal_page,
        "https": https_code in ("200", "301", "302"),
        "https_code": https_code,
        "dns": dns_works(),
        "ping": ping_works(),
        "host_ssh": host_ssh_works(),
    }
    print(json.dumps(result))
    return 0


def client_main(argv: list[str]) -> int:
    if argv[0] == "login":
        return cmd_login()
    if argv[0] == "password":
        return cmd_password()
    if argv[0] == "access":
        return cmd_access(argv[1], argv[2])
    if argv[0] == "logout":
        return cmd_logout()
    if argv[0] == "status":
        return cmd_status()
    if argv[0] == "check":
        return cmd_check()
    if argv[0] == "page":
        code, body = curl(BASE + "/")
        print(json.dumps({
            "code": code,
            "rules": 'id="rules"' in body,
            "admin_panel": 'id="admin-panel"' in body,
            "ttl": 'id="ttl"' in body,
            "ttl_unit": 'id="ttl-unit"' in body,
            "rules_api": "/api/admin/rules" in body,
            "access_api": "/api/access" in body,
            "password_view": 'id="password-view"' in body,
            "sessions_tab": 'data-admin="sessions"' in body,
            "firewall_tab": 'data-admin="firewall"' in body,
        }))
        return 0
    raise SystemExit(f"ismeretlen kliens-parancs: {argv[0]}")


# ------------------------------------------------------------------- host mód

def run_client(
    *args: str, password: str | None = None, new_password: str | None = None
) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if password is not None:
        env[PASS_ENV] = password
    if new_password is not None:
        env[NEW_PASS_ENV] = new_password
    return subprocess.run(
        ["ip", "netns", "exec", "hvclient", "python3", __file__, "client", *args],
        capture_output=True, text=True, env=env, timeout=120,
    )


def client_json(
    *args: str, password: str | None = None, new_password: str | None = None
) -> dict:
    proc = run_client(*args, password=password, new_password=new_password)
    if proc.returncode not in (0, 1):
        raise RuntimeError(
            f"kliens hiba ({' '.join(args)}): rc={proc.returncode}\n{proc.stderr[-2000:]}"
        )
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise RuntimeError(
            f"nem értelmezhető kimenet ({' '.join(args)}): {proc.stdout[-2000:]}\n{proc.stderr[-1000:]}"
        ) from exc


def check(title: str, cond: bool, detail: str = "") -> None:
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {title}" + (f" — {detail}" if detail else ""), flush=True)
    if not cond:
        failures.append(title)


def snapshot() -> dict:
    proc = subprocess.run(["nft", "list", "table", "inet", "hatarvedelem"],
                          capture_output=True, text=True)
    return {"rc": proc.returncode, "text": proc.stdout, "err": proc.stderr}


def set_has(table_dump: str, set_name: str, needle: str) -> bool:
    marker = f"set {set_name} {{"
    start = table_dump.find(marker)
    if start < 0:
        return False
    end = table_dump.find("\n\t}", start)
    block = table_dump[start:end if end >= 0 else None]
    return needle in block


def set_is_empty(table_dump: str, set_name: str) -> bool:
    return not set_has(table_dump, set_name, CLIENT_IP)


def nft_json_entries(set_name: str) -> list[dict]:
    """A valódi nft -j kimenet feldolgozása a gyártási parserrel."""
    proc = subprocess.run(
        ["nft", "-j", "list", "set", "inet", "hatarvedelem", set_name],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return []
    return gateway.Firewall.parse_set_json(proc.stdout, set_name)


def nft_state(label: str) -> dict:
    snap = snapshot()
    state = {
        "v4": set_has(snap["text"], "allowed_v4", CLIENT_IP),
        "tcp": set_has(snap["text"], "allowed_tcp", CLIENT_IP),
        "udp": set_has(snap["text"], "allowed_udp", CLIENT_IP),
        "icmp": set_has(snap["text"], "allowed_icmp", CLIENT_IP),
        "host_ssh": set_has(snap["text"], "host_ssh_v4", CLIENT_IP),
    }
    print(f"    nft {label}: {json.dumps(state)}", flush=True)
    return state


def user_cli(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "--user", "hatarvedelem", "hatarvedelem",
         "python3", "/opt/hatarvedelem/server.py", "user", *args],
        cwd="/root/hatarvedelem", input=stdin, capture_output=True, text=True,
    )


def main() -> int:
    password = secrets.token_urlsafe(18)
    new_password = password + "-v2"

    user_cli("del", USER)  # esetleges maradék eltakarítása
    created = user_cli("add", USER, "--password-stdin", stdin=password + "\n")
    if created.returncode != 0:
        print(f"HIBA: a tesztfelhasználó létrehozása nem sikerült: {created.stderr.strip()}")
        return 2

    logout_done = False
    try:
        print("== 0. Kiinduló állapot ==", flush=True)
        page = client_json("page")
        check("portál oldal betölt", page.get("code") == "200")
        check("szabályválasztó a felületen", bool(page.get("rules")))
        check("admin panel a felületen", bool(page.get("admin_panel")))
        check("TTL mező a felületen", bool(page.get("ttl")))
        check("óra/perc TTL választó a felületen", bool(page.get("ttl_unit")))
        check("admin szabály API a felületen", bool(page.get("rules_api")))
        check("/api/access hívás a felületen", bool(page.get("access_api")))
        check("jelszócsere nézet a felületen", bool(page.get("password_view")))
        check("munkamenetek fül a felületen", bool(page.get("sessions_tab")))
        check("tűzfal fül a felületen", bool(page.get("firewall_tab")))
        login = client_json("login", password=password)
        check("login: helyes jelszóval van munkamenet", bool(login.get("ok")))
        check("login: még nincs hálózati engedély", not login.get("body", {}).get("authorized"))
        check("login: várakozó állapot (pending)", bool(login.get("body", {}).get("pending")))
        check("login: első belépésnél kötelező jelszócsere",
              login.get("body", {}).get("must_change_password") is True)
        rule_ids = [rule.get("id") for rule in login.get("body", {}).get("rules", [])]
        check("login: a felhasználó szabályai megvannak", "browse" in rule_ids and "full" in rule_ids,
              json.dumps(rule_ids))

        before_change = client_json("access", "browse", "60")
        check("jelszócsere előtt: hozzáférés elutasítva (403)",
              before_change.get("code") == 403, json.dumps(before_change.get("body")))
        changed = client_json(
            "password", password=password, new_password=new_password
        )
        check("jelszócsere: 200", bool(changed.get("ok")), json.dumps(changed.get("body")))
        check("jelszócsere: a kötelező csere flag eltűnt",
              changed.get("body", {}).get("must_change_password") is False)

        status = client_json("status")
        check("status: pending=True", bool(status.get("body", {}).get("pending")))
        check("status: authorized=False", not status.get("body", {}).get("authorized"))
        check("status: szabályok és limitek megvannak",
              "rules" in status.get("body", {}) and "limits" in status.get("body", {}))
        limits = status.get("body", {}).get("limits", {})
        check("limitek: 60–86400 másodperc",
              limits.get("min_ttl") == 60 and limits.get("max_ttl") == 86400,
              json.dumps(limits))

        blocked = client_json("check")
        check("bejelentkezés előtt: HTTP a portálra terelve",
              blocked.get("http_portal") is True, json.dumps(blocked))
        check("bejelentkezés előtt: HTTPS tiltva", blocked.get("https") is False)
        check("bejelentkezés előtt: DNS tiltva", blocked.get("dns") is False)
        check("bejelentkezés előtt: ping tiltva", blocked.get("ping") is False)
        check("bejelentkezés előtt: host SSH tiltva", blocked.get("host_ssh") is False)
        state = nft_state("bejelentkezés előtt")
        check("nft: host SSH halmaz üres", not state["host_ssh"])

        print("== 1. Böngészés szabály 60 másodpercre ==", flush=True)
        access = client_json("access", "browse", "60")
        check("access browse: 200", bool(access.get("ok")), json.dumps(access.get("body")))
        check("access browse: engedélyezve", bool(access.get("body", {}).get("authorized")))
        check("access browse: a szabály neve megvan",
              access.get("body", {}).get("rule") == "browse")
        grant = access.get("body", {}).get("grant", {})
        check("access browse: a portengedély megvan",
              isinstance(grant.get("tcp"), list) and bool(grant.get("tcp")),
              json.dumps(grant))
        check("access browse: nincs teljes hozzáférés",
              grant.get("full") is False, json.dumps(grant))
        web = client_json("check")
        check("browse: HTTP kimegy, nem a portál", web.get("http_external") is True, json.dumps(web))
        check("browse: HTTPS kimegy", web.get("https") is True)
        check("browse: DNS engedélyezett", web.get("dns") is True, json.dumps(web))
        check("browse: ping nem engedélyezett", web.get("ping") is False)
        check("browse: host SSH megnyílt", web.get("host_ssh") is True, json.dumps(web))
        state = nft_state("browse után")
        check("nft: allowed_tcp tartalmazza a klienst", state["tcp"])
        check("nft: allowed_udp tartalmazza a klienst", state["udp"])
        check("nft: allowed_v4 nem tartalmazza a klienst", not state["v4"])
        check("nft: allowed_icmp nem tartalmazza a klienst", not state["icmp"])
        check("nft: host SSH halmaz tartalmazza a klienst", state["host_ssh"])
        tcp_entries = nft_json_entries("allowed_tcp")
        client_ports = {
            entry["port"] for entry in tcp_entries
            if entry.get("address") == CLIENT_IP
        }
        check("nft JSON: a kliens TCP-portjai olvashatók",
              bool(client_ports), json.dumps(sorted(client_ports)))
        check("nft JSON: a hátralévő idő is olvasható",
              all(
                  isinstance(entry.get("expires_in"), int)
                  for entry in tcp_entries
                  if entry.get("address") == CLIENT_IP
              ),
              json.dumps(tcp_entries))
        ssh_entries = nft_json_entries("host_ssh_v4")
        check("nft JSON: a host SSH engedély olvasható",
              any(entry.get("address") == CLIENT_IP for entry in ssh_entries))

        print("== 2. TTL-határok ==", flush=True)
        low = client_json("access", "browse", "59")
        check("TTL 59 elutasítva (400)", low.get("code") == 400, json.dumps(low.get("body")))
        high = client_json("access", "browse", "86401")
        check("TTL 86401 elutasítva (400)", high.get("code") == 400, json.dumps(high.get("body")))
        no_rule = client_json("access", "nincs-ilyen", "60")
        check("ismeretlen szabály elutasítva (400)", no_rule.get("code") == 400)
        still_web = client_json("check")
        check("elutasított kérés nem vonta vissza a hozzáférést",
              still_web.get("http_external") is True and still_web.get("https") is True)
        min_ok = client_json("access", "browse", "60")
        check("TTL 60 elfogadva", bool(min_ok.get("ok")), json.dumps(min_ok.get("body")))

        print("== 3. Módosítás teljes hozzáférésre ==", flush=True)
        access = client_json("access", "full", "60")
        check("access full: 200", bool(access.get("ok")), json.dumps(access.get("body")))
        check("access full: teljes hozzáférés a grantben",
              access.get("body", {}).get("grant", {}).get("full") is True,
              json.dumps(access.get("body", {}).get("grant")))
        full = client_json("check")
        check("full: HTTP kimegy", full.get("http_external") is True, json.dumps(full))
        check("full: HTTPS kimegy", full.get("https") is True)
        check("full: DNS kimegy", full.get("dns") is True)
        check("full: ping kimegy", full.get("ping") is True)
        check("full: host SSH megnyílt", full.get("host_ssh") is True)
        snap = snapshot()["text"]
        check("nft: allowed_v4 tartalmazza a klienst", set_has(snap, "allowed_v4", CLIENT_IP))
        # A teljes hozzáférésű szabály az allowed_v4-en keresztül ICMP-t is
        # enged; külön allowed_icmp elem csak akkor jön létre, ha a szabály
        # kifejezetten az icmp szolgáltatást is tartalmazza.
        check(
            "nft: ICMP engedélyezve (allowed_v4 vagy allowed_icmp)",
            set_has(snap, "allowed_v4", CLIENT_IP)
            or set_has(snap, "allowed_icmp", CLIENT_IP),
        )

        print("== 4. Visszaváltás böngészésre ==", flush=True)
        access = client_json("access", "browse", "60")
        check("access browse újra: 200", bool(access.get("ok")), json.dumps(access.get("body")))
        back = client_json("check")
        check("browse: ping visszavonva", back.get("ping") is False, json.dumps(back))
        check("browse: HTTP továbbra is kimegy", back.get("http_external") is True)
        check("browse: DNS továbbra is működik", back.get("dns") is True)
        snap = snapshot()["text"]
        check("nft: allowed_v4 kiürült", not set_has(snap, "allowed_v4", CLIENT_IP))
        check("nft: allowed_icmp kiürült", not set_has(snap, "allowed_icmp", CLIENT_IP))

        print("== 5. Kilépés ==", flush=True)
        out = client_json("logout")
        logout_done = True
        check("logout: 200", bool(out.get("ok")), json.dumps(out.get("body")))
        after = client_json("check")
        check("logout: HTTP a portálra terelve", after.get("http_portal") is True, json.dumps(after))
        check("logout: HTTPS tiltva", after.get("https") is False)
        check("logout: DNS tiltva", after.get("dns") is False)
        check("logout: ping tiltva", after.get("ping") is False)
        check("logout: host SSH tiltva", after.get("host_ssh") is False, json.dumps(after))
        state = nft_state("logout után")
        check("logout: minden halmaz üres", not any(state.values()), json.dumps(state))

        print("== 6. Természetes lejárat ==", flush=True)
        login = client_json("login", password=new_password)
        check("lejárat: új belépés", bool(login.get("ok")))
        access = client_json("access", "browse", "60")
        check("lejárat: böngészés engedélyezve 60 másodpercre", bool(access.get("ok")),
              json.dumps(access.get("body", {}).get("error")))
        before = client_json("check")
        check("lejárat előtt: HTTP kimegy", before.get("http_external") is True, json.dumps(before))
        check("lejárat előtt: DNS működik", before.get("dns") is True, json.dumps(before))
        check("lejárat előtt: host SSH működik", before.get("host_ssh") is True, json.dumps(before))
        check("lejárat előtt: ping tiltva", before.get("ping") is False)
        print("    várakozás a lejáratig (65 s)...", flush=True)
        time.sleep(65)
        expired = client_json("check")
        check("lejárat után: DNS tiltva", expired.get("dns") is False, json.dumps(expired))
        check("lejárat után: ping tiltva", expired.get("ping") is False, json.dumps(expired))
        check("lejárat után: host SSH tiltva", expired.get("host_ssh") is False, json.dumps(expired))
        check("lejárat után: HTTPS tiltva", expired.get("https") is False)
        check("lejárat után: HTTP a portálra terelve", expired.get("http_portal") is True)
        state = nft_state("lejárat után")
        check("lejárat után: minden halmaz üres", not any(state.values()), json.dumps(state))
        status = client_json("status")
        check("lejárat után: munkamenet megszűnt",
              not status.get("body", {}).get("authenticated"))
        logout_done = True

        print("== 7. Portál nyilvános elérése ==", flush=True)
        pub = subprocess.run(
            ["curl", "-sS", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", BASE + "/api/challenge"],
            capture_output=True, text=True,
        )
        check("portál a kezelői gépről is elérhető", pub.stdout.strip() == "200", pub.stdout.strip())
    finally:
        if not logout_done:
            run_client("logout")
        user_cli("del", USER)
        for path in (COOKIE,):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    print()
    if failures:
        print(f"SIKERTELEN: {len(failures)} ellenőrzés bukott:", flush=True)
        for item in failures:
            print(f"  - {item}", flush=True)
        return 1
    print("MINDEN ELLENŐRZÉS SIKERES", flush=True)
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "client":
        raise SystemExit(client_main(sys.argv[2:]))
    raise SystemExit(main())
