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
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import gateway  # noqa: E402

BASE = "http://192.168.10.1:8100"
COOKIE = "/root/e2e_cookies.txt"
# A portál egy IP-n egyszerre csak egy munkamenetet tart. Az admin API-t ezért
# a host loopback címéről (127.0.0.1) érjük el, külön sütitárral: így a kliens
# névtér 192.168.10.2-es munkamenete és az admin munkamenet egyszerre élhet.
ADMIN_BASE = os.environ.get("E2E_ADMIN_BASE", "http://127.0.0.1:8100")
ADMIN_COOKIE = os.environ.get("E2E_ADMIN_COOKIE", "/root/e2e_admin_cookies.txt")
SCEN_COOKIE = os.environ.get("E2E_SCEN_COOKIE", "/root/e2e_scenario_cookies.txt")
EXPIRY_COOKIE = os.environ.get("E2E_EXPIRY_COOKIE", "/root/e2e_expiry_cookies.txt")
CLI_COOKIE = os.environ.get("E2E_CLI_COOKIE", "/root/e2e_cli_cookies.txt")
BLOCK_COOKIE = os.environ.get("E2E_BLOCK_COOKIE", "/root/e2e_block_cookies.txt")
MULTI_COOKIE = os.environ.get("E2E_MULTI_COOKIE", "/root/e2e_multi_cookies.txt")
USER = os.environ.get("E2E_USER", "claudetest")
PASS_ENV = "E2E_PASS"
NEW_PASS_ENV = "E2E_NEW_PASS"
NFT_SETS = ("allowed_v4", "allowed_tcp", "allowed_udp", "allowed_icmp",
            "allowed_input_tcp", "allowed_input_udp", "client_mac")
# A klienshez tartozó engedélyhalmazok; a client_mac külön kezelendő, mert
# abban IP . MAC kulcs van, nem IP vagy IP . port.
GRANT_SETS = ("allowed_v4", "allowed_tcp", "allowed_udp", "allowed_icmp",
              "allowed_input_tcp", "allowed_input_udp")
CLIENT_IP = "192.168.10.2"

# A kiterjesztett forgatókönyvek kapcsolói. Alapból minden kapcsoló KI van,
# ezért egy szokásos futás nem indít újraindítást és nem vár lejáratra.
LONG_GATE = "HV_E2E_LONG"
PENDING_GATE = "HV_E2E_PENDING"
RESTART_GATE = "HV_E2E_RESTART"
MULTI_GATE = "HV_E2E_MULTI"
# A K6 saját tesztfelhasználója és alapértelmezett szabálypárja. A pár a
# HV_E2E_RULES változóval felülírható; a felhasználót a forgatókönyv-erőforrások
# hozzák létre, a szabályokat a K6 a belépés előtt rendeli hozzá.
MULTI_USER = "e2e-multi-user"
MULTI_DEFAULT_RULES = ("e2e-rev-fwd", "e2e-rev-host")
try:
    LONG_MAX_WAIT = max(60, int(os.environ.get("E2E_LONG_MAX_WAIT", "900")))
except ValueError:
    LONG_MAX_WAIT = 900

# A forgatókönyvek által létrehozott erőforrások. A takarítás a gyűjtőket a
# tagjaik előtt törli, mert a szabálytár nem engedi a gyűjtőben hivatkozott
# tag törlését. A gyűjtő egyszerre ad forward TCP/UDP, ICMP, teljes (allowed_v4)
# és host (input) engedélyt, ezért egyetlen engedélyezéssel mind a hét
# érintett halmaz ellenőrizhető.
SCENARIO_RULES = (
    "e2e-full-coll",
    "e2e-rev-fwd", "e2e-rev-full", "e2e-rev-host",
)
# A takarításnak a fő folyamat saját szabályait is törölnie kell. A gyűjtőket
# a tagjaik előtt kell törölni.
CLEANUP_RULES = (
    "e2e-combo",
    "e2e-full-coll",
    "host-e2e",
    "e2e-rev-fwd", "e2e-rev-full", "e2e-rev-host",
)
SCENARIO_GROUPS = ("e2e-rev-grp",)
SCENARIO_USERS = (
    "e2e-rev-user", "e2e-rev-del", "e2e-exp-user",
    "e2e-blk-user", "e2e-cli-user", MULTI_USER,
)
BLOCK_LABEL_PREFIX = "e2e-block-"
PREAUTH_LABEL_PREFIX = "e2e-preauth-"
CONNTRACK_BIN = (
    os.environ.get("HV_CONNTRACK_BIN") or shutil.which("conntrack") or ""
)
# A restart-helper állapotfájljai; a main finally a markerrel engedi tovább.
RESTART_MARKER = ""
RESTART_STATE = ""
RESTART_LOG = ""
RESTART_TIMEOUT = 180

# A kiterjesztett forgatókönyvek admin munkamenete a host loopbackjáról.
_admin_portal: Portal | None = None
_admin_password = ""

failures: list[str] = []
passed = 0
skipped: list[str] = []
pending: list[str] = []


# ------------------------------------------------------------------ kliens mód

class Portal:
    def __init__(
        self, base: str = BASE, cookie_path: str | None = None
    ) -> None:
        self.base = base.rstrip("/")
        self.cookie_path = (
            cookie_path
            or os.environ.get("E2E_COOKIE", COOKIE)
        )
        jar = http.cookiejar.MozillaCookieJar(self.cookie_path)
        if os.path.exists(self.cookie_path):
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
            # Az Origin a tényleges Hosttal egyezik (a szerver ezt nézi),
            # ezért a loopback admin kérésnél is a loopback cím kerül ide.
            headers["Origin"] = self.base
        req = urllib.request.Request(
            self.base + path, data=body, headers=headers,
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


def _access_rule_ids(rule) -> list[str]:
    """A szabály-választás rendezett, ismétlődés nélküli azonosítói.

    A ``rule`` lehet vesszővel elválasztott szöveg (a kliens-parancs és a
    régi hívók ezt használják) vagy szabály-azonosítók sorozata. Az eredeti
    sorrend marad meg; az üres elemek kimaradnak.
    """
    raw: list[str] = []
    if isinstance(rule, str):
        raw.extend(rule.split(","))
    else:
        for item in rule:
            if not isinstance(item, str):
                raise TypeError(
                    "a szabály-azonosítóknak szövegeknek kell lenniük"
                )
            raw.extend(item.split(","))
    ids: list[str] = []
    for item in raw:
        value = item.strip()
        if value and value not in ids:
            ids.append(value)
    return ids


def cmd_access(rule: str | Sequence[str], ttl: str) -> int:
    ids = _access_rule_ids(rule)
    # A ``rules`` lista a mérvadó; a ``rule`` a régi szerverek és kliensek
    # kedvéért az első azonosítót tartalmazza. Egy azonosítónál a szerver
    # továbbra is fogadja ezt a régi alakot.
    portal = Portal()
    code, text = portal.request(
        "/api/access",
        {"rules": ids, "rule": ids[0] if ids else "", "ttl": int(ttl)},
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


def cmd_tcp_probe(host: str, port: str, timeout: str) -> int:
    """TCP-kapcsolat eredménye: open / refused / timeout / error.

    A host_ssh_works() csak igaz/hamis értéket ad, ezért a blokk-teszt nem
    tudná megkülönböztetni az eldobást (időtúllépés) az elutasítástól. Ez a
    parancs a kliens névtérben fut, és méri az eltelt időt is.
    """
    started = time.monotonic()
    status = "error"
    detail = ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(max(0.5, float(timeout)))
    try:
        sock.connect((host, int(port)))
        status = "open"
    except (socket.timeout, TimeoutError):
        status = "timeout"
    except ConnectionRefusedError:
        status = "refused"
    except OSError as exc:
        status = "error"
        detail = str(exc)[:120]
    finally:
        sock.close()
    print(json.dumps({
        "status": status,
        "elapsed": round(time.monotonic() - started, 3),
        "detail": detail,
    }))
    return 0


def cmd_tcp_hold(
    host: str, port: str, hold_seconds: str, established_path: str,
    after_path: str, release_path: str, wait_seconds: str,
) -> int:
    """Tartós TLS-kapcsolat a blokk meglévő folyamra gyakorolt hatásához.

    Az első kérés után jelzőfájlt ír (a hívó ekkor telepíti a blokkot),
    majd ugyanazon a kapcsolaton kér a blokk alatt, kiírja az eredményt,
    megvárja a blokk eltávolítását jelző fájlt, és újra kér. Az utolsó
    kérés sikere bizonyítja, hogy a blokk eltávolítása után újraengedélyezés
    nélkül működik a még érvényes engedély.
    """
    result = {
        "established": False,
        "after": "not_started",
        "after_reply": False,
        "recovered": False,
        "recover_status": "not_started",
        "error": "",
    }
    hold = max(1.0, float(hold_seconds))
    wait = max(1.0, float(wait_seconds))
    request = (
        b"HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )
    sock = None
    try:
        sock = socket.create_connection((host, int(port)), timeout=8)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=host)
        sock.settimeout(8)
        sock.sendall(request)
        if not sock.recv(4096):
            raise OSError("a szerver az első kérésre üres választ adott")
        result["established"] = True
        with open(established_path, "w", encoding="utf-8") as fh:
            fh.write("established\n")
        time.sleep(hold)
        # A blokk alatti kérés: a helyi TCP-pufferbe kerül, a hálózaton
        # viszont a blokk eldobja, ezért a válasz elmarad.
        try:
            sock.sendall(request)
            sock.settimeout(wait)
            if sock.recv(4096):
                result["after"] = "reply"
                result["after_reply"] = True
            else:
                result["after"] = "closed"
        except socket.timeout:
            result["after"] = "timeout"
        except OSError as exc:
            result["after"] = "error"
            result["error"] = str(exc)[:160]
        with open(after_path, "w", encoding="utf-8") as fh:
            json.dump({
                "after": result["after"],
                "after_reply": result["after_reply"],
            }, fh)
        # A blokk eltávolítását a hívó markerrel jelzi; a TCP a blokkolt
        # szegmenst addig újraküldi, majd a marker után ugyanazon a
        # kapcsolaton újra kérünk.
        release_deadline = time.monotonic() + max(15.0, wait * 4)
        while time.monotonic() < release_deadline:
            if os.path.exists(release_path):
                break
            time.sleep(0.2)
        try:
            sock.sendall(request)
            sock.settimeout(max(8.0, wait))
            if sock.recv(4096):
                result["recovered"] = True
                result["recover_status"] = "reply"
            else:
                result["recover_status"] = "closed"
        except socket.timeout:
            result["recover_status"] = "timeout"
        except OSError as exc:
            result["recover_status"] = "error"
            result["error"] = (result["error"] + " | " + str(exc))[:240]
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"[:240]
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        print(json.dumps(result), flush=True)
    return 0


def cmd_traffic() -> int:
    """Rövid forgalomgenerálás a conntrack-ellenőrzésekhez.

    A DNS-válasz és a host SSH kapcsolat a kliens forrás-IP-jéhez tartozó
    conntrack-bejegyzést hoz létre. A visszavonás után ezeknek el kell
    tűnniük; a portál saját, 8100-as folyamait a host oldali segéd szűri.
    """
    print(json.dumps({
        "dns": dns_works(),
        "host_ssh": host_ssh_works(),
    }))
    return 0


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


def cmd_admin_seed() -> int:
    """Host SSH és vegyes gyűjtő létrehozása, majd hozzárendelés a tesztuserhez."""
    portal = Portal()
    results = []
    for payload in (
        {
            "action": "create", "id": "host-e2e",
            "label": "E2E host SSH", "direction": "input", "tcp": [22],
            "default_ttl": 300, "max_ttl": 900,
        },
        {
            "action": "create", "id": "e2e-combo",
            "label": "E2E vegyes", "collection": True,
            "members": ["browse", "host-e2e"],
            "default_ttl": 120, "max_ttl": 600,
        },
    ):
        code, text = portal.request("/api/admin/rules", payload)
        data = safe_json(text)
        ok = code == 200 or (
            isinstance(data, dict) and "már létezik" in str(data.get("error", ""))
        )
        results.append({"rule": payload["id"], "code": code, "ok": ok})
    code, text = portal.request("/api/admin/users", {
        "action": "update", "name": USER,
        "rules": ["browse", "full", "host-e2e", "e2e-combo"],
    })
    data = safe_json(text)
    results.append({"user": USER, "code": code, "ok": code == 200})
    print(json.dumps({
        "ok": all(item["ok"] for item in results),
        "results": results,
        "body": data,
    }))
    return 0 if all(item["ok"] for item in results) else 1


def _admin_tolerant(portal: Portal, path: str, payload: dict) -> tuple[bool, str]:
    """Admin művelet, a „már nincs ilyen” hibát sikernek tekintve."""
    try:
        code, text = portal.request(path, payload)
    except Exception as exc:  # a takarítás ne szakadjon meg egy hálózati hibától
        return False, f"{type(exc).__name__}: {exc}"[:200]
    data = safe_json(text)
    message = str(data.get("error", "")) if isinstance(data, dict) else str(data)
    if code == 200:
        return True, ""
    # Csak a már hiányzó erőforrást tekintjük késznek. A „nem törölhető”
    # valódi maradékot jelez (pl. gyűjtőre mutató hivatkozás), azt nem
    # szabad elrejteni.
    if "nincs ilyen" in message:
        return True, ""
    return False, f"code={code} {message[:160]}"


def cmd_admin_cleanup() -> int:
    """A kiterjesztett forgatókönyvek maradékainak eltakarítása.

    Az outer main finally blokkja akkor is meghívja, ha egy forgatókönyv
    félbeszakadt. Minden hiányzó erőforrásra toleráns; csak a valódi hibákat
    jelzi, és a kliens munkamenetét nem érinti.
    """
    portal = Portal()
    problems: list[str] = []

    # 1. Blokk- és pre-auth bejegyzések a jól ismert címke-prefixszel.
    code, text = portal.request("/api/admin/settings")
    data = safe_json(text)
    settings = (
        data.get("settings")
        if code == 200 and isinstance(data, dict) else None
    )
    for kind, prefix in (
        ("block", BLOCK_LABEL_PREFIX),
        ("preauth", PREAUTH_LABEL_PREFIX),
    ):
        entries = []
        if isinstance(settings, dict) and isinstance(settings.get(kind), list):
            entries = [
                entry for entry in settings[kind]
                if isinstance(entry, dict)
                and str(entry.get("label", "")).startswith(prefix)
            ]
        for entry in entries:
            entry_id = entry.get("id")
            if not isinstance(entry_id, str) or not entry_id:
                continue
            ok, detail = _admin_tolerant(portal, "/api/admin/settings", {
                "action": "delete", "kind": kind, "id": entry_id,
            })
            if not ok:
                problems.append(f"{kind} {entry_id}: {detail}")

    # 2. Csoportok (a szabály- és felhasználóhivatkozások előtt).
    for group_id in SCENARIO_GROUPS:
        ok, detail = _admin_tolerant(portal, "/api/admin/groups", {
            "action": "delete", "id": group_id,
        })
        if not ok:
            problems.append(f"group {group_id}: {detail}")

    # 3. Szabályok; a gyűjtők a CLEANUP_RULES elején vannak.
    for rule_id in CLEANUP_RULES:
        ok, detail = _admin_tolerant(portal, "/api/admin/rules", {
            "action": "delete", "id": rule_id,
        })
        if not ok:
            problems.append(f"rule {rule_id}: {detail}")

    # 4. Ideiglenes felhasználók.
    for name in SCENARIO_USERS:
        ok, detail = _admin_tolerant(portal, "/api/admin/users", {
            "action": "delete", "name": name,
        })
        if not ok:
            problems.append(f"user {name}: {detail}")

    # 5. A teszt kliens IP esetleges maradék tiltása ne akadályozza a
    # következő futást. A hiányzó tiltás 404, ami itt rendben van.
    try:
        code, _text = portal.request("/api/admin/fail2ban", {
            "action": "unban", "ip": CLIENT_IP,
        })
        if code not in (200, 404):
            problems.append(f"fail2ban unban: code={code}")
    except Exception as exc:
        problems.append(f"fail2ban unban: {type(exc).__name__}")

    print(json.dumps({"ok": not problems, "failures": problems}))
    return 0 if not problems else 1


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
    if argv[0] == "admin-seed":
        return cmd_admin_seed()
    if argv[0] == "admin-cleanup":
        return cmd_admin_cleanup()
    if argv[0] == "check":
        return cmd_check()
    if argv[0] == "tcp-probe":
        return cmd_tcp_probe(argv[1], argv[2], argv[3])
    if argv[0] == "tcp-hold":
        return cmd_tcp_hold(
            argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]
        )
    if argv[0] == "traffic":
        return cmd_traffic()
    if argv[0] == "page":
        code, body = curl(BASE + "/")
        print(json.dumps({
            "code": code,
            "rules": 'id="rules"' in body,
            "admin_panel": 'id="admin-panel"' in body,
            "ttl": 'id="ttl"' in body,
            "ttl_unit_absent": 'id="ttl-unit"' not in body,
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
    *args: str,
    password: str | None = None,
    new_password: str | None = None,
    cookie: str | None = None,
    user: str | None = None,
) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if password is not None:
        env[PASS_ENV] = password
    if new_password is not None:
        env[NEW_PASS_ENV] = new_password
    if cookie is not None:
        env["E2E_COOKIE"] = cookie
    if user is not None:
        # A kliens login parancsa ezt olvassa; a munkamenet-süti külön van.
        env["E2E_USER"] = user
    return subprocess.run(
        ["ip", "netns", "exec", "hvclient", "python3", __file__, "client", *args],
        capture_output=True, text=True, env=env, timeout=120,
    )


def client_json(
    *args: str,
    password: str | None = None,
    new_password: str | None = None,
    cookie: str | None = None,
    user: str | None = None,
) -> dict:
    proc = run_client(
        *args, password=password, new_password=new_password,
        cookie=cookie, user=user,
    )
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
    global passed
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {title}" + (f" — {detail}" if detail else ""), flush=True)
    if cond:
        passed += 1
    else:
        failures.append(title)


def skip(title: str, detail: str = "") -> None:
    """Kihagyott ellenőrzés; nem számít hibának és nem növeli a PASS-t."""
    print(f"[SKIP] {title}" + (f" — {detail}" if detail else ""), flush=True)
    skipped.append(title)


def pending_skip(title: str, gate: str, detail: str = "") -> None:
    """Kapcsolóval védett, még nem stabil forgatókönyv kihagyása."""
    reason = f"{gate} nincs bekapcsolva"
    if detail:
        reason += f"; {detail}"
    print(f"[SKIP] {title} — {reason}", flush=True)
    pending.append(title)


def gate_on(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


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


def client_mac() -> str:
    """A hvclient MAC-címe a host ARP-táblájából (a portál is innen olvas)."""
    proc = subprocess.run(
        ["ip", "neigh", "show", CLIENT_IP], capture_output=True, text=True,
    )
    for token in proc.stdout.split():
        if token.count(":") == 5:
            return token.lower()
    return ""


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
    input_tcp = [
        entry for entry in nft_json_entries("allowed_input_tcp")
        if entry.get("address") == CLIENT_IP
    ]
    state = {
        "v4": set_has(snap["text"], "allowed_v4", CLIENT_IP),
        "tcp": set_has(snap["text"], "allowed_tcp", CLIENT_IP),
        "udp": set_has(snap["text"], "allowed_udp", CLIENT_IP),
        "icmp": set_has(snap["text"], "allowed_icmp", CLIENT_IP),
        "input_tcp": bool(input_tcp),
        "input_udp": set_has(snap["text"], "allowed_input_udp", CLIENT_IP),
        "host_ssh": any(entry.get("port") == 22 for entry in input_tcp),
        "mac": set_has(snap["text"], "client_mac", CLIENT_IP),
    }
    print(f"    nft {label}: {json.dumps(state)}", flush=True)
    return state


def grant_state() -> dict:
    """A kliens engedélyeinek jelenléte halmazonként, kiírás nélkül."""
    snap = snapshot()["text"]
    return {
        name: set_has(snap, name, CLIENT_IP)
        for name in NFT_SETS
    }


def nft_raw_elements(set_name: str) -> list:
    """Az nft -j nyers elemei, hogy az ``expires`` mező ellenőrizhető legyen."""
    proc = subprocess.run(
        ["nft", "-j", "list", "set", "inet", "hatarvedelem", set_name],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return []
    data = safe_json(proc.stdout)
    if not isinstance(data, dict):
        return []
    elements = []
    for top in data.get("nftables", []):
        if not isinstance(top, dict):
            continue
        item = top.get("set")
        if not isinstance(item, dict):
            continue
        if item.get("name") not in (None, set_name):
            continue
        raw = item.get("elem")
        if isinstance(raw, list):
            elements.extend(raw)
    return elements


def raw_element_body(raw_element) -> dict:
    if not isinstance(raw_element, dict):
        return {}
    body = raw_element.get("elem", raw_element)
    return body if isinstance(body, dict) else {}


def client_entries(set_name: str) -> list[dict]:
    """A klienshez tartozó, feldolgozott halmazelemek (expires_in-nel)."""
    return [
        entry for entry in nft_json_entries(set_name)
        if entry.get("address") == CLIENT_IP
    ]


def expected_grant_entries(
    *,
    tcp: tuple[int, ...] = (80,),
    udp: tuple[int, ...] = (53,),
    icmp: bool = True,
    full: bool = True,
    input_tcp: tuple[int, ...] = (22,),
    input_udp: tuple[int, ...] = (53,),
    mac: bool = True,
) -> dict[str, set[int | None]]:
    """A várt elemek halmazonként; az address-only halmazok kulcsa None."""
    expected: dict[str, set[int | None]] = {}
    if full:
        expected["allowed_v4"] = {None}
    if icmp:
        expected["allowed_icmp"] = {None}
    if tcp:
        expected["allowed_tcp"] = set(tcp)
    if udp:
        expected["allowed_udp"] = set(udp)
    if input_tcp:
        expected["allowed_input_tcp"] = set(input_tcp)
    if input_udp:
        expected["allowed_input_udp"] = set(input_udp)
    if mac:
        expected["client_mac"] = {None}
    return expected


def grant_element_problems(
    expected: dict[str, set[int | None]]
) -> tuple[dict[str, list[int | None]], list[str]]:
    """A hiányzó és az ``expires`` mezőt nélkülöző engedélyelemek."""
    missing: dict[str, list[int | None]] = {}
    no_expiry: list[str] = []
    for set_name, wanted in expected.items():
        entries = client_entries(set_name)
        if set_name == "client_mac":
            present: set[int | None] = {None} if entries else set()
            if entries and not all(
                isinstance(entry.get("mac"), str)
                and len(entry.get("mac", "")) == 17
                for entry in entries
            ):
                missing.setdefault(set_name, []).extend(sorted(wanted))
                continue
        else:
            present = {entry.get("port") for entry in entries}
        absent = wanted - present
        if absent:
            missing[set_name] = sorted(
                absent, key=lambda value: -1 if value is None else value
            )
        if not entries:
            no_expiry.append(f"{set_name}: nincs elem")
            continue
        for entry in entries:
            if not isinstance(entry.get("expires_in"), int):
                no_expiry.append(
                    f"{set_name}: {entry.get('address')}."
                    f"{entry.get('port') or ''} expires_in hiányzik"
                )
        raw = nft_raw_elements(set_name)
        if not raw:
            no_expiry.append(f"{set_name}: nyers nft elem nincs")
            continue
        for raw_element in raw:
            body = raw_element_body(raw_element)
            expires = body.get("expires")
            if isinstance(expires, bool) or not isinstance(expires, (int, float)):
                no_expiry.append(f"{set_name}: nyers elem expires nélkül")
                break
    return missing, no_expiry


def verify_grant_elements(
    label: str, expected: dict[str, set[int | None]]
) -> None:
    """Várt elemek és a kerneloldali ``expires`` mező ellenőrzése.

    A grant_all() minden elemhez kernel TTL-t ad, ezért a nyers nft JSON-ben
    minden engedélyelemnek hordoznia kell ``expires`` mezőt. A vizsgálat a
    teljes halmazra fut: a teszt VM-en a dinamikus halmazokban csak a teszt
    kliens elemei vannak.
    """
    missing, no_expiry = grant_element_problems(expected)
    check(
        f"{label}: a várt engedélyelemek minden halmazban megvannak",
        not missing,
        json.dumps(missing, sort_keys=True),
    )
    check(
        f"{label}: minden engedélyelem expires mezőt hordoz",
        not no_expiry,
        "; ".join(no_expiry[:8]),
    )


def user_cli(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return server_cli("user", *args, stdin=stdin)


def server_cli(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    """A futó konténer CLI-je (user/fail2ban); a démon control socketjét használja."""
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "--user", "hatarvedelem", "hatarvedelem",
         "python3", "/opt/hatarvedelem/server.py", *args],
        cwd=ROOT, input=stdin, capture_output=True, text=True, timeout=120,
    )


def fail2ban_cli(*args: str) -> subprocess.CompletedProcess:
    return server_cli("fail2ban", *args)


# ------------------------------------------------------- admin API (loopback)

def _admin_login(password: str, attempts: int = 3) -> bool:
    """Admin munkamenet a host loopbackjáról, külön sütitárral.

    A portál egy IP-n egy munkamenetet tart, ezért a kliens névtér
    192.168.10.2-es munkamenete mellett csak a 127.0.0.1-es admin
    munkamenet élhet. A belépési korlátot 429-nél kivárjuk.
    """
    global _admin_portal, _admin_password
    portal = Portal(ADMIN_BASE, ADMIN_COOKIE)
    code, text = portal.request("/api/challenge")
    if code != 200:
        return False
    try:
        captcha = solve_pow(json.loads(text))
    except (ValueError, KeyError, TypeError):
        return False
    last_code = 0
    for attempt in range(attempts):
        code, text = portal.request(
            "/api/login", {"user": USER, "pass": password, "captcha": captcha}
        )
        last_code = code
        if code == 429:
            if attempt + 1 < attempts:
                time.sleep(61)
            code, text = portal.request("/api/challenge")
            if code != 200:
                return False
            captcha = solve_pow(json.loads(text))
            continue
        break
    if last_code != 200:
        return False
    # Az admin jogot a tényleges admin végponton ellenőrizzük; a login
    # önmagában még kötelező jelszócsere előtti munkamenetet is adhat.
    code, _text = portal.request("/api/admin/state")
    if code != 200:
        return False
    _admin_portal = portal
    _admin_password = password
    return True


def ensure_admin(primary: str, fallback: str = "") -> bool:
    if _admin_login(primary):
        return True
    return bool(fallback) and _admin_login(fallback)


def _admin_request(path: str, payload: dict | None = None) -> tuple[int, str]:
    global _admin_portal
    if _admin_portal is None:
        return 0, ""
    code, text = _admin_portal.request(path, payload)
    data = safe_json(text)
    if (
        code == 403
        and isinstance(data, dict)
        and data.get("code") == "admin_session"
        and _admin_password
    ):
        # Lejárt admin munkamenet: egyszer újra belépünk, majd ismételjük.
        if _admin_login(_admin_password):
            code, text = _admin_portal.request(path, payload)
    return code, text


def admin_get(path: str, **params: str | int) -> tuple[int, str]:
    if params:
        path = f"{path}?{urllib.parse.urlencode(params)}"
    return _admin_request(path)


def admin_post(path: str, payload: dict) -> tuple[int, str]:
    return _admin_request(path, payload)


def admin_json(path: str, payload: dict | None = None, **params: str | int) -> dict:
    if payload is None:
        code, text = admin_get(path, **params)
    else:
        code, text = admin_post(path, payload)
    data = safe_json(text)
    if not isinstance(data, dict):
        return {"ok": False, "code": code, "error": str(data)[:200]}
    data.setdefault("ok", code == 200)
    data["_code"] = code
    return data


def admin_sessions_for_ip(ip: str = CLIENT_IP) -> list[dict] | None:
    data = admin_json("/api/admin/sessions")
    if data.get("_code") != 200:
        return None
    rows = data.get("sessions")
    if not isinstance(rows, list):
        return None
    return [row for row in rows if isinstance(row, dict) and row.get("ip") == ip]


def admin_log_rows(event: str, limit: int = 250) -> list[dict] | None:
    data = admin_json("/api/admin/logs", event=event, limit=limit)
    if data.get("_code") != 200:
        return None
    rows = data.get("logs")
    if not isinstance(rows, list):
        return None
    return [row for row in rows if isinstance(row, dict)]


def audit_event(
    event: str, predicate, timeout: float = 8.0
) -> tuple[str, dict]:
    """Esemény keresése az admin naplóban: found / missing / unavailable."""
    deadline = time.monotonic() + timeout
    while True:
        rows = admin_log_rows(event)
        if rows is None:
            return "unavailable", {}
        for row in rows:
            if row.get("event") != event:
                continue
            try:
                if predicate(row):
                    return "found", row
            except Exception:
                continue
        if time.monotonic() >= deadline:
            return "missing", {}
        time.sleep(0.5)


def check_audit(
    label: str, event: str, predicate, timeout: float = 8.0
) -> None:
    state, row = audit_event(event, predicate, timeout)
    if state == "unavailable":
        skip(f"{label}: audit esemény ({event})", "az admin napló nem érhető el")
        return
    check(
        f"{label}: audit esemény ({event})",
        state == "found",
        "nem található" if state != "found" else json.dumps(row, ensure_ascii=False)[:400],
    )


# --------------------------------------------------------------- conntrack

def _conntrack_lines() -> list[str] | None:
    if not CONNTRACK_BIN:
        return None
    try:
        proc = subprocess.run(
            [CONNTRACK_BIN, "-L", "-s", CLIENT_IP],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def client_conntrack_flows() -> list[str] | None:
    """A kliens nem-portál conntrack folyamai.

    A portál saját 8100-as folyamát kiszűrjük: a kilépés válasza még a
    conntrack-ürítés után is létrehozhat egy bejegyzést, és az nem jelent
    hálózati engedélyt.
    """
    lines = _conntrack_lines()
    if lines is None:
        return None
    return [
        line for line in lines
        if "dport=8100" not in line and "sport=8100" not in line
    ]


def check_conntrack_empty(label: str) -> None:
    flows = client_conntrack_flows()
    if flows is None:
        skip(f"{label}: conntrack üres", "a conntrack eszköz nem érhető el")
        return
    check(f"{label}: conntrack üres", not flows, json.dumps(flows[:4]))


def check_conntrack_traffic(label: str) -> None:
    flows = client_conntrack_flows()
    if flows is None:
        skip(f"{label}: conntrack forgalom", "a conntrack eszköz nem érhető el")
        return
    check(f"{label}: conntrack forgalom van", bool(flows), json.dumps(flows[:2]))


# ------------------------------------------------------- kliens műveletek

def client_login(
    user: str, password: str, cookie: str, label: str, attempts: int = 3
) -> dict:
    result: dict = {}
    for attempt in range(attempts):
        result = client_json(
            "login", password=password, user=user, cookie=cookie
        )
        if result.get("code") != 429:
            break
        if attempt + 1 < attempts:
            print(f"    {label}: login korlát (429), várakozás 61 s...", flush=True)
            time.sleep(61)
    check(f"{label}: friss belépés", bool(result.get("ok")), json.dumps(result.get("body")))
    return result


def client_access(
    rule: str, ttl: int, cookie: str, label: str, attempts: int = 3
) -> dict:
    result: dict = {}
    for attempt in range(attempts):
        result = client_json("access", rule, str(ttl), cookie=cookie)
        if result.get("code") != 429:
            break
        if attempt + 1 < attempts:
            print(f"    {label}: access korlát (429), várakozás 61 s...", flush=True)
            time.sleep(61)
    check(
        f"{label}: engedélyezés ({rule})",
        bool(result.get("ok")) and bool(result.get("body", {}).get("authorized")),
        json.dumps(result.get("body")),
    )
    return result


def generate_traffic(label: str) -> None:
    traffic = client_json("traffic")
    check(
        f"{label}: DNS és host SSH forgalom ment",
        bool(traffic.get("dns")) and bool(traffic.get("host_ssh")),
        json.dumps(traffic),
    )
    check_conntrack_traffic(label)


def assert_revoked(label: str) -> None:
    """Munkamenet, halmazok és conntrack ellenőrzése egy visszavonás után."""
    sessions = admin_sessions_for_ip()
    if sessions is None:
        skip(f"{label}: munkamenet megszűnt", "az admin munkamenet-lista nem érhető el")
    else:
        check(
            f"{label}: munkamenet megszűnt",
            not sessions,
            json.dumps([row.get("id") for row in sessions]),
        )
    state = grant_state()
    check(
        f"{label}: minden engedélyhalmaz üres",
        not any(state.values()),
        json.dumps(state),
    )
    check_conntrack_empty(label)


# ------------------------------------------------------- forgatókönyv-erőforrások

FULL_COLL_PAYLOAD = {
    "label": "E2E teljes gyűjtő",
    "description": "forward TCP/UDP/ICMP, teljes és host engedély egyben",
    "collection": True,
    "members": ["e2e-rev-fwd", "e2e-rev-full", "e2e-rev-host"],
    "default_ttl": 60,
    "max_ttl": 300,
}
REV_FWD_PAYLOAD = {
    "label": "E2E forward",
    "description": "TCP 80, UDP 53 és ICMP",
    "direction": "forward",
    "tcp": [80],
    "udp": [53],
    "icmp": True,
    "full": False,
    "default_ttl": 60,
    "max_ttl": 300,
}
REV_FULL_PAYLOAD = {
    "label": "E2E teljes",
    "description": "teljes forward hozzáférés (allowed_v4)",
    "direction": "forward",
    "tcp": [],
    "udp": [],
    "icmp": False,
    "full": True,
    "default_ttl": 60,
    "max_ttl": 300,
}
REV_HOST_PAYLOAD = {
    "label": "E2E host",
    "description": "host SSH 22/TCP és UDP 53",
    "direction": "input",
    "tcp": [22],
    "udp": [53],
    "icmp": False,
    "full": False,
    "default_ttl": 60,
    "max_ttl": 300,
}


def ensure_rule(rule_id: str, payload: dict) -> tuple[bool, str]:
    data = admin_json("/api/admin/rules", {
        "action": "create", "id": rule_id, **payload,
    })
    if data.get("ok"):
        return True, ""
    # Maradék szabály frissítése ugyanazzal a teljes payloaddal.
    data = admin_json("/api/admin/rules", {
        "action": "update", "id": rule_id, **payload,
    })
    return bool(data.get("ok")), str(data.get("error", ""))[:200]


def ensure_group(group_id: str, rules: list[str]) -> tuple[bool, str]:
    payload = {
        "action": "create", "id": group_id,
        "label": "E2E visszavonás csoport",
        "description": "a csoportfrissítés visszavonási út tesztje",
        "rules": rules, "members": [],
    }
    data = admin_json("/api/admin/groups", payload)
    if data.get("ok"):
        return True, ""
    payload["action"] = "update"
    data = admin_json("/api/admin/groups", payload)
    return bool(data.get("ok")), str(data.get("error", ""))[:200]


def ensure_temp_user(
    name: str, password: str, *, rules: list[str] | None = None,
    groups: list[str] | None = None,
) -> tuple[bool, str]:
    # A korábbi futás maradéka ne örököljön csoporttagságot vagy szabályt.
    admin_post("/api/admin/users", {"action": "delete", "name": name})
    created = user_cli(
        "add", name, "--no-must-change", "--password-stdin",
        stdin=password + "\n",
    )
    if created.returncode != 0:
        return False, (created.stderr or created.stdout).strip()[:200]
    payload: dict = {"action": "update", "name": name}
    if rules is not None:
        payload["rules"] = rules
    if groups is not None:
        payload["groups"] = groups
    data = admin_json("/api/admin/users", payload)
    return bool(data.get("ok")), str(data.get("error", ""))[:200]


def ensure_scenario_resources() -> dict[str, str] | None:
    """A közös szabályok, csoport és ideiglenes felhasználók előkészítése.

    Minden erőforrás-azonosító a SCENARIO_* listákban szerepel, ezért a main
    finally takarítása akkor is eltávolítja őket, ha egy forgatókönyv
    félbeszakad. A jelszavak csak memóriában élnek, és soha nem íródnak ki.
    """
    passwords = {name: secrets.token_urlsafe(18) for name in SCENARIO_USERS}
    problems: list[str] = []
    for rule_id, payload in (
        ("e2e-rev-fwd", REV_FWD_PAYLOAD),
        ("e2e-rev-full", REV_FULL_PAYLOAD),
        ("e2e-rev-host", REV_HOST_PAYLOAD),
        ("e2e-full-coll", FULL_COLL_PAYLOAD),
    ):
        ok, detail = ensure_rule(rule_id, payload)
        if not ok:
            problems.append(f"rule {rule_id}: {detail}")
    ok, detail = ensure_group("e2e-rev-grp", ["e2e-full-coll"])
    if not ok:
        problems.append(f"group e2e-rev-grp: {detail}")
    for name in SCENARIO_USERS:
        if name == MULTI_USER and not gate_on(MULTI_GATE):
            # A K6 kapcsoló nélkül nem jön létre a saját felhasználója sem,
            # így az alap futás erőforrásai változatlanok maradnak.
            continue
        if name == "e2e-rev-user":
            rules = None
        elif name == MULTI_USER:
            # A K6 a saját (esetleg HV_E2E_RULES-szel felülírt) párját
            # rendeli hozzá a belépés előtt. Az explicit üres lista fontos:
            # így a fiók nem örökli a régi, kiosztás nélküli forward
            # szabályokat.
            rules = []
        else:
            rules = ["e2e-full-coll"]
        ok, detail = ensure_temp_user(name, passwords[name], rules=rules)
        if not ok:
            problems.append(f"user {name}: {detail}")
    # A csoporttag csak a felhasználó létrehozása után állítható be.
    group = admin_json("/api/admin/groups", {
        "action": "update", "id": "e2e-rev-grp",
        "label": "E2E visszavonás csoport",
        "description": "a csoportfrissítés visszavonási út tesztje",
        "rules": ["e2e-full-coll"], "members": ["e2e-rev-user"],
    })
    if not group.get("ok"):
        problems.append(f"group members: {group.get('error', '')}")
    # A csoporttagság a felhasználói rekordba is bekerül; a frissítés
    # egyúttal visszavonja az esetleges maradék munkameneteket.
    user = admin_json("/api/admin/users", {
        "action": "update", "name": "e2e-rev-user",
        "groups": ["e2e-rev-grp"],
    })
    if not user.get("ok"):
        problems.append(f"user group: {user.get('error', '')}")
    check(
        "kiterjesztett erőforrások előkészítve",
        not problems,
        "; ".join(problems),
    )
    return passwords if not problems else None


def _revocation_login(
    user: str, password: str, rule: str, label: str,
    cookie: str = SCEN_COOKIE,
) -> None:
    """Friss belépés + engedélyezés a közös gyűjtővel, majd elemellenőrzés."""
    client_login(user, password, cookie, label)
    client_access(rule, 120, cookie, label)
    verify_grant_elements(label, expected_grant_entries())
    # A forgalom a visszavonás előtti conntrack állapotot biztosítja.
    generate_traffic(label)


def scenario_revocation_matrix(passwords: dict[str, str]) -> None:
    print("== K1. Visszavonási utak ==", flush=True)
    user = "e2e-rev-user"
    password = passwords[user]

    # 1. Kliens kilépés.
    label = "K1/logout"
    _revocation_login(user, password, "e2e-full-coll", label)
    out = client_json("logout", cookie=SCEN_COOKIE)
    check(f"{label}: 200", bool(out.get("ok")), json.dumps(out.get("body")))
    assert_revoked(label)
    check_audit(label, "logout", lambda row: (
        row.get("user") == user and row.get("authorized") is True
    ))

    # 2. Admin által megszakított munkamenet.
    label = "K1/admin-terminate"
    _revocation_login(user, password, "e2e-full-coll", label)
    sessions = admin_sessions_for_ip()
    session_id = ""
    if sessions:
        authorized = [row for row in sessions if row.get("authorized")]
        if authorized:
            session_id = str(authorized[0].get("id") or "")
    if not session_id:
        check(f"{label}: a kliens munkamenet az admin listában", False,
              json.dumps(sessions))
    else:
        data = admin_json("/api/admin/sessions", {
            "action": "terminate", "id": session_id,
        })
        check(f"{label}: admin terminate 200", bool(data.get("ok")),
              json.dumps({k: v for k, v in data.items() if k != "sessions"}))
    assert_revoked(label)
    check_audit(label, "admin_session_terminated", lambda row: (
        row.get("target") == user and row.get("ip") == CLIENT_IP
    ))

    # 3. A gyűjtőszabály saját módosítása.
    label = "K1/rule-update"
    _revocation_login(user, password, "e2e-full-coll", label)
    updated = dict(FULL_COLL_PAYLOAD)
    updated["description"] = f"frissítve {int(time.time())}"
    data = admin_json("/api/admin/rules", {
        "action": "update", "id": "e2e-full-coll", **updated,
    })
    check(f"{label}: admin rule update 200", bool(data.get("ok")),
          str(data.get("error", ""))[:160])
    assert_revoked(label)
    check_audit(label, "admin_rule_updated", lambda row: (
        row.get("target") == "e2e-full-coll"
        and int(row.get("sessions_revoked") or 0) >= 1
    ))

    # 4. Gyűjtőtag módosítása: a függő gyűjtő munkamenete is bontandó.
    label = "K1/collection-member-update"
    _revocation_login(user, password, "e2e-full-coll", label)
    member = dict(REV_FWD_PAYLOAD)
    member["description"] = f"tag frissítve {int(time.time())}"
    data = admin_json("/api/admin/rules", {
        "action": "update", "id": "e2e-rev-fwd", **member,
    })
    check(f"{label}: admin member update 200", bool(data.get("ok")),
          str(data.get("error", ""))[:160])
    assert_revoked(label)
    check_audit(label, "admin_rule_updated", lambda row: (
        row.get("target") == "e2e-rev-fwd"
        and "e2e-full-coll" in str(row.get("collections_affected", ""))
        and int(row.get("sessions_revoked") or 0) >= 1
    ))

    # 5. Csoportfrissítés: a csoporttag munkamenete bontandó.
    label = "K1/group-update"
    _revocation_login(user, password, "e2e-full-coll", label)
    data = admin_json("/api/admin/groups", {
        "action": "update", "id": "e2e-rev-grp",
        "label": "E2E visszavonás csoport",
        "description": f"csoport frissítve {int(time.time())}",
        "rules": ["e2e-full-coll"], "members": [user],
    })
    check(f"{label}: admin group update 200", bool(data.get("ok")),
          str(data.get("error", ""))[:160])
    assert_revoked(label)
    check_audit(label, "admin_group_updated", lambda row: (
        row.get("target") == "e2e-rev-grp"
        and int(row.get("sessions_revoked") or 0) >= 1
    ))

    # 6. Felhasználó letiltása.
    label = "K1/user-disable"
    disabled_user = "e2e-rev-del"
    _revocation_login(disabled_user, passwords[disabled_user], "e2e-full-coll", label)
    data = admin_json("/api/admin/users", {
        "action": "update", "name": disabled_user, "enabled": False,
    })
    check(f"{label}: admin user disable 200", bool(data.get("ok")),
          str(data.get("error", ""))[:160])
    assert_revoked(label)
    check_audit(label, "admin_user_updated", lambda row: (
        row.get("target") == disabled_user
        and row.get("enabled") is False
        and int(row.get("sessions_revoked") or 0) >= 1
    ))
    # A törlés útjához újra engedélyezzük; ez maga is visszavonja a
    # munkameneteket, de itt már nincs élő munkamenet.
    admin_json("/api/admin/users", {
        "action": "update", "name": disabled_user, "enabled": True,
    })

    # 7. Felhasználó törlése.
    label = "K1/user-delete"
    _revocation_login(disabled_user, passwords[disabled_user], "e2e-full-coll", label)
    data = admin_json("/api/admin/users", {
        "action": "delete", "name": disabled_user,
    })
    check(f"{label}: admin user delete 200", bool(data.get("ok")),
          str(data.get("error", ""))[:160])
    assert_revoked(label)
    check_audit(label, "admin_user_deleted", lambda row: (
        row.get("target") == disabled_user
        and int(row.get("sessions_revoked") or 0) >= 1
    ))

    # 8. Fail2ban tiltás. A tiltás a kliens portál-elérését is lezárja,
    # ezért az ellenőrzések után azonnal feloldjuk.
    label = "K1/fail2ban"
    _revocation_login(user, password, "e2e-full-coll", label)
    try:
        data = admin_json("/api/admin/fail2ban", {
            "action": "ban", "ip": CLIENT_IP, "seconds": 60,
        })
        check(f"{label}: admin ban 200", bool(data.get("ok")),
              str(data.get("error", ""))[:160])
        assert_revoked(label)
        check_audit(label, "fail2ban_ban", lambda row: (
            row.get("ip") == CLIENT_IP
            and int(row.get("sessions_revoked") or 0) >= 1
        ))
    finally:
        admin_json("/api/admin/fail2ban", {
            "action": "unban", "ip": CLIENT_IP,
        })


def wait_condition(predicate, timeout: float, interval: float = 2.0) -> bool:
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def scenario_natural_expiry(
    passwords: dict[str, str], min_ttl: int
) -> None:
    """Természetes lejárat a szerver min_ttl értékével.

    A kernel TTL-jét szándékosan nem rövidítjük: a munkamenet valódi
    lejáratát és a reaper naplóeseményét vizsgáljuk. A szerver min_ttl-je
    60 másodperc, ezért a várakozás legalább ennyi; a felső korlát a
    HV_E2E_LONG kapcsolóhoz tartozó E2E_LONG_MAX_WAIT.
    """
    title = "K2. Természetes lejárat (HV_E2E_LONG)"
    if not gate_on(LONG_GATE):
        skip(title, f"{LONG_GATE} nincs bekapcsolva")
        return
    print(f"== {title} ==", flush=True)
    ttl = max(60, int(min_ttl))
    # A várakozás felső korlátja a kapcsolóhoz tartozó E2E_LONG_MAX_WAIT.
    # Ha a szerver min_ttl-je ennél hosszabb, a teszt nem tudná kivárni a
    # valódi lejáratot; ilyenkor inkább egyértelműen kihagyjuk, mintsem
    # hamis FAILt vagy órás várakozást produkáljunk.
    if ttl + 30 > LONG_MAX_WAIT:
        skip(
            title,
            f"a szerver min_ttl={ttl} s, az E2E_LONG_MAX_WAIT="
            f"{LONG_MAX_WAIT} s kevés a kiváráshoz (legalább TTL+30 kell)",
        )
        return
    user = "e2e-exp-user"
    label = "K2/expiry"
    client_login(user, passwords[user], EXPIRY_COOKIE, label)
    # A TTL az /api/access feldolgozásakor indul, ezért az óra indítása
    # előbb történik, mint a kérés; a későbbi nft/forgalmi ellenőrzések
    # ideje nem rövidítheti le a várt lejáratot.
    started = time.time()
    client_access("e2e-full-coll", ttl, EXPIRY_COOKIE, label)
    verify_grant_elements(label, expected_grant_entries())
    generate_traffic(label)
    deadline = started + min(LONG_MAX_WAIT, ttl + 120)
    print(f"    várakozás a természetes lejáratig (TTL {ttl} s)...", flush=True)
    wait_condition(
        lambda: not any(grant_state().values())
        and not (client_conntrack_flows() or []),
        max(0.0, deadline - time.time()),
        interval=3.0,
    )
    elapsed = time.time() - started
    check(
        f"{label}: a lejárat legalább a TTL után következett be",
        elapsed >= ttl,
        f"eltelt={elapsed:.0f} s, TTL={ttl} s",
    )
    state = grant_state()
    check(
        f"{label}: minden engedélyhalmaz lejárt",
        not any(state.values()), json.dumps(state),
    )
    check_conntrack_empty(label)
    sessions = admin_sessions_for_ip()
    if sessions is None:
        skip(f"{label}: munkamenet megszűnt", "az admin munkamenet-lista nem érhető el")
    else:
        check(
            f"{label}: munkamenet megszűnt",
            not sessions,
            json.dumps([row.get("id") for row in sessions]),
        )
    check_audit(label, "session_expired", lambda row: (
        row.get("user") == user and row.get("reason") == "expired"
    ), timeout=30.0)


# ------------------------------------------------------------ blokk-teszt

def admin_setting_entries(kind: str) -> list[dict]:
    data = admin_json("/api/admin/settings")
    if data.get("_code") != 200:
        return []
    settings = data.get("settings")
    if not isinstance(settings, dict):
        return []
    entries = settings.get(kind)
    if not isinstance(entries, list):
        return []
    return [row for row in entries if isinstance(row, dict)]


def admin_blocks() -> list[dict]:
    return admin_setting_entries("block")


def delete_admin_settings(kind: str, prefix: str) -> None:
    for row in admin_setting_entries(kind):
        if not str(row.get("label", "")).startswith(prefix):
            continue
        entry_id = row.get("id")
        if isinstance(entry_id, str) and entry_id:
            admin_post("/api/admin/settings", {
                "action": "delete", "kind": kind, "id": entry_id,
            })


def delete_admin_blocks(prefix: str = BLOCK_LABEL_PREFIX) -> None:
    delete_admin_settings("block", prefix)


def create_admin_setting(
    kind: str, label: str, dst: str, proto: str, ports: list[int]
) -> str:
    kind_name = "blokk" if kind == "block" else "pre-auth"
    data = admin_json("/api/admin/settings", {
        "action": "create", "kind": kind,
        "entry": {
            "label": label, "dst": dst, "proto": proto,
            "ports": ports, "enabled": True,
        },
    })
    if data.get("_code") != 200:
        check(f"{kind_name} létrehozása ({label})", False,
              str(data.get("error", ""))[:160])
        return ""
    matching = [
        row for row in admin_setting_entries(kind)
        if row.get("label") == label
    ]
    if not matching:
        check(f"{kind_name} létrehozása ({label})", False,
              "nincs azonosító a válaszban")
        return ""
    check(f"{kind_name} létrehozása ({label})", True)
    return str(matching[-1].get("id") or "")


def delete_admin_setting(kind: str, entry_id: str, label: str) -> None:
    if not entry_id:
        return
    kind_name = "blokk" if kind == "block" else "pre-auth"
    data = admin_json("/api/admin/settings", {
        "action": "delete", "kind": kind, "id": entry_id,
    })
    check(f"{kind_name} törlése ({label})", bool(data.get("ok")),
          str(data.get("error", ""))[:160])


def create_admin_block(label: str, dst: str, proto: str, ports: list[int]) -> str:
    return create_admin_setting("block", label, dst, proto, ports)


def delete_admin_block(entry_id: str, label: str) -> None:
    delete_admin_setting("block", entry_id, label)


def nft_chain_text(chain: str) -> str:
    proc = subprocess.run(
        ["nft", "list", "chain", "inet", "hatarvedelem", chain],
        capture_output=True, text=True,
    )
    return proc.stdout if proc.returncode == 0 else ""


def start_tcp_hold(
    host: str, port: int, hold_seconds: float, wait_seconds: float
) -> tuple[subprocess.Popen, tuple[str, str, str]]:
    """A kliens névtérben futó tartós TLS-folyam indítása."""
    stamp = f"{os.getpid()}-{int(time.time() * 1000)}"
    established = f"/tmp/hv-e2e-hold-{stamp}.established"
    after = f"/tmp/hv-e2e-hold-{stamp}.after"
    release = f"/tmp/hv-e2e-hold-{stamp}.release"
    for path in (established, after, release):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    proc = subprocess.Popen(
        [
            "ip", "netns", "exec", "hvclient", "python3",
            os.path.abspath(__file__), "client", "tcp-hold",
            host, str(port), str(hold_seconds), established, after,
            release, str(wait_seconds),
        ],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc, (established, after, release)


def finish_tcp_hold(
    proc: subprocess.Popen, timeout: float
) -> tuple[dict, str]:
    try:
        output, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        output, _ = proc.communicate()
        return {"error": "a folyamat nem fejeződött be időben"}, output
    lines = [line for line in output.splitlines() if line.strip()]
    data = safe_json(lines[-1]) if lines else {}
    if not isinstance(data, dict):
        return {"error": output[-240:]}, output
    return data, output


def scenario_block_precedence(passwords: dict[str, str]) -> None:
    title = "K3. Blokk elsőbbsége (HV_E2E_PENDING)"
    if not gate_on(PENDING_GATE):
        pending_skip(title, PENDING_GATE)
        return
    print(f"== {title} ==", flush=True)
    user = "e2e-blk-user"
    label = "K3/block"
    fwd_block_id = ""
    host_block_id = ""
    flow_block_id = ""
    portal_block_id = ""
    preauth_id = ""
    preauth_block_id = ""
    hold_proc: subprocess.Popen | None = None
    hold_paths: tuple[str, str, str] = ("", "", "")
    try:
        delete_admin_blocks()
        delete_admin_settings("preauth", PREAUTH_LABEL_PREFIX)
        client_login(user, passwords[user], BLOCK_COOKIE, label)
        client_access("e2e-full-coll", 120, BLOCK_COOKIE, label)
        verify_grant_elements(label, expected_grant_entries())
        generate_traffic(label)

        # A láncok sorrendje: a blokk minden engedély (és a konténer
        # accept) előtt, a portál accept viszont a blokk előtt fut, a NAT
        # blokk pedig a redirect/DNAT előtt.
        forward_chain = nft_chain_text("forward")
        input_chain = nft_chain_text("input")
        prerouting = nft_chain_text("prerouting")
        forward_block_pos = forward_chain.find("jump block")
        forward_grant_pos = forward_chain.find("@allowed_v4")
        container_pos = forward_chain.find("172.30.0.2 tcp dport")
        check(
            f"{label}: a blokk a forward engedélyek előtt fut",
            0 <= forward_block_pos < forward_grant_pos,
            f"block={forward_block_pos}, grant={forward_grant_pos}",
        )
        check(
            f"{label}: a blokk a konténer accept előtt fut",
            0 <= forward_block_pos < container_pos,
            f"block={forward_block_pos}, container={container_pos}",
        )
        portal_accept_pos = input_chain.find("dport 8100 accept")
        input_block_pos = input_chain.find("jump block")
        check(
            f"{label}: a portál accept a blokk előtt fut",
            0 <= portal_accept_pos < input_block_pos,
            f"portal={portal_accept_pos}, block={input_block_pos}",
        )
        check(
            f"{label}: a NAT-blokk a redirect/DNAT előtt fut",
            0 <= prerouting.find("jump block_nat") < prerouting.find("redirect"),
            f"block_nat={prerouting.find('jump block_nat')}, "
            f"redirect={prerouting.find('redirect')}",
        )
        # 1. Meglévő, már established TLS-folyam a blokk alatt, majd a
        # blokk törlése után ugyanazon a kapcsolaton, újraengedélyezés
        # nélkül. A conntrackot szándékosan nem ürítjük.
        before_fwd = client_json("tcp-probe", "1.1.1.1", "80", "3")
        before_host = client_json("tcp-probe", "192.168.10.1", "22", "3")
        check(f"{label}: engedélyezett forward TCP 80 nyitva",
              before_fwd.get("status") == "open", json.dumps(before_fwd))
        check(f"{label}: engedélyezett host SSH nyitva",
              before_host.get("status") == "open", json.dumps(before_host))

        hold_proc, hold_paths = start_tcp_hold("1.1.1.1", 443, 4, 3)
        established_path, after_path, release_path = hold_paths
        established = wait_condition(
            lambda: os.path.exists(established_path), 15, 0.25
        )
        if not established:
            hold_data, _hold_out = finish_tcp_hold(hold_proc, 5)
            hold_proc = None
            check(f"{label}: meglévő TLS-folyam létrejött", False,
                  json.dumps(hold_data)[:300])
        else:
            check(f"{label}: meglévő TLS-folyam létrejött", True)
            before_conntrack = _conntrack_lines()
            if before_conntrack is None:
                skip(f"{label}: a meglévő folyam a conntrackban van",
                     "a conntrack eszköz nem érhető el")
            else:
                check(
                    f"{label}: a meglévő folyam a blokk előtt a conntrackban van",
                    any("dport=443" in line for line in before_conntrack),
                    json.dumps([line for line in before_conntrack
                                if "dport=443" in line][:3]),
                )
            flow_block_id = create_admin_block(
                BLOCK_LABEL_PREFIX + "flow", "1.1.1.1", "tcp", [443]
            )
            during_conntrack = _conntrack_lines()
            if during_conntrack is None:
                skip(f"{label}: a blokk nem ürítette a conntrackot",
                     "a conntrack eszköz nem érhető el")
            else:
                check(
                    f"{label}: a blokk nem ürítette a conntrackot",
                    any("dport=443" in line for line in during_conntrack),
                    json.dumps([line for line in during_conntrack
                                if "dport=443" in line][:3]),
                )
            after_seen = wait_condition(
                lambda: os.path.exists(after_path), 25, 0.25
            )
            after_data = _read_json_file(after_path) if after_seen else {}
            check(
                f"{label}: a blokk alatt a meglévő folyam válasza elmarad "
                "(időtúllépés, nem megszakítás)",
                after_seen and after_data.get("after") == "timeout"
                and not after_data.get("after_reply"),
                json.dumps(after_data)[:300],
            )
            during_flow = client_json("tcp-probe", "1.1.1.1", "443", "3")
            check(f"{label}: a blokk alatt az új 443 kapcsolat eldobva",
                  during_flow.get("status") == "timeout",
                  json.dumps(during_flow))
            missing, no_expiry = grant_element_problems(
                expected_grant_entries()
            )
            check(
                f"{label}: a blokk nem távolított el engedélyelemet",
                not missing,
                json.dumps(missing, sort_keys=True),
            )
            check(
                f"{label}: a blokk nem rövidítette az engedélyek TTL-jét",
                not no_expiry,
                "; ".join(no_expiry[:8]),
            )
            delete_admin_block(flow_block_id, BLOCK_LABEL_PREFIX + "flow")
            flow_block_id = ""
            try:
                with open(release_path, "w", encoding="utf-8") as fh:
                    fh.write("release\n")
            except OSError:
                pass
            hold_data, _hold_out = finish_tcp_hold(hold_proc, 25)
            hold_proc = None
            check(
                f"{label}: a blokk törlése után ugyanaz a folyam újra működik",
                bool(hold_data.get("recovered")),
                json.dumps(hold_data)[:400],
            )
            status = client_json("status", cookie=BLOCK_COOKIE)
            check(
                f"{label}: a meglévő folyamhoz nem kellett újraengedélyezés",
                bool(status.get("body", {}).get("authorized")),
                json.dumps(status.get("body")),
            )

        # 2. Új kapcsolatok: forward 80 és host SSH 22 eldobása, valamint a
        # portál 8100-as tiltása ellenére a portál elérése.
        fwd_block_id = create_admin_block(
            BLOCK_LABEL_PREFIX + "fwd", "1.1.1.1", "tcp", [80]
        )
        host_block_id = create_admin_block(
            BLOCK_LABEL_PREFIX + "host", "192.168.10.1", "tcp", [22]
        )
        portal_block_id = create_admin_block(
            BLOCK_LABEL_PREFIX + "portal", "192.168.10.1", "tcp", [8100]
        )
        # A blokk-láncok tartalma csak a bejegyzések létrehozása után
        # olvasható; a sorrendet a fenti, bejegyzés nélküli láncokon
        # ellenőriztük.
        block_chain = nft_chain_text("block")
        block_nat = nft_chain_text("block_nat")
        check(f"{label}: a blokk-szabály a kernelben van",
              "1.1.1.1" in block_chain and "192.168.10.1" in block_chain,
              block_chain[-500:])
        check(
            f"{label}: a blokk a conntrack eredeti tuple-jára illeszkedik "
            "(a válaszirányt is lefedi)",
            "ct original ip daddr" in block_chain
            and "ct original proto-dst" in block_chain,
            block_chain[-400:],
        )
        check(
            f"{label}: a NAT-blokk a DNAT előtti célt/portot használja",
            "ct original ip daddr" in block_nat
            and "ct original proto-dst" in block_nat,
            block_nat[-400:],
        )
        page = client_json("page", cookie=BLOCK_COOKIE)
        check(
            f"{label}: a 8100-at tiltó bejegyzés ellenére a portál elérhető",
            page.get("code") == "200" and bool(page.get("rules")),
            json.dumps(page)[:300],
        )
        during_fwd = client_json("tcp-probe", "1.1.1.1", "80", "3")
        during_host = client_json("tcp-probe", "192.168.10.1", "22", "3")
        check(f"{label}: a blokkolt forward TCP eldobva (időtúllépés)",
              during_fwd.get("status") == "timeout", json.dumps(during_fwd))
        check(f"{label}: a blokkolt host SSH eldobva (időtúllépés)",
              during_host.get("status") == "timeout", json.dumps(during_host))
        # A WAN/DNAT oldali megkerüléshez külön WAN forrásnévtér és
        # publikált DNAT-szolgáltatás kellene; a harness ilyet nem hoz
        # létre. A pre-DNAT szemantikát a block_nat szabály szövege
        # rögzíti, ezért a belső cím/port blokkja nem érinti a DNAT-utat.
        skip(
            f"{label}: WAN/DNAT oldali megkerülés",
            "nincs WAN forrásnévtér és publikált DNAT-szolgáltatás",
        )
        skip(
            f"{label}: belső cím/port blokkja nem fogja a DNAT-utat",
            "TODO: WAN névtér + publikált konténerport szükséges",
        )
        # A Docker-híd egress csak a 172.30.0.2 konténer-elfogadó szabály
        # mellett tesztelhető; egy általános bridge-konténer más forrás-IP-t
        # kap, ezért a futó Minecraft konténer hálózatát/nevét nem
        # bitoroljuk a tesztben.
        skip(
            f"{label}: Docker-híd konténer kimenet (443)",
            "TODO: a 172.30.0.2 konténer-elfogadó szabályhoz dedikált "
            "tesztkonténer kell, a futó Minecraft konténer megzavarása nélkül",
        )
        # Beállításfájl-sérülés: csak a beállításfájl egy másolatának
        # biztonságos cseréjével és HV_E2E_RESTARTtal lenne értelmes; a
        # harness nem írja a futó konténer beállításfájlját.
        skip(
            f"{label}: sérült beállításfájl és last-known-good blokk",
            "TODO: a beállításfájl másolatának cseréje invasiv, nincs "
            "implementálva",
        )

        delete_admin_block(fwd_block_id, BLOCK_LABEL_PREFIX + "fwd")
        fwd_block_id = ""
        delete_admin_block(host_block_id, BLOCK_LABEL_PREFIX + "host")
        host_block_id = ""
        delete_admin_block(portal_block_id, BLOCK_LABEL_PREFIX + "portal")
        portal_block_id = ""
        after_fwd = client_json("tcp-probe", "1.1.1.1", "80", "3")
        after_host = client_json("tcp-probe", "192.168.10.1", "22", "3")
        check(f"{label}: a blokk törlése után a forward engedély újra él",
              after_fwd.get("status") == "open", json.dumps(after_fwd))
        check(f"{label}: a blokk törlése után a host SSH újra él",
              after_host.get("status") == "open", json.dumps(after_host))
        missing, no_expiry = grant_element_problems(expected_grant_entries())
        check(
            f"{label}: a blokkolás után is minden engedélyelem megvan",
            not missing,
            json.dumps(missing, sort_keys=True),
        )
        check(
            f"{label}: a blokkolás után is van kernel TTL",
            not no_expiry,
            "; ".join(no_expiry[:8]),
        )
        status = client_json("status", cookie=BLOCK_COOKIE)
        check(f"{label}: újraengedélyezés nem kellett",
              bool(status.get("body", {}).get("authorized")),
              json.dumps(status.get("body")))

        # 3. Pre-auth engedély és a blokk elsőbbsége. Ez nem WAN/DNAT, de
        # ugyanazt a block_nat → preauth_nat sorrendet gyakorolja: a blokk
        # a pre-auth engedélyt is felülírja, majd a törlése után az
        # engedély újra érvényes.
        out = client_json("logout", cookie=BLOCK_COOKIE)
        check(f"{label}: kilépés a pre-auth teszthez", bool(out.get("ok")),
              json.dumps(out.get("body")))
        preauth_id = create_admin_setting(
            "preauth", PREAUTH_LABEL_PREFIX + "fwd",
            "1.1.1.1", "tcp", [80],
        )
        # A TCP-probe önmagában nem különbözteti meg a pre-auth engedélyt a
        # portál-átirányítástól (mindkettő nyitott port), ezért HTTP-t is
        # nézünk: pre-auth mellett a válasz nem a portál oldala.
        pre = client_json("check")
        check(f"{label}: a pre-auth engedély működik (nem portál-átirányítás)",
              pre.get("http_external") is True
              and pre.get("http_portal") is False,
              json.dumps(pre))
        preauth_block_id = create_admin_block(
            BLOCK_LABEL_PREFIX + "preauth", "1.1.1.1", "tcp", [80]
        )
        blocked_pre = client_json("check")
        check(f"{label}: a blokk a pre-auth engedélyt is felülírja",
              blocked_pre.get("http_external") is False
              and blocked_pre.get("http_portal") is False,
              json.dumps(blocked_pre))
        delete_admin_block(preauth_block_id, BLOCK_LABEL_PREFIX + "preauth")
        preauth_block_id = ""
        restored_pre = client_json("check")
        check(f"{label}: a blokk törlése után a pre-auth engedély újra él",
              restored_pre.get("http_external") is True
              and restored_pre.get("http_portal") is False,
              json.dumps(restored_pre))
        delete_admin_setting(
            "preauth", preauth_id, PREAUTH_LABEL_PREFIX + "fwd"
        )
        preauth_id = ""
    finally:
        if hold_proc is not None:
            if hold_paths[2]:
                try:
                    with open(hold_paths[2], "w", encoding="utf-8") as fh:
                        fh.write("cleanup\n")
                except OSError:
                    pass
            if hold_proc.poll() is None:
                try:
                    hold_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    hold_proc.kill()
                    hold_proc.communicate()
        for path in hold_paths:
            if not path:
                continue
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        for block_id, suffix in (
            (flow_block_id, "flow"), (fwd_block_id, "fwd"),
            (host_block_id, "host"), (portal_block_id, "portal"),
            (preauth_block_id, "preauth"),
        ):
            delete_admin_block(block_id, BLOCK_LABEL_PREFIX + suffix)
        delete_admin_setting(
            "preauth", preauth_id, PREAUTH_LABEL_PREFIX + "fwd"
        )
        delete_admin_blocks()
        delete_admin_settings("preauth", PREAUTH_LABEL_PREFIX)


# --------------------------------------------------------- CLI-propagáció

def scenario_cli_propagation(passwords: dict[str, str]) -> None:
    title = "K5. CLI-propagáció (HV_E2E_PENDING)"
    if not gate_on(PENDING_GATE):
        pending_skip(title, PENDING_GATE)
        return
    print(f"== {title} ==", flush=True)
    user = "e2e-cli-user"
    label = "K5/cli"
    current = passwords[user]
    try:
        # 1. fail2ban ban a futó démonon: azonnali munkamenet- és
        # conntrack-bontás, a következő /api/access nélkül.
        _revocation_login(
            user, current, "e2e-full-coll", label + "/ban",
            cookie=CLI_COOKIE,
        )
        proc = fail2ban_cli("ban", CLIENT_IP, "--seconds", "30")
        check(f"{label}/ban: CLI fail2ban ban rc=0", proc.returncode == 0,
              (proc.stderr or proc.stdout).strip()[:200])
        assert_revoked(label + "/ban")
        check_audit(label + "/ban", "fail2ban_ban", lambda row: (
            row.get("ip") == CLIENT_IP
            and int(row.get("sessions_revoked") or 0) >= 1
        ))
    finally:
        # A tiltás a kliens portál-elérését is zárja; mindenképp oldjuk fel.
        fail2ban_cli("unban", CLIENT_IP)
        admin_post("/api/admin/fail2ban", {"action": "unban", "ip": CLIENT_IP})

    # 2. CLI jelszócsere: a munkamenet és a conntrack azonnal bontandó.
    new_password = current + "-cli"
    _revocation_login(
        user, current, "e2e-full-coll", label + "/passwd",
        cookie=CLI_COOKIE,
    )
    proc = user_cli(
        "passwd", user, "--no-must-change", "--password-stdin",
        stdin=new_password + "\n",
    )
    check(f"{label}/passwd: CLI passwd rc=0", proc.returncode == 0,
          (proc.stderr or proc.stdout).strip()[:200])
    assert_revoked(label + "/passwd")
    check_audit(label + "/passwd", "cli_password_changed", lambda row: (
        row.get("target") == user
        and int(row.get("sessions_revoked") or 0) >= 1
    ))

    # 3. CLI felhasználótörlés: ugyanaz a követelmény.
    _revocation_login(
        user, new_password, "e2e-full-coll", label + "/del",
        cookie=CLI_COOKIE,
    )
    proc = user_cli("del", user)
    check(f"{label}/del: CLI user del rc=0", proc.returncode == 0,
          (proc.stderr or proc.stdout).strip()[:200])
    assert_revoked(label + "/del")
    check_audit(label + "/del", "cli_user_deleted", lambda row: (
        row.get("target") == user
        and int(row.get("sessions_revoked") or 0) >= 1
    ))


# ------------------------------------------------- több szabály együtt

def multi_rule_pair() -> tuple[str, str] | None:
    """A K6 két szabálya: HV_E2E_RULES vagy az ismert teszt-szabályok."""
    raw = os.environ.get("HV_E2E_RULES", "").strip()
    values = [item.strip() for item in raw.split(",") if item.strip()]
    if not values:
        values = list(MULTI_DEFAULT_RULES)
    if len(values) != 2 or values[0] == values[1]:
        return None
    return values[0], values[1]


def _grant_ports(value) -> list[int]:
    if not isinstance(value, list):
        return []
    return sorted({
        item for item in value
        if isinstance(item, int) and not isinstance(item, bool)
        and 1 <= item <= 65535
    })


def _normalise_grant(raw) -> dict | None:
    """Egy grant-dict normalizált alakja; ismeretlen irány esetén None."""
    if not isinstance(raw, dict):
        return None
    direction = raw.get("direction")
    if direction not in ("forward", "input"):
        return None
    return {
        "direction": direction,
        "tcp": _grant_ports(raw.get("tcp")),
        "udp": _grant_ports(raw.get("udp")),
        "icmp": bool(raw.get("icmp")),
        "full": bool(raw.get("full")),
    }


def _rule_grant_parts(
    rule: dict, catalogue: dict[str, dict],
    seen: frozenset[str] = frozenset(),
) -> list[dict] | None:
    """Egy szabály irányonkénti grantjei; gyűjtő tagjai rekurzívan.

    A ``catalogue`` a szabály-azonosítók public payloadjait tartalmazza.
    Hiányzó tag vagy körkörös hivatkozás esetén None-t ad, hogy a hívó
    egyértelműen jelezhesse a hibát a hamis PASS helyett.
    """
    rule_id = str(rule.get("id") or "")
    if rule_id and rule_id in seen:
        return None
    members = rule.get("members")
    if rule.get("collection") or (isinstance(members, list) and members):
        if not isinstance(members, list):
            return None
        parts: list[dict] = []
        for member_id in members:
            member = (
                catalogue.get(member_id)
                if isinstance(member_id, str) else None
            )
            if member is None:
                return None
            sub = _rule_grant_parts(
                member, catalogue, seen | {rule_id}
            )
            if sub is None:
                return None
            parts.extend(sub)
        return parts
    part = _normalise_grant(rule)
    return [part] if part is not None else None


def _grant_union(parts: list[dict]) -> dict[str, dict]:
    """Irányonkénti unió; egy irány full engedélye elnyeli a portokat."""
    union: dict[str, dict] = {}
    for part in parts:
        entry = union.setdefault(part["direction"], {
            "tcp": set(), "udp": set(), "icmp": False, "full": False,
        })
        if part["full"]:
            entry["full"] = True
        else:
            entry["tcp"].update(part["tcp"])
            entry["udp"].update(part["udp"])
            entry["icmp"] = entry["icmp"] or part["icmp"]
    for entry in union.values():
        if entry["full"]:
            entry["tcp"].clear()
            entry["udp"].clear()
            entry["icmp"] = False
    return {
        direction: entry for direction, entry in union.items()
        if entry["full"] or entry["tcp"] or entry["udp"] or entry["icmp"]
    }


def _grant_union_detail(union: dict[str, dict]) -> dict:
    return {
        direction: {
            "tcp": sorted(entry["tcp"]),
            "udp": sorted(entry["udp"]),
            "icmp": entry["icmp"],
            "full": entry["full"],
        }
        for direction, entry in sorted(union.items())
    }


def _grant_gaps(expected: dict[str, dict], actual: dict[str, dict]) -> dict:
    """Az actual grantből hiányzó várt elemek irányonként."""
    gaps: dict[str, list[str]] = {}
    for direction, wanted in expected.items():
        got = actual.get(direction)
        missing: list[str] = []
        if got is None:
            missing.append("teljes irány")
        elif wanted["full"]:
            if not got["full"]:
                missing.append("full")
        elif not got["full"]:
            missing.extend(
                f"tcp/{port}" for port in sorted(wanted["tcp"] - got["tcp"])
            )
            missing.extend(
                f"udp/{port}" for port in sorted(wanted["udp"] - got["udp"])
            )
            if wanted["icmp"] and not got["icmp"]:
                missing.append("icmp")
        if missing:
            gaps[direction] = missing
    return gaps


def _grant_removed(first: dict[str, dict], second: dict[str, dict]) -> list[dict]:
    """Az első választás azon elemei, amelyeket a második már nem fed."""
    removed: list[dict] = []
    for direction, old in first.items():
        new = second.get(direction) or {
            "tcp": set(), "udp": set(), "icmp": False, "full": False,
        }
        if old["full"]:
            if not new["full"]:
                removed.append({"direction": direction, "kind": "full"})
            continue
        if new["full"]:
            continue
        for port in sorted(old["tcp"] - new["tcp"]):
            removed.append({
                "direction": direction, "kind": "tcp", "port": port,
            })
        for port in sorted(old["udp"] - new["udp"]):
            removed.append({
                "direction": direction, "kind": "udp", "port": port,
            })
        if old["icmp"] and not new["icmp"]:
            removed.append({"direction": direction, "kind": "icmp"})
    return removed


def _grant_removed_present(removed: list[dict], actual: dict[str, dict]) -> list[dict]:
    """A grants-ben (még) jelen lévő, eltávolítandó elemek."""
    present: list[dict] = []
    for item in removed:
        got = actual.get(item["direction"]) or {
            "tcp": set(), "udp": set(), "icmp": False, "full": False,
        }
        kind = item["kind"]
        found = got["full"] or (
            (kind == "full" and got["full"])
            or (kind == "tcp" and item["port"] in got["tcp"])
            or (kind == "udp" and item["port"] in got["udp"])
            or (kind == "icmp" and got["icmp"])
        )
        if found:
            present.append(item)
    return present


def _nft_grant_element(item: dict) -> tuple[str, int | None] | None:
    """Egy grant-elem (halmaz, port) párja; port nélküli halmaznál None."""
    direction = item["direction"]
    kind = item["kind"]
    if kind == "full":
        return ("allowed_v4", None) if direction == "forward" else None
    if kind == "icmp":
        return ("allowed_icmp", None) if direction == "forward" else None
    if kind in ("tcp", "udp"):
        if direction == "input":
            set_name = (
                "allowed_input_tcp" if kind == "tcp"
                else "allowed_input_udp"
            )
        else:
            set_name = "allowed_tcp" if kind == "tcp" else "allowed_udp"
        return set_name, int(item["port"])
    return None


def _nft_union_elements(union: dict[str, dict]) -> list[dict]:
    elements: list[dict] = []
    for direction, entry in union.items():
        if entry["full"]:
            elements.append({"direction": direction, "kind": "full"})
            continue
        for port in sorted(entry["tcp"]):
            elements.append({
                "direction": direction, "kind": "tcp", "port": port,
            })
        for port in sorted(entry["udp"]):
            elements.append({
                "direction": direction, "kind": "udp", "port": port,
            })
        if entry["icmp"]:
            elements.append({"direction": direction, "kind": "icmp"})
    return elements


def _nft_element_report(elements: list[dict]) -> tuple[list[str], list[str]]:
    """(hiányzó, jelen lévő) nft halmazelemek a klienshez."""
    missing: list[str] = []
    present: list[str] = []
    cache: dict[str, list[dict]] = {}
    for item in elements:
        name = f"{item['direction']}/{item['kind']}"
        if "port" in item:
            name += f"/{item['port']}"
        mapping = _nft_grant_element(item)
        if mapping is None:
            # Ilyen grantet a szerver a szabályvalidációban elutasít; ha
            # mégis megjelenik, nem tudjuk ellenőrizni, ezért hibának
            # számít, nem csendes kihagyásnak.
            missing.append(f"{name} (nincs halmazleképezés)")
            continue
        set_name, port = mapping
        if set_name not in cache:
            cache[set_name] = client_entries(set_name)
        rows = cache[set_name]
        found = bool(rows) if port is None else any(
            entry.get("port") == port for entry in rows
        )
        label = f"{set_name}:{'*' if port is None else port}"
        if found:
            present.append(label)
        else:
            missing.append(label)
    return missing, present


def _selection_fields(payload: dict) -> tuple[list | None, list | None]:
    """A válasz selected_rules/grants mezői (opcionálisan session alatt)."""
    if not isinstance(payload, dict):
        return None, None
    sources = [payload]
    nested = payload.get("session")
    if isinstance(nested, dict):
        sources.append(nested)
    for source in sources:
        selected = source.get("selected_rules")
        grants = source.get("grants")
        if isinstance(selected, list) and isinstance(grants, list):
            return selected, grants
    return None, None


def _selection_state(
    access_body: dict, cookie: str
) -> tuple[list | None, list | None, str]:
    """A választás az /api/access válaszából, szükség esetén /api/statusból."""
    selected, grants = _selection_fields(access_body)
    source = "access"
    if selected is None or grants is None:
        status = client_json("status", cookie=cookie)
        selected, grants = _selection_fields(status.get("body", {}))
        source = "status"
    return selected, grants, source


def _response_grants(raw_grants) -> list[dict] | None:
    if not isinstance(raw_grants, list):
        return None
    parts: list[dict] = []
    for item in raw_grants:
        part = _normalise_grant(item)
        if part is None:
            return None
        parts.append(part)
    return parts


def scenario_multi_access(passwords: dict[str, str]) -> None:
    """K6: két szabály együttes, majd részleges választása.

    A HV_E2E_MULTI kapcsoló nélkül kihagyott. A szabálypár a HV_E2E_RULES
    vesszővel elválasztott két azonosítója, alapból a harness saját
    e2e-rev-fwd/e2e-rev-host szabályai. A forgatókönyv a saját
    tesztfelhasználóját használja, ezért a többi forgatókönyv
    szabálykiosztását nem módosítja.
    """
    title = "K6. Több szabály együttes engedélyezése (HV_E2E_MULTI)"
    if not gate_on(MULTI_GATE):
        skip(title, f"{MULTI_GATE} nincs bekapcsolva")
        return
    print(f"== {title} ==", flush=True)

    pair = multi_rule_pair()
    if pair is None:
        check(
            f"{title}: a HV_E2E_RULES két különböző szabály-azonosítót "
            "tartalmaz",
            False,
            f"kapott={os.environ.get('HV_E2E_RULES', '')!r}",
        )
        return
    first, second = pair
    label = "K6/multi"
    password = passwords.get(MULTI_USER, "")
    if not password:
        check(
            f"{label}: a tesztfelhasználó jelszava elérhető",
            False,
            f"a(z) {MULTI_USER} nem szerepel a forgatókönyv-erőforrásokban",
        )
        return

    logged_in = False
    try:
        # A szabálykiosztás a belépés előtt történik; a HV_E2E_RULES párja
        # így élő szabályokra is mutathat, ha azok léteznek és kioszthatók.
        assigned = admin_json("/api/admin/users", {
            "action": "update", "name": MULTI_USER,
            "rules": [first, second],
        })
        check(
            f"{label}: a két szabály hozzárendelve a tesztfelhasználóhoz",
            bool(assigned.get("ok")),
            str(assigned.get("error", ""))[:200],
        )
        if not assigned.get("ok"):
            return

        login = client_login(MULTI_USER, password, MULTI_COOKIE, label)
        logged_in = bool(login.get("ok"))
        if not logged_in:
            return
        login_body = login.get("body", {})

        # A várt unióhoz a szabályok public payloadja kell. Az admin state
        # a gyűjtők tagjait is tartalmazza; a belépési válasz a felhasználó
        # számára feloldott nézetet adja, ezért az utóbbi felülírja.
        rules_by_id: dict[str, dict] = {}
        state = admin_json("/api/admin/state")
        if isinstance(state.get("rules"), list):
            for row in state["rules"]:
                if isinstance(row, dict) and isinstance(row.get("id"), str):
                    rules_by_id[row["id"]] = row
        if isinstance(login_body.get("rules"), list):
            for row in login_body["rules"]:
                if isinstance(row, dict) and isinstance(row.get("id"), str):
                    rules_by_id[row["id"]] = row
        missing_rules = [rule_id for rule_id in pair if rule_id not in rules_by_id]
        check(
            f"{label}: mindkét szabály a felhasználó választható készletében "
            "van",
            not missing_rules,
            json.dumps(missing_rules),
        )
        if missing_rules:
            return

        parts_first = _rule_grant_parts(rules_by_id[first], rules_by_id)
        parts_second = _rule_grant_parts(rules_by_id[second], rules_by_id)
        check(
            f"{label}: a két szabály grantjei feloldhatók",
            parts_first is not None and parts_second is not None,
            json.dumps({first: bool(parts_first), second: bool(parts_second)}),
        )
        if parts_first is None or parts_second is None:
            return
        union_first = _grant_union(parts_first)
        union_second = _grant_union(parts_second)
        union_both = _grant_union(parts_first + parts_second)
        check(
            f"{label}: mindkét szabály ad hozzáférést",
            bool(union_first) and bool(union_second),
            json.dumps({
                first: _grant_union_detail(union_first),
                second: _grant_union_detail(union_second),
            }, sort_keys=True),
        )
        if not union_first or not union_second:
            return

        # A TTL a két szabály közül a szigorúbb max_ttl-hez igazodik.
        limits = login_body.get("limits")
        limits = limits if isinstance(limits, dict) else {}
        try:
            min_ttl = int(limits.get("min_ttl", 60))
        except (TypeError, ValueError):
            min_ttl = 60
        try:
            max_ttl = int(limits.get("max_ttl", 2592000))
        except (TypeError, ValueError):
            max_ttl = 2592000
        rule_ttls = []
        for rule_id in pair:
            value = rules_by_id[rule_id].get("max_ttl")
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                rule_ttls.append(value)
        strictest = min(rule_ttls) if rule_ttls else max_ttl
        ttl = max(min_ttl, min(120, max_ttl, strictest))
        check(
            f"{label}: a kért TTL a két szabály korlátján belül van",
            min_ttl <= ttl <= strictest and ttl <= max_ttl,
            f"ttl={ttl}, min={min_ttl}, szigorúbb max={strictest}, "
            f"globális max={max_ttl}",
        )
        if not (min_ttl <= ttl <= strictest and ttl <= max_ttl):
            return

        # (a) Mindkét szabály együttes engedélyezése.
        access_label = label + "/both"
        access = client_access(
            ",".join(pair), ttl, MULTI_COOKIE, access_label
        )
        selected, raw_grants, source = _selection_state(
            access.get("body", {}), MULTI_COOKIE
        )
        check(
            f"{access_label}: a selected_rules a megadott sorrendben "
            "tartalmazza mindkét szabályt",
            selected == list(pair),
            f"forrás={source}, kapott={json.dumps(selected)}",
        )
        parts = _response_grants(raw_grants)
        check(
            f"{access_label}: a grants lista olvasható",
            parts is not None,
            json.dumps(raw_grants)[:400],
        )
        if parts is None:
            return
        actual = _grant_union(parts)
        gaps = _grant_gaps(union_both, actual)
        check(
            f"{access_label}: a grants lefedi a két szabály unióját",
            not gaps,
            f"hiányzó={json.dumps(gaps, sort_keys=True)}; "
            f"kapott={json.dumps(_grant_union_detail(actual), sort_keys=True)}",
        )
        expected_elements = _nft_union_elements(union_both)
        missing, _present = _nft_element_report(expected_elements)
        check(
            f"{access_label}: az nft halmazok tartalmazzák az unió elemeit",
            not missing,
            f"hiányzó={json.dumps(missing)}",
        )

        # (b) Csak a második szabály. Az első azon elemei, amelyeket a
        # második nem fed, a válaszból és a kernelből is el kell tűnjenek.
        second_label = label + "/second"
        access = client_access(second, ttl, MULTI_COOKIE, second_label)
        selected, raw_grants, source = _selection_state(
            access.get("body", {}), MULTI_COOKIE
        )
        check(
            f"{second_label}: a selected_rules csak a második szabályt "
            "tartalmazza",
            selected == [second],
            f"forrás={source}, kapott={json.dumps(selected)}",
        )
        parts = _response_grants(raw_grants)
        check(
            f"{second_label}: a grants lista olvasható",
            parts is not None,
            json.dumps(raw_grants)[:400],
        )
        if parts is None:
            return
        actual = _grant_union(parts)
        gaps = _grant_gaps(union_second, actual)
        check(
            f"{second_label}: a grants lefedi a második szabály unióját",
            not gaps,
            f"hiányzó={json.dumps(gaps, sort_keys=True)}; "
            f"kapott={json.dumps(_grant_union_detail(actual), sort_keys=True)}",
        )
        missing_second, _present_second = _nft_element_report(
            _nft_union_elements(union_second)
        )
        check(
            f"{second_label}: a megmaradt második szabály elemei a "
            "kernelben maradtak",
            not missing_second,
            f"hiányzó={json.dumps(missing_second)}",
        )
        removed = _grant_removed(union_first, union_second)
        if removed:
            still_granted = _grant_removed_present(removed, actual)
            check(
                f"{second_label}: az első szabály már le nem fedett elemei "
                "nincsenek a grants-ben",
                not still_granted,
                json.dumps(still_granted, sort_keys=True),
            )
            _missing_nft, still_present = _nft_element_report(removed)
            check(
                f"{second_label}: az első szabály egyedi elemei eltűntek az "
                "nft halmazokból",
                not still_present,
                f"még jelen: {json.dumps(still_present)}",
            )
        else:
            skip(
                f"{second_label}: eltávolított elemek ellenőrzése",
                "a két szabály grantje azonos, nincs egyedi eltávolítható elem",
            )

        # (c) Mindkét szabály visszaállítása: az unió újra érvényes.
        restored_label = label + "/restored"
        access = client_access(
            ",".join(pair), ttl, MULTI_COOKIE, restored_label
        )
        selected, raw_grants, source = _selection_state(
            access.get("body", {}), MULTI_COOKIE
        )
        check(
            f"{restored_label}: a selected_rules ismét mindkét szabályt "
            "tartalmazza",
            selected == list(pair),
            f"forrás={source}, kapott={json.dumps(selected)}",
        )
        parts = _response_grants(raw_grants)
        check(
            f"{restored_label}: a grants lista olvasható",
            parts is not None,
            json.dumps(raw_grants)[:400],
        )
        if parts is None:
            return
        actual = _grant_union(parts)
        gaps = _grant_gaps(union_both, actual)
        check(
            f"{restored_label}: a grants ismét lefedi a két szabály unióját",
            not gaps,
            f"hiányzó={json.dumps(gaps, sort_keys=True)}; "
            f"kapott={json.dumps(_grant_union_detail(actual), sort_keys=True)}",
        )
        missing, _present = _nft_element_report(expected_elements)
        check(
            f"{restored_label}: az nft halmazok ismét tartalmazzák az unió "
            "elemeit",
            not missing,
            f"hiányzó={json.dumps(missing)}",
        )
    finally:
        if logged_in:
            try:
                client_json("logout", cookie=MULTI_COOKIE)
            except Exception:
                pass


# --------------------------------------------------------- újraindítás

def portal_ready() -> bool:
    try:
        with urllib.request.urlopen(
            ADMIN_BASE + "/api/challenge", timeout=2
        ) as response:
            return response.status == 200
    except Exception:
        return False


def _compose_up(mode: str | None) -> subprocess.CompletedProcess:
    """Konténer újraindítása a megadott HV_FLUSH_ON_START értékkel.

    ``mode=None`` az alapértelmezett (HV_FLUSH_ON_START=1) visszaállítás.
    A HV_ALLOW_STALE_GRANTS_ON_START-ot mindig kivesszük, így a 0 mód is
    a biztonságos, ürítő ágat használja.
    """
    env = dict(os.environ)
    env.pop("HV_ALLOW_STALE_GRANTS_ON_START", None)
    if mode is None:
        env.pop("HV_FLUSH_ON_START", None)
    else:
        env["HV_FLUSH_ON_START"] = mode
    return subprocess.run(
        ["docker", "compose", "up", "-d", "--force-recreate", "hatarvedelem"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=300,
    )


def _write_json_atomic(path: str, payload: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _read_json_file(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def restart_helper_main(argv: list[str]) -> int:
    """Leválasztott segédfolyamat: újraindít, állapotot ír, majd visszaállít.

    A marker fájl hiánya esetén legkésőbb a megadott idő után akkor is
    visszaállítja az alapértelmezett üzemmódot, hogy egy megszakadt SSH
    ne hagyja a portált ideiglenes beállításokkal.
    """
    if len(argv) < 4:
        return 2
    mode, state_path, marker_path, timeout_raw = argv[:4]
    try:
        timeout = max(30, int(timeout_raw))
    except ValueError:
        timeout = RESTART_TIMEOUT
    state: dict = {"mode": mode, "phase": "starting"}

    def save(**fields) -> None:
        state.update(fields)
        try:
            _write_json_atomic(state_path, state)
        except OSError:
            pass

    try:
        save(phase="restarting")
        result = _compose_up(mode)
        state["up_rc"] = result.returncode
        state["up_output"] = (result.stdout + result.stderr)[-1500:]
        ready = wait_condition(portal_ready, 120, 2)
        state["ready"] = ready
        state["sets"] = {
            name: [
                entry for entry in nft_json_entries(name)
                if entry.get("address") == CLIENT_IP
            ]
            for name in NFT_SETS
        }
        # A per-szet olvasás hiba esetén üres listát ad, ezért külön
        # rögzítjük, hogy maga az nft tábla olvasható volt-e. Enélkül egy
        # sikertelen nft-hívás hamis „nincs maradék engedély” eredményt adna.
        table = subprocess.run(
            ["nft", "list", "table", "inet", "hatarvedelem"],
            capture_output=True, text=True,
        )
        state["table_ok"] = table.returncode == 0
        # A conntrack hiánya nem bizonyíték az ürességre: None-ként mentjük,
        # és a hívó ilyenkor SKIPpel, nem PASS-szal jelent.
        state["conntrack"] = _conntrack_lines()
        save(phase="up")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if os.path.exists(marker_path):
                break
            time.sleep(1)
        state["marker_seen"] = os.path.exists(marker_path)
        save(phase="restoring")
        restore = _compose_up(None)
        state["restore_rc"] = restore.returncode
        state["restore_output"] = (restore.stdout + restore.stderr)[-1500:]
        state["restore_ready"] = wait_condition(portal_ready, 120, 2)
        save(phase="restored")
        return 0 if state.get("ready") and state.get("restore_ready") else 1
    except Exception as exc:
        save(phase="error", error=f"{type(exc).__name__}: {exc}"[:300])
        try:
            restore = _compose_up(None)
            state["restore_rc"] = restore.returncode
            state["restore_ready"] = wait_condition(portal_ready, 120, 2)
            save(phase="restored")
        except Exception as restore_exc:
            save(phase="error", restore_error=str(restore_exc)[:200])
        return 1


def _start_restart_helper(mode: str) -> subprocess.Popen:
    global RESTART_MARKER, RESTART_STATE, RESTART_LOG
    stamp = f"{os.getpid()}-{mode}-{int(time.time())}"
    RESTART_STATE = f"/tmp/hv-e2e-restart-{stamp}.json"
    RESTART_MARKER = f"/tmp/hv-e2e-restart-{stamp}.continue"
    RESTART_LOG = f"/tmp/hv-e2e-restart-{stamp}.log"
    for path in (RESTART_STATE, RESTART_MARKER, RESTART_LOG):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    log = open(RESTART_LOG, "ab")
    try:
        return subprocess.Popen(
            [
                sys.executable, os.path.abspath(__file__),
                "restart-helper", mode, RESTART_STATE, RESTART_MARKER,
                str(RESTART_TIMEOUT),
            ],
            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True, close_fds=True,
        )
    finally:
        log.close()


def scenario_restart_matrix(passwords: dict[str, str]) -> None:
    title = "K4. Újraindítási mátrix (HV_E2E_RESTART)"
    if not gate_on(RESTART_GATE):
        skip(title, f"{RESTART_GATE} nincs bekapcsolva")
        return
    print(f"== {title} ==", flush=True)
    print("FIGYELEM: ez a forgatókönyv újraindítja a hatarvedelem konténert, "
          "és a tűzfal újratöltése megszakíthatja az SSH-kapcsolatot.",
          flush=True)
    print("FIGYELEM: a leválasztott segédfolyamat legkésőbb "
          f"{RESTART_TIMEOUT} s múlva akkor is visszaállítja az "
          "alapértelmezett üzemmódot, ha a teszt megszakad.", flush=True)
    user = "e2e-exp-user"
    label = "K4/restart"
    global RESTART_MARKER
    try:
        for mode in ("1", "true", "0"):
            mode_label = f"{label}/{mode}"
            client_login(user, passwords[user], EXPIRY_COOKIE, mode_label)
            client_access("e2e-full-coll", 300, EXPIRY_COOKIE, mode_label)
            verify_grant_elements(mode_label, expected_grant_entries())
            generate_traffic(mode_label)

            helper = _start_restart_helper(mode)
            state_path = RESTART_STATE
            up = wait_condition(
                lambda: _read_json_file(state_path).get("phase") in
                ("up", "error", "restored"),
                180, 1.0,
            )
            state = _read_json_file(state_path)
            check(f"{mode_label}: a segédfolyamat elindult", up,
                  json.dumps({k: state.get(k) for k in ("phase", "up_rc", "error")}))
            check(f"{mode_label}: a portál újraindult", bool(state.get("ready")),
                  json.dumps({k: state.get(k) for k in ("phase", "up_rc")}))
            check(
                f"{mode_label}: az nft tábla olvasható az újraindítás után",
                bool(state.get("table_ok")),
                json.dumps({k: state.get(k) for k in ("phase", "up_rc")}),
            )
            sets = state.get("sets") if isinstance(state.get("sets"), dict) else {}
            missing_sets = [name for name in NFT_SETS if name not in sets]
            stale = {
                name: rows for name, rows in sets.items() if rows
            }
            check(
                f"{mode_label}: minden halmaz állapota kiolvasható",
                not missing_sets, json.dumps(missing_sets),
            )
            check(
                f"{mode_label}: nincs maradék engedély egyik halmazban sem",
                not stale, json.dumps(stale)[:400],
            )
            conntrack_state = state.get("conntrack")
            if not isinstance(conntrack_state, list):
                skip(
                    f"{mode_label}: nincs maradék conntrack bejegyzés",
                    "a conntrack eszköz nem érhető el",
                )
            else:
                check(
                    f"{mode_label}: nincs maradék conntrack bejegyzés",
                    not conntrack_state,
                    json.dumps(conntrack_state)[:400],
                )
            # Az admin munkamenet a konténer újraindításakor megszűnt; az
            # admin_get automatikusan újra belép a tárolt jelszóval.
            sessions = admin_sessions_for_ip()
            if sessions is None:
                skip(f"{mode_label}: nincs kliens munkamenet",
                     "az admin munkamenet-lista nem érhető el")
            else:
                check(f"{mode_label}: nincs kliens munkamenet",
                      not sessions,
                      json.dumps([row.get("id") for row in sessions]))
            # Engedjük tovább a segédfolyamatot, és várjuk meg a visszaállást.
            with open(RESTART_MARKER, "w", encoding="utf-8") as fh:
                fh.write("continue\n")
            restored = wait_condition(
                lambda: _read_json_file(state_path).get("phase") == "restored",
                240, 1.0,
            )
            final = _read_json_file(state_path)
            check(f"{mode_label}: az alapértelmezett üzemmód visszaállt",
                  restored and bool(final.get("restore_ready")),
                  json.dumps({k: final.get(k)
                              for k in ("phase", "restore_rc", "restore_ready")}))
            try:
                helper_rc = helper.wait(timeout=15)
            except subprocess.TimeoutExpired:
                helper_rc = None
            check(f"{mode_label}: a segédfolyamat lefutott",
                  helper_rc is not None, f"rc={helper_rc}")
            try:
                os.unlink(RESTART_MARKER)
            except FileNotFoundError:
                pass
            RESTART_MARKER = ""
    finally:
        if RESTART_MARKER:
            try:
                with open(RESTART_MARKER, "w", encoding="utf-8") as fh:
                    fh.write("cleanup\n")
            except OSError:
                pass
            wait_condition(
                lambda: _read_json_file(RESTART_STATE).get("phase") == "restored",
                240, 2.0,
            )


# ------------------------------------------------------- host oldali takarítás

def _admin_tolerant_request(path: str, payload: dict) -> bool:
    try:
        code, text = admin_post(path, payload)
    except Exception:
        return False
    if code == 200:
        return True
    data = safe_json(text)
    message = str(data.get("error", "")) if isinstance(data, dict) else str(data)
    return "nincs ilyen" in message


def terminate_client_sessions() -> None:
    """A kliens IP esetlegesen maradt munkameneteinek lezárása adminból."""
    try:
        sessions = admin_sessions_for_ip()
    except Exception:
        return
    if sessions is None:
        return
    for row in sessions:
        session_id = row.get("id")
        if isinstance(session_id, str) and session_id:
            _admin_tolerant_request("/api/admin/sessions", {
                "action": "terminate", "id": session_id,
            })


def host_admin_cleanup() -> bool:
    """A kiterjesztett erőforrások eltakarítása a loopback admin sütivel.

    Akkor használjuk, ha a kliens oldali újrabejelentkezés (pl. 429 miatt)
    nem sikerül. Nem törli a tesztfelhasználót; azt a main finally CLI-vel
    távolítja el.
    """
    global _admin_portal
    if _admin_portal is None:
        if not _admin_password or not _admin_login(_admin_password):
            return False
    # Az admin munkamenet a konténer-újraindítás után elavult lehet; ez a
    # hívás 403 esetén automatikusan újra belép. Hálózati hiba esetén a
    # hívó a kliens oldali takarításra vált.
    try:
        code, _text = admin_get("/api/admin/state")
    except Exception:
        return False
    if code != 200:
        return False
    problems = 0
    try:
        delete_admin_blocks()
        delete_admin_settings("preauth", PREAUTH_LABEL_PREFIX)
        leftovers = any(
            str(row.get("label", "")).startswith(BLOCK_LABEL_PREFIX)
            for row in admin_blocks()
        ) or any(
            str(row.get("label", "")).startswith(PREAUTH_LABEL_PREFIX)
            for row in admin_setting_entries("preauth")
        )
    except Exception:
        leftovers = True
    if leftovers:
        problems += 1
    for group_id in SCENARIO_GROUPS:
        if not _admin_tolerant_request("/api/admin/groups", {
            "action": "delete", "id": group_id,
        }):
            problems += 1
    for rule_id in CLEANUP_RULES:
        if not _admin_tolerant_request("/api/admin/rules", {
            "action": "delete", "id": rule_id,
        }):
            problems += 1
    for name in SCENARIO_USERS:
        if not _admin_tolerant_request("/api/admin/users", {
            "action": "delete", "name": name,
        }):
            problems += 1
    if not _admin_tolerant_request("/api/admin/fail2ban", {
        "action": "unban", "ip": CLIENT_IP,
    }):
        problems += 1
    return problems == 0


def usage_text() -> str:
    return f"""Dropjak végponttól végpontig teszt (host mód)

Használat:
  python3 tests/e2e_vm.py            # teljes futás a teszt-VM hostján
  python3 tests/e2e_vm.py --help     # ez a súgó (nincs hálózati művelet)

A host mód a kliens lépéseket a hvclient hálózati névtérből futtatja, a
tűzfalhalmazokat a host névterében ellenőrzi, a végén pedig eltakarít.

Kiterjesztett forgatókönyvek (alapból minden kapcsoló KI):
  K1. Visszavonási utak                   admin API szükséges
  K2. Természetes lejárat                 HV_E2E_LONG=1
  K3. Blokk elsőbbsége                    HV_E2E_PENDING=1
  K4. Újraindítási mátrix                 HV_E2E_RESTART=1
  K5. CLI-propagáció                      HV_E2E_PENDING=1
  K6. Több szabály együttes engedélyezése HV_E2E_MULTI=1
      HV_E2E_RULES=elso,masodik           (alap: e2e-rev-fwd,e2e-rev-host)

További környezeti változók: E2E_LONG_MAX_WAIT, E2E_USER, E2E_PASS,
E2E_NEW_PASS, E2E_ADMIN_BASE, E2E_ADMIN_COOKIE, E2E_COOKIE,
E2E_SCEN_COOKIE, E2E_EXPIRY_COOKIE, E2E_CLI_COOKIE, E2E_BLOCK_COOKIE,
E2E_MULTI_COOKIE, HV_CONNTRACK_BIN.
"""


def main() -> int:
    password = secrets.token_urlsafe(18)
    new_password = password + "-v2"

    user_cli("del", USER)  # esetleges maradék eltakarítása
    # A tesztfelhasználó admin, hogy a host SSH-hez szükséges, kifejezetten
    # 22/TCP-t engedélyező host szabályt és a vegyes gyűjtőt az admin API-n
    # keresztül létrehozhassa, majd hozzárendelhesse önmagához. A szabályok
    # nem részei a seedelt készletnek, ezért a teszt hozza létre és törli.
    created = user_cli(
        "add", USER, "--role", "admin", "--rule", "browse",
        "--password-stdin", stdin=password + "\n",
    )
    if created.returncode != 0:
        print(f"HIBA: a tesztfelhasználó létrehozása nem sikerült: {created.stderr.strip()}")
        return 2

    logout_done = False
    extended_started = False
    try:
        print("== 0. Kiinduló állapot ==", flush=True)
        page = client_json("page")
        check("portál oldal betölt", page.get("code") == "200")
        check("szabályválasztó a felületen", bool(page.get("rules")))
        check("admin panel a felületen", bool(page.get("admin_panel")))
        check("TTL mező a felületen", bool(page.get("ttl")))
        check("nincs óra/perc TTL választó a felületen", bool(page.get("ttl_unit_absent")))
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
        check("login: a felhasználó szabályai megvannak",
              "browse" in rule_ids and "admin-full" not in rule_ids,
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
        check("limitek: 60–2592000 másodperc",
              limits.get("min_ttl") == 60 and limits.get("max_ttl") == 2592000,
              json.dumps(limits))

        # A host SSH-hoz kifejezetten 22/TCP-t engedélyező, a felhasználóhoz
        # rendelt host szabály kell. A szabály és a vegyes gyűjtő létrehozása
        # admin API-val történik; a saját szabályok frissítése után újra kell
        # jelentkezni.
        seeded = client_json("admin-seed")
        check("admin: host SSH és vegyes gyűjtő létrehozva, hozzárendelve",
              bool(seeded.get("ok")), json.dumps(seeded))
        relogin = client_json("login", password=new_password)
        check("új belépés a szabály-kiosztás után", bool(relogin.get("ok")),
              json.dumps(relogin.get("body")))
        rule_ids = [
            rule.get("id") for rule in relogin.get("body", {}).get("rules", [])
        ]
        check("az új szabályok a felhasználónál vannak",
              "host-e2e" in rule_ids and "e2e-combo" in rule_ids
              and "admin-full" not in rule_ids, json.dumps(rule_ids))

        legacy = client_json("access", gateway.LEGACY_ADMIN_RULE_ID, "60")
        check("a fenntartott admin-full szabály nem kérhető (400)",
              legacy.get("code") == 400, json.dumps(legacy.get("body")))

        blocked = client_json("check")
        check("bejelentkezés előtt: HTTP a portálra terelve",
              blocked.get("http_portal") is True, json.dumps(blocked))
        check("bejelentkezés előtt: HTTPS tiltva", blocked.get("https") is False)
        check("bejelentkezés előtt: DNS tiltva", blocked.get("dns") is False)
        check("bejelentkezés előtt: ping tiltva", blocked.get("ping") is False)
        check("bejelentkezés előtt: host SSH tiltva", blocked.get("host_ssh") is False)
        state = nft_state("bejelentkezés előtt")
        check("nft: host SSH halmaz üres", not state["host_ssh"])
        check("nft: MAC-kötés nincs", not state["mac"])

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
        check("browse: host SSH nem nyílt meg", web.get("host_ssh") is False, json.dumps(web))
        state = nft_state("browse után")
        check("nft: allowed_tcp tartalmazza a klienst", state["tcp"])
        check("nft: allowed_udp tartalmazza a klienst", state["udp"])
        check("nft: allowed_v4 nem tartalmazza a klienst", not state["v4"])
        check("nft: allowed_icmp nem tartalmazza a klienst", not state["icmp"])
        check("nft: host SSH halmaz üres", not state["host_ssh"])
        check("nft: MAC-kötés rögzítve", state["mac"])
        expected_mac = client_mac()
        mac_entries = nft_json_entries("client_mac")
        bound = [
            entry.get("mac") for entry in mac_entries
            if entry.get("address") == CLIENT_IP
        ]
        check("nft JSON: a MAC-kötés olvasható",
              bool(bound) and all(mac and len(mac) == 17 for mac in bound),
              json.dumps(mac_entries))
        if expected_mac:
            check("nft JSON: a MAC az ARP-ból származik",
                  bound and bound[0] == expected_mac,
                  f"várt={expected_mac} kapott={bound}")
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
        input_entries = nft_json_entries("allowed_input_tcp")
        check("nft JSON: browse nem nyit host SSH-t",
              not any(entry.get("address") == CLIENT_IP for entry in input_entries),
              json.dumps(input_entries))

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
        check("full: host SSH nem nyílt meg", full.get("host_ssh") is False,
              json.dumps(full))
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

        print("== 3b. Host SSH szabály (22/TCP input) ==", flush=True)
        access = client_json("access", "host-e2e", "60")
        check("access host-e2e: 200", bool(access.get("ok")),
              json.dumps(access.get("body")))
        grant = access.get("body", {}).get("grant", {})
        check("access host-e2e: input irány, nincs teljes hozzáférés",
              grant.get("direction") == "input" and grant.get("full") is False,
              json.dumps(grant))
        admin = client_json("check")
        check("host-e2e: host SSH megnyílt", admin.get("host_ssh") is True,
              json.dumps(admin))
        check("host-e2e: forward forgalom nem nyílt meg",
              admin.get("http_external") is False and admin.get("dns") is False,
              json.dumps(admin))
        state = nft_state("host-e2e után")
        check("nft: host SSH a közönséges input TCP halmazban van",
              state["host_ssh"], json.dumps(state))
        check("nft: nincs külön host SSH halmaz", "host_ssh_v4" not in snap)
        ssh_entries = nft_json_entries("allowed_input_tcp")
        client_ssh = [
            entry for entry in ssh_entries
            if entry.get("address") == CLIENT_IP and entry.get("port") == 22
        ]
        check("nft JSON: a host SSH engedély olvasható", bool(client_ssh),
              json.dumps(ssh_entries))
        check("nft JSON: a host SSH engedély TTL-je olvasható",
              all(isinstance(entry.get("timeout"), int) and entry["timeout"] > 0
                  for entry in client_ssh),
              json.dumps(client_ssh))

        print("== 4. Visszaváltás böngészésre ==", flush=True)
        access = client_json("access", "browse", "60")
        check("access browse újra: 200", bool(access.get("ok")), json.dumps(access.get("body")))
        back = client_json("check")
        check("browse: ping visszavonva", back.get("ping") is False, json.dumps(back))
        check("browse: host SSH visszavonva", back.get("host_ssh") is False,
              json.dumps(back))
        check("browse: HTTP továbbra is kimegy", back.get("http_external") is True)
        check("browse: DNS továbbra is működik", back.get("dns") is True)
        snap = snapshot()["text"]
        check("nft: allowed_v4 kiürült", not set_has(snap, "allowed_v4", CLIENT_IP))
        check("nft: allowed_icmp kiürült", not set_has(snap, "allowed_icmp", CLIENT_IP))
        input_entries = nft_json_entries("allowed_input_tcp")
        check("nft: host SSH (input TCP 22) kiürült",
              not any(
                  entry.get("address") == CLIENT_IP
                  and entry.get("port") == 22
                  for entry in input_entries
              ), json.dumps(input_entries))

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
        access = client_json("access", "e2e-combo", "60")
        check("lejárat: vegyes gyűjtő engedélyezve 60 másodpercre",
              bool(access.get("ok")),
              json.dumps(access.get("body", {}).get("error")))
        before = client_json("check")
        check("lejárat előtt: HTTP kimegy", before.get("http_external") is True, json.dumps(before))
        check("lejárat előtt: DNS működik", before.get("dns") is True, json.dumps(before))
        check("lejárat előtt: host SSH működik", before.get("host_ssh") is True, json.dumps(before))
        check("lejárat előtt: ping nem engedélyezett", before.get("ping") is False)
        state = nft_state("lejárat előtt")
        check("nft: host SSH input TCP 22 tartalmazza a klienst", state["host_ssh"])
        print("    várakozás a lejáratig (65 s)...", flush=True)
        time.sleep(65)
        expired = client_json("check")
        check("lejárat után: DNS tiltva", expired.get("dns") is False, json.dumps(expired))
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

        # ------------------------------------------------ kiterjesztett kör
        print("== Kiterjesztett forgatókönyvek ==", flush=True)
        extended_started = True
        # Egy megszakadt előző futás tiltása ne zárja ki a klienst.
        fail2ban_cli("unban", CLIENT_IP)
        admin_ok = ensure_admin(new_password, password)
        check("kiterjesztett: admin API elérhető loopbackról", admin_ok)
        passwords_ext = None
        if admin_ok:
            # A korábbi futás maradékainak eltakarítása; a létrehozók
            # egyébként is idempotensek, de így nem halmozódnak a blokkok.
            admin_post("/api/admin/fail2ban", {
                "action": "unban", "ip": CLIENT_IP,
            })
            host_admin_cleanup()
            passwords_ext = ensure_scenario_resources()
        if passwords_ext and admin_ok:
            # Sorrend: visszavonás, több szabály, természetes lejárat, blokk,
            # CLI, majd a legutolsóként az újraindítás (az mindent kiürít).
            # Egy váratlan kivétel ne akassza meg a többi forgatókönyvet és
            # a takarítást.
            scenarios = (
                ("K1. Visszavonási utak",
                 scenario_revocation_matrix, (passwords_ext,)),
                ("K6. Több szabály együttes engedélyezése (HV_E2E_MULTI)",
                 scenario_multi_access, (passwords_ext,)),
                ("K2. Természetes lejárat (HV_E2E_LONG)",
                 scenario_natural_expiry,
                 (passwords_ext, int(limits.get("min_ttl", 60)))),
                ("K3. Blokk elsőbbsége (HV_E2E_PENDING)",
                 scenario_block_precedence, (passwords_ext,)),
                ("K5. CLI-propagáció (HV_E2E_PENDING)",
                 scenario_cli_propagation, (passwords_ext,)),
                ("K4. Újraindítási mátrix (HV_E2E_RESTART)",
                 scenario_restart_matrix, (passwords_ext,)),
            )
            for scenario_title, scenario_func, scenario_args in scenarios:
                try:
                    scenario_func(*scenario_args)
                except Exception as exc:
                    check(
                        f"{scenario_title}: végrehajtás",
                        False,
                        f"{type(exc).__name__}: {exc}"[:300],
                    )
        else:
            for title in (
                "K1. Visszavonási utak",
                "K6. Több szabály együttes engedélyezése (HV_E2E_MULTI)",
                "K2. Természetes lejárat (HV_E2E_LONG)",
                "K3. Blokk elsőbbsége (HV_E2E_PENDING)",
                "K5. CLI-propagáció (HV_E2E_PENDING)",
                "K4. Újraindítási mátrix (HV_E2E_RESTART)",
            ):
                skip(title, "az admin API vagy a forgatókönyv-erőforrások "
                            "nem érhetők el")
    finally:
        # Ha az újraindítási forgatókönyv félbeszakadt, a markerrel engedjük
        # tovább a segédfolyamatot, és várjuk meg a visszaállítást. Ez akkor
        # is lefut, ha a teszt közben kivétel történt.
        if RESTART_MARKER:
            try:
                with open(RESTART_MARKER, "w", encoding="utf-8") as fh:
                    fh.write("cleanup\n")
            except OSError:
                pass
            if not wait_condition(
                lambda: _read_json_file(RESTART_STATE).get("phase") == "restored",
                240, 2.0,
            ):
                print(
                    "FIGYELEM: az újraindítási segédfolyamat 240 s alatt nem "
                    "jelzett visszaállást; ellenőrizd a portál állapotát.",
                    flush=True,
                )
        if not logout_done and not extended_started:
            try:
                run_client("logout")
            except Exception:
                pass
        if extended_started:
            # A fail2ban tiltás a kliens portál-elérését is zárja.
            try:
                fail2ban_cli("unban", CLIENT_IP)
            except Exception:
                pass
        try:
            cleaned = host_admin_cleanup() if extended_started else False
        except Exception:
            cleaned = False
        if extended_started and cleaned:
            # Adminból zárjuk le az esetleg maradt kliens munkamenetet.
            terminate_client_sessions()
        if not cleaned:
            # A teszt által létrehozott szabályok eltakarítása. Ha a
            # jelszócsere már megtörtént, az új jelszóval lehet belépni.
            # A 429-es belépési korlátot kivárjuk.
            for candidate in (new_password, password):
                relogin = None
                for attempt in range(3):
                    relogin = run_client("login", password=candidate)
                    if relogin.returncode == 0:
                        break
                    parsed = safe_json(relogin.stdout.strip())
                    code = parsed.get("code") if isinstance(parsed, dict) else None
                    if code != 429:
                        break
                    time.sleep(61)
                if relogin is not None and relogin.returncode == 0:
                    client_json("admin-cleanup")
                    run_client("logout")
                    break
        try:
            deleted = user_cli("del", USER)
            delete_rc = deleted.returncode
        except Exception:
            delete_rc = 1
        if delete_rc != 0:
            _admin_tolerant_request("/api/admin/users", {
                "action": "delete", "name": USER,
            })
        for path in (COOKIE, ADMIN_COOKIE, SCEN_COOKIE, EXPIRY_COOKIE,
                     CLI_COOKIE, BLOCK_COOKIE, MULTI_COOKIE):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        for path in (RESTART_MARKER, RESTART_STATE, RESTART_LOG):
            if not path:
                continue
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    print()
    print(
        f"ÖSSZEGZÉS: {passed} PASS, {len(skipped)} SKIP, "
        f"{len(pending)} PENDING, {len(failures)} FAIL",
        flush=True,
    )
    if pending:
        print("PENDING (a kapcsoló nincs bekapcsolva, nem hiba):", flush=True)
        for item in pending:
            print(f"  - {item}", flush=True)
    if skipped:
        print("SKIP:", flush=True)
        for item in skipped:
            print(f"  - {item}", flush=True)
    if failures:
        print(f"SIKERTELEN: {len(failures)} ellenőrzés bukott:", flush=True)
        for item in failures:
            print(f"  - {item}", flush=True)
        return 1
    print("MINDEN ELLENŐRZÉS SIKERES", flush=True)
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--help", "-h"):
        print(usage_text())
        raise SystemExit(0)
    if len(sys.argv) > 1 and sys.argv[1] == "client":
        raise SystemExit(client_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "restart-helper":
        raise SystemExit(restart_helper_main(sys.argv[2:]))
    raise SystemExit(main())
