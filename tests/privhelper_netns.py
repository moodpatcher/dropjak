#!/usr/bin/env python3
"""The privileged helper end to end in a user+net namespace (without root).

Run:  unshare -rn python3 tests/privhelper_netns.py

The real, rendered template is loaded; privhelper.py runs as a separate
process on a socket in a temporary directory, and a RemoteFirewall (the
portal side) drives it: replace_custom, grant/revoke, bans, host guards,
state_token, healthy, the input-chain check and the snapshot. The kernel
state is read back with nft. Injection attempts and unknown verbs must be
refused with the table intact; a killed helper must make grants fail and a
restarted one must serve again.

Output: JSON with the checks; exit code 0 if everything is fine.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
TMP = tempfile.mkdtemp(prefix="dropjak-helper-")
SOCKET = os.path.join(TMP, "helper.sock")
ENV = {
    "HV_WAN_IF": "eth0",
    "HV_LAN_IF": "eth1",
    "HV_LAN_NET": "192.168.10.0/24",
    "HV_PORTAL_NET": "0.0.0.0/0",
    "PORT": "8100",
    "HV_TUNNEL_RUN_DIR": TMP,
    "HV_STATE_DIR": TMP,
}
os.environ.update(ENV)
os.environ["HV_PRIV_HELPER"] = SOCKET
for path in (str(ROOT), str(TESTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

import gateway  # noqa: E402
from test_single_nic import render  # noqa: E402

T = "inet hatarvedelem"
CLIENT = "198.51.100.7"
checks: dict[str, dict] = {}


def check(name: str, ok: bool, detail="") -> None:
    checks[name] = {"ok": bool(ok), "detail": str(detail)[:2000]}


def nft(*args: str) -> str:
    return subprocess.run(
        ["nft", *args], capture_output=True, text=True, timeout=30
    ).stdout


def start_helper() -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "privhelper.py"), "--socket", SOCKET,
         "--allow-uid", str(os.getuid())],
        env={**os.environ, "HV_PRIV_HELPER": SOCKET},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc


def main() -> int:
    rendered = render(ENV)
    path = os.path.join(TMP, "dropjak.nft")
    Path(path).write_text(rendered, encoding="utf-8")
    load = subprocess.run(["nft", "-f", path], capture_output=True, text=True)
    if load.returncode != 0:
        print(json.dumps({"ok": False, "error": load.stderr[-2000:]}))
        return 1

    helper = start_helper()
    try:
        fw = gateway.make_firewall()
        check("remote_firewall", isinstance(fw, gateway.RemoteFirewall))
        check("ready", fw.wait_ready(15))

        fw.replace_custom(
            [{"id": "p1", "proto": "tcp", "ports": [443],
              "dst": "203.0.113.0/24", "enabled": True}],
            [{"id": "b1", "proto": "tcp", "ports": [25], "enabled": True}],
        )
        preauth = nft("list", "chain", "inet", "hatarvedelem", "preauth")
        block = nft("list", "chain", "inet", "hatarvedelem", "block")
        check("replace_custom_preauth", "203.0.113.0/24" in preauth, preauth)
        check("replace_custom_block", "dport 25" in block or "proto-dst 25" in block, block)

        token = fw.state_token()
        check("state_token", isinstance(token, int), token)
        check("healthy", fw.healthy() == (True, "ok"), fw.healthy())
        check(
            "input_chain_consistent",
            fw.input_chain_consistent(8100) == (True, "ok"),
            fw.input_chain_consistent(8100),
        )

        grants = (
            gateway.Ports(tcp=(80, 443)),
            gateway.Ports(tcp=(22,), direction="input"),
        )
        fw.grant_all(CLIENT, grants, 600)
        fwd = nft("list", "set", "inet", "hatarvedelem", "allowed_tcp")
        inp = nft("list", "set", "inet", "hatarvedelem", "allowed_input_tcp")
        check("grant_forward", f"{CLIENT} . 80" in fwd and f"{CLIENT} . 443" in fwd, fwd)
        check("grant_input", f"{CLIENT} . 22" in inp, inp)
        snapshot = fw.snapshot()
        check(
            "snapshot",
            any(item.get("address") == CLIENT for item in snapshot["sets"]["allowed_tcp"]),
            snapshot["sets"]["allowed_tcp"],
        )

        fw.revoke_all(CLIENT, grants)
        fwd = nft("list", "set", "inet", "hatarvedelem", "allowed_tcp")
        inp = nft("list", "set", "inet", "hatarvedelem", "allowed_input_tcp")
        check("revoke", CLIENT not in fwd and CLIENT not in inp, fwd + inp)

        fw.ban("203.0.113.9", 600)
        fw.proxy_ban("203.0.113.10", 600)
        bans = nft("list", "set", "inet", "hatarvedelem", "banned_v4")
        proxy = nft("list", "set", "inet", "hatarvedelem", "proxy_banned_v4")
        check("ban", "203.0.113.9" in bans and "203.0.113.10" in proxy, bans + proxy)
        fw.unban("203.0.113.9")
        bans = nft("list", "set", "inet", "hatarvedelem", "banned_v4")
        check("unban", "203.0.113.9" not in bans, bans)

        fw.sync_host_ports([22, 8000], [53])
        service = nft("list", "set", "inet", "hatarvedelem", "host_service_tcp")
        check("sync_host_ports", "8000" in service, service)

        # The fixed command set: no raw nft, no injected statements.
        client = fw.client
        refused = {}
        for op, args in (
            ("nft", {"args": ["flush", "ruleset"]}),
            ("run", {"command": "nft flush ruleset"}),
            ("replace_custom", {"keep_block": False, "rules": [
                "add rule inet hatarvedelem preauth accept; flush ruleset"]}),
            ("replace_custom", {"keep_block": False, "rules": [
                "add rule inet hatarvedelem input accept"]}),
            ("replace_custom", {"keep_block": False, "rules": [
                "add rule inet hatarvedelem preauth accept\ndelete table inet hatarvedelem"]}),
            ("replace_custom", {"keep_block": False, "rules": [
                'add rule inet hatarvedelem preauth include "/etc/passwd"']}),
            ("ban", {"ip": "203.0.113.5", "ttl": 60, "set": "allowed_v4"}),
        ):
            try:
                client.call(op, args)
            except gateway.FirewallError as exc:
                refused[op + str(len(refused))] = str(exc)
            else:
                refused[op + str(len(refused))] = "ACCEPTED"
        check("refusals", "ACCEPTED" not in refused.values(), refused)
        allowed_v4 = nft("list", "set", "inet", "hatarvedelem", "allowed_v4")
        check("no_injected_grant", "203.0.113.5" not in allowed_v4, allowed_v4)
        check(
            "table_intact",
            "203.0.113.0/24" in nft("list", "chain", "inet", "hatarvedelem", "preauth")
            and fw.state_token() == token,
            nft("list", "tables"),
        )

        try:
            sock = client.nflog_socket()
        except OSError as exc:
            check("nflog_open", True, f"not available here: {exc}")
        else:
            check("nflog_open", sock.fileno() >= 0, "received")
            sock.close()

        # A dead helper: grants fail (never silently succeed); a restarted
        # helper serves again, the table untouched.
        helper.terminate()
        helper.wait(timeout=10)
        try:
            fw.grant_all(CLIENT, grants, 600)
        except gateway.HelperUnavailable as exc:
            check("grant_refused_without_helper", True, exc)
        except Exception as exc:  # noqa: BLE001
            check("grant_refused_without_helper", False, repr(exc))
        else:
            check("grant_refused_without_helper", False, "granted")
        helper = start_helper()
        check("ready_after_restart", fw.wait_ready(15))
        check("token_after_restart", fw.state_token() == token)
        fw.grant_all(CLIENT, grants, 600)
        fwd = nft("list", "set", "inet", "hatarvedelem", "allowed_tcp")
        check("grant_after_restart", f"{CLIENT} . 80" in fwd, fwd)
    finally:
        helper.terminate()
        try:
            output, _ = helper.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            helper.kill()
            output = ""
    ok = all(item["ok"] for item in checks.values())
    print(json.dumps({"ok": ok, "checks": checks, "helper_log": output[-3000:]}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
