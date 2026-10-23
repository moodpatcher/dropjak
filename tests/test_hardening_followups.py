#!/usr/bin/env python3
"""The design-step follow-ups of the 2026-10-23 security review.

DJ-01 (invalid conntrack state, escalating drop bans), DJ-02
(HV_NO_FORWARD_NETS), DJ-04 (native check timer, per-interface
route_localnet), DJ-07 (per-source log budget, drop-log start retry),
DJ-13 (portal connection limit, request deadlines), DJ-15 (separate sync
listener), DJ-17 (grants bound to the LAN/WAN interfaces, rp_filter),
DJ-18 (input chain consistency) and DJ-32 (container egress settings).
Nothing here touches the real firewall or network.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
for path in (str(ROOT), str(TESTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

import droplog  # noqa: E402
import fail2ban as fail2ban_mod  # noqa: E402
import gateway  # noqa: E402
import server  # noqa: E402
import settings_store  # noqa: E402
from test_block_precedence import chain_rules  # noqa: E402

NFT = (ROOT / "deploy" / "dropjak.nft").read_text(encoding="utf-8")
ENTRYPOINT = (ROOT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
SETUP_HOST = (ROOT / "docker" / "setup-host.sh").read_text(encoding="utf-8")
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
ENV_EXAMPLE = (ROOT / ".env.example").read_text(encoding="utf-8")
INDEX = (ROOT / "index.html").read_text(encoding="utf-8")

LOG_BUDGET = "update @log_src_v4 { ip saddr limit rate 30/minute burst 60 packets }"


def index_of(rules: list[str], needle: str) -> int:
    for index, rule in enumerate(rules):
        if needle in rule:
            return index
    raise AssertionError(f"rule not found: {needle}")


# ------------------------------------------------------------------ template


class TemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.forward = chain_rules(NFT, "forward")
        cls.input = chain_rules(NFT, "input")

    def test_invalid_state_is_dropped_before_the_ban_rules(self) -> None:
        for name, rules in (("forward", self.forward), ("input", self.input)):
            with self.subTest(chain=name):
                drop = rules.index("ct state invalid drop")
                self.assertIn("reason=ct-invalid", rules[drop - 1])
                self.assertLess(drop, index_of(rules, "@banned_v4"))
                self.assertLess(index_of(rules, "nfproto ipv6 drop"), drop)

    def test_grants_are_bound_to_the_lan_and_wan_interfaces(self) -> None:
        other = 'ct direction original iifname != { __CLIENT_IFS__ }'
        drops = [i for i, r in enumerate(self.forward)
                 if r.startswith(other) and r.endswith(" drop")]
        self.assertEqual(len(drops), 4)
        for grant in ("@allowed_v4 meta mark", "@allowed_tcp meta mark",
                      "@allowed_udp meta mark", "@allowed_icmp ip protocol icmp meta mark"):
            self.assertLess(max(drops), index_of(self.forward, grant), grant)
        drops = [i for i, r in enumerate(self.input)
                 if r.startswith(other) and r.endswith(" drop")]
        self.assertEqual(len(drops), 2)
        self.assertLess(
            max(drops),
            index_of(self.input, "ip saddr . tcp dport @allowed_input_tcp tcp dport != __PORT__ accept"),
        )
        self.assertLess(max(drops), self.input.index("jump portproxy_input"))

    def test_every_ipv4_log_rule_has_a_per_source_budget(self) -> None:
        self.assertRegex(
            NFT,
            r"add set inet hatarvedelem log_src_v4 \{\s*type ipv4_addr\s*"
            r"size 8192\s*flags dynamic,timeout\s*timeout 2m\s*\}",
        )
        logs = [r for r in chain_rules(NFT, "forward") + chain_rules(NFT, "input")
                if " log prefix " in r]
        self.assertTrue(logs)
        for rule in logs:
            with self.subTest(rule=rule):
                if "nfproto ipv6" in rule:
                    self.assertNotIn("log_src_v4", rule)
                    continue
                self.assertIn(LOG_BUDGET + " limit rate", rule)
        # The portal renders its own log rules the same way.
        self.assertEqual(gateway.LOG_SOURCE_SET, "log_src_v4")
        self.assertIn(gateway.LOG_SOURCE_LIMIT, LOG_BUDGET)

    def test_catch_all_logs_have_a_higher_rule_wide_limit(self) -> None:
        for rules, reason in ((self.forward, "no-grant"), (self.forward, "wan-drop"),
                              (self.input, "input-lan"), (self.input, "input-wan")):
            # The catch-all is the last rule with the reason.
            rule = [r for r in rules if f"reason={reason} " in r][-1]
            self.assertIn("} limit rate 120/minute burst 240 packets log", rule)

    def test_portal_connection_limit_precedes_the_portal_accepts(self) -> None:
        drop = index_of(self.input, "add @portal_conn_v4 { ip saddr ct count over 32 } drop")
        self.assertIn("reason=portal-connlimit", self.input[drop - 1])
        self.assertTrue(self.input[drop].startswith("tcp dport __PORT__ ct state new"))
        self.assertLess(drop, index_of(self.input, 'iifname "__LAN_IF__" tcp dport __PORT__ accept'))
        self.assertLess(drop, index_of(self.input, "ip saddr __PORTAL_NET__ tcp dport __PORT__ accept"))
        self.assertIn("add set inet hatarvedelem portal_conn_v4", NFT)

    def test_container_exception_is_no_longer_in_the_template(self) -> None:
        self.assertNotIn("172.30.0.2", NFT)
        jump = self.forward.index("jump container_egress")
        self.assertLess(self.forward.index("ip daddr @no_forward_v4 drop"), jump)
        self.assertLess(jump, self.forward.index("jump preauth"))
        self.assertIn("add chain inet hatarvedelem container_egress\n", NFT)
        self.assertNotIn("flush chain inet hatarvedelem container_egress", NFT)

    def test_no_forward_placeholder(self) -> None:
        self.assertIn(
            "{ 169.254.0.0/16__NO_FORWARD_NETS__ }", NFT
        )


class SingleNicRenderTests(unittest.TestCase):
    """The follow-up rules in both modes (HV_SINGLE_NIC)."""

    @classmethod
    def setUpClass(cls) -> None:
        import test_single_nic as tsn  # noqa: PLC0415
        env = {"HV_NO_FORWARD_NETS": "10.0.0.0/8"}
        cls.single = tsn.active_lines(tsn.render({**tsn.SINGLE, **env}))
        cls.two = tsn.active_lines(tsn.render({**tsn.TWO, **env}))

    def test_grant_interface_check_uses_the_client_interfaces(self) -> None:
        for lines, ifs in ((self.single, '{ "eth0" }'),
                           (self.two, '{ "eth1", "eth0" }')):
            hits = [l for l in lines
                    if l.startswith(f"ct direction original iifname != {ifs}")]
            self.assertEqual(len(hits), 12, ifs)  # 4 forward + 2 input pairs

    def test_mode_independent_rules_stay_active(self) -> None:
        for lines in (self.single, self.two):
            text = "\n".join(lines)
            self.assertEqual(text.count("ct state invalid drop"), 2)
            self.assertIn("add @portal_conn_v4 { ip saddr ct count over 32 } drop", text)
            self.assertIn("jump container_egress", text)
            self.assertIn(
                "add element inet hatarvedelem no_forward_v4 "
                "{ 169.254.0.0/16, 10.0.0.0/8 }", text)
            for line in lines:
                if " log prefix " in line and "nfproto ipv6" not in line:
                    self.assertIn(LOG_BUDGET, line)
        # The LAN catch-all log rules exist only with two NICs.
        self.assertFalse([l for l in self.single if "reason=no-grant" in l])
        self.assertTrue([l for l in self.two if "reason=no-grant" in l])

    def test_container_egress_without_a_lan(self) -> None:
        fw = gateway.Firewall(dry_run=True, logger=lambda *_: None,
                              lan_if="", wan_if="eth0", lan_network=None,
                              single_nic=True)
        rules = fw._container_egress_rules([egress()])
        self.assertFalse([r for r in rules if "container-pivot" in r
                          or "ct state new drop" in r])
        self.assertTrue([r for r in rules if r.endswith(" accept")])

    def test_input_chain_check_uses_the_wan_in_single_nic_mode(self) -> None:
        fw = gateway.Firewall(binary="/bin/true", logger=lambda *_: None,
                              lan_if="eth1", wan_if="eth0", single_nic=True)
        listing = ('iifname "eth0" tcp dport 22 drop\n'
                   "ip saddr . tcp dport @allowed_input_tcp tcp dport != 8100 accept\n")
        fw._run = lambda args, check=True: subprocess.CompletedProcess(
            args, 0, listing.encode(), b"")
        self.assertEqual(fw.input_chain_consistent(8100), (True, "ok"))

    def test_setup_host_rp_filter_on_the_wan_only(self) -> None:
        result = HostSysctlTests.run_setup_snippet(
            None, "HV_SINGLE_NIC=1\nHV_WAN_IF=eth0\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("net.ipv4.conf.eth0.rp_filter = 1", result.stdout)
        self.assertNotIn("disable_ipv6", result.stdout)
        self.assertNotIn("route_localnet", result.stdout)
        self.assertIn('RP_FILTER_IFS=("$WAN_IF")', INSTALL)


# ------------------------------------------------------- HV_NO_FORWARD_NETS


class NoForwardRenderTests(unittest.TestCase):
    def render(self, value: str):
        helpers = ENTRYPOINT[:ENTRYPOINT.index("ensure_state_dir() {")]
        start = ENTRYPOINT.index("render_ruleset() {")
        function = ENTRYPOINT[start:ENTRYPOINT.index("\n}", start) + 2]
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "r.nft")
            env = dict(
                os.environ, HV_APP_DIR=str(ROOT), HV_NFT_FILE=out,
                HV_LAN_IF="eth1", HV_WAN_IF="eth0",
                HV_LAN_NET="192.168.10.0/24", HV_PORTAL_NET="0.0.0.0/0",
                PORT="8100", HV_NO_FORWARD_NETS=value,
            )
            result = subprocess.run(
                ["sh", "-c", helpers + function + "\nrender_ruleset\n"],
                env=env, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            text = Path(out).read_text(encoding="utf-8")
        line = next(l for l in text.splitlines()
                    if l.startswith("add element inet hatarvedelem no_forward_v4"))
        return line, result.stdout + result.stderr

    def test_empty_keeps_only_link_local(self) -> None:
        line, _ = self.render("")
        self.assertEqual(
            line, "add element inet hatarvedelem no_forward_v4 { 169.254.0.0/16 }"
        )

    def test_networks_are_merged_and_invalid_ones_skipped(self) -> None:
        line, output = self.render(
            "10.0.0.0/8, 10.1.0.0/16 100.64.0.0/10,10.0.0.5/8,fd00::/8,bogus,"
            "169.254.169.254/32"
        )
        self.assertEqual(
            line,
            "add element inet hatarvedelem no_forward_v4 "
            "{ 169.254.0.0/16, 10.0.0.0/8, 100.64.0.0/10 }",
        )
        for bad in ("10.0.0.5/8", "fd00::/8", "bogus"):
            self.assertIn(f"invalid HV_NO_FORWARD_NETS entry", output)
            self.assertIn(bad, output)

    def test_a_supernet_of_link_local_is_split_around_it(self) -> None:
        line, _ = self.render("169.0.0.0/8")
        elements = line.split("{", 1)[1].rstrip(" }").split(", ")
        nets = [ipaddress.ip_network(item.strip()) for item in elements]
        # No overlap (an interval set would reject it), same coverage.
        self.assertEqual(
            list(ipaddress.collapse_addresses(nets)),
            [ipaddress.ip_network("169.0.0.0/8")],
        )
        self.assertEqual(sum(n.num_addresses for n in nets), 2 ** 24)

    def test_installer_validates_strictly(self) -> None:
        self.assertIn('canon_v4_net "$net" strict', INSTALL)
        self.assertIn('strict=sys.argv[2] == "strict"', INSTALL)
        self.assertIn("__NO_FORWARD_NETS__|$(sed_escape \"$NO_FORWARD_ELEMENTS\")", INSTALL)
        self.assertIn("--no-forward-nets", INSTALL)
        self.assertIn("HV_NO_FORWARD_NETS: ${HV_NO_FORWARD_NETS:-}", COMPOSE)
        self.assertIn("HV_NO_FORWARD_NETS=", ENV_EXAMPLE)

    def test_ui_labels_the_new_drop_reasons(self) -> None:
        for reason in ("no-forward", "ct-invalid", "grant-iface", "portal-connlimit"):
            # One en and one de label each.
            self.assertEqual(INDEX.count(f"    '{reason}': '"), 2, reason)


# --------------------------------------------------- sysctl and native timer


class HostSysctlTests(unittest.TestCase):
    def run_setup_snippet(self, env_lines: str, old_file: str = ""):
        start = SETUP_HOST.index("LAN_IF=${HV_LAN_IF:-}")
        end = SETUP_HOST.index('chmod 0644 "$SYSCTL_FILE"')
        snippet = SETUP_HOST[start:end]
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text(env_lines, encoding="utf-8")
            sysctl = os.path.join(tmp, "90-dropjak.conf")
            if old_file:
                Path(sysctl).write_text(old_file, encoding="utf-8")
            result = subprocess.run(
                ["bash", "-c",
                 "set -euo pipefail\ndie() { echo \"ERROR: $*\" >&2; exit 1; }\n"
                 + snippet + '\ncat "$SYSCTL_FILE"\necho "OLD=$OLD_ALL_LOCALNET"\n'],
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                     "REPO_DIR": tmp, "SYSCTL_FILE": sysctl},
                capture_output=True, text=True, timeout=30,
            )
        return result

    def test_rp_filter_and_per_interface_route_localnet(self) -> None:
        result = self.run_setup_snippet(
            "HV_LAN_IF=eth1\nHV_WAN_IF=eth0\nHV_ROUTE_LOCALNET_IFS=eth0, eth2.5\n",
            old_file="net.ipv4.conf.all.route_localnet = 1\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        out = result.stdout
        self.assertIn("net.ipv4.conf.eth1.rp_filter = 1", out)
        self.assertIn("net.ipv4.conf.eth0.rp_filter = 1", out)
        self.assertIn("net.ipv4.conf.eth0.route_localnet = 1", out)
        self.assertIn("net/ipv4/conf/eth2.5/route_localnet = 1", out)
        self.assertNotIn("conf.all.route_localnet", out)
        self.assertIn("OLD=1", out)

    def test_no_route_localnet_without_interfaces(self) -> None:
        result = self.run_setup_snippet("HV_LAN_IF=eth1\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("route_localnet", result.stdout)
        self.assertIn("net.ipv4.conf.eth1.rp_filter = 1", result.stdout)
        self.assertIn("OLD=0", result.stdout)

    def test_invalid_interface_is_refused(self) -> None:
        result = self.run_setup_snippet(
            "HV_LAN_IF=eth1\nHV_ROUTE_LOCALNET_IFS=eth0;reboot\n"
        )
        self.assertNotEqual(result.returncode, 0)

    def test_migration_resets_the_live_all_value(self) -> None:
        self.assertIn(
            "echo 0 >/proc/sys/net/ipv4/conf/all/route_localnet", SETUP_HOST
        )
        self.assertIn(
            "printf '0\\n' > /proc/sys/net/ipv4/conf/all/route_localnet", INSTALL
        )
        self.assertIn('RP_FILTER_IFS=("$LAN_IF" "$WAN_IF")', INSTALL)
        self.assertIn('ipv4_conf_key "$iface" rp_filter', INSTALL)

    def test_native_check_timer_is_installed(self) -> None:
        service = (ROOT / "deploy" / "dropjak-firewall-check.service").read_text(
            encoding="utf-8")
        timer = (ROOT / "deploy" / "dropjak-firewall-check.timer").read_text(
            encoding="utf-8")
        self.assertIn("Type=oneshot", service)
        self.assertIn("list chain inet hatarvedelem forward", service)
        self.assertIn("reload-or-restart dropjak-firewall.service", service)
        self.assertIn("OnUnitActiveSec=10s", timer)
        self.assertIn('"$SRC_DIR/deploy/dropjak-firewall-check.timer" "$CHECK_TIMER"', INSTALL)
        self.assertIn('systemctl enable --now "${FIREWALL_SERVICE}-check.timer"', INSTALL)


# ----------------------------------------------------------- container egress


def egress(**overrides) -> dict:
    entry = {"id": "app", "label": "App", "address": "172.30.0.2",
             "bridge": "br-app", "tcp": [53, 80, 443], "udp": [53],
             "enabled": True}
    entry.update(overrides)
    return entry


class ContainerEgressSettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.dict(os.environ, {
            "HV_LAN_IF": "eth1", "HV_WAN_IF": "eth0",
            "HV_LAN_NET": "192.168.10.0/24",
        })
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "settings.json")

    def test_valid_entry_is_normalized(self) -> None:
        out = settings_store._container_egress([
            egress(id=None, tcp=["443", 80, 80], udp=[]),
            egress(id="mc", address="10.5.0.3", bridge="br-*"),
        ])
        self.assertRegex(out[0]["id"], r"^[0-9a-f]{8}$")
        self.assertEqual(out[0]["tcp"], [80, 443])
        self.assertEqual(out[0]["udp"], [])
        self.assertEqual(out[1]["bridge"], "br-*")

    def test_invalid_entries_are_rejected(self) -> None:
        for bad in (
            egress(address="8.8.8.8"),
            egress(address="127.0.0.1"),
            egress(address="169.254.169.254"),
            egress(address="192.168.10.5"),  # inside HV_LAN_NET
            egress(address="10.77.0.9"),  # the tunnel network
            egress(address="172.30.0.0/24"),
            egress(bridge=""),
            egress(bridge="br app"),
            egress(bridge="b*r"),
            egress(bridge="eth1"),  # the LAN interface
            egress(bridge="eth*"),  # matches the LAN and WAN interfaces
            egress(bridge="x" * 16),
            egress(tcp=[], udp=[]),
            egress(tcp=[0]),
            egress(tcp="80"),
            egress(enabled="yes"),
            egress(label=""),
        ):
            with self.subTest(entry=bad), self.assertRaises(settings_store.SettingsError):
                settings_store._container_egress([bad])
        with self.assertRaises(settings_store.SettingsError):
            settings_store._container_egress([egress(), egress(id="b")])  # same address
        with self.assertRaises(settings_store.SettingsError):
            settings_store._container_egress([egress()] * 2)

    def test_old_file_gets_the_former_template_exception(self) -> None:
        Path(self.path).write_text(json.dumps({"preauth": [], "block": []}),
                                   encoding="utf-8")
        logs = []
        store = settings_store.SettingsStore(self.path, logger=logs.append)
        snapshot = store.snapshot()
        self.assertEqual(snapshot["error"], "")
        self.assertEqual(snapshot["container_egress"], [{
            "id": "minecraft", "label": "Minecraft", "address": "172.30.0.2",
            "bridge": "br-*", "tcp": [53, 80, 443], "udp": [53], "enabled": True,
        }])
        self.assertTrue(any("container egress" in line for line in logs))
        # Once saved, the key is present and an empty list stays empty.
        store.commit(store.prepare_container_egress([]))
        again = settings_store.SettingsStore(self.path, logger=lambda *_: None)
        self.assertEqual(again.snapshot()["container_egress"], [])

    def test_fresh_install_has_no_exception(self) -> None:
        store = settings_store.SettingsStore(self.path, logger=lambda *_: None)
        self.assertEqual(store.snapshot()["container_egress"], [])

    def test_migration_never_invalidates_the_file(self) -> None:
        with mock.patch.dict(os.environ, {"HV_LAN_NET": "172.30.0.0/24"}):
            self.assertEqual(settings_store.legacy_container_egress(), [])

    def test_prepare_and_commit_round_trip(self) -> None:
        store = settings_store.SettingsStore(self.path, logger=lambda *_: None)
        data = store.prepare_container_egress([egress()])
        self.assertEqual(store.snapshot()["container_egress"], [])  # not yet saved
        store.commit(data)
        stored = json.loads(Path(self.path).read_text(encoding="utf-8"))
        self.assertEqual(stored["container_egress"][0]["address"], "172.30.0.2")


class ContainerEgressRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fw = gateway.Firewall(
            dry_run=True, logger=lambda *_: None, lan_if="eth1", wan_if="eth0",
            lan_network=ipaddress.ip_network("192.168.10.0/24"),
        )

    def test_rules_are_bound_to_the_bridge(self) -> None:
        rules = self.fw._container_egress_rules([egress(), egress(
            id="off", address="172.31.0.2", enabled=False)])
        T = "add rule inet hatarvedelem container_egress"
        mark = self.fw.fwd_mark
        self.assertEqual(rules, [
            f'{T} iifname != "br-app" ip saddr 172.30.0.2 {self.fw._log_statement("container-spoof")}',
            f'{T} iifname != "br-app" ip saddr 172.30.0.2 drop',
            f'{T} iifname "br-app" ip saddr 172.30.0.2 ip daddr 192.168.10.0/24 ct state new '
            f'{self.fw._log_statement("container-pivot")}',
            f'{T} iifname "br-app" ip saddr 172.30.0.2 ip daddr 192.168.10.0/24 ct state new drop',
            f'{T} iifname "br-app" ip saddr 172.30.0.2 tcp dport {{ 53, 80, 443 }} '
            f"meta mark set {mark} accept",
            f'{T} iifname "br-app" ip saddr 172.30.0.2 udp dport 53 '
            f"meta mark set {mark} accept",
            f'{T} oifname "br-app" ip daddr 172.30.0.2 ct state established,related '
            f"ct original ip saddr 172.30.0.2 meta mark set {mark} accept",
        ])
        for rule in rules:
            if rule.endswith(" accept"):
                self.assertIn("br-app", rule)

    def test_invalid_entry_raises(self) -> None:
        for bad in (egress(address="nope"), egress(bridge="br app"),
                    egress(tcp=[70000]), egress(tcp=[], udp=[])):
            with self.subTest(entry=bad), self.assertRaises(gateway.FirewallError):
                self.fw._container_egress_rules([bad])

    def test_replace_custom_replaces_the_chain(self) -> None:
        scripts = []
        with mock.patch.object(self.fw, "_run_script", side_effect=scripts.append):
            self.fw.replace_custom((), (), container_egress=[egress()])
            self.fw.replace_custom((), (), keep_block=True)
        for script in scripts:
            self.assertIn("flush chain inet hatarvedelem container_egress", script)
        self.assertIn("container_egress iifname \"br-app\"", scripts[0])
        # An invalid settings file empties it, like pre-auth.
        self.assertNotIn("container_egress iifname", scripts[1])

    def test_ruleset_view_lists_the_chain(self) -> None:
        self.assertIn("container_egress", gateway.RULESET_CHAINS)


class ContainerEgressHttpTests(unittest.TestCase):
    def test_admin_action_is_wired_and_exported(self) -> None:
        source = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn('if action == "container_egress":', source)
        self.assertIn("prepare_container_egress(", source)
        self.assertIn('"container_egress": len(settings.get("container_egress", []))', source)
        self.assertIn("function renderContainerEgressSection(", INDEX)
        self.assertIn("action: 'container_egress'", INDEX)
        for text in ("Konténer-kimenet", "Új konténer-kimenet", "Konténer IP-cím"):
            self.assertEqual(INDEX.count(f"    '{text}': '"), 2, text)


# ------------------------------------------------------------- fail2ban, drops


class FakeBanFirewall:
    def __init__(self) -> None:
        self.bans: list[tuple[str, int]] = []

    def ban(self, ip: str, ttl: int) -> None:
        self.bans.append((ip, ttl))

    def unban(self, ip: str) -> None:
        pass

    def sync_bans(self, elements) -> None:
        pass


class EscalatingDropBanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(
            os.environ, {"HV_MGMT_NET": "", "HV_FAIL2BAN_DROP_EXEMPT": ""}
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.fw = FakeBanFirewall()
        self.manager = fail2ban_mod.Fail2ban(
            self.fw, path=os.path.join(self.tmp.name, "f.json"),
            logger=lambda *_: None, ban_seconds=3600, drop_count_enabled=True,
            drop_ports_enabled=True, drop_max=1000, drop_ports=3,
            drop_window_seconds=60,
        )

    def scan(self, ip: str) -> None:
        for port in (1, 2, 3):
            self.manager.record_drop(ip, proto="tcp", dport=port, reason="input-wan")

    def test_first_drop_ban_is_short_and_repeats_double(self) -> None:
        ip = "192.0.2.10"
        for _ in range(6):
            self.scan(ip)
            self.manager._bans[ip]["until"] = time.time() - 1  # expire it
        self.assertEqual([ttl for _, ttl in self.fw.bans],
                         [300, 600, 1200, 2400, 3600, 3600])

    def test_strikes_are_per_address_and_forgotten(self) -> None:
        self.scan("192.0.2.11")
        self.manager._drop_strikes["192.0.2.11"] = (
            3, time.time() - fail2ban_mod.DROP_STRIKE_MEMORY - 1)
        self.manager._bans["192.0.2.11"]["until"] = time.time() - 1
        self.scan("192.0.2.11")
        self.scan("192.0.2.12")
        self.assertEqual([ttl for _, ttl in self.fw.bans], [300, 300, 300])

    def test_short_configured_ban_is_not_lengthened(self) -> None:
        self.manager._config["ban_seconds"] = 120
        self.scan("192.0.2.13")
        self.assertEqual(self.fw.bans, [("192.0.2.13", 120)])

    def test_login_bans_keep_the_full_length(self) -> None:
        for _ in range(self.manager._config["max_attempts"]):
            self.manager.record_failure("192.0.2.14", user="x")
        self.assertEqual(self.fw.bans, [("192.0.2.14", 3600)])


class DropLogStartRetryTests(unittest.TestCase):
    def test_failed_start_keeps_retrying_with_back_off(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = droplog.DropLog(os.path.join(tmp, "d.jsonl"),
                                    logger=lambda *_: None)
            listener = droplog.DropLogListener(store, enabled=True,
                                               logger=lambda *_: None)
            sock = mock.Mock()
            sock.recv.side_effect = socket.timeout()
            attempts = []

            def opener():
                attempts.append(1)
                if len(attempts) < 3:
                    raise OSError(19, "No such device")
                return sock

            waits = []
            real_wait = listener._stop.wait

            def wait(delay):
                waits.append(delay)
                return real_wait(0.01)

            with mock.patch.object(listener, "_open_socket", side_effect=opener), \
                    mock.patch.object(listener._stop, "wait", side_effect=wait):
                self.assertFalse(listener.start())
                deadline = time.monotonic() + 5
                while not listener.status()["running"] and time.monotonic() < deadline:
                    time.sleep(0.01)
                status = listener.status()
                listener.stop()
        self.assertTrue(status["running"])
        self.assertEqual(status["restarts"], 0)
        self.assertEqual(status["error"], "")
        self.assertEqual(len(attempts), 3)
        self.assertEqual(waits[:2], [1.0, 2.0])

    def test_disabled_listener_does_not_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = droplog.DropLog(os.path.join(tmp, "d.jsonl"),
                                    logger=lambda *_: None)
            listener = droplog.DropLogListener(store, enabled=False,
                                               logger=lambda *_: None)
            self.assertFalse(listener.start())
            self.assertIsNone(listener._thread)


# ---------------------------------------------------- input chain consistency


class InputChainConsistencyTests(unittest.TestCase):
    def firewall(self, listing: str, returncode: int = 0):
        fw = gateway.Firewall(binary="/bin/true", logger=lambda *_: None,
                              lan_if="eth1", wan_if="eth0")
        fw._run = lambda args, check=True: subprocess.CompletedProcess(
            args, returncode, listing.encode(), b"no such chain")
        return fw

    GOOD = ('iifname "eth1" tcp dport 8100 accept\n'
            "ip saddr . tcp dport @allowed_input_tcp tcp dport != 8100 accept\n")

    def test_rendered_for_this_portal(self) -> None:
        self.assertEqual(self.firewall(self.GOOD).input_chain_consistent(8100),
                         (True, "ok"))

    def test_mismatches_are_reported(self) -> None:
        ok, why = self.firewall(self.GOOD).input_chain_consistent(80)
        self.assertFalse(ok)
        self.assertIn("portal port 80", why)
        ok, why = self.firewall(self.GOOD.replace("eth1", "eth9")).input_chain_consistent(8100)
        self.assertFalse(ok)
        self.assertIn("LAN interface eth1", why)
        ok, why = self.firewall("", returncode=1).input_chain_consistent(8100)
        self.assertFalse(ok)

    def test_mismatch_refuses_host_grants_only(self) -> None:
        gw = object.__new__(gateway.Gateway)
        gw.firewall = types.SimpleNamespace(
            input_chain_consistent=lambda: (False, "no rule names eth1"))
        audits = []
        gw._write_audit = lambda event, **fields: audits.append((event, fields))
        gw._host_ports_ok = True
        gw._input_chain_ok = True
        self.assertFalse(gw.check_input_chain())
        self.assertFalse(gw._host_ports_healthy())
        self.assertEqual(audits[0][0], "firewall_error")
        self.assertEqual(audits[0][1]["operation"], "input_chain")
        gw.firewall = types.SimpleNamespace(input_chain_consistent=lambda: (True, "ok"))
        self.assertTrue(gw.check_input_chain())
        self.assertTrue(gw._host_ports_healthy())

    def test_dry_run_is_consistent(self) -> None:
        fw = gateway.Firewall(dry_run=True, logger=lambda *_: None, lan_if="eth1")
        self.assertEqual(fw.input_chain_consistent(), (True, "ok"))


# ------------------------------------------------------------- HTTP server


class _ServerCase(unittest.TestCase):
    server_class = server.AppServer

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        settings = settings_store.SettingsStore(
            os.path.join(self.tmp.name, "s.json"), logger=lambda *_: None
        )
        gw = types.SimpleNamespace(
            settings=settings,
            audit=types.SimpleNamespace(write=lambda event, **f: None),
            tunnel_sync_lock=threading.Lock(), tunnel_sync_times={},
        )
        self.server = self.server_class(("127.0.0.1", 0), gw)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]


class RequestDeadlineTests(_ServerCase):
    def setUp(self) -> None:
        for name, value in (("REQUEST_HEADER_SECONDS", 0.5),
                            ("KEEPALIVE_IDLE_SECONDS", 0.3)):
            patcher = mock.patch.object(server, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        super().setUp()

    def closed_after(self, sock) -> float:
        start = time.monotonic()
        sock.settimeout(10)
        while sock.recv(65536):
            pass
        return time.monotonic() - start

    def test_trickling_headers_are_cut_at_the_deadline(self) -> None:
        with socket.create_connection(("127.0.0.1", self.port), 5) as sock:
            start = time.monotonic()
            sock.sendall(b"GET /api/status HTTP/1.1\r\n")
            closed = False
            for _ in range(20):
                time.sleep(0.1)
                try:
                    sock.sendall(b"X-Slow: 1\r\n")
                except OSError:
                    closed = True
                    break
                sock.settimeout(0.01)
                try:
                    if sock.recv(1) == b"":
                        closed = True
                        break
                except socket.timeout:
                    pass
            self.assertTrue(closed, "the slow client kept its connection")
            self.assertLess(time.monotonic() - start, 1.8)

    def test_idle_keep_alive_is_closed(self) -> None:
        with socket.create_connection(("127.0.0.1", self.port), 5) as sock:
            sock.sendall(b"GET /api/tunnel/none HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            sock.settimeout(5)
            first = sock.recv(65536)
            self.assertTrue(first.startswith(b"HTTP/1.1 "))
            self.assertNotIn(b"Connection: close", first)
            # Kept open for the idle period, then closed.
            waited = self.closed_after(sock)
            self.assertGreater(waited, 0.15)
            self.assertLess(waited, 2.0)

    def test_deadline_reader_raises_after_the_deadline(self) -> None:
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        handler = types.SimpleNamespace(_read_deadline=time.monotonic() - 1)
        reader = server._DeadlineReader(a, handler)
        with self.assertRaises(TimeoutError):
            reader.readinto(bytearray(4))
        handler._read_deadline = time.monotonic() + 5
        b.sendall(b"ok")
        buf = bytearray(4)
        self.assertEqual(reader.readinto(buf), 2)
        self.assertIsNone(a.gettimeout())


class TunnelSyncListenerTests(_ServerCase):
    server_class = server.TunnelSyncServer

    def get(self, path: str, peer: str) -> int:
        with mock.patch.object(server.Handler, "_peer_ip", lambda self: peer):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            conn.request("GET", path, headers={"Authorization": "Bearer x"})
            status = conn.getresponse().status
            conn.close()
        return status

    def test_only_tunnel_peers_reach_only_the_sync_endpoint(self) -> None:
        # A tunnel peer without an enabled agent: the sync handler's 403.
        self.assertEqual(self.get("/api/tunnel/config", "10.77.0.2"), 403)
        for path in ("/", "/api/status", "/api/admin/state", "/index.html"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path, "10.77.0.2"), 404)
        # Anyone else gets nothing here, not even the sync endpoint.
        self.assertEqual(self.get("/api/tunnel/config", "192.168.10.5"), 404)
        self.assertEqual(self.get("/api/status", "127.0.0.1"), 404)

    def test_listener_binds_the_tunnel_address_with_freebind(self) -> None:
        self.assertTrue(self.server.tunnel_only)
        level = getattr(socket, "IP_FREEBIND", 15)
        self.assertEqual(self.server.socket.getsockopt(socket.IPPROTO_IP, level), 1)
        source = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn("(settings_store.TUNNEL_SERVER_ADDRESS,\n"
                      "               settings_store.TUNNEL_SYNC_PORT)", source)

    def test_sync_port_defaults_next_to_the_portal(self) -> None:
        with mock.patch.dict(os.environ, {"HV_TUNNEL_SYNC_PORT": ""}):
            self.assertEqual(settings_store._tunnel_sync_port(),
                             settings_store.PORTAL_PORT + 1)
        with mock.patch.dict(os.environ, {"HV_TUNNEL_SYNC_PORT": "9000"}):
            self.assertEqual(settings_store._tunnel_sync_port(), 9000)
        for bad in (str(settings_store.PORTAL_PORT), "0", "x"):
            with mock.patch.dict(os.environ, {"HV_TUNNEL_SYNC_PORT": bad}):
                self.assertEqual(settings_store._tunnel_sync_port(),
                                 settings_store.PORTAL_PORT + 1)


if __name__ == "__main__":
    unittest.main()
