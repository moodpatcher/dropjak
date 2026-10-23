#!/usr/bin/env python3
"""Static and unit checks for block-chain precedence (audit finding F4).

The ``block`` chain is interface-agnostic: ``apply_custom()`` emits
``meta l4proto ... ct original ...`` rules without an ``iifname`` match, so
the chain can match forwarded traffic in both directions on any interface and
host-destined input traffic. These tests pin the template ordering so every
relevant packet reaches the chain before any grant, and pin the generated
block rules so they stay interface-free.

The template tests only read the repository file. The ``apply_custom`` test
captures the generated script; it never runs nft or changes firewall state.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NFT_TEMPLATE = ROOT / "deploy" / "dropjak.nft"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def chain_rules(template: str, name: str) -> list[str]:
    """Return the rules of ``chain <name>`` as logical one-line rules.

    Comment-only lines are skipped and backslash continuations are joined so
    ordering assertions cannot be confused by line wrapping.
    """
    match = re.search(
        rf"^    chain {re.escape(name)} \{{\n(.*?)^    \}}\n",
        template,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"chain {name} not found in {NFT_TEMPLATE}")

    rules: list[str] = []
    pending = ""
    for raw in match.group(1).splitlines():
        line = raw.strip()
        if not pending and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            pending += (" " if pending else "") + line[:-1].rstrip()
            continue
        if pending:
            line = pending + " " + line
            pending = ""
        if line:
            rules.append(" ".join(line.split()))
    if pending:
        rules.append(" ".join(pending.split()))
    return rules


class BlockPrecedenceTemplateTests(unittest.TestCase):
    """The installed nftables template must reach block before any grant."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.template = NFT_TEMPLATE.read_text(encoding="utf-8")
        cls.forward = chain_rules(cls.template, "forward")
        cls.input = chain_rules(cls.template, "input")
        cls.prerouting = chain_rules(cls.template, "prerouting")

    @staticmethod
    def indices(rules: list[str], needle: str) -> list[int]:
        return [index for index, rule in enumerate(rules) if needle in rule]

    @staticmethod
    def jump_indices(rules: list[str], chain: str) -> list[int]:
        pattern = re.compile(rf"\bjump {re.escape(chain)}\b")
        return [
            index for index, rule in enumerate(rules) if pattern.search(rule)
        ]

    def only_jump(
        self, rules: list[str], chain: str, prefix: str = ""
    ) -> int:
        jumps = self.jump_indices(rules, chain)
        self.assertEqual(len(jumps), 1, (chain, jumps))
        self.assertEqual(rules[jumps[0]], f"{prefix}jump {chain}")
        return jumps[0]

    # In the input chain the block jump is limited to the original
    # direction (DJ-33): every client->host packet is original-direction, a
    # reply-direction packet there belongs to a connection the host opened.
    # It is also limited to the LAN interface: block entries restrict the
    # LAN clients, not inbound WAN traffic to the host (Caddy on 443).
    INPUT_BLOCK = 'iifname "__LAN_IF__" ct direction original '

    # -- forward -----------------------------------------------------------

    def test_forward_has_exactly_one_unconditional_block_jump(self) -> None:
        jumps = self.jump_indices(self.forward, "block")
        self.assertEqual(len(jumps), 1, jumps)
        self.assertEqual(self.forward[jumps[0]], "jump block")
        # A conditional LAN jump would let the server side of an existing
        # flow, WAN/DNAT traffic and container-bridge replies bypass block.
        self.assertNotIn('iifname "__LAN_IF__" jump block', self.forward)

    def test_forward_block_runs_after_fail2ban_and_mac_drops(self) -> None:
        block = self.only_jump(self.forward, "block")

        ban_logs = self.indices(self.forward, "reason=fail2ban")
        ban_drops = self.indices(self.forward, "ip saddr @banned_v4 ct direction original drop")
        self.assertTrue(ban_logs)
        self.assertEqual(len(ban_drops), 1, ban_drops)
        # Banned packets must still be logged as fail2ban, not as block.
        self.assertLess(ban_logs[0], ban_drops[0])
        self.assertLess(ban_drops[0], block)

        mac_logs = self.indices(self.forward, "reason=mac")
        mac_drops = self.indices(self.forward, "@client_mac drop")
        self.assertTrue(mac_logs)
        self.assertTrue(mac_drops)
        self.assertLess(max(mac_logs), block)
        self.assertLess(max(mac_drops), block)

    def test_forward_block_precedes_every_grant_and_preauth(self) -> None:
        block = self.only_jump(self.forward, "block")

        # No accept rule may run before block, which covers all session and
        # container accepts. This is the core of finding F4.
        early_accepts = [
            rule
            for rule in self.forward[:block]
            if rule.endswith(" accept")
        ]
        self.assertEqual(early_accepts, [])

        session_tokens = (
            "@allowed_tcp meta mark set",
            "@allowed_udp meta mark set",
            "ip saddr @allowed_icmp ip protocol icmp",
            "ip saddr @allowed_v4 meta mark",
            "ip daddr @allowed_icmp ip protocol icmp",
            "ip daddr @allowed_v4 meta mark",
        )
        for token in session_tokens:
            hits = [
                index
                for index in self.indices(self.forward, token)
                if self.forward[index].endswith(" accept")
            ]
            self.assertTrue(hits, token)
            self.assertLess(block, min(hits), token)

        preauth = self.forward.index("jump preauth")
        self.assertLess(block, preauth)
        # Block must also be evaluated before the container egress accepts.
        container_accepts = [
            index
            for index, rule in enumerate(self.forward)
            if "172.30.0.2" in rule and rule.endswith(" accept")
        ]
        self.assertEqual(len(container_accepts), 3, container_accepts)
        self.assertLess(block, min(container_accepts))

    # -- input -------------------------------------------------------------

    def test_input_has_exactly_one_lan_block_jump(self) -> None:
        jumps = self.jump_indices(self.input, "block")
        self.assertEqual(len(jumps), 1, jumps)
        self.assertEqual(
            self.input[jumps[0]], self.INPUT_BLOCK + "jump block"
        )

    def test_input_block_runs_after_exemptions_and_ban_drop(self) -> None:
        block = self.only_jump(self.input, "block", self.INPUT_BLOCK)

        # Loopback, breakglass, IPv6, DHCP and the early portal accepts stay
        # reachable; a block entry must not lock out the portal or rescue.
        ordered_before = (
            "iif lo accept",
            "jump breakglass",
            "meta nfproto ipv6 drop",
            'iifname "__LAN_IF__" ip saddr 0.0.0.0 '
            "udp sport 68 udp dport 67 accept",
            'iifname "__LAN_IF__" udp sport 68 udp dport 67 accept',
            'iifname "__LAN_IF__" tcp dport __PORT__ accept',
            "ip saddr __PORTAL_NET__ tcp dport __PORT__ accept",
            "ip saddr @banned_v4 ct direction original drop",
        )
        for rule in ordered_before:
            hits = self.indices(self.input, rule)
            self.assertTrue(hits, rule)
            self.assertLess(hits[0], block, rule)

        # Every accept before block must be one of those exemptions.
        exempt_fragments = (
            "iif lo accept",
            "udp sport 68 udp dport 67 accept",
            "tcp dport __PORT__ accept",
        )
        for index, rule in enumerate(self.input[:block]):
            if rule.endswith(" accept"):
                self.assertTrue(
                    any(fragment in rule for fragment in exempt_fragments),
                    rule,
                )

    def test_input_block_precedes_mac_guards_and_host_grants(self) -> None:
        block = self.only_jump(self.input, "block", self.INPUT_BLOCK)

        for needle in (
            "reason=mac",
            "reason=ssh-revoked",
            "reason=host-revoked",
            "reason=dns-revoked",
        ):
            hits = self.indices(self.input, needle)
            self.assertTrue(hits, needle)
            self.assertLess(block, min(hits), needle)

        established = self.input.index("ct state established,related accept")
        self.assertLess(block, established)

        for rule in (
            "ip saddr . tcp dport @allowed_input_tcp "
            "tcp dport != __PORT__ accept",
            "ip saddr . udp dport @allowed_input_udp "
            "udp dport != __PORT__ accept",
        ):
            grant = self.input.index(rule)
            self.assertLess(block, grant, rule)

    def test_input_jumps_preauth_input_after_block_before_portal(self) -> None:
        # The pre-auth_input chain runs AFTER the block (the block overrides), but
        # BEFORE the portal and SSH rules, so host-port access is reachable
        # before login.
        self.assertIn(
            "add chain inet hatarvedelem preauth_input", self.template
        )
        block = self.only_jump(self.input, "block", self.INPUT_BLOCK)
        preauth_input = self.only_jump(self.input, "preauth_input")
        self.assertLess(block, preauth_input)

        for rule in (
            'iifname "__LAN_IF__" tcp dport __PORT__ accept',
            "ip saddr __PORTAL_NET__ tcp dport __PORT__ accept",
            "reason=ssh-revoked",
            "reason=host-revoked",
            "ip saddr . tcp dport @allowed_input_tcp "
            "tcp dport != __PORT__ accept",
        ):
            hits = self.indices(self.input, rule)
            self.assertTrue(hits, rule)
            # The early portal exceptions are deliberately before the block; after
            # pre-auth come the chain's later, substantive rules.
            self.assertLess(preauth_input, hits[-1], rule)

    # -- prerouting / block_nat -------------------------------------------

    def test_block_nat_remains_lan_scoped_and_precedes_redirect(self) -> None:
        jumps = self.jump_indices(self.prerouting, "block_nat")
        self.assertEqual(len(jumps), 1, jumps)
        self.assertEqual(
            self.prerouting[jumps[0]],
            'iifname "__LAN_IF__" jump block_nat',
        )
        # Only the LAN path is redirected to the portal, so only that path
        # needs the pre-redirect NAT block.
        for rule in self.prerouting:
            if re.search(r"\bjump block_nat\b", rule):
                self.assertTrue(
                    rule.startswith('iifname "__LAN_IF__" '), rule
                )

        redirect = (
            'iifname "__LAN_IF__" meta l4proto tcp '
            "ct original proto-dst 80 redirect to :__PORT__"
        )
        self.assertLess(jumps[0], self.prerouting.index(redirect))


class ApplyCustomBlockRuleTests(unittest.TestCase):
    """``apply_custom()`` block rules must stay interface-agnostic."""

    def test_generated_block_rules_have_no_interface_match(self) -> None:
        import gateway  # lazy: importing the module reads runtime config

        firewall = gateway.Firewall(
            dry_run=True,
            logger=lambda *_: None,
            lan_if="eth1",
            wan_if="eth0",
        )
        scripts: list[str] = []
        firewall._run_script = scripts.append  # type: ignore[method-assign]

        firewall.apply_custom(
            block=[
                {"dst": "192.0.2.0/24", "proto": "tcp", "ports": [80, 443]},
                {"dst": "", "proto": "udp", "ports": [53]},
            ]
        )

        self.assertEqual(len(scripts), 1)
        block_lines = [
            line.strip()
            for line in scripts[0].splitlines()
            if re.match(r"^add rule inet \S+ block ", line.strip())
        ]
        # Two entries, each rendered as one log rule and one drop rule.
        self.assertEqual(len(block_lines), 4, block_lines)
        for line in block_lines:
            with self.subTest(line=line):
                self.assertNotIn("iifname", line)
                self.assertNotIn("oifname", line)
                self.assertIn("meta l4proto", line)
                self.assertIn("ct original proto-dst", line)


if __name__ == "__main__":
    unittest.main()
