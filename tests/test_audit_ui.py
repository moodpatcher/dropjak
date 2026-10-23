#!/usr/bin/env python3
"""Static frontend tests for displaying the audit log.

The test does not start a browser: it checks the ``index.html`` event label
map and the markers of the log filter/log viewer. Server-side event codes are
collected with AST, so calls split over several lines and conditional event
names are counted correctly too.
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402

INDEX_PATH = ROOT / "index.html"
SOURCE_FILES = ("server.py", "gateway.py", "fail2ban.py")
LABEL_ENTRY_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"\[\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*\]"
)


def _js_object_body(source: str, declaration: str) -> str:
    """The exact body of the ``const NAME = { ... }`` object literal."""
    start = source.index(declaration)
    start = source.index("{", start)
    depth = 0
    for index in range(start, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1:index]
    raise AssertionError(f"unterminated object literal: {declaration}")


def _parse_event_labels(source: str) -> dict[str, tuple[str, str, str]]:
    body = _js_object_body(source, "const AUDIT_EVENT_LABELS = {")
    # The static page must not contain the server-side "totp_recovery"
    # field name, so one of the event keys is assembled from two literals.
    body = re.sub(
        r"\[\s*'([^']*)'\s*\+\s*'([^']*)'\s*\]\s*:",
        lambda match: f"{match.group(1)}{match.group(2)}:",
        body,
    )
    labels: dict[str, tuple[str, str, str]] = {}
    for match in LABEL_ENTRY_RE.finditer(body):
        labels[match.group(1)] = match.group(2, 3, 4)
    return labels


def _js_function(name: str, source: str) -> str:
    match = re.search(
        rf"function {re.escape(name)}\([^)]*\) \{{.*?\n\}}", source, re.S
    )
    if match is None:
        raise AssertionError(f"missing JS function: {name}")
    return match.group(0)


def _constant_strings(node: ast.AST | None) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.IfExp):
        return _constant_strings(node.body) + _constant_strings(node.orelse)
    return []


def _is_audit_receiver(node: ast.AST) -> bool:
    """``audit.write``, ``self.gw.audit.write`` and ``gateway.AuditLog().write``."""
    if isinstance(node, ast.Name):
        return node.id == "audit"
    if isinstance(node, ast.Attribute):
        return node.attr == "audit"
    if isinstance(node, ast.Call):
        return "audit" in ast.unparse(node).lower()
    return False


def _emitted_audit_events() -> set[str]:
    """The event codes actually emitted on the server side."""
    events: set[str] = set()
    for filename in SOURCE_FILES:
        tree = ast.parse(
            (ROOT / filename).read_text(encoding="utf-8"), filename=filename
        )
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            name = (
                function.attr if isinstance(function, ast.Attribute)
                else function.id if isinstance(function, ast.Name)
                else ""
            )
            if name == "write":
                if not _is_audit_receiver(function.value):
                    continue
                arguments = node.args[:1]
            elif name in ("_audit", "_write_audit"):
                arguments = node.args[:1]
            elif name == "_cli_audit":
                # _cli_audit(audit, event, **fields)
                arguments = node.args[1:2]
            else:
                continue
            if arguments:
                events.update(_constant_strings(arguments[0]))
    return events


class AuditUiStaticTests(unittest.TestCase):
    """Static frontend markers of the audit events and the log filter."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INDEX_PATH.read_text(encoding="utf-8")
        cls.labels = _parse_event_labels(cls.source)
        cls.emitted = _emitted_audit_events()

    def test_event_label_map_covers_every_emitted_event(self) -> None:
        self.assertTrue(self.emitted, "no audit event found in the source")
        missing = sorted(self.emitted - set(self.labels))
        self.assertFalse(
            missing,
            "missing AUDIT_EVENT_LABELS entry: " + ", ".join(missing),
        )
        for code in sorted(self.emitted):
            row = self.labels[code]
            self.assertEqual(len(row), 3, code)
            for label in row:
                self.assertTrue(label.strip(), f"empty label: {code}")

    def test_severity_map_events_are_labelled(self) -> None:
        # Old/new events of the central severity map must also get a label.
        missing = sorted(set(gateway.AUDIT_SEVERITY) - set(self.labels))
        self.assertFalse(
            missing,
            "missing AUDIT_EVENT_LABELS entry: " + ", ".join(missing),
        )

    def test_label_lookup_and_fallback(self) -> None:
        self.assertIn("function auditEventLabel(code)", self.source)
        self.assertIn("const row = AUDIT_EVENT_LABELS[code]", self.source)
        # For an unknown code the raw event code remains.
        self.assertIn("if (!row) return code", self.source)
        self.assertIn("row[lang === 'en' ? 1 : lang === 'de' ? 2 : 0]", self.source)
        # The log table does not translate event names from the tr() dictionary.
        self.assertIn("auditEventLabel(entry.event || '—')", self.source)
        self.assertNotIn("tr(entry.event", self.source)

    def test_severity_badge_and_filter_are_present(self) -> None:
        self.assertIn("entry.severity || 'info'", self.source)
        self.assertIn("`sev-badge sev-${severity}`", self.source)
        for css_class in (
            ".sev-badge.sev-info{",
            ".sev-badge.sev-warn{",
            ".sev-badge.sev-alert{",
        ):
            self.assertIn(css_class, self.source)
        # Both the badge's text and its tooltip are translated.
        self.assertIn("const SEVERITY_LABELS = {", self.source)
        self.assertIn("title: `${tr('Szint')}: ${severityText}`", self.source)
        self.assertIn("const severitySelect = el('select', {}", self.source)
        self.assertIn(
            "['', 'összes szint'], ['info', 'információ'], "
            "['warn', 'figyelmeztetés'], ['alert', 'riasztás']",
            self.source,
        )
        self.assertIn("severity: severitySelect.value", self.source)
        self.assertIn("severity: logFilter.severity || ''", self.source)
        self.assertIn("['Szint', severitySelect]", self.source)

    def test_log_detail_lists_audit_fields(self) -> None:
        start = self.source.index("function logDetail(entry)")
        end = self.source.index("function renderLogs()", start)
        detail = self.source[start:end]
        keys = set(re.findall(r"'([a-z_]+)'", detail))
        required = {
            "severity", "ticket_hash", "purpose", "method", "attempts",
            "remaining", "banned", "ban_until", "session_ip", "request_ip",
            "target_ip", "tickets_revoked", "count", "old_user", "new_user",
            "was_enrolled", "removed", "source", "actor",
            "collections_affected",
        }
        self.assertFalse(required - keys, sorted(required - keys))

    def test_manual_log_reads_only_for_user_actions(self) -> None:
        self.assertIn("async function loadLogs(manual = false)", self.source)
        self.assertIn("if (manual) query.set('manual', '1')", self.source)
        # adminSetTab, the Refresh button and clearing the Filters send the flag.
        self.assertEqual(self.source.count("loadLogs(true)"), 3)
        tab_start = self.source.index("function adminSetTab(name)")
        tab_end = self.source.index("function adminNotice()", tab_start)
        self.assertIn(
            "if (name === 'logs') loadLogs(true);",
            self.source[tab_start:tab_end],
        )
        schedule_start = self.source.index("function scheduleLogs()")
        schedule_end = self.source.index("async function loadAdminState()", schedule_start)
        schedule = self.source[schedule_start:schedule_end]
        self.assertIn("loadLogs()", schedule)
        self.assertNotIn("loadLogs(true)", schedule)

    def test_event_filter_is_select_and_manual_load_repaints(self) -> None:
        # The event filter is built from the labelled codes, keeping unknown/legacy
        # values, and uses the select's value for filtering.
        for token in (
            "const eventSelect = multiSelect({",
            "options: auditEventOptions(logFilter.events)",
            "events: (logFilter.events || []).join(',')",
            "adminPanel.append(eventSelect.chips);",
            "Object.keys(AUDIT_EVENT_LABELS)",
            "for (const code of extra || []) if (!codes.includes(code)) codes.push(code);",
            "placeholder: 'összes esemény'",
            "onChange: events => { logFilter.events = events; apply(); }",
            "['Esemény', eventSelect]",
            "for (const node of [userInput, qInput, ipInput])",
            # IP/CIDR filter and the highlighted host of proxy events.
            "ip: ipInput.value.trim()",
            "ip: logFilter.ip || ''",
            "['IP-cím / CIDR', ipInput]",
            "function logSubject(entry)",
            "class: 'log-subject mono'",
        ):
            self.assertIn(token, self.source, token)
        self.assertNotIn("placeholder: tr('esemény')", self.source)
        # The raw event code appears after the localized label as a small muted
        # code, so it stays searchable and recognizable.
        self.assertIn("class: 'log-event-code muted'", self.source)
        self.assertIn("text: entry.event", self.source)
        self.assertIn(
            "auditEventLabel(entry.event || '—')", self.source
        )
        # Manual loading triggered with Enter repaints even if the focus stayed
        # in the filter field; automatic refresh does not.
        logs_start = self.source.index("async function loadLogs")
        logs_end = self.source.index("function scheduleLogs", logs_start)
        logs = self.source[logs_start:logs_end]
        self.assertIn("if (manual || !typing)", logs)
        self.assertNotIn("if (!typing) {", logs)
        drops_start = self.source.index("async function loadDrops")
        drops_end = self.source.index("function scheduleDrops", drops_start)
        drops = self.source[drops_start:drops_end]
        self.assertIn("async function loadDrops(manual = false)", drops)
        self.assertIn("if (manual || !typing)", drops)

    def test_pure_helpers_in_node(self) -> None:
        """hostHref, auditEventGroup and the live list's new-row counter."""
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not available for the JS helper test")
        regex = re.search(r"const HOSTNAME_RE = .*;", self.source)
        groups = re.search(
            r"const AUDIT_EVENT_GROUPS = \[.*?\n\];", self.source, re.S
        )
        self.assertIsNotNone(regex)
        self.assertIsNotNone(groups)
        functions = "\n".join(
            _js_function(name, self.source)
            for name in ("hostHref", "auditEventGroup", "liveKey", "liveNewCount")
        )
        script = regex.group(0) + "\n" + groups.group(0) + "\n" + functions + """
const rows = [{ ts: 30 }, { ts: 20 }];
process.stdout.write(JSON.stringify({
  ok: hostHref('Owui.Z1.Example.com'),
  trimmed: hostHref(' a.b.hu '),
  bad: ['', 'localhost', '1.2.3.4', 'a..b.hu', '-a.b.hu', 'a.b.hu/x',
    'a.b.hu"><x', 'javascript:alert(1)', 'a_b.example.com',
    'x'.repeat(64) + '.hu'].map(hostHref),
  groups: ['login_failed', 'proxy_page_opened', 'totp_failed', 'session_ended',
    'fail2ban_ban', 'conntrack_failed', 'admin_rule_deleted', 'cli_user_created',
    'control_denied', 'service_start', 'mystery_event'].map(auditEventGroup),
  fresh: liveNewCount(rows, [{ ts: 40 }, { ts: 31 }, { ts: 30 }, { ts: 20 }]),
  none: liveNewCount(rows, rows),
  first: liveNewCount([], [{ ts: 1 }]),
  key: liveKey({ ts: 1.5, event: 'logout', user: 'a', ip: '10.0.0.1' }),
}));
"""
        result = subprocess.run(
            [node, "-e", script], capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["ok"], "https://owui.z1.example.com/")
        self.assertEqual(data["trimmed"], "https://a.b.hu/")
        self.assertEqual(data["bad"], [""] * 10)
        self.assertEqual(data["groups"], [
            "Belépés és hozzáférés", "Proxy", "2FA", "Munkamenetek",
            "Fail2ban és tűzfal", "Fail2ban és tűzfal", "Adminisztráció",
            "Parancssor", "Vezérlőcsatorna", "Szolgáltatás", "Egyéb",
        ])
        self.assertEqual(data["fresh"], 2)
        self.assertEqual(data["none"], 0)
        self.assertEqual(data["first"], 1)
        self.assertEqual(data["key"], "1.5|logout|a|10.0.0.1|||")

    def test_live_list_and_host_links_markup(self) -> None:
        for token in (
            "if (!manual && liveHold('logs', logRows, fresh))",
            "if (!manual && liveHold('drops', dropRows, fresh, data.status || null))",
            "adminPanel.append(livePill('logs'));",
            "adminPanel.append(livePill('drops'));",
            "class: 'table-wrap live-wrap'",
            "class: 'table-wrap drop-table-wrap live-wrap'",
            "target: '_blank', rel: 'noopener noreferrer'",
            "hostLink(entry.host)",
            "hostLink(host, 'mono')",
            "'Keresés a proxy-bejegyzések között…',\n      proxyHost\n",
            "const ok = await copyText(host.textContent);",
        ):
            self.assertIn(token, self.source, token)
        self.assertNotIn("Minecraft", self.source)
        for hungarian in (
            "Megnyitás új lapon", "Hostnév másolása", "Másolva", "Egyik sem",
            "Eltávolítás", "Keresés az események között…", "Tudnivalók",
            "Belépés és hozzáférés", "Fail2ban és tűzfal", "Adminisztráció",
            "Parancssor", "Vezérlőcsatorna", "Szolgáltatás",
        ):
            with self.subTest(text=hungarian):
                self.assertEqual(self.source.count(f"'{hungarian}': '"), 2)
        self.assertEqual(
            self.source.count("/^(\\d+) új bejegyzés — mutasd$/"), 2
        )

    def test_event_filter_translations_present(self) -> None:
        for hungarian, english, german in (
            ("összes esemény", "all events", "alle Ereignisse"),
            ("eseménykód", "event code", "Ereignis-Code"),
            (
                "keresés a látható értékekben (esemény, felhasználó, IP, "
                "szabály, ok)",
                "search visible values (event, user, IP, rule, reason)",
                "sichtbare Werte durchsuchen (Ereignis, Benutzer, IP, "
                "Regel, Grund)",
            ),
        ):
            self.assertIn(f"'{hungarian}': '{english}'", self.source)
            self.assertIn(f"'{hungarian}': '{german}'", self.source)

    def test_severity_filter_translations_present(self) -> None:
        for hungarian, english, german in (
            ("Szint", "Severity", "Schweregrad"),
            ("összes szint", "all severities", "alle Schweregrade"),
            ("információ", "info", "Info"),
            ("figyelmeztetés", "warning", "Warnung"),
            ("riasztás", "alert", "Alarm"),
        ):
            self.assertIn(f"'{hungarian}': '{english}'", self.source)
            self.assertIn(f"'{hungarian}': '{german}'", self.source)


if __name__ == "__main__":
    unittest.main()
