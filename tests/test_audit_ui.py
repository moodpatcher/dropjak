#!/usr/bin/env python3
"""Statikus frontend-tesztek az auditnapló megjelenítéséhez.

A teszt nem indít böngészőt: az ``index.html`` eseménycímke-térképét és a
naplószűrő/naplómegjelenítő jelölőit ellenőrzi. A szerveroldali eseménykódokat
AST-vel gyűjtjük ki, így a több sorra tördelt hívások és a feltételes
eseménynevek is helyesen számítanak.
"""

from __future__ import annotations

import ast
import re
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
    """A ``const NÉV = { ... }`` objektumliterál pontos törzse."""
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
    raise AssertionError(f"lezáratlan objektumliterál: {declaration}")


def _parse_event_labels(source: str) -> dict[str, tuple[str, str, str]]:
    body = _js_object_body(source, "const AUDIT_EVENT_LABELS = {")
    # A statikus oldal nem tartalmazhatja a szerveroldali "totp_recovery"
    # mezőnevet, ezért az egyik eseménykulcs két literálból áll össze.
    body = re.sub(
        r"\[\s*'([^']*)'\s*\+\s*'([^']*)'\s*\]\s*:",
        lambda match: f"{match.group(1)}{match.group(2)}:",
        body,
    )
    labels: dict[str, tuple[str, str, str]] = {}
    for match in LABEL_ENTRY_RE.finditer(body):
        labels[match.group(1)] = match.group(2, 3, 4)
    return labels


def _constant_strings(node: ast.AST | None) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.IfExp):
        return _constant_strings(node.body) + _constant_strings(node.orelse)
    return []


def _is_audit_receiver(node: ast.AST) -> bool:
    """``audit.write``, ``self.gw.audit.write`` és ``gateway.AuditLog().write``."""
    if isinstance(node, ast.Name):
        return node.id == "audit"
    if isinstance(node, ast.Attribute):
        return node.attr == "audit"
    if isinstance(node, ast.Call):
        return "audit" in ast.unparse(node).lower()
    return False


def _emitted_audit_events() -> set[str]:
    """A szerveroldalon ténylegesen kibocsátott eseménykódok."""
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
    """Az audit-események és a naplószűrő statikus frontend-jelölői."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INDEX_PATH.read_text(encoding="utf-8")
        cls.labels = _parse_event_labels(cls.source)
        cls.emitted = _emitted_audit_events()

    def test_event_label_map_covers_every_emitted_event(self) -> None:
        self.assertTrue(self.emitted, "nem található audit-esemény a forrásban")
        missing = sorted(self.emitted - set(self.labels))
        self.assertFalse(
            missing,
            "hiányzó AUDIT_EVENT_LABELS bejegyzés: " + ", ".join(missing),
        )
        for code in sorted(self.emitted):
            row = self.labels[code]
            self.assertEqual(len(row), 3, code)
            for label in row:
                self.assertTrue(label.strip(), f"üres címke: {code}")

    def test_severity_map_events_are_labelled(self) -> None:
        # A központi súlyossági térkép régi/új eseményei is kapjanak címkét.
        missing = sorted(set(gateway.AUDIT_SEVERITY) - set(self.labels))
        self.assertFalse(
            missing,
            "hiányzó AUDIT_EVENT_LABELS bejegyzés: " + ", ".join(missing),
        )

    def test_label_lookup_and_fallback(self) -> None:
        self.assertIn("function auditEventLabel(code)", self.source)
        self.assertIn("const row = AUDIT_EVENT_LABELS[code]", self.source)
        # Ismeretlen kód esetén a nyers eseménykód marad.
        self.assertIn("if (!row) return code", self.source)
        self.assertIn("row[lang === 'en' ? 1 : lang === 'de' ? 2 : 0]", self.source)
        # A naplótábla nem a tr() szótárból fordítja az eseményneveket.
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
        # A jelvény szövege és tooltipje is fordul.
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
        # adminSetTab, a Frissítés gomb és a Szűrők törlése küldi a jelzőt.
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
        # Az eseményszűrő a címkézett kódokból épül, ismeretlen/legacy
        # értéket megtartva, és a select értékét használja a szűrés.
        for token in (
            "const eventSelect = el('select'",
            "Object.keys(AUDIT_EVENT_LABELS)",
            "if (logFilter.event && !eventCodes.includes(logFilter.event))",
            "value: '', text: tr('összes esemény')",
            "text: `${auditEventLabel(code)} (${code})`",
            "event: eventSelect.value",
            "['Esemény', eventSelect]",
            "for (const node of [userInput, qInput, ipInput])",
            # IP/CIDR szűrő és a proxy-események kiemelt hostja.
            "ip: ipInput.value.trim()",
            "ip: logFilter.ip || ''",
            "['IP-cím / CIDR', ipInput]",
            "function logSubject(entry)",
            "class: 'log-subject mono'",
        ):
            self.assertIn(token, self.source, token)
        self.assertNotIn("placeholder: tr('esemény')", self.source)
        # A nyers eseménykód a lokalizált címke után, kicsi muted code-ként
        # jelenik meg, hogy kereshető és felismerhető legyen.
        self.assertIn("class: 'log-event-code muted'", self.source)
        self.assertIn("text: entry.event", self.source)
        self.assertIn(
            "auditEventLabel(entry.event || '—')", self.source
        )
        # Az Enterrel indított kézi betöltés akkor is újrarajzol, ha a
        # fókusz a szűrőmezőben maradt; az automatikus frissítés nem.
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
