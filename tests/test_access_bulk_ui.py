#!/usr/bin/env python3
"""Static and node tests for the access selector's shortcut buttons.

The test starts no browser: it checks the markers of the ``Mind kijelölése``
(select all) and ``Max`` buttons, the HU/EN/DE labels, and the pure
selection/TTL helper functions. The computations run with real node, as in
test_audit_ui and test_tunnel_ui.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX_PATH = ROOT / "index.html"


def _js_function(name: str, source: str) -> str:
    match = re.search(
        rf"function {re.escape(name)}\([^)]*\) \{{.*?\n\}}", source, re.S
    )
    if match is None:
        raise AssertionError(f"missing JS function: {name}")
    return match.group(0)


class AccessBulkUiMarkupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INDEX_PATH.read_text(encoding="utf-8")

    def test_select_all_and_max_buttons(self) -> None:
        # Real buttons, not elements that submit a form.
        self.assertIn(
            '<button id="rules-select-all" class="ghost small" type="button" '
            'data-i18n="Mind kijelölése">Mind kijelölése</button>',
            self.source,
        )
        self.assertIn(
            '<button id="ttl-max" class="ghost small" type="button" '
            'data-i18n="Max" data-i18n-aria-label="Maximális időtartam beállítása">Max</button>',
            self.source,
        )
        # The select-all shortcut sits next to Max in the duration row of the
        # footer; the rule list header holds only the title and the status.
        head = self.source.index('class="access-head"')
        rules = self.source.index('id="rules"', head)
        self.assertLess(self.source.index('id="access-pill"'), rules)
        self.assertGreater(
            self.source.index('id="rules-select-all"'), rules
        )
        ttl_row = self.source.index('class="ttl-row"')
        self.assertLess(ttl_row, self.source.index('id="ttl-max"'))
        self.assertLess(
            self.source.index('id="ttl-max"'),
            self.source.index('id="rules-select-all"'),
        )
        self.assertLess(
            self.source.index('id="rules-select-all"'),
            self.source.index("</div>", ttl_row),
        )
        # The field's own bounds are whole hours.
        self.assertIn('min="1" max="720" step="1"', self.source)

    def test_phone_layout_stacks_the_access_footer(self) -> None:
        # On phones the duration row wraps, the select-all control gets its
        # own full-width line and the primary button spans the footer.
        for needle in (
            ".ttl-row{width:100%;flex-wrap:wrap;gap:8px}",
            ".ttl-row #rules-select-all{flex:1 1 100%;min-height:40px}",
            ".foot-actions #grant{flex:1 1 100%;min-height:44px}",
            ".rules-scroll{-webkit-overflow-scrolling:touch;"
            "overscroll-behavior:contain}",
            "@media (max-width:400px){",
        ):
            self.assertIn(needle, self.source)

    def test_new_strings_are_translated(self) -> None:
        for needle in (
            "'Mind kijelölése': 'Select all'",
            "'Maximális időtartam beállítása': 'Set the maximum duration'",
            "'Mind kijelölése': 'Alle auswählen'",
            "'Maximális időtartam beállítása': 'Maximale Dauer festlegen'",
            "'Max': 'Max'",
        ):
            self.assertIn(needle, self.source)

    def test_selection_cap_comes_from_server(self) -> None:
        server = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn("MAX_SESSION_RULES = 16", server)
        self.assertIn('"max_rules": MAX_SESSION_RULES', server)
        self.assertIn("max_rules", self.source)


class AccessBulkHelpersNodeTests(unittest.TestCase):
    """Selection and the maximum hour count with real node execution."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INDEX_PATH.read_text(encoding="utf-8")

    @unittest.skipUnless(shutil.which("node"), "node is not available")
    def test_helpers(self) -> None:
        functions = "\n".join(
            _js_function(name, self.source)
            for name in (
                "selectedRules", "ttlBounds", "ttlDisplayBounds",
                "selectionMaxHours", "selectionLimit", "selectAllIds",
            )
        )
        script = (
            "const assert = require('assert');\n"
            "const DEFAULT_LIMITS = { min_ttl: 60, max_ttl: 2592000, "
            "default_ttl: 3600, max_rules: 16 };\n"
            "let auth = null;\n"
            "let selectedRuleIds = [];\n"
            + functions
            + r"""
const rules = [
  { id: 'a', max_ttl: 5400 },
  { id: 'b', max_ttl: 10800 },
  { id: 'c', max_ttl: 3600 },
];
auth = { limits: { min_ttl: 60, max_ttl: 7200 }, rules };
selectedRuleIds = ['a', 'b'];
assert.strictEqual(selectionMaxHours(), 1); // 5400 s -> 1 hour
selectedRuleIds = ['b'];
assert.strictEqual(selectionMaxHours(), 2); // 7200 s -> 2 hours
selectedRuleIds = ['a', 'b', 'c'];
assert.strictEqual(selectionMaxHours(), 1); // 3600 s -> 1 hour
selectedRuleIds = [];
assert.strictEqual(selectionMaxHours(), 2); // nothing selected: limits.max_ttl
// The stricter global limit wins over the rule's max_ttl.
auth = { limits: { min_ttl: 60, max_ttl: 3600 }, rules };
selectedRuleIds = ['b'];
assert.strictEqual(selectionMaxHours(), 1);
// A rule shorter than one hour: after rounding down, the field minimum.
auth = { limits: { min_ttl: 60, max_ttl: 7200 },
  rules: [{ id: 'short', max_ttl: 1800 }] };
selectedRuleIds = ['short'];
assert.strictEqual(selectionMaxHours(), 1);
// With a missing/invalid max_rules the server limit (16) applies.
auth = { limits: { min_ttl: 60, max_ttl: 7200, max_rules: 3 }, rules };
assert.strictEqual(selectionLimit(), 3);
auth = { limits: { min_ttl: 60, max_ttl: 7200 }, rules };
assert.strictEqual(selectionLimit(), 16);

const catalog = [{ id: 'a' }, { id: 'b' }, { id: 'c' }, { id: 'd' }];
assert.deepStrictEqual(selectAllIds(catalog, [], 3), ['a', 'b', 'c']);
// The existing selection is kept and topped up to the limit.
assert.deepStrictEqual(selectAllIds(catalog, ['d'], 3), ['d', 'a', 'b']);
assert.deepStrictEqual(selectAllIds(catalog, ['d'], 6), ['d', 'a', 'b', 'c']);
// Idempotent: a second call returns the same and does not modify the input.
const once = selectAllIds(catalog, [], 3);
const keep = ['a'];
selectAllIds(catalog, keep, 3);
assert.deepStrictEqual(keep, ['a']);
assert.deepStrictEqual(selectAllIds(catalog, once, 3), once);
// An unknown (meanwhile deleted) identifier drops out.
assert.deepStrictEqual(selectAllIds([{ id: 'a' }], ['x'], 16), ['a']);
process.stdout.write(JSON.stringify({ ok: true }));
"""
        )
        result = subprocess.run(
            ["node", "-e", script], capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"ok": True})


if __name__ == "__main__":
    unittest.main()
