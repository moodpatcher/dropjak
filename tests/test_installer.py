#!/usr/bin/env python3
"""Static checks for the native installer (``install.sh``).

These tests only read repository files: they do not run the installer, touch
the network, import the application modules, or write anything. They guard
the packaging contract between ``install.sh``, the nftables template and the
documentation.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO_ROOT / "install.sh"
NFT_TEMPLATE = REPO_ROOT / "deploy" / "dropjak.nft"

# Every file the native unit imports or serves at runtime. ``server.py``
# imports ``gateway``, ``fail2ban`` and ``settings_store``; ``gateway`` also
# imports ``droplog``. The assets come from ``server.STATIC_FILES`` and
# ``VERSION`` is read by ``gateway._read_version()``.
REQUIRED_RUNTIME_FILES = {
    "server.py",
    "gateway.py",
    "settings_store.py",
    "fail2ban.py",
    "droplog.py",
    "tunnel.py",
    "index.html",
    "icon.png",
    "blocked.png",
    "unauthorized.png",
    "sus.png",
    "ok.png",
    "services.json",
    "VERSION",
}

EXPECTED_NFT_PLACEHOLDERS = {
    "__LAN_IF__",
    "__WAN_IF__",
    "__LAN_NET__",
    "__PORTAL_NET__",
    "__PORT__",
    "__FWD_MARK__",
    "__DROP_LOG_GROUP__",
    "__PROXY__",
    "__NO_FORWARD_NETS__",
}

# Pre-3.0.0 SSH plumbing that must not be described as current behaviour.
# The changelog section of ``DOKUMENTACIO.md`` is deliberately not scanned: it
# records that these were removed and is expected to name them.
STALE_SSH_TOKENS = ("host_ssh_v4", "admin-full")
DESIGN_BACKUP_DIR = "design-backup-2026-10-20"
# Each merged section of DOKUMENTACIO.md starts with its original file name.
SOURCE_MARK = re.compile(r"^_Source: `([^`]+)`", re.M)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def documentation_texts() -> list[tuple[str, str]]:
    """README plus the former ``docs/`` sections of DOKUMENTACIO.md.

    The frozen design backup is skipped, as are the sections that never lived
    under ``docs/`` (project status, local guide, changelog).
    """
    texts = [("README.md", read_text(REPO_ROOT / "README.md"))]
    merged = read_text(REPO_ROOT / "DOKUMENTACIO.md")
    marks = list(SOURCE_MARK.finditer(merged))
    for mark, nxt in zip(marks, marks[1:] + [None]):
        source = mark.group(1)
        if not source.startswith("docs/") or DESIGN_BACKUP_DIR in source:
            continue
        end = nxt.start() if nxt else len(merged)
        texts.append((f"DOKUMENTACIO.md ({source})", merged[mark.start():end]))
    return texts


def installed_sources(install_sh: str) -> set[str]:
    """Repository-relative paths installed with ``install -m 0644``.

    Backslash-continued shell lines are joined first so every source argument
    in a multi-line ``install`` command is found.
    """
    logical = re.sub(r"\\\n[ \t]*", " ", install_sh)
    sources: set[str] = set()
    for line in logical.splitlines():
        if re.match(r"\s*install\s+-m\s+0644\b", line):
            sources.update(re.findall(r'"\$SRC_DIR/([^"]+)"', line))
    return sources


class InstallerStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.install = read_text(INSTALL_SH)
        cls.template = read_text(NFT_TEMPLATE)

    def test_every_installed_source_file_exists(self) -> None:
        """Each ``install ... "$SRC_DIR/<path>"`` source must exist."""
        sources = installed_sources(self.install)
        self.assertTrue(
            sources,
            'install.sh has no "install -m 0644 $SRC_DIR/..." commands',
        )
        for relative in sorted(sources):
            with self.subTest(source=relative):
                self.assertTrue(
                    (REPO_ROOT / relative).is_file(),
                    f"install.sh installs a missing file: {relative}",
                )

    def test_copy_list_covers_runtime_modules_and_assets(self) -> None:
        copied = installed_sources(self.install)
        missing = REQUIRED_RUNTIME_FILES - copied
        self.assertEqual(
            missing,
            set(),
            "install.sh does not copy these runtime files: "
            + ", ".join(sorted(missing)),
        )

    def test_every_nft_placeholder_is_substituted(self) -> None:
        placeholders = set(
            re.findall(r"__[A-Z0-9_]+__", self.template)
        )
        self.assertEqual(
            placeholders,
            EXPECTED_NFT_PLACEHOLDERS,
            "deploy/dropjak.nft placeholders changed; update "
            "install.sh and EXPECTED_NFT_PLACEHOLDERS together",
        )
        for placeholder in sorted(placeholders):
            with self.subTest(placeholder=placeholder):
                self.assertIn(
                    placeholder,
                    self.install,
                    f"install.sh never mentions {placeholder}",
                )
                self.assertRegex(
                    self.install,
                    r"s\|" + re.escape(placeholder) + r"\|",
                    f"install.sh has no sed substitution for {placeholder}",
                )

    def test_placeholder_defaults_match_container_defaults(self) -> None:
        self.assertIn(
            'FWD_MARK="${HV_FWD_MARK:-0x44524a4b}"',
            self.install,
            "HV_FWD_MARK must default to the docker/entrypoint.sh value",
        )
        self.assertIn(
            'DROP_LOG_GROUP="${HV_DROP_LOG_GROUP:-5}"',
            self.install,
            "HV_DROP_LOG_GROUP must default to 5",
        )

    def test_rendered_template_leftover_check_aborts(self) -> None:
        pattern = re.compile(
            r"if\s+grep\s+-qE\s+'__\[A-Z0-9_\]\+__'\s+"
            r'"\$TMP_NFT"\s*;\s*then\s+die\b',
            re.DOTALL,
        )
        self.assertRegex(
            self.install,
            pattern,
            "install.sh must abort when a __PLACEHOLDER__ remains in the "
            "rendered nftables ruleset",
        )

    def test_docs_have_no_stale_ssh_wording(self) -> None:
        texts = documentation_texts()
        self.assertGreater(len(texts), 1, "no docs/ sections found")
        for name, text in texts:
            for token in STALE_SSH_TOKENS:
                with self.subTest(file=name, token=token):
                    self.assertNotRegex(
                        text,
                        r"\b" + re.escape(token) + r"\b",
                        f"{name} still contains "
                        f"pre-3.0.0 SSH wording: {token}",
                    )


if __name__ == "__main__":
    unittest.main()
