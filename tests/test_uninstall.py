"""Behavioural checks for the uninstaller (``uninstall.sh``).

The dry-run tests copy the script into a temporary directory and execute it
there, so they never touch the host. The real-run test is only performed when
the test process itself is not root.
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "uninstall.sh"
USAGE = "Usage: sudo ./uninstall.sh [--yes] [--keep-data] [--dry-run]"


def demote() -> "callable[[], None] | None":
    """Return a preexec function that drops root privileges, if possible."""
    if os.geteuid() != 0:
        return None
    for name in ("nobody", "nfsnobody"):
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            continue

        def drop(entry=entry) -> None:
            os.setgroups([])
            os.setgid(entry.pw_gid)
            os.setuid(entry.pw_uid)

        return drop
    return None


class UninstallScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        # A demoted test user must be able to read the copied script.
        os.chmod(self.dir, 0o755)
        self.script = self.dir / "uninstall.sh"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def install(self, *markers: str) -> None:
        shutil.copy2(SCRIPT, self.script)
        os.chmod(self.script, 0o755)
        for marker in markers:
            path = self.dir / marker
            path.write_text("", encoding="utf-8")
            os.chmod(path, 0o644)

    def run_script(self, *args: str, drop_privs: bool = False,
                   script: Path | None = None
                   ) -> subprocess.CompletedProcess:
        kwargs = {"capture_output": True, "text": True, "timeout": 60}
        preexec = demote() if drop_privs else None
        if preexec is not None:
            kwargs["preexec_fn"] = preexec
        return subprocess.run(
            ["/bin/bash", str(script or self.script), *args], **kwargs
        )

    def test_syntax_is_valid(self) -> None:
        result = subprocess.run(
            ["/bin/bash", "-n", str(SCRIPT)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_prints_usage(self) -> None:
        result = self.run_script("--help", script=SCRIPT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(USAGE, result.stdout)

    def test_dry_run_with_compose_marker_changes_nothing(self) -> None:
        self.install("docker-compose.yml")
        result = self.run_script("--dry-run", "--yes", drop_privs=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = result.stdout + result.stderr
        self.assertIn(str(self.dir), output)
        self.assertIn("nft delete table inet hatarvedelem", output)
        self.assertTrue((self.dir / "docker-compose.yml").is_file())
        self.assertTrue(self.script.is_file())

    def test_dry_run_with_native_marker_changes_nothing(self) -> None:
        self.install("server.py")
        result = self.run_script("-n", "--yes", drop_privs=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = result.stdout + result.stderr
        self.assertIn(str(self.dir), output)
        self.assertIn("nft delete table inet hatarvedelem", output)
        self.assertTrue((self.dir / "server.py").is_file())
        self.assertTrue(self.script.is_file())

    def test_real_run_requires_root(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the test process is root")
        self.install("server.py")
        result = self.run_script("--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root", (result.stdout + result.stderr).lower())

    def test_refuses_directory_without_install_marker(self) -> None:
        self.install()  # the script alone is not a Dropjak marker
        result = self.run_script("--dry-run", "--yes", drop_privs=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing", result.stderr.lower())
        self.assertIn("does not look like a dropjak installation",
                      result.stderr.lower())
        self.assertTrue(self.script.is_file())


if __name__ == "__main__":
    unittest.main()
