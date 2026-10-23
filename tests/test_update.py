"""Behavioural checks for the updater (``update.sh``).

The tests copy the script into a temporary checkout and, where needed,
initialise a small git repository there. The dry-run tests never touch the
host. The real-run test is only performed when the test process is not root.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "update.sh"
USAGE = "Usage: sudo ./update.sh [--yes] [--dry-run]"


class UpdateScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        os.chmod(self.dir, 0o755)
        self.checkout = self.dir / "checkout"
        self.checkout.mkdir()
        self.script = self.checkout / "update.sh"
        self.backups = self.dir / "backups"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def install_script(self) -> None:
        shutil.copy2(SCRIPT, self.script)
        os.chmod(self.script, 0o755)

    def init_repo(self) -> None:
        self.install_script()

        def git(*args: str) -> None:
            subprocess.run(
                ["git", "-C", str(self.checkout), *args],
                capture_output=True, text=True, timeout=30, check=True,
            )

        git("init", "-q")
        git("config", "user.email", "test@example.invalid")
        git("config", "user.name", "Dropjak Test")
        git("add", "-A")
        git("commit", "-q", "-m", "initial")

    def run_script(self, *args: str, script: Path | None = None,
                   env: dict[str, str] | None = None
                   ) -> subprocess.CompletedProcess:
        environment = os.environ.copy()
        if env:
            environment.update(env)
        return subprocess.run(
            ["/bin/bash", str(script or self.script), *args],
            capture_output=True, text=True, timeout=60, env=environment,
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

    def test_dry_run_in_git_checkout_changes_nothing(self) -> None:
        self.init_repo()
        result = self.run_script(
            "--dry-run", "--yes", env={"HV_BACKUPS": str(self.backups)}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("git", output)
        self.assertIn("pull --ff-only", output)
        self.assertFalse(self.backups.exists(),
                         "the dry run must not create the backup directory")
        status = subprocess.run(
            ["git", "-C", str(self.checkout), "status", "--porcelain"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(status.stdout, "", "the dry run dirtied the checkout")

    def test_dry_run_refuses_backup_inside_checkout(self) -> None:
        self.init_repo()
        inside = self.checkout / "backups"
        result = self.run_script(
            "--dry-run", "--yes", env={"HV_BACKUPS": str(inside)}
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the repository",
                      (result.stdout + result.stderr).lower())
        self.assertFalse(inside.exists())

    def test_real_run_requires_root(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the test process is root")
        self.install_script()
        result = self.run_script("--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root", (result.stdout + result.stderr).lower())

    def test_dry_run_outside_git_repository_still_succeeds(self) -> None:
        self.install_script()  # no git init
        result = self.run_script(
            "--dry-run", "--yes", env={"HV_BACKUPS": str(self.backups)}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = (result.stdout + result.stderr).lower()
        self.assertIn("not a git repository", output)
        self.assertFalse(self.backups.exists())


if __name__ == "__main__":
    unittest.main()
