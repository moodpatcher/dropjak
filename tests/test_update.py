"""Behavioural checks for the updater (``update.sh``).

The tests copy the script into a temporary checkout and, where needed,
initialise a small git repository there. The dry-run tests never touch the
host. The real-run test is only performed when the test process is not root.
"""

from __future__ import annotations

import os
import shutil
import stat
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



IMAGE_ID = "sha256:" + "cd" * 32

DOCKER_STUB = f"""#!/bin/bash
printf '%s\\n' "$*" >> "$STUB_LOG"
case "$1" in
  version) echo 27.0.0 ;;
  image) echo {IMAGE_ID} ;;
  images) for tag in ${{STUB_TAGS:-}}; do echo "$tag"; done ;;
esac
exit 0
"""

# Pretends to be root for `id -u`, so a real run works in a temporary
# directory without privileges.
ID_STUB = """#!/bin/bash
if [ "${1:-}" = "-u" ]; then echo 0; exit 0; fi
exec /usr/bin/id "$@"
"""

HOST_PATHS = (
    "/var/lib/docker/volumes/dropjak-state/_data",
    "/var/lib/hatarvedelem",
    "/etc/systemd/system/dropjak.service.d",
    "/etc/systemd/system/dropjak-helper.service.d",
)


def read_manifest(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            values[key] = value
    return values


class UpdateManifestTests(unittest.TestCase):
    """The manifest and the pre-update image tag that restore.sh relies on."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.checkout = self.dir / "checkout"
        self.checkout.mkdir()
        self.backups = self.dir / "backups"
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.log = self.dir / "stub.log"
        self.log.write_text("", encoding="utf-8")
        for name, text in (("docker", DOCKER_STUB), ("id", ID_STUB)):
            (self.bin / name).write_text(text, encoding="utf-8")
            os.chmod(self.bin / name, 0o755)
        shutil.copy2(SCRIPT, self.checkout / "update.sh")
        (self.checkout / "docker-compose.yml").write_text(
            "services:\n  dropjak:\n    image: dropjak:2\n", encoding="utf-8")
        (self.checkout / "VERSION").write_text("1.2.3\n", encoding="utf-8")
        (self.checkout / ".gitignore").write_text(".env\n", encoding="utf-8")
        env = self.checkout / ".env"
        env.write_text("PORT=8100\n", encoding="utf-8")
        os.chmod(env, 0o600)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Dropjak Test")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "initial")
        self.head = self.git("rev-parse", "HEAD")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def git(self, *args: str, cwd: Path | None = None) -> str:
        return subprocess.run(
            ["git", "-C", str(cwd or self.checkout), *args],
            capture_output=True, text=True, timeout=30, check=True,
        ).stdout.strip()

    def run_update(self, *args: str, fake_root: bool = False,
                   env: dict[str, str] | None = None
                   ) -> subprocess.CompletedProcess:
        environment = os.environ.copy()
        environment.pop("STUB_TAGS", None)
        stub_path = str(self.bin)
        if not fake_root:
            # Only docker; the real id.
            only_docker = self.dir / "docker-only"
            only_docker.mkdir(exist_ok=True)
            shutil.copy2(self.bin / "docker", only_docker / "docker")
            stub_path = str(only_docker)
        environment.update({
            "PATH": f"{stub_path}:{environment.get('PATH', '/usr/bin:/bin')}",
            "STUB_LOG": str(self.log),
            "HV_BACKUPS": str(self.backups),
        })
        if env:
            environment.update(env)
        return subprocess.run(
            ["/bin/bash", str(self.checkout / "update.sh"), *args],
            capture_output=True, text=True, timeout=60, env=environment,
            stdin=subprocess.DEVNULL,
        )

    def skip_if_host_state(self) -> None:
        for path in HOST_PATHS:
            if os.path.isdir(path):
                self.skipTest(f"{path} exists on this host; a real run would copy it")

    def manifests(self) -> list[Path]:
        return sorted(self.backups.glob("dropjak-*.manifest"))

    def test_dry_run_previews_manifest_and_tag(self) -> None:
        result = self.run_update("--dry-run", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        out = result.stdout
        self.assertIn("[dry-run]   style=compose", out)
        self.assertIn(f"[dry-run]   commit={self.head}", out)
        self.assertIn("[dry-run]   branch=main", out)
        self.assertIn(f"[dry-run]   compose_image_id={IMAGE_ID}", out)
        self.assertRegex(out, r"\[dry-run\] docker tag dropjak:2 "
                              r"dropjak:pre-update-\d{8}-\d{6}")
        self.assertFalse(self.backups.exists())
        calls = self.log.read_text().splitlines()
        self.assertFalse(any(c.startswith(("tag ", "rmi ")) for c in calls),
                         calls)

    def test_backup_only_writes_manifest_and_tag_without_pull(self) -> None:
        self.skip_if_host_state()
        result = self.run_update("--backup-only", "--yes", fake_root=True,
                                 env={"STUB_TAGS": " ".join(
                                     f"dropjak:pre-update-2026100{i}-101010"
                                     for i in range(1, 6))})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifests = self.manifests()
        self.assertEqual(len(manifests), 1)
        self.assertEqual(stat.S_IMODE(manifests[0].stat().st_mode), 0o600)
        values = read_manifest(manifests[0])
        self.assertEqual(values["kind"], "backup")
        self.assertEqual(values["style"], "compose")
        self.assertEqual(values["commit"], self.head)
        self.assertEqual(values["branch"], "main")
        self.assertEqual(values["version"], "1.2.3")
        self.assertEqual(values["compose_image"], "dropjak:2")
        self.assertEqual(values["compose_image_id"], IMAGE_ID)
        ts = values["timestamp"]
        self.assertEqual(values["pre_update_tag"], f"dropjak:pre-update-{ts}")
        self.assertTrue((self.backups / values["config_backup"]).is_file())
        calls = self.log.read_text().splitlines()
        self.assertIn(f"tag dropjak:2 dropjak:pre-update-{ts}", calls)
        self.assertFalse(any(c.startswith("rmi ") for c in calls),
                         "--backup-only must never prune pre-update tags")
        self.assertNotIn("pull --ff-only", result.stdout)
        self.assertNotIn("commit after pull", result.stdout)

    def test_update_writes_manifest_before_pull_and_prunes(self) -> None:
        self.skip_if_host_state()
        origin = self.dir / "origin.git"
        subprocess.run(["git", "clone", "-q", "--bare", str(self.checkout),
                        str(origin)], check=True, capture_output=True,
                       timeout=30)
        self.git("remote", "add", "origin", str(origin))
        self.git("fetch", "-q", "origin")
        self.git("branch", "-q", "--set-upstream-to=origin/main", "main")
        other = self.dir / "other"
        subprocess.run(["git", "clone", "-q", str(origin), str(other)],
                       check=True, capture_output=True, timeout=30)
        self.git("config", "user.email", "test@example.invalid", cwd=other)
        self.git("config", "user.name", "Dropjak Test", cwd=other)
        (other / "VERSION").write_text("1.2.4\n", encoding="utf-8")
        self.git("commit", "-q", "-am", "next", cwd=other)
        self.git("push", "-q", "origin", "main", cwd=other)
        new_head = self.git("rev-parse", "HEAD", cwd=other)

        tags = [f"dropjak:pre-update-2026100{i}-101010" for i in range(1, 5)]
        result = self.run_update("--yes", fake_root=True,
                                 env={"STUB_TAGS": " ".join(tags)})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.git("rev-parse", "HEAD"), new_head)
        values = read_manifest(self.manifests()[0])
        self.assertEqual(values["kind"], "update")
        self.assertEqual(values["commit"], self.head,
                         "the manifest must record the commit before the pull")
        self.assertEqual(values["version"], "1.2.3")
        calls = self.log.read_text().splitlines()
        rmis = [c for c in calls if c.startswith("rmi ")]
        # Four old tags listed; the newest three are kept.
        self.assertEqual(rmis, ["rmi dropjak:pre-update-20261001-101010"])
        self.assertIn("restore.sh", result.stdout)


if __name__ == "__main__":
    unittest.main()
