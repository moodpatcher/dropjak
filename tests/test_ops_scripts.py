"""Behavioural checks for the operator scripts ``start.sh``, ``stop.sh`` and
``restore.sh``.

Every test copies the scripts into a temporary checkout and runs them in
dry-run mode with stub ``docker``/``systemctl`` commands first on PATH, so
the host is never touched. Real runs are only checked for the root
requirement.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
START = ROOT / "start.sh"
STOP = ROOT / "stop.sh"
RESTORE = ROOT / "restore.sh"
UPDATE = ROOT / "update.sh"

IMAGE_ID = "sha256:" + "ab" * 32
GOOD_KEY = "k" * 64

# A stub docker: logs every call and answers the read-only queries.
DOCKER_STUB = f"""#!/bin/bash
printf '%s\\n' "$*" >> "$STUB_LOG"
case "$1" in
  version) echo 27.0.0 ;;
  compose) exit 0 ;;
  image)
    [[ -z "${{STUB_NO_IMAGE:-}}" ]] || exit 1
    echo {IMAGE_ID} ;;
  images) for tag in ${{STUB_TAGS:-}}; do echo "$tag"; done ;;
  inspect) echo "running healthy" ;;
esac
exit 0
"""

SYSTEMCTL_STUB = """#!/bin/bash
printf 'systemctl %s\\n' "$*" >> "$STUB_LOG"
exit 0
"""

COMPOSE_YML = """services:
  dropjak:
    image: dropjak:2
  caddy:
    image: caddy:2.10.2-alpine@sha256:4c6e
    profiles: ["proxy"]
"""

UNIT_TEXT = "[Service]\nEnvironment=PORT=8080\nExecStart=/bin/true\n"


def write_exec(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o755)


class OpsBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        os.chmod(self.dir, 0o755)
        self.checkout = self.dir / "checkout"
        self.checkout.mkdir()
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.log = self.dir / "stub.log"
        self.log.write_text("", encoding="utf-8")
        self.units = self.dir / "systemd"
        self.units.mkdir()
        self.backups = self.dir / "backups"
        write_exec(self.bin / "docker", DOCKER_STUB)
        write_exec(self.bin / "systemctl", SYSTEMCTL_STUB)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # ------------------------------------------------------------ layout

    def install_scripts(self) -> None:
        for script in (START, STOP, RESTORE, UPDATE):
            shutil.copy2(script, self.checkout / script.name)
            os.chmod(self.checkout / script.name, 0o755)

    def compose_layout(self, env: str | None = None) -> None:
        self.install_scripts()
        (self.checkout / "docker-compose.yml").write_text(
            COMPOSE_YML, encoding="utf-8")
        (self.checkout / "docker").mkdir(exist_ok=True)
        shutil.copy2(ROOT / "docker" / "entrypoint.sh",
                     self.checkout / "docker" / "entrypoint.sh")
        (self.checkout / "deploy").mkdir(exist_ok=True)
        shutil.copy2(ROOT / "deploy" / "Caddyfile",
                     self.checkout / "deploy" / "Caddyfile")
        (self.checkout / "VERSION").write_text("9.9.9\n", encoding="utf-8")
        self.write_env(env if env is not None else "PORT=8100\n")

    def write_env(self, text: str, mode: int = 0o600) -> None:
        path = self.checkout / ".env"
        path.write_text(text, encoding="utf-8")
        os.chmod(path, mode)

    def native_units(self) -> None:
        for unit in ("dropjak.service", "dropjak-helper.service",
                     "dropjak-firewall.service",
                     "dropjak-firewall-check.timer"):
            (self.units / unit).write_text(UNIT_TEXT, encoding="utf-8")

    # ------------------------------------------------------------ running

    def run_script(self, name: str, *args: str,
                   env: dict[str, str] | None = None,
                   script: Path | None = None) -> subprocess.CompletedProcess:
        environment = os.environ.copy()
        for key in ("SSH_CONNECTION", "COMPOSE_PROFILES", "HV_PROXY",
                    "HV_PROXY_KEY", "PORT", "STUB_NO_IMAGE", "STUB_TAGS"):
            environment.pop(key, None)
        environment.update({
            "PATH": f"{self.bin}:{environment.get('PATH', '/usr/bin:/bin')}",
            "STUB_LOG": str(self.log),
            "HV_SYSTEMD_DIR": str(self.units),
            "HV_BACKUPS": str(self.backups),
        })
        if env:
            environment.update(env)
        return subprocess.run(
            ["/bin/bash", str(script or self.checkout / name), *args],
            capture_output=True, text=True, timeout=120, env=environment,
            stdin=subprocess.DEVNULL,
        )

    def stub_calls(self) -> list[str]:
        return [line for line in self.log.read_text().splitlines() if line]


# ---------------------------------------------------------------- stop.sh


class StopScriptTests(OpsBase):
    def test_syntax_is_valid(self) -> None:
        result = subprocess.run(["/bin/bash", "-n", str(STOP)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_prints_usage(self) -> None:
        result = self.run_script("stop.sh", "--help", script=STOP)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Usage: sudo ./stop.sh [--yes] [--down] [--dry-run]",
                      result.stdout)

    def test_never_flushes_or_deletes_the_nft_table(self) -> None:
        text = STOP.read_text(encoding="utf-8")
        code = "\n".join(line for line in text.splitlines()
                         if not line.lstrip().startswith("#"))
        self.assertIsNone(re.search(r"\bnft\b", code),
                          "stop.sh must not call nft at all")
        for pattern in (r"flush\s+(ruleset|table|set|chain)",
                        r"delete\s+table", r"destroy\s+table"):
            self.assertIsNone(re.search(pattern, code), pattern)

    def test_dry_run_compose_stops_caddy_before_portal(self) -> None:
        self.compose_layout("COMPOSE_PROFILES=proxy\nHV_PROXY=1\n")
        result = self.run_script("stop.sh", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        out = result.stdout
        caddy = out.index("docker compose --profile proxy stop caddy")
        portal = out.index("docker compose --profile proxy stop\n")
        self.assertLess(caddy, portal)
        self.assertNotIn(" down", out)
        self.assertIn("stays loaded", out)
        self.assertEqual(self.stub_calls(), [],
                         "the dry run must not call docker")

    def test_dry_run_down_never_removes_volumes(self) -> None:
        self.compose_layout()
        result = self.run_script("stop.sh", "--dry-run", "--down")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("docker compose down --remove-orphans", result.stdout)
        self.assertNotRegex(result.stdout, r"down[^\n]*\s-v\b")

    def test_dry_run_native_stops_portal_then_helper(self) -> None:
        self.install_scripts()
        self.native_units()
        result = self.run_script("stop.sh", "-n")
        self.assertEqual(result.returncode, 0, result.stderr)
        out = result.stdout
        portal = out.index("systemctl stop dropjak.service")
        helper = out.index("systemctl stop dropjak-helper.service")
        self.assertLess(portal, helper)
        self.assertNotIn("systemctl stop dropjak-firewall", out)
        self.assertIn("native systemd", out)

    def test_ssh_session_gets_the_grant_warning(self) -> None:
        self.compose_layout()
        result = self.run_script(
            "stop.sh", "--dry-run",
            env={"SSH_CONNECTION": "203.0.113.7 50000 198.51.100.1 22"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("203.0.113.7", result.stderr)
        self.assertIn("does not remove your SSH grant", result.stderr)

    def test_down_is_refused_for_native(self) -> None:
        self.install_scripts()
        self.native_units()
        result = self.run_script("stop.sh", "--dry-run", "--down")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Docker Compose deployment only", result.stderr)

    def test_real_run_requires_root(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the test process is root")
        self.compose_layout()
        result = self.run_script("stop.sh", "--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root", result.stderr.lower())
        self.assertEqual(self.stub_calls(), [])


# ---------------------------------------------------------------- start.sh


class StartScriptTests(OpsBase):
    def test_syntax_is_valid(self) -> None:
        result = subprocess.run(["/bin/bash", "-n", str(START)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_prints_usage(self) -> None:
        result = self.run_script("start.sh", "--help", script=START)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Usage: sudo ./start.sh [--yes] [--dry-run]",
                      result.stdout)

    def test_dry_run_compose_passes_preflight(self) -> None:
        self.compose_layout(
            f"COMPOSE_PROFILES=proxy\nHV_PROXY=1\nHV_PROXY_KEY={GOOD_KEY}\n"
            "PORT=8100\n")
        result = self.run_script("start.sh", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        out = result.stdout
        self.assertIn("preflight ok: sh -n docker/entrypoint.sh", out)
        self.assertIn("preflight ok: docker compose config -q", out)
        self.assertIn("preflight ok: image dropjak:2 exists locally", out)
        self.assertIn("caddy validate", out)
        portal = out.index("docker compose --profile proxy up -d dropjak")
        rest = out.index("docker compose --profile proxy up -d\n")
        self.assertLess(portal, rest)
        self.assertIn("http://127.0.0.1:8100/api/status", out)
        self.assertNotIn(GOOD_KEY, out + result.stderr)
        calls = self.stub_calls()
        self.assertFalse(any(" up" in call for call in calls), calls)
        self.assertFalse(any(call.startswith("run ") for call in calls), calls)

    def test_short_proxy_key_fails_preflight(self) -> None:
        self.compose_layout(
            "COMPOSE_PROFILES=proxy\nHV_PROXY=1\nHV_PROXY_KEY=short\n")
        result = self.run_script("start.sh", "--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HV_PROXY_KEY of at least 32 characters (now 5)",
                      result.stderr)
        self.assertIn("nothing was started", result.stderr)
        self.assertNotIn("up -d", result.stdout)

    def test_world_readable_env_fails_preflight(self) -> None:
        self.compose_layout()
        os.chmod(self.checkout / ".env", 0o644)
        result = self.run_script("start.sh", "--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("chmod 600", result.stderr)

    def test_missing_image_prints_the_host_network_build(self) -> None:
        self.compose_layout()
        result = self.run_script("start.sh", "--dry-run",
                                 env={"STUB_NO_IMAGE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .",
            result.stderr)

    def test_build_flag_builds_on_the_host_network(self) -> None:
        self.compose_layout()
        result = self.run_script("start.sh", "--dry-run", "--build",
                                 env={"STUB_NO_IMAGE": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("env DOCKER_BUILDKIT=0 docker build --network host "
                      "-t dropjak:2 .", result.stdout)

    def test_caddy_validate_can_be_skipped(self) -> None:
        self.compose_layout(
            f"COMPOSE_PROFILES=proxy\nHV_PROXY=1\nHV_PROXY_KEY={GOOD_KEY}\n")
        result = self.run_script("start.sh", "--dry-run",
                                 "--skip-caddy-validate")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("caddy validate skipped", result.stdout)

    def test_rollback_dry_run_names_the_newest_pre_update_tag(self) -> None:
        self.compose_layout()
        tags = ("dropjak:pre-update-20261001-101010 "
                "dropjak:pre-update-20261020-101010 dropjak:2 "
                "dropjak:pre-update-20261010-101010")
        result = self.run_script("start.sh", "--dry-run", "--rollback-on-fail",
                                 env={"STUB_TAGS": tags})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("on failure: docker tag dropjak:pre-update-20261020-101010 "
                      "dropjak:2", result.stdout)

    def test_dry_run_native_starts_helper_then_portal(self) -> None:
        self.install_scripts()
        self.native_units()
        result = self.run_script("start.sh", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        out = result.stdout
        helper = out.index("systemctl start dropjak-helper.service")
        portal = out.index("systemctl start dropjak.service")
        self.assertLess(helper, portal)
        self.assertIn("nft -c -f /etc/nftables/dropjak.nft", out)
        self.assertIn("http://127.0.0.1:8080/api/status", out)
        self.assertEqual(self.stub_calls(), [])

    def test_native_preflight_requires_the_units(self) -> None:
        self.install_scripts()
        result = self.run_script("start.sh", "--dry-run", "--native")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dropjak-helper.service not installed", result.stderr)

    def test_real_run_requires_root(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the test process is root")
        self.compose_layout()
        result = self.run_script("start.sh", "--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root", result.stderr.lower())
        self.assertEqual(self.stub_calls(), [])


# ---------------------------------------------------------------- restore.sh


class RestoreScriptTests(OpsBase):
    def setUp(self) -> None:
        super().setUp()
        self.compose_layout()
        (self.checkout / ".gitignore").write_text(".env\nsecrets/\n",
                                                  encoding="utf-8")
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Dropjak Test")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "first")
        self.first = self.git("rev-parse", "HEAD")
        (self.checkout / "VERSION").write_text("9.9.10\n", encoding="utf-8")
        self.git("commit", "-q", "-am", "second")
        self.second = self.git("rev-parse", "HEAD")
        self.backups.mkdir()
        os.chmod(self.backups, 0o700)

    def git(self, *args: str, cwd: Path | None = None) -> str:
        result = subprocess.run(
            ["git", "-C", str(cwd or self.checkout), *args],
            capture_output=True, text=True, timeout=30, check=True)
        return result.stdout.strip()

    def add_backup(self, ts: str, commit: str, kind: str = "update",
                   style: str = "compose", with_state: bool = True) -> None:
        config = self.backups / f"dropjak-{ts}.tar.gz"
        with tarfile.open(config, "w:gz") as archive:
            data = f"PORT=8100\n# backup {ts}\n".encode()
            info = tarfile.TarInfo("./env")
            info.size = len(data)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))
        state_name = ""
        if with_state:
            state_name = f"dropjak-state-{ts}.tar.gz"
            with tarfile.open(self.backups / state_name, "w:gz") as archive:
                data = b"{}\n"
                info = tarfile.TarInfo("./users.json")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        lines = [
            "# Dropjak update manifest (read by restore.sh)",
            "format=1", f"kind={kind}", f"timestamp={ts}",
            "created=2026-10-24T10:00:00+0200", f"style={style}",
            f"checkout={self.checkout}", f"commit={commit}", "branch=main",
            "version=9.9.9", "compose_image=dropjak:2",
            f"compose_image_id={IMAGE_ID}",
            f"pre_update_tag=dropjak:pre-update-{ts}",
            f"config_backup={config.name}",
            f"docker_state_backup={state_name if style == 'compose' else ''}",
            f"native_state_backup={state_name if style == 'native' else ''}",
        ]
        manifest = self.backups / f"dropjak-{ts}.manifest"
        manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.chmod(manifest, 0o600)

    def test_syntax_is_valid(self) -> None:
        result = subprocess.run(["/bin/bash", "-n", str(RESTORE)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_prints_usage(self) -> None:
        result = self.run_script("restore.sh", "--help", script=RESTORE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Usage: sudo ./restore.sh [--list] [--backup TIMESTAMP]",
                      result.stdout)
        self.assertIn("git reset --keep", result.stdout)

    def test_list_shows_every_manifest(self) -> None:
        self.add_backup("20261020-101010", self.first)
        self.add_backup("20261021-101010", self.second, kind="backup")
        result = self.run_script("restore.sh", "--list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"20261020-101010\s+update\s+compose")
        self.assertRegex(result.stdout, r"20261021-101010\s+backup\s+compose")
        self.assertIn(self.first[:7], result.stdout)

    def test_dry_run_picks_the_newest_update_backup(self) -> None:
        self.add_backup("20261019-101010", self.first)
        self.add_backup("20261020-101010", self.first)
        # Newer, but a safety backup: not the default.
        self.add_backup("20261022-101010", self.second, kind="backup")
        result = self.run_script("restore.sh", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        out = result.stdout
        self.assertIn("Backup:                20261020-101010 (update", out)
        self.assertIn("update.sh --backup-only", out)
        self.assertIn("docker compose stop", out)
        self.assertIn(f"checkout --detach {self.first}", out)
        self.assertIn("docker tag dropjak:pre-update-20261020-101010 dropjak:2",
                      out)
        self.assertIn("dropjak-state-20261020-101010.tar.gz", out)
        self.assertIn("start.sh", out)
        # Nothing changed.
        self.assertEqual(self.git("rev-parse", "HEAD"), self.second)
        self.assertEqual((self.checkout / ".env").read_text(), "PORT=8100\n")
        self.assertEqual(sorted(p.name for p in self.backups.iterdir()),
                         sorted([
                             "dropjak-20261019-101010.manifest",
                             "dropjak-20261019-101010.tar.gz",
                             "dropjak-state-20261019-101010.tar.gz",
                             "dropjak-20261020-101010.manifest",
                             "dropjak-20261020-101010.tar.gz",
                             "dropjak-state-20261020-101010.tar.gz",
                             "dropjak-20261022-101010.manifest",
                             "dropjak-20261022-101010.tar.gz",
                             "dropjak-state-20261022-101010.tar.gz",
                         ]))
        calls = self.stub_calls()
        self.assertFalse(any(call.startswith(("tag ", "run ", "volume create"))
                             for call in calls), calls)

    def test_dry_run_selected_backup(self) -> None:
        self.add_backup("20261019-101010", self.first)
        self.add_backup("20261020-101010", self.second)
        result = self.run_script("restore.sh", "--dry-run",
                                 "--backup", "20261019-101010")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Backup:                20261019-101010", result.stdout)
        self.assertIn(f"checkout --detach {self.first}", result.stdout)

    def test_dry_run_uses_reset_keep_on_the_tracked_branch(self) -> None:
        origin = self.dir / "origin.git"
        subprocess.run(["git", "clone", "-q", "--bare", str(self.checkout),
                        str(origin)], check=True, capture_output=True,
                       timeout=30)
        self.git("remote", "add", "origin", str(origin))
        self.git("fetch", "-q", "origin")
        self.git("branch", "-q", "--set-upstream-to=origin/main", "main")
        self.add_backup("20261020-101010", self.first)
        result = self.run_script("restore.sh", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"reset --keep {self.first}", result.stdout)

    def test_dirty_tree_is_refused(self) -> None:
        self.add_backup("20261020-101010", self.first)
        (self.checkout / "VERSION").write_text("local change\n",
                                               encoding="utf-8")
        result = self.run_script("restore.sh", "--dry-run", "--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("local changes", result.stderr)
        self.assertIn("stash", result.stderr)
        self.assertEqual(self.stub_calls(), [])

    def test_missing_archive_is_refused(self) -> None:
        self.add_backup("20261020-101010", self.first)
        (self.backups / "dropjak-state-20261020-101010.tar.gz").unlink()
        result = self.run_script("restore.sh", "--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("state archive not found", result.stderr)

    def test_unknown_commit_is_refused(self) -> None:
        self.add_backup("20261020-101010", "0" * 40)
        result = self.run_script("restore.sh", "--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not in this repository", result.stderr)

    def test_dry_run_native_restores_state_with_ownership(self) -> None:
        self.native_units()
        self.add_backup("20261020-101010", self.first, style="native")
        result = self.run_script("restore.sh", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        out = result.stdout
        self.assertIn("systemctl stop dropjak.service", out)
        self.assertIn("find /var/lib/hatarvedelem -mindepth 1 -delete", out)
        self.assertIn("chown -R hatarvedelem:hatarvedelem /var/lib/hatarvedelem",
                      out)
        self.assertIn("install.sh --wan-if", out)

    def test_real_run_requires_root(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the test process is root")
        self.add_backup("20261020-101010", self.first)
        result = self.run_script("restore.sh", "--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root", result.stderr.lower())

    def test_never_deletes_backups(self) -> None:
        text = RESTORE.read_text(encoding="utf-8")
        for line in text.splitlines():
            if re.search(r"\brm\b", line):
                self.assertNotIn("BACKUP_DIR", line, line)


class InstallerCopiesOpsScripts(unittest.TestCase):
    def test_install_sh_installs_the_scripts_executable(self) -> None:
        text = (ROOT / "install.sh").read_text(encoding="utf-8")
        logical = re.sub(r"\\\n[ \t]*", " ", text)
        line = next(l for l in logical.splitlines()
                    if '"$SRC_DIR/start.sh"' in l)
        self.assertRegex(line, r"^\s*install -m 0755 ")
        for name in ("start.sh", "stop.sh", "restore.sh"):
            self.assertIn(f'"$SRC_DIR/{name}"', line)

    def test_scripts_are_executable_in_the_repository(self) -> None:
        for script in (START, STOP, RESTORE):
            self.assertTrue(script.stat().st_mode & stat.S_IXUSR, script)


if __name__ == "__main__":
    unittest.main()
