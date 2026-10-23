"""The interactive .env generator (configure.sh) and the proxy seed."""

import importlib
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "configure.sh"
sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402
import settings_store  # noqa: E402

# The order of the prompts: single-NIC question, LAN if, WAN if, LAN net,
# portal net, mgmt net, port, access mode, admin yes/no, admin user, admin
# password.
ANSWERS = [
    "n", "eth1", "eth0", "192.168.10.0/24", "0.0.0.0/0",
    "192.168.10.0/24", "8100", "1", "y", "admin", "secret123",
]
MODE2_ANSWERS = [
    "n", "eth1", "eth0", "192.168.10.0/24", "0.0.0.0/0",
    "192.168.10.0/24", "8100", "2", "example.com",
    "fw.example.com", "y", "admin", "secret123",
]


def env_value(text: str, name: str) -> str:
    return [
        line.split("=", 1)[1] for line in text.splitlines()
        if line.startswith(name + "=")
    ][0]


class ConfigureScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.env_file = Path(self.tmp.name) / ".env"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_script(self, answers: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(SCRIPT), "--env-file", str(self.env_file)],
            input="\n".join(answers) + "\n",
            capture_output=True, text=True, timeout=30,
        )

    def test_generates_env_with_public_portal_and_admin(self) -> None:
        result = self.run_script(ANSWERS)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.env_file.read_text(encoding="utf-8")
        self.assertIn("HV_SINGLE_NIC=0", text)
        self.assertIn("HV_LAN_IF=eth1", text)
        self.assertIn("HV_WAN_IF=eth0", text)
        self.assertIn("HV_LAN_NET=192.168.10.0/24", text)
        self.assertIn("HV_PORTAL_NET=0.0.0.0/0", text)
        self.assertIn("HV_MGMT_NET=192.168.10.0/24", text)
        self.assertIn("PORT=8100", text)
        self.assertIn("HV_ADMIN_ENABLED=1", text)
        self.assertIn("HV_ADMIN_USER=admin", text)
        self.assertIn("HV_ADMIN_PASSWORD=secret123", text)
        # Mode 1 keeps the portal on the host IP over plain HTTP.
        self.assertNotIn("HV_PROXY", text)
        self.assertNotIn("HV_PORTAL_URL", text)
        self.assertNotIn("HV_PORTAL_HOSTS", text)
        self.assertIn("plain HTTP", result.stderr)
        mode = stat.S_IMODE(os.stat(self.env_file).st_mode)
        self.assertEqual(mode, 0o600)

    def test_existing_values_become_defaults(self) -> None:
        self.env_file.write_text(
            "HV_LAN_IF=lan9\n"
            "HV_WAN_IF=wan9\n"
            "HV_LAN_NET=10.20.0.0/24\n"
            "HV_PORTAL_NET=10.20.0.0/24\n"
            "HV_MGMT_NET=10.20.0.0/24\n"
            "PORT=8200\n"
            "HV_ADMIN_USER=root2\n",
            encoding="utf-8",
        )
        answers = ["n", "", "", "", "", "", "", "1", "", "", ""]
        result = self.run_script(answers)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.env_file.read_text(encoding="utf-8")
        self.assertIn("HV_LAN_IF=lan9", text)
        self.assertIn("HV_WAN_IF=wan9", text)
        self.assertIn("HV_PORTAL_NET=10.20.0.0/24", text)
        self.assertIn("PORT=8200", text)
        self.assertIn("HV_ADMIN_USER=root2", text)

    def test_password_with_special_characters_is_quoted(self) -> None:
        answers = list(ANSWERS)
        answers[-1] = "p@ss word"
        result = self.run_script(answers)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "HV_ADMIN_PASSWORD='p@ss word'",
            self.env_file.read_text(encoding="utf-8"),
        )

    def test_https_mode_writes_proxy_settings(self) -> None:
        result = self.run_script(MODE2_ANSWERS)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.env_file.read_text(encoding="utf-8")
        self.assertIn("HV_PROXY=1", text)
        self.assertIn("COMPOSE_PROFILES=proxy", text)
        self.assertIn("HV_PROXY_DOMAINS=example.com", text)
        self.assertIn("HV_PORTAL_DOMAIN=fw.example.com", text)
        self.assertIn("HV_PORTAL_URL=https://fw.example.com", text)
        self.assertIn("HV_PORTAL_HOSTS=fw.example.com", text)
        self.assertIn("HV_WAN_HTTPS_ONLY=1", text)
        key = env_value(text, "HV_PROXY_KEY")
        self.assertRegex(key, r"^[0-9a-f]{64}$")
        # The DNS requirement is printed while asking and in the summary.
        self.assertIn("wildcard A", result.stderr)
        self.assertIn(
            "portal: https://fw.example.com "
            "(root: example.com, HTTPS via Caddy)",
            result.stderr,
        )

    def test_https_mode_lowercases_domain_text(self) -> None:
        answers = list(MODE2_ANSWERS)
        answers[8] = "Example.COM."
        answers[9] = "FW.Example.COM"
        result = self.run_script(answers)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.env_file.read_text(encoding="utf-8")
        self.assertIn("HV_PROXY_DOMAINS=example.com", text)
        self.assertIn("HV_PORTAL_DOMAIN=fw.example.com", text)

    def test_https_mode_rejects_subdomain_outside_root(self) -> None:
        answers = [
            "n", "eth1", "eth0", "192.168.10.0/24", "0.0.0.0/0",
            "192.168.10.0/24", "8100", "2", "example.com",
            "fw.other.com",     # not under example.com: re-prompt
            "fw.example.com", "y", "admin", "secret123",
        ]
        result = self.run_script(answers)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("strictly under the root domain", result.stderr)
        text = self.env_file.read_text(encoding="utf-8")
        self.assertIn("HV_PORTAL_DOMAIN=fw.example.com", text)
        self.assertIn("HV_PORTAL_URL=https://fw.example.com", text)

    def test_https_rerun_preserves_proxy_key(self) -> None:
        old_key = "a" * 64
        self.env_file.write_text(
            "HV_SINGLE_NIC=1\n"
            "HV_WAN_IF=wan9\n"
            "HV_PORTAL_NET=0.0.0.0/0\n"
            "PORT=8100\n"
            "HV_PROXY=1\n"
            f"HV_PROXY_KEY={old_key}\n"
            "HV_PROXY_DOMAINS=example.com\n"
            "HV_PORTAL_DOMAIN=fw.example.com\n",
            encoding="utf-8",
        )
        # Every prompt accepts its default; the mode defaults to 2 because
        # the existing .env has HV_PROXY=1.
        answers = ["", "", "", "", "", "", "", "", "n"]
        result = self.run_script(answers)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.env_file.read_text(encoding="utf-8")
        self.assertEqual(env_value(text, "HV_PROXY_KEY"), old_key)
        self.assertIn("HV_PROXY_DOMAINS=example.com", text)
        self.assertIn("HV_PORTAL_DOMAIN=fw.example.com", text)

    def test_no_admin_account(self) -> None:
        answers = ANSWERS[:8] + ["n"]
        result = self.run_script(answers)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.env_file.read_text(encoding="utf-8")
        self.assertIn("HV_ADMIN_ENABLED=0", text)
        self.assertNotIn("HV_ADMIN_PASSWORD=", text)

    def test_single_nic_writes_empty_lan_values(self) -> None:
        answers = ["y", "wan9", "", "", "", "1", "y", "admin", "secret123"]
        result = self.run_script(answers)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.env_file.read_text(encoding="utf-8")
        self.assertIn("HV_SINGLE_NIC=1", text)
        self.assertIn("HV_LAN_IF=\n", text)
        self.assertIn("HV_LAN_NET=\n", text)
        self.assertIn("HV_WAN_IF=wan9", text)
        self.assertIn("HV_PORTAL_NET=0.0.0.0/0", text)

    def test_empty_password_is_generated(self) -> None:
        answers = list(ANSWERS)
        answers[-1] = ""
        result = self.run_script(answers)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.env_file.read_text(encoding="utf-8")
        self.assertIn("HV_ADMIN_PASSWORD=", text)
        password = [
            line.split("=", 1)[1] for line in text.splitlines()
            if line.startswith("HV_ADMIN_PASSWORD=")
        ][0]
        self.assertGreaterEqual(len(password), 24)


class GatewayProxySeedTests(unittest.TestCase):
    """HV_PROXY_DOMAINS / HV_PORTAL_DOMAIN seed only the first settings file."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name)
        self.settings_path = self.state / "firewall-settings.json"
        self.env = {
            "HV_STATE_DIR": self.tmp.name,
            "HV_SETTINGS": str(self.settings_path),
            "HV_USERS": str(self.state / "users.json"),
            "HV_RULES": str(self.state / "rules.json"),
            "HV_GROUPS": str(self.state / "groups.json"),
            "HV_AUDIT_LOG": str(self.state / "audit.jsonl"),
        }
        self.addCleanup(self._restore)
        self.addCleanup(self.tmp.cleanup)

    @staticmethod
    def _restore() -> None:
        importlib.reload(settings_store)
        importlib.reload(gateway)

    def make_gateway(self, **extra: str):
        env = dict(self.env)
        env.update(extra)
        logs: list[str] = []
        with mock.patch.dict(os.environ, env):
            importlib.reload(settings_store)
            module = importlib.reload(gateway)
            with mock.patch.object(module, "log", logs.append):
                # Construction alone must not touch nftables.
                gw = module.Gateway()
        return gw, logs

    def test_first_start_seeds_proxy_from_environment(self) -> None:
        gw, logs = self.make_gateway(
            HV_PROXY_DOMAINS="example.com, Second.example.org ,",
            HV_PORTAL_DOMAIN="FW.Example.COM",
        )
        self.assertTrue(self.settings_path.exists())
        snap = gw.settings.snapshot()
        self.assertEqual(
            snap["proxy_domains"], ["example.com", "second.example.org"]
        )
        self.assertEqual(snap["portal_domain"], "fw.example.com")
        self.assertTrue(
            any("proxy seed from the environment" in line for line in logs)
        )

    def test_existing_settings_file_is_not_overwritten(self) -> None:
        initial = settings_store.SettingsStore(
            str(self.settings_path), logger=lambda *_: None
        )
        initial.seed_proxy(["admin.example.net"], "ui.admin.example.net")
        gw, logs = self.make_gateway(
            HV_PROXY_DOMAINS="example.com",
            HV_PORTAL_DOMAIN="fw.example.com",
        )
        snap = gw.settings.snapshot()
        self.assertEqual(snap["proxy_domains"], ["admin.example.net"])
        self.assertEqual(snap["portal_domain"], "ui.admin.example.net")
        self.assertEqual(logs, [])

    def test_invalid_seed_is_warned_and_ignored(self) -> None:
        gw, logs = self.make_gateway(
            HV_PROXY_DOMAINS="example.com",
            HV_PORTAL_DOMAIN="fw.other.com",
        )
        self.assertFalse(self.settings_path.exists())
        snap = gw.settings.snapshot()
        self.assertEqual(snap["proxy_domains"], [])
        self.assertEqual(snap["portal_domain"], "")
        self.assertTrue(
            any(
                "WARNING: ignoring the proxy seed" in line for line in logs
            )
        )


if __name__ == "__main__":
    unittest.main()
