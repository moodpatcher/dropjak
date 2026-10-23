"""The interactive .env generator (configure.sh)."""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "configure.sh"

# The order of the prompts: single-NIC question, LAN if, WAN if, LAN net,
# portal net, mgmt net, port, optional DNS name, admin yes/no, admin user,
# admin password.
ANSWERS = [
    "n", "eth1", "eth0", "192.168.10.0/24", "0.0.0.0/0",
    "192.168.10.0/24", "8100", "", "y", "admin", "secret123",
]


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
        answers = ["n", "", "", "", "", "", "", "", "", "", ""]
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

    def test_portal_dns_name_adds_hosts_and_url(self) -> None:
        answers = list(ANSWERS)
        answers[7] = "gw.example.com"
        result = self.run_script(answers)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.env_file.read_text(encoding="utf-8")
        self.assertIn(
            "HV_PORTAL_HOSTS=gw.example.com,gw.example.com:8100", text
        )
        self.assertIn("HV_PORTAL_URL=http://gw.example.com:8100", text)

    def test_no_admin_account(self) -> None:
        answers = ANSWERS[:8] + ["n"]
        result = self.run_script(answers)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.env_file.read_text(encoding="utf-8")
        self.assertIn("HV_ADMIN_ENABLED=0", text)
        self.assertNotIn("HV_ADMIN_PASSWORD=", text)

    def test_single_nic_writes_empty_lan_values(self) -> None:
        answers = ["y", "wan9", "", "", "", "", "y", "admin", "secret123"]
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


if __name__ == "__main__":
    unittest.main()
