#!/usr/bin/env python3
"""Port proxy csomagszinten: valódi nft szabályok egy user+net névtérben.

A tests/portproxy_netns.py-t futtatja ``unshare -rn`` alatt (root nem kell).
A cél szolgáltatások csak a 127.0.0.1-en figyelnek (TCP és UDP), mint a
Docker 127.0.0.1-re publikált portja; input és forward, WAN és LAN kliens.
Kihagyva, ha a user namespace vagy az nft/nsenter nem érhető el.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

HELPER = Path(__file__).resolve().with_name("portproxy_netns.py")


@unittest.skipUnless(
    all(shutil.which(tool) for tool in ("unshare", "nsenter", "nft", "ip")),
    "nincs unshare/nsenter/nft/ip",
)
class PortProxyPacketTests(unittest.TestCase):
    def test_loopback_only_targets_end_to_end(self) -> None:
        probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True)
        if probe.returncode != 0:
            self.skipTest("a user namespace nem elérhető")
        result = subprocess.run(
            ["unshare", "-rn", sys.executable, str(HELPER)],
            capture_output=True, text=True, timeout=240,
        )
        if result.returncode != 0 and not result.stdout.strip():
            if "Operation not permitted" in result.stderr:
                self.skipTest("a névtérben nem engedélyezett: " + result.stderr[-200:])
            self.fail(result.stderr[-3000:])
        report = json.loads(result.stdout)
        failed = {
            name: check["detail"] for name, check in report["checks"].items()
            if isinstance(check, dict) and not check["ok"]
        }
        self.assertEqual(failed, {}, json.dumps(report, indent=1, ensure_ascii=False))
        self.assertTrue(report["ok"])


if __name__ == "__main__":
    unittest.main()
