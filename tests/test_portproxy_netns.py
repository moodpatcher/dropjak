#!/usr/bin/env python3
"""Port proxy at packet level: real nft rules in a user+net namespace.

Runs tests/portproxy_netns.py under ``unshare -rn`` (root is not needed).
The target services listen only on 127.0.0.1 (TCP and UDP), like Docker's
port published on 127.0.0.1; input and forward, WAN and LAN client.
Skipped if the user namespace or nft/nsenter is unavailable.
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
    "unshare/nsenter/nft/ip not available",
)
class PortProxyPacketTests(unittest.TestCase):
    def test_loopback_only_targets_end_to_end(self) -> None:
        probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True)
        if probe.returncode != 0:
            self.skipTest("the user namespace is not available")
        result = subprocess.run(
            ["unshare", "-rn", sys.executable, str(HELPER)],
            capture_output=True, text=True, timeout=240,
        )
        if result.returncode != 0 and not result.stdout.strip():
            if "Operation not permitted" in result.stderr:
                self.skipTest("not permitted in the namespace: " + result.stderr[-200:])
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
