#!/usr/bin/env python3
"""WireGuard tunnel (dropjak0) management on the cloud side.

The portal container runs in the host network namespace, so the WireGuard
interface is created on the host. Private keys never appear on the command
line: ``wg`` always reads them from a 0600 temporary file under /run (tmpfs),
which is deleted immediately after the operation.

The module swallows every error and exposes it in the ``error`` field: a
WireGuard failure can never block the portal. ``allowed-ips`` is only the
agent's own /32 address, so an agent cannot reach other addresses in the
cloud. An agent gets a peer only once its public key is known (legacy
gateway-generated keys, or after enrollment).
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager

INTERFACE = "dropjak0"
SERVER_ADDRESS = "10.77.0.1"
ONLINE_SECONDS = 180
_RUN_DIR = os.environ.get("HV_TUNNEL_RUN_DIR", "").strip() or "/run/dropjak"


class TunnelError(RuntimeError):
    """The WireGuard operation failed."""


class TunnelManager:
    """Synchronization of the dropjak0 interface, keys and agent peers."""

    def __init__(
        self,
        interface: str = INTERFACE,
        run_dir: str = _RUN_DIR,
        logger=None,
        wg_bin: str = "wg",
        ip_bin: str = "ip",
        runner=subprocess.run,
    ) -> None:
        self.interface = interface
        self.run_dir = run_dir
        self.log = logger or (lambda message: None)
        self.wg_bin = wg_bin
        self.ip_bin = ip_bin
        self.runner = runner
        self.error = ""
        self._signature: str | None = None
        self._lock = threading.Lock()

    # -- helpers ---------------------------------------------------------------

    def _run(self, args, input_text: str | None = None, check: bool = True):
        try:
            result = self.runner(
                args, input=input_text, capture_output=True, text=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise TunnelError(f"{args[0]} cannot be executed: {exc}") from exc
        if check and result.returncode != 0:
            detail = (result.stderr or "").strip()[:300]
            raise TunnelError(
                detail or f"{args[0]} hiba ({result.returncode})"
            )
        return result

    @contextmanager
    def _key_file(self, content: str):
        """0600 temporary key file on tmpfs; deleted after the block."""
        try:
            os.makedirs(self.run_dir, exist_ok=True)
            fd, path = tempfile.mkstemp(
                dir=self.run_dir, prefix="dropjak-wg-", suffix=".key"
            )
        except OSError as exc:
            raise TunnelError(f"cannot create key file: {exc}") from exc
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(content.strip() + "\n")
            yield path
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    @staticmethod
    def signature(tunnels: dict) -> str:
        """Covers only the interface settings: saving anything else does not reconfigure."""
        agents = [
            [
                agent.get("id"), agent.get("address"), agent.get("public_key"),
                agent.get("preshared_key"), bool(agent.get("enabled")),
            ]
            for agent in tunnels.get("agents", [])
        ]
        return json.dumps(
            [
                tunnels.get("port"), tunnels.get("server_private_key"),
                agents,
            ],
            sort_keys=True,
        )

    def generate_keys(self) -> dict:
        """A key pair and a preshared key (the private key goes over stdin).

        Used for the server key pair; agents generate their own keys and
        enroll (only legacy agents carry gateway-generated keys).
        """
        private_key = self._run([self.wg_bin, "genkey"]).stdout.strip()
        public_key = self._run(
            [self.wg_bin, "pubkey"], private_key + "\n"
        ).stdout.strip()
        preshared_key = self._run([self.wg_bin, "genpsk"]).stdout.strip()
        if not private_key or not public_key or not preshared_key:
            raise TunnelError("wg key generation produced empty output")
        return {
            "private_key": private_key,
            "public_key": public_key,
            "preshared_key": preshared_key,
        }

    # -- interface and peers ---------------------------------------------------

    def _ensure_link(self) -> None:
        result = self._run(
            [self.ip_bin, "link", "add", self.interface, "type", "wireguard"],
            check=False,
        )
        if result.returncode != 0 and "File exists" not in (result.stderr or ""):
            raise TunnelError(
                (result.stderr or "").strip()
                or "cannot create WireGuard interface"
            )
        # replace: in a restarted container (preserved network namespace)
        # the address may already exist; add then says "Address already assigned".
        result = self._run(
            [
                self.ip_bin, "addr", "replace", f"{SERVER_ADDRESS}/24",
                "dev", self.interface,
            ],
            check=False,
        )
        if result.returncode != 0 and "File exists" not in (result.stderr or ""):
            raise TunnelError(
                (result.stderr or "").strip()
                or "cannot set WireGuard address"
            )
        self._run(
            [
                self.ip_bin, "link", "set", self.interface,
                "mtu", "1420", "up",
            ]
        )

    def _peers(self) -> set[str]:
        result = self._run(
            [self.wg_bin, "show", self.interface, "peers"], check=False
        )
        if result.returncode != 0:
            return set()
        return {
            line.strip() for line in (result.stdout or "").splitlines()
            if line.strip()
        }

    def _remove_peers(self) -> None:
        for public_key in sorted(self._peers()):
            self._run(
                [self.wg_bin, "set", self.interface, "peer", public_key,
                 "remove"],
                check=False,
            )

    def remove_all(self) -> None:
        """Remove all peers (factory reset); never raises."""
        with self._lock:
            try:
                self._remove_peers()
                self.error = ""
            except Exception as exc:
                self.error = str(exc)
                self.log(f"[tunnel] failed to remove peers: {exc}")
            self._signature = None

    def _apply(self, tunnels: dict) -> None:
        self._ensure_link()
        with self._key_file(tunnels["server_private_key"]) as key_path:
            self._run([
                self.wg_bin, "set", self.interface,
                "private-key", key_path,
                "listen-port", str(int(tunnels.get("port") or 51820)),
            ])
        desired: dict[str, str] = {}
        for agent in tunnels.get("agents", []):
            # An agent waiting for enrollment has no public key yet, so it
            # gets no peer: nothing can handshake as it.
            if not agent.get("enabled") or not agent.get("public_key"):
                continue
            desired[agent["public_key"]] = agent["address"]
            with self._key_file(agent["preshared_key"]) as psk_path:
                self._run([
                    self.wg_bin, "set", self.interface,
                    "peer", agent["public_key"],
                    "preshared-key", psk_path,
                    "allowed-ips", f"{agent['address']}/32",
                ])
        # A disabled or deleted agent's peer must not remain in the kernel.
        for public_key in sorted(set(self._peers()) - set(desired)):
            self._run([
                self.wg_bin, "set", self.interface,
                "peer", public_key, "remove",
            ], check=False)

    def reconcile(self, tunnels: dict) -> bool:
        """Synchronize the interface and peers; True if the operation ran.

        With an identical signature (and a clean state) it leaves the kernel
        alone, so saving a port proxy or any other setting does not
        reconfigure WireGuard.
        """
        with self._lock:
            signature = self.signature(tunnels)
            if signature == self._signature and not self.error:
                return False
            try:
                if tunnels.get("server_private_key"):
                    self._apply(tunnels)
                else:
                    self._remove_peers()
            except Exception as exc:
                self.error = str(exc)
                self.log(f"[tunnel] WireGuard configuration failed: {exc}")
                return False
            self.error = ""
            self._signature = signature
            return True

    # -- status ----------------------------------------------------------------

    def _show(self, command: str) -> dict:
        result = self._run(
            [self.wg_bin, "show", self.interface, command]
        )
        values: dict[str, tuple] = {}
        for line in (result.stdout or "").splitlines():
            fields = line.split("\t")
            if not fields or not fields[0].strip():
                continue
            try:
                values[fields[0].strip()] = tuple(
                    int(value) for value in fields[1:]
                )
            except ValueError:
                continue
        return values

    def status(self, tunnels: dict, now: float | None = None) -> dict:
        """(id -> online/handshake/traffic) and the error; never raises."""
        now = time.time() if now is None else now
        agents = tunnels.get("agents", [])
        rows = {
            agent["id"]: {
                "id": agent["id"], "online": False, "last_handshake": 0,
                "rx_bytes": 0, "tx_bytes": 0,
            }
            for agent in agents
        }
        enabled = [
            agent for agent in agents
            if agent.get("enabled") and agent.get("public_key")
        ]
        error = self.error
        if enabled and tunnels.get("server_private_key"):
            try:
                handshakes = self._show("latest-handshakes")
                transfer = self._show("transfer")
            except Exception as exc:
                error = str(exc)
            else:
                for agent in enabled:
                    public_key = agent["public_key"]
                    row = rows[agent["id"]]
                    stamp = handshakes.get(public_key, (0,))[0]
                    row["last_handshake"] = stamp
                    row["online"] = bool(stamp) and now - stamp < ONLINE_SECONDS
                    traffic = transfer.get(public_key, (0, 0))
                    row["rx_bytes"] = traffic[0] if len(traffic) > 0 else 0
                    row["tx_bytes"] = traffic[1] if len(traffic) > 1 else 0
        return {"error": error, "agents": list(rows.values())}
