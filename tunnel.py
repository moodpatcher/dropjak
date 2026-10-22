#!/usr/bin/env python3
"""WireGuard-alagút (dropjak0) kezelése a felhő oldalon.

A portál konténer a host hálózati névterében fut, ezért a WireGuard
interfész a hoston jön létre. A titkos kulcsok soha nem kerülnek
parancssorba: a ``wg`` mindig 0600-os, /run alatti (tmpfs) ideiglenes
fájlból olvassa őket, amelyek a művelet után azonnal törlődnek.

A modul minden hibát elnyel és az ``error`` mezőben tesz elérhetővé: egy
WireGuard-hiba soha nem akaszthatja meg a portált. Az ``allowed-ips``
ügynökönként csak a saját /32 cím, ezért egy ügynök a felhő más címeit nem
érheti el.
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
    """A WireGuard-művelet nem sikerült."""


class TunnelManager:
    """A dropjak0 interfész, a kulcsok és az ügynök-peerek szinkronja."""

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

    # -- segédek ---------------------------------------------------------------

    def _run(self, args, input_text: str | None = None, check: bool = True):
        try:
            result = self.runner(
                args, input=input_text, capture_output=True, text=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise TunnelError(f"{args[0]} nem futtatható: {exc}") from exc
        if check and result.returncode != 0:
            detail = (result.stderr or "").strip()[:300]
            raise TunnelError(
                detail or f"{args[0]} hiba ({result.returncode})"
            )
        return result

    @contextmanager
    def _key_file(self, content: str):
        """0600-os ideiglenes kulcsfájl a tmpfs-en; a blokk után törölve."""
        try:
            os.makedirs(self.run_dir, exist_ok=True)
            fd, path = tempfile.mkstemp(
                dir=self.run_dir, prefix="dropjak-wg-", suffix=".key"
            )
        except OSError as exc:
            raise TunnelError(f"a kulcsfájl nem hozható létre: {exc}") from exc
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
        """Csak az interfész beállításait fedi: más mentés nem konfigurál."""
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
        """Ügynök kulcspár és megosztott kulcs (a privát kulcs stdin-en megy)."""
        private_key = self._run([self.wg_bin, "genkey"]).stdout.strip()
        public_key = self._run(
            [self.wg_bin, "pubkey"], private_key + "\n"
        ).stdout.strip()
        preshared_key = self._run([self.wg_bin, "genpsk"]).stdout.strip()
        if not private_key or not public_key or not preshared_key:
            raise TunnelError("a wg kulcsgenerálás üres kimenetet adott")
        return {
            "private_key": private_key,
            "public_key": public_key,
            "preshared_key": preshared_key,
        }

    # -- interfész és peerek ---------------------------------------------------

    def _ensure_link(self) -> None:
        result = self._run(
            [self.ip_bin, "link", "add", self.interface, "type", "wireguard"],
            check=False,
        )
        if result.returncode != 0 and "File exists" not in (result.stderr or ""):
            raise TunnelError(
                (result.stderr or "").strip()
                or "a WireGuard interfész nem hozható létre"
            )
        # replace: újraindított konténerben (megtartott hálózati névtérben)
        # a cím már bent lehet, az add ilyenkor "Address already assigned".
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
                or "a WireGuard cím nem állítható be"
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
        """Minden peer törlése (gyári visszaállítás); hiba nem dob."""
        with self._lock:
            try:
                self._remove_peers()
                self.error = ""
            except Exception as exc:
                self.error = str(exc)
                self.log(f"[alagút] a peerek törlése nem sikerült: {exc}")
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
            if not agent.get("enabled"):
                continue
            desired[agent["public_key"]] = agent["address"]
            with self._key_file(agent["preshared_key"]) as psk_path:
                self._run([
                    self.wg_bin, "set", self.interface,
                    "peer", agent["public_key"],
                    "preshared-key", psk_path,
                    "allowed-ips", f"{agent['address']}/32",
                ])
        # A kikapcsolt vagy törölt ügynök peerje nem maradhat a kernelben.
        for public_key in sorted(set(self._peers()) - set(desired)):
            self._run([
                self.wg_bin, "set", self.interface,
                "peer", public_key, "remove",
            ], check=False)

    def reconcile(self, tunnels: dict) -> bool:
        """Az interfész és a peerek szinkronja; True, ha futott a művelet.

        Azonos aláírásnál (és hibamentes állapotnál) nem nyúl a kernelhez,
        így egy port proxy vagy más beállítás mentése nem konfigurálja újra
        a WireGuardot.
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
                self.log(f"[alagút] WireGuard beállítás nem sikerült: {exc}")
                return False
            self.error = ""
            self._signature = signature
            return True

    # -- állapot ---------------------------------------------------------------

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
        """(id -> online/kézbesítés/forgalom) és a hiba; soha nem dob."""
        now = time.time() if now is None else now
        agents = tunnels.get("agents", [])
        rows = {
            agent["id"]: {
                "id": agent["id"], "online": False, "last_handshake": 0,
                "rx_bytes": 0, "tx_bytes": 0,
            }
            for agent in agents
        }
        enabled = [agent for agent in agents if agent.get("enabled")]
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
