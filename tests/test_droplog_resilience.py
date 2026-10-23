#!/usr/bin/env python3
"""Drop-log listener resilience and the bounded read path.

The listener runs on a fake socket, so the tests need no netlink or nft.
They check that a receive-buffer overflow (ENOBUFS) does not stop the
listener, that other socket errors lead to an automatic restart, that the
listener does not fsync per packet, and that read() scans newest first and
stops early.
"""

from __future__ import annotations

import errno
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import droplog  # noqa: E402


class ScriptedSocket:
    """recv() plays a script: bytes are returned, exceptions are raised.

    When the script runs out, the listener is stopped and recv() times out.
    """

    def __init__(self, listener, script) -> None:
        self.listener = listener
        self.script = list(script)
        self.closed = False

    def recv(self, _size: int) -> bytes:
        if not self.script:
            self.listener._stop.set()
            raise socket.timeout()
        step = self.script.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step

    def close(self) -> None:
        self.closed = True


class ListenerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = droplog.DropLog(
            os.path.join(self.tmp.name, "drops.jsonl"), logger=lambda *_: None
        )
        self.logs: list[str] = []
        self.listener = droplog.DropLogListener(
            self.store, logger=self.logs.append
        )
        self.handled: list[bytes] = []
        self.listener._handle = self.handled.append

    def run_loop(self, sock) -> None:
        self.listener._sock = sock
        self.listener._running = True
        thread = threading.Thread(target=self.listener._loop, daemon=True)
        thread.start()
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive(), "the listener loop did not end")

    def test_enobufs_is_counted_and_listener_keeps_running(self) -> None:
        sock = ScriptedSocket(self.listener, [
            b"first",
            OSError(errno.ENOBUFS, os.strerror(errno.ENOBUFS)),
            OSError(errno.ENOBUFS, os.strerror(errno.ENOBUFS)),
            b"second",
        ])
        with mock.patch.object(self.listener, "_open_socket") as reopen:
            self.run_loop(sock)
        # Both buffers after the overflow were still processed on the same
        # socket; nothing was reopened.
        self.assertEqual(self.handled, [b"first", b"second"])
        reopen.assert_not_called()
        self.assertFalse(sock.closed)
        status = self.listener.status()
        self.assertEqual(status["overruns"], 2)
        self.assertEqual(status["restarts"], 0)
        self.assertEqual(status["error"], "")
        # The warning is rate-limited: one line for the two overflows.
        self.assertEqual(
            sum("overflow" in line for line in self.logs), 1
        )

    def test_other_socket_error_restarts_with_backoff(self) -> None:
        listener = self.listener
        first = ScriptedSocket(listener, [
            b"before", OSError(errno.ENETDOWN, "network is down"),
        ])
        second = ScriptedSocket(listener, [b"after"])
        attempts = []

        def reopen():
            attempts.append(time.monotonic())
            if len(attempts) < 3:
                raise OSError(errno.EADDRINUSE, "busy")
            return second

        waits = []
        real_wait = listener._stop.wait

        def wait(delay):
            waits.append(delay)
            return real_wait(0)

        with mock.patch.object(listener, "_open_socket", side_effect=reopen), \
                mock.patch.object(listener._stop, "wait", side_effect=wait):
            self.run_loop(first)

        self.assertTrue(first.closed)
        self.assertEqual(self.handled, [b"before", b"after"])
        self.assertEqual(len(attempts), 3)
        # Exponential back-off between the attempts.
        self.assertEqual(waits[:3], [1.0, 2.0, 4.0])
        status = listener.status()
        self.assertEqual(status["restarts"], 1)
        self.assertEqual(status["error"], "")

    def test_stop_during_backoff_ends_the_loop(self) -> None:
        sock = ScriptedSocket(self.listener, [OSError(errno.EIO, "io")])

        def reopen():
            self.listener._stop.set()
            raise OSError(errno.EIO, "still failing")

        with mock.patch.object(droplog, "DROP_LOG_RESTART_MIN_DELAY", 0.01), \
                mock.patch.object(
                    self.listener, "_open_socket", side_effect=reopen
                ):
            self.run_loop(sock)
        status = self.listener.status()
        self.assertFalse(status["running"])
        self.assertIn("still failing", status["error"])

    def test_packets_are_not_fsynced_one_by_one(self) -> None:
        listener = droplog.DropLogListener(self.store, logger=lambda *_: None)
        with mock.patch.object(droplog.os, "fsync") as fsync:
            for port in range(50):
                listener._count_packet(
                    {"src": "192.0.2.9", "dport": port, "reason": "input-wan"}
                )
            self.assertEqual(fsync.call_count, 0)
            listener._sync_store(force=True)
            self.assertEqual(fsync.call_count, 1)
            # Nothing new: no further fsync.
            listener._sync_store(force=True)
            self.assertEqual(fsync.call_count, 1)
            # Direct writes (ban events) keep their own fsync.
            self.store.write({"reason": "fail2ban", "event": "ban"})
            self.assertEqual(fsync.call_count, 2)
        self.assertEqual(len(self.store.read(limit=100)), 51)

    def test_mode_message_copies_headers_only(self) -> None:
        mode = droplog._mode_message(5, 1)
        copy_range = int.from_bytes(mode[24:28], "big")
        self.assertEqual(copy_range, droplog.DROP_LOG_COPY_RANGE)
        self.assertLessEqual(copy_range, 128)
        # Enough for the largest IPv4 header plus the TCP/UDP ports.
        self.assertGreaterEqual(copy_range, 60 + 4)


class BoundedReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "drops.jsonl")
        self.store = droplog.DropLog(self.path, logger=lambda *_: None)

    def fill(self, path: str, start: float, count: int, **extra) -> None:
        with open(path, "a", encoding="utf-8") as fh:
            for index in range(count):
                row = {"ts": start + index, "src": "192.0.2.1",
                       "dport": index, "reason": "input-wan", **extra}
                fh.write(json.dumps(row) + "\n")

    def test_newest_rows_first_without_reading_rotated_files(self) -> None:
        now = time.time()
        self.fill(self.path + ".1", now - 1000, 100)
        self.fill(self.path, now - 100, 100)
        opened = []
        real = droplog.DropLog._lines_newest_first

        def spy(path, *args, **kwargs):
            opened.append(os.path.basename(path))
            return real(path, *args, **kwargs)

        with mock.patch.object(
            droplog.DropLog, "_lines_newest_first", side_effect=spy
        ):
            rows = self.store.read(limit=10)
        self.assertEqual([row["dport"] for row in rows], list(range(99, 89, -1)))
        self.assertEqual(opened, ["drops.jsonl"])
        # A larger limit continues into the rotated file, still in order.
        rows = self.store.read(limit=150)
        self.assertEqual(len(rows), 150)
        stamps = [row["ts"] for row in rows]
        self.assertEqual(stamps, sorted(stamps, reverse=True))

    def test_scan_is_capped_when_filter_matches_nothing(self) -> None:
        now = time.time()
        self.fill(self.path, now - 500, 500)
        with mock.patch.object(droplog, "DROP_LOG_READ_MAX_LINES", 50), \
                mock.patch.object(droplog.json, "loads",
                                  wraps=json.loads) as loads:
            rows = self.store.read(src="198.51.100.1")
        self.assertEqual(rows, [])
        self.assertLessEqual(loads.call_count, 50)

    def test_ban_folding_still_works_with_early_stop(self) -> None:
        now = time.time()
        self.store.write({"ts": now - 60, "reason": "fail2ban", "event": "ban",
                          "src": "192.0.2.50", "ban_until": now + 3600})
        for index in range(30):
            self.store.write({"ts": now - 50 + index, "reason": "fail2ban",
                              "src": "192.0.2.50", "dport": 22})
        rows = self.store.read(limit=5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "ban")
        self.assertEqual(rows[0]["packets"], 30)

    def test_multibyte_text_across_block_boundary(self) -> None:
        self.store.write({"ts": 1.0, "reason": "input-wan", "note": "é" * 40})
        self.store.write({"ts": 2.0, "reason": "input-wan", "note": "ő" * 40})
        lines = list(droplog.DropLog._lines_newest_first(self.path, block=7))
        rows = [json.loads(line) for line in lines if line]
        self.assertEqual([row["note"][0] for row in rows], ["ő", "é"])


if __name__ == "__main__":
    unittest.main()
