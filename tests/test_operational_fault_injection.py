"""
Operational fault-injection checks for the C server.

These tests are intentionally small. They do not replace long-running chaos
tests, but they make sure the basic failure paths do not wedge the server:
database outage, database recovery, and a client that disconnects mid-frame.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secchat_testlib import (  # noqa: E402
    DB_CONTAINER,
    DB_ROOT_PASS,
    DB_ROOT_USER,
    ChatClient,
    db_reset,
    http_get,
    make_friends,
    open_dm,
    recv_until,
    unique,
    wait_ready,
    ws_connect,
    ws_recv,
    ws_send,
    ws_send_msg,
)


REPO = Path(__file__).resolve().parents[1]


def compose(*args: str, timeout: float = 90.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def wait_db_container(timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        proc = subprocess.run(
            [
                "docker", "exec", DB_CONTAINER,
                "mysqladmin", "ping",
                f"-u{DB_ROOT_USER}", f"-p{DB_ROOT_PASS}",
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        last = (proc.stdout + proc.stderr).strip()
        if proc.returncode == 0 and "mysqld is alive" in last:
            return
        time.sleep(0.1)
    raise RuntimeError(f"database did not recover in {timeout}s: {last}")


def wait_readyz_unavailable(timeout: float = 20.0) -> tuple[int, str]:
    deadline = time.time() + timeout
    status = 200
    body = ""
    while time.time() < deadline:
        status, body = http_get("/readyz", timeout=2.0)
        if status == 503 and "db_unavailable" in body:
            return status, body
        time.sleep(0.1)
    return status, body


class OperationalFaultInjectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        wait_ready()
        db_reset()

    def tearDown(self) -> None:
        # Keep later test files from inheriting a stopped database if an
        # assertion fails midway through this file.
        compose("up", "-d", "db")
        wait_db_container()
        wait_ready(timeout=60.0)

    def test_db_outage_fails_readyz_fast_and_recovers(self) -> None:
        with ChatClient() as client:
            client.register_and_login(unique("stable"))

        compose("stop", "db", timeout=60.0)
        try:
            status, body = wait_readyz_unavailable(timeout=20.0)
            self.assertEqual(status, 503, body)
            self.assertIn("db_unavailable", body)

            status, body = http_get("/healthz", timeout=2.0)
            self.assertEqual(status, 200, body)

            sock = ws_connect()
            try:
                started = time.time()
                ws_send(sock, {
                    "type": "register",
                    "username": unique("dbdown"),
                    "email": f"{unique('dbdown')}@test.local",
                    "password": "0" * 64,
                })
                response = ws_recv(sock, timeout=8.0)
                self.assertLess(time.time() - started, 9.0)
                self.assertTrue(
                    response is None or response.get("type") == "error",
                    response,
                )
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
        finally:
            compose("up", "-d", "db", timeout=90.0)
            wait_db_container()

        wait_ready(timeout=60.0)
        with ChatClient() as after:
            response = after.register(unique("after"))
            self.assertIsNotNone(response)
            self.assertIn(response.get("type"), {"ok", "registered"})

    def test_db_outage_during_message_send_fails_fast_and_session_recovers(self) -> None:
        alice = ChatClient()
        bob = ChatClient()
        try:
            alice.register_and_login(unique("alice_fault"))
            bob.register_and_login(unique("bob_fault"))
            make_friends(alice.sock, alice.user_id, bob.sock, bob.user_id)
            conv_id = open_dm(alice.sock, bob.user_id)
            self.assertIsNotNone(conv_id)

            baseline = ws_send_msg(alice.sock, conv_id, unique("before_db_down"))
            seen = recv_until(
                alice.sock,
                lambda msg: msg.get("type") == "message"
                and msg.get("body") == baseline,
                timeout=5.0,
            )
            self.assertIsNotNone(seen)

            compose("stop", "db", timeout=60.0)
            try:
                status, body = wait_readyz_unavailable(timeout=20.0)
                self.assertEqual(status, 503, body)
                started = time.time()
                interrupted = ws_send_msg(
                    alice.sock,
                    conv_id,
                    unique("during_db_down"),
                )
                response = recv_until(
                    alice.sock,
                    lambda msg: msg.get("type") in {"error", "message"}
                    and (
                        msg.get("type") == "error"
                        or msg.get("body") == interrupted
                    ),
                    timeout=12.0,
                )
                self.assertLess(time.time() - started, 13.0)
                self.assertIsNotNone(response)
                self.assertEqual(response.get("type"), "error", response)
            finally:
                compose("up", "-d", "db", timeout=90.0)
                wait_db_container()

            wait_ready(timeout=60.0)
            recovered = ws_send_msg(alice.sock, conv_id, unique("after_db_recovery"))
            seen = recv_until(
                alice.sock,
                lambda msg: msg.get("type") == "message"
                and msg.get("body") == recovered,
                timeout=8.0,
            )
            self.assertIsNotNone(seen)
        finally:
            alice.close()
            bob.close()

    def test_partial_websocket_frame_disconnect_does_not_poison_server(self) -> None:
        sock = ws_connect()
        try:
            payload = b'{"type":"auth","email":"cut@test.local"'
            declared_len = 128
            mask = b"test"
            header = (
                struct.pack("!BB", 0x81, 0x80 | 126)
                + struct.pack("!H", declared_len)
                + mask
            )
            masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            sock.sendall(header + masked)
        finally:
            sock.close()

        wait_ready(timeout=30.0)
        with ChatClient() as client:
            response = client.register(unique("socket"))
            self.assertIsNotNone(response)
            self.assertIn(response.get("type"), {"ok", "registered"})

    def test_oversized_websocket_frame_is_rejected_without_allocating_large_body(self) -> None:
        sock = ws_connect()
        try:
            ws_send(sock, {
                "type": "auth",
                "email": "oversized@test.local",
                "password": "0" * (5 * 1024 * 1024),
            })
            response = ws_recv(sock, timeout=10.0)
            self.assertIsNotNone(response)
            self.assertEqual(response.get("type"), "error", response)
            self.assertIn("large", response.get("msg", "").lower())
        finally:
            sock.close()

        wait_ready(timeout=30.0)
        with ChatClient() as client:
            response = client.register(unique("after_oversized"))
            self.assertIsNotNone(response)
            self.assertIn(response.get("type"), {"ok", "registered"})

    def test_server_accepts_new_socket_after_protocol_error(self) -> None:
        raw = socket.create_connection(
            (os.environ.get("CHAT_HOST", "localhost"),
             int(os.environ.get(
                 "CHAT_PORT",
                 os.environ.get("CHAT_WS_PORT", "18888"),
             ))),
            timeout=5.0,
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(raw, server_hostname="localhost")
        try:
            tls.sendall(b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n")
        finally:
            tls.close()

        wait_ready(timeout=30.0)
        with ChatClient() as client:
            client.register_and_login(unique("fresh"))
            ws_send(client.sock, {"type": "get_inbox"})
            inbox = recv_until(
                client.sock,
                lambda msg: msg.get("type") == "inbox",
                timeout=4.0,
            )
            self.assertIsNotNone(inbox)


if __name__ == "__main__":
    wait_ready()
    db_reset()
    unittest.main(verbosity=2)
