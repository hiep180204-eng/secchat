"""
test_avatar.py — avatar upload / has_avatar state / remove flow.

Handlers (server/services/profile.c):
  upload_avatar  — base64-encoded image + MIME type → ok / error
  remove_avatar  — clear stored avatar → ok / error
  get_profile    — returns has_avatar bool

Tests verify both the has_avatar flag and the returned avatar_b64 payload so
the desktop UI can refresh avatars without a separate download endpoint.

  AV-1   upload valid PNG returns ok
  AV-2   get_profile returns has_avatar=true after upload
  AV-3   remove_avatar returns ok
  AV-4   get_profile returns has_avatar=false after remove
  AV-5   upload with empty data returns error
  AV-6   upload with invalid base64 returns error
  AV-7   upload with correct base64 but wrong MIME returns error
  AV-8   upload valid JPEG returns ok
  AV-9   oversized avatar payload returns error
  AV-10  profile/avatar can be viewed before direct friendship
"""

from __future__ import annotations

import base64
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secchat_testlib import (
    wait_ready, db_reset, unique,
    ChatClient, ws_send, recv_until,
)

# Minimal valid PNG (1x1 pixel transparent)
_PNG_BYTES = bytes([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,  # IHDR length + type
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,  # 1x1
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,  # bit depth + colortype
    0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41,  # IDAT length + type
    0x54, 0x78, 0x9C, 0x62, 0x00, 0x01, 0x00, 0x00,  # IDAT data
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
    0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,  # IEND
    0x42, 0x60, 0x82,
])

# Minimal valid JPEG (smallest valid JFIF)
_JPEG_BYTES = bytes([
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46,
    0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x00, 0xFF, 0xD9,
])

_PNG_B64  = base64.b64encode(_PNG_BYTES).decode()
_JPEG_B64 = base64.b64encode(_JPEG_BYTES).decode()


def _expect_any(c: ChatClient, timeout: float = 3.0) -> dict:
    msg = recv_until(c.sock, lambda m: m.get("type") in ("ok", "error"), timeout=timeout)
    assert msg is not None, "no ok/error response"
    return msg


def _get_profile(c: ChatClient) -> dict:
    ws_send(c.sock, {"type": "get_profile", "user_id": c.user_id})
    msg = recv_until(c.sock, lambda m: m.get("type") == "profile", timeout=3.0)
    assert msg is not None, "no profile response"
    return msg


class TestAvatar(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_ready()
        db_reset()
        time.sleep(1.2)

    # --- happy path ---

    def test_AV1_upload_valid_png_ok(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "upload_avatar",
                              "data": _PNG_B64,
                              "mime": "image/png"})
            r = _expect_any(c)
            self.assertEqual(r.get("type"), "ok")

    def test_AV2_has_avatar_true_after_upload(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "upload_avatar",
                              "data": _PNG_B64,
                              "mime": "image/png"})
            _expect_any(c)
            p = _get_profile(c)
            self.assertTrue(p.get("has_avatar"),
                            "has_avatar should be true after upload")
            self.assertEqual(p.get("avatar_mime"), "image/png")
            self.assertEqual(base64.b64decode(p.get("avatar_b64", "")), _PNG_BYTES)

    def test_AV3_remove_avatar_ok(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "upload_avatar",
                              "data": _PNG_B64,
                              "mime": "image/png"})
            _expect_any(c)
            ws_send(c.sock, {"type": "remove_avatar"})
            r = _expect_any(c)
            self.assertEqual(r.get("type"), "ok")

    def test_AV4_has_avatar_false_after_remove(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "upload_avatar",
                              "data": _PNG_B64,
                              "mime": "image/png"})
            _expect_any(c)
            ws_send(c.sock, {"type": "remove_avatar"})
            _expect_any(c)
            p = _get_profile(c)
            self.assertFalse(p.get("has_avatar"),
                             "has_avatar should be false after remove")
            self.assertEqual(p.get("avatar_b64", ""), "")
            self.assertEqual(p.get("avatar_mime", ""), "")

    # --- validation ---

    def test_AV5_empty_data_is_error(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "upload_avatar",
                              "data": "",
                              "mime": "image/png"})
            r = _expect_any(c)
            self.assertEqual(r.get("type"), "error")

    def test_AV6_invalid_base64_is_error(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "upload_avatar",
                              "data": "not!valid!base64!!!",
                              "mime": "image/png"})
            r = _expect_any(c)
            self.assertEqual(r.get("type"), "error")

    def test_AV7_wrong_mime_is_error(self):
        # PNG bytes but declared as JPEG → magic-byte check fails
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "upload_avatar",
                              "data": _PNG_B64,
                              "mime": "image/jpeg"})
            r = _expect_any(c)
            self.assertEqual(r.get("type"), "error")

    def test_AV8_upload_valid_jpeg_ok(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "upload_avatar",
                              "data": _JPEG_B64,
                              "mime": "image/jpeg"})
            r = _expect_any(c)
            self.assertEqual(r.get("type"), "ok")

    def test_AV9_oversized_avatar_is_error(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "upload_avatar",
                              "data": "A" * (129 * 1024),
                              "mime": "image/png"})
            r = _expect_any(c)
            self.assertEqual(r.get("type"), "error")
            self.assertIn("large", r.get("msg", "").lower())

    def test_AV10_nonfriend_profile_avatar_is_visible(self):
        with ChatClient() as alice, ChatClient() as bob:
            alice.register_and_login(unique("alice"))
            bob.register_and_login(unique("bob"))
            ws_send(bob.sock, {"type": "upload_avatar",
                               "data": _PNG_B64,
                               "mime": "image/png"})
            _expect_any(bob)

            ws_send(alice.sock, {"type": "get_profile", "user_id": bob.user_id})
            p = recv_until(
                alice.sock,
                lambda m: m.get("type") in ("profile", "error"),
                timeout=3.0,
            )
            self.assertIsNotNone(p)
            self.assertEqual(p.get("type"), "profile")
            self.assertTrue(p.get("has_avatar"))
            self.assertEqual(base64.b64decode(p.get("avatar_b64", "")), _PNG_BYTES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
