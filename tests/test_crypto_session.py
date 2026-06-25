#!/usr/bin/env python3
"""Focused tests for the client crypto session boundary."""

from __future__ import annotations

import os
import json
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from client.crypto_engine.session import CryptoSession, CryptoStateError
from client.crypto_engine.audit import same_identity_key
from client.utils import (
    decrypt_with_key,
    encrypt_with_key,
    identity_keygen,
)


class CryptoSessionTest(unittest.TestCase):
    def test_simultaneous_dm_start_converges_and_keeps_secondary_session(self) -> None:
        master_a = os.urandom(32)
        master_b = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp:
            a_dir = os.path.join(tmp, "a")
            b_dir = os.path.join(tmp, "b")
            os.makedirs(a_dir)
            os.makedirs(b_dir)
            a = CryptoSession(master_key=master_a, secchat_dir=a_dir, my_uid=123)
            b = CryptoSession(master_key=master_b, secchat_dir=b_dir, my_uid=234)
            a.identity_pk, a.identity_sk = identity_keygen()
            b.identity_pk, b.identity_sk = identity_keygen()
            a_bundle = a.fresh_pqxdh_bundle_command()
            b_bundle = b.fresh_pqxdh_bundle_command()

            conv_id = 7001
            a_init, _ = a.initiate_pqxdh_dm(b_bundle, conv_id, 234)
            b_init, _ = b.initiate_pqxdh_dm(a_bundle, conv_id, 123)
            a_original = a.double_ratchet_states[conv_id]
            b_original = b.double_ratchet_states[conv_id]
            self.assertNotEqual(a_original.session_id, b_original.session_id)

            a_seen = a.decrypt_live_message({
                "conversation_id": conv_id,
                "from_id": 234,
                "sender_id": 234,
                "body": b_init,
            })
            b_seen = b.decrypt_live_message({
                "conversation_id": conv_id,
                "from_id": 123,
                "sender_id": 123,
                "body": a_init,
            })
            self.assertEqual(a_seen["status"], "control")
            self.assertEqual(b_seen["status"], "control")

            canonical = min(a_original.session_id, b_original.session_id)
            self.assertEqual(a.double_ratchet_states[conv_id].session_id, canonical)
            self.assertEqual(b.double_ratchet_states[conv_id].session_id, canonical)
            self.assertIn(a_original.session_id, b.load_double_ratchet_sessions(conv_id))
            self.assertIn(b_original.session_id, a.load_double_ratchet_sessions(conv_id))

            old_a_wire = a_original.encrypt("old session from 123")
            old_b_wire = b_original.encrypt("old session from 234")
            self.assertEqual(
                b.decrypt_live_message({
                    "conversation_id": conv_id,
                    "from_id": 123,
                    "sender_id": 123,
                    "body": old_a_wire,
                })["body"],
                "old session from 123",
            )
            self.assertEqual(
                a.decrypt_live_message({
                    "conversation_id": conv_id,
                    "from_id": 234,
                    "sender_id": 234,
                    "body": old_b_wire,
                })["body"],
                "old session from 234",
            )

            canonical_wire = a.encrypt_for_conv(conv_id, "canonical from 123")
            self.assertEqual(
                b.decrypt_live_message({
                    "conversation_id": conv_id,
                    "from_id": 123,
                    "sender_id": 123,
                    "body": canonical_wire,
                })["body"],
                "canonical from 123",
            )

    def test_plaintext_cache_roundtrip_and_rewrap(self) -> None:
        old_master = os.urandom(32)
        new_master = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp:
            engine = CryptoSession(master_key=old_master, secchat_dir=tmp, my_uid=1)
            engine.cache_message(10, 42, 2, "hello", "12:00")
            engine.cache_outgoing_wire(10, "S3DR:wire", 1, "outgoing")

            cached = engine.load_cached_messages(10)
            self.assertEqual(cached[42]["body"], "hello")
            self.assertEqual(cached[CryptoSession.wire_cache_key("S3DR:wire")]["body"], "outgoing")

            engine.rewrap_local_state(old_master, new_master)
            engine.master_key = new_master
            cached_after = engine.load_cached_messages(10)
            self.assertEqual(cached_after[42]["body"], "hello")

    def test_verified_state_is_encrypted_at_rest(self) -> None:
        master = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp:
            engine = CryptoSession(master_key=master, secchat_dir=tmp, my_uid=1)
            engine.save_verified(99, True)
            with open(engine.verified_path(99), "r", encoding="utf-8") as fh:
                token = fh.read().strip()
            self.assertNotEqual(token, "1")
            self.assertEqual(decrypt_with_key(master, token, check_replay=False), "1")

    def test_cache_policy_can_disable_expire_and_clear_plaintext_cache(self) -> None:
        master = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp:
            engine = CryptoSession(master_key=master, secchat_dir=tmp, my_uid=1)
            engine.cache_message(10, 1, 2, "kept", "12:00")
            self.assertIn(1, engine.load_cached_messages(10))

            path = engine.msg_cache_path(10)
            with open(path, "w", encoding="utf-8") as fh:
                stale = {
                    "id": 2,
                    "from": 2,
                    "body": "stale",
                    "ts": "12:01",
                    "cached_at": time.time() - 86400 * 10,
                }
                from client.utils import encrypt_with_key
                import json
                fh.write(encrypt_with_key(master, json.dumps(stale)) + "\n")

            engine.set_cache_policy(ttl_days=1)
            self.assertEqual(engine.load_cached_messages(10), {})

            engine.cache_message(10, 3, 2, "delete me", "12:02")
            self.assertTrue(os.path.exists(path))
            saved = engine.set_cache_policy(enabled=False, clear_on_logout=True)
            self.assertFalse(saved["enabled"])
            self.assertTrue(saved["clear_on_logout"])
            self.assertFalse(os.path.exists(path))
            self.assertEqual(engine.load_cached_messages(10), {})

    def test_conversation_cache_policy_disables_only_sensitive_conversation(self) -> None:
        master = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp:
            engine = CryptoSession(master_key=master, secchat_dir=tmp, my_uid=1)
            engine.cache_message(10, 1, 2, "sensitive", "12:00")
            engine.cache_message(11, 2, 2, "normal", "12:01")
            self.assertTrue(os.path.exists(engine.msg_cache_path(10)))
            self.assertTrue(os.path.exists(engine.msg_cache_path(11)))

            policy = engine.set_conversation_cache_enabled(10, False)
            self.assertIn(10, policy["disabled_conversation_ids"])
            self.assertFalse(os.path.exists(engine.msg_cache_path(10)))
            self.assertEqual(engine.load_cached_messages(10), {})
            self.assertEqual(engine.load_cached_messages(11)[2]["body"], "normal")

            engine.cache_message(10, 3, 2, "not stored", "12:02")
            self.assertFalse(os.path.exists(engine.msg_cache_path(10)))
            policy = engine.set_conversation_cache_enabled(10, True)
            self.assertNotIn(10, policy["disabled_conversation_ids"])
            engine.cache_message(10, 4, 2, "stored again", "12:03")
            self.assertEqual(engine.load_cached_messages(10)[4]["body"], "stored again")

    def test_transcript_consistency_detects_missing_tampered_and_membership_changes(self) -> None:
        master = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp:
            engine = CryptoSession(master_key=master, secchat_dir=tmp, my_uid=1)
            for mid in (1, 2, 3):
                engine.record_transcript_message(20, mid, 2, f"body {mid}", f"12:0{mid}")

            warnings = engine.verify_history_consistency(20, [
                {"id": 1, "sender_id": 2, "body": "body 1", "time": "renormalized"},
            ])
            self.assertFalse(any("changed" in w for w in warnings))
            engine.record_transcript_message(20, 4, 2, "[Forward-secret]", "12:04")
            self.assertNotIn("4", engine._load_transcript_state(20).get("messages", {}))

            warnings = engine.verify_history_consistency(20, [
                {"id": 1, "sender_id": 2, "body": "body 1", "time": "12:01"},
                {"id": 3, "sender_id": 2, "body": "body 3", "time": "12:03"},
            ])
            self.assertTrue(any("missing" in w for w in warnings))

            warnings = engine.verify_history_consistency(20, [
                {"id": 2, "sender_id": 2, "body": "tampered", "time": "12:02"},
            ])
            self.assertTrue(any("changed" in w for w in warnings))

            warnings = engine.verify_history_consistency(20, [
                {"id": 5, "sender_id": 2, "body": "newer", "time": "12:05"},
                {"id": 4, "sender_id": 2, "body": "older", "time": "12:04"},
            ])
            self.assertTrue(any("out of message order" in w for w in warnings))

            members = [{"user_id": 1, "role": "owner"}, {"user_id": 2, "role": "member"}]
            self.assertEqual(engine.verify_group_membership(30, members), [])
            changed = [{"user_id": 1, "role": "owner"}]
            self.assertEqual(engine.verify_group_membership(30, changed), [])
            self.assertEqual(engine.verify_group_membership(
                30, changed, expected_change=True), [])

    def test_e2ee_backup_restore_rewraps_state_for_new_master_key(self) -> None:
        old_master = os.urandom(32)
        new_master = os.urandom(32)
        passphrase = "backup-passphrase"
        with tempfile.TemporaryDirectory() as tmp:
            backup_path = os.path.join(tmp, "backup.json")
            engine = CryptoSession(master_key=old_master, secchat_dir=tmp, my_uid=7)
            pk, sk = identity_keygen()
            engine.identity_pk = pk
            engine.identity_sk = sk
            engine.save_identity_key()
            engine.cache_message(44, 9, 8, "cached history", "12:00")
            engine.set_cache_policy(enabled=True, ttl_days=90, clear_on_logout=True)
            exported = engine.export_e2ee_backup(
                backup_path,
                passphrase,
                account_username="alice",
                include_cache=True,
            )
            self.assertGreaterEqual(exported["files"], 3)
            self.assertTrue(exported["backup_id"])
            self.assertEqual(exported["backup_generation"], 1)
            inspected = engine.inspect_e2ee_backup(backup_path)
            self.assertEqual(inspected["backup_id"], exported["backup_id"])
            self.assertEqual(inspected["generation"], 1)
            self.assertTrue(inspected["include_cache"])

            for name in os.listdir(tmp):
                if name != "backup.json":
                    os.remove(os.path.join(tmp, name))

            restored_engine = CryptoSession(master_key=new_master, secchat_dir=tmp, my_uid=7)
            restored = restored_engine.restore_e2ee_backup(backup_path, passphrase)
            self.assertEqual(restored["account_username"], "alice")
            self.assertEqual(restored["backup_id"], exported["backup_id"])
            self.assertTrue(restored["identity_review_recommended"])
            self.assertEqual(restored_engine.load_cached_messages(44)[9]["body"], "cached history")
            self.assertTrue(restored_engine.get_cache_policy()["clear_on_logout"])
            self.assertEqual(restored_engine.identity_sk, sk)

            with open(restored_engine.identity_key_path(), "r", encoding="utf-8") as fh:
                token = fh.read().strip()
            self.assertNotEqual(token, decrypt_with_key(new_master, token, check_replay=False))

    def test_preserve_identity_restore_prefers_backup_plaintext_over_placeholder_cache(self) -> None:
        old_master = os.urandom(32)
        new_master = os.urandom(32)
        passphrase = "backup-passphrase"
        with tempfile.TemporaryDirectory() as tmp:
            old_dir = os.path.join(tmp, "old")
            new_dir = os.path.join(tmp, "new")
            os.makedirs(old_dir)
            os.makedirs(new_dir)
            backup_path = os.path.join(tmp, "backup.json")

            source = CryptoSession(master_key=old_master, secchat_dir=old_dir, my_uid=7)
            source.identity_pk, source.identity_sk = identity_keygen()
            source.save_identity_key()
            source.cache_message(44, 9, 8, "readable history from backup", "12:00")
            source.export_e2ee_backup(
                backup_path,
                passphrase,
                account_username="alice",
                include_cache=True,
            )

            target = CryptoSession(master_key=new_master, secchat_dir=new_dir, my_uid=7)
            target.cache_message(44, 9, 8, "[Forward-secret]", "12:00")
            target.restore_e2ee_backup(
                backup_path,
                passphrase,
                preserve_current_identity=True,
            )

            self.assertEqual(
                target.load_cached_messages(44)[9]["body"],
                "readable history from backup",
            )

    def test_e2ee_backup_rejects_weak_passphrase_and_local_revoke(self) -> None:
        master = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp:
            backup_path = os.path.join(tmp, "backup.json")
            engine = CryptoSession(master_key=master, secchat_dir=tmp, my_uid=7)
            pk, sk = identity_keygen()
            engine.identity_pk = pk
            engine.identity_sk = sk
            engine.save_identity_key()

            with self.assertRaises(CryptoStateError):
                engine.export_e2ee_backup(
                    backup_path,
                    "password",
                    account_username="alice",
                    include_cache=False,
                )

            engine.export_e2ee_backup(
                backup_path,
                "backup-passphrase",
                account_username="alice",
                include_cache=False,
            )
            status = engine.revoke_local_backups()
            self.assertEqual(status["revoked_before_generation"], 1)
            with self.assertRaises(CryptoStateError):
                engine.restore_e2ee_backup(backup_path, "backup-passphrase")

    def test_fresh_pqxdh_bundle_replaces_backed_up_one_time_prekeys(self) -> None:
        master = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp:
            engine = CryptoSession(master_key=master, secchat_dir=tmp, my_uid=7)
            pk, sk = identity_keygen()
            engine.identity_pk = pk
            engine.identity_sk = sk
            first = engine.fresh_pqxdh_bundle_command()
            first_store = engine.load_pqxdh_prekeys()
            second = engine.fresh_pqxdh_bundle_command()
            second_store = engine.load_pqxdh_prekeys()

            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            self.assertEqual(first["identity_pk"], second["identity_pk"])
            self.assertNotEqual(
                first_store["curve_signed"]["pk"],
                second_store["curve_signed"]["pk"],
            )
            self.assertNotEqual(
                sorted(item["pk"] for item in first_store["curve_one_time"].values()),
                sorted(item["pk"] for item in second_store["curve_one_time"].values()),
            )

    def test_mls_import_failure_discards_local_state_for_republish(self) -> None:
        class RejectingBridge:
            def available(self) -> bool:
                return True

            def import_state(self, state_b64: str) -> dict:
                raise RuntimeError("unsupported MLS ciphersuite")

        master = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp:
            engine = CryptoSession(master_key=master, secchat_dir=tmp, my_uid=7)
            token = encrypt_with_key(master, json.dumps({
                "schema_version": 1,
                "state_b64": "old-classical-state",
                "credential_identity_b64": "old-credential",
                "groups": [123],
            }))
            with open(engine.mls_state_path(), "w", encoding="utf-8") as fh:
                fh.write(token)
            engine.mls_bridge = RejectingBridge()  # type: ignore[assignment]

            self.assertFalse(engine._load_mls_state_into_bridge())
            self.assertFalse(os.path.exists(engine.mls_state_path()))
            self.assertFalse(engine.mls_identity_ready)
            self.assertEqual(engine.mls_credential_identity_b64, "")
            self.assertNotIn(123, engine.mls_group_ready)

    def test_missing_identity_record_keeps_secure_state_and_message_cache(self) -> None:
        master = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp:
            engine = CryptoSession(master_key=master, secchat_dir=tmp, my_uid=7)
            engine.cache_message(10, 1, 2, "cached history", "12:00")
            protected_files = [
                engine.msg_cache_path(10),
                engine.double_ratchet_path(10),
            ]
            for path in protected_files[1:]:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("dummy protected secure state")

            result = engine.restore_identity_key_record({"found": False})

            self.assertFalse(result["found"])
            self.assertTrue(result.get("upload"))
            for path in protected_files:
                self.assertTrue(os.path.exists(path), path)
            self.assertEqual(
                engine.load_cached_messages(10)[1]["body"],
                "cached history",
            )

    def test_restore_identity_record_restores_encrypted_identity_secret(self) -> None:
        master = os.urandom(32)
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dst:
            source = CryptoSession(master_key=master, secchat_dir=src, my_uid=7)
            source.identity_pk, source.identity_sk = identity_keygen()
            upload = source.current_identity_key_record_command()
            self.assertTrue(upload.get("identity_sk_enc"))

            restored = CryptoSession(master_key=master, secchat_dir=dst, my_uid=7)
            result = restored.restore_identity_key_record({
                "found": True,
                "identity_pk": upload["identity_pk"],
                "identity_sig": upload["identity_sig"],
                "identity_sk_enc": upload["identity_sk_enc"],
            })

            self.assertTrue(result["identity_secret_restored"])
            self.assertEqual(restored.identity_pk, source.identity_pk)
            self.assertEqual(restored.identity_sk, source.identity_sk)
            self.assertTrue(os.path.exists(restored.identity_key_path()))

            pqxdh_upload = restored.fresh_pqxdh_bundle_command()
            self.assertTrue(same_identity_key(
                pqxdh_upload["identity_pk"], upload["identity_pk"]))

    def test_backup_state_survives_password_rewrap(self) -> None:
        old_master = os.urandom(32)
        new_master = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp:
            backup_path = os.path.join(tmp, "backup.json")
            engine = CryptoSession(master_key=old_master, secchat_dir=tmp, my_uid=7)
            pk, sk = identity_keygen()
            engine.identity_pk = pk
            engine.identity_sk = sk
            engine.save_identity_key()
            exported = engine.export_e2ee_backup(
                backup_path,
                "backup-passphrase",
                account_username="alice",
                include_cache=False,
            )
            self.assertEqual(engine.get_backup_status()["latest_generation"], 1)

            engine.rewrap_local_state(old_master, new_master)
            engine.master_key = new_master
            status = engine.get_backup_status()
            self.assertEqual(status["latest_backup_id"], exported["backup_id"])
            self.assertEqual(status["latest_generation"], 1)

    def test_signed_transcript_checkpoint_detects_group_view_mismatch(self) -> None:
        master = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            author = CryptoSession(master_key=master, secchat_dir=tmp_a, my_uid=1)
            verifier = CryptoSession(master_key=master, secchat_dir=tmp_b, my_uid=2)
            pk, sk = identity_keygen()
            author.identity_pk = pk
            author.identity_sk = sk

            for engine in (author, verifier):
                engine.record_transcript_message(90, 1, 1, "one", "12:01")
                engine.record_transcript_message(90, 2, 2, "two", "12:02")

            wire = author.create_transcript_checkpoint(90)
            self.assertTrue(wire.startswith("S3MLS:"))
            self.assertTrue(verifier.handle_group_integrity_control(90, wire))
            self.assertEqual(verifier.pop_control_warnings(90), [])

        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            author = CryptoSession(master_key=master, secchat_dir=tmp_a, my_uid=1)
            verifier = CryptoSession(master_key=master, secchat_dir=tmp_b, my_uid=2)
            pk, sk = identity_keygen()
            author.identity_pk = pk
            author.identity_sk = sk
            author.record_transcript_message(91, 1, 1, "one", "12:01")
            author.record_transcript_message(91, 2, 2, "two", "12:02")
            verifier.record_transcript_message(91, 1, 1, "one", "12:01")
            verifier.record_transcript_message(91, 2, 2, "tampered", "12:02")

            self.assertTrue(verifier.handle_group_integrity_control(
                91, author.create_transcript_checkpoint(91)))
            warnings = verifier.pop_control_warnings(91)
            self.assertTrue(any("local message order" in w for w in warnings))

    def test_transcript_checkpoint_skips_prejoin_baseline_mismatch(self) -> None:
        master = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            author = CryptoSession(master_key=master, secchat_dir=tmp_a, my_uid=1)
            new_member = CryptoSession(master_key=master, secchat_dir=tmp_b, my_uid=3)
            pk, sk = identity_keygen()
            author.identity_pk = pk
            author.identity_sk = sk

            author.record_transcript_message(93, 1, 1, "before join", "12:01")
            author.record_transcript_message(93, 2, 2, "also before join", "12:02")
            author.record_transcript_message(93, 3, 1, "after join", "12:03")
            new_member.record_transcript_message(93, 3, 1, "after join", "12:03")

            self.assertTrue(new_member.handle_group_integrity_control(
                93, author.create_transcript_checkpoint(93)))
            self.assertEqual(new_member.pop_control_warnings(93), [])

    def test_signed_transcript_checkpoint_rejects_tampering(self) -> None:
        master = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            author = CryptoSession(master_key=master, secchat_dir=tmp_a, my_uid=1)
            verifier = CryptoSession(master_key=master, secchat_dir=tmp_b, my_uid=2)
            pk, sk = identity_keygen()
            author.identity_pk = pk
            author.identity_sk = sk
            author.record_transcript_message(92, 1, 1, "one", "12:01")
            verifier.record_transcript_message(92, 1, 1, "one", "12:01")

            from client.crypto_engine.secure_protocol import PREFIX_MLS, json_b64, json_unb64
            wire = author.create_transcript_checkpoint(92)
            payload = json_unb64(wire[len(PREFIX_MLS):])
            payload["transcript_head"] = "0" * 64
            bad_wire = PREFIX_MLS + json_b64(payload)

            self.assertTrue(verifier.handle_group_integrity_control(92, bad_wire))
            warnings = verifier.pop_control_warnings(92)
            self.assertTrue(any("invalid signature" in w for w in warnings))


if __name__ == "__main__":
    unittest.main(verbosity=2)
