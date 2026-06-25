#!/usr/bin/env python3
"""Identity transparency verification and persistence tests."""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from client.crypto_engine.audit import (  # noqa: E402
    AUDITOR_PUBLIC_KEY_HEX,
    AuditError,
    check_consistency,
    verify_checkpoint,
    verify_identity_from_auditor,
    verify_inclusion,
)
from client.crypto_engine.session import CryptoSession, CryptoStateError  # noqa: E402
from auditor_service import _assign_leaf_indices, _body, _inclusion_proof  # noqa: E402


SEED = bytes.fromhex("8b4f8067f2ba1a39d62f08bd24ff152a9cd18c95b9cf4f78015fd9706f3b6c42")


def _node_hash(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256(
        b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    ).hexdigest()


def _checkpoint(leaves: list[str]) -> dict:
    root = _node_hash(leaves[0], leaves[1])
    created_at = "2026-05-17T00:00:00Z"
    msg = f"SecChatAuditCheckpoint|2|{root}|{created_at}".encode("utf-8")
    sig = Ed25519PrivateKey.from_private_bytes(SEED).sign(msg).hex()
    return {
        "tree_size": 2,
        "root_hash": root,
        "created_at": created_at,
        "signature": sig,
        "auditor_pk": AUDITOR_PUBLIC_KEY_HEX,
    }


class IdentityAuditTest(unittest.TestCase):
    def test_checkpoint_and_inclusion_proof_verify(self) -> None:
        leaves = [
            hashlib.sha256(b"leaf-a").hexdigest(),
            hashlib.sha256(b"leaf-b").hexdigest(),
        ]
        cp = _checkpoint(leaves)
        verify_checkpoint(cp)
        verify_inclusion(leaves[1], 1, [{"side": "left", "hash": leaves[0]}], cp)
        with self.assertRaises(AuditError):
            verify_inclusion(leaves[1], 1, [{"side": "left", "hash": leaves[1]}], cp)

    def test_audit_errors_have_specific_codes(self) -> None:
        leaves = [
            hashlib.sha256(b"leaf-a").hexdigest(),
            hashlib.sha256(b"leaf-b").hexdigest(),
        ]
        cp = _checkpoint(leaves)

        with self.assertRaises(AuditError) as malformed:
            verify_checkpoint({"tree_size": 1, "root_hash": "bad"})
        self.assertEqual(malformed.exception.code, "checkpoint_malformed")

        bad_sig = dict(cp)
        bad_sig["signature"] = "00" * 64
        with self.assertRaises(AuditError) as bad_checkpoint_sig:
            verify_checkpoint(bad_sig)
        self.assertEqual(
            bad_checkpoint_sig.exception.code,
            "checkpoint_signature_invalid",
        )

        with self.assertRaises(AuditError) as bad_side:
            verify_inclusion(leaves[1], 1, [{"side": "middle", "hash": leaves[0]}], cp)
        self.assertEqual(bad_side.exception.code, "proof_side_malformed")

        with self.assertRaises(AuditError) as bad_root:
            verify_inclusion(leaves[1], 1, [{"side": "left", "hash": leaves[1]}], cp)
        self.assertEqual(bad_root.exception.code, "proof_root_mismatch")

        old_cp = {"tree_size": 3, "root_hash": "a" * 64, "created_at": "old"}
        with self.assertRaises(AuditError) as rollback:
            check_consistency("http://auditor", old_cp, cp)
        self.assertEqual(rollback.exception.code, "checkpoint_rollback")

    def test_identity_version_404_is_not_reported_as_unavailable(self) -> None:
        class _Body(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.close()

        body = _Body(b'{"error":"identity version not found"}')
        err = HTTPError(
            "http://auditor/identity/2/9/proof",
            404,
            "Not Found",
            {},
            body,
        )
        with patch("client.crypto_engine.audit.urlopen", side_effect=err):
            with self.assertRaises(AuditError) as ctx:
                verify_identity_from_auditor(
                    "http://auditor",
                    user_id=2,
                    identity_version=9,
                    identity_pk="id",
                )
        self.assertEqual(ctx.exception.code, "identity_version_not_found")

    def test_identity_version_zero_and_leaf_index_zero_are_valid(self) -> None:
        class _Body(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.close()

        row = {
            "log_index": 1,
            "user_id": 2,
            "identity_version": 0,
            "identity_pk": "aQ==",
            "device_id_hash": "",
            "device_label": "primary device",
            "event_type": "initial",
            "created_at": "2026-06-06T00:00:00Z",
            "leaf_hash": hashlib.sha256(b"leaf-version-zero").hexdigest(),
        }
        rows = _assign_leaf_indices([row])
        data = _body(rows)
        proof = {
            "leaf": rows[0],
            "leaf_index": 0,
            "proof": _inclusion_proof(data["leaf_hashes"], 0),
            "checkpoint": data["checkpoint"],
        }
        with patch(
            "client.crypto_engine.audit.urlopen",
            return_value=_Body(json.dumps(proof).encode("utf-8")),
        ):
            verified = verify_identity_from_auditor(
                "http://auditor",
                user_id=2,
                identity_version=0,
                identity_pk="aQ==",
            )
        self.assertEqual(verified["status"], "ok")

    def test_auditor_uses_dense_leaf_indices_when_log_ids_have_gaps(self) -> None:
        leaves = [
            hashlib.sha256(b"leaf-a").hexdigest(),
            hashlib.sha256(b"leaf-b").hexdigest(),
        ]
        rows = [
            {"log_index": 1, "leaf_hash": leaves[0]},
            {"log_index": 5, "leaf_hash": leaves[1]},
        ]
        _assign_leaf_indices(rows)
        self.assertEqual([r["leaf_index"] for r in rows], [0, 1])
        data = _body(rows)
        proof = _inclusion_proof(data["leaf_hashes"], rows[1]["leaf_index"])
        verify_checkpoint(data["checkpoint"])
        verify_inclusion(leaves[1], rows[1]["leaf_index"], proof, data["checkpoint"])

    def test_identity_audit_state_is_encrypted_and_detects_key_change(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session = CryptoSession(master_key=b"\x01" * 32, secchat_dir=td, my_uid=1)
            first = session.record_identity_audit_ok(
                2,
                identity_pk="id-1",
                identity_version=0,
                safety_number="1111 2222",
                checkpoint={"tree_size": 1, "root_hash": "a" * 64},
                leaf={"event_type": "initial", "device_label": "primary device"},
            )
            self.assertEqual(first["status"], "unverified")
            second = session.record_identity_audit_ok(
                2,
                identity_pk="id-2",
                identity_version=1,
                safety_number="3333 4444",
                checkpoint={"tree_size": 2, "root_hash": "b" * 64},
                leaf={"event_type": "rotation", "device_label": "primary device"},
            )
            self.assertEqual(second["status"], "key_changed")
            session.mark_identity_reviewed(2, verified=False)

            path = session.identity_audit_path(2)
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read()
            self.assertNotIn("id-2", raw)

            reloaded = CryptoSession(master_key=b"\x01" * 32, secchat_dir=td, my_uid=1)
            state = reloaded.load_identity_audit(2)
            self.assertEqual(state["identity_pk"], "id-2")
            self.assertEqual(state["status"], "reviewed_unverified")
            self.assertEqual(len(state["history"]), 2)

    def test_successful_audit_clears_old_false_mismatch_for_same_identity(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session = CryptoSession(master_key=b"\x04" * 32, secchat_dir=td, my_uid=1)
            session.record_identity_audit_problem(
                2,
                identity_pk="/w==",
                identity_version=0,
                safety_number="1111 2222",
                status="audit_mismatch",
                error="old false proof failure",
            )
            fixed = session.record_identity_audit_ok(
                2,
                identity_pk="_w",
                identity_version=0,
                safety_number="1111 2222",
                checkpoint={"tree_size": 1, "root_hash": "a" * 64},
                leaf={"event_type": "initial", "device_label": "primary device"},
            )
            self.assertEqual(fixed["status"], "unverified")
            self.assertEqual(len(fixed["history"]), 1)

    def test_global_auditor_checkpoint_state_detects_rollback_and_split_view(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session = CryptoSession(master_key=b"\x02" * 32, secchat_dir=td, my_uid=1)
            cp1 = {
                "tree_size": 1,
                "root_hash": "a" * 64,
                "created_at": "2026-05-18T00:00:00Z",
            }
            cp2 = {
                "tree_size": 2,
                "root_hash": "b" * 64,
                "created_at": "2026-05-18T00:01:00Z",
            }
            state = session.record_auditor_checkpoint(
                cp1, source="test", user_id=2, identity_version=0)
            self.assertEqual(state["checkpoint"]["tree_size"], 1)
            state = session.record_auditor_checkpoint(
                cp2, source="test", user_id=3, identity_version=0)
            self.assertEqual(state["checkpoint"]["tree_size"], 2)
            self.assertEqual(len(state["observations"]), 2)

            with open(session.auditor_state_path(), "r", encoding="utf-8") as fh:
                raw = fh.read()
            self.assertNotIn("b" * 64, raw)

            reloaded = CryptoSession(master_key=b"\x02" * 32, secchat_dir=td, my_uid=1)
            self.assertEqual(
                reloaded.load_auditor_state()["checkpoint"]["root_hash"], "b" * 64)
            with self.assertRaises(CryptoStateError):
                reloaded.record_auditor_checkpoint(
                    cp1, source="rollback", user_id=4, identity_version=0)
            with self.assertRaises(CryptoStateError):
                reloaded.record_auditor_checkpoint(
                    {
                        "tree_size": 2,
                        "root_hash": "c" * 64,
                        "created_at": "2026-05-18T00:02:00Z",
                    },
                    source="split-view",
                    user_id=5,
                    identity_version=0,
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
