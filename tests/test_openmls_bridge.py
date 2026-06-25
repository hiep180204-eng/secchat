#!/usr/bin/env python3
"""Smoke test for the Rust OpenMLS bridge binary."""

from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from client.crypto_engine.openmls_bridge import MlsBridge, PQ_HYBRID_CIPHERSUITE


class MlsBridgeTest(unittest.TestCase):
    def test_openmls_bridge_selftest_if_binary_is_available(self) -> None:
        bridge = MlsBridge()
        if not bridge.available():
            self.skipTest("OpenMLS bridge binary is not built on this host")
        result = bridge.selftest()
        self.assertTrue(result["ok"])
        self.assertEqual(result["backend"], "openmls")
        self.assertEqual(result["ciphersuite"], PQ_HYBRID_CIPHERSUITE)
        self.assertTrue(result["pq_hybrid"])
        self.assertFalse(result["pq_authentication"])
        self.assertGreater(result["welcome_bytes"], 0)
        self.assertTrue(result["validator_create_ok"])
        self.assertTrue(result["validator_remove_ok"])
        self.assertTrue(result["validator_rejects_bogus_commit"])
        self.assertFalse(result["bob_active_after_remove"])

    def test_openmls_state_export_import_if_binary_is_available(self) -> None:
        alice = MlsBridge()
        bob = MlsBridge()
        if not alice.available() or not bob.available():
            self.skipTest("OpenMLS bridge binary is not built on this host")
        try:
            alice.init_identity(
                user_id=1,
                email="123@gmail.com",
                secchat_identity_pk="alice-id",
                secchat_identity_version=1,
            )
            bob.init_identity(
                user_id=2,
                email="234@gmail.com",
                secchat_identity_pk="bob-id",
                secchat_identity_version=1,
            )
            bob_kp = bob.top_up_key_packages(count=1)[0]["key_package_b64"]
            alice.create_group(42)
            add = alice.add_members(42, [bob_kp])
            bob.join_from_welcome(42, add["welcome_b64"])
            first = alice.encrypt_application(42, "before restart")
            self.assertEqual(bob.decrypt_application(42, first), "before restart")

            exported = bob.export_state()
            self.assertEqual(exported["ciphersuite"], PQ_HYBRID_CIPHERSUITE)
            self.assertTrue(exported["pq_hybrid"])
            bob.close()
            bob_restored = MlsBridge()
            try:
                bob_restored.import_state(exported["state_b64"])
                second = alice.encrypt_application(42, "after restart")
                self.assertEqual(
                    bob_restored.decrypt_application(42, second),
                    "after restart",
                )
            finally:
                bob_restored.close()
        finally:
            alice.close()
            bob.close()


if __name__ == "__main__":
    unittest.main()
