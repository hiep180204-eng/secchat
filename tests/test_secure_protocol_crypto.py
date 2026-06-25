import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.crypto_engine.secure_protocol import (
    PREFIX_DR,
    PREFIX_PQ_INIT,
    DoubleRatchet,
    generate_local_bundle,
    json_unb64,
    pqxdh_initiate,
    pqxdh_respond,
)
from client.crypto_engine.openmls_bridge import MlsBridge, PQ_HYBRID_CIPHERSUITE
from client.utils import identity_keygen


class SecureProtocolCryptoTests(unittest.TestCase):
    def _users(self):
        a_id_pk, a_id_sk = identity_keygen()
        b_id_pk, b_id_sk = identity_keygen()
        a_upload, a_store = generate_local_bundle(a_id_pk, a_id_sk, otk_count=2)
        b_upload, b_store = generate_local_bundle(b_id_pk, b_id_sk, otk_count=2)
        return (a_id_pk, a_id_sk, a_upload, a_store), (b_id_pk, b_id_sk, b_upload, b_store)

    def test_pqxdh_initial_and_double_ratchet_roundtrip(self):
        a, b = self._users()
        token, a_state, _fp_a = pqxdh_initiate(
            b[2], a[3], a[0], a[1], 101, 202,
            sender_identity_version=3)
        self.assertTrue(token.startswith(PREFIX_PQ_INIT))
        meta = json_unb64(token[len(PREFIX_PQ_INIT):])
        self.assertEqual(meta["sender_identity_version"], 3)

        plain, b_state, _fp_b, sender_uid = pqxdh_respond(
            token, b[3], expected_uid=202)
        self.assertEqual(sender_uid, 101)
        self.assertEqual(plain, "__S3_INIT__")

        w1 = a_state.encrypt("hello b")
        self.assertTrue(w1.startswith(PREFIX_DR))
        self.assertEqual(b_state.decrypt(w1), "hello b")

        w2 = b_state.encrypt("hello a")
        self.assertEqual(a_state.decrypt(w2), "hello a")

    def test_double_ratchet_out_of_order_and_replay_rejection(self):
        root = os.urandom(32)
        a_state = DoubleRatchet.new(root, initiator=True, session_id="unit-test")
        b_state = DoubleRatchet.new(
            root, initiator=False, remote_dh=a_state.dh_pk, session_id="unit-test")
        wires = [a_state.encrypt(f"m{i}") for i in range(3)]

        self.assertEqual(b_state.decrypt(wires[2]), "m2")
        self.assertEqual(b_state.decrypt(wires[0]), "m0")
        self.assertEqual(b_state.decrypt(wires[1]), "m1")
        with self.assertRaises(Exception):
            b_state.decrypt(wires[1])

    def test_openmls_bridge_selftest_covers_group_welcome_commit_and_remove(self):
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
        self.assertGreater(result["remove_commit_bytes"], 0)
        self.assertTrue(result["validator_rejects_bogus_commit"])
        self.assertFalse(result["bob_active_after_remove"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
