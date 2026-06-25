import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secchat_testlib import (
    ChatClient,
    _mysql,
    add_member_mls,
    apply_group_change,
    create_group_mls,
    db_reset,
    ensure_mls_ready,
    fake_S3DR,
    make_friends,
    open_dm,
    prepare_group_change,
    recv_until,
    remove_member_mls,
    set_member_role_mls,
    unique,
    wait_ready,
    ws_send,
    ws_send_msg,
)


def _upload_identity_record(c: ChatClient, identity_pk: str) -> dict:
    ws_send(c.sock, {
        "type": "upload_keys",
        "identity_pk": identity_pk,
        "identity_sig": f"sig-{identity_pk}",
        "identity_sk_enc": f"idsk-{identity_pk}",
    })
    got = recv_until(
        c.sock,
        lambda m: m.get("type") in ("ok", "error"),
        timeout=4.0,
    )
    if not got:
        raise AssertionError("upload_keys did not return")
    return got


def _upload_bundle(c: ChatClient, identity_pk: str | None = None, *,
                   curve_spk_id: int = 10, pq_spk_id: int = 20,
                   curve_otk_id: int = 11, pq_otk_id: int = 21) -> None:
    ws_send(c.sock, {
        "type": "upload_pqxdh_bundle",
        "identity_pk": identity_pk or f"idpk-{c.user_id}",
        "curve_spk_id": curve_spk_id,
        "curve_spk": f"curve-spk-{curve_spk_id}",
        "curve_spk_sig": f"curve-sig-{curve_spk_id}",
        "pq_spk_id": pq_spk_id,
        "pq_kem_alg": "ML-KEM-1024",
        "pq_spk": f"pq-spk-{pq_spk_id}",
        "pq_spk_sig": f"pq-sig-{pq_spk_id}",
        "curve_one_time_prekeys": [
            {
                "key_id": curve_otk_id,
                "public_key": f"curve-otk-{curve_otk_id}",
                "signature": f"curve-otk-sig-{curve_otk_id}",
            },
        ],
        "pq_one_time_prekeys": [
            {
                "key_id": pq_otk_id,
                "alg": "ML-KEM-1024",
                "public_key": f"pq-otk-{pq_otk_id}",
                "signature": f"pq-otk-sig-{pq_otk_id}",
            },
        ],
    })
    got = recv_until(c.sock, lambda m: m.get("type") == "ok", timeout=4.0)
    if not got:
        raise AssertionError("upload_pqxdh_bundle did not return ok")


class SecureProtocolServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        wait_ready(timeout=30.0)

    def setUp(self):
        db_reset()

    def test_pqxdh_bundle_fetch_consumes_one_time_prekeys(self):
        a = ChatClient(); b = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            b.register_and_login(unique("bob"))
            _upload_bundle(b)

            ws_send(a.sock, {"type": "get_pqxdh_bundle", "user_id": b.user_id})
            first = recv_until(a.sock, lambda m: m.get("type") == "pqxdh_bundle", timeout=4.0)
            self.assertIsNotNone(first)
            self.assertEqual(first.get("curve_otk_id"), 11)
            self.assertEqual(first.get("pq_otk_id"), 21)

            ws_send(a.sock, {"type": "get_pqxdh_bundle", "user_id": b.user_id})
            second = recv_until(a.sock, lambda m: m.get("type") == "pqxdh_bundle", timeout=4.0)
            self.assertIsNotNone(second)
            self.assertEqual(second.get("curve_otk_id"), -1)
            self.assertEqual(second.get("pq_otk_id"), -1)
        finally:
            a.close(); b.close()

    def test_pqxdh_reupload_replaces_old_one_time_prekey_generation(self):
        a = ChatClient(); b = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            b.register_and_login(unique("bob"))
            _upload_bundle(
                b, curve_spk_id=100, pq_spk_id=200,
                curve_otk_id=101, pq_otk_id=201)
            _upload_bundle(
                b, curve_spk_id=300, pq_spk_id=400,
                curve_otk_id=301, pq_otk_id=401)

            ws_send(a.sock, {"type": "get_pqxdh_bundle", "user_id": b.user_id})
            got = recv_until(
                a.sock, lambda m: m.get("type") == "pqxdh_bundle", timeout=4.0)
            self.assertIsNotNone(got)
            self.assertEqual(got.get("curve_spk_id"), 300)
            self.assertEqual(got.get("pq_spk_id"), 400)
            self.assertEqual(got.get("curve_otk_id"), 301)
            self.assertEqual(got.get("pq_otk_id"), 401)
            self.assertNotEqual(got.get("curve_otk_id"), 101)
            self.assertNotEqual(got.get("pq_otk_id"), 201)
        finally:
            a.close(); b.close()

    def test_identity_upload_is_append_only_unless_rotated(self):
        a = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            first = _upload_identity_record(a, "idpk-initial")
            self.assertEqual(first.get("type"), "ok")

            second = _upload_identity_record(a, "idpk-substituted")
            self.assertEqual(second.get("type"), "error")
            self.assertIn("rotate_identity", second.get("msg", ""))

            rows = _mysql(
                "SELECT COUNT(*), MIN(identity_version), MAX(event_type) "
                "FROM identity_key_log",
                batch=True,
            ).strip().split("\t")
            self.assertEqual(rows[0], "1")
            self.assertEqual(rows[1], "0")
            self.assertEqual(rows[2], "initial")
        finally:
            a.close()

    def test_pqxdh_identity_compare_accepts_base64_url_equivalent(self):
        a = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            # Same raw byte 0xff, encoded as standard base64 vs url-safe/no pad.
            first = _upload_identity_record(a, "/w==")
            self.assertEqual(first.get("type"), "ok")

            _upload_bundle(a, identity_pk="_w")
            ws_send(a.sock, {"type": "get_my_pqxdh_status"})
            status = recv_until(
                a.sock,
                lambda m: m.get("type") == "pqxdh_status",
                timeout=4.0,
            )
            self.assertIsNotNone(status)
            self.assertTrue(status.get("has_bundle"))
            self.assertEqual(status.get("curve_prekeys"), 1)
            self.assertEqual(status.get("pq_prekeys"), 1)

            bad = _upload_identity_record(a, "AA==")
            self.assertEqual(bad.get("type"), "error")
            self.assertIn("rotate_identity", bad.get("msg", ""))
        finally:
            a.close()

    def test_get_my_keys_returns_encrypted_identity_secret(self):
        a = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            first = _upload_identity_record(a, "idpk-backup")
            self.assertEqual(first.get("type"), "ok")

            ws_send(a.sock, {"type": "get_my_keys"})
            mine = recv_until(
                a.sock,
                lambda m: m.get("type") == "my_keys",
                timeout=4.0,
            )
            self.assertIsNotNone(mine)
            self.assertTrue(mine.get("found"))
            self.assertEqual(mine.get("identity_sk_enc"), "idsk-idpk-backup")
        finally:
            a.close()

    def test_inbox_with_dm_and_group_is_valid_json_after_saved_removed(self):
        a = ChatClient(); b = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            b.register_and_login(unique("bob"))
            make_friends(a.sock, a.user_id, b.sock, b.user_id)

            ws_send(a.sock, {"type": "saved_messages"})
            saved = recv_until(
                a.sock, lambda m: m.get("type") == "error", timeout=4.0)
            self.assertIsNotNone(saved)
            self.assertIn(
                saved.get("msg", ""),
                ("Unsupported command", "Saved Messages is no longer supported"),
            )
            open_dm(a.sock, b.user_id)
            create_group_mls(a, unique("group"), [b])

            ws_send(a.sock, {"type": "get_inbox"})
            inbox = recv_until(
                a.sock, lambda m: m.get("type") == "inbox" or "__raw__" in m,
                timeout=4.0,
            )
            self.assertIsNotNone(inbox)
            self.assertNotIn("__raw__", inbox)
            convs = inbox.get("conversations", [])
            self.assertTrue(any(c.get("is_group") for c in convs))
            self.assertTrue(any(not c.get("is_group") for c in convs))
            self.assertFalse(any(c.get("is_saved_messages") for c in convs))
        finally:
            a.close(); b.close()

    def test_removed_direct_group_mutation_command_is_rejected(self):
        a = ChatClient(); b = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            b.register_and_login(unique("bob"))
            make_friends(a.sock, a.user_id, b.sock, b.user_id)
            ws_send(a.sock, {
                "type": "create_group",
                "name": unique("group"),
                "members": [b.user_id],
            })
            denied = recv_until(
                a.sock,
                lambda m: m.get("type") == "error"
                and str(m.get("msg", "")) == "Unsupported command",
                timeout=4.0,
            )
            self.assertIsNotNone(denied)
        finally:
            a.close(); b.close()

    def test_removed_wire_prefix_is_rejected(self):
        a = ChatClient(); b = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            b.register_and_login(unique("bob"))
            make_friends(a.sock, a.user_id, b.sock, b.user_id)
            conv = open_dm(a.sock, b.user_id)
            self.assertIsNotNone(conv)

            ws_send(a.sock, {
                "type": "message",
                "conversation_id": conv,
                "body": "E2R:1:removed",
            })
            err = recv_until(
                a.sock,
                lambda m: m.get("type") == "error"
                and "unsupported encrypted" in str(m.get("msg", "")),
                timeout=4.0,
            )
            self.assertIsNotNone(err)
        finally:
            a.close(); b.close()

    def test_classical_mls_key_package_upload_is_rejected(self):
        a = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            ensure_mls_ready(a, publish=False)
            ws_send(a.sock, {
                "type": "upload_mls_key_packages",
                "key_packages": [{
                    "key_package_ref": "classical-ref",
                    "key_package_b64": "AAAA",
                    "ciphersuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                    "credential_identity_b64": "",
                    "secchat_signature": "AAAA",
                }],
            })
            got = recv_until(
                a.sock,
                lambda m: m.get("type") in ("mls_key_packages_uploaded", "error"),
                timeout=6.0,
            )
            self.assertIsNotNone(got)
            self.assertEqual(got.get("type"), "mls_key_packages_uploaded")
            self.assertEqual(int(got.get("stored", -1)), 0)
            self.assertEqual(int(got.get("rejected", -1)), 1)
        finally:
            a.close()

    def test_bogus_mls_apply_is_rejected_without_membership_mutation(self):
        a = ChatClient(); b = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            b.register_and_login(unique("bob"))
            make_friends(a.sock, a.user_id, b.sock, b.user_id)

            prepared = prepare_group_change(
                a,
                "create_group",
                name=unique("group"),
                members=[int(b.user_id)],
            )
            self.assertEqual(prepared.get("type"), "group_change_prepared")
            gid = int(prepared["conversation_id"])
            apply_group_change(a, prepared, target_user_ids=[int(b.user_id)])
            rejected = recv_until(
                a.sock,
                lambda m: m.get("type") == "error"
                and "MLS validation failed" in str(m.get("msg", "")),
                timeout=8.0,
            )
            self.assertIsNotNone(rejected)
            member_count = _mysql(
                "SELECT COUNT(*) FROM conversation_members "
                f"WHERE conversation_id={gid}"
            ).strip()
            handshake_count = _mysql(
                "SELECT COUNT(*) FROM mls_group_handshake "
                f"WHERE conversation_id={gid}"
            ).strip()
            state_count = _mysql(
                "SELECT COUNT(*) FROM mls_group_state "
                f"WHERE conversation_id={gid}"
            ).strip()
            self.assertEqual(member_count, "0")
            self.assertEqual(handshake_count, "0")
            self.assertEqual(state_count, "0")
        finally:
            a.close(); b.close()

    def test_history_returns_pin_and_reaction_metadata(self):
        a = ChatClient(); b = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            b.register_and_login(unique("bob"))
            make_friends(a.sock, a.user_id, b.sock, b.user_id)
            conv = open_dm(a.sock, b.user_id)
            self.assertIsNotNone(conv)

            wire = ws_send_msg(a.sock, conv, "metadata check")
            echo = recv_until(
                a.sock,
                lambda m: m.get("type") == "message" and m.get("body") == wire,
                timeout=4.0,
            )
            self.assertIsNotNone(echo)
            mid = int(echo["id"])

            ws_send(a.sock, {"type": "pin_message", "message_id": mid})
            pinned = recv_until(
                a.sock,
                lambda m: m.get("type") == "message_pinned"
                and int(m.get("message_id", 0)) == mid,
                timeout=4.0,
            )
            self.assertIsNotNone(pinned)

            ws_send(a.sock, {"type": "add_reaction", "message_id": mid, "emoji": "ok"})
            reacted = recv_until(
                a.sock,
                lambda m: m.get("type") == "reaction_added"
                and int(m.get("message_id", 0)) == mid,
                timeout=4.0,
            )
            self.assertIsNotNone(reacted)

            ws_send(a.sock, {"type": "history", "conversation_id": conv})
            hist = recv_until(
                a.sock,
                lambda m: m.get("type") == "history"
                and int(m.get("conversation_id", 0)) == conv,
                timeout=4.0,
            )
            self.assertIsNotNone(hist)
            row = next(
                (m for m in hist.get("messages", [])
                 if int(m.get("id", 0)) == mid),
                None,
            )
            self.assertIsNotNone(row)
            self.assertTrue(row.get("pinned"))
            self.assertEqual(row.get("reactions"), [
                {"emoji": "ok", "count": 1, "me": True}
            ])
        finally:
            a.close(); b.close()

    def test_reply_edit_and_delete_metadata_round_trip(self):
        a = ChatClient(); b = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            b.register_and_login(unique("bob"))
            make_friends(a.sock, a.user_id, b.sock, b.user_id)
            conv = open_dm(a.sock, b.user_id)
            self.assertIsNotNone(conv)

            original_wire = ws_send_msg(a.sock, conv, "original")
            original = recv_until(
                a.sock,
                lambda m: m.get("type") == "message"
                and m.get("body") == original_wire,
                timeout=4.0,
            )
            self.assertIsNotNone(original)
            original_id = int(original["id"])

            reply_wire = ws_send_msg(
                a.sock, conv, "reply", reply_to_message_id=original_id)
            reply = recv_until(
                a.sock,
                lambda m: m.get("type") == "message"
                and m.get("body") == reply_wire,
                timeout=4.0,
            )
            self.assertIsNotNone(reply)
            self.assertEqual(int(reply.get("reply_to_message_id", 0)), original_id)

            edit_wire = fake_S3DR("edited")
            ws_send(a.sock, {
                "type": "edit_message",
                "message_id": original_id,
                "new_body": edit_wire,
            })
            edit = recv_until(
                a.sock,
                lambda m: m.get("type") == "message"
                and int(m.get("edit_target_message_id", 0) or 0) == original_id,
                timeout=4.0,
            )
            self.assertIsNotNone(edit)

            ws_send(a.sock, {"type": "delete_message", "message_id": original_id})
            deleted = recv_until(
                a.sock,
                lambda m: m.get("type") == "message_deleted"
                and int(m.get("id", 0) or 0) == original_id,
                timeout=4.0,
            )
            self.assertIsNotNone(deleted)

            ws_send(b.sock, {"type": "delete_message", "message_id": int(reply["id"])})
            denied = recv_until(
                b.sock,
                lambda m: m.get("type") == "error"
                and "Cannot delete" in str(m.get("msg", "")),
                timeout=4.0,
            )
            self.assertIsNotNone(denied)
        finally:
            a.close(); b.close()

    def test_group_history_hides_messages_before_member_join(self):
        a = ChatClient(); b = ChatClient(); c = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            b.register_and_login(unique("bob"))
            c.register_and_login(unique("carol"))
            make_friends(a.sock, a.user_id, b.sock, b.user_id)
            make_friends(a.sock, a.user_id, c.sock, c.user_id)

            gid = create_group_mls(a, unique("group"), [b])

            before_wire = ws_send_msg(a.sock, gid, "before carol joined")
            before_echo = recv_until(
                a.sock,
                lambda m: m.get("type") == "message" and m.get("body") == before_wire,
                timeout=4.0,
            )
            self.assertIsNotNone(before_echo)
            _mysql(
                "UPDATE messages SET sent_at='2000-01-01 00:00:00.000' "
                f"WHERE id={int(before_echo['id'])}"
            )
            _mysql(
                "UPDATE conversation_members SET joined_at='1999-01-01 00:00:00' "
                f"WHERE conversation_id={gid} AND user_id={b.user_id}"
            )

            added = add_member_mls(a, gid, c)
            self.assertIsNotNone(added)

            after_wire = ws_send_msg(a.sock, gid, "after carol joined")
            after_echo = recv_until(
                a.sock,
                lambda m: m.get("type") == "message" and m.get("body") == after_wire,
                timeout=4.0,
            )
            self.assertIsNotNone(after_echo)

            ws_send(c.sock, {"type": "history", "conversation_id": gid})
            hist_c = recv_until(
                c.sock,
                lambda m: m.get("type") == "history"
                and int(m.get("conversation_id", 0)) == gid,
                timeout=4.0,
            )
            self.assertIsNotNone(hist_c)
            bodies_c = [m.get("body", "") for m in hist_c.get("messages", [])]
            self.assertNotIn(before_wire, bodies_c)
            self.assertIn(after_wire, bodies_c)

            ws_send(b.sock, {"type": "history", "conversation_id": gid})
            hist_b = recv_until(
                b.sock,
                lambda m: m.get("type") == "history"
                and int(m.get("conversation_id", 0)) == gid,
                timeout=4.0,
            )
            self.assertIsNotNone(hist_b)
            bodies_b = [m.get("body", "") for m in hist_b.get("messages", [])]
            self.assertIn(before_wire, bodies_b)
            self.assertIn(after_wire, bodies_b)
        finally:
            a.close(); b.close(); c.close()

    def test_group_membership_events_include_role_transcript_state(self):
        a = ChatClient(); b = ChatClient(); c = ChatClient()
        try:
            a.register_and_login(unique("alice"))
            b.register_and_login(unique("bob"))
            c.register_and_login(unique("carol"))
            make_friends(a.sock, a.user_id, b.sock, b.user_id)
            make_friends(a.sock, a.user_id, c.sock, c.user_id)

            gid = create_group_mls(a, unique("group"), [b])

            added = add_member_mls(a, gid, c)
            self.assertIsNotNone(added)
            self.assertIn("member_ids", added)
            self.assertEqual(added.get("username"), c.username)
            self.assertEqual(added.get("by_username"), a.username)
            self.assertEqual(added.get("operation"), "add_member")
            self.assertGreater(int(added.get("system_event_id", 0) or 0), 0)
            self.assertIn("after_message_id", added)
            members = added.get("members") or []
            self.assertIn(
                {"user_id": a.user_id, "role": "admin"},
                members,
            )
            self.assertIn(
                {"user_id": c.user_id, "role": "member"},
                members,
            )

            before_wire = ws_send_msg(a.sock, gid, "before role change")
            before_msg = recv_until(
                a.sock,
                lambda m: m.get("type") == "message"
                and m.get("body") == before_wire,
                timeout=4.0,
            )
            self.assertIsNotNone(before_msg)
            before_id = int(before_msg.get("id", 0) or 0)
            self.assertGreater(before_id, 0)

            role_changed = set_member_role_mls(a, gid, b, "admin")
            self.assertIsNotNone(role_changed)
            self.assertEqual(role_changed.get("username"), b.username)
            self.assertEqual(role_changed.get("by_username"), a.username)
            self.assertEqual(role_changed.get("operation"), "set_member_role")
            role_event_id = int(role_changed.get("system_event_id", 0) or 0)
            self.assertGreater(role_event_id, 0)
            self.assertEqual(
                int(role_changed.get("after_message_id", 0) or 0),
                before_id,
            )
            self.assertIn(
                {"user_id": b.user_id, "role": "admin"},
                role_changed.get("members") or [],
            )

            after_wire = ws_send_msg(a.sock, gid, "after role change")
            after_msg = recv_until(
                a.sock,
                lambda m: m.get("type") == "message"
                and m.get("body") == after_wire,
                timeout=4.0,
            )
            self.assertIsNotNone(after_msg)
            after_id = int(after_msg.get("id", 0) or 0)
            self.assertGreater(after_id, before_id)

            ws_send(b.sock, {"type": "history", "conversation_id": gid})
            hist = recv_until(
                b.sock,
                lambda m: m.get("type") == "history"
                and int(m.get("conversation_id", 0) or 0) == gid,
                timeout=4.0,
            )
            self.assertIsNotNone(hist)
            hist_messages = hist.get("messages") or []
            hist_ids = [int(m.get("id", 0) or 0) for m in hist_messages]
            self.assertIn(before_id, hist_ids)
            self.assertIn(after_id, hist_ids)
            role_events = [
                ev for ev in hist.get("system_events", [])
                if ev.get("event_type") == "member_role_changed"
                and int(ev.get("system_event_id", 0) or 0) == role_event_id
            ]
            self.assertEqual(len(role_events), 1)
            self.assertEqual(
                int(role_events[0].get("after_message_id", 0) or 0),
                before_id,
            )

            removed = remove_member_mls(a, gid, c)
            self.assertIsNotNone(removed)
            self.assertEqual(removed.get("username"), c.username)
            self.assertEqual(removed.get("by_username"), a.username)
            self.assertEqual(removed.get("operation"), "remove_member")
            self.assertGreater(int(removed.get("system_event_id", 0) or 0), 0)
        finally:
            a.close(); b.close(); c.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
