from __future__ import annotations

import time
import unittest
from typing import Any

from ui_vnc_harness import VncE2ETestCase, VncClient


PASSWORD = "123456"


def _list_has_item(snapshot: dict[str, Any], list_name: str, text: str) -> bool:
    for widget in snapshot.get("widgets") or []:
        if widget.get("object_name") != list_name:
            continue
        for item in widget.get("items") or []:
            if text in str(item.get("text", "")):
                return True
    return False


def _message_visible(snapshot: dict[str, Any], text: str) -> bool:
    messages = snapshot.get("chat", {}).get("message_texts") or []
    return any(text in str(message) for message in messages)


def register_user(client: VncClient, username: str, email: str,
                  password: str = PASSWORD) -> None:
    client.click_widget("login.go_register")
    client.wait_for("register page", lambda s: s.get("current_page") == "register")
    client.type_into("register.username", username)
    client.type_into("register.email", email)
    client.type_into("register.password", password)
    client.type_into("register.confirm", password)
    client.click_widget("register.submit")
    client.wait_for(
        f"{username} auto logged in after register",
        lambda s: s.get("current_page") == "chat"
        and s.get("chat", {}).get("me") == username,
        timeout=35.0,
    )


def login_user(client: VncClient, email: str, username: str | None = None,
               password: str = PASSWORD) -> None:
    client.wait_for("login page", lambda s: s.get("current_page") == "login")
    client.type_into("login.email", email)
    client.type_into("login.password", password)
    client.click_widget("login.submit")
    client.wait_for(
        f"{email} logged in",
        lambda s: s.get("current_page") == "chat"
        and (username is None or s.get("chat", {}).get("me") == username),
        timeout=35.0,
    )


def logout_user(client: VncClient) -> None:
    client.click_widget("chat.exit")
    client.wait_for("login page after logout", lambda s: s.get("current_page") == "login",
                    timeout=20.0)


def search_user(client: VncClient, query: str, expected: str) -> None:
    client.click_widget("chat.nav.search")
    client.type_into("chat.search_input", query)
    client.click_widget("chat.search_go")
    client.wait_for(
        f"search result {expected}",
        lambda s: _list_has_item(s, "chat.search_results", expected),
        timeout=15.0,
    )


def choose_context_action(client: VncClient, list_name: str, text_contains: str,
                          action_index: int) -> None:
    client.click_list_item(list_name, text_contains=text_contains, button=3)
    time.sleep(0.3)
    for _ in range(action_index):
        client.press("Down")
        time.sleep(0.05)
    client.press("Return")


def send_friend_request(sender: VncClient, target_username: str) -> None:
    search_user(sender, target_username, target_username)
    choose_context_action(sender, "chat.search_results", target_username, 2)
    try:
        sender.click_widget("OK", timeout=3.0)
    except AssertionError:
        pass


def accept_first_request(receiver: VncClient, requester_username: str) -> None:
    receiver.wait_for(
        "online friend request badge",
        lambda s: int(s.get("chat", {}).get("pending_requests_count") or 0) > 0,
        timeout=20.0,
    )
    receiver.click_widget("chat.nav.requests")
    receiver.wait_for(
        "request label visible",
        lambda s: any(
            requester_username in str(w.get("text", ""))
            for w in s.get("widgets") or []
        ),
        timeout=15.0,
    )
    receiver.click_widget("Accept")
    receiver.wait_for(
        "request list empty after accept",
        lambda s: int(s.get("chat", {}).get("pending_requests_count") or 0) == 0,
        timeout=20.0,
    )


def open_dm_from_search(client: VncClient, peer_username: str) -> None:
    client.click_widget("chat.nav.chats")
    client.wait_for(
        f"{peer_username} is a friend",
        lambda s: _list_has_item(s, "chat.friend_list", peer_username),
        timeout=30.0,
    )
    choose_context_action(client, "chat.friend_list", peer_username, 2)
    client.wait_for(
        f"active DM with {peer_username}",
        lambda s: s.get("chat", {}).get("active_conv_id", 0) > 0
        and peer_username in str(s.get("chat", {}).get("header", "")),
        timeout=35.0,
    )


def send_message(client: VncClient, body: str) -> None:
    client.type_into("chat.message_input", body)
    client.click_widget("chat.send")
    client.wait_for(
        f"local message visible: {body}",
        lambda s: _message_visible(s, body),
        timeout=25.0,
    )


class TestVncAuthAndMessaging(VncE2ETestCase):
    def test_register_auto_login_logout_and_relogin_through_vnc(self) -> None:
        client = self.vnc["chat-client1"]
        register_user(client, "alice_vnc", "alice_vnc@example.test")
        logout_user(client)
        login_user(client, "alice_vnc@example.test", "alice_vnc")

    def test_friend_request_online_badge_and_dm_unread_flow(self) -> None:
        alice = self.vnc["chat-client1"]
        bob = self.vnc["chat-client2"]

        register_user(alice, "alice_vnc", "alice_vnc@example.test")
        register_user(bob, "bob_vnc", "bob_vnc@example.test")

        send_friend_request(alice, "bob_vnc")
        accept_first_request(bob, "alice_vnc")

        open_dm_from_search(alice, "bob_vnc")
        send_message(alice, "hello bob over vnc")

        bob.wait_for(
            "incoming DM appears in inbox",
            lambda s: _list_has_item(s, "chat.dm_list", "alice_vnc")
            or "unread" in str(s.get("chat", {}).get("unread_conv_ids", [])),
            timeout=45.0,
        )
        bob.click_widget("chat.nav.chats")
        bob.click_list_item("chat.dm_list", text_contains="alice_vnc")
        bob.wait_for(
            "bob sees alice message",
            lambda s: _message_visible(s, "hello bob over vnc")
            and not s.get("chat", {}).get("pending_error_bubbles"),
            timeout=45.0,
        )
        send_message(bob, "hi alice from vnc2")
        alice.wait_for(
            "alice receives bob reply",
            lambda s: _message_visible(s, "hi alice from vnc2"),
            timeout=45.0,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
