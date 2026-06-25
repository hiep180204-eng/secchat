#!/usr/bin/env python3
"""Sinh một lượng traffic 'bình thường' để chụp màn hình metrics của server GUI.

Dùng lại các helper trong tests/secchat_testlib.py: đăng ký/đăng nhập vài người
dùng, kết bạn, mở DM và gửi tin, sửa/xóa/thả cảm xúc, tạo nhóm MLS, và đọc
inbox/tìm kiếm. Sau khi xong, giữ các kết nối mở và ngủ một lúc để dashboard
hiển thị cả 'active connections' lẫn các bộ đếm tích lũy trong lúc chụp.

    python tools/generate_demo_traffic.py [--hold-seconds 60]
"""
from __future__ import annotations

import argparse
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_TESTS = os.path.join(os.path.dirname(_HERE), "tests")
sys.path.insert(0, _TESTS)

from secchat_testlib import (  # noqa: E402
    wait_ready, unique, ChatClient, make_friends,
    create_group_mls, ws_send, ws_send_msg, recv_until,
    get_metrics,
)


def open_dm(c: ChatClient, peer_uid: int) -> int:
    ws_send(c.sock, {"type": "start_dm", "user_id": peer_uid})
    m = recv_until(c.sock, lambda m: m.get("conversation_id") is not None, timeout=6.0)
    assert m, "start_dm không phản hồi"
    return int(m["conversation_id"])


def send_msg(c: ChatClient, conv: int, body: str) -> int:
    sent = ws_send_msg(c.sock, conv, body)
    m = recv_until(
        c.sock,
        lambda m: (m.get("type") == "message" and m.get("body") == sent)
        or m.get("type") == "error",
        timeout=8.0,
    )
    assert m and m.get("type") != "error", f"gửi tin lỗi: {m}"
    time.sleep(0.35)  # tránh chạm rate-limit chống spam của server
    return int(m.get("id") or m.get("message_id"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hold-seconds", type=int, default=60,
                    help="giữ kết nối mở sau khi sinh traffic (để chụp màn hình)")
    args = ap.parse_args()

    wait_ready(timeout=30.0)
    print("[traffic] server sẵn sàng, bắt đầu sinh traffic...", flush=True)

    names = ["alice", "bob", "carol", "dave", "erin"]
    users: list[ChatClient] = []
    for n in names:
        c = ChatClient()
        c.register_and_login(unique(n))
        users.append(c)
    print(f"[traffic] đã đăng nhập {len(users)} người dùng", flush=True)

    for i, j in [(0, 1), (0, 2), (1, 2), (3, 4), (0, 3)]:
        make_friends(users[i].sock, users[i].user_id, users[j].sock, users[j].user_id)
    print("[traffic] đã tạo 5 quan hệ bạn bè", flush=True)

    # DM A-B: trò chuyện hai chiều
    conv_ab = open_dm(users[0], users[1].user_id)
    last_mid = 0
    for k in range(5):
        last_mid = send_msg(users[0], conv_ab, unique("xin chào"))
        send_msg(users[1], conv_ab, unique("chào lại"))
    # sửa + xóa + thả cảm xúc trên tin gần nhất
    ws_send(users[1].sock, {"type": "add_reaction", "message_id": last_mid, "emoji": "👍"})
    recv_until(users[1].sock, lambda m: m.get("type") == "reaction_added", timeout=4.0)
    ws_send(users[0].sock, {"type": "edit_message", "message_id": last_mid,
                            "new_body": _fake_edit()})
    recv_until(users[0].sock,
               lambda m: m.get("type") == "message"
               and int(m.get("edit_target_message_id", 0) or 0) == last_mid,
               timeout=4.0)
    doomed = send_msg(users[0], conv_ab, unique("xóa thử"))
    ws_send(users[0].sock, {"type": "delete_message", "message_id": doomed})
    recv_until(users[0].sock, lambda m: m.get("type") == "message_deleted", timeout=4.0)

    # DM A-C
    conv_ac = open_dm(users[0], users[2].user_id)
    for k in range(5):
        send_msg(users[0], conv_ac, unique("tin nhắn"))

    print("[traffic] đã gửi/sửa/xóa tin DM + thả cảm xúc", flush=True)

    # Nhóm MLS
    g1 = create_group_mls(users[0], unique("Nhóm demo"), [users[1], users[2]])
    print(f"[traffic] đã tạo nhóm MLS #{g1}", flush=True)

    # Đọc inbox + tìm kiếm (sinh truy vấn DB)
    for c in users:
        ws_send(c.sock, {"type": "get_inbox"})
    for q in ("ali", "bo", "ca"):
        ws_send(users[0].sock, {"type": "search_user", "query": q})
        recv_until(users[0].sock, lambda m: m.get("type") == "search_result", timeout=4.0)
        time.sleep(1.05)

    m = get_metrics()
    print("[traffic] metrics hiện tại:", flush=True)
    print(f"  auth ok={m['auth']['ok']} registers={m['auth']['registers']}", flush=True)
    print(f"  messages sent={m['messages']['sent']} edited={m['messages']['edited']} "
          f"deleted={m['messages']['deleted']}", flush=True)
    print(f"  groups={m['groups']['created']} reactions={m['reactions']['added']}", flush=True)
    print(f"  ws_frames recv/sent={m['io']['ws_frames_recv']}/{m['io']['ws_frames_sent']}", flush=True)
    print(f"  db queries={m['database']['queries']} active conns={m['connections']['active']} "
          f"peak={m['connections']['peak']}", flush=True)

    print(f"[traffic] giữ {len(users)} kết nối mở trong {args.hold_seconds}s để chụp màn hình...",
          flush=True)
    time.sleep(args.hold_seconds)
    for c in users:
        c.close()
    print("[traffic] xong.", flush=True)
    return 0


def _fake_edit() -> str:
    from secchat_testlib import fake_S3DR
    return fake_S3DR(unique("đã sửa"))


if __name__ == "__main__":
    raise SystemExit(main())
