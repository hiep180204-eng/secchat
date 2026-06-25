from __future__ import annotations

import json
import os
import re
import shutil
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
FIGURE = ROOT / "Figure"
DIAGRAMS = ROOT / "diagrams"
EVIDENCE = ROOT / "out" / "evidence"
VISIBLE = ROOT.parent / "tests" / "artifacts" / "visible_manual_checklist" / "20260608_205331"

FIGURE.mkdir(exist_ok=True)
DIAGRAMS.mkdir(exist_ok=True)


FONT_CANDIDATES = [
    r"C:\Windows\Fonts\segoeui.ttf",
    r"C:\Windows\Fonts\arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]
BOLD_FONT_CANDIDATES = [
    r"C:\Windows\Fonts\segoeuib.ttf",
    r"C:\Windows\Fonts\arialbd.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
]


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    for path in (BOLD_FONT_CANDIDATES if bold else FONT_CANDIDATES):
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


F_TITLE = font(36, True)
F_H = font(24, True)
F = font(19)
F_SMALL = font(16)
F_TINY = font(14)

COL = {
    "bg": "#fbfcfe",
    "ink": "#18212f",
    "muted": "#5f6b7a",
    "line": "#5b6778",
    "blue": "#dbeafe",
    "blue_b": "#2563eb",
    "green": "#dcfce7",
    "green_b": "#16a34a",
    "yellow": "#fef3c7",
    "yellow_b": "#d97706",
    "red": "#fee2e2",
    "red_b": "#dc2626",
    "purple": "#ede9fe",
    "purple_b": "#7c3aed",
    "gray": "#f1f5f9",
    "gray_b": "#64748b",
}


def wrap(draw: ImageDraw.ImageDraw, text: str, max_width: int, fnt=F) -> list[str]:
    lines: list[str] = []
    for para in str(text).split("\n"):
        words = para.split()
        cur = ""
        for w in words:
            trial = w if not cur else cur + " " + w
            if draw.textbbox((0, 0), trial, font=fnt)[2] <= max_width:
                cur = trial
            else:
                if cur:
                    lines.append(cur)
                cur = w
        if cur:
            lines.append(cur)
    return lines or [""]


def text_center(draw, box, text, fnt=F, fill=None):
    fill = fill or COL["ink"]
    x1, y1, x2, y2 = box
    lines = wrap(draw, text, max(10, x2 - x1 - 20), fnt)
    lh = draw.textbbox((0, 0), "Ag", font=fnt)[3] + 5
    y = (y1 + y2) / 2 - lh * len(lines) / 2
    for line in lines:
        bb = draw.textbbox((0, 0), line, font=fnt)
        draw.text(((x1 + x2) / 2 - (bb[2] - bb[0]) / 2, y), line, font=fnt, fill=fill)
        y += lh


def title(draw, text, subtitle=None):
    draw.text((60, 38), text, font=F_TITLE, fill=COL["ink"])
    if subtitle:
        draw.text((62, 86), subtitle, font=F, fill=COL["muted"])


def arrow(draw, a, b, label="", color=None, width=3):
    color = color or COL["line"]
    x1, y1 = a
    x2, y2 = b
    draw.line((x1, y1, x2, y2), fill=color, width=width)
    import math

    ang = math.atan2(y2 - y1, x2 - x1)
    size = 12
    p1 = (x2, y2)
    p2 = (x2 - size * math.cos(ang - 0.45), y2 - size * math.sin(ang - 0.45))
    p3 = (x2 - size * math.cos(ang + 0.45), y2 - size * math.sin(ang + 0.45))
    draw.polygon([p1, p2, p3], fill=color)
    if label:
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        lines = wrap(draw, label, 180, F_TINY)
        w = max(draw.textbbox((0, 0), ln, font=F_TINY)[2] for ln in lines) + 20
        h = 22 * len(lines) + 8
        draw.rounded_rectangle((mx - w / 2, my - h / 2, mx + w / 2, my + h / 2), 8, fill="white", outline="#d7dee8")
        text_center(draw, (mx - w / 2, my - h / 2, mx + w / 2, my + h / 2), label, F_TINY, COL["muted"])


def edge_points(a_box, b_box):
    ax1, ay1, ax2, ay2 = a_box
    bx1, by1, bx2, by2 = b_box
    acx, acy = (ax1 + ax2) / 2, (ay1 + ay2) / 2
    bcx, bcy = (bx1 + bx2) / 2, (by1 + by2) / 2
    dx, dy = bcx - acx, bcy - acy
    if abs(dx) > abs(dy):
        start = (ax2 if dx > 0 else ax1, acy)
        end = (bx1 if dx > 0 else bx2, bcy)
    else:
        start = (acx, ay2 if dy > 0 else ay1)
        end = (bcx, by1 if dy > 0 else by2)
    return start, end


def rounded(draw, box, text, fill, outline, fnt=F, radius=14):
    draw.rounded_rectangle(box, radius, fill=fill, outline=outline, width=3)
    text_center(draw, box, text, fnt)


def ellipse(draw, box, text, fill=COL["blue"], outline=COL["blue_b"]):
    draw.ellipse(box, fill=fill, outline=outline, width=3)
    text_center(draw, box, text, F_SMALL)


def diamond(draw, cx, cy, w, h, text, fill=COL["yellow"], outline=COL["yellow_b"]):
    pts = [(cx, cy - h / 2), (cx + w / 2, cy), (cx, cy + h / 2), (cx - w / 2, cy)]
    draw.polygon(pts, fill=fill, outline=outline)
    draw.line(pts + [pts[0]], fill=outline, width=3)
    text_center(draw, (cx - w / 2 + 8, cy - h / 2 + 8, cx + w / 2 - 8, cy + h / 2 - 8), text, F_SMALL)


def actor(draw, x, y, name):
    draw.ellipse((x - 18, y, x + 18, y + 36), outline=COL["ink"], width=3)
    draw.line((x, y + 36, x, y + 102), fill=COL["ink"], width=3)
    draw.line((x - 45, y + 58, x + 45, y + 58), fill=COL["ink"], width=3)
    draw.line((x, y + 102, x - 42, y + 156), fill=COL["ink"], width=3)
    draw.line((x, y + 102, x + 42, y + 156), fill=COL["ink"], width=3)
    text_center(draw, (x - 110, y + 164, x + 110, y + 220), name, F_SMALL)


def save(img: Image.Image, name: str):
    img.save(FIGURE / name)


def write_mmd(name: str, content: str):
    (DIAGRAMS / f"{name}.mmd").write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def render_use_case():
    img = Image.new("RGB", (1900, 1220), COL["bg"])
    d = ImageDraw.Draw(img)
    title(d, "Sơ đồ use case tổng quan", "Các chức năng chính của SecChat và các tác nhân ngoài hệ thống")
    sys_box = (350, 145, 1535, 1110)
    d.rounded_rectangle(sys_box, 18, fill="#ffffff", outline="#b8c2d0", width=3)
    d.text((385, 165), "SecChat", font=F_H, fill=COL["ink"])
    actor(d, 170, 250, "Người dùng")
    actor(d, 170, 760, "Quản trị vận hành")
    actor(d, 1710, 280, "Chat server")
    actor(d, 1710, 760, "Auditor / database")
    cases = [
        (430, 230, "Đăng ký, đăng nhập"),
        (720, 230, "Quản lý hồ sơ và riêng tư"),
        (1010, 230, "Tìm kiếm, kết bạn, chặn"),
        (430, 430, "Mở DM và gửi tin E2EE"),
        (720, 430, "Thao tác tin nhắn, file"),
        (1010, 430, "Review identity DM"),
        (430, 650, "Tạo group MLS PQ"),
        (720, 650, "Thêm, xóa, đổi role"),
        (1010, 650, "Gửi tin group và system event"),
        (430, 870, "Cache và backup E2EE"),
        (720, 870, "Unread, scroll, history"),
        (1010, 870, "Health, metrics, audit"),
    ]

    # UML associations are drawn as plain lines. Use vertical buses so the
    # diagram remains readable when there are many use cases.
    user_bus_x = 365
    server_bus_x = 1520
    d.line((285, 360, user_bus_x, 360), fill=COL["line"], width=3)
    d.line((285, 865, user_bus_x, 865), fill=COL["line"], width=3)
    d.line((user_bus_x, 285, user_bus_x, 990), fill=COL["line"], width=3)
    for x, y, _ in cases[:11]:
        d.line((user_bus_x, y + 60, x, y + 60), fill=COL["line"], width=2)
    d.line((user_bus_x, 930, 1010, 930), fill=COL["line"], width=2)

    d.line((1590, 385, server_bus_x, 385), fill=COL["line"], width=3)
    d.line((1590, 865, server_bus_x, 865), fill=COL["line"], width=3)
    d.line((server_bus_x, 285, server_bus_x, 990), fill=COL["line"], width=3)
    for idx in [3, 4, 6, 7, 8, 10, 11]:
        x, y, _ = cases[idx]
        d.line((x + 230, y + 60, server_bus_x, y + 60), fill=COL["line"], width=2)
    for idx in [5, 11]:
        x, y, _ = cases[idx]
        d.line((x + 230, y + 60, server_bus_x, y + 60), fill=COL["line"], width=2)

    for x, y, txt in cases:
        ellipse(d, (x, y, x + 230, y + 120), txt)
    write_mmd(
        "UseCaseDiagram",
        """
        flowchart LR
          U([Người dùng]) --- A((Đăng ký, đăng nhập))
          U --- B((Quản lý hồ sơ và riêng tư))
          U --- C((Tìm kiếm, kết bạn, chặn))
          U --- D((Mở DM và gửi tin E2EE))
          U --- E((Thao tác tin nhắn, file))
          U --- F((Review identity DM))
          U --- G((Tạo group MLS PQ))
          U --- H((Thêm, xóa, đổi role))
          U --- I((Gửi tin group và system event))
          U --- J((Cache và backup E2EE))
          U --- K((Unread, scroll, history))
          O([Quản trị vận hành]) --- L((Health, metrics, audit))
          S([Chat server]) --- D
          S --- G
          S --- H
          ADB([Auditor / database]) --- F
          ADB --- L
        """,
    )
    save(img, "UseCaseDiagram.png")


def render_activity(name: str, heading: str, steps: list[tuple[str, str]], decisions: set[int] | None = None):
    decisions = decisions or set()
    img = Image.new("RGB", (1500, 1120), COL["bg"])
    d = ImageDraw.Draw(img)
    title(d, heading)
    lane_w = 430
    lanes = ["Người dùng", "Client", "Server / crypto"]
    for i, lane in enumerate(lanes):
        x1 = 65 + i * lane_w
        d.rounded_rectangle((x1, 140, x1 + lane_w - 25, 1040), 10, fill="#ffffff", outline="#d7dee8", width=2)
        d.text((x1 + 20, 160), lane, font=F_H, fill=COL["muted"])
    last_box = None
    for idx, (lane, text) in enumerate(steps):
        li = lanes.index(lane)
        x = 95 + li * lane_w
        y = 230 + idx * 95
        if idx in decisions:
            cur_box = (x + 185 - 145, y + 40 - 45, x + 185 + 145, y + 40 + 45)
            diamond(d, x + 185, y + 40, 290, 90, text)
        else:
            cur_box = (x, y, x + 370, y + 76)
            rounded(d, cur_box, text, COL["gray"], COL["gray_b"], F_SMALL, radius=18)
        if last_box:
            start, end = edge_points(last_box, cur_box)
            arrow(d, start, end)
        last_box = cur_box
    write_mmd(
        name,
        "flowchart TD\n" + "\n".join(f"  S{i}[{txt}]" + (f" --> S{i+1}" if i < len(steps) - 1 else "") for i, (_, txt) in enumerate(steps)),
    )
    save(img, f"{name}.png")


def render_activities():
    render_activity(
        "ActivityAuthDm",
        "Sơ đồ hoạt động đăng nhập, công bố khóa và gửi DM",
        [
            ("Người dùng", "Nhập email và mật khẩu"),
            ("Client", "Mở local state bằng master key"),
            ("Client", "Sinh hoặc nạp identity, prekey, MLS KeyPackage"),
            ("Server / crypto", "Lưu public bundle và kiểm tra chữ ký"),
            ("Người dùng", "Chọn bạn và mở DM"),
            ("Client", "Lấy bundle của peer"),
            ("Client", "Chạy PQXDH hybrid"),
            ("Client", "Mã hóa tin bằng Double Ratchet"),
            ("Server / crypto", "Lưu và chuyển tiếp ciphertext"),
            ("Client", "Peer giải mã và cập nhật ratchet"),
        ],
    )
    render_activity(
        "ActivityGroupMembership",
        "Sơ đồ hoạt động quản lý thành viên group",
        [
            ("Người dùng", "Admin chọn thao tác group"),
            ("Client", "Chuẩn bị Commit và GroupInfo bằng OpenMLS"),
            ("Server / crypto", "Validate PublicGroup, epoch, actor, member set"),
            ("Server / crypto", "Commit hợp lệ?"),
            ("Server / crypto", "Mutate membership và lưu public state"),
            ("Server / crypto", "Ghi system event có after_message_id"),
            ("Client", "Nhận event live hoặc tải history"),
            ("Client", "Merge event đúng vị trí timeline"),
        ],
        decisions={3},
    )
    render_activity(
        "ActivityBackupRestore",
        "Sơ đồ hoạt động backup và restore E2EE",
        [
            ("Người dùng", "Chọn export backup"),
            ("Client", "Thu thập local state và cache theo policy"),
            ("Client", "Mã hóa backup bằng passphrase riêng"),
            ("Người dùng", "Chuyển file sang VNC khác"),
            ("Client", "Nhập passphrase restore"),
            ("Client", "Re-wrap bằng master key hiện tại"),
            ("Server / crypto", "Công bố bundle và KeyPackage mới"),
            ("Client", "Mở lại lịch sử đọc được từ cache/state"),
        ],
    )


def render_erd():
    img = Image.new("RGB", (2100, 1450), COL["bg"])
    d = ImageDraw.Draw(img)
    title(d, "ERD hệ thống SecChat", "Các thực thể chính trong database vận hành E2EE")
    entities = {
        "users": (80, 170, ["id PK", "username", "email", "password_hash", "identity_pk_b64"]),
        "friendships": (430, 170, ["id PK", "requester_id FK", "addressee_id FK", "status"]),
        "user_blocks": (780, 170, ["blocker_id FK", "blocked_id FK"]),
        "conversations": (1130, 170, ["id PK", "type", "name", "creator_id", "created_at"]),
        "conversation_members": (1480, 170, ["conversation_id FK", "user_id FK", "role", "last_read_message_id", "force_unread"]),
        "messages": (1130, 520, ["id PK", "conversation_id FK", "sender_id FK", "body ciphertext", "reply_to_id", "edit_target_message_id"]),
        "message_reactions": (1480, 520, ["message_id FK", "user_id FK", "emoji"]),
        "pinned_messages": (780, 520, ["conversation_id FK", "message_id FK", "user_id FK"]),
        "pqxdh_bundles": (80, 520, ["user_id FK", "identity_key", "signed_prekey", "pq_signed_prekey", "signature"]),
        "mls_key_packages": (430, 520, ["id PK", "user_id FK", "key_package_b64", "ciphersuite", "signature"]),
        "mls_group_state": (430, 890, ["conversation_id FK", "ciphersuite", "public_state_b64", "public_state_hash", "validated_at"]),
        "mls_group_handshake": (780, 890, ["conversation_id FK", "epoch", "commit_b64", "welcome_b64", "group_info_b64"]),
        "group_system_events": (1130, 890, ["id PK", "conversation_id FK", "event_type", "actor_id", "target_user_id", "after_message_id"]),
        "identity_key_log": (80, 890, ["id PK", "user_id FK", "identity_pk", "version", "created_at"]),
        "notification_queue": (1480, 890, ["id PK", "user_id FK", "event_type", "payload_json"]),
    }
    centers = {}
    for name, (x, y, fields) in entities.items():
        w, h = 300, 210
        d.rounded_rectangle((x, y, x + w, y + h), 8, fill="#ffffff", outline=COL["green_b"], width=3)
        d.rectangle((x, y, x + w, y + 42), fill=COL["green"], outline=COL["green_b"], width=0)
        text_center(d, (x, y, x + w, y + 42), name, F_H)
        yy = y + 55
        for f in fields:
            d.text((x + 14, yy), f, font=F_TINY, fill=COL["ink"])
            yy += 26
        centers[name] = (x + w / 2, y + h / 2)
    rels = [
        ("users", "friendships", "1 - n"),
        ("users", "user_blocks", "1 - n"),
        ("users", "conversation_members", "1 - n"),
        ("conversations", "conversation_members", "1 - n"),
        ("conversations", "messages", "1 - n"),
        ("messages", "message_reactions", "1 - n"),
        ("messages", "pinned_messages", "1 - n"),
        ("users", "pqxdh_bundles", "1 - n"),
        ("users", "mls_key_packages", "1 - n"),
        ("conversations", "mls_group_state", "1 - 1"),
        ("conversations", "mls_group_handshake", "1 - n"),
        ("conversations", "group_system_events", "1 - n"),
        ("users", "identity_key_log", "1 - n"),
        ("users", "notification_queue", "1 - n"),
        ("messages", "group_system_events", "anchor"),
    ]
    for a, b, label in rels:
        arrow(d, centers[a], centers[b], label, COL["gray_b"], width=2)
    write_mmd(
        "ERDDetail",
        """
        erDiagram
          users ||--o{ friendships : participates
          users ||--o{ user_blocks : blocks
          users ||--o{ conversation_members : joins
          conversations ||--o{ conversation_members : has
          conversations ||--o{ messages : stores
          messages ||--o{ message_reactions : has
          messages ||--o{ pinned_messages : pinned
          users ||--o{ pqxdh_bundles : publishes
          users ||--o{ mls_key_packages : publishes
          conversations ||--|| mls_group_state : has
          conversations ||--o{ mls_group_handshake : records
          conversations ||--o{ group_system_events : records
          messages ||--o{ group_system_events : anchors
          users ||--o{ identity_key_log : appends
          users ||--o{ notification_queue : receives
        """,
    )
    save(img, "ERDDetail.png")


def render_class_diagram():
    img = Image.new("RGB", (2100, 1320), COL["bg"])
    d = ImageDraw.Draw(img)
    title(d, "Sơ đồ cấu trúc đối tượng", "Các lớp chính ở client, crypto engine, server và auditor")
    classes = {
        "App": (70, 170, ["ws: WSNet", "crypto: CryptoSession", "chat: ChatPage"], ["handle_event()", "send_command()", "publish_keys()"], COL["blue"], COL["blue_b"]),
        "ChatPage": (430, 170, ["active_conversation", "sidebar models", "timeline"], ["render_history()", "merge_system_events()", "show_popover()"], COL["blue"], COL["blue_b"]),
        "WSNet": (790, 170, ["socket", "queue"], ["connect()", "send_json()", "dispatch()"], COL["blue"], COL["blue_b"]),
        "CryptoSession": (1150, 170, ["identity", "ratchets", "mls states"], ["encrypt_dm()", "decrypt()", "backup_restore()"], COL["yellow"], COL["yellow_b"]),
        "DoubleRatchet": (1510, 170, ["root_key", "chain_key", "message_numbers"], ["next_send_key()", "try_skipped_key()", "reject_replay()"], COL["yellow"], COL["yellow_b"]),
        "MlsBridge": (1510, 500, ["OpenMLS state", "X-Wing ciphersuite"], ["create_group()", "process_commit()", "selftest()"], COL["yellow"], COL["yellow_b"]),
        "ClientHandler": (70, 500, ["Client socket", "CallerContext"], ["read_frame()", "route_command()", "send_event()"], COL["red"], COL["red_b"]),
        "AuthService": (430, 500, ["UserRepo", "KeyRepo"], ["register()", "login()", "upload_keys()"], COL["red"], COL["red_b"]),
        "MessagingService": (790, 500, ["MessageRepo", "ConversationRepo"], ["send_message()", "history()", "mark_read()"], COL["red"], COL["red_b"]),
        "GroupService": (1150, 500, ["MLS validator", "Group repos"], ["prepare_change()", "apply_change()", "write_system_event()"], COL["red"], COL["red_b"]),
        "Repository": (430, 830, ["MySQL connection pool"], ["prepared_query()", "retry_lost_connection()"], COL["green"], COL["green_b"]),
        "AuditorService": (790, 830, ["identity log", "Merkle tree"], ["checkpoint()", "inclusion_proof()", "verify_request()"], COL["purple"], COL["purple_b"]),
        "MlsValidator": (1150, 830, ["PublicGroup state"], ["validate_create()", "validate_commit()", "export_public_state()"], COL["purple"], COL["purple_b"]),
    }

    def cls(name, x, y, attrs, methods, fill, outline):
        w, h = 310, 250
        d.rounded_rectangle((x, y, x + w, y + h), 8, fill="#ffffff", outline=outline, width=3)
        d.rectangle((x, y, x + w, y + 45), fill=fill, outline=outline)
        text_center(d, (x, y, x + w, y + 45), name, F_H)
        d.line((x, y + 130, x + w, y + 130), fill=outline, width=2)
        yy = y + 58
        for a in attrs:
            d.text((x + 12, yy), "+ " + a, font=F_TINY, fill=COL["ink"])
            yy += 22
        yy = y + 142
        for m in methods:
            d.text((x + 12, yy), "+ " + m, font=F_TINY, fill=COL["ink"])
            yy += 22
        return (x + w / 2, y + h / 2)

    centers = {n: cls(n, x, y, attrs, methods, fill, outline) for n, (x, y, attrs, methods, fill, outline) in classes.items()}
    for a, b, lab in [
        ("App", "ChatPage", "owns"),
        ("App", "WSNet", "uses"),
        ("App", "CryptoSession", "uses"),
        ("CryptoSession", "DoubleRatchet", "DM"),
        ("CryptoSession", "MlsBridge", "group"),
        ("ClientHandler", "AuthService", "routes"),
        ("ClientHandler", "MessagingService", "routes"),
        ("ClientHandler", "GroupService", "routes"),
        ("AuthService", "Repository", "persists"),
        ("MessagingService", "Repository", "persists"),
        ("GroupService", "Repository", "persists"),
        ("GroupService", "MlsValidator", "validates"),
        ("AuditorService", "Repository", "reads log"),
    ]:
        arrow(d, centers[a], centers[b], lab, COL["gray_b"], 2)
    write_mmd(
        "ClassDiagramDetail",
        """
        classDiagram
          App --> ChatPage
          App --> WSNet
          App --> CryptoSession
          CryptoSession --> DoubleRatchet
          CryptoSession --> MlsBridge
          ClientHandler --> AuthService
          ClientHandler --> MessagingService
          ClientHandler --> GroupService
          AuthService --> Repository
          MessagingService --> Repository
          GroupService --> Repository
          GroupService --> MlsValidator
          AuditorService --> Repository
        """,
    )
    save(img, "ClassDiagramDetail.png")


def render_sequence(name: str, heading: str, participants: list[str], messages: list[tuple[int, int, str]]):
    img = Image.new("RGB", (1900, 1100), COL["bg"])
    d = ImageDraw.Draw(img)
    title(d, heading)
    x0, spacing = 130, 320
    xs = [x0 + i * spacing for i in range(len(participants))]
    for x, p in zip(xs, participants):
        rounded(d, (x - 115, 150, x + 115, 215), p, "#ffffff", COL["gray_b"], F_SMALL, 10)
        d.line((x, 215, x, 1010), fill="#c8d1dc", width=3)
    y = 270
    for src, dst, msg in messages:
        x1, x2 = xs[src], xs[dst]
        arrow(d, (x1, y), (x2, y), msg, COL["line"], 2)
        y += 78
    mmd_lines = ["sequenceDiagram"]
    aliases = [re.sub(r"[^A-Za-z0-9]", "", p)[:12] or f"P{i}" for i, p in enumerate(participants)]
    for a, p in zip(aliases, participants):
        mmd_lines.append(f"  participant {a} as {p}")
    for s, t, msg in messages:
        mmd_lines.append(f"  {aliases[s]}->>{aliases[t]}: {msg}")
    write_mmd(name, "\n".join(mmd_lines))
    save(img, f"{name}.png")


def render_sequences():
    render_sequence(
        "SequenceLoginKeyPublish",
        "Sơ đồ tuần tự đăng nhập và công bố khóa",
        ["Người dùng", "Client", "Server", "Database", "Auditor"],
        [
            (0, 1, "Nhập email, mật khẩu"),
            (1, 2, "auth password hash"),
            (2, 3, "kiểm tra tài khoản"),
            (2, 1, "auth ok, user id"),
            (1, 1, "mở local state bằng master key"),
            (1, 2, "upload PQXDH bundle"),
            (1, 2, "upload MLS KeyPackage X-Wing"),
            (2, 3, "lưu public material"),
            (2, 4, "append identity log"),
            (4, 1, "checkpoint / proof"),
        ],
    )
    render_sequence(
        "SequenceDmE2ee",
        "Sơ đồ tuần tự gửi DM E2EE",
        ["Client A", "Server", "Database", "Client B"],
        [
            (0, 1, "get_pqxdh_bundle(B)"),
            (1, 2, "claim one-time prekey"),
            (1, 0, "bundle + identity proof"),
            (0, 0, "PQXDH hybrid, tạo root secret"),
            (0, 0, "Double Ratchet encrypt"),
            (0, 1, "message S3PQI/S3DR"),
            (1, 2, "store ciphertext"),
            (1, 3, "broadcast ciphertext"),
            (3, 3, "decrypt, ratchet forward"),
            (3, 1, "mark_read last_message_id"),
        ],
    )
    render_sequence(
        "SequenceGroupMlsValidation",
        "Sơ đồ tuần tự thay đổi group bằng MLS PQ",
        ["Admin client", "OpenMLS bridge", "Server", "MLS validator", "Database", "Member clients"],
        [
            (0, 1, "create Commit / Welcome / GroupInfo"),
            (1, 0, "artifact X-Wing"),
            (0, 2, "apply_group_change"),
            (2, 3, "validate PublicGroup"),
            (3, 2, "epoch, actor, member set ok"),
            (2, 4, "mutate membership"),
            (2, 4, "store public_state and handshake"),
            (2, 4, "insert group_system_event"),
            (2, 5, "broadcast commit/event"),
            (5, 1, "process commit/welcome"),
        ],
    )
    render_sequence(
        "SequenceHistoryReadSystemEvents",
        "Sơ đồ tuần tự tải history, read cursor và system event",
        ["Client", "Server", "messages", "group_system_events", "conversation_members"],
        [
            (0, 1, "history(conversation_id)"),
            (1, 2, "fetch visible ciphertext"),
            (1, 3, "fetch events by after_message_id"),
            (1, 0, "messages + system_events"),
            (0, 0, "merge timeline, giữ scroll"),
            (0, 1, "mark_read(last_message_id)"),
            (1, 4, "update last_read_message_id"),
            (1, 0, "inbox unread normalized"),
        ],
    )
    render_sequence(
        "SequenceBackupRestore",
        "Sơ đồ tuần tự backup và restore E2EE",
        ["Client cũ", "Backup file", "Client mới", "Server"],
        [
            (0, 0, "thu local state và cache theo policy"),
            (0, 1, "encrypt bằng passphrase"),
            (1, 2, "người dùng chọn restore"),
            (2, 2, "decrypt backup, re-wrap master key"),
            (2, 3, "upload fresh PQXDH bundle"),
            (2, 3, "upload fresh MLS KeyPackage"),
            (3, 2, "auth/session ok"),
            (2, 2, "hiển thị history đọc được"),
        ],
    )
    render_sequence(
        "SequenceIdentityAudit",
        "Sơ đồ tuần tự kiểm tra identity",
        ["Client A", "Server", "Database", "Auditor", "Client UI"],
        [
            (0, 1, "request peer identity version"),
            (1, 2, "read identity_key_log"),
            (1, 3, "request inclusion proof"),
            (3, 1, "Merkle proof + checkpoint"),
            (1, 0, "identity bundle + proof"),
            (0, 0, "verify signature/proof"),
            (0, 4, "show safety code / warning"),
            (4, 0, "mark reviewed if user confirms"),
        ],
    )


def render_deployment():
    img = Image.new("RGB", (1700, 1000), COL["bg"])
    d = ImageDraw.Draw(img)
    title(d, "Mô hình triển khai Docker", "Môi trường chạy sản phẩm và kiểm thử visible")
    nodes = [
        (90, 240, "client1 VNC\nPyQt5 + crypto engine", COL["blue"], COL["blue_b"]),
        (90, 560, "client2 VNC\nPyQt5 + crypto engine", COL["blue"], COL["blue_b"]),
        (610, 250, "chat-server\nC WebSocket + HTTP", COL["red"], COL["red_b"]),
        (610, 590, "auditor\nMerkle checkpoint", COL["purple"], COL["purple_b"]),
        (1120, 250, "MySQL 8.0\nschema + ciphertext", COL["green"], COL["green_b"]),
        (1120, 590, "secchat_mls_bridge\nOpenMLS X-Wing", COL["yellow"], COL["yellow_b"]),
    ]
    centers = []
    for x, y, txt, fill, border in nodes:
        rounded(d, (x, y, x + 360, y + 180), txt, fill, border, F_H)
        centers.append((x + 180, y + 90))
    for a, b, lab in [(0, 2, "TLS WebSocket"), (1, 2, "TLS WebSocket"), (2, 4, "SQL"), (2, 5, "validator CLI"), (2, 3, "identity log"), (3, 4, "read log")]:
        arrow(d, centers[a], centers[b], lab)
    write_mmd(
        "DeploymentRuntime",
        """
        flowchart LR
          C1[client1 VNC] -->|TLS WebSocket| S[chat-server]
          C2[client2 VNC] -->|TLS WebSocket| S
          S -->|SQL| DB[(MySQL)]
          S -->|validator CLI| MLS[secchat_mls_bridge]
          S -->|identity log| A[auditor]
          A -->|read log| DB
        """,
    )
    save(img, "DeploymentRuntime.png")


def copy_visible_screenshots():
    mapping = {
        "chat-client1_02_demo_login.png": "ui_login_demo.png",
        "chat-client1_03_friend_full.png": "ui_friend_list.png",
        "chat-client1_04_dm_two_way.png": "ui_dm_current.png",
        "chat-client1_06_verify_short_code.png": "ui_identity_review.png",
        "chat-client1_07_group_123_234.png": "ui_group_current.png",
        "chat-client1_08_message_actions.png": "ui_message_actions_current.png",
        "chat-client1_09_file_attachment.png": "ui_file_attachment_current.png",
        "chat-client1_10_group_add_role_kick_345.png": "ui_group_membership_current.png",
        "chat-client1_12_backup_rotate_restore.png": "ui_profile_backup_current.png",
        "chat-client1_13_final_core.png": "ui_final_core_current.png",
    }
    for src, dst in mapping.items():
        p = VISIBLE / src
        if p.exists():
            shutil.copyfile(p, FIGURE / dst)


def extract_summary_lines(path: Path, patterns: list[str], max_lines: int = 10) -> list[str]:
    if not path.exists():
        return [f"Không tìm thấy log: {path.name}"]
    text = ""
    for enc in ("utf-8", "utf-16", "utf-16-le", "cp1258", "cp1252"):
        try:
            candidate = path.read_text(encoding=enc, errors="strict")
        except UnicodeError:
            continue
        if candidate.count("\x00") < 10:
            text = candidate
            break
    if not text:
        text = path.read_text(encoding="utf-8", errors="replace")
    lines = []
    for line in text.splitlines():
        if any(p in line for p in patterns):
            clean = re.sub(r"\s+", " ", line).strip()
            if clean.startswith("# "):
                continue
            if clean and clean not in lines:
                lines.append(clean)
        if len(lines) >= max_lines:
            break
    return lines or ["Log không có dòng khớp mẫu, xem file evidence để đối chiếu."]


def render_log_card(name: str, heading: str, subtitle: str, lines: list[str]):
    img = Image.new("RGB", (1500, 900), "#ffffff")
    d = ImageDraw.Draw(img)
    d.rectangle((0, 0, 1500, 900), fill=COL["bg"])
    d.rounded_rectangle((55, 55, 1445, 845), 18, fill="#ffffff", outline="#cbd5e1", width=3)
    d.text((100, 95), heading, font=F_TITLE, fill=COL["ink"])
    d.text((102, 148), subtitle, font=F, fill=COL["muted"])
    y = 220
    for ln in lines:
        d.rounded_rectangle((100, y, 1400, y + 72), 10, fill=COL["gray"], outline="#d7dee8")
        d.text((122, y + 22), "OK", font=F_H, fill=COL["green_b"])
        text_center(d, (165, y + 6, 1380, y + 66), ln, F_SMALL, COL["ink"])
        y += 90
        if y > 770:
            break
    save(img, name)


def render_evidence_cards():
    render_log_card(
        "audit_host_tests.png",
        "Kết quả test tự động",
        "Nguồn: report/out/evidence/host_tests_final_pass.txt",
        extract_summary_lines(EVIDENCE / "host_tests_final_pass.txt", ["24/24 passed", "0 failed", "tests/test_secure_protocol_server.py", "tests/test_client_ui_interactions.py"], 8),
    )
    render_log_card(
        "audit_visible_checklist.png",
        "Kết quả visible manual checklist",
        "Nguồn: report/out/evidence/visible_manual_checklist_final.txt",
        extract_summary_lines(EVIDENCE / "visible_manual_checklist_final.txt", ["Ran 2 tests", "OK", "CHECKLIST", "PASS"], 8),
    )
    render_log_card(
        "audit_openmls_selftest.png",
        "Kết quả OpenMLS X-Wing selftest",
        "Nguồn: report/out/evidence/openmls_selftest_final.txt",
        extract_summary_lines(EVIDENCE / "openmls_selftest_final.txt", ["ciphersuite", "pq_hybrid", "validator_create_ok", "validator_remove_ok", "bob_active_after_remove"], 8),
    )
    render_log_card(
        "audit_server_c.png",
        "Kết quả kiểm toán C server",
        "Nguồn: report/out/evidence/server_c_audit_final_pass.txt",
        extract_summary_lines(EVIDENCE / "server_c_audit_final_pass.txt", ["SecChat C server security audit helper", "Results: 75 passed", "Done 10000 runs", "cppcheck", "error"], 8),
    )


def main():
    render_use_case()
    render_activities()
    render_erd()
    render_class_diagram()
    render_sequences()
    render_deployment()
    copy_visible_screenshots()
    render_evidence_cards()


if __name__ == "__main__":
    main()
