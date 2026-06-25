from __future__ import annotations

import math
import os
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
FIGURE_DIR = ROOT / "Figure"
DIAGRAM_DIR = ROOT / "diagrams"


COLORS = {
    "bg": "#fbfcfe",
    "ink": "#18212f",
    "muted": "#5f6b7a",
    "line": "#718096",
    "client": "#dbeafe",
    "client_border": "#2563eb",
    "crypto": "#fef3c7",
    "crypto_border": "#d97706",
    "server": "#fee2e2",
    "server_border": "#dc2626",
    "db": "#dcfce7",
    "db_border": "#16a34a",
    "network": "#ede9fe",
    "network_border": "#7c3aed",
    "neutral": "#f1f5f9",
    "neutral_border": "#64748b",
    "risk": "#ffe4e6",
    "risk_border": "#e11d48",
}


FONT_CANDIDATES = [
    r"C:\Windows\Fonts\arial.ttf",
    r"C:\Windows\Fonts\segoeui.ttf",
    r"C:\Windows\Fonts\calibri.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]

BOLD_FONT_CANDIDATES = [
    r"C:\Windows\Fonts\arialbd.ttf",
    r"C:\Windows\Fonts\segoeuib.ttf",
    r"C:\Windows\Fonts\calibrib.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
]


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = BOLD_FONT_CANDIDATES if bold else FONT_CANDIDATES
    for path in candidates:
        if os.path.exists(path):
            return ImageFont.truetype(path, size=size)
    return ImageFont.load_default()


TITLE_FONT = _font(38, True)
SUBTITLE_FONT = _font(24, False)
NODE_FONT = _font(23, True)
TEXT_FONT = _font(20, False)
SMALL_FONT = _font(17, False)


def wrap_text(draw: ImageDraw.ImageDraw, text: str, font, max_width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        trial = word if not current else current + " " + word
        if draw.textbbox((0, 0), trial, font=font)[2] <= max_width:
            current = trial
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def draw_wrapped_text(draw, xy, text, font, fill, max_width, line_gap=5, anchor="mm"):
    lines = []
    for para in text.split("\n"):
        if not para.strip():
            lines.append("")
        else:
            lines.extend(wrap_text(draw, para.strip(), font, max_width))
    line_h = draw.textbbox((0, 0), "Ag", font=font)[3] + line_gap
    total_h = line_h * len(lines) - line_gap
    x, y = xy
    if anchor == "mm":
        y0 = y - total_h / 2
    elif anchor == "ma":
        y0 = y
    else:
        y0 = y
    for line in lines:
        bbox = draw.textbbox((0, 0), line, font=font)
        draw.text((x - (bbox[2] - bbox[0]) / 2, y0), line, font=font, fill=fill)
        y0 += line_h


@dataclass
class Node:
    id: str
    x: int
    y: int
    w: int
    h: int
    title: str
    body: str = ""
    style: str = "neutral"

    @property
    def center(self):
        return (self.x + self.w / 2, self.y + self.h / 2)


@dataclass
class Arrow:
    a: str
    b: str
    label: str = ""
    dashed: bool = False


def draw_arrow(draw, start, end, color, width=3, dashed=False):
    x1, y1 = start
    x2, y2 = end
    if dashed:
        steps = max(8, int(math.hypot(x2 - x1, y2 - y1) / 22))
        for i in range(steps):
            if i % 2 == 0:
                t1 = i / steps
                t2 = (i + 1) / steps
                draw.line((x1 + (x2 - x1) * t1, y1 + (y2 - y1) * t1,
                           x1 + (x2 - x1) * t2, y1 + (y2 - y1) * t2),
                          fill=color, width=width)
    else:
        draw.line((x1, y1, x2, y2), fill=color, width=width)
    angle = math.atan2(y2 - y1, x2 - x1)
    size = 13
    p1 = (x2, y2)
    p2 = (x2 - size * math.cos(angle - math.pi / 7),
          y2 - size * math.sin(angle - math.pi / 7))
    p3 = (x2 - size * math.cos(angle + math.pi / 7),
          y2 - size * math.sin(angle + math.pi / 7))
    draw.polygon([p1, p2, p3], fill=color)


def edge_points(a: Node, b: Node):
    ax, ay = a.center
    bx, by = b.center
    dx, dy = bx - ax, by - ay
    if abs(dx) / max(a.w, 1) > abs(dy) / max(a.h, 1):
        sx = a.x + a.w if dx > 0 else a.x
        sy = ay
        ex = b.x if dx > 0 else b.x + b.w
        ey = by
    else:
        sx = ax
        sy = a.y + a.h if dy > 0 else a.y
        ex = bx
        ey = b.y if dy > 0 else b.y + b.h
    return (sx, sy), (ex, ey)


def render_diagram(filename: str, title: str, subtitle: str,
                   nodes: list[Node], arrows: list[Arrow],
                   size=(1800, 1120)) -> None:
    img = Image.new("RGB", size, COLORS["bg"])
    draw = ImageDraw.Draw(img)

    draw.text((70, 46), title, font=TITLE_FONT, fill=COLORS["ink"])
    if subtitle:
        draw.text((72, 94), subtitle, font=SUBTITLE_FONT, fill=COLORS["muted"])

    node_map = {n.id: n for n in nodes}
    for ar in arrows:
        a, b = node_map[ar.a], node_map[ar.b]
        start, end = edge_points(a, b)
        draw_arrow(draw, start, end, COLORS["line"], dashed=ar.dashed)
        if ar.label:
            lx = (start[0] + end[0]) / 2
            ly = (start[1] + end[1]) / 2 - 18
            lines = wrap_text(draw, ar.label, SMALL_FONT, 230)
            text_h = 22 * len(lines) + 10
            text_w = min(260, max(draw.textbbox((0, 0), ln, font=SMALL_FONT)[2] for ln in lines) + 26)
            draw.rounded_rectangle(
                (lx - text_w / 2, ly - text_h / 2, lx + text_w / 2, ly + text_h / 2),
                radius=12, fill="#ffffff", outline="#d5dce8", width=1,
            )
            draw_wrapped_text(draw, (lx, ly - text_h / 2 + 8), ar.label,
                              SMALL_FONT, COLORS["muted"], text_w - 24, anchor="ma")

    for n in nodes:
        fill = COLORS.get(n.style, COLORS["neutral"])
        border = COLORS.get(n.style + "_border", COLORS["neutral_border"])
        draw.rounded_rectangle(
            (n.x, n.y, n.x + n.w, n.y + n.h),
            radius=18, fill=fill, outline=border, width=3,
        )
        draw_wrapped_text(draw, (n.x + n.w / 2, n.y + 22), n.title,
                          NODE_FONT, COLORS["ink"], n.w - 36, anchor="ma")
        if n.body:
            draw_wrapped_text(draw, (n.x + n.w / 2, n.y + 72), n.body,
                              TEXT_FONT, COLORS["ink"], n.w - 42, anchor="ma")

    out = FIGURE_DIR / filename
    img.save(out)


def write_mmd(name: str, content: str) -> None:
    (DIAGRAM_DIR / f"{name}.mmd").write_text(content.strip() + "\n", encoding="utf-8")


def build() -> None:
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    DIAGRAM_DIR.mkdir(parents=True, exist_ok=True)

    diagrams = []

    diagrams.append((
        "Architecture.png",
        "Kiến trúc tổng thể SecChat",
        "Client giữ plaintext và khóa; server điều phối quyền, validate public MLS state và chuyển tiếp ciphertext.",
        [
            Node("user", 80, 250, 310, 150, "Người dùng", "Nhập mật khẩu, đọc và gửi tin nhắn", "neutral"),
            Node("client", 500, 200, 360, 220, "Client PyQt", "UI chat, profile, group, pin, reaction", "client"),
            Node("crypto", 500, 560, 360, 230, "CryptoSession", "Master key, PQXDH, Double Ratchet, MLS group, cache mã hóa", "crypto"),
            Node("local", 80, 610, 310, 170, "Local encrypted state", "identity key, prekey, ratchet, group state, cache", "crypto"),
            Node("tls", 960, 310, 260, 160, "TLS + WebSocket", "JSON event và ciphertext đi qua kênh TLS", "network"),
            Node("server", 1370, 200, 330, 220, "Server C", "auth, services, MLS validator, repository, metrics", "server"),
            Node("db", 1370, 560, 330, 210, "MySQL", "users, messages, prekey bundle, MLS public state, metadata", "db"),
            Node("auditor", 940, 680, 330, 180, "Auditor service", "đọc identity_key_log, ký checkpoint, trả Merkle proof", "network"),
        ],
        [
            Arrow("user", "client", "thao tác UI"),
            Arrow("client", "crypto", "mã hóa / giải mã"),
            Arrow("crypto", "local", "lưu state đã mã hóa"),
            Arrow("client", "tls", ""),
            Arrow("tls", "server", ""),
            Arrow("server", "db", "SQL metadata + ciphertext"),
            Arrow("server", "tls", ""),
            Arrow("db", "auditor", "identity log", dashed=True),
            Arrow("crypto", "auditor", "audit proof", dashed=True),
        ],
        """
        flowchart LR
          U[Người dùng] --> C[Client PyQt]
          C --> CE[CryptoSession]
          CE --> LS[Local encrypted state]
          C --> TLS[TLS + WebSocket]
          TLS --> S[Server C]
          S --> DB[(MySQL + MLS public state)]
          DB --> A[Auditor service]
          C -. audit proof .-> A
          S --> TLS
        """,
    ))

    diagrams.append((
        "TrustBoundary.png",
        "Ranh giới tin cậy",
        "E2EE bảo vệ nội dung; public MLS state giúp server kiểm tra membership mà không có group secret.",
        [
            Node("client", 90, 230, 430, 250, "Vùng client được tin cậy", "Plaintext, master key, ratchet state, group state", "client"),
            Node("local", 90, 585, 430, 190, "Ổ đĩa người dùng", "Dữ liệu nhạy cảm được mã hóa bằng master key", "crypto"),
            Node("net", 690, 270, 300, 170, "Mạng", "TLS che JSON khỏi người nghe lén trên đường truyền", "network"),
            Node("server", 1160, 170, 500, 220, "Server không được tin cậy với nội dung", "auth, quyền group, PublicGroup validation, thứ tự message, metrics", "server"),
            Node("db", 1160, 470, 500, 200, "Database có thể bị lộ", "ciphertext, metadata và public MLS state; không có application secret", "db"),
            Node("auditor", 1160, 760, 500, 170, "Auditor giảm rủi ro key substitution", "kiểm tra identity history, không che metadata và không giải mã nội dung", "network"),
        ],
        [
            Arrow("client", "net", "TLS"),
            Arrow("net", "server", ""),
            Arrow("server", "db", "metadata"),
            Arrow("client", "local", "local state"),
            Arrow("db", "server", "history", dashed=True),
            Arrow("db", "auditor", "identity log", dashed=True),
            Arrow("client", "auditor", "proof", dashed=True),
        ],
        """
        flowchart LR
          subgraph Client["Vùng client"]
            C[Plaintext + master key]
            L[Local state mã hóa]
            C --> L
          end
          N[Mạng TLS]
          subgraph Server["Vùng server"]
            S[Services + MLS validator]
            DB[(Database)]
            A[Auditor]
            S <--> DB
            DB -. identity log .-> A
          end
          C -->|ciphertext| N --> S
          S -->|ciphertext + metadata + public MLS state| DB
          C -. proof .-> A
        """,
    ))

    diagrams.append((
        "UseCaseOverview.png",
        "Use case tổng quan của SecChat",
        "Các nhóm chức năng chính nhìn từ góc độ người dùng ứng dụng.",
        [
            Node("user", 80, 470, 300, 170, "Người dùng", "đăng ký, chat, quản lý hồ sơ và kiểm tra cảnh báo bảo mật", "neutral"),
            Node("account", 520, 130, 340, 190, "Tài khoản và hồ sơ", "đăng ký, đăng nhập, đổi mật khẩu, avatar, privacy", "client"),
            Node("social", 520, 380, 340, 190, "Quan hệ xã hội", "tìm kiếm, gửi lời mời, chấp nhận, block", "client"),
            Node("chat", 520, 640, 340, 210, "Hội thoại", "DM, group, file, edit, pin, reaction, forward, sự kiện hệ thống", "client"),
            Node("security", 980, 250, 380, 220, "Bảo mật người dùng", "PQXDH bundle, MLS KeyPackage, safety code, backup E2EE", "crypto"),
            Node("server", 980, 610, 380, 210, "Dịch vụ server", "WebSocket, history, inbox, cursor đọc, group membership, metrics", "server"),
            Node("auditor", 1460, 250, 260, 190, "Auditor", "Merkle proof cho identity key", "network"),
            Node("db", 1460, 610, 260, 190, "MySQL", "ciphertext, metadata, prekey, identity log, sự kiện group", "db"),
        ],
        [
            Arrow("user", "account", ""),
            Arrow("user", "social", ""),
            Arrow("user", "chat", ""),
            Arrow("account", "security", "mở E2EE"),
            Arrow("social", "server", "bạn bè"),
            Arrow("chat", "server", "ciphertext"),
            Arrow("security", "auditor", "proof", dashed=True),
            Arrow("security", "server", "key material"),
            Arrow("server", "db", "lưu và truy vấn"),
            Arrow("db", "auditor", "identity log", dashed=True),
        ],
        """
        flowchart LR
          U[Người dùng] --> A[Tài khoản và hồ sơ]
          U --> S[Quan hệ xã hội]
          U --> C[Hội thoại]
          A --> K[Bảo mật người dùng]
          C --> WS[Dịch vụ server]
          S --> WS
          K --> WS
          K -. proof .-> AU[Auditor]
          WS --> DB[(MySQL)]
          DB -. identity log .-> AU
        """,
    ))

    diagrams.append((
        "MainUserFlow.png",
        "Luồng sử dụng chính của ứng dụng",
        "Từ đăng nhập đến kết bạn, mở DM, gửi tin, restore và tạo group.",
        [
            Node("login", 80, 210, 300, 170, "Đăng nhập", "mở master key và E2EE state", "client"),
            Node("publish", 470, 210, 310, 170, "Công bố key bundle", "bundle mới cho VNC active", "crypto"),
            Node("friend", 860, 210, 310, 170, "Kết bạn", "search, request, accept", "client"),
            Node("dm", 1250, 210, 310, 170, "Mở DM", "start_dm và lấy bundle peer", "client"),
            Node("pqxdh", 1250, 500, 310, 190, "PQXDH + ratchet", "S3PQI rồi S3DR", "crypto"),
            Node("message", 860, 500, 310, 190, "Gửi và nhận tin", "ciphertext, history, cursor đọc", "client"),
            Node("restore", 470, 500, 310, 190, "Restore E2EE", "snapshot cache/state nếu đổi VNC", "client"),
            Node("group", 80, 500, 300, 190, "Group chat", "MLS X-Wing, Welcome, S3MLS", "crypto"),
        ],
        [
            Arrow("login", "publish", ""),
            Arrow("publish", "friend", ""),
            Arrow("friend", "dm", ""),
            Arrow("dm", "pqxdh", "key exchange"),
            Arrow("pqxdh", "message", "ready"),
            Arrow("restore", "publish", "", dashed=True),
            Arrow("message", "restore", "", dashed=True),
            Arrow("message", "group", "tạo hoặc vào group"),
            Arrow("group", "message", "S3MLS"),
        ],
        """
        flowchart LR
          L[Đăng nhập] --> P[Công bố key bundle]
          P --> F[Kết bạn]
          F --> D[Mở DM]
          D --> X[PQXDH + Double Ratchet]
          X --> M[Gửi và nhận tin]
          M -. cache/history .-> R[Restore E2EE]
          R -. giữ identity nếu có .-> P
          M --> G[Group chat MLS X-Wing]
          G --> M
        """,
    ))

    diagrams.append((
        "AuthKeyFlow.png",
        "Luồng đăng ký, đăng nhập và mở khóa state",
        "Đăng ký chỉ tạo tài khoản; client phải đăng nhập thành công rồi mới mở state và công bố bundle.",
        [
            Node("input", 70, 220, 320, 170, "Người dùng nhập thông tin", "username, email và mật khẩu nếu đăng ký", "neutral"),
            Node("clienthash", 490, 210, 330, 190, "Client password hash", "PBKDF2 với salt là email đăng nhập", "client"),
            Node("register", 910, 120, 330, 150, "Register", "server tạo tài khoản nếu chưa có", "server"),
            Node("serverauth", 910, 340, 330, 190, "Auth", "server kiểm tra hash đã lưu", "server"),
            Node("ok", 1340, 250, 320, 150, "Login ok", "Trả user id và username thực tế", "server"),
            Node("master", 500, 560, 330, 190, "Derive master key", "Mật khẩu gốc + username thực tế", "crypto"),
            Node("state", 930, 540, 330, 220, "Mở local E2EE state", "identity, prekey, ratchet, group, cache", "crypto"),
            Node("bundle", 1340, 560, 320, 190, "Công bố public material", "PQXDH bundle và MLS KeyPackage X-Wing", "client"),
        ],
        [
            Arrow("input", "clienthash", "không gửi mật khẩu thô"),
            Arrow("clienthash", "register", "register nếu tạo mới"),
            Arrow("register", "serverauth", "auth ngay sau register"),
            Arrow("clienthash", "serverauth", "auth nếu đã có tài khoản"),
            Arrow("serverauth", "ok", "xác thực thành công"),
            Arrow("input", "master", "mật khẩu gốc giữ tại client"),
            Arrow("ok", "master", "username"),
            Arrow("master", "state", "giải mã state"),
            Arrow("state", "bundle", "fresh prekey"),
        ],
        """
        sequenceDiagram
          participant U as Người dùng
          participant C as Client
          participant S as Server
          U->>C: username/email + mật khẩu
          C->>C: tạo password hash
          alt đăng ký tài khoản mới
            C->>S: register(username, email, password hash)
            S->>S: tạo user và lưu server hash
            S-->>C: đăng ký thành công
            C->>S: auth(email, password hash)
          else đăng nhập tài khoản đã có
            C->>S: auth(email, password hash)
          end
          S->>S: kiểm tra server hash đã lưu
          S-->>C: user id + username
          C->>C: derive master key
          C->>C: mở E2EE state cục bộ
          C->>S: upload_pqxdh_bundle + upload_mls_key_packages
        """,
    ))

    diagrams.append((
        "PQXDHFlow.png",
        "Bắt tay DM kiểu PQXDH",
        "Client kiểm tra bundle, proof identity và transcript trước khi tạo root secret.",
        [
            Node("a", 70, 210, 300, 210, "Client A", "Lấy bundle, kiểm tra chữ ký và proof", "client"),
            Node("server", 500, 190, 300, 210, "Chat server", "Trả bundle, chỉ cấp OTK cùng generation và tiêu thụ OTK", "server"),
            Node("auditor", 500, 520, 300, 190, "Auditor", "Trả checkpoint và Merkle proof cho identity_version", "network"),
            Node("bundle", 930, 190, 330, 250, "Bundle của B", "identity pk, signed X25519 prekey, signed KEM prekey, OTK cùng generation", "crypto"),
            Node("mix", 930, 565, 330, 210, "HKDF transcript", "DH secrets + KEM shared secret -> root secret", "crypto"),
            Node("msg", 1340, 565, 310, 210, "S3PQI", "Tin đầu tiên chứa transcript và payload đã mã hóa", "network"),
            Node("b", 1400, 210, 300, 220, "Client B", "Decapsulate, kiểm tra transcript, khởi tạo Double Ratchet", "client"),
        ],
        [
            Arrow("a", "server", "get_pqxdh_bundle"),
            Arrow("server", "bundle", "bundle"),
            Arrow("a", "auditor", "proof"),
            Arrow("auditor", "a", "checkpoint", dashed=True),
            Arrow("bundle", "a", "", dashed=True),
            Arrow("a", "mix", "DH"),
            Arrow("bundle", "mix", "KEM ss"),
            Arrow("mix", "msg", "root secret"),
            Arrow("msg", "b", "S3PQI"),
        ],
        """
        sequenceDiagram
          participant A as Client A
          participant S as Server
          participant T as Auditor
          participant B as Client B
          A->>S: get_pqxdh_bundle(B)
          S-->>A: bundle cùng generation + identity_version
          S->>S: tiêu thụ OTK đã cấp
          A->>T: proof(user_id, identity_version)
          T-->>A: checkpoint + inclusion proof
          A->>A: verify proof and signatures
          A->>A: X25519 DH + ML-KEM/Kyber encapsulate
          A->>A: HKDF -> root secret
          A->>B: S3PQI initial message
          B->>B: decapsulate + DH + HKDF
          B->>B: init Double Ratchet
        """,
    ))

    diagrams.append((
        "DoubleRatchetFlow.png",
        "Double Ratchet cho DM",
        "Mỗi message dùng message key mới; state được mã hóa cục bộ sau khi cập nhật.",
        [
            Node("root", 110, 250, 330, 180, "Root key", "Trộn DH ratchet secret khi đổi lượt", "crypto"),
            Node("send", 560, 180, 330, 190, "Send chain", "Chain key gửi -> message key", "client"),
            Node("recv", 560, 515, 330, 190, "Receive chain", "Chain key nhận -> message key", "client"),
            Node("msg", 1010, 185, 330, 190, "S3DR message", "dh, pn, n, ciphertext", "network"),
            Node("skip", 1010, 520, 330, 190, "Skipped keys", "Hỗ trợ tin lệch thứ tự trong giới hạn", "crypto"),
            Node("persist", 1430, 345, 290, 200, "Encrypted state file", "ratchet state được mã hóa bằng master key", "crypto"),
        ],
        [
            Arrow("root", "send", "KDF_RK"),
            Arrow("send", "msg", "encrypt"),
            Arrow("msg", "recv", "decrypt"),
            Arrow("recv", "root", "DH ratchet khi remote key đổi"),
            Arrow("recv", "skip", "lưu key bỏ qua"),
            Arrow("send", "persist", "save"),
            Arrow("recv", "persist", "save"),
        ],
        """
        stateDiagram
          [*] --> RootKey
          RootKey --> SendChain: KDF_RK
          SendChain --> MessageKey: KDF_CK
          MessageKey --> S3DR: encrypt
          S3DR --> ReceiveChain: decrypt
          ReceiveChain --> SkippedKeys: out-of-order
          ReceiveChain --> RootKey: remote DH changed
        """,
    ))

    diagrams.append((
        "IdentityTransparencyFlow.png",
        "Identity transparency",
        "Mỗi identity key được ghi vào log append-only và được auditor ký checkpoint.",
        [
            Node("client", 80, 220, 320, 180, "Client", "upload_keys hoặc rotate_identity", "client"),
            Node("server", 500, 210, 330, 200, "Chat server", "chỉ cho đổi identity qua rotate_identity", "server"),
            Node("log", 930, 200, 340, 220, "identity_key_log", "user_id, version, identity_pk, leaf_hash", "db"),
            Node("auditor", 1370, 200, 330, 220, "Auditor service", "dựng Merkle tree và ký checkpoint", "network"),
            Node("peer", 500, 590, 330, 190, "Client lấy bundle", "nhận identity_version từ get_pqxdh_bundle", "client"),
            Node("proof", 930, 575, 340, 220, "Merkle proof", "inclusion proof + checkpoint signature + consistency", "crypto"),
            Node("ui", 1370, 590, 330, 190, "UI security state", "verified, key changed, audit lỗi cụ thể", "client"),
        ],
        [
            Arrow("client", "server", "upload"),
            Arrow("server", "log", "append"),
            Arrow("log", "auditor", "read", dashed=True),
            Arrow("peer", "proof", "proof"),
            Arrow("auditor", "proof", "checkpoint"),
            Arrow("proof", "ui", "result"),
            Arrow("server", "peer", "bundle", dashed=True),
        ],
        """
        sequenceDiagram
          participant C as Client đổi identity
          participant S as Chat server
          participant L as identity_key_log
          participant A as Auditor
          participant P as Peer client
          C->>S: upload_keys hoặc rotate_identity
          S->>L: append initial/rotation event
          A->>L: đọc log và dựng Merkle tree
          A-->>A: ký checkpoint
          P->>S: get_pqxdh_bundle(user)
          S-->>P: identity_pk + identity_version
          P->>A: proof(user_id, version)
          A-->>P: leaf + inclusion proof + checkpoint
          P-->>P: kiểm tra proof, signature, consistency
          alt proof và checkpoint hợp lệ
            P-->>P: lưu audit hợp lệ
          else proof, key, version hoặc checkpoint sai
            P-->>P: lưu audit_mismatch + last_error_code
          else auditor không truy cập được
            P-->>P: lưu audit_unavailable + last_error_code
          end
        """,
    ))

    diagrams.append((
        "GroupMlsFlow.png",
        "Group MLS X-Wing hybrid",
        "OpenMLS tạo artifact MLS; server validate public state trước khi cập nhật membership.",
        [
            Node("admin", 90, 250, 320, 190, "Admin client", "Tạo nhóm, thêm hoặc xóa thành viên", "client"),
            Node("kp", 520, 150, 330, 200, "KeyPackage X-Wing", "single-use, ký bằng SecChat identity", "crypto"),
            Node("prepare", 520, 520, 330, 190, "prepare_group_change", "Server kiểm tra friend/admin/block và claim KeyPackage", "server"),
            Node("bridge", 950, 220, 360, 230, "OpenMLS bridge", "Tạo Commit, Welcome, GroupInfo, ratchet tree", "crypto"),
            Node("validate", 950, 590, 360, 210, "PublicGroup validator", "Kiểm tra ciphersuite, group id, epoch, actor, member set", "server"),
            Node("apply", 1380, 500, 340, 210, "apply_group_change", "Lưu handshake và public state sau validation", "server"),
            Node("members", 1380, 170, 340, 210, "Members", "Process Welcome/Commit và đọc S3MLS", "client"),
            Node("removed", 1380, 800, 340, 150, "Removed member", "Không nhận secret epoch mới", "risk"),
        ],
        [
            Arrow("kp", "bridge", "claim"),
            Arrow("admin", "prepare", "request"),
            Arrow("prepare", "bridge", "operation id + KeyPackage"),
            Arrow("bridge", "validate", "Commit/Welcome/GroupInfo/tree"),
            Arrow("validate", "apply", ""),
            Arrow("apply", "members", "replay handshake"),
            Arrow("apply", "removed", "không gửi Welcome", dashed=True),
        ],
        """
        flowchart LR
          KP[KeyPackage X-Wing] --> B[OpenMLS bridge]
          A[Admin] --> P[prepare_group_change]
          P --> B
          B --> C[Commit + Welcome + GroupInfo + RatchetTree]
          C --> V[OpenMLS PublicGroup validation]
          V --> AP[apply_group_change]
          AP --> M[Members process handshake]
          AP -. no new secret .-> R[Removed member]
        """,
    ))

    diagrams.append((
        "GroupSystemEventsFlow.png",
        "Sự kiện hệ thống trong dòng thời gian group",
        "Metadata membership được lưu riêng và ghép theo after_message_id, không đi vào plaintext cache.",
        [
            Node("op", 80, 230, 330, 190, "Thay đổi group", "add, remove, leave, role hoặc info update", "client"),
            Node("mls", 500, 170, 360, 210, "MLS validation", "Commit hoặc control message hợp lệ", "server"),
            Node("anchor", 500, 500, 360, 190, "Tính anchor", "MAX(messages.id) tại thời điểm apply", "server"),
            Node("table", 940, 250, 360, 230, "group_system_events", "operation_id, actor, target, role, members, after_message_id", "db"),
            Node("history", 1360, 170, 340, 210, "Phản hồi history", "messages ciphertext + system_events", "server"),
            Node("merge", 1360, 500, 340, 210, "Client ghép dòng thời gian", "đặt sự kiện sau anchor và chống duplicate", "client"),
            Node("cache", 940, 620, 360, 170, "Local cache", "chỉ cache plaintext message đã decrypt", "crypto"),
        ],
        [
            Arrow("op", "mls", "apply"),
            Arrow("mls", "anchor", "validation ok"),
            Arrow("anchor", "table", "insert"),
            Arrow("table", "history", ""),
            Arrow("history", "merge", ""),
            Arrow("merge", "cache", "", dashed=True),
        ],
        """
        flowchart LR
          OP[Thay đổi group] --> V[MLS validation hợp lệ]
          V --> A[Tính after_message_id]
          A --> GSE[(group_system_events)]
          GSE --> H[history: messages + system_events]
          H --> M[Client ghép dòng thời gian]
          M -. không đưa vào plaintext cache .-> C[Local cache]
        """,
    ))

    diagrams.append((
        "GroupCommitChainFlow.png",
        "Chuỗi MLS Commit và validation",
        "Server kiểm tra public MLS state trước khi mutate; client tiếp tục kiểm tra consistency khi replay.",
        [
            Node("c0", 90, 250, 320, 190, "Public state epoch 0", "members, group id, transcript hash", "crypto"),
            Node("c1", 520, 250, 330, 190, "Commit epoch 1", "actor credential, proposal, confirmation", "crypto"),
            Node("validator", 950, 250, 330, 210, "Server PublicGroup validation", "epoch, ciphersuite, actor, member set", "server"),
            Node("state", 1380, 250, 330, 190, "Validated public state", "lưu public_state_hash và epoch mới", "db"),
            Node("server", 520, 620, 330, 190, "Server history", "trả handshake và group info", "server"),
            Node("check", 950, 620, 330, 190, "Client consistency check", "so khớp epoch, member hash, transcript", "client"),
            Node("warn", 1380, 620, 330, 190, "Cảnh báo", "history thiếu, rollback hoặc membership mismatch", "risk"),
        ],
        [
            Arrow("c0", "c1", ""),
            Arrow("c1", "validator", ""),
            Arrow("validator", "state", ""),
            Arrow("server", "check", ""),
            Arrow("state", "check", ""),
            Arrow("check", "warn", "không khớp", dashed=True),
        ],
        """
        flowchart LR
          C0[Public state epoch 0] --> C1[Commit epoch 1]
          C1 --> V[Server PublicGroup validation]
          V --> STATE[Validated public state]
          SERVER[Server history/group info] --> CHECK[Client consistency check]
          STATE --> CHECK
          CHECK -. mismatch .-> WARN[Warning]
        """,
    ))

    diagrams.append((
        "TranscriptConsistencyFlow.png",
        "Transcript checkpoint cho group",
        "Mỗi client ký view mà mình đã thấy để phát hiện server trả history hoặc thứ tự khác nhau.",
        [
            Node("messages", 90, 230, 340, 190, "Local accepted messages", "message id, sender, body hash, deleted/edit target", "client"),
            Node("head", 540, 220, 330, 210, "Transcript head", "hash nối tiếp theo thứ tự message", "crypto"),
            Node("checkpoint", 980, 220, 330, 210, "Signed checkpoint", "conversation_id, last_message_id, count, head", "crypto"),
            Node("server", 1410, 220, 310, 210, "Server chuyển tiếp", "lưu như S3MLS control message", "server"),
            Node("peer", 540, 590, 330, 190, "Peer client", "nhận checkpoint của thành viên khác", "client"),
            Node("compare", 980, 590, 330, 190, "Compare local view", "so khớp head tại cùng message id", "client"),
            Node("warning", 1410, 590, 310, 190, "Warning", "missing message, reorder, rollback hoặc split-view", "risk"),
        ],
        [
            Arrow("messages", "head", "hash"),
            Arrow("head", "checkpoint", "sign"),
            Arrow("checkpoint", "server", "S3MLS"),
            Arrow("server", "peer", "deliver"),
            Arrow("peer", "compare", "record"),
            Arrow("head", "compare", "local", dashed=True),
            Arrow("compare", "warning", "mismatch", dashed=True),
        ],
        """
        flowchart LR
          MSG[Local accepted messages] --> HEAD[Transcript head]
          HEAD --> CP[Signed checkpoint]
          CP --> S[Server stores/forwards S3MLS control]
          S --> P[Peer client]
          P --> CHECK[Compare with local view]
          HEAD -. local head .-> CHECK
          CHECK -. mismatch .-> WARN[Warning]
        """,
    ))

    diagrams.append((
        "OfflineHistoryFlow.png",
        "Tin offline và tải lại lịch sử",
        "Tin offline không được làm mất lịch sử cũ; client ghép theo message id và ẩn ciphertext không giải mã được.",
        [
            Node("b_off", 90, 230, 310, 160, "Client B offline", "Không có socket đang nhận", "neutral"),
            Node("a_send", 90, 560, 310, 170, "Client A gửi tin", "Mã hóa S3DR hoặc S3MLS", "client"),
            Node("server", 540, 390, 320, 210, "Server", "Lưu ciphertext và cập nhật inbox theo cursor", "server"),
            Node("db", 980, 390, 320, 210, "MySQL", "messages, system_events và cursor đọc", "db"),
            Node("b_login", 1420, 220, 310, 170, "B đăng nhập lại", "Nhận inbox theo last_read_message_id", "client"),
            Node("history", 1420, 570, 310, 190, "Client mở hội thoại", "Request full history rồi ghép theo msg_id và anchor", "crypto"),
        ],
        [
            Arrow("a_send", "server", "ciphertext"),
            Arrow("server", "db", "insert"),
            Arrow("db", "b_login", "inbox có tin mới"),
            Arrow("b_login", "history", "mở conversation"),
            Arrow("history", "db", "history", dashed=True),
            Arrow("db", "history", "messages", dashed=True),
        ],
        """
        sequenceDiagram
          participant A as Client A
          participant S as Server
          participant DB as MySQL
          participant B as Client B
          B-->>S: offline
          A->>S: encrypted message
          S->>DB: store ciphertext
          B->>S: login
          S-->>B: inbox/offline event theo cursor đọc
          B->>S: history(conversation_id)
          S->>DB: load messages + system_events
          S-->>B: old + offline messages + system events
          B->>B: merge by message id and anchor
        """,
    ))

    diagrams.append((
        "EditEventFlow.png",
        "Edit message dạng event mã hóa",
        "Server append edit event; client decrypt event rồi cập nhật message gốc.",
        [
            Node("orig", 100, 220, 330, 180, "Message gốc", "Đã lưu ciphertext và hiển thị plaintext ở client", "client"),
            Node("edit", 560, 210, 330, 200, "Người gửi sửa tin", "Mã hóa nội dung mới qua S3DR hoặc S3MLS", "crypto"),
            Node("server", 1010, 210, 330, 200, "Server", "Insert row mới với edit_target_message_id", "server"),
            Node("db", 1430, 210, 300, 200, "Messages table", "Giữ message gốc và edit event", "db"),
            Node("recv", 560, 560, 330, 200, "Người nhận", "Decrypt edit event như message thường", "client"),
            Node("apply", 1010, 560, 330, 200, "Apply local update", "Thay body của message gốc và hiển thị đã sửa", "client"),
        ],
        [
            Arrow("orig", "edit", "edit action"),
            Arrow("edit", "server", "encrypted edit event"),
            Arrow("server", "db", "append row"),
            Arrow("server", "recv", "broadcast"),
            Arrow("recv", "apply", "plaintext mới"),
            Arrow("db", "apply", "history replay", dashed=True),
        ],
        """
        sequenceDiagram
          participant A as Sender
          participant S as Server
          participant DB as MySQL
          participant B as Receiver
          A->>A: encrypt edited plaintext
          A->>S: S3DR/S3MLS edit event
          S->>DB: insert row with edit_target_message_id
          S-->>B: message event
          B->>B: decrypt event
          B->>B: update original message locally
        """,
    ))

    diagrams.append((
        "MessageActionsFlow.png",
        "Pin, reaction và forward",
        "Các action cập nhật metadata hoặc tạo ciphertext mới, không làm server đọc plaintext.",
        [
            Node("menu", 90, 250, 310, 190, "Menu ba chấm", "React, forward, pin, edit", "client"),
            Node("react", 520, 160, 300, 170, "Reaction", "Chọn emoji, lưu count và người đã react", "server"),
            Node("pin", 520, 400, 300, 170, "Pin", "Cập nhật pinned state và Pins list", "server"),
            Node("forward", 920, 160, 340, 180, "Forward", "Client re-encrypt plaintext vào hội thoại đích", "crypto"),
            Node("ui", 1370, 250, 330, 220, "UI realtime", "Chip reaction, badge pin, nhãn forward", "client"),
        ],
        [
            Arrow("menu", "react", "add/remove_reaction"),
            Arrow("menu", "pin", "pin/unpin_message"),
            Arrow("menu", "forward", "encrypt new message"),
            Arrow("react", "ui", "event"),
            Arrow("pin", "ui", "event"),
            Arrow("forward", "ui", "new ciphertext message"),
        ],
        """
        flowchart LR
          M[Menu ba chấm] --> R[Reaction metadata]
          M --> P[Pin metadata]
          M --> F[Forward: client mã hóa lại]
          R --> UI[UI realtime]
          P --> UI
          F --> UI
        """,
    ))

    diagrams.append((
        "DatabaseOverview.png",
        "Nhóm bảng dữ liệu chính",
        "Database lưu ciphertext, public key material, public MLS state và metadata; secret cục bộ không nằm trên server.",
        [
            Node("users", 70, 180, 320, 180, "users", "tài khoản, email, profile, privacy, password hash", "db"),
            Node("friends", 70, 470, 320, 170, "friendships / blocks", "quan hệ xã hội và chặn", "db"),
            Node("conv", 500, 170, 330, 180, "conversations", "DM, saved messages, group", "db"),
            Node("members", 500, 470, 330, 170, "conversation_members", "role, last_read_message_id, mute, pinned conv", "db"),
            Node("messages", 920, 150, 360, 200, "messages", "S3PQI/S3DR/S3MLS body, sender, time, edit target, forward", "db"),
            Node("meta", 920, 420, 360, 150, "message metadata", "message_reactions, pinned_messages", "db"),
            Node("gse", 920, 640, 360, 190, "group_system_events", "metadata dòng thời gian membership, operation_id, after_message_id", "db"),
            Node("keys", 1370, 130, 350, 190, "key bundles", "user_keys, pqxdh_bundles, one-time prekeys", "crypto"),
            Node("mls", 1370, 390, 350, 210, "MLS public tables", "mls_key_packages, pending_ops, handshake, group_state", "crypto"),
            Node("idlog", 1370, 690, 350, 170, "identity_key_log", "append-only identity history cho auditor", "crypto"),
            Node("notify", 500, 760, 330, 160, "notification_queue", "sự kiện offline và thông báo hệ thống", "server"),
        ],
        [
            Arrow("users", "friends", "user id"),
            Arrow("users", "conv", ""),
            Arrow("conv", "members", ""),
            Arrow("conv", "messages", ""),
            Arrow("messages", "meta", ""),
            Arrow("conv", "gse", ""),
            Arrow("users", "keys", ""),
            Arrow("conv", "mls", ""),
            Arrow("users", "idlog", ""),
            Arrow("users", "notify", ""),
            Arrow("messages", "notify", ""),
            Arrow("gse", "notify", "", dashed=True),
            Arrow("idlog", "keys", "version", dashed=True),
            Arrow("keys", "mls", "KeyPackage", dashed=True),
        ],
        """
        erDiagram
          users ||--o{ friendships : has
          users ||--o{ user_blocks : blocks
          users ||--o{ conversation_members : joins
          conversations ||--o{ conversation_members : contains
          conversations ||--o{ messages : stores
          conversations ||--o{ group_system_events : has
          messages ||--o{ message_reactions : has
          messages ||--o{ pinned_messages : can_be_pinned
          users ||--o{ pqxdh_bundles : publishes
          users ||--o{ mls_key_packages : publishes
          conversations ||--o{ mls_group_handshake : has
          conversations ||--|| mls_group_state : validates
          users ||--o{ identity_key_log : has_identity_history
          users ||--o{ notification_queue : receives
        """,
    ))

    diagrams.append((
        "CryptoEngineSplit.png",
        "Tách crypto engine khỏi UI controller",
        "App điều phối UI/WebSocket; CryptoSession sở hữu state crypto và mã hóa outbound.",
        [
            Node("pages", 90, 230, 300, 190, "UI pages", "login, register, chat, dialogs", "client"),
            Node("app", 520, 220, 330, 210, "App controller", "nhận signal, gửi command, cập nhật UI", "client"),
            Node("net", 520, 560, 330, 170, "network.py", "WebSocket TLS thread", "network"),
            Node("session", 990, 190, 360, 240, "CryptoSession", "state, file mã hóa, cache, encrypt_for_conv", "crypto"),
            Node("protocol", 1420, 190, 310, 240, "Giao thức SecChat", "PQXDH, Double Ratchet, MLS group", "crypto"),
            Node("files", 990, 560, 360, 190, "Encrypted local files", "identity, ratchet, group, verified, msgs", "crypto"),
        ],
        [
            Arrow("pages", "app", "Qt signal"),
            Arrow("app", "net", "safe_send"),
            Arrow("net", "app", "server event"),
            Arrow("app", "session", "mã hóa và state"),
            Arrow("session", "protocol", ""),
            Arrow("session", "files", "save/load"),
        ],
        """
        flowchart LR
          UI[UI pages] <--> APP[App controller]
          APP <--> NET[network.py]
          APP --> CS[CryptoSession]
          CS --> P[Giao thức SecChat]
          CS --> FS[Encrypted local files]
        """,
    ))

    diagrams.append((
        "DeploymentDocker.png",
        "Triển khai bằng Docker Compose",
        "Các container chạy chung network nội bộ; auditor có API riêng cho key transparency.",
        [
            Node("host", 80, 250, 320, 190, "Host Windows", "Docker Desktop, repo secchat", "neutral"),
            Node("cert", 80, 620, 320, 160, ".tmp_cert", "public TLS cert cho client dev", "crypto"),
            Node("server", 540, 210, 330, 210, "chat-server", "WebSocket 8888, HTTP 8889, GUI 5900", "server"),
            Node("db", 1400, 210, 320, 210, "chat-db", "MySQL 8.0, volume dữ liệu", "db"),
            Node("clients", 540, 620, 390, 180, "chat-client1 và chat-client2", "VNC 5901/5902, đọc cert", "client"),
            Node("auditor", 1000, 620, 330, 180, "chat-auditor", "HTTP 8890, Merkle checkpoint/proof", "network"),
        ],
        [
            Arrow("host", "cert", "bind"),
            Arrow("cert", "server", "/certs"),
            Arrow("cert", "clients", "ro", dashed=True),
            Arrow("clients", "server", "WebSocket"),
            Arrow("clients", "auditor", "proof", dashed=True),
            Arrow("server", "db", "MySQL"),
            Arrow("auditor", "db", "identity log"),
        ],
        """
        flowchart LR
          H[Host Windows] --> S[chat-server]
          H --> A[chat-auditor]
          H --> C[chat-client1 / chat-client2]
          H --> CERT[.tmp_cert]
          CERT --> S
          CERT --> C
          S --> DB[(chat-db)]
          A --> DB
          C --> S
          C -. proof .-> A
        """,
    ))

    diagrams.append((
        "MessageDataFlow.png",
        "Data flow gửi tin nhắn",
        "Plaintext chỉ nằm ở client; server lưu và chuyển tiếp ciphertext.",
        [
            Node("plain", 80, 270, 310, 170, "Plaintext", "Người gửi nhập nội dung", "client"),
            Node("enc", 500, 230, 340, 220, "CryptoSession encrypt", "S3PQI, S3DR hoặc S3MLS", "crypto"),
            Node("server", 950, 230, 330, 220, "Server validate", "kiểm tra quyền và E2EE prefix", "server"),
            Node("db", 1390, 230, 310, 220, "Database", "lưu ciphertext body", "db"),
            Node("recv", 950, 590, 330, 190, "Receiver decrypt", "khôi phục plaintext ở client nhận", "client"),
            Node("cache", 500, 590, 340, 190, "Local cache", "plaintext cache được mã hóa bằng master key", "crypto"),
        ],
        [
            Arrow("plain", "enc", "body"),
            Arrow("enc", "server", "ciphertext"),
            Arrow("server", "db", "insert"),
            Arrow("server", "recv", "broadcast/history"),
            Arrow("recv", "cache", "lưu để đọc lại"),
            Arrow("cache", "recv", "preview/history", dashed=True),
        ],
        """
        flowchart LR
          P[Plaintext ở client gửi] --> E[Encrypt trong CryptoSession]
          E --> S[Server validate prefix]
          S --> DB[(messages.body ciphertext)]
          S --> R[Client nhận decrypt]
          R --> C[Local cache mã hóa]
        """,
    ))

    diagrams.append((
        "CacheBackupFlow.png",
        "Cache cục bộ và backup E2EE",
        "Cache plaintext được mã hóa để phục vụ UX; backup là snapshot cục bộ do người dùng giữ passphrase.",
        [
            Node("decrypt", 90, 230, 330, 190, "Client giải mã", "khôi phục plaintext ở client", "client"),
            Node("policy", 520, 180, 330, 220, "Cache policy", "bật/tắt toàn cục, TTL, clear on logout, per conversation", "client"),
            Node("cache", 950, 190, 330, 210, "Encrypted plaintext cache", "theo tài khoản và VNC, bọc bằng master key", "crypto"),
            Node("preview", 1380, 220, 330, 170, "UI preview/history", "dùng cache; ẩn tin không decrypt được", "client"),
            Node("export", 520, 590, 330, 190, "Export backup", "chọn có kèm cache hay không", "client"),
            Node("file", 950, 570, 330, 220, "File backup", "mã hóa bằng passphrase riêng, có generation và backup_id", "crypto"),
            Node("restore", 1380, 590, 330, 190, "Restore", "merge cache, re-wrap state, publish bundle mới", "client"),
        ],
        [
            Arrow("decrypt", "policy", ""),
            Arrow("policy", "cache", ""),
            Arrow("cache", "preview", ""),
            Arrow("cache", "export", "", dashed=True),
            Arrow("export", "file", ""),
            Arrow("file", "restore", ""),
        ],
        """
        flowchart LR
          D[Decrypt ở client] --> P[Cache policy]
          P --> C[Encrypted plaintext cache]
          C --> UI[Preview/history, hide undecryptable]
          C -. optional .-> E[Export E2EE backup]
          E --> F[Passphrase-encrypted backup file]
          F --> R[Restore snapshot and publish fresh bundle]
        """,
    ))

    diagrams.append((
        "KeyLifecycle.png",
        "Vòng đời khóa người dùng",
        "Khóa có vai trò khác nhau: xác thực, bắt tay, ratchet, group, restore và lưu cục bộ.",
        [
            Node("register", 90, 230, 310, 170, "Đăng ký", "Tạo identity key và prekey bundle", "client"),
            Node("publish", 520, 220, 330, 190, "Công bố khóa công khai", "identity pk, PQXDH prekey và MLS KeyPackage X-Wing", "server"),
            Node("handshake", 960, 220, 330, 190, "Bắt tay PQXDH", "Tạo root secret cho DM", "crypto"),
            Node("ratchet", 1390, 220, 310, 190, "Trạng thái ratchet", "Cập nhật theo message", "crypto"),
            Node("group", 960, 570, 330, 190, "Epoch group MLS", "X-Wing Welcome, Commit và epoch secret", "crypto"),
            Node("rotate", 520, 570, 330, 190, "Xoay safety key", "Identity version đổi, cần verify lại", "client"),
            Node("password", 90, 570, 310, 190, "Restore hoặc đổi mật khẩu", "Re-wrap local files; backup là snapshot", "crypto"),
        ],
        [
            Arrow("register", "publish", ""),
            Arrow("publish", "handshake", ""),
            Arrow("handshake", "ratchet", ""),
            Arrow("publish", "group", ""),
            Arrow("rotate", "publish", ""),
            Arrow("password", "publish", "", dashed=True),
        ],
        """
        flowchart LR
          R[Đăng ký] --> P[Công bố bundle và MLS KeyPackage]
          P --> H[Bắt tay PQXDH]
          H --> DR[Double Ratchet state]
          P --> G[MLS X-Wing epoch secret]
          CP[Restore hoặc đổi mật khẩu] -. re-wrap, giữ identity nếu restore .-> P
          ROT[Xoay safety key] --> P
        """,
    ))

    diagrams.append((
        "DbMessageStorage.png",
        "Dữ liệu tin nhắn trong database",
        "Bảng messages lưu ciphertext body và metadata cần vận hành.",
        [
            Node("body", 100, 230, 380, 210, "messages.body", "S3PQI / S3DR / S3MLS\nKhông phải plaintext", "db"),
            Node("meta", 610, 180, 360, 190, "Metadata cơ bản", "conversation_id, sender_id, sent_at", "server"),
            Node("edit", 610, 500, 360, 190, "Metadata thao tác", "edit_target, forwarded_from, deleted_at", "server"),
            Node("react", 1100, 180, 330, 190, "Reaction / pin", "message_reactions, pinned_messages", "db"),
            Node("risk", 1500, 340, 240, 190, "Kết luận", "Nội dung được bảo vệ; metadata chưa được ẩn", "risk"),
        ],
        [
            Arrow("body", "meta", "cùng row"),
            Arrow("body", "edit", "message id"),
            Arrow("meta", "react", "message id"),
            Arrow("react", "risk", "metadata"),
            Arrow("body", "risk", "ciphertext"),
        ],
        """
        flowchart LR
          B[messages.body: S3PQI/S3DR/S3MLS] --> M[conversation_id, sender_id, sent_at]
          B --> E[edit_target, forwarded_from, deleted_at]
          M --> R[reactions/pins]
          B --> K[Nội dung được bảo vệ]
          R --> MD[Metadata chưa được ẩn]
        """,
    ))

    for idx, (filename, title, subtitle, nodes, arrows, mmd) in enumerate(diagrams, start=1):
        stem = Path(filename).stem
        write_mmd(stem, mmd)
        render_diagram(filename, title, subtitle, nodes, arrows)

    readme = "\n".join([
        "# Report diagrams",
        "",
        "Các file `.mmd` là source Mermaid để sửa nhanh nội dung sơ đồ.",
        "Các ảnh `.png` tương ứng nằm trong `report/Figure/` và được LaTeX include trực tiếp.",
        "Chạy lại bằng lệnh:",
        "",
        "```powershell",
        "python report\\render_diagrams.py",
        "```",
        "",
    ])
    (DIAGRAM_DIR / "README.md").write_text(readme, encoding="utf-8")


if __name__ == "__main__":
    build()
