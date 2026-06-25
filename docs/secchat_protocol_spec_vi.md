# Đặc tả giao thức SecChat

Tài liệu này mô tả wire format và state machine hiện tại của SecChat sau khi
group runtime được chuyển sang OpenMLS. SecChat không wire-compatible với Signal.
DM dùng bắt tay hybrid kiểu PQXDH và Double Ratchet riêng của SecChat. Group
dùng MLS RFC 9420 thông qua OpenMLS với X-Wing draft hybrid ML-KEM-768 +
X25519; server chỉ lưu/phát artifact công khai hoặc ciphertext, không sinh group
secret.

## 1. Mục tiêu

SecChat bảo vệ nội dung tin nhắn khỏi server, database và attacker nghe lén
mạng. Client mã hóa trước khi gửi. Server quản lý auth, friend policy,
membership, delivery, history và metadata cần thiết cho sản phẩm.

Hệ thống hiện là mô hình active device. Nếu đăng nhập cùng account trên thiết bị
khác mà chưa restore E2EE backup, thiết bị đó không có state cũ để đọc lại mọi
message forward-secret.

## 2. Primitive

Các primitive chính:

- Ed25519 cho identity key, chữ ký prekey và safety number.
- X25519 cho phần cổ điển của bắt tay DM.
- ML-KEM hoặc Kyber cho phần hậu lượng tử của bắt tay DM.
- HKDF-SHA256 để trộn shared secret và tách chain key.
- AES-GCM để mã hóa payload cục bộ của SecChat.
- OpenMLS 0.8.1 cho group MLS RFC 9420.

Ciphersuite MLS mặc định là
`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`.
Đây là PQ confidentiality/HNDL theo draft X-Wing; authentication vẫn là Ed25519
classical, không phải PQ signature hoặc final RFC/IANA PQ MLS.

## 3. Prefix wire

Message mới trong bảng `messages.body` chỉ được dùng các prefix sau:

- `S3PQI:` cho DM initial message sau khi initiator chạy bắt tay PQXDH.
- `S3DR:` cho DM message sau khi hai bên có Double Ratchet state.
- `S3MLS:` cho group application/control message chứa MLS bytes.

Server từ chối plaintext và các prefix cũ như `E2E:`, `E2R:`, `E2RK:`,
`E2GS:` và `__KEM_INIT__` cho message mới.

## 4. Identity và safety number

Mỗi account có Ed25519 identity key pair. Public key nằm trong bundle; secret key
được lưu trong local encrypted state. Safety number của hai người dùng được tính
từ hai public key đã sort:

```text
digest = SHA-256("SecChatSafety" || 0x00 || left_pk || right_pk)
safety = 16 byte đầu, in hex và nhóm 4 ký tự
```

Nếu identity key hoặc identity version đổi, client bỏ trạng thái verified của
conversation liên quan và yêu cầu người dùng review lại.

## 5. Identity audit

Server ghi identity event vào `identity_key_log`. Auditor dựng Merkle tree, ký
checkpoint và trả inclusion proof. Client kiểm tra proof trước khi tin
`pqxdh_bundle` của peer. Lỗi audit phải được báo rõ, ví dụ thiếu proof, proof
sai, checkpoint rollback, split-view hoặc bundle không khớp identity log.

## 6. PQXDH bundle

Client upload bundle bằng `upload_pqxdh_bundle`.

Đầu vào:

- Ed25519 identity public key và identity version.
- Signed X25519 prekey.
- Signed PQ KEM prekey.
- Danh sách one-time X25519 prekey.
- Danh sách one-time PQ KEM prekey.

Đầu ra server:

- Signed prekey hiện hành.
- One-time prekey nếu còn; prekey này bị consume khi trả cho initiator.
- Audit material cho identity key.

Client nhận bundle phải kiểm tra chữ ký prekey bằng identity key đã audit. Nếu
chữ ký, thuật toán hoặc proof sai, client hủy bắt tay và báo lỗi đúng nguyên
nhân.

## 7. DM initial bằng PQXDH

Initiator lấy bundle của responder, chọn one-time prekey nếu có, sinh ephemeral
X25519 key và encapsulate PQ KEM. Root secret được tính:

```text
root = HKDF-SHA256(dh1 || dh2 || optional(dh3) || pq_ss,
                   info = "SecChat-PQXDH",
                   length = 32)
```

Từ root secret, hai bên tạo `DoubleRatchet`. Initiator mã hóa initial payload và
gửi `S3PQI`. Responder đọc `S3PQI`, kiểm tra `recipient_uid`, lấy local prekey
secret tương ứng, decapsulate PQ KEM, tính lại root secret và decrypt initial
payload.

Đầu ra thành công:

- Cả hai bên có cùng root secret.
- Cả hai bên lưu Double Ratchet state theo conversation và session id.
- One-time prekey đã dùng không được tái sử dụng.

## 8. Double Ratchet cho DM

Double Ratchet state gồm root key, local ratchet key pair, remote ratchet public
key, send/receive chain key, header key, counter gửi/nhận, session id, replay set
và skipped-key cache giới hạn.

Khi gửi `S3DR`, client tạo message key từ send chain, mã hóa payload bằng
AES-GCM và gắn AAD canonical gồm conversation id, sender, receiver, identity
version, session id và message kind. Header nhìn thấy đủ để route session; bản
sao encrypted header giúp phát hiện sửa header.

Khi nhận, client chọn state theo session id, kiểm tra replay, xử lý skipped key,
thực hiện DH ratchet nếu remote DH đổi, decrypt payload và rollback state nếu
decrypt thất bại. Skipped-key cache có giới hạn để tránh DoS bằng message số thứ
tự quá xa.

## 9. Plaintext envelope và padding

Trước khi đưa vào `S3DR` hoặc `S3MLS`, plaintext người dùng được bọc:

```json
{
  "_type": "__secchat_payload_v1__",
  "body": "nội dung người dùng",
  "pad": "random-base64"
}
```

Padding đưa message vào các bucket kích thước để giảm lộ độ dài tương đối. Cơ
chế này không che được conversation id, sender, thời điểm gửi hoặc membership.

## 10. MLS group bằng OpenMLS

Group không dùng secret tự chế. Client dùng `MlsBridge` gọi binary Rust
`secchat_mls_bridge`, bridge dùng OpenMLS để tạo KeyPackage, Welcome, Commit,
GroupInfo và application message.

Các command bridge chính:

- `init_identity`: tạo MLS credential bind với SecChat identity hiện tại.
- `top_up_key_packages`: sinh KeyPackage single-use.
- `create_group`: tạo MLS group với group id gắn conversation id.
- `add_members`: tạo MLS Commit, Welcome và GroupInfo để thêm member.
- `remove_members`: tạo MLS Commit và GroupInfo để xóa member.
- `join_from_welcome`: member mới join từ Welcome.
- `process_commit`: member hiện có merge Commit.
- `encrypt_application`: mã hóa plaintext group thành MLS application bytes.
- `decrypt_application`: giải mã MLS application bytes.

Server có API:

- `upload_mls_key_packages`
- `claim_mls_key_package`
- `prepare_group_change`
- `apply_group_change`
- `get_mls_handshake`

`prepare_group_change` kiểm tra policy và tạo operation id. Với membership
operation, `apply_group_change` yêu cầu Commit, GroupInfo, RatchetTree và group id;
server dùng OpenMLS `PublicGroup` để validate ciphersuite, group id, actor
credential, epoch và expected member set trước khi ghi handshake hoặc mutate
membership. Server không tự tạo secret group, không giải mã MLS application bytes
và không thể đọc nội dung group.

## 11. Add, remove và role trong group

Tạo group:

1. Client yêu cầu server tạo conversation group.
2. Client gọi `create_group` trong bridge.
3. Client thêm các member ban đầu bằng `add_members`.
4. Client apply operation `create_group` với Commit, GroupInfo, RatchetTree,
   group id và Welcome.

Thêm member:

1. Admin gọi `prepare_group_change(add_member)`.
2. Server kiểm tra friend/block/admin policy. Target phải có KeyPackage X-Wing
   đã được server verify chữ ký SecChat khi upload.
3. Admin gọi `add_members` trong bridge.
4. Admin gửi Commit, GroupInfo và Welcome cho server qua `apply_group_change`.
5. Server validate public MLS commit/state rồi mới thêm member; target replay
   Welcome để join.

Xóa hoặc kick member:

1. Admin gọi `prepare_group_change(remove_member)`.
2. Admin gọi `remove_members` trong bridge.
3. Server validate Commit/GroupInfo/RatchetTree bằng public state trước đó rồi
   mới lưu handshake và cập nhật membership ở `apply_group_change`.
4. Member bị xóa xử lý Commit remove thì group local inactive và không đọc được
   message sau epoch mới.

Role, tên nhóm, avatar và bio là app-level control message mã hóa qua MLS
application message. Server chỉ cập nhật metadata sau khi nhận operation hợp lệ
kèm control message.

## 12. History, offline và replay

Server trả history theo message id. Client phải merge theo message id, không thay
toàn bộ view bằng live event. Với group, client gọi `get_mls_handshake` để replay
Welcome và Commit trước khi decrypt `S3MLS` application message trong history.

Nếu thiếu state cục bộ, client hiển thị placeholder rõ ràng như
`[Encrypted message - MLS state unavailable]` và không được làm hỏng state hiện
tại.

## 13. Edit, delete, reply, forward, reaction và pin

Edit và forward dùng message mã hóa mới. Server append event mới thay vì ghi đè
ciphertext gốc. Reply metadata được giữ tối thiểu để client render sau khi
decrypt.

Reaction và pin hiện vẫn là metadata server-side. Chúng không tiết lộ body nhưng
tiết lộ hành vi người dùng. Nếu cần giảm metadata hơn nữa, hai loại event này
nên chuyển dần sang encrypted control event.

## 14. Local state và backup

Client lưu identity key, local prekey, Double Ratchet state, MLS runtime/cache,
verified safety state, cache policy và plaintext cache trong local encrypted
state. Master key được dẫn xuất từ thông tin đăng nhập. Backup E2EE dùng
passphrase riêng, PBKDF2-HMAC-SHA256 và AES-GCM với manifest làm associated
data.

Sau rotate identity, import backup không được publish lại identity cũ. Backup
chỉ merge cache/history hợp lệ ở chế độ historical; nếu state cũ không còn hợp
lệ thì message forward-secret cũ chỉ đọc được khi cache/backup tương ứng còn
khả dụng.

## 15. Điều kiện đúng tối thiểu

Một build SecChat hiện tại chỉ được coi là đúng nếu:

- server không lưu plaintext body cho message mới;
- message mới chỉ dùng `S3PQI`, `S3DR`, `S3MLS` hoặc attachment prefix hợp lệ;
- client kiểm tra prekey signature và audit proof trước khi dùng bundle;
- lỗi audit được báo đúng nguyên nhân;
- `S3PQI` chỉ được xử lý nếu `recipient_uid` là chính mình;
- ratchet decrypt fail không làm tiến state;
- skipped-key cache có giới hạn;
- group add/remove đi qua KeyPackage, Welcome, Commit và GroupInfo của OpenMLS;
- server không cập nhật membership trước `apply_group_change`;
- removed member không đọc được message group sau Commit remove;
- local state và cache plaintext được mã hóa at rest;
- visible manual checklist pass trên reset Docker sạch.
