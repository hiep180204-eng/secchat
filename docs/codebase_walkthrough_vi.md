# SecChat - ghi chú đọc codebase

Tài liệu này là bản đọc lại codebase theo trạng thái hiện tại của repo. Mục tiêu là giúp người sửa code nắm được hệ thống chạy như thế nào, file nào chịu trách nhiệm gì, và cần kiểm tra gì sau mỗi thay đổi.

## 1. Bức tranh tổng thể

SecChat gồm 5 phần chính:

- `server/`: server C, nhận kết nối TLS + WebSocket, xử lý auth, bạn bè, chat, group, profile, privacy, key management, metrics và HTTP control plane.
- `client/`: client PyQt, gồm UI, WebSocket client và lớp điều phối `App`.
- `client/crypto_engine/`: crypto engine Python tách khỏi UI, giữ state E2EE, PQXDH-style, Double Ratchet, MLS group state, local cache và backup.
- `auditor_service.py`: HTTP service đọc `identity_key_log`, dựng Merkle tree và trả proof/checkpoint cho identity transparency.
- `tests/` và các file `test_*.py` ở root: test integration, crypto, UI widget, UI VNC, operational fault injection, formal verification.

Docker Compose dựng đủ môi trường thủ công:

- `chat-db`: MySQL 8.0, schema `chatdb`.
- `chat-server`: server C, WebSocket host port `18888`, HTTP control plane host port `18889`.
- `chat-auditor`: auditor API host port `18890`.
- `chat-client1`, `chat-client2`: client PyQt chạy trong container, expose VNC `5901`, `5902`.

## 2. Luồng khởi động server

Điểm vào là `server/main.c`.

Thứ tự chính:

1. `config_load()` đọc env vào singleton `g_config`.
2. OpenSSL tạo TLS context từ cert/key.
3. `db_connect()` kết nối MySQL, chạy migration và khởi tạo DB pool.
4. `clients_init()`, `metrics_init()`, `auth_init()`, `ratelimit_init()`.
5. `http_server_start()` mở `/healthz`, `/readyz`, `/metrics`.
6. Janitor thread đóng kết nối chưa login sau timeout.
7. Disappearing-message thread soft-delete message hết hạn.
8. Main loop `accept()` socket, tạo thread riêng cho mỗi client.

Mỗi client thread làm TLS handshake, WebSocket handshake, rồi đọc frame bằng `ws_recv()`. Message JSON được đưa vào `dispatch()`.

## 3. Dispatcher server

`dispatch()` trong `server/main.c` là cổng vào WebSocket command.

Command chưa cần auth:

- `auth`
- `register`

Mọi command khác phải qua `require_auth()`. Sau đó server chuyển theo bounded context:

- `friends_dispatch()`: kết bạn, danh sách bạn, request.
- `profile_dispatch()`: hồ sơ, avatar.
- `presence_dispatch()`: online/offline, privacy.
- `chat_dispatch()`: message, history, inbox, edit/delete, reaction, pin, forward, disappearing, conversation preferences.
- `groups_dispatch()`: prepare/apply OpenMLS group change, phát handshake và đọc group info.
- `keys_dispatch()`: key upload, PQXDH bundle, identity rotation, prekey, conversation key.
- `blocking_dispatch()`: block/unblock.

Khi thêm command mới, nên đặt ở service đúng domain thay vì phình `main.c`.

## 4. Tầng dữ liệu server

Code server chia tầng theo quy ước:

- `services/`: kiểm tra nghiệp vụ, auth/session, quyền truy cập, validation, tạo event trả client.
- `repository/`: truy cập MySQL, ưu tiên prepared statement khi có dữ liệu người dùng.
- `domain/`: validation và caller context.
- `infra/`: config, log, metrics, migration, DB pool, crypto helper, rate limit.
- `transport/`: WebSocket, HTTP, quản lý client online.

Quy tắc quan trọng khi sửa:

- Repository phải lấy connection bằng `db_pool_acquire()` và trả bằng `db_pool_release()`.
- Input từ client phải đi qua validation ở service/domain trước khi ghi DB.
- Message body là ciphertext. Server không được giải mã hoặc tạo plaintext preview.
- DB migration mới đặt ở `server/repository/migrations/` và phải chạy idempotent.
- Không hardcode env trực tiếp ở nhiều nơi; thêm field vào `Config` nếu là cấu hình server.

## 5. Schema và migration

Migration chạy trong `server/infra/migrate.c` theo thứ tự tên file `.sql`. Trạng thái lưu ở `schema_migrations`.

Các bảng lõi:

- `users`: tài khoản, email, hash mật khẩu, profile, status.
- `friendships`: quan hệ bạn bè.
- `conversations`: DM/group, tên group, trạng thái disband, disappearing timer.
- `conversation_members`: membership, read marker, hidden/archive/pin/mute preference.
- `messages`: ciphertext body, metadata edit/delete/reply/forward.
- `user_keys`: key bundle cũ và identity secret được client mã hóa.
- `conversation_keys`: key wrap cũ theo conversation.
- `identity_key_log`: append-only log cho auditor.
- `pqxdh_*`: bundle/prekey PQXDH.
- `mls_key_packages`: KeyPackage OpenMLS single-use do client upload.
- `mls_group_state`: GroupInfo/epoch công khai gần nhất để server định tuyến và kiểm tra operation.
- `mls_group_handshake`: Welcome, Commit, GroupInfo và control bytes để client replay khi login.
- `mls_pending_group_ops`: operation id cho prepare/apply group change.
- `group_roles`: quyền admin/member trong group.
- `notifications`: event offline chờ flush khi user login.

`tests/secchat_testlib.py::db_reset()` truncate các bảng trừ `schema_migrations`, nên reset test không chạy lại migration từ đầu.

## 6. Auth và mật khẩu

Client gửi password đã hash một lớp. Server không lưu hash đó trực tiếp mà PBKDF2 lại với salt server-side.

Luồng login trong `server/services/auth.c`:

1. Đọc `email` hoặc `username`, đọc password hash.
2. Rate limit theo khóa tổng hợp `(login, ip)`.
3. Tìm user bằng `user_repo_find_for_auth()`.
4. Verify PBKDF2 salt/derived.
5. Set status online, kick session cũ cùng uid, gắn uid vào slot client.
6. Trả `ok`, broadcast presence, flush notification offline.

Lưu ý: `tools/seed_demo_users.py` tạo đúng dạng hash mà server đang cần, không insert password plaintext.

## 7. Messaging server

`server/services/messaging_service.c` xử lý:

- `message`
- `history`
- `get_inbox`
- `start_dm`
- `edit_message`
- `delete_message`
- `typing_start`
- `typing_stop`

Server chỉ chấp nhận message body có prefix SecChat:

- `S3PQI:`: DM initial, kèm transcript bắt tay.
- `S3DR:`: DM sau khi có Double Ratchet state.
- `S3MLS:`: group application/control message được OpenMLS mã hóa.

Plaintext và prefix legacy bị từ chối cho message mới. History/inbox trả ciphertext hoặc prefix ciphertext; client tự decrypt và tự lấy preview từ cache local nếu có.

Edit message không ghi đè message gốc. Server append một message event mới có `edit_target_message_id`. Cách này giữ thứ tự ratchet và transcript replay.

Delete message là soft delete metadata, không cần giải mã body.

## 8. Group management

`server/services/groups.c` quản lý group ở mức server:

- Chỉ bạn bè mới được thêm vào group.
- Creator là admin ban đầu.
- Có thể có nhiều admin.
- Admin mới được kick, đổi role, đổi thông tin group, disband.
- Last admin không được tự demote nếu chưa promote người khác.
- Nếu last admin rời group, server auto-promote member cũ nhất.

Group flow dùng OpenMLS. Server kiểm tra quyền tạo nhóm, thêm thành viên, xóa thành viên, đổi role và đổi thông tin nhóm, nhưng không tự sinh group secret. Với thao tác cần thay đổi MLS membership, client gọi `prepare_group_change`, nhận operation id và KeyPackage đã claim nếu cần, sau đó OpenMLS bridge tạo Commit, Welcome và GroupInfo. Server chỉ cập nhật membership sau `apply_group_change` hợp lệ.

Role, tên nhóm, bio và avatar nhóm là control message được client mã hóa qua MLS application message. Server có thể lưu metadata hiển thị sau khi operation hợp lệ, nhưng không đọc được nội dung control plaintext.

## 9. Key management và identity transparency

`server/services/keys.c` quản lý key material mà client upload.

Các đường chính:

- `upload_keys`: legacy/compat, lưu Kyber/X25519/identity public và secret đã mã hóa client-side.
- `rotate_identity`: đường chính để đổi identity key thật sự, bump `identity_version`, ghi `identity_key_log`, gửi notification cho peer.
- `upload_pqxdh_bundle`: lưu bundle SecChat gồm signed curve prekey, signed PQ KEM prekey và one-time prekeys.
- `get_pqxdh_bundle`: trả bundle peer và consume one-time prekey nếu còn.
- `get_my_keys`, `get_my_pqxdh_status`: hỗ trợ client khôi phục/kiểm tra trạng thái key.

Server không có master key client nên không đọc được `identity_sk_enc` hoặc local state. Tuy vậy việc lưu encrypted identity secret trên server vẫn là tradeoff bảo mật: nếu DB lộ và password yếu, nguy cơ brute-force tăng.

Auditor:

- `auditor_service.py` đọc `identity_key_log`.
- Dựng Merkle tree theo append order.
- Ký checkpoint bằng Ed25519.
- Trả `/checkpoint`, `/identity/<uid>`, `/identity/<uid>/<version>/proof`, `/consistency`.

Client kiểm tra proof trong `client/crypto_engine/audit.py` trước khi tin identity bundle của peer.

## 10. Client controller

`client/app.py` là controller chính. Nó nối:

- UI pages: login/register/chat.
- `WSNet`: WebSocket TLS client.
- `CryptoSession`: state và thao tác E2EE.

Controller chịu trách nhiệm quyết định khi nào:

- login/register/logout;
- upload/fetch key bundle;
- queue message trong lúc chờ key;
- decrypt event live/history;
- refresh inbox/friends/profile;
- chặn gửi nếu identity audit yêu cầu user review;
- gọi UI cập nhật trạng thái.

Controller không nên chứa primitive mật mã thấp tầng. Khi cần sửa mã hóa, ưu tiên sửa `client/crypto_engine/`.

`_session_gen` và `WSNet._gen` là cơ chế chống callback stale: sau logout/reconnect, event từ socket cũ không được cập nhật UI/session mới.

## 11. WebSocket client

`client/network.py::WSNet` là client TLS + WebSocket tự viết.

Điểm cần nhớ:

- Client pin cert server qua `/certs/chat.crt` trong Docker hoặc `.tmp_cert` khi chạy native.
- Nếu cert thiếu thì fail closed, không downgrade sang insecure.
- Receive loop chạy daemon thread và emit Qt signal về main thread.
- Frame client gửi lên server luôn mask đúng chuẩn WebSocket.

Test helper `tests/secchat_testlib.py` dùng raw socket riêng để test server mà không cần PyQt.

## 12. Crypto engine

`client/crypto_engine/secure_protocol.py` chứa primitive SecChat:

- Prefix wire format `S3PQI`, `S3DR`, `S3MLS`.
- ML-KEM/Kyber wrapper qua `oqs`.
- X25519, Ed25519.
- Signed prekey bundle.
- PQXDH-style initial handshake.
- Double Ratchet state: session id, header key, AAD canonical, skipped-key
  cache giới hạn, replay check và session map để xử lý hai bên start DM đồng
  thời.
- wrapper wire cho `S3MLS`.

SecChat mượn ý tưởng từ Signal PQXDH và Double Ratchet, nhưng không wire-compatible với Signal.

`client/crypto_engine/openmls_bridge.py` là wrapper JSON cho binary Rust
`secchat_mls_bridge`. Bridge này được build trong Docker từ `mls_bridge/` bằng
OpenMLS 0.8.1 và là runtime group E2EE hiện tại. Các command chính gồm
`init_identity`, `top_up_key_packages`, `create_group`, `add_members`,
`remove_members`, `join_from_welcome`, `process_commit`,
`encrypt_application`, `decrypt_application` và `selftest`.

`client/crypto_engine/session.py` chứa state cấp ứng dụng:

- Identity key, Kyber/X25519 key.
- PQXDH local prekeys.
- DM Double Ratchet states.
- MLS group states qua OpenMLS bridge.
- Safety number verification.
- Identity audit state.
- Plaintext cache đã mã hóa local.
- Backup/restore E2EE state.
- Transcript checkpoint và MLS group handshake replay.

State nằm trong `~/.secchat/<username>/` và được bọc bằng master key dẫn xuất từ mật khẩu login.

## 13. Local cache và backup

Plaintext cache là tính năng usability, không phải bảo mật tuyệt đối:

- Giúp đọc lại history sau relogin khi ratchet đã tiến.
- Được mã hóa lại bằng master key local.
- Có policy bật/tắt toàn cục, TTL, clear on logout, disable theo conversation.
- Nếu đăng nhập trên VNC/container khác không có cache hoặc backup, message cũ có thể không decrypt được và UI sẽ ẩn message không đọc được.

Backup E2EE là snapshot local có passphrase riêng:

- Có manifest/version/generation.
- Có thể bao gồm hoặc không bao gồm cache.
- Restore re-wrap state bằng master key hiện tại.
- Không phải sync multi-device liên tục.

## 14. Test runner và nhóm test

Điểm vào test chung: `tests/run_all_tests.py`.

Các category chính:

- `legacy`: test root cũ còn dùng flow integration rộng.
- `server_contract`: HTTP, privacy, notification, rate limit, limits, operational fault injection.
- `crypto_contract`: crypto/session/history/relogin.
- `ui_widget`: PyQt widget tests offscreen.
- `ui_vnc`: E2E thật qua VNC containers.
- `formal`: ProVerif wrapper.

Lệnh thường dùng (chạy bằng Python của `.venv`):

```powershell
$env:QT_QPA_PLATFORM='offscreen'
$env:CHAT_PORT='18888'
$env:CHAT_HTTP_PORT='18889'
.venv\Scripts\python.exe tests\run_all_tests.py --timeout 600
```

Khi chỉ sửa server contract, có thể chạy:

```powershell
.venv\Scripts\python.exe tests\run_all_tests.py --category server_contract --timeout 600
```

## 15. Quy trình kiểm tra sau khi sửa

Sau mỗi hướng thay đổi quan trọng:

1. Build/restart Docker nếu đụng server, schema, Dockerfile hoặc runtime dependency.
2. Chạy test category gần nhất với thay đổi.
3. Nếu thay đổi đụng crypto/chat/auth/group/key, chạy thêm full runner hoặc ít nhất category liên quan.
4. Kiểm tra `/readyz` và `/metrics` nếu sửa server lifecycle/control plane.
5. Reset Docker volume nếu cần môi trường sạch cho kiểm tra thủ công.
6. Seed user demo bằng `tools/seed_demo_users.py`.

Reset thủ công:

```powershell
docker compose down -v
docker compose up -d --build
```

Seed user demo:

```powershell
.venv\Scripts\python.exe tools\seed_demo_users.py
```

User demo sau khi seed:

- `123@gmail.com` / `123456`
- `234@gmail.com` / `123456`
- `345@gmail.com` / `123456`

## 16. Các điểm dễ gây lỗi khi sửa

- Đừng để server ghi plaintext message hoặc preview plaintext vào DB.
- Đừng đổi identity key bằng `upload_keys`; phải dùng `rotate_identity`.
- Đừng tạo self-DM/Saved Messages mới: `start_dm` hiện chặn `other_uid == my_uid`.
- Khi sửa group membership, client phải tạo OpenMLS Commit/Welcome/GroupInfo rồi server mới apply metadata.
- Khi sửa history/inbox, giữ filter không làm lộ control message không nên hiển thị như user message.
- Khi sửa cache, đảm bảo logout và account switch không dùng nhầm state của account trước.
- Khi sửa WebSocket, phải giữ frame parsing/masking/size limit và TLS pinning.
- Khi sửa migration, nhớ DB test reset không drop `schema_migrations`.
- Khi sửa test, dùng `recv_until()` thay vì drain mù để tránh lệch WebSocket frame.

## 17. File nên đọc theo thứ tự

Nếu cần onboard nhanh, đọc theo thứ tự này:

1. `docker-compose.yml`
2. `server/main.c`
3. `server/services/auth.c`
4. `server/services/messaging_service.c`
5. `server/services/groups.c`
6. `server/services/keys.c`
7. `server/repository/migrations/0001_initial_schema.sql` và migration mới nhất
8. `client/main.py`
9. `client/network.py`
10. `client/app.py`
11. `client/crypto_engine/secure_protocol.py`
12. `client/crypto_engine/session.py`
13. `client/crypto_engine/audit.py`
14. `auditor_service.py`
15. `tests/run_all_tests.py`
16. `tests/secchat_testlib.py`

