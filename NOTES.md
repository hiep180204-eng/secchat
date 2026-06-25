# Ghi chú phát triển SecChat

File này ghi lại các quyết định kỹ thuật quan trọng của repo. Nội dung được
viết bằng tiếng Việt để người đọc đồ án có thể đối chiếu nhanh với codebase.

## Ghi chú đọc codebase

Đọc trước `docs/codebase_walkthrough_vi.md` nếu cần nắm nhanh kiến trúc hiện tại,
luồng server/client/crypto/auditor, cách chạy test và quy trình reset Docker +
seed user demo sau khi thay đổi.

## Trạng thái giao thức hiện tại

SecChat hiện dùng wire S3 cho traffic mới. Body message hợp lệ trên server
phải có một trong các prefix sau:

- `S3PQI:` cho tin nhắn DM đầu tiên, kèm transcript bắt tay kiểu PQXDH.
- `S3DR:` cho tin nhắn DM sau khi đã có Double Ratchet state.
- `S3MLS:` cho group application message hoặc control message được mã hóa
  bằng MLS.

Các format cũ như `E2R:`, `E2RK:`, `E2GS:`, `E2E:` và `__KEM_INIT__` là legacy
và không còn được chấp nhận cho tin nhắn mới. Dữ liệu cũ nếu còn trong database
chỉ nên xem là dữ liệu trước cutover.

SecChat không phải Signal wire compatibility. Hệ thống chỉ áp dụng các ý tưởng
từ Signal PQXDH và Double Ratchet vào một wire format riêng của SecChat. DM mới
có `session_id`, AAD canonical ràng buộc conversation/sender/receiver, encrypted
header copy, skipped-key cache giới hạn, replay set và session map để xử lý
trường hợp hai bên cùng start conversation.

Backup E2EE hiện là format version 3. Export lưu thêm DR session map; khi import
sau khi đã rotate identity, client chỉ merge cache/history hợp lệ ở chế độ
historical và không publish lại identity cũ.

## Quyết định về group và MLS RFC 9420

Group runtime mới đi qua Rust OpenMLS bridge ở `mls_bridge/` và wrapper Python
`client/crypto_engine/openmls_bridge.py`. Bridge dùng OpenMLS 0.8.1 với
ciphersuite draft hybrid
`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`. X-Wing ở đây là hybrid
ML-KEM-768 + X25519 cho confidentiality/HNDL của group; authentication vẫn là
Ed25519 cổ điển. Không claim PQ signature, interop MLS cross-vendor, hoặc final
RFC/IANA cho PQ MLS.

Client tạo KeyPackage, Welcome, Commit, GroupInfo, RatchetTree và application
message. Server kiểm tra policy, verify chữ ký SecChat trên KeyPackage trước khi
lưu, rồi dùng OpenMLS `PublicGroup` để validate public GroupInfo/Commit trước
khi ghi handshake hoặc mutate membership. Server vẫn không giữ group secret và
không giải mã payload group.

Luồng thay đổi group có hai bước server-side:

- `prepare_group_change`: server kiểm tra policy trước, claim KeyPackage
  single-use nếu cần thêm member và tạo operation id.
- `apply_group_change`: client gửi Commit, GroupInfo, Welcome hoặc encrypted
  control message do OpenMLS sinh; server chỉ áp membership sau khi public MLS
  validation pass và expected member set khớp pending operation.

Role, tên nhóm, bio và avatar nhóm là app-level control message được gửi qua
MLS application message. Thành viên bị remove không nhận secret epoch mới và
OpenMLS đánh dấu group của họ inactive sau khi xử lý Commit remove. Server không
tự sinh secret group, không giải mã payload group và không có parser cho
ciphertext group cũ trong flow reset sạch.

Header group không dùng nút `Review identity`. Safety number và identity review
là ceremony một-một cho DM; group hiển thị trạng thái MLS/PQ và các cảnh báo
thật về consistency, history, connection hoặc MLS control. Nếu cần kiểm tra
identity của từng thành viên, người dùng mở profile hoặc member detail của
người đó.

Các thay đổi membership như thêm thành viên, xóa thành viên, rời nhóm, đổi role
và cập nhật thông tin nhóm được render thành system event trong client. Server
lưu các event này trong `group_system_events` như metadata timeline persisted,
kèm `operation_id`, `after_message_id`, actor, target và snapshot `members`.
History trả `system_events` tách riêng với `messages`: body tin nhắn người dùng
vẫn là ciphertext E2EE, còn system event chỉ là metadata membership server đã
biết. Client dùng `after_message_id` để xếp event đúng giữa các tin nhắn, dùng
`system_event_id`/`operation_id` để chống duplicate giữa realtime notification
và history replay, đồng thời vẫn giữ local transient event nếu history chưa kịp
trả event persisted.

## Minh bạch khóa định danh

SecChat có auditor service riêng cho lịch sử identity key. Chat server ghi event
identity vào `identity_key_log`. Auditor dựng Merkle tree, ký checkpoint và trả
proof cho client.

Khi client nhận `pqxdh_bundle`, client kiểm tra:

- identity key trong bundle khớp leaf đã audit;
- identity version khớp;
- inclusion proof hợp lệ;
- chữ ký checkpoint hợp lệ;
- checkpoint không rollback so với checkpoint đã thấy trước đó.

Nếu proof sai, checkpoint rollback hoặc key trong bundle không khớp log, client
đánh dấu audit warning và buộc người dùng review identity trước khi gửi tiếp.

Auditor hiện vẫn là service trong cùng project Docker. Đây là mô hình tốt cho
đồ án, nhưng chưa phải hạ tầng key transparency phân tán cấp production.

## Điểm kiểm tra transcript

Client có thể ký checkpoint cho transcript group mà nó đã thấy. Checkpoint ghi
message count, last message id, transcript head và hash checkpoint trước.

Khi member khác nhận checkpoint, client so sánh với view local tại cùng message
id. Nếu server cho các client thấy thứ tự khác nhau, sửa message đã thấy hoặc
rollback view của một peer, client có thể phát hiện và cảnh báo.

Cơ chế này không che metadata và không ngăn server drop hoặc delay message. Nó
chỉ giúp phát hiện một số dạng split-view và history không nhất quán.

## Kiến trúc server

```text
server/
  main.c                  vòng accept TLS, tạo thread, xử lý signal
  transport/              WebSocket, HTTP control plane, danh sách client
  protocol/               helper JSON dựa trên cJSON
  infra/                  config, migration, db pool, metrics, log, rate limit
  domain/                 validate input và caller context
  repository/             truy cập MySQL, ưu tiên prepared statement
  services/               auth, message, group, key, reaction, pin, profile...
```

Các nguyên tắc quan trọng:

- Repository phải dùng `db_pool_acquire()` và `db_pool_release()`.
- Query có dữ liệu từ client nên dùng `MYSQL_STMT`.
- Config đi qua `g_config`, không gọi `getenv()` rải rác.
- Validation nằm ở `domain/validation.h` và service phải gọi trước khi ghi DB.
- `clients_send_to_uid` gửi tới tất cả session đang online của một uid.

## Kiến trúc client

Client có UI PyQt, networking WebSocket và crypto engine tách riêng.

Các file chính:

- `client/app.py` điều phối event giữa UI, network và crypto engine.
- `client/pages/chat_page.py` dựng UI chat, message list, menu, profile, privacy
  và backup.
- `client/network.py` xử lý kết nối WebSocket.
- `client/crypto_engine/secure_protocol.py` chứa primitive giao thức hiện tại:
  PQXDH-style, Double Ratchet và envelope message bảo mật.
- `client/crypto_engine/session.py` quản lý local encrypted state, plaintext
  cache, backup, transcript và trạng thái OpenMLS cho group qua `MlsBridge`.
- `client/crypto_engine/audit.py` kiểm tra proof từ auditor service.

UI controller không nên tự sở hữu logic mật mã chi tiết. Nếu cần sửa mã hóa,
ưu tiên sửa trong `client/crypto_engine/`.

## Bộ nhớ đệm cục bộ và backup

Plaintext cache giúp preview và history cũ vẫn đọc được sau relogin, đặc biệt
khi ratchet đã tiến và không còn message key cũ. Cache được mã hóa bằng master
key nhưng vẫn là dữ liệu nhạy cảm trên thiết bị.

Người dùng có thể:

- tắt cache toàn cục;
- đặt thời gian giữ cache;
- xóa cache thủ công;
- xóa cache khi logout;
- tắt cache riêng cho conversation nhạy cảm.

Backup E2EE là file cục bộ được mã hóa bằng passphrase riêng. Backup có format
version, backup id, generation, manifest và tùy chọn có bao gồm cache hay không.
Restore sẽ re-wrap state bằng master key hiện tại, merge cache theo message id
và cho phép client công bố lại PQXDH bundle mới nếu identity secret được khôi
phục. Backup là snapshot cục bộ, không phải đồng bộ liên tục giữa nhiều VNC.

Group MLS hiện đã có persistence: bridge Rust chạy OpenMLS, export toàn bộ
OpenMLS storage và signer state thành snapshot, sau đó Python client lưu vào
`mls_state.bin` đã mã hóa bằng master key cục bộ. Backup E2EE gom file này
như các state khác, nên restore trên VNC khác có thể nạp lại MLS identity,
KeyPackage state và group state. Khi rotate safety key, client xóa MLS state cũ
để không publish lại KeyPackage đã bind với identity cũ.

Giới hạn quan trọng: nếu người dùng mất máy và không có file backup, server
không thể tự khôi phục E2EE state cũ. Nếu quên mật khẩu tài khoản, backup không
tự giúp đăng nhập server.

Server lưu thêm `identity_sk_enc`, tức identity secret đã được client mã hóa
bằng master key dẫn xuất từ mật khẩu. Mục đích là cho cùng một account khi đăng
nhập ở VNC khác có thể tạo và ký PQXDH prekey mới hợp lệ, nhờ vậy người khác có
thể bắt đầu hội thoại mới kể cả khi account đó offline. Dữ liệu này không đồng
bộ plaintext cache, Double Ratchet state hoặc MLS group state; lịch sử cũ trên máy
mới vẫn không đọc được nếu không có cache/backup. Đây là đánh đổi rõ ràng: server
không đọc được identity secret nếu không có mật khẩu, nhưng bản sao mã hóa trên
server vẫn làm tăng rủi ro brute-force nếu mật khẩu yếu hoặc server bị lộ DB.

SecChat hiện không hỗ trợ liên kết nhiều thiết bị/VNC cho cùng một tài khoản.
Nếu đăng nhập cùng tài khoản ở VNC khác chưa có local E2EE state hoặc plaintext
cache, các tin cũ không giải mã được sẽ bị ẩn khỏi UI thay vì hiện placeholder
như `[Forward-secret]` hoặc `[Encrypted message - MLS state unavailable]`.
Khi đăng nhập lại đúng VNC/tài khoản còn cache, history cũ vẫn phải hiển thị
đúng thứ tự. Nếu VNC mới có `identity_sk_enc` hoặc restore được identity secret
từ backup, client có thể bắt đầu đoạn chat mới bằng bundle mới dưới cùng safety
identity. Nếu không có identity secret, không được silent rotate; người dùng
phải restore, backfill từ VNC cũ hoặc chủ động rotate safety key. Đây là hành vi
chủ đích cho đến khi có thiết kế multi-device key linking thật sự.

## Vận hành và bảo mật server C

Server viết bằng C nên cần chú ý memory safety. Repo đã có các công cụ hỗ trợ:

- `tools/security_audit.py` quét heuristic các vùng rủi ro.
- `tools/run_server_c_audit.py` chạy audit trong Docker, gồm static analysis,
  sanitizer build và fuzz smoke test.
- `server/fuzz/` chứa fuzz target cho WebSocket frame và JSON validation.

Các vùng cần kiểm tra khi sửa server:

- WebSocket parser;
- JSON input và JSON escaping;
- buffer cho message lớn;
- prepared statement và đường lỗi MySQL;
- giới hạn kích thước input;
- rate limit;
- cleanup khi socket hoặc database lỗi.

Đây là hygiene mạnh cho đồ án, nhưng chưa phải production audit hoàn chỉnh. Muốn
tiến gần production cần fuzzing dài hạn trong CI, fault injection sâu hơn và
review thủ công các đường cấp phát lớn.

## Kiểm chứng hình thức

Repo có mô hình ProVerif bước đầu ở `formal/proverif/secchat_dm.pv`. Mô hình
này kiểm tra luồng DM sau khi identity key của responder đã được xác minh
hoặc pin bằng safety number.

Mô hình không bao phủ UI, local file, cache, database, metadata, server C memory
safety hoặc group protocol. Vì vậy chỉ nên nói SecChat đã có bước formal
verification ban đầu cho DM, không nói toàn bộ hệ thống đã được formal verify.

Chạy bằng:

```powershell
python tools\run_formal_verification.py --download --require
```

## Các lệnh kiểm tra thường dùng

Chạy toàn bộ test:

```powershell
python tests\run_all_tests.py --timeout 600
```

Chạy test crypto session:

```powershell
python -m unittest tests.test_crypto_session -v
```

Chạy test UI flow:

```powershell
$env:QT_QPA_PLATFORM='offscreen'
python -m unittest tests.test_client_ui_user_flows -v
```

Chạy audit server C:

```powershell
python tools\run_server_c_audit.py
```

Kiểm tra message body trong database:

```powershell
docker exec -it chat-db sh -lc 'MYSQL_PWD="$MYSQL_PASSWORD" mysql -uchatuser --table chatdb -e "SELECT id, conversation_id, sender_id, CASE WHEN body LIKE '\''S3PQI:%'\'' THEN '\''DM initial S3PQI'\'' WHEN body LIKE '\''S3DR:%'\'' THEN '\''DM ratchet S3DR'\'' WHEN body LIKE '\''S3MLS:%'\'' THEN '\''Group/control S3MLS'\'' ELSE '\''OTHER/PLAINTEXT?'\'' END AS wire_type, LEFT(body, 90) AS body_prefix, edit_target_message_id, sent_at FROM messages ORDER BY id DESC LIMIT 30;"'
```

## Reset Docker cho kiểm tra thủ công

Khi cần môi trường sạch:

```powershell
docker compose down -v
docker compose up -d --build
```

Sau khi reset, tạo lại user mẫu nếu cần kiểm tra UI:

```powershell
python tools\seed_demo_users.py
```

Script này tạo hoặc sửa ba user mẫu để login bằng đúng hash mà UI đang dùng:

- `234@gmail.com` với mật khẩu `123456`
- `123@gmail.com` với mật khẩu `123456`
- `345@gmail.com` với mật khẩu `123456`

## Checklist thủ công hiển thị trên VNC

Checklist visible dùng để chạy lại luồng kiểm tra thủ công từ đầu đến cuối trên
hai màn hình VNC thật của `chat-client1` và `chat-client2`. Script riêng sẽ reset
Docker, bật probe UI, build lại container, chờ server/auditor sẵn sàng, seed ba
user mẫu ở trên rồi chạy automation bằng `xdotool` và `scrot`. Test này không
dùng `QT_QPA_PLATFORM=offscreen`.

Chạy nhóm core:

```powershell
powershell -ExecutionPolicy Bypass -File tools\run_visible_manual_checklist.ps1
```

Chạy thêm nhóm destructive, gồm stop/start auditor và server:

```powershell
powershell -ExecutionPolicy Bypass -File tools\run_visible_manual_checklist.ps1 -IncludeDestructive
```

File test `tests/test_visible_manual_checklist_vnc.py` có gate bắt buộc
`SECCHAT_VISIBLE_MANUAL=1`, do script trên tự set. Không thêm file này vào
`NEW_TESTS`, `UI_VNC_TESTS` hoặc runner mặc định. Artifact mỗi lần chạy nằm trong
`tests/artifacts/visible_manual_checklist/<timestamp>/`, gồm screenshot theo
chương lớn; khi fail sẽ ghi thêm bước đang chạy, snapshot UI và log container.

Khi chạy test từ host Windows, dùng Python của môi trường ảo `.venv` của repo (đã có
PyQt5, cryptography, oqs và PyMySQL):

```powershell
$env:QT_QPA_PLATFORM='offscreen'
$env:CHAT_PORT='18888'
$env:CHAT_HTTP_PORT='18889'
.venv\Scripts\python.exe tests\run_all_tests.py --timeout 600
```

## Các tài liệu nên đọc

- `docs/system_security_spec_vi.md`: đặc tả bảo mật toàn hệ thống.
- `docs/secchat_protocol_spec_vi.md`: đặc tả giao thức chi tiết.
- `docs/secchat_protocol_design.md`: bản giải thích ngắn gọn về giao thức hiện tại.
- `docs/missing_capabilities_plain_vi.md`: những điểm còn thiếu nếu bỏ qua QKD
  và phần cứng đặc thù.
- `docs/identity_transparency_design_vi.md`: thiết kế identity transparency.
- `docs/mls_rfc9420_feasibility_vi.md`: lịch sử đánh giá và quyết định chuyển group sang OpenMLS.
- `docs/security_audit_checklist.md`: checklist bảo mật server C.
## Ghi chu sua loi E2EE ngay 2026-06-01

- Restore backup sau khi user da rotate safety key khong duoc rollback identity
  len server nua. Neu backup co fingerprint khac identity hien tai va client
  biet server dang dung identity hien tai, restore chi merge `msgs_*.bin`
  plaintext cache de hien lai lich su doc duoc; identity, prekey, ratchet, group,
  verification va audit state hien tai duoc giu nguyen.
- Restore tren VNC moi bi chan vi thieu `identity_sk_enc` van la full restore:
  backup co the khoi phuc identity cu, publish lai bundle hop le va tiep tuc
  doc/nhan tin nhu truoc.

## Ghi chu sua loi PQXDH mixed prekey ngay 2026-06-01

- Server cu co the tra bundle bi tron the he: signed prekey moi nhung OTK cu.
  Huong sua hien tai uu tien flow reset sach: server phai khong bao gio phat
  bundle bi tron generation, con client chi dung prekey store hien tai.
- `key_pqxdh_upload_bundle()` hien xoa OTK PQXDH cu cua user ngay khi signed bundle
  moi duoc upload thanh cong. Sau do server moi chen batch OTK moi, nen
  `get_pqxdh_bundle` khong con ghep signed prekey moi voi OTK cu.
- Khong them fallback cuu ciphertext legacy/mixed-generation tren client. Neu
  server lai phat sai generation, luong reset sach se fail ro rang de sua o
  server thay vi che loi bang viec thu cac private prekey cu.

## Ghi chu bao loi audit ngay 2026-06-02

- Moi loi identity transparency/auditor tren client phai co `last_error_code`
  on dinh ben canh `last_error`. UI dung code nay de hien thi dung loai loi,
  vi du `identity_version_not_found`, `identity_key_mismatch`,
  `proof_root_mismatch`, `checkpoint_rollback`, `checkpoint_split_view`,
  `checkpoint_signature_invalid`, `auditor_http_error` hoac
  `auditor_unavailable`.
- HTTP 404 `identity version not found` tu auditor khong duoc ghi thanh
  auditor unavailable. Day la loi audit cua identity/version trong log, nen
  phai hien thi dung la version khong co trong auditor log.
- Khi audit thanh cong lai, `record_identity_audit_ok()` xoa `last_error` va
  `last_error_code`; khi key rotation that su xay ra thi khong giu lai code loi
  audit cu.

## Ghi chu visible manual checklist ngay 2026-06-07

- `tools/run_visible_manual_checklist.ps1` la entrypoint rieng cho walkthrough UI
  hien thi tren hai VNC/noVNC. Test bi gate bang `SECCHAT_VISIBLE_MANUAL=1` va
  khong nam trong runner mac dinh.
- Core walkthrough da bao phu dang ky/dang nhap, friend/block, DM, group,
  audit short code, edit/delete/reply/forward/pin/reaction, file, avatar/profile,
  privacy/cache, doi mat khau, export/import E2EE, rotate safety key, search,
  metrics/log va DB ciphertext-only. Nhom destructive chi chay khi truyen
  `-IncludeDestructive`.
- Forward hien tai khong ghi `forwarded_from_id` vao DB. Source message cua
  forward nam trong `SCMSG` da ma hoa de server khong thay metadata nay; vi vay
  test kiem tra forward bang UI label `Forwarded`, con DB chi assert cac metadata
  server bat buoc nhu reply/edit/delete/reaction/group role/identity log.

## Ghi chu edge case visible manual ngay 2026-06-07

- Visible walkthrough da them cac edge case chay bang thao tac that tren noVNC:
  blocked DM send, blank message, cancel/no-member group creation, cancel
  reaction/edit/forward/delete, cancel attach, file rong, invalid backup, wrong
  backup passphrase, cancel rotate safety key, search khong co ket qua va blank
  search. Cac case nay van dung UI probe chi de dinh vi/assert, khong bypass logic.
- Khi server tra loi tu choi gui nhu `Cannot send message (blocked)`, client phai
  chuyen pending bubble sang failed bubble thay vi de `Sending` treo. Loi nay duoc
  test bang user345 gui DM sau khi bi user123 block; DB count phai khong tang va
  user123 khong nhan plaintext/ciphertext moi.
- Restore backup sai passphrase phai bao ro `Backup could not be decrypted...`
  thay vi hien hop thoai trong rong do `InvalidTag` khong co text mac dinh.
- Forward dialog khong duoc dua vao target mac dinh. Khi co them DM user345,
  target dau tien co the la DM khac; walkthrough chon dung combo item
  `Group: <ten group>` truoc khi bam OK.

## Ghi chu danh gia crypto ngay 2026-06-07

- Xem `docs/crypto_assessment_vi.md` de biet danh gia hien trang KEM/PQXDH,
  Double Ratchet, Forward Secrecy va MLS theo code thuc te.
- Cap nhat sau nang cap PQ MLS: group moi dung X-Wing draft hybrid
  ML-KEM-768 + X25519; server validate public MLS state/commit bang OpenMLS
  `PublicGroup` truoc khi mutate membership; KeyPackage sai ciphersuite hoac sai
  chu ky SecChat bi reject server-side.
- Gioi han con lai: identity audit tren UI hien la warning-only, MLS signatures
  van la Ed25519 classical authentication, chua co PQ signature hay interop final
  RFC/IANA cho PQ MLS; group state cu can reset/migrate sach.

## Ghi chu sua warning, context menu va unread ngay 2026-06-07

- Identity state va history/group warning phai nam o hai bucket rieng. Trang
  thai chua review safety number chi hien `Review identity` va guidance
  `conversation is not verified`; khong ghi vao `_security_warnings`, khong hien
  `History warning` va khong lam nut `Details` xuat hien neu khong co warning
  history/group/connection that.
- Unread state dung cursor `conversation_members.last_read_message_id`. Client
  gui `mark_read.last_message_id` la message id lon nhat dang thay trong
  conversation; server fallback bang max visible message id neu client cu khong
  gui field nay. Inbox tinh unread bang `messages.id > last_read_message_id`,
  khong dung `sent_at > last_read_at` nua de tranh loi do DATETIME chi toi giay.
- Context menu trong chat UI khong dung `QMenu` native cho friend, DM, group,
  search result, group member va message actions nua. Cac menu nay dung
  `secchatContextPopover` bang `QFrame`/`QPushButton`; van ho tro keyboard
  navigation kieu QMenu de visible checklist co the right-click, bam Down va
  Enter.

## Ghi chu sidebar native paint va unread stale ngay 2026-06-07

- Sidebar friend/DM/group da dung custom row widget thi khong duoc giu text o
  `QListWidgetItem.DisplayRole`. Text logic cho test/probe nam o
  `SIDEBAR_TEXT_ROLE`, con DisplayRole de rong va native item hover/selected
  trong stylesheet de transparent de tranh Qt paint lai UI cu phia sau row moi.
- Khi client da doc toi `last_message_id` va gui `mark_read`, inbox response cu
  khong duoc bat lai unread neu `last_message_id <= _last_read_sent[conv_id]`.
  `mark_read`/mo conversation clear ca `_unread_convs`, `unread_count` va
  `force_unread` trong record local; `mark_unread` thu cong van set unread rieng
  cho user hien tai.

## Ghi chu scroll, restore cache va refactor ngay 2026-06-08

- Khi mo DM/group, timeline phai vao tin moi nhat. Neu nguoi dung da keo len de
  doc tin cu thi history reload, live message va redraw khong duoc tu keo xuong
  day nua. Cac list co scroll nhu DM/group/friend/search/request cung phai giu
  vi tri sau refresh; cac list ngan hon viewport duoc normalize ve top de tranh
  click/hover lech item.
- Message list va helper scroll duoc tach sang `client/components/` de
  `ChatPage` chi giu orchestration UI. Cac test legacy script duoc gom vao
  `tests/legacy/`; artifact runtime nam trong `tests/artifacts/` va bi ignore.
  File `1.png` la avatar demo hop le va duoc giu lai bang exception trong
  `.gitignore`.
- Restore E2EE backup theo che do giu identity hien tai phai merge cache roi
  request lai history cua conversation dang mo. Khi cache hien tai co placeholder
  nhu `[Forward-secret]` nhung backup co plaintext cung message id, client phai
  uu tien plaintext tu backup de lich su cu hien lai sau rotate safety key.
- Cac suite DB/integration khong duoc chay song song voi nhau, dac biet
  `test_operational_fault_injection.py` vi test nay co chu y tam dung DB/server.
  Chay song song se tao loi gia nhu TLS handshake timeout hoac DB reset tranh
  chap; neu can aggregate thi dung `tests/run_all_tests.py` theo thu tu.
