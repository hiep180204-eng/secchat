# Đánh giá crypto SecChat

Cập nhật: 2026-06-07

## Phạm vi đọc

Đánh giá này dựa trên code hiện tại trong:

- `client/crypto_engine/secure_protocol.py`
- `client/crypto_engine/session.py`
- `client/crypto_engine/openmls_bridge.py`
- `client/app.py`
- `mls_bridge/src/main.rs`
- `server/services/keys.c`
- `server/services/messaging_service.c`
- `server/services/groups.c`
- `server/domain/validation.c`
- `server/repository/key_repo.c`
- các test trong `tests/`
- các đặc tả trong `docs/`

## Kết luận ngắn

SecChat hiện có E2EE nội dung ở mức khá tốt cho demo/luận văn: DM dùng
PQXDH lai hậu lượng tử + X25519 để khởi tạo, sau đó dùng Double Ratchet;
group dùng OpenMLS qua Rust bridge với X-Wing draft hybrid ML-KEM-768 +
X25519. Server không giải mã nội dung tin nhắn và wire mới bị giới hạn ở
`S3PQI:`, `S3DR:`, `S3MLS:`.

Không nên mô tả hệ thống là production-grade, Signal-compatible, MLS
interoperable đầy đủ, formally verified end-to-end, hay post-quantum
authentication. Các giới hạn quan trọng nhất là: identity audit trên UI đang là
cảnh báo chứ không hard-block, MLS PQ hiện theo draft X-Wing chưa phải RFC/IANA
final, signatures vẫn là Ed25519 classical, và endpoint/local cache vẫn là phần
rất nhạy cảm.

## KEM / PQXDH

Điểm đã có:

- DM initial handshake dùng KEM từ liboqs, mặc định `ML-KEM-1024`; server cho
  phép `ML-KEM-1024`, `Kyber1024`, `ML-KEM-768`, `Kyber768`.
- Signed prekey và one-time prekey có chữ ký Ed25519 từ identity key.
- Initiator kết hợp shared secret KEM với các DH X25519 rồi HKDF thành root
  key cho Double Ratchet.
- KEM algorithm, key id, identity version và transcript được bind vào AAD nên
  không phải ciphertext KEM rời rạc dễ bị downgrade im lặng.
- Server chỉ lưu/phát public bundle và consume one-time prekey; private prekey
  nằm phía client.

Giới hạn:

- Nếu thiếu `liboqs`, client không tạo/giải PQXDH được; code sẽ fail rõ ràng.
- Server không verify chữ ký prekey/PQXDH bundle; client verify ở crypto layer.
- Luồng audit identity/auditor trong `client/app.py` hiện ghi cảnh báo nhưng
  vẫn cho tiếp tục key exchange/send. Nếu threat model yêu cầu transparency
  mismatch phải chặn MITM, đây là khoảng cách quan trọng cần sửa.
- `key_pqxdh_get_bundle_consuming()` lấy và xóa curve OTK/PQ OTK theo nhiều câu
  SQL, chưa có transaction bao toàn bộ cặp OTK. Với demo là chấp nhận được,
  nhưng production nên khóa/consume nguyên bundle generation atomically.
- `identity_sk_enc` được lưu server-side ở dạng mã hóa để hỗ trợ đăng nhập lại
  trên client mới. Thiết kế này tiện dụng nhưng tăng rủi ro brute force nếu mật
  khẩu yếu hoặc client KDF bị cấu hình kém.

## Double Ratchet

Điểm đã có:

- Có Double Ratchet custom kiểu Signal: X25519 DH ratchet, root chain, send/recv
  chain, per-message key, replay detection, skipped-message-key cache và giới
  hạn `MAX_SKIP_KEYS`.
- Message AAD bind `session_id`, `conversation_id`, sender/recipient uid,
  identity version, DH public key và counter.
- Có encrypted-header copy và rollback state nếu decrypt fail trong
  `CryptoSession`.
- State Double Ratchet được lưu local ở dạng mã hóa theo master key.
- Simultaneous DM start có session map để hội tụ về session canonical.

Giới hạn:

- Đây là implementation riêng, không phải Signal Protocol wire-compatible và
  chưa có audit độc lập.
- Header/routing metadata như conversation id, uid, session id, counter vẫn lộ
  cho server.
- Local plaintext cache được mã hóa bằng master key để phục vụ history/preview,
  nhưng cache này làm forward secrecy thực tế phụ thuộc mạnh vào endpoint.

## Forward Secrecy

Điểm đã có:

- DM initial secret là hybrid: X25519 DH + KEM shared secret.
- One-time prekey được consume để giảm tác hại khi signed prekey dài hạn bị lộ.
- Double Ratchet discard message key sau khi dùng và advance chain theo từng
  message.
- Replay và out-of-order có kiểm soát bằng cache skipped key có giới hạn.

Giới hạn:

- Forward secrecy không bảo vệ plaintext đã được cache local, backup E2EE đã
  xuất, screenshot, clipboard, memory hoặc endpoint bị chiếm quyền.
- Nếu attacker lấy được state hiện tại của endpoint, các tin tương lai chỉ phục
  hồi tính bí mật sau khi có ratchet/update mới đủ mạnh và endpoint sạch lại.
- Với group, thuộc tính FS/PCS chủ yếu dựa vào OpenMLS epoch/update. Group mới
  dùng X-Wing draft hybrid ML-KEM-768 + X25519 cho confidentiality/HNDL, nhưng
  authentication vẫn là Ed25519 classical.

## MLS / group

Điểm đã có:

- Group dùng OpenMLS 0.8.1 trong `mls_bridge`, không còn là group secret tự chế.
- Ciphersuite hiện tại: `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`.
  Đây là X-Wing draft hybrid ML-KEM-768 + X25519; không phải final RFC/IANA PQ
  MLS và không cung cấp PQ signatures.
- Có flow KeyPackage, Welcome, Commit, GroupInfo, application message và
  export/import state qua bridge.
- Server lưu/chuyển artifact và enforce policy ứng dụng: membership, role,
  friend relation, pending operation, disbanded group.
- Server verify SecChat Ed25519 signature trên MLS KeyPackage và chỉ lưu
  KeyPackage đúng ciphersuite X-Wing.
- Server dùng OpenMLS `PublicGroup` để validate GroupInfo/Commit public state,
  ciphersuite, group id, actor credential, epoch và expected member set trước
  khi ghi handshake hoặc mutate membership.
- Bridge selftest bao phủ add member, decrypt app message, export/import state,
  remove member và kiểm tra member bị remove không còn active.

Giới hạn:

- Đây là MLS-backed SecChat group, không phải client MLS interoperable độc lập:
  credential, envelope, control message và server workflow là SecChat-specific.
- X-Wing/PQ MLS đang theo draft; cần migration nếu IETF final thay đổi
  ciphersuite, encoding hoặc IANA id.
- Authentication vẫn là Ed25519 classical; nếu cần PQ authentication phải thêm
  PQ/hybrid signature hoặc credential scheme khác.
- Server validation dùng public MLS state, không thể thay thế việc audit độc lập
  toàn bộ OpenMLS/libcrux, fuzzing sâu, hoặc formal model cho group.

## Việc nên ưu tiên nếu nâng lên production

- Chuyển identity audit mismatch/unavailable từ warning-only sang hard-block
  trước key exchange/send, hoặc bắt user xác nhận risk rõ ràng và ghi state đó.
- Thêm test cho hành vi hard-block identity audit nếu chọn threat model đó.
- Bọc PQXDH bundle fetch/OTK consume trong transaction/row lock rõ ràng.
- Theo dõi draft/IETF final cho MLS PQ ciphersuites và chuẩn bị migration group
  state khi X-Wing/PQ MLS đổi encoding hoặc identifier.
- Giảm plaintext cache mặc định cho conversation nhạy cảm và làm rõ UX khi cache
  bị disable.
- Audit độc lập phần Double Ratchet custom, parser C server, bridge serialization
  và E2EE backup/restore.

## Kiểm chứng đã chạy ngày 2026-06-07

- Host crypto/session tests:
  `python -m unittest tests.test_secure_protocol_crypto tests.test_crypto_session tests.test_openmls_bridge -v`
  pass 21 tests, skip 3 OpenMLS host-binary tests do binary không build trên
  host Windows.
- Docker contract/crypto tests:
  `tests/run_all_tests.py --category server_contract,crypto_contract --timeout 600 --skip-vnc-ui`
  pass 17/17 test files.
- Container OpenMLS bridge:
  `docker exec chat-server secchat_mls_bridge selftest`
  trả `ok: true`, OpenMLS `0.8.1`, ciphersuite
  `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`, `pq_hybrid: true`,
  `pq_authentication: false`.
- Visible manual checklist:
  `tools/run_visible_manual_checklist.ps1 -IncludeDestructive` pass core và
  destructive VNC flow.
