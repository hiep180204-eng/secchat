# Thiết kế giao thức SecChat

Ngày cập nhật: 2026-05-20

Tài liệu này giải thích ngắn gọn thiết kế giao thức SecChat. Mục tiêu là giúp
người đọc hiểu hệ thống đang làm gì trước khi đọc đặc tả chặt chẽ hơn trong
`docs/secchat_protocol_spec_vi.md`.

SecChat không tương thích wire format với Signal và cũng không phải MLS RFC
9420 đầy đủ. Hệ thống lấy ý tưởng từ các giao thức đó để xây dựng một giao thức
riêng phù hợp với code hiện tại: DM dùng bắt tay kiểu PQXDH và Double Ratchet,
group dùng epoch, Welcome material và MLS Commit theo hướng MLS RFC 9420.

## Tóm tắt

SecChat chỉ chấp nhận các prefix mới cho message body:

- `S3PQI:` dùng cho tin nhắn DM đầu tiên, kèm transcript bắt tay kiểu PQXDH.
- `S3DR:` dùng cho tin nhắn DM sau khi hai bên đã có Double Ratchet state.
- `S3MLS:` dùng cho group Welcome, group application message, group commit hoặc
  transcript checkpoint.

Các prefix cũ như `E2R:`, `E2RK:`, `E2GS:`, `E2E:` và `__KEM_INIT__` là legacy.
Server không nhận chúng cho tin nhắn mới. Quyết định này giúp database mới dễ
kiểm tra hơn: tin nhắn hợp lệ phải bắt đầu bằng một trong các prefix SecChat.

## DM dùng PQXDH-style

Mỗi user upload một prekey bundle đã ký. Bundle này là gói public key để người
khác có thể bắt đầu DM kể cả khi user đang offline.

Một bundle gồm các phần quan trọng:

- Ed25519 identity public key;
- signed X25519 prekey;
- signed ML-KEM hoặc Kyber prekey;
- một số X25519 one-time prekey nếu còn;
- một số ML-KEM hoặc Kyber one-time prekey nếu còn;
- tên thuật toán KEM, mặc định là `ML-KEM-1024`, có thể dùng `Kyber1024`,
  `ML-KEM-768` hoặc `Kyber768` nếu môi trường hỗ trợ.

Khi Alice muốn nhắn Bob, Alice gọi `get_pqxdh_bundle` để lấy bundle của Bob.
Server sẽ consume one-time prekey nếu còn. Nếu hết one-time prekey, server trả
signed prekey dự phòng.

Luồng bắt tay có thể hiểu như sau:

```text
Alice lấy bundle của Bob.
Alice kiểm tra chữ ký trên các prekey của Bob.
Alice sinh một X25519 ephemeral key mới.
Alice chạy KEM encapsulation tới public key hậu lượng tử của Bob.

root = HKDF(
  DH(Alice signed curve secret, Bob signed curve public)
  || DH(Alice ephemeral curve secret, Bob signed curve public)
  || optional DH(Alice ephemeral curve secret, Bob one-time curve public)
  || ML-KEM shared secret,
  info = "SecChat-PQXDH"
)
```

Sau đó Alice gửi một message `S3PQI` cho Bob. Message này chứa identity key của
Alice, prekey của Alice, ephemeral key, id các prekey của Bob đã dùng, tên thuật
toán KEM, KEM ciphertext, public key Double Ratchet đầu tiên của Alice và một
ciphertext nhỏ để xác nhận hai bên derive cùng root key.

Bob nhận `S3PQI`, dùng secret key tương ứng để decapsulate KEM ciphertext, tính
các DH term còn lại rồi derive cùng root key. Nếu sai key, sai thuật toán, sai
chữ ký hoặc transcript bị sửa, bước decrypt sẽ thất bại.

Tên thuật toán KEM được đưa vào transcript. Vì vậy attacker không thể âm thầm
hạ cấp từ thuật toán mạnh sang thuật toán yếu mà không làm chữ ký hoặc decrypt
bị lỗi.

## Double Ratchet cho DM

Sau tin `S3PQI`, DM dùng `S3DR`. Double Ratchet giúp mỗi tin có message key riêng
và làm state tiến dần sau mỗi lần gửi hoặc nhận.

Client lưu state đã mã hóa trên máy:

- root key;
- local X25519 ratchet key pair;
- remote X25519 ratchet public key;
- send chain key;
- receive chain key;
- số thứ tự gửi, số thứ tự nhận và `pn`;
- skipped-key cache có giới hạn.

Khi gửi một tin:

```text
nếu cần DH ratchet:
  sinh local ratchet key pair mới
  root_key, ck_send = KDF_RK(root_key, DH(new_secret, remote_public))

mk, ck_send = KDF_CK(ck_send)
gửi S3DR {dh, pn, n, AEAD(mk, plaintext)}
n_send += 1
```

Khi nhận một tin:

```text
parse S3DR
nếu đã có skipped key cho (dh, n):
  decrypt và xóa skipped key
ngược lại:
  nếu remote dh thay đổi:
    cập nhật root key và receive chain
    sinh local ratchet key mới cho chiều gửi tiếp theo
  derive các skipped key cần thiết tới số n
  decrypt bằng message key hiện tại
```

Replay bị chặn vì key đã dùng sẽ bị xóa và chain chỉ tiến về phía trước.
Tin đến lệch thứ tự vẫn được xử lý nếu nằm trong giới hạn skipped-key cache.

## Group MLS RFC 9420 bằng OpenMLS

Group không dùng sender-key legacy `E2GS` và không dùng epoch secret tự chế. Client dùng `MlsBridge` để gọi Rust bridge chạy OpenMLS 0.8.1. Server chỉ kiểm tra policy, claim KeyPackage, lưu/phát Welcome, Commit, GroupInfo và ciphertext `S3MLS`; server không sinh group secret và không giải mã group payload.

Khi tạo group, client gọi `create_group` trong bridge. Khi thêm member, admin gọi `prepare_group_change`; server kiểm tra friend/block/admin policy và claim một KeyPackage single-use của target. Sau đó bridge tạo Commit, Welcome và GroupInfo bằng OpenMLS, client gửi lại bằng `apply_group_change`, rồi server mới cập nhật membership.

Khi xóa hoặc kick member, bridge tạo Commit remove. Member bị xóa xử lý Commit này thì group local inactive và không nhận secret epoch sau. Vì vậy họ không đọc được message group sau khi bị xóa.

Role, tên nhóm, bio và avatar nhóm là control message ở tầng ứng dụng, được mã hóa bằng MLS application message. Server chỉ cập nhật metadata sau khi operation hợp lệ đã được apply.

Tin group có dạng tổng quát:

```text
S3MLS: base64url({
  kind: "app",
  mls_message_b64: "<TLS-serialized MLS application message>"
})
```

Nếu client không có MLS state phù hợp, UI phải hiển thị rằng message không khả dụng thay vì thử đoán hoặc fallback sang plaintext.

## Hậu lượng tử, lai, QKD và kiểm chứng hình thức

Post-quantum key agreement là mật mã phần mềm được thiết kế để chống lại máy
tính lượng tử trong tương lai. Trong SecChat, phần này là ML-KEM hoặc Kyber
chạy trên TCP/TLS/WebSocket bình thường. Nó không cần phần cứng lượng tử.

Hybrid key agreement nghĩa là trộn secret từ thuật toán hậu lượng tử với secret
từ X25519 bằng HKDF. Nếu sau này X25519 bị máy tính lượng tử phá nhưng ML-KEM
vẫn an toàn, transcript đã ghi lại vẫn được bảo vệ bởi phần hậu lượng tử. Nếu giả
định hậu lượng tử có vấn đề nhưng X25519 vẫn an toàn trước attacker cổ điển,
phần X25519 vẫn đóng góp bảo vệ.

QKD là chuyện khác. QKD dùng kênh vật lý lượng tử và phần cứng chuyên dụng để
phân phối khóa. QKD vẫn cần kênh cổ điển đã xác thực và không tự cung cấp app
chat, Double Ratchet, group membership, replay protection, storage policy hoặc
UI. Vì vậy nên mô tả SecChat là hệ thống E2EE dùng post-quantum/hybrid key
agreement, không gọi là QKD.

Formal verification khác với test. Test chạy các tình huống cụ thể. Formal
verification mô hình hóa giao thức bằng công cụ như ProVerif, Tamarin hoặc
CryptoVerif để chứng minh một số tính chất trong mô hình đó. SecChat hiện có
mô hình ProVerif bước đầu cho DM, nhưng chưa phải giao thức đã được formal
verify toàn bộ.

## Ghi chú triển khai

Crypto của client nằm chủ yếu trong `client/crypto_engine/secure_protocol.py`.

State nhạy cảm và cache nằm trong `client/crypto_engine/session.py`, được lưu
ở dạng mã hóa bằng master key.

Server lưu bundle trong các bảng `pqxdh_bundles`,
`pqxdh_curve_one_time_prekeys` và `pqxdh_pq_one_time_prekeys`.

Server chỉ nên ghi message body có prefix SecChat hợp lệ. Các test server kiểm tra
việc consume prekey, reject prefix legacy và lưu ciphertext đúng format.
