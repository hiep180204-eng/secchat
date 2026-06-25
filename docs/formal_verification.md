# Kiểm chứng hình thức cho SecChat

Formal verification khác với test. Test chạy một số tình huống cụ thể để phát
hiện lỗi hồi quy trong implementation. Formal verification mô hình hóa giao
thức bằng công cụ chuyên dụng rồi kiểm tra các thuộc tính như secrecy,
authentication hoặc chống downgrade trong một mô hình tấn công đã định nghĩa.

SecChat hiện có mô hình ProVerif đầu tiên tại
`formal/proverif/secchat_dm.pv`. Mô hình này trừu tượng hóa luồng DM sau
khi identity key của người nhận đã được xác minh hoặc pin bằng safety number:
prekey bundle có chữ ký, bắt tay hybrid dùng X25519 và ML-KEM, domain
separation cho SecChat, ràng buộc thuật toán KEM vào transcript, và một tin
nhắn ứng dụng được mã hóa sau khi hai bên tạo root key.

Các thuộc tính đang được kiểm tra là nội dung tin ứng dụng không bị attacker
biết, responder chỉ accept root key nếu đã có begin event tương ứng từ
initiator, và message mà responder nhận phải khớp với message đã được initiator
gửi trong mô hình. Vì thuật toán `ML-KEM-1024` và domain `secchat_pqxdh`
được ký trong bundle và kiểm tra lại trong initial message, mô hình cũng kiểm
tra hướng chống downgrade ở mức transcript binding.

Giả định “identity key đã được xác minh” là điểm rất quan trọng. Khi bỏ kiểm
tra này khỏi model, ProVerif tìm được đúng kiểu tấn công key substitution:
server độc hại đưa một bundle tự ký của attacker thay cho bundle của người
nhận. Vì vậy UI xác minh safety number không phải trang trí; nó là phần cần
thiết để người dùng phát hiện thay khóa.

Chạy mô hình bằng lệnh:

```powershell
python tools\run_formal_verification.py --download --require
```

Trên Windows, runner tải binary ProVerif 2.05 chính thức vào thư mục `.tools`
của repo nếu chưa có. Trên Linux hoặc macOS, cài `proverif` vào `PATH` hoặc đặt
biến môi trường `PROVERIF_BIN`.

Điểm cần nói rõ: đây mới là formal model cho một phần giao thức DM, chưa phải
chứng minh cho toàn bộ SecChat. Nó không bao phủ UI PyQt, file local, cache,
metadata, database, server C, lỗi memory safety, side-channel, hoặc group
protocol. Vì vậy cách mô tả đúng là: SecChat đã có bước formal verification ban
đầu cho transcript DM, nhưng chưa phải formally verified protocol đầy đủ.
