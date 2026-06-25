# Mô hình kiểm chứng hình thức của SecChat

Thư mục này chứa mô hình ProVerif cho một số thuộc tính bảo mật của giao thức
SecChat. Đây là mô hình có thể được công cụ kiểm tra tự động, không phải test
chức năng thông thường.

File chính là `secchat_dm.pv`. File này mô hình hóa luồng DM ở mức
trừu tượng, sau khi identity key của người nhận đã được người dùng xác minh hoặc
pin bằng safety number.

Mô hình đang kiểm tra các điểm sau:

- attacker không biết được nội dung tin ứng dụng sau bước bắt tay hybrid;
- responder chỉ accept root key nếu có begin event tương ứng từ initiator;
- tin mà responder nhận phải khớp với event gửi tin của initiator trong mô hình;
- tên thuật toán KEM và domain của SecChat được ràng buộc vào transcript đã ký,
  giúp phát hiện hướng downgrade trong phạm vi mô hình.

Điểm quan trọng là giả định identity key đã được xác minh. Nếu bỏ giả định này,
ProVerif tìm được đúng kiểu tấn công key substitution đã mô tả trong threat
model: server độc hại có thể đưa bundle tự ký của attacker thay cho bundle của
người nhận. Vì vậy safety number và UI xác minh danh tính là một phần quan trọng
của hệ thống, không phải chi tiết trang trí.

Mô hình này không chứng minh toàn bộ implementation. Nó không bao phủ UI PyQt,
file local đã mã hóa, memory safety của server C, database, metadata, timing
trên mạng hoặc group protocol.

Chạy mô hình bằng lệnh:

```powershell
python tools\run_formal_verification.py --download --require
```

Trên Windows, runner tải binary ProVerif 2.05 chính thức vào thư mục `.tools`
của repo nếu chưa có. Trên Linux hoặc macOS, có thể cài `proverif` vào `PATH`
hoặc đặt biến môi trường `PROVERIF_BIN`.
