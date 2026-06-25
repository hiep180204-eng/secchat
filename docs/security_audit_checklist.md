# kiểm tra bảo mật server c

Tài liệu này dùng để kiểm tra phần server viết bằng c theo cách lặp lại được. Nó không chứng minh hệ thống an toàn ở mức production, nhưng giúp tránh bỏ sót các vùng rủi ro chính khi thay đổi code.

## mục tiêu

Server là điểm nhận dữ liệu không tin cậy từ mạng, giải mã khung WebSocket, parse JSON, gọi database và phát lại dữ liệu cho các client. Vì server viết bằng c, lỗi nhỏ trong xử lý chuỗi, cấp phát bộ nhớ hoặc độ dài buffer có thể trở thành lỗi crash, rò rỉ dữ liệu hoặc lỗi bảo mật. Vì vậy mỗi thay đổi ở server cần được xem bằng hai lớp: kiểm thử chức năng và kiểm tra memory safety.

## các vùng cần kiểm tra

### WebSocket parser

Parser cần giới hạn kích thước frame, kiểm tra đúng độ dài payload trước khi đọc, xử lý frame bị cắt ngang, frame đóng kết nối, ping/pong và các opcode không hỗ trợ. Nếu client gửi frame quá lớn hoặc frame báo độ dài sai, server không được đọc vượt buffer, không được cấp phát vô hạn và phải đóng kết nối sạch.

### JSON input và JSON output

Mọi trường chuỗi nhận từ client cần có giới hạn độ dài trước khi đi vào business logic. Khi server tạo JSON trả về, dữ liệu do người dùng nhập như tên, bio hoặc tên file phải được escape đúng. Không được dùng chuỗi người dùng trực tiếp vào `snprintf` theo kiểu `%s` nếu chưa chắc đã được escape và còn đủ dung lượng buffer.

### buffer và message lớn

Các message mã hóa có thể dài vì chứa metadata, ciphertext hoặc file base64. Server cần kiểm tra giới hạn kích thước ở tầng nhận frame và tầng validate message body. Những hàm như `sprintf`, `strcpy`, `strcat`, `gets` không nên xuất hiện trong server. Với `memcpy`, `snprintf`, `malloc`, cần kiểm tra rõ ràng kích thước đích, giá trị trả về và cleanup khi lỗi.

### SQL

Các truy vấn có dữ liệu từ client nên đi qua prepared statement. Nếu có query dạng nối chuỗi, cần chứng minh dữ liệu không đến từ người dùng hoặc đã được escape đúng. Mỗi lỗi từ MySQL phải trả về lỗi rõ ràng cho client hoặc log nội bộ, không được tiếp tục dùng dữ liệu chưa khởi tạo.

### input limit và rate limit

Các command như đăng nhập, gửi message, upload prekey, reaction, đổi mật khẩu và tạo nhóm đều cần giới hạn độ dài input. Auth và các command dễ spam cần rate limit theo user hoặc theo kết nối. Khi bị rate limit, server nên trả lỗi rõ ràng và không làm hỏng trạng thái phiên.

### lỗi database và socket

Nếu database mất kết nối, prepared statement fail, socket gửi lỗi hoặc client disconnect giữa chừng, server cần cleanup bộ nhớ, không giữ lock lâu và không để trạng thái conversation bị cập nhật một nửa. Các đường broadcast cần xử lý client offline như một trường hợp bình thường.

## lệnh kiểm tra nhanh

Chạy toàn bộ luồng kiểm toán C chuẩn của repo trong Docker:

```powershell
python tools/run_server_c_audit.py
```

Lệnh này cài công cụ cần thiết trong container server nếu chưa có, sau đó chạy
heuristic scanner của repo, unit test domain, build với AddressSanitizer và
UndefinedBehaviorSanitizer, fuzz smoke test cho WebSocket/JSON/domain
validation, và `cppcheck`.

Chạy kiểm tra heuristic trong repo:

```powershell
python tools/security_audit.py
```

Chạy ở chế độ dùng cho ci hoặc kiểm tra nghiêm ngặt:

```powershell
python tools/security_audit.py --strict
```

Các công cụ ngoài repo đã được nối vào `tools/run_server_c_audit.py` ở mức chạy
nhanh:

- `cppcheck` để tìm lỗi c phổ biến.
- `asan` và `ubsan` khi chạy test server để bắt lỗi bộ nhớ lúc runtime.
- fuzzing riêng cho parser WebSocket và parser JSON command.

`clang-tidy` và fuzzing dài hạn vẫn nên bổ sung sau nếu muốn tiến gần hơn tới
kiểm toán production.

## kết luận hiện tại

Hệ thống hiện đã có validate domain, rate limit, prepared statement ở nhiều
đường, test hồi quy rộng, static analysis, sanitizer build và fuzz smoke test
cho một số parser quan trọng. Tuy nhiên phần server c vẫn chưa nên gọi là đã
được kiểm toán production. Trước khi chạy thật cần fuzzing dài hơn, review thủ
công các đường nhận dữ liệu mạng, kiểm tra lỗi database/socket bằng fault
injection và đưa luồng kiểm toán này vào CI.
