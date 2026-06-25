# rà soát cấp phát bộ nhớ trong server C

Tài liệu này ghi lại phần rà soát thủ công hiện tại cho các vùng cấp phát bộ nhớ lớn trong server C. Mục tiêu là giảm rủi ro do client gửi dữ liệu quá lớn hoặc ngắt kết nối giữa chừng. Đây là bước hygiene mạnh hơn, không phải kiểm toán production hoàn chỉnh.

## thay đổi đã áp dụng

Server không còn cấp buffer nhận WebSocket 20 MB cho mỗi client. Giới hạn nhận frame của mỗi client hiện là 512 KiB. Lớp xử lý message tiếp tục có giới hạn riêng cho body mã hóa là 64 KiB. Nếu cần gửi file hoặc media lớn, hệ thống nên dùng protocol chunk/file riêng thay vì nhét toàn bộ dữ liệu vào một message JSON.

Connection pool của database đã được chỉnh để fail fast hơn khi database mất kết nối. Readiness dùng trạng thái DB do health thread cập nhật nền, vì vậy HTTP control plane không bị chặn bởi DNS hoặc MySQL connect khi database đang down. Nếu database dừng, `/readyz` chuyển sang `db_unavailable` sau khi health thread phát hiện lỗi, thay vì để request bị treo sau mutex hoặc đợi reconnect lâu.

Fuzzing đã có corpus khởi tạo cho JSON, WebSocket handshake, số nguyên lỗi biên, message mã hóa và dữ liệu cần escape. CI có chế độ fuzz theo thời gian và lưu artifact/corpus để kiểm tra crash nếu có.

## các vùng allocation còn cần để ý

Buffer nhận WebSocket trong `server/main.c` hiện là 512 KiB cho mỗi client. Với giới hạn client hiện tại, đây là mức chấp nhận được cho demo và kiểm thử, nhưng hệ thống production nên cân nhắc đọc streaming hoặc giảm tiếp theo loại command.

History trong `server/services/messaging_service.c` tạo JSON động từ tối đa 100 message. Vì message body đã bị giới hạn 64 KiB, kích thước history có trần thực tế, nhưng vẫn nên phân trang rõ hơn nếu sau này tăng giới hạn hoặc thêm file/media.

Danh sách pin và reaction dùng buffer JSON cố định hoặc giới hạn số dòng trả về. Cách này đủ cho demo, nhưng production nên có pagination để tránh vừa bị cắt dữ liệu vừa khó giải thích với UI.

Các public key, prekey và identity bundle dùng buffer cỡ vài KiB. Đây là hợp lý với key hiện tại, nhưng nếu thay đổi thuật toán KEM hoặc format bundle, phải cập nhật giới hạn và test lỗi biên.

Avatar vẫn là vùng dữ liệu tương đối lớn. Server đã kiểm tra mime và magic byte, nhưng nếu dùng thật cần thêm giới hạn kích thước ảnh ở cả client và server, resize ảnh trước khi lưu, và rate limit upload.

## checklist khi sửa server C

Khi thêm command mới, cần trả lời các câu hỏi sau trước khi merge:

- command có giới hạn kích thước input riêng chưa;
- mọi chuỗi từ client đã được escape trước khi đưa vào JSON output chưa;
- mọi truy vấn có input từ client dùng prepared statement hoặc input đã được chứng minh an toàn chưa;
- lỗi database có trả lỗi rõ ràng và cleanup đầy đủ không;
- client ngắt socket giữa frame hoặc giữa request có làm rò lock/bộ nhớ không;
- buffer cố định có kiểm tra kết quả `snprintf` hoặc giới hạn vòng lặp không;
- test có trường hợp input rỗng, quá dài, JSON sai, số nguyên lỗi biên và socket đóng sớm không.

## phần còn lại

Phần còn lại vẫn cần fuzz chạy dài hạn trong CI, fault injection sâu hơn cho lỗi database/socket khó hơn, và review thủ công các đường cấp phát bộ nhớ lớn khi có feature mới. Nếu muốn tiến gần production, nên thêm fuzz nhiều mục tiêu hơn cho từng command parser, chạy sanitizer trong pipeline lâu hơn, và dùng thêm static analysis chuyên sâu như `clang-tidy` hoặc CodeQL.

## cập nhật bổ sung

Đã thêm fuzz target riêng cho WebSocket frame parser. Target này không cần TLS socket, nên có thể đưa dữ liệu ngẫu nhiên trực tiếp vào logic kiểm tra opcode, mask, độ dài payload, control frame, frame thiếu dữ liệu và frame quá lớn. Như vậy fuzzing không chỉ kiểm tra handshake HTTP và JSON helper, mà còn kiểm tra phần frame parser quan trọng hơn.

Fault injection cũng đã được mở rộng. Ngoài việc dừng database rồi kiểm tra `/readyz`, test mới còn dừng database giữa lúc hai user đã có DM và đang gửi message. Kỳ vọng là server trả lỗi nhanh, không treo session, sau khi database phục hồi thì cùng session vẫn gửi message lại được. Test socket cũng có trường hợp gửi frame vượt giới hạn 512 KiB để xác nhận server trả lỗi `Message too large` mà không cấp phát body lớn.

Rà soát allocation đã xử lý thêm các điểm rõ ràng:

- inbox và pinned messages không còn ghép ciphertext preview lớn vào buffer 64 KiB;
- server chỉ trả phần preview ciphertext có giới hạn cho inbox và pin list, còn plaintext preview vẫn do client lấy từ cache cục bộ đã mã hóa;
- avatar cá nhân có giới hạn base64 và raw bytes rõ ràng;
- avatar group có giới hạn riêng và kiểm tra lỗi OpenSSL BIO;
- các đường upload avatar trả lỗi rõ ràng khi payload quá lớn thay vì cố decode/lưu.

Sau các thay đổi này, phần còn lại không phải “không làm được”, mà là công việc vận hành liên tục: chạy fuzz lâu nhiều giờ trong CI, thêm nhiều target fuzz cho từng command lớn, fault injection cho lỗi MySQL trả giữa transaction, lỗi socket khi broadcast tới nhiều client, và review thủ công mỗi khi có code C mới.
