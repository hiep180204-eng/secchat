# vận hành SecChat

Tài liệu này mô tả trạng thái vận hành của SecChat sau khi bỏ chức năng report.
Mục tiêu là làm rõ phần nào đã có thể kiểm tra được, phần nào còn thiếu nếu muốn
chạy như một hệ thống thật.

SecChat hiện có health check, readiness, metrics, Docker Compose, migration SQL,
giới hạn input ở nhiều command và rate limit cơ bản. Những phần này đủ cho demo,
kiểm thử tích hợp và báo cáo đồ án. Chúng chưa đủ để gọi là vận hành production.

## phạm vi hiện tại

Hệ thống hiện không triển khai report hoặc moderation workflow. Client không có
nút report, server không xử lý `report_user` hoặc `report_message`, database
không tạo bảng `user_reports`, và server GUI không có tab report. Nếu một client
cũ gửi lệnh report, server chỉ trả lỗi command không hỗ trợ.

Quyết định này giúp phạm vi bảo mật rõ hơn. Trong E2EE, moderation không thể làm
theo cách server tự đọc nội dung tin. Nếu sau này cần chống abuse ở mức sản phẩm,
cần thiết kế riêng: bằng chứng nào được gửi, có chứa plaintext hay không, ai có
quyền đọc, lưu bao lâu, người bị xử lý có quyền phản hồi thế nào, và audit hành
động của người vận hành ra sao.

## backup và restore database

Repo có hai script vận hành tối thiểu:

```powershell
powershell -ExecutionPolicy Bypass -File tools\db_backup.ps1
```

Lệnh này tạo file SQL trong `.ops_backups`. Thư mục này bị ignore khỏi source
control vì backup chứa dữ liệu thật của database.

Khôi phục là thao tác phá hủy dữ liệu hiện tại, nên script bắt buộc có cờ xác
nhận:

```powershell
powershell -ExecutionPolicy Bypass -File tools\db_restore.ps1 -InputFile .ops_backups\chatdb-YYYYMMDD-HHMMSS.sql -ConfirmRestore
```

Trước khi chạy restore trên môi trường thật, phải dừng client ghi dữ liệu mới,
backup trạng thái hiện tại, chạy restore trên môi trường staging nếu có, rồi mới
restore production.

## monitoring và cảnh báo

Server có `/healthz`, `/readyz` và `/metrics`. Trong demo, server GUI đọc metrics
để người vận hành xem trạng thái. Production cần thêm hệ thống ngoài để scrape
metrics, lưu lịch sử và cảnh báo khi có dấu hiệu bất thường.

Các cảnh báo tối thiểu nên có:

- `/readyz` lỗi hoặc không phản hồi;
- số lỗi validation tăng nhanh;
- số lỗi database tăng;
- số kết nối tăng vượt ngưỡng;
- rate limit bị kích hoạt nhiều bất thường;
- dung lượng database hoặc disk backup gần đầy;
- auditor service không trả checkpoint hợp lệ.

## audit log và quyền vận hành

SecChat hiện chưa có audit log đầy đủ cho hành động quản trị. Nếu có server
operator thật, hệ thống cần ghi lại ai thực hiện thao tác, thao tác gì, vào thời
điểm nào, từ máy nào, và kết quả ra sao. Log này không nên chứa plaintext tin
nhắn hoặc secret key.

Server GUI hiện chỉ nên xem là công cụ demo vận hành. Nếu dùng thật, cần đăng
nhập riêng cho operator, phân quyền, audit log, giới hạn mạng truy cập và TLS
cho control plane.

## migration và rollback

Migration hiện chạy theo hướng tiến lên. Production cần mỗi migration có kế
hoạch rollback hoặc ít nhất có backup bắt buộc trước khi nâng cấp. Với schema có
thay đổi dữ liệu, cần rehearsal trên bản copy database trước khi chạy trên dữ
liệu thật.

Quy trình nâng cấp tối thiểu nên là: backup, kiểm tra backup đọc được, chạy
migration trên staging, chạy test smoke, nâng production, kiểm tra `/readyz`,
kiểm tra đăng nhập, gửi DM, gửi group, và truy vấn database để xác nhận message
body vẫn là ciphertext.

## chống spam và chống abuse

Hệ thống đã có rate limit cơ bản, nhưng chưa đủ cho môi trường mở. Cần thêm
quota theo user hoặc IP cho đăng ký, đăng nhập, tìm kiếm user, gửi friend
request, gửi message, upload avatar, upload prekey và tạo group.

Vì report đã bị bỏ khỏi phạm vi, hệ thống hiện không có quy trình xử lý abuse do
người dùng gửi. Nếu muốn thêm lại, cần thiết kế riêng cho E2EE như đã nêu ở phần
phạm vi, không nên khôi phục handler report cũ.

## kết luận

Trạng thái hiện tại phù hợp cho đồ án và demo kỹ thuật: có health, metrics,
Docker, migration, test và script backup/restore cơ bản. Trạng thái này chưa đủ
cho production vì còn thiếu monitoring dài hạn, alerting, rollback, audit log,
quota chống abuse, quy trình incident response và moderation design phù hợp với
E2EE.
