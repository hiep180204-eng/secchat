# ma trận kiểm thử và audit của SecChat

Tài liệu này gom lại các lớp kiểm thử hiện có để tránh nhầm giữa kiểm thử API,
kiểm thử giao thức, kiểm thử server C và kiểm thử UI như người dùng thật. Mục
tiêu là khi sửa hệ thống, người phát triển biết nên chạy lớp nào và mỗi lớp
chứng minh được điều gì.

## các lớp kiểm thử

Kiểm thử domain và crypto kiểm tra các phần nhỏ nhất: validate input, hash mật
khẩu, PQXDH, Double Ratchet, MLS group, cache, backup, transcript và identity
audit. Các test này chạy nhanh, ít phụ thuộc Docker, phù hợp để bắt lỗi logic.

Kiểm thử server integration dùng WebSocket/HTTP thật để kiểm tra đăng ký, đăng
nhập, kết bạn, nhóm, inbox, history, reaction, pin, avatar, notification, rate
limit, privacy, saved messages, legacy command rejection và các API server còn
lại. Lớp này chứng minh server và database phối hợp đúng, nhưng chủ yếu vẫn gửi
command qua WebSocket.

Kiểm thử UI widget kiểm tra trạng thái hiển thị của client: message row, search,
retry, cache policy, profile, backup, safety banner, reaction chip và các cảnh
báo bảo mật. Lớp này không thay thế integration test, nhưng bắt lỗi giao diện
mà API test không thấy.

Kiểm thử UI user-flow nằm trong `tests/test_client_ui_user_flows.py`. Lớp này
dùng `QTest` để mô phỏng người dùng thật hơn: nhập text vào form, bấm nút, mở
menu ba chấm, chọn reaction, chỉnh sửa message, forward, xóa message, tạo nhóm,
đổi mật khẩu, chỉnh privacy, unblock, xem pinned messages và chỉnh group info.
Kết quả được kiểm tra trên widget hiển thị và trên signal mà UI gửi cho
controller. Đây là lớp cần chạy khi thay đổi layout, dialog, menu, message list
hoặc cách người dùng truy cập chức năng.

Kiểm thử fault injection nằm trong `tests/test_operational_fault_injection.py`.
Nó cố tình làm database down, gửi frame WebSocket lỗi, gửi frame quá lớn và kiểm
tra server có fail fast, hồi phục và không làm hỏng session.

Audit server C chạy qua `tools/run_server_c_audit.py`. Lệnh này chạy scanner
heuristic, build sanitizer, fuzz JSON/WebSocket frame và `cppcheck`. Nó giúp bắt
lỗi memory-safety rõ ràng, nhưng không thay thế kiểm toán production dài hạn.

## lệnh thường dùng

Chạy UI-flow như người dùng:

```powershell
$env:QT_QPA_PLATFORM='offscreen'
python tests\test_client_ui_user_flows.py -v
```

Chạy toàn bộ test:

```powershell
python tests\run_all_tests.py --timeout 600
```

Chạy audit server C:

```powershell
python tools\run_server_c_audit.py --fuzz-runs 5000 --artifact-dir .audit_artifacts
```

## giới hạn của UI-flow test

UI-flow test chạy offscreen nên không kiểm tra chất lượng thị giác tuyệt đối như
ảnh chụp màn hình thật. Nó kiểm tra được cấu trúc widget, text, button, dialog,
menu và signal. Nếu cần đánh giá pixel, font, spacing hoặc render trên VNC thật,
cần thêm bước chụp màn hình thủ công hoặc automation qua desktop/VNC. Với phạm
vi hiện tại, lớp UI-flow đã đủ để đảm bảo các chức năng chính không chỉ tồn tại
ở API mà còn có đường dùng được trong client.
