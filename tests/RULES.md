# Quy tắc viết test ổn định cho SecChat

Các quy tắc này tồn tại vì hệ thống đã từng gặp nhiều lỗi lặp lại khi test
WebSocket, Docker, database và UI. Khi viết hoặc sửa test, hãy ưu tiên các quy
tắc dưới đây để lỗi test phản ánh đúng lỗi hệ thống, không phải lỗi race hoặc
đọc sai socket.

## 1. Không gọi `drain()` trước `recv_until`

Nếu gọi `drain(sock, 0.4)` và timeout xảy ra giữa một WebSocket frame, buffer SSL
có thể còn một phần header. Lần đọc tiếp theo sẽ đọc rác, fail im lặng hoặc làm
assertion phía sau báo lỗi rất khó hiểu.

Hãy dùng `recv_until(sock, predicate, timeout=...)` cho cả quá trình chờ event.
Hàm này đọc từng frame đầy đủ và chỉ trả về khi gặp payload phù hợp hoặc timeout
sạch.

`drain()` chỉ nên dùng lúc teardown, khi socket sắp đóng.

## 2. Luôn truyền `timeout` rõ ràng

Các hàm như `ws_recv`, `recv_until` và `http_get` phải có timeout rõ ràng.
Không để test block vô hạn. Mặc định thường là 5 giây; chọn lâu hơn nếu luồng đó
thật sự chậm, ví dụ rate limit cần thời gian hồi token hoặc disappearing message
cần chờ TTL.

## 3. Luôn dùng `unique()`

Username, email, group name và nội dung dùng để assert nên được tạo bằng
`unique()`.

```python
from secchat_testlib import unique
alice = unique("alice")
```

Docker volume của database có thể tồn tại qua nhiều lần `docker compose up`.
Tên cứng như `"testA"` rất dễ đụng ở lần chạy thứ hai. `unique()` thêm hậu tố
UUID ngắn để tránh trùng.

## 4. Luôn `wait_ready()` trước kết nối đầu tiên

```python
if __name__ == "__main__":
    wait_ready()
    db_reset()
    unittest.main()
```

`wait_ready()` poll `/readyz` cho tới khi server báo database đã sẵn sàng. Nếu bỏ
qua bước này, test đầu tiên có thể race với quá trình khởi động server.

## 5. Khi có `request_id`, phải match theo `request_id`

Một số request có thể xen kẽ với broadcast async như presence, friend
notification hoặc message read. Khi protocol có `request_id`, hãy match response
theo `request_id` hoặc theo một field unique trong payload. Không dựa vào thứ tự
message đến.

## 6. Dùng `ChatClient` như context manager

```python
with ChatClient() as alice:
    alice.register_and_login(unique("alice"))
    ...
```

Context manager tự đóng socket khi assertion fail hoặc có exception. Nếu không
dùng, socket bị rò có thể làm nhiễu test tiếp theo.

## 7. Với metrics, hãy snapshot rồi so diff

```python
before = get_metrics()
do_thing()
after = get_metrics()
assert after["messages"]["sent"] - before["messages"]["sent"] == 1
```

Metrics là counter toàn process. Test khác trong cùng lần chạy có thể đã tăng
counter trước đó. Vì vậy không assert giá trị tuyệt đối.

## 8. Không dùng `time.sleep` dài nếu không thật sự cần

`time.sleep` lớn hơn 0.1 giây chỉ nên xuất hiện ở test thật sự phụ thuộc thời
gian:

- `test_rate_limit.py`, vì token rate limit hồi theo thời gian thực;
- test disappearing message, vì TTL và sweep cần chờ.

Ở các chỗ khác, hãy dùng `recv_until` với timeout đủ rộng. `time.sleep(0.5)` cố
định thường chỉ che đi race condition.

## 9. Mỗi file test tự sở hữu trạng thái database

Mỗi file test nên gọi `db_reset()` lúc bắt đầu. Các test trong cùng một file có
thể chia sẻ state, nhưng một file không được phụ thuộc dữ liệu do file khác tạo.
Runner có thể chạy với `--reset-each` để reset giữa từng file nếu cần kiểm tra
chặt hơn.

## 10. Import helper theo mẫu thống nhất

File test trong thư mục `tests/` thường bắt đầu bằng:

```python
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secchat_testlib import (
    wait_ready, db_reset, unique,
    ws_connect, ws_close, ws_send, ws_recv,
    recv_until, recv_type, collect,
    register_user, login, make_friends, open_dm,
    http_get, get_metrics,
    ChatClient,
)
```

Với file test ở root repo, thêm đường dẫn `tests` vào `sys.path` trước khi import
`secchat_testlib`.

## 11. Test UI phải dùng widget thật

Khi test hành vi UI client, ưu tiên `QTest.mouseClick` và `QTest.keyClicks` thay
vì gọi thẳng private handler. Có thể stub modal helper như `QMenu.exec_`,
`QMessageBox.question` hoặc `QInputDialog.getItem` để chọn đúng thao tác mà
người dùng sẽ bấm, nhưng test vẫn phải assert trạng thái widget nhìn thấy được
và signal UI được emit.

Đặt `QT_QPA_PLATFORM=offscreen` để UI test chạy được trong CI hoặc Docker:

```powershell
$env:QT_QPA_PLATFORM='offscreen'
python tests\test_client_ui_user_flows.py -v
```

## 12. Luồng người dùng chính phải có test VNC thật

Các test PyQt offscreen chỉ dùng cho widget, dialog và hợp đồng signal nhỏ. Những
luồng người dùng nhìn thấy được như đăng ký, đăng nhập, kết bạn, nhắn tin, group,
đổi tài khoản, cache E2EE và badge unread phải được bao phủ trong nhóm `ui_vnc`
để app chạy trong `chat-client1` và `chat-client2` giống phiên VNC thật.

Nhóm này cần container client được tạo với `SECCHAT_TEST_PROBE=1`. Probe chỉ ghi
snapshot đọc được của UI ra `/tmp/secchat-ui-state.json`, không nhận lệnh và không
thao tác thay người dùng. Test vẫn bấm phím, click chuột qua `xdotool` và lưu
ảnh chụp, log, snapshot vào `--artifact-dir` khi fail.

```powershell
$env:SECCHAT_TEST_PROBE='1'
docker compose up -d --build --force-recreate client1 client2
python tests\run_all_tests.py --category ui_vnc --timeout 900
```
