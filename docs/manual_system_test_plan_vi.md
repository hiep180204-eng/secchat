# kế hoạch kiểm thử thủ công toàn bộ hệ thống SecChat

Tài liệu này dùng để kiểm thử hệ thống như một người dùng thật thao tác trên UI, thay vì chỉ gửi API call. Mỗi mục gồm thao tác cần làm và kết quả mong đợi. Khi một bước không đúng như mong đợi, ghi lại thời điểm, tài khoản đang dùng, conversation, ảnh chụp màn hình và log liên quan.

Các tài khoản demo mặc định:

- `234@gmail.com` / `123456`
- `123@gmail.com` / `123456`
- `345@gmail.com` / `123456`

Nên mở hai hoặc ba client song song, mỗi client đăng nhập một tài khoản. Nếu cần kiểm thử offline/relogin, đóng hoặc logout một client nhưng giữ client còn lại hoạt động.

## 1. chuẩn bị môi trường

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| khởi động sạch | chạy `docker compose down -v`, sau đó `docker compose up -d --build` | các container server, database, auditor và client chạy ổn định |
| seed tài khoản demo | chạy `python tools\seed_demo_users.py` | ba tài khoản demo tồn tại và đăng nhập được |
| health check server | mở `/readyz` hoặc dùng command kiểm tra health | server trả trạng thái `ok` |
| health check auditor | mở endpoint auditor `/readyz` | auditor trả trạng thái sẵn sàng |
| chứng chỉ local | kiểm tra thư mục `.tmp_cert` trong repo | có cert runtime, không lưu sang thư mục ngoài project |

## 2. đăng nhập, đăng xuất và đăng ký

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| đăng nhập đúng | đăng nhập `234@gmail.com / 123456` | vào được màn hình chat, danh sách bạn bè/inbox tải lên |
| đăng nhập sai mật khẩu | nhập đúng email nhưng sai mật khẩu | UI báo `Email or password is incorrect`, không crash và không vào chat |
| đăng xuất | bấm `Exit` | quay về màn hình đăng nhập, timer/poll dừng, không còn cập nhật chat của phiên cũ |
| đăng nhập lại | đăng nhập lại cùng tài khoản | history, cache policy, verified flag và key state cục bộ được nạp lại |
| đăng ký tài khoản mới | tạo user mới bằng email hợp lệ | đăng ký thành công và có thể đăng nhập |
| đăng ký lỗi | dùng username quá ngắn, email sai dạng hoặc email đã tồn tại | UI báo lỗi rõ ràng, không tạo account lỗi |

Điểm cần chú ý về mã hóa: sau khi logout/login lại, các tin nhắn cũ đã từng đọc vẫn phải đọc được nếu local plaintext cache còn bật. Tin nhắn mới nhận trong lúc offline vẫn phải đọc được sau khi đăng nhập lại. Không được xuất hiện lỗi kiểu ratchet mismatch làm mất toàn bộ lịch sử.

## 3. publish key, PQXDH và trạng thái mã hóa khi login

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| publish bundle lần đầu | đăng nhập một account mới hoặc account sau reset Docker | client tự upload key legacy và PQXDH bundle, không hiện lỗi `No PQXDH bundle found` cho chính account đó |
| không báo đổi identity giả | đăng nhập lại nhiều lần cùng account | không hiện lỗi `Identity change requires rotate_identity` nếu identity key thật không đổi |
| peer chưa publish key | thử start DM với account chưa từng đăng nhập/publish bundle | UI báo contact chưa publish encryption keys, không treo key exchange |
| peer publish sau | cho peer đăng nhập một lần, rồi retry start DM | DM key exchange hoàn tất, có thể gửi tin |
| DB không có plaintext | sau khi gửi vài tin, kiểm tra bảng `messages` trong DB | body chỉ có prefix `S3PQI:`, `S3DR:` hoặc `S3MLS:`, không có plaintext |

Lệnh tham khảo để xem loại message trong database:

```powershell
docker exec -it chat-db mysql -uchatuser -pchangeme_chat_pass chatdb -e "SELECT id, conversation_id, sender_id, CASE WHEN body LIKE 'S3PQI:%' THEN 'PQXDH initial S3PQI' WHEN body LIKE 'S3DR:%' THEN 'Double Ratchet S3DR' WHEN body LIKE 'S3MLS:%' THEN 'MLS RFC 9420 S3MLS' ELSE 'OTHER/PLAINTEXT?' END AS wire_type, LEFT(body, 90) AS body_prefix, edit_target_message_id, sent_at FROM messages ORDER BY id DESC LIMIT 30;"
```

## 4. bạn bè và yêu cầu kết bạn

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| tìm user | user 234 tìm user 123 bằng email/username | thấy user 123 trong kết quả tìm kiếm |
| gửi request | user 234 gửi friend request cho user 123 | user 234 thấy trạng thái đã gửi, user 123 thấy request |
| nhận notification request | user 123 đang online khi request đến | nút Requests cập nhật số lượng hoặc UI báo có request |
| accept request | user 123 accept | hai bên thấy nhau trong danh sách Friends |
| reject request | tạo request khác rồi reject | request biến mất, hai bên không thành friend |
| unfriend | bấm unfriend một contact | contact biến khỏi Friends, DM cũ nếu còn trong inbox không được làm hỏng state crypto |
| block nếu có UI | block một user rồi thử gửi DM | tin không gửi được và UI báo bị chặn; unblock xong gửi lại được |

## 5. Saved Messages đã bỏ

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| không có lối vào Saved Messages | kiểm tra sidebar và các menu tạo conversation | không còn nút hoặc menu `Saved Messages` |
| không tự DM chính mình | thử start DM với chính user hiện tại nếu có đường thao tác/API | server từ chối hoặc UI không cho thao tác; không tạo conversation tự lưu |
| không có cảnh báo identity giả | đăng nhập lại và refresh inbox | không xuất hiện conversation Saved Messages cũ hoặc banner verify dành cho chính mình |

## 6. DM cơ bản

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| start DM | user 234 chọn user 123 và start conversation | hai bên có DM trong inbox; bên kia không cần tự start DM mới nhận được |
| gửi khi chưa verify | gửi tin trước khi mark verified | tin vẫn gửi/nhận/giải mã được; UI chỉ cảnh báo chưa xác minh |
| nhận live | user 234 gửi khi user 123 online | user 123 thấy tin gần như ngay lập tức, preview inbox cập nhật plaintext sau khi decrypt |
| gửi hai chiều | user 123 trả lời | cả hai đọc được tin của nhau |
| history | đóng mở conversation nhiều lần | không duplicate tin và không mất tin cũ |
| unread/read | user 123 không mở DM, user 234 gửi tin | unread count tăng; mở DM thì count giảm hoặc reset theo logic hiện tại |

## 7. verify identity và safety number

Verify không phải là bước tạo khóa mã hóa. Khóa được tạo bằng PQXDH/Double Ratchet. Verify là việc người dùng so sánh safety number hoặc short code với người kia qua kênh ngoài SecChat để xác nhận identity key đúng người.

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| mở verify dialog | trong DM bấm nhãn `Verify safety ...` hoặc `Review identity` | dialog hiển thị safety number đầy đủ, short code, trạng thái audit và lịch sử identity nếu có |
| short code hai bên | mở verify dialog trên cả hai client trong cùng DM | short code/safety number giống nhau |
| mark verified | một bên bấm `Mark Verified` | bên đó chuyển badge `verified`; bên kia không tự động verified vì đây là quyết định cục bộ |
| continue unverified | bấm `Continue Unverified` nếu có | vẫn gửi tin được, badge vẫn thể hiện chưa verified |
| rotate identity | rotate safety key ở một account | contact thấy cảnh báo key changed/safety changed, verified flag bị hạ, tin vẫn có thể gửi sau review/cảnh báo |
| auditor lỗi | tạm dừng auditor hoặc giả lập auditor unavailable nếu có thể | UI hiện audit warning/unavailable nhưng không dừng khả năng chat |

## 8. DM khi offline, logout và relogin

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| offline nhận tin | user 123 logout, user 234 gửi 3 tin DM | user 234 thấy tin đã gửi; user 123 chưa online |
| relogin nhận offline | user 123 login lại và mở DM | thấy cả lịch sử cũ trước logout và 3 tin offline mới |
| không mất history | so sánh với màn hình user 234 | thứ tự và số lượng tin khớp, không chỉ còn tin offline |
| gửi tiếp sau relogin | user 123 trả lời sau khi login lại | cả hai đọc được, không có `[Cannot decrypt]` hoặc ratchet mismatch |
| logout nhiều lần | lặp lại logout/login và gửi offline nhiều vòng | ratchet state vẫn tiếp tục, không phải start DM lại |

## 9. edit, delete, reply, forward, pin và reaction trong DM

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| menu dấu ba chấm | hover hoặc bấm `...` ở cuối message | menu action hiện React, Forward, Pin/Unpin, Edit/Delete nếu là tin của mình |
| edit message | user gửi sửa tin của chính mình | bên kia thấy nội dung mới decrypt được, có marker edited, history sau relogin vẫn là nội dung mới |
| delete message | xóa tin của chính mình nếu UI cho phép | hai bên thấy message bị xóa/ẩn theo thiết kế, không làm hỏng tin khác |
| reply | reply một tin | message mới có liên kết reply nếu UI hỗ trợ; body vẫn decrypt được |
| forward | forward một message sang DM/group khác | message gửi như message mã hóa thường, có nhãn `Forwarded` nhỏ màu xám |
| pin | pin một message | message hiện badge pin, danh sách Pins cập nhật |
| unpin | unpin message vừa pin | badge pin biến mất, danh sách Pins cập nhật |
| reaction picker | bấm React | hiện bảng emoji; chọn emoji thì chip emoji count hiện dưới message |
| toggle reaction | bấm lại chip/reaction của mình | reaction của mình được remove hoặc count giảm đúng |
| relogin metadata | logout/login lại sau edit/pin/reaction | edited, pinned và reactions vẫn hiển thị đúng từ history server |

## 10. gửi file, media và kéo thả

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| gửi file nhỏ | bấm nút `+` hoặc upload file dưới giới hạn | file gửi thành công, bên kia thấy attachment |
| preview file | gửi ảnh/video nếu UI hỗ trợ preview | preview hiển thị đúng hoặc có link/tên file rõ ràng |
| kéo thả file | kéo file vào message list | UI nhận file và gửi như thao tác upload |
| file quá lớn | gửi file lớn hơn giới hạn | UI báo lỗi rõ ràng, không crash |
| relogin file | logout/login lại | metadata file vẫn hiển thị, cache không làm hỏng message text |

## 11. group cơ bản

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| tạo group | user 234 tạo group với user 123 | group xuất hiện ở sidebar của user 234 và user 123 |
| không popup sai | user 123 được add vào group | user 123 không bị mở popup edit group info bất ngờ |
| Welcome group | ngay sau khi tạo, user 234 gửi nhiều tin group | user 123 đọc được sau khi Welcome tới, không hiện mãi `MLS state unavailable` |
| gửi hai chiều | user 123 gửi lại vào group | user 234 đọc được |
| trạng thái sending | gửi group message | pending `sending` biến mất khi server accept; bubble không bị đẩy lên sai vị trí |
| history group | đóng mở group hoặc relogin | history group còn đủ, đúng thứ tự, không duplicate |

## 12. group membership, MLS epoch và consistency

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| thêm member mới | tạo user thứ ba, add vào group | member mới thấy group và đọc được tin sau khi tham gia |
| lịch sử trước join | member mới mở history trước thời điểm join | không đọc được pre-join history nếu không có Welcome/secret tương ứng; UI phải hiển thị unavailable rõ ràng, không crash |
| remove member | admin remove một member | member bị remove không nhận/decrypt được tin sau remove |
| member còn lại | các member còn lại gửi group sau remove | đọc được bình thường |
| OpenMLS Commit | sau add/remove, mở warning detail nếu có cảnh báo | detail bấm được và giải thích mismatch/Commit nếu có |
| consistency bình thường | group không bị can thiệp | không hiện consistency warning dai dẳng |
| đổi group info | admin sửa tên/mô tả group | group info cập nhật cho member bằng control message mã hóa, không làm mất MLS state |
| quyền admin/member | member thường thử remove/sửa role nếu UI cho phép | server từ chối hoặc UI không cho thao tác trái quyền |

## 13. cache plaintext cục bộ

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| cache bật mặc định | đọc vài tin rồi logout/login | tin cũ vẫn đọc được nhờ cache mã hóa bằng master key |
| tắt cache global | vào privacy/cache setting và tắt cache | UI hiện `Cache off`; preview/history cũ có thể không khôi phục sau relogin nhưng tin mới vẫn gửi/nhận được |
| tắt cache cho một conversation | đánh dấu một DM/group là sensitive/no local cache | conversation đó không lưu plaintext cache; conversation khác không bị ảnh hưởng |
| xóa cache thủ công | bấm clear local cache | preview có thể quay về encrypted/unavailable cho tin cũ forward-secret; key exchange hiện tại không bị reset |
| clear on logout | bật xóa cache khi logout rồi logout/login | cache bị xóa theo policy; ratchet/key state vẫn không được xóa nếu chỉ xóa cache |
| TTL cache | đặt thời gian giữ cache ngắn rồi kiểm tra sau khi hết hạn | entry hết hạn bị dọn, UI báo rõ nếu tin cũ không đọc lại được |

## 14. đổi mật khẩu, backup và restore

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| đổi mật khẩu sai current | nhập current password sai | UI báo lỗi, mật khẩu không đổi |
| đổi mật khẩu đúng | đổi sang mật khẩu mới | thành công, local E2EE state được re-wrap bằng master key mới |
| login bằng mật khẩu cũ | logout rồi thử mật khẩu cũ | đăng nhập thất bại |
| login bằng mật khẩu mới | login bằng mật khẩu mới | đăng nhập được, tin DM/group cũ vẫn đọc được nếu cache/state còn |
| export backup yếu | export backup với passphrase yếu | UI từ chối và giải thích passphrase yếu |
| export backup mạnh | export backup với passphrase đủ mạnh | tạo file backup E2EE thành công |
| restore backup | restore backup trên cùng account | state được khôi phục, UI khuyến nghị review identity |
| backup có cache | export include cache rồi restore | preview/history đã cache có thể khôi phục |
| backup không cache | export không include cache rồi restore | key/ratchet có thể khôi phục nhưng plaintext cache cũ không đi kèm |
| revoke local backup | revoke backup local nếu có UI | client hiện tại từ chối restore backup đã revoke; bản copy ngoài máy không thể bị xóa tự động |

## 15. profile, avatar và privacy

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| mở profile cá nhân | bấm avatar/tên của mình | dialog profile mở, có đổi mật khẩu, privacy/cache, backup, rotate identity |
| upload avatar | chọn ảnh avatar | avatar cập nhật ở sidebar/message row/profile |
| remove avatar | remove avatar | avatar về mặc định, nút upload/remove cùng kích thước |
| sửa display name/bio | cập nhật profile | contact thấy thông tin mới sau refresh |
| không có read receipt | mở privacy/profile và kiểm tra UI | không còn tùy chọn read receipt; trạng thái read/unread chỉ dùng cục bộ, không gửi cho người khác |
| privacy typing | tắt typing nếu có | người khác không thấy typing indicator từ bạn |

## 16. inbox, search và UI layout

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| preview inbox DM | gửi tin DM rồi quay ra sidebar | preview là plaintext sau khi decrypt/cache, không phải `[Encrypted message]` nếu đã đọc được |
| preview inbox group | gửi tin group | preview group hiển thị plaintext sau decrypt/cache |
| search messages | dùng ô Search messages trong conversation | chỉ hiện message khớp, action menu vẫn hoạt động |
| search users | tìm user ở sidebar | kết quả đúng, không làm mất inbox hiện tại |
| layout group messages | gửi nhiều tin group liên tiếp | row không bị giãn bất thường, nút `...` ở cuối message, không sát timestamp |
| warning detail | khi có warning, bấm `Open warning details` | mở được detail, không bị label không click được |
| resize window | đổi kích thước cửa sổ | text không tràn khỏi button/card, message list không overlap |

## 17. trạng thái lỗi gửi tin và retry

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| gửi khi crypto chưa sẵn sàng | gửi ngay khi DM/group vừa tạo và key chưa hoàn tất | UI hiện pending hoặc failed rõ ràng, không mất nội dung |
| retry sau key ready | khi key exchange/Welcome hoàn tất, bấm Retry | message gửi lại thành công |
| dismiss failed | bấm Dismiss | failed bubble biến mất, không xóa message thật đã gửi |
| mất mạng/server | dừng server rồi gửi tin | UI báo lỗi hoặc pending/fail, không crash |
| server chạy lại | bật server lại và reconnect/login | user có thể tiếp tục chat, không mất local crypto state |

## 18. server GUI, logs và metrics

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| mở server GUI | chạy UI server nếu dùng | chỉ còn các tab vận hành cần thiết như Logs và Metrics |
| không có API Coverage | kiểm tra tab server GUI | không còn tab API Coverage |
| metrics scroll | kéo xuống cuối metrics rồi chờ refresh | vị trí scroll không tự nhảy lên đầu |
| logs lỗi | tạo một lỗi nhẹ như login sai | log ghi lỗi nghiệp vụ, không ghi plaintext message hoặc secret key |

## 19. kiểm tra dữ liệu trong database

| mục kiểm thử | thao tác | kết quả mong đợi |
|---|---|---|
| message body | query bảng `messages` sau khi gửi DM/group | body là ciphertext `S3PQI`, `S3DR`, `S3MLS` |
| không có legacy wire | query prefix cũ `E2R`, `E2RK`, `E2GS`, `E2E`, `__KEM_INIT__` | không có message mới dùng prefix cũ |
| edit event | edit một tin rồi query | message gốc không bị ghi đè body; có row edit event với `edit_target_message_id` |
| reaction/pin | pin/react rồi query bảng liên quan nếu cần | metadata tồn tại nhưng không chứa plaintext body |
| identity log | rotate identity rồi query identity log nếu cần | có event identity mới, version tăng |

## 20. tiêu chí pass cuối cùng

Một vòng kiểm thử thủ công được xem là đạt khi các điều kiện sau đúng:

- ba user demo đăng nhập được sau reset Docker;
- cả DM và group gửi nhận hai chiều được khi online;
- user offline nhận được tin mới sau relogin mà không mất lịch sử cũ;
- edit, reaction, pin, forward, retry và preview inbox hoạt động đúng;
- chưa verify vẫn gửi được nhưng UI cảnh báo rõ;
- mark verified chỉ thay đổi trạng thái tin cậy cục bộ, không phá key exchange;
- Saved Messages không còn xuất hiện và server/UI không tạo DM tự lưu với chính mình;
- group add/remove member không làm member hợp lệ mất khả năng đọc tin sau epoch hiện tại;
- cache policy, đổi mật khẩu và backup/restore không làm hỏng identity key hoặc ratchet state nếu thao tác đúng;
- database không chứa plaintext message;
- server GUI và metrics không có lỗi UI rõ ràng;
- không có lỗi lặp lại như `Identity change requires rotate_identity`, `No PQXDH bundle found`, ratchet mismatch hoặc MLS state unavailable trong flow bình thường.
