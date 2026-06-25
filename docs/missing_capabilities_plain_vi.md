# Hệ thống còn thiếu gì nếu bỏ qua QKD, phần cứng đặc thù và công nghệ độc quyền

Tài liệu này đánh giá SecChat như một phần mềm nhắn tin bảo mật bình thường:
client, server, database, giao thức khóa, E2EE, group, backup và trải nghiệm
người dùng. Các điểm dưới đây không dựa vào QKD, thiết bị lượng tử, phần cứng
đặc thù, hoặc công nghệ độc quyền. Nói ngắn gọn, SecChat đã đủ tốt để làm đồ án
và demo kỹ thuật, nhưng vẫn còn nhiều khoảng cách nếu muốn thành một hệ thống
nhắn tin an toàn và bền vững như sản phẩm thật.

## 1. Đặc tả bảo mật đã rõ hơn, nhưng bằng chứng chưa bao phủ toàn hệ thống

SecChat hiện đã có đặc tả giao thức hiện tại trong
`docs/secchat_protocol_spec_vi.md` và đặc tả bảo mật toàn hệ thống trong
`docs/system_security_spec_vi.md`. Hai tài liệu này tách vai trò rõ hơn: đặc tả
giao thức mô tả wire format, identity, PQXDH-style DM, Double Ratchet-style
message, MLS group và state machine; đặc tả bảo mật mô tả tài sản cần bảo vệ,
ranh giới tin cậy, local state, cache, backup, UI, database, server validation,
metadata và vận hành.

Điểm còn thiếu không còn là “chưa có đặc tả”, mà là chưa có bằng chứng đủ rộng
bám theo đặc tả đó. SecChat có test integration tốt và có mô hình ProVerif cho
một phần luồng DM, nhưng mô hình này chưa chứng minh toàn bộ client, server
C, database, backup, group, local cache, UI hoặc vận hành. Nói cách khác, hệ
thống đã có quy tắc được viết rõ hơn, nhưng chưa có formal model và kiểm toán
đủ rộng để chứng minh mọi quy tắc đó luôn đúng trong mô hình tấn công đầy đủ.

Việc cần làm tiếp là buộc thay đổi code, test và tài liệu đi cùng nhau. Mỗi khi
đổi crypto, identity, group, backup, cache hoặc server validation, đặc tả phải
được cập nhật cùng lúc và test phải kiểm tra invariant tương ứng. Nếu không, tài
liệu sẽ nhanh chóng trở thành mô tả cũ thay vì đặc tả thật của hệ thống.

## 2. Xác minh danh tính vẫn phụ thuộc vào hành vi của người dùng

Hệ thống có identity key, safety number, short code và cảnh báo khi safety number
đổi. Đây là hướng đúng. Tuy nhiên, nếu người dùng bỏ qua cảnh báo và không so
sánh safety number qua kênh khác, server độc hại vẫn có thể cố thay key ở lần
đầu thiết lập liên lạc hoặc khi key rotation.

Điểm còn thiếu là cơ chế làm cho việc xác minh trở thành thói quen tự nhiên hơn.
Ví dụ: trạng thái verified nên nổi bật trong danh sách hội thoại, cảnh báo key
change nên khó bỏ qua hơn, và mỗi lần safety number đổi cần có lịch sử rõ ràng
về thời điểm đổi, ai đổi, thiết bị nào đổi, và người dùng đã xác minh lại chưa.
Hệ thống đã được bổ sung bước đầu cơ chế transparency log cho identity key. Chat
server ghi identity event vào `identity_key_log`, auditor service riêng dựng
Merkle tree và ký checkpoint, còn client kiểm tra proof khi nhận PQXDH bundle.
Nhờ vậy, key change có lịch sử rõ hơn, trạng thái verified xuất hiện ngay trong
danh sách hội thoại, và key change hoặc audit mismatch buộc người dùng review
trước khi gửi tiếp.

Bản mới còn pin một checkpoint auditor chung cho toàn tài khoản trên thiết bị.
Điều này nghĩa là client không chỉ kiểm tra từng contact riêng lẻ, mà còn nhớ
log head mới nhất đã thấy. Nếu lần kiểm tra identity sau đó nhận checkpoint nhỏ
hơn, hoặc cùng kích thước nhưng root khác, client coi đó là rollback hoặc
split-view và chuyển hội thoại liên quan sang audit warning. Màn hình verify
cũng hiển thị pinned account log để người dùng có thể so sánh log head khi cần.

Điểm còn thiếu là mức phân tán như hệ thống production. Auditor hiện là một
service trong cùng project Docker, chưa có nhiều auditor độc lập, chưa có public
checkpoint bên ngoài và chưa có gossip qua kênh không phụ thuộc server. Vì vậy
cơ chế mới giảm mạnh khả năng server/auditor cho một thiết bị thấy các lịch sử
key mâu thuẫn, nhưng chưa biến SecChat thành một hệ thống key transparency hoàn
chỉnh như hạ tầng lớn ngoài đời. Nếu chat server và auditor cùng bị chiếm và
kiểm soát toàn bộ kênh giao tiếp, hệ thống vẫn cần người dùng hoặc một kênh bên
ngoài để so sánh checkpoint hoặc safety number.

## 3. Group protocol đã chuyển sang OpenMLS

Group hiện dùng OpenMLS cho KeyPackage, Welcome, Commit, GroupInfo và application message theo RFC 9420. Đây là bước nâng cấp quan trọng so với hướng dùng epoch secret tự chế: secret tree, Commit remove và application message đều do thư viện MLS thực hiện.

Server vẫn giữ vai trò policy và delivery. Khi admin thêm hoặc xóa member, server kiểm tra quyền trước ở `prepare_group_change`, claim KeyPackage nếu cần, sau đó chỉ cập nhật membership ở `apply_group_change` khi client gửi artifact MLS hợp lệ. Server không sinh group secret và không giải mã payload group.

Phần còn cần cải thiện nếu muốn tiến gần production hơn là persistence nhiều thiết bị, kiểm thử liên vận với implementation MLS khác, fuzzing message parser và formal verification cho toàn bộ flow group.

Transcript consistency vẫn hữu ích để phát hiện rollback hoặc split-view ở mức lịch sử hiển thị, nhưng không thay thế kiểm chứng hình thức cho toàn bộ hệ thống.

## 4. Server vẫn kiểm soát metadata và thứ tự sự kiện

E2EE bảo vệ nội dung tin nhắn, nhưng server vẫn biết nhiều metadata: ai đăng
nhập, ai nói chuyện với ai, conversation id, group membership, thời điểm gửi
tin, số lượng tin, message nào bị edit, message nào bị pin, và reaction nào
được gửi. Metadata này đủ để suy ra social graph và thói quen sử dụng. Không
thể xóa hoàn toàn loại metadata này chỉ bằng cách mã hóa body tin nhắn.

Hệ thống hiện đã giảm rủi ro ở mức thực tế hơn trước. Client tắt typing và read
receipt mặc định trong chế độ metadata protection, padding plaintext trước khi
mã hóa để giảm lộ độ dài nội dung, kiểm tra history consistency, kiểm tra signed
group commit, và dùng identity transparency log cho identity key.

Bản hiện tại còn thêm signed transcript checkpoint cho group. Mỗi client tự
tính hash chuỗi transcript theo thứ tự message đã thấy, ký checkpoint bằng
identity key và gửi checkpoint đó như một control message `S3MLS`. Khi client
khác nhận checkpoint, nó kiểm tra chữ ký, kiểm tra checkpoint chain của peer và
so sánh transcript head với view local tại cùng `last_message_id`. Nếu server
cho hai thành viên group thấy thứ tự khác nhau, sửa nội dung đã thấy, rollback
checkpoint hoặc bỏ qua một đoạn view mà client đã biết, client sẽ cảnh báo.

Cơ chế này không làm server mất khả năng quan sát metadata và cũng không ngăn
server từ chối dịch vụ, trì hoãn message hoặc giấu message mới chưa ai khác xác
nhận. Nó biến một phần hành vi gian lận từ “âm thầm” thành “có thể phát hiện”.
Để tiến xa hơn cần kiến trúc nặng hơn như nhiều server độc lập, gossip
checkpoint giữa client qua kênh ngoài, sealed sender, mixnet hoặc private
information retrieval. Những phần đó chưa nằm trong phạm vi hệ thống hiện tại.

## 5. Local plaintext cache là đánh đổi cần quản lý tiếp

Local plaintext cache giúp preview và history cũ vẫn đọc được sau relogin, đặc
biệt khi ratchet đã tiến và message key cũ không còn. Hệ thống mã hóa cache bằng
master key, có tùy chọn tắt cache toàn cục, đặt thời gian giữ cache, xóa cache
thủ công, hoặc xóa khi logout.

Bản hiện tại đã làm rõ chính sách này hơn ở UI. Header hội thoại hiển thị trạng
thái `Cache 7 days`, `Cache off` hoặc `No local cache` để người dùng biết ngay
hội thoại đang lưu cache cục bộ thế nào. Menu của từng DM/group có lựa chọn tắt
local cache riêng cho hội thoại nhạy cảm và xóa cache riêng của hội thoại đó.
Khi tắt local cache cho một hội thoại, file cache plaintext của hội thoại đó bị
xóa ngay và các lần decrypt sau không ghi cache mới cho hội thoại này.

Màn hình privacy giải thích rằng cache là dữ liệu plaintext đã decrypt, được mã
hóa trên thiết bị và dùng cho preview/history recovery. Export backup cũng hỏi
rõ có bao gồm local plaintext cache hay không; các hội thoại đã đánh dấu `No
local cache` không được đưa vào backup theo đường cache.

Giới hạn còn lại là vấn đề nhiều thiết bị và thiết bị bị mất. Chính sách này chỉ
áp dụng cho thiết bị local hiện tại. Nếu người dùng dùng nhiều thiết bị, mỗi
thiết bị vẫn cần policy riêng. Nếu thiết bị đã bị compromise sau khi người dùng
đăng nhập, attacker ở endpoint vẫn có thể đọc dữ liệu đang hiển thị hoặc dữ liệu
đã decrypt trong memory; local cache policy không giải quyết được endpoint
compromise.

## 6. Backup và khôi phục mới ở mức cục bộ

SecChat đã nâng backup từ một file cục bộ đơn giản thành một protocol rõ hơn.
Mỗi backup có format version, backup id, generation, thời điểm tạo, account,
identity fingerprint, nhãn thiết bị và thông tin có đưa cache plaintext vào hay
không. Payload vẫn được mã hóa E2EE bằng passphrase riêng, nên server không đọc
được identity key, ratchet state, group state hoặc cache trong backup. Khi
restore, client re-encrypt state bằng master key hiện tại, đăng lại legacy key
bundle nếu còn cần, và tạo prekey bundle mới dưới identity đã khôi phục.
Client không đăng lại one-time prekey cũ từ backup vì các key đó có thể đã được
dùng trước thời điểm restore.

UI trong profile cá nhân hiển thị trạng thái backup gần nhất, cho export,
restore, xem trạng thái và revoke local backup cũ. Export từ chối passphrase quá
yếu. Revoke hiện là revoke cục bộ: thiết bị này sẽ từ chối restore backup đã
biết hoặc generation cũ, nhưng không thể xóa bản copy đã bị đưa sang nơi khác.
Sau restore, app nhắc người dùng xác minh lại safety number vì việc chuyển máy
vẫn là thay đổi nhạy cảm.

Giới hạn còn lại là chưa có backup tự đồng bộ nhiều thiết bị và chưa có cơ chế
server lưu encrypted backup blob. Nếu người dùng mất máy và không có file
backup, E2EE state cũ vẫn mất. Nếu quên mật khẩu tài khoản, backup không giúp
đăng nhập server. Để đi xa hơn cần thiết kế device enrollment riêng: thiết bị
mới phải được thiết bị cũ hoặc recovery key xác nhận, backup phải có version và
revoke rõ trên mọi thiết bị, và passphrase yếu phải được coi là rủi ro bảo mật
nghiêm trọng.

## 7. Chưa hỗ trợ nhiều thiết bị độc lập cho cùng một tài khoản

Hiện mô hình gần với một tài khoản một phiên chính. App chat thật thường có
nhiều thiết bị: máy tính, điện thoại, tablet. Mỗi thiết bị nên có device key
riêng, prekey riêng, ratchet riêng, trạng thái đã xác minh riêng, và cơ chế
thêm/xóa thiết bị an toàn.

Nếu không có multi-device protocol, người dùng đổi máy hoặc đăng nhập ở máy mới
dễ làm mất E2EE state hoặc làm safety number đổi khó hiểu. Nếu thêm multi-device
không chặt, attacker có thể lợi dụng server để thêm thiết bị giả. Vì vậy phần
này cần thiết kế riêng, không nên chỉ copy local state sang nhiều nơi.

## 8. Server C cần kiểm toán bảo mật sâu hơn

Server viết bằng C nên các lỗi như buffer, string length, JSON parsing, SQL bind,
cleanup sau lỗi, và WebSocket frame parsing cần được kiểm tra kỹ. Test pass là
tốt, nhưng với C thì test chức năng không đủ để kết luận an toàn cấp production.

Phần này đã được cải thiện bằng một luồng kiểm toán lặp lại được. Repo có
`tools/run_server_c_audit.py` để chạy `cppcheck`, build bằng AddressSanitizer và
UndefinedBehaviorSanitizer, unit test domain bằng sanitizer, và fuzz smoke test
cho WebSocket handshake, JSON helper và các hàm validate domain. Fuzz harness
nằm trong `server/fuzz/fuzz_json_validation.c`; nó đưa input không tin cậy vào
các hàm nhận dữ liệu mạng thay vì chỉ kiểm tra luồng thành công.

Trong lần kiểm tra này cũng đã sửa các lỗi nhỏ ở tầng JSON helper: escape JSON
không còn dereference con trỏ null, và parse số nguyên từ chuỗi đã kiểm tra
overflow, trailing junk và giới hạn `int`. Parser WebSocket handshake được tách
thêm hàm thuần `ws_build_accept` để fuzz được mà không cần socket TLS thật.

Điểm còn thiếu sau bước này là mức kiểm toán production đầy đủ. Fuzz smoke test
trong repo chỉ là bước nhanh để phát hiện crash rõ ràng; muốn mạnh hơn cần chạy
fuzz lâu trong CI, thêm corpus từ traffic thật đã loại bỏ dữ liệu nhạy cảm,
thêm fault injection cho lỗi database/socket, và review thủ công các đường cấp
phát bộ nhớ lớn. Đây không phải công nghệ đặc thù; đây là hygiene cơ bản khi
chạy server C nhận dữ liệu từ mạng.

## 9. UI cần dẫn người dùng đi qua rủi ro bảo mật

Phần UI đã được cải thiện theo hướng không chỉ hiển thị tính năng, mà còn giải
thích tác động bảo mật của trạng thái hiện tại. Header hội thoại có thêm banner
hướng dẫn khi history đang tải, identity chưa verified, key bị đổi, auditor lỗi,
cache local bị tắt, hoặc có cảnh báo consistency. Khi identity bị chặn do key
change hoặc audit mismatch, ô nhập tin nhắn nói rõ người dùng phải review
identity và so sánh safety code ngoài SecChat trước khi gửi tiếp.

Message list cũng có trạng thái rõ hơn. Tin đang chờ server hiện `Sending`, tin
gửi lỗi có nút `Retry`, còn message không đọc được do thiếu state, MLS group
không có hoặc cache bị tắt sẽ hiển thị lời giải thích ngắn ngay dưới message.
Điều này giúp người dùng phân biệt giữa lỗi mạng, key chưa sẵn sàng, và việc
thiết bị không còn state để decrypt.

Các hành động nhạy cảm đã được viết lại rõ hơn. Dialog verify giải thích rằng
`Mark Verified` chỉ nên bấm sau khi đã so sánh code qua kênh khác; `Continue
Unverified` vẫn cho chat nhưng giữ trạng thái chưa tin cậy. Profile giải thích
`Rotate Safety Key` sẽ làm người khác thấy cảnh báo key change. `Restore E2EE
Backup` nói rõ restore có thể thay identity, ratchet, group và verification
state cục bộ, nên thiết bị mới cần xác minh lại safety number.

Giới hạn còn lại là UI vẫn chưa đạt mức app production hoàn chỉnh. Nó đã đủ để
demo các quyết định bảo mật chính, nhưng app thật còn cần onboarding tốt hơn,
notification đa nền tảng, quản lý nhiều thiết bị, recovery UX, accessibility,
và kiểm thử UI dài hạn trên nhiều kích thước màn hình.

## 10. Chưa có vận hành production

Một hệ thống chạy thật cần nhiều thứ hơn khả năng gửi và nhận tin. SecChat đã
có health check, readiness, metrics, rate limit cơ bản, giới hạn kích thước
input, Docker Compose, migration SQL và script backup/restore database trong
`tools/db_backup.ps1` và `tools/db_restore.ps1`. Những phần này đủ tốt cho demo
và kiểm thử đồ án, nhưng chưa phải vận hành production.

Các phần còn thiếu là log audit cho hành động quản trị, backup database theo
lịch, kiểm tra restore định kỳ, migration có đường rollback, monitoring tập
trung, cảnh báo khi lỗi tăng bất thường, giới hạn tài nguyên theo user hoặc IP,
chống spam, chống abuse, log retention, quy trình incident response và cách
triển khai an toàn khi nâng cấp server.

Phần report đã được bỏ khỏi phạm vi hiện tại. Client không còn nút report,
server không còn handler `report_user` hoặc `report_message`, migration không
tạo bảng `user_reports`, và server GUI không còn tab report. Các lệnh report cũ
nếu gửi thủ công chỉ được xem là command không hỗ trợ.

Điều này làm phạm vi hệ thống rõ hơn: SecChat hiện tập trung vào E2EE chat,
không tuyên bố có moderation workflow. Nếu sau này cần moderation trong một hệ
thống E2EE, không nên thêm nhanh bằng cách gửi plaintext lên server. Cần thiết
kế riêng về bằng chứng người dùng gửi, dữ liệu được lưu, ai được xem, thời gian
giữ dữ liệu, quyền phản hồi của người bị xử lý và cách hạn chế lộ nội dung cho
những người không liên quan. Chi tiết vận hành hiện được ghi riêng trong
`docs/production_operations_vi.md`.

## Kết luận

Nếu bỏ qua QKD, phần cứng đặc thù và công nghệ độc quyền, những thứ SecChat còn
thiếu không phải là “thiết bị mạnh hơn”, mà là quy tắc, bằng chứng và quy trình
chặt hơn. Hệ thống đã có đặc tả bảo mật toàn hệ thống, nhưng vẫn cần formal
model rộng hơn, group protocol hoàn chỉnh hơn, phát hiện server gian lận tốt
hơn, multi-device, backup/restore trưởng thành hơn, kiểm toán C server, vận hành
production và UI giúp người dùng hiểu đúng các quyết định bảo mật.

Nói theo cách đơn giản: SecChat đã mã hóa được nội dung tin nhắn và đã có nền
tảng giao thức tốt cho đồ án. Phần còn thiếu là biến nền tảng đó thành một hệ
thống có quy tắc đầy đủ, có bằng chứng rộng hơn, có vận hành an toàn hơn, và ít
phụ thuộc hơn vào việc người dùng hoặc server luôn làm đúng.
