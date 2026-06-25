# đặc tả bảo mật hệ thống SecChat

Ngày cập nhật: 2026-05-18

Tài liệu này là đặc tả bảo mật bao phủ toàn bộ hệ thống SecChat ở trạng thái
hiện tại. Nó không thay thế đặc tả giao thức ở
`docs/secchat_protocol_spec_vi.md`; tài liệu giao thức mô tả wire format và
state machine mật mã, còn tài liệu này mô tả tài sản cần bảo vệ, ranh giới tin
cậy, hành vi bắt buộc của client, server, database, auditor, UI, backup và vận
hành.

Các từ `MUST`, `MUST NOT`, `SHOULD`, `MAY` được dùng theo nghĩa quy phạm:
`MUST` là bắt buộc, `MUST NOT` là cấm, `SHOULD` là nên làm trừ khi có lý do kỹ
thuật rõ ràng, `MAY` là tùy chọn.

## 1. mục tiêu bảo mật

SecChat có mục tiêu chính là bảo vệ nội dung tin nhắn khỏi server, database bị
lộ và attacker nghe lén mạng. Nội dung người dùng nhập MUST được mã hóa ở client
trước khi rời thiết bị. Server MUST chỉ lưu và chuyển tiếp ciphertext có prefix
giao thức hợp lệ.

Hệ thống cũng đặt mục tiêu phụ:

- giảm thiệt hại khi message key ngắn hạn bị lộ;
- phát hiện replay và ciphertext bị sửa;
- phát hiện một phần việc server trả history hoặc membership không nhất quán;
- giúp người dùng nhận biết identity key đã verified, key change và audit
  mismatch;
- bảo vệ local state, cache và backup khi lưu trên máy;
- giữ ranh giới rõ ràng giữa tính năng đã có và phần chưa đủ production.

SecChat không đặt mục tiêu che giấu toàn bộ metadata, không bảo vệ endpoint đã
bị malware kiểm soát, không phải QKD, không tương thích wire-level với Signal,
SecChat không đặt mục tiêu che giấu toàn bộ metadata, không bảo vệ endpoint đã bị malware kiểm soát, không phải QKD, không tương thích wire-level với Signal, và chưa phải hệ thống đã formal verify toàn bộ.

## 2. tài sản cần bảo vệ

Các tài sản bí mật nhất là plaintext message, file/media trước khi mã hóa,
identity secret key, prekey secret, one-time prekey secret, Double Ratchet state,
MLS group secret, backup passphrase, master key cục bộ và cache plaintext đã
decrypt.

Các tài sản cần toàn vẹn là ciphertext, message id, edit target, group membership
event, MLS Commit, identity log entry, auditor checkpoint, local
verification state, backup manifest và migration database.

Các tài sản riêng tư nhưng hiện chưa được ẩn hoàn toàn là user id, conversation
id, group membership, thời điểm gửi, số lượng tin, kích thước tương đối của
ciphertext, trạng thái online, typing, pin, reaction, unread state cục bộ và quan hệ
bạn bè.

Log vận hành, metrics và backup database MUST NOT chứa plaintext message hoặc
secret key. Nếu log cần ghi lỗi, log SHOULD dùng id kỹ thuật, mã lỗi và thông
tin tổng quát thay vì ghi trực tiếp dữ liệu người dùng nhập.

## 3. ranh giới tin cậy

Client được tin để giữ plaintext, master key, identity secret key và trạng thái
mật mã. UI và crypto engine cùng nằm trên thiết bị người dùng, nhưng UI SHOULD
không tự sở hữu logic mật mã chi tiết. Crypto engine là nơi sở hữu state nhạy
cảm, mã hóa outbound message, giải mã inbound message, replay history và cache.

Server được tin để xác thực tài khoản, kiểm tra quyền truy cập, lưu thứ tự
message, chuyển tiếp event và trả history. Server MUST NOT được tin để giữ bí
mật nội dung tin nhắn. Server có thể gây hại bằng cách trì hoãn message, giấu
event, trả history thiếu, thay key bundle, hoặc tạo view membership khác nhau.
Client MUST có cơ chế phát hiện một phần các hành vi này bằng identity
transparency, transcript consistency và MLS Commit.

Database được xem là có thể bị lộ. Vì vậy database MUST chỉ chứa ciphertext cho
message body và public key material hoặc metadata cần vận hành. Database MAY lưu
metadata sản phẩm, nhưng tài liệu và UI MUST không mô tả hệ thống như đã ẩn toàn
bộ metadata.

Auditor service được tin để ký checkpoint identity log trong phạm vi project.
Client MUST pin auditor public key hoặc cấu hình auditor tin cậy. Nếu auditor
proof sai, checkpoint rollback hoặc auditor key thay đổi bất thường, client MUST
hiển thị audit warning.

Network được xem là không tin cậy. TLS bảo vệ WebSocket khỏi attacker trên đường
truyền, nhưng E2EE vẫn là lớp bảo vệ nội dung chính khi server hoặc database bị
lộ.

## 4. primitive mật mã và thư viện

Client MUST dùng thư viện có sẵn cho Ed25519, X25519, ML-KEM hoặc Kyber,
AES-GCM, HKDF-SHA256 và PBKDF2-HMAC-SHA256. Client và server MUST NOT tự viết
lại primitive mật mã thấp tầng.

Các khóa và ciphertext MUST có domain separation theo đặc tả giao thức. KEM
algorithm MUST được đưa vào transcript để chống downgrade. Nếu client thấy
algorithm trong bundle, transcript và local state không khớp, client MUST từ
chối bắt tay.

Random nonce, key pair và one-time prekey MUST lấy từ nguồn random mật mã của hệ
điều hành hoặc thư viện mật mã. Không được dùng random thông thường cho secret.

## 5. tài khoản, mật khẩu và master key

Client MUST NOT gửi mật khẩu thô lên server. Luồng hiện tại dùng hash phía
client từ mật khẩu và email, sau đó server hash tiếp với salt riêng. Server lưu
server-side password hash, không lưu raw password.

Master key cục bộ được dẫn xuất từ mật khẩu gốc và username thực tế sau đăng
nhập. Master key chỉ dùng để mở local encrypted state, không phải khóa message
trên wire.

Khi đổi mật khẩu, client MUST:

- xác thực mật khẩu hiện tại với server;
- derive master key mới;
- re-wrap local encrypted state;
- re-upload key material cần thiết nếu secret được bọc bằng master key cũ;
- giữ nguyên khả năng đọc state E2EE cũ nếu re-wrap thành công.

Nếu đổi mật khẩu thất bại, client MUST không xóa hoặc ghi đè state cũ. Nếu đăng
nhập sai mật khẩu, UI SHOULD trả lỗi thân thiện và không lộ email có tồn tại hay
không.

## 6. state cục bộ đã mã hóa và cache plaintext

Client MUST mã hóa identity secret key, prekey secret, ratchet state, group
state, verified state, identity audit state, transcript state, backup metadata
và plaintext cache bằng master key hoặc key được dẫn xuất từ master key.

Plaintext cache là đánh đổi giữa trải nghiệm và bảo mật cục bộ. Cache MAY được
bật để preview và history vẫn đọc được sau relogin khi ratchet đã tiến. Client
MUST cho người dùng:

- tắt cache toàn cục;
- đặt thời gian giữ cache;
- xóa cache thủ công;
- xóa cache khi logout;
- tắt cache riêng cho conversation nhạy cảm;
- biết rõ backup có bao gồm cache hay không.

Nếu một conversation được đánh dấu không lưu cache, client MUST xóa cache hiện
có của conversation đó và MUST NOT ghi plaintext cache mới cho conversation đó.
Nếu cache bị tắt, UI SHOULD giải thích rằng một số preview hoặc history cục bộ
có thể kém đầy đủ hơn.

Cache policy không bảo vệ được thiết bị đã bị malware kiểm soát sau khi người
dùng mở khóa app. Tài liệu MUST ghi rõ giới hạn này.

## 7. định danh, safety number và minh bạch khóa

Mỗi account có Ed25519 identity key. Identity public key dùng để kiểm tra chữ ký
prekey và tính safety number. Safety number giúp người dùng xác minh danh tính
qua kênh ngoài SecChat.

Client MUST lưu trạng thái verified theo peer hoặc conversation ở dạng mã hóa.
Khi identity key đổi, client MUST bỏ trạng thái verified cũ và hiển thị trạng
thái key changed. Nếu người dùng chưa review key change hoặc audit mismatch, UI
MUST chặn gửi tin tới peer bị ảnh hưởng cho tới khi người dùng mở màn hình
review. Sau review, người dùng MAY chọn verified hoặc tiếp tục unverified, nhưng
trạng thái unverified MUST vẫn hiển thị rõ.

Server MUST ghi identity event `initial` và `rotation` vào identity log. Đổi
identity MUST đi qua `rotate_identity`; upload lại key khác bằng đường upload
thường MUST bị từ chối.

Auditor MUST dựng Merkle log append-only từ identity event và ký checkpoint.
Client khi nhận PQXDH bundle SHOULD kiểm tra:

- identity public key trong bundle khớp leaf đã audit;
- identity version khớp log;
- inclusion proof hợp lệ;
- checkpoint signature hợp lệ;
- checkpoint mới không rollback so với checkpoint đã thấy.

Client MUST lưu một auditor checkpoint chung cho toàn tài khoản trên thiết bị,
không chỉ checkpoint riêng theo từng peer. Mọi lần kiểm tra identity SHOULD đi
qua checkpoint chung này. Nếu checkpoint mới có `tree_size` nhỏ hơn checkpoint
đã pin, hoặc có cùng `tree_size` nhưng `root_hash` khác, client MUST coi đó là
rollback hoặc split-view và chuyển contact liên quan sang `audit_mismatch`.
Client SHOULD lưu lịch sử quan sát checkpoint gồm thời điểm, peer liên quan,
identity version, tree size và root hash để người dùng hoặc người kiểm thử có
thể đối chiếu.

Nếu proof sai, checkpoint rollback hoặc cùng version nhưng key khác, client MUST
đánh dấu audit mismatch.

## 8. DM E2EE

DM mới MUST dùng wire S3 của SecChat:

- `S3PQI:` cho initial message dùng PQXDH-style transcript;
- `S3DR:` cho message sau khi đã có Double Ratchet state.

Server MUST reject plaintext và MUST reject legacy prefix đối với message mới.
Client MUST NOT dùng đường legacy để bắt đầu DM mới.

Trước khi dùng bundle của peer, client MUST kiểm tra chữ ký prekey bằng identity
key, kiểm tra KEM algorithm, kiểm tra identity transparency nếu auditor khả dụng,
và bind toàn bộ public material vào transcript.

Double Ratchet state MUST tiến theo từng message. Client MUST lưu ratchet state
đã cập nhật sau khi gửi hoặc giải mã thành công. Client MUST có replay check,
session id, AAD ràng buộc conversation/sender/receiver và skipped-key cache
trong giới hạn. Nếu message đến lệch thứ tự nhưng còn trong giới hạn
skipped-key, client SHOULD giải mã được. Nếu không đủ state, UI SHOULD hiển thị
lý do không decrypt được thay vì làm hỏng state.

Client MUST NOT decrypt inbox preview bằng cách làm tiến ratchet. Preview SHOULD
dùng plaintext cache đã mã hóa cục bộ hoặc fallback rõ ràng nếu chưa có cache.

## 9. group E2EE

Group runtime dùng OpenMLS theo RFC 9420. Group message và group control material dùng `S3MLS:`. Client sinh KeyPackage, Welcome, Commit, GroupInfo và application message; server chỉ kiểm tra quyền, lưu/phát artifact và không sinh group secret.

Mỗi group có MLS epoch và secret tree do OpenMLS quản lý. Thành viên mới join bằng Welcome dành riêng cho KeyPackage đã claim. Thành viên bị xóa MUST NOT nhận secret của epoch sau khi bị xóa. Nếu client không có MLS state phù hợp, UI SHOULD hiển thị message không khả dụng thay vì thử giải mã sai.

Membership change MUST đi qua `prepare_group_change` và `apply_group_change`. Commit và GroupInfo do OpenMLS sinh; role, tên nhóm, avatar và bio là encrypted app-level control message trong MLS. Client MUST cảnh báo nếu thiếu Welcome, Commit stale, replay commit hoặc MLS state không nối tiếp.

Server vẫn kiểm soát delivery và ordering, nên transcript checkpoint vẫn cần để phát hiện rollback hoặc split-view ở mức lịch sử hiển thị.

## 10. message, edit, forward, pin và reaction

Message body MUST là ciphertext. Server MUST kiểm tra membership trước khi lưu
hoặc trả history.

Edit message MUST là event mã hóa mới, append-only, trỏ tới message gốc bằng
`edit_target_message_id`. Server MUST NOT ghi đè ciphertext gốc bằng plaintext
hoặc ciphertext mới. Client giải mã edit event như message thường rồi áp dụng
plaintext mới lên message gốc trong local history.

Forward trong UI MUST giải mã plaintext ở client rồi mã hóa lại thành message mới
cho conversation đích. Server-side copy ciphertext giữa conversation khác khóa
MUST NOT được dùng làm đường E2EE chính.

Pin và reaction là metadata. Server MAY lưu và đồng bộ chúng để UI nhất quán.
Tài liệu MUST ghi rõ chúng vẫn làm lộ metadata thao tác với server.

Conversation delete một phía không nằm trong đường chính hiện tại vì từng gây
mất state và mất history. Nếu thêm lại, thiết kế mới MUST tách rõ xóa local view,
xóa cache cục bộ và xóa server history; không được xóa ratchet/group state làm
hỏng khả năng đọc message mới.

Report và moderation workflow hiện không nằm trong phạm vi. Server MUST không xử
lý `report_user` hoặc `report_message`; lệnh cũ SHOULD trả unsupported command.

## 11. kiểm tra dữ liệu ở server và quyền truy cập

Server MUST yêu cầu auth trước mọi command cần tài khoản. Server MUST kiểm tra:

- user là member của conversation trước khi gửi message/history;
- user có quyền admin trước khi remove member, đổi role, update group info hoặc
  disband group;
- target user hợp lệ trước khi block/unblock;
- body message không rỗng, không quá giới hạn và có prefix SecChat hợp lệ;
- command không hỗ trợ phải trả error rõ ràng, không treo client.

Server MUST dùng prepared statement hoặc repository API an toàn cho dữ liệu từ
client. JSON output chứa dữ liệu người dùng nhập MUST được escape đúng. Command
dễ spam SHOULD có rate limit theo user hoặc kết nối.

Server C SHOULD được kiểm tra bằng static analysis, sanitizer và fuzzing cho
WebSocket parser, JSON parser, input lớn và lỗi database. Repo hiện có
`tools/run_server_c_audit.py` để chạy `cppcheck`, AddressSanitizer,
UndefinedBehaviorSanitizer và fuzz smoke test cho WebSocket handshake, JSON
helper và domain validation. Test chức năng không đủ để kết luận memory safety
cấp production; luồng kiểm toán này là kiểm tra bắt buộc khi thay đổi server C,
không phải chứng nhận production.

## 12. database và migration

Database MUST không lưu plaintext message body. Bảng `messages.body` SHOULD chỉ
có các prefix `S3PQI:`, `S3DR:` hoặc `S3MLS:` đối với message mới.

Database MAY lưu metadata cần vận hành như conversation id, sender id, timestamp,
edit target, forwarded state, pin, reaction, membership, notification và key
bundle public material. Database MUST NOT lưu identity secret key, ratchet secret
hoặc plaintext cache.

Migration SHOULD có thứ tự rõ ràng và idempotent khi có thể. Production thật cần
backup trước migration và rollback plan. Hiện hệ thống mới có migration tiến lên,
chưa phải migration framework production đầy đủ.

## 13. metadata và tính nhất quán history

E2EE không che metadata. Server vẫn thấy ai nói với ai, thời điểm, conversation,
group membership, số lượng tin và thao tác metadata. Metadata protection hiện
chỉ là giảm lộ một phần: tắt typing theo policy, bỏ read receipt, padding plaintext
trước khi mã hóa, kiểm tra history consistency, MLS Commit, transcript
checkpoint và identity transparency.

Client SHOULD lưu transcript state đã mã hóa để phát hiện message đã từng thấy
nhưng biến mất, ciphertext cũ bị sửa, hoặc history bị trả sai thứ tự trong phạm
vi client đã biết. Group SHOULD dùng signed transcript checkpoint để so sánh view
giữa các member khi có dữ liệu.

Các cơ chế này không ngăn server từ chối dịch vụ, trì hoãn message, hoặc giấu
message mới chưa có client nào xác nhận. Tài liệu MUST trình bày đây là phát
hiện gian lận một phần, không phải metadata anonymity.

## 14. backup và khôi phục

Backup E2EE cục bộ MUST dùng passphrase riêng và MUST mã hóa bằng thuật toán có
associated data cho manifest. Manifest SHOULD chứa format version, backup id,
generation, account, identity fingerprint, device label, thời điểm tạo và thông
tin có bao gồm cache hay không.

Backup MUST NOT gửi plaintext hoặc secret key không mã hóa lên server. Nếu
passphrase yếu, client SHOULD từ chối export. Restore MUST re-encrypt state bằng
master key hiện tại. Restore MUST NOT re-upload one-time prekey cũ vì chúng có
thể đã bị dùng.

Revoke backup hiện là revoke cục bộ. Nó MAY làm client hiện tại từ chối backup
đã biết hoặc generation cũ, nhưng không thể xóa file đã copy ra ngoài. Tài liệu
và UI MUST nói rõ giới hạn này.

Nếu người dùng mất thiết bị và không có backup file, E2EE state cũ không thể
khôi phục. Nếu người dùng quên mật khẩu tài khoản, backup không giúp đăng nhập
server.

## 15. UI bảo mật

UI MUST không chỉ hiển thị tính năng, mà phải dẫn người dùng qua quyết định bảo
mật. Conversation list và header SHOULD hiển thị trạng thái verified, verify,
key changed, audit warning, cache off, no local cache, history warning và sending
state.

Nếu key changed hoặc audit mismatch chưa được review, composer MUST bị chặn cho
tới khi người dùng mở review. Màn hình review MUST nói rõ `Mark Verified` chỉ
nên dùng sau khi so sánh code qua kênh ngoài SecChat. `Continue Unverified` MAY
cho gửi tiếp, nhưng trạng thái chưa verified MUST vẫn còn rõ ràng.

Tin đang gửi SHOULD có trạng thái `Sending`. Tin gửi lỗi SHOULD có retry. Tin
không decrypt được SHOULD giải thích ngắn lý do có thể là thiếu local state,
MLS group không có, cache bị tắt hoặc dữ liệu legacy.

UI MUST không hiển thị report/moderation như tính năng hiện có.

## 16. vận hành

SecChat hiện có Docker Compose, health check, readiness, metrics, migration SQL,
script backup/restore database, test suite và reset/rebuild flow. Đây là đủ cho
demo và môi trường phát triển.

Production thật cần thêm:

- backup database theo lịch và restore drill;
- migration rollback;
- monitoring tập trung và alerting;
- log audit cho thao tác quản trị;
- log retention và log rotation;
- giới hạn tài nguyên theo user, IP và command;
- chống spam và chống abuse;
- quy trình incident response;
- đưa kiểm toán C server bằng static analysis, sanitizer và fuzzing vào CI;
- phân quyền và bảo vệ control plane/server GUI.

Vì report đã bị bỏ khỏi phạm vi, hệ thống hiện không có moderation workflow.
Nếu sau này thêm lại moderation cho E2EE, nó MUST có thiết kế riêng về bằng
chứng, quyền đọc, thời gian lưu, tác động tới plaintext và audit hành động của
operator.

## 17. kiểm chứng hình thức và test

Bộ test chứng minh các luồng đã nghĩ tới chạy đúng và giúp ngăn regression.
Test không chứng minh giao thức an toàn trong mọi trạng thái.

ProVerif model hiện chỉ bao phủ một phần DM. Tài liệu MUST không gọi toàn bộ
hệ thống là formally verified. Cách nói đúng là SecChat có test rộng và có bước
formal model ban đầu cho một phần giao thức, nhưng chưa có proof bao phủ client,
server C, database, UI, backup, group, metadata và vận hành.

Mọi thay đổi lớn về crypto, group, identity, backup hoặc cache SHOULD cập nhật
đặc tả trước hoặc cùng lúc với code, rồi bổ sung test bám theo invariant trong
tài liệu này.

## 18. invariant kiểm tra nhanh

Các invariant sau phải luôn đúng:

- message mới trong database không được là plaintext;
- message mới phải dùng `S3PQI:`, `S3DR:` hoặc `S3MLS:`;
- server không được giải mã message body;
- `report_user` và `report_message` không được xử lý như tính năng;
- identity khác key hiện tại phải đi qua `rotate_identity`;
- key change phải xóa verified state liên quan;
- audit mismatch phải hiển thị cảnh báo;
- auditor checkpoint phải được pin chung theo tài khoản và không được rollback;
- edit message phải là encrypted append-only event;
- forward phải mã hóa lại ở client khi chuyển conversation;
- inbox preview không được làm tiến ratchet;
- local secret và cache phải lưu ở dạng mã hóa;
- tắt cache riêng conversation phải xóa cache của conversation đó;
- restore backup không được re-upload one-time prekey cũ;
- group membership change phải có commit hoặc cảnh báo consistency;
- removed member không được nhận MLS epoch secret mới;
- unsupported command phải trả lỗi rõ ràng.

Nếu một thay đổi làm sai một invariant trong danh sách này, thay đổi đó phải được
xem là lỗi bảo mật hoặc phải cập nhật lại đặc tả kèm lý do rõ ràng.
