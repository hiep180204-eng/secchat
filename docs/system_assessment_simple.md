# Đánh giá hệ thống SecChat

Ngày: 2026-05-15

Cập nhật nhanh 2026-05-30: đánh giá dưới đây vẫn đúng về hướng kiến trúc, nhưng
cần đọc cùng `docs/secchat_protocol_spec_vi.md`, `docs/system_security_spec_vi.md`
và `docs/missing_capabilities_plain_vi.md`. Cách trình bày chính xác hiện tại là
SecChat dùng bắt tay lai hậu lượng tử bằng X25519 + ML-KEM/Kyber và E2EE, không
phải QKD phần cứng. Group dùng OpenMLS theo MLS RFC 9420. Multi-
device chưa hỗ trợ; nếu cùng tài khoản đăng nhập ở VNC khác chưa có local state
thì tin cũ không giải mã được sẽ bị ẩn. `saved_messages` và report/moderation
không còn là tính năng chính; lệnh cũ phải bị reject rõ ràng.

Tài liệu này đánh giá toàn bộ hệ thống bằng ngôn ngữ đơn giản. Mục tiêu là
phục vụ báo cáo, bảo vệ đồ án, và định hướng sửa tiếp. Đây không phải là chứng
minh toán học về độ an toàn của giao thức.

## Kết luận ngắn

SecChat hiện phù hợp để làm một hệ thống nhắn tin bảo mật ở mức đồ án hoặc
demo kỹ thuật. Hệ thống đã thể hiện được nhiều ý chính của một ứng dụng chat
riêng tư hiện đại:

- người dùng có thể đăng ký, đăng nhập, kết bạn, chat riêng và chat nhóm;
- server lưu ciphertext thay vì lưu nội dung tin nhắn dạng đọc được;
- DM dùng ý tưởng thỏa thuận khóa lai hậu lượng tử;
- DM dùng ratchet sau bước bắt tay khóa ban đầu;
- group dùng secret theo epoch để đổi khóa khi trạng thái nhóm thay đổi;
- client mã hóa key và trạng thái E2EE khi lưu trên máy;
- test bao phủ nhiều lỗi từng gặp, nhất là lỗi offline, history, edit, pin,
  reaction, relogin và kiểm tra lệnh moderation cũ đã bị từ chối.

Không nên trình bày hệ thống này là sản phẩm production. Cũng không nên nói nó
là Signal. Cách nói chính xác hơn là: SecChat là giao thức riêng, lấy cảm hứng
từ Signal PQXDH, Double Ratchet, và MLS.

## Các thành phần chính

### Client

Client là ứng dụng desktop viết bằng PyQt.

Client xử lý:

- màn hình đăng nhập và đăng ký;
- danh sách bạn bè, lời mời kết bạn, tìm kiếm người dùng;
- giao diện DM và group chat;
- sửa tin nhắn, ghim tin nhắn, reaction và forward;
- profile, avatar, đổi mật khẩu, quyền riêng tư;
- trạng thái E2EE cục bộ.

Trước đây, `client/app.py` vừa điều khiển UI vừa giữ nhiều logic crypto. Cách
này khó đọc và khó kiểm tra, vì một file phải làm quá nhiều việc.

Sau lần refactor này, phần lớn trạng thái crypto, file key, file ratchet, file
group state, verified safety number, cache plaintext, và mã hóa outbound message
đã được chuyển sang `client/crypto_engine/session.py`.

`client/app.py` vẫn còn chịu trách nhiệm nhận WebSocket event, gọi UI, và điều
phối một phần decrypt history. Đây là phần nên tiếp tục tách ở bước sau.

### Crypto engine ở client

Crypto engine hiện gồm hai lớp chính:

- `client/crypto_engine/secure_protocol.py`: chứa các primitive giao thức như PQXDH-style
  handshake, Double Ratchet state, và MLS RFC 9420 group state.
- `client/crypto_engine/session.py`: quản lý trạng thái phiên crypto, lưu file
  đã mã hóa, cache, tạo bundle key, rotate identity, và mã hóa tin nhắn gửi đi.

Việc tách này tốt hơn vì:

- UI không còn phải biết quá nhiều chi tiết về file key;
- trạng thái crypto có một nơi quản lý rõ ràng hơn;
- test crypto dễ viết hơn;
- nếu sau này đổi giao thức, có thể sửa trong package crypto trước;
- giảm rủi ro sửa UI làm hỏng logic khóa.

Crypto engine hiện đã tách rõ hơn: state nhạy cảm, outbound encryption, inbound decrypt, history replay, PQXDH initial message và MLS RFC 9420 Welcome nằm trong `CryptoSession`. `App` chủ yếu còn điều phối WebSocket và UI.

### Server

Server viết bằng C, chạy WebSocket qua TLS, dùng MySQL để lưu dữ liệu.

Server xử lý:

- đăng ký, đăng nhập, đổi mật khẩu;
- kết bạn và chặn;
- tạo group, thêm/xóa member, role;
- lưu và trả history tin nhắn;
- inbox preview;
- pin, reaction, forward, edit event;
- profile, avatar, privacy;
- upload/fetch key bundle và prekey;
- metrics và health check.

Server không nên được tin tưởng để đọc nội dung tin nhắn. Thiết kế hiện tại đã
đẩy nội dung tin nhắn sang E2EE ciphertext. Tuy vậy, server vẫn biết metadata.

Server vẫn thấy:

- user nào đang nói chuyện với user nào;
- conversation id;
- group membership;
- thời điểm gửi tin;
- số lượng tin;
- message id bị edit;
- tin nào bị pin và reaction;
- trạng thái online/offline ở mức hệ thống.

Nói ngắn gọn: nội dung tin nhắn được bảo vệ tốt hơn, nhưng metadata chưa được
ẩn.

Sau bản sửa mới, client có thêm một lớp phát hiện server bất thường. Mỗi
conversation lưu một transcript cục bộ đã mã hóa gồm hash của message đã từng
thấy. Khi server trả history, client kiểm tra ba dấu hiệu dễ phát hiện: message
đã từng thấy nhưng bị thiếu trong cửa sổ history, message cũ bị đổi nội dung
ciphertext/metadata quan trọng, và history bị trả sai thứ tự message id. Với
group, client cũng lưu hash danh sách member và cảnh báo nếu membership thay
đổi mà không đi kèm event membership hợp lệ.

Cơ chế này không biến server thành không cần tin cậy. Server vẫn có thể trì
hoãn message, không giao message mới, hoặc kiểm soát metadata vận hành. Nhưng
nó làm server khó âm thầm sửa history hoặc thay đổi view group mà client không
có tín hiệu cảnh báo. Đây là bước phù hợp cho đồ án vì nó thể hiện rõ ranh giới
giữa E2EE nội dung và tính nhất quán của log do server cung cấp.

### Database

Database lưu:

- user và password hash;
- quan hệ bạn bè;
- conversation và member;
- encrypted messages;
- metadata của message;
- key bundle và prekey;
- notification.

Bảng `messages` nên chỉ chứa wire format đã mã hóa, ví dụ:

- `S3PQI:` cho tin nhắn DM đầu tiên dùng bắt tay PQXDH-style;
- `S3DR:` cho tin nhắn DM sau khi đã vào Double Ratchet;
- `S3MLS:` cho tin nhắn group hoặc material điều khiển group.

Các format cũ như `E2R`, `E2RK`, `E2GS`, `E2E`, và `__KEM_INIT__` là legacy.
Chúng chỉ nên được nhắc đến khi giải thích quá trình nâng cấp hệ thống.

## Đánh giá giao thức bảo mật

### Điều hệ thống làm tốt

Nội dung tin nhắn không được gửi lên server dưới dạng plaintext. Server chỉ lưu
ciphertext có prefix giao thức.

DM dùng ý tưởng hybrid:

- X25519 là trao đổi khóa elliptic-curve truyền thống;
- ML-KEM/Kyber là KEM hậu lượng tử;
- hai secret được trộn lại để tạo secret chung.

Ý tưởng chính là nếu một nhánh bị yếu đi trong tương lai, nhánh còn lại vẫn có
thể giúp bảo vệ secret. Đây là hướng thiết kế phù hợp với giai đoạn chuyển sang
mật mã hậu lượng tử.

Sau bắt tay ban đầu, DM dùng Double Ratchet-style state. Ratchet giúp giới hạn
thiệt hại: nếu lộ một message key, attacker không mặc nhiên đọc được toàn bộ
quá khứ và tương lai.

Group dùng mô hình epoch. Khi nhóm đổi trạng thái, hệ thống có thể chuyển sang
epoch mới với secret mới. Đây là hướng đúng nếu muốn tiến gần hơn đến MLS.

Client có identity key và safety number. Người dùng có thể so sánh safety
number để phát hiện thay đổi identity key đáng nghi.

Các file E2EE cục bộ được mã hóa bằng key dẫn xuất từ mật khẩu người dùng. Điều
này tốt hơn nhiều so với lưu key JSON thô trên ổ đĩa.

### Điểm yếu cần nói rõ

Hệ thống chưa được formal verify. Nghĩa là chưa có chứng minh bằng công cụ toán
học rằng mọi trạng thái của giao thức đều an toàn.

Hệ thống không tương thích wire-level với Signal. Nó dùng một số ý tưởng giống
Signal, nhưng format, state, và xử lý chi tiết là của SecChat.

Group hiện đã dùng OpenMLS theo RFC 9420 cho KeyPackage, Welcome, Commit và application message. Hệ thống vẫn không tương thích wire-level với Signal hay các client MLS khác vì credential binding, API server và envelope ứng dụng là thiết kế riêng của SecChat.

Metadata chưa được bảo vệ. Server vẫn biết ai nói với ai, nói lúc nào, group
có ai, và message nào bị thao tác như edit, pin hoặc reaction.

Local plaintext cache là đánh đổi giữa trải nghiệm và bảo mật. Nó giúp người
dùng đọc lại lịch sử sau relogin trong khi vẫn giữ hướng forward secrecy cho
wire message. Nhưng nếu attacker lấy được máy và local state sau khi mở khóa,
lịch sử đã cache có thể bị đọc.

Cache plaintext hiện đã có chính sách rõ hơn ở UI quyền riêng tư. Người dùng
có thể tắt lưu cache, đặt thời gian giữ cache là 1, 7, 30, 90 ngày hoặc không
hết hạn, xóa cache thủ công, chọn xóa cache khi logout, và tắt cache riêng cho
từng conversation nhạy cảm. Header hội thoại hiển thị `Cache 7 days`, `Cache
off` hoặc `No local cache` để người dùng biết trạng thái hiện tại. Cache vẫn
được mã hóa bằng master key cục bộ; khi tắt cache toàn cục hệ thống xóa các file
`msgs_*.bin`, còn khi tắt cache cho một conversation hệ thống xóa file cache của
conversation đó và không ghi thêm plaintext preview/history cho nó. Đánh đổi là
preview và khả năng đọc lại một số message forward-secret có thể kém thuận tiện
hơn.

Khôi phục tài khoản hiện đã có bước thực tế hơn. Trong profile cá nhân, người
dùng có thể export một file backup E2EE cục bộ và restore lại sau khi đăng
nhập. File backup dùng passphrase riêng, được mã hóa bằng PBKDF2-HMAC-SHA256
và AES-GCM. Nội dung backup gồm identity key, prekey, ratchet state, group
epoch state, verified safety number, transcript consistency state và tùy chọn
cache plaintext. Khi restore, state được re-encrypt lại bằng master key hiện
tại, nên backup cũ vẫn dùng được sau khi người dùng đổi mật khẩu.

Backup hiện có version, backup id, generation, manifest và identity fingerprint.
Manifest được dùng làm associated data cho AES-GCM, nên nếu metadata backup bị
sửa thì restore sẽ lỗi. Profile cá nhân hiển thị trạng thái backup, cho xem
thông tin backup gần nhất và revoke backup cũ ở phạm vi local. Khi restore,
client đăng lại legacy key bundle nếu còn cần và tạo prekey bundle mới dưới
identity đã restore. App không re-upload one-time prekey cũ trong backup vì các
key đó có thể đã bị dùng trước khi restore. Passphrase yếu bị từ chối ngay khi
export.

Điểm cần nói rõ là đây là backup cục bộ, không phải cloud backup. Server không
đọc được backup vì backup không được gửi lên server. Nếu người dùng quên mật
khẩu tài khoản thì vẫn không đăng nhập được server. Nếu người dùng mất cả máy
và không có file backup thì E2EE state cũ coi như mất; đây là lựa chọn đúng
hơn về bảo mật so với việc để server giữ key khôi phục plaintext.

Phần còn thiếu là backup tự đồng bộ và quy trình thêm thiết bị mới theo đúng
nghĩa multi-device. Revoke hiện chỉ làm client hiện tại từ chối backup cũ; nó
không thu hồi được file đã copy ra ngoài. Muốn thành hệ thống thật cần thêm
device enrollment, recovery key hoặc encrypted backup store do server giữ nhưng
không đọc được.

Group protocol cũng đã được tăng tính nhất quán. Khi client chủ động thêm,
xóa hoặc đổi thông tin quan trọng của group, client tạo một MLS Commit
dạng `S3MLS` và đưa nó vào transcript cục bộ. Commit có chữ ký Ed25519 của
identity key, actor, role của actor, epoch trước, epoch sau, danh sách member
trước và sau thay đổi, hash của các danh sách đó và hash commit trước đó. Khi
group info cho thấy membership đổi nhưng không khớp commit head local, UI có
thể cảnh báo bằng `History warning`.

Phần group hiện đã dùng OpenMLS. Phần còn cần làm thêm là
quy trình commit nhiều admin đồng thời, chưa có transparency log phân tán, và
chưa chứng minh hình thức rằng mọi client luôn có cùng view. Tuy vậy, so với
trước, server khó âm thầm đổi membership hoặc bỏ qua commit hơn vì client đã
có hash chain và chữ ký để phát hiện một phần.

Sau refactor gần nhất, inbound decrypt và replay history đã chuyển sang crypto engine. Phần cần dọn tiếp là các đường legacy cũ, đặc biệt là luồng key agreement cũ, để `App` không còn chứa logic crypto trực tiếp.

Server viết bằng C nên cần review kỹ các phần memory, string length, và lỗi
biên. Test hiện pass, nhưng với C thì test pass chưa đủ để nói an toàn tuyệt
đối.

## So sánh với Signal

Signal là hệ thống đã được dùng thật, được nghiên cứu nhiều năm, có spec rõ,
có triển khai trưởng thành, và có nhiều quyết định bảo mật đã được cộng đồng
kiểm tra.

SecChat giống Signal ở mức ý tưởng:

- có identity key;
- có prekey bundle;
- có ý tưởng PQXDH-style cho bắt tay ban đầu;
- có Double Ratchet-style cho DM;
- có safety number;
- có E2EE cho nội dung tin nhắn.

SecChat khác Signal ở các điểm quan trọng:

- không tương thích với client Signal thật;
- không dùng đúng wire format Signal;
- chữ ký identity dùng Ed25519 theo lựa chọn riêng của SecChat;
- group dùng OpenMLS RFC 9420, nhưng không phải Signal Groups và không tương thích wire-level với client MLS khác;
- metadata vẫn rất tập trung ở server;
- chưa có formal proof;
- chưa có nhiều năm audit và triển khai thực tế;
- phần crypto vẫn còn một số đường legacy và glue code cần dọn tiếp.

Cách trình bày an toàn nhất trong báo cáo là:

"SecChat áp dụng các ý tưởng từ Signal PQXDH, Double Ratchet, và MLS RFC 9420
MLS group, nhưng đây là giao thức SecChat riêng, không phải Signal chuẩn."

## Đánh giá như một phần mềm nhắn tin

Về tính năng, app đã có khá nhiều phần giống một ứng dụng chat thật:

- DM;
- group chat;
- saved messages;
- typing indicator;
- trạng thái read/unread cục bộ, không gửi read receipt cho peer;
- reaction;
- pin message và danh sách pinned messages;
- forward;
- edit;
- block user;
- profile và avatar;
- privacy settings;
- đổi mật khẩu;
- rotate safety key.

Điểm tốt là các API quan trọng đã có UI để dùng. Người dùng có thể kiểm thử
nhiều luồng mà không cần gửi WebSocket command thủ công.

Điểm UI đã cải thiện:

- message list hiện dùng row widget thật, có trạng thái sending, failed và retry;
- header hội thoại có banner giải thích rủi ro khi identity chưa verified, key
  đổi, audit lỗi, history đang tải hoặc cache local bị tắt;
- verify dialog nói rõ `Mark Verified` nghĩa là đã so sánh code ngoài SecChat;
- profile giải thích rõ rotate safety key và restore backup ảnh hưởng tới
  identity, ratchet, group và verification state;
- message không decrypt được có giải thích ngắn về thiếu state, MLS group hoặc
  local cache.

Điểm yếu còn lại là UI vẫn chưa phải app production. History rất lớn có thể chưa
tối ưu, media/file attachment chưa phải trọng tâm, onboarding bảo mật còn đơn
giản, notification đa nền tảng và accessibility chưa đầy đủ. Với đồ án, UI hiện
đủ để demo luồng bảo mật và tính năng chat. Nếu muốn thành sản phẩm thật, cần
kiểm thử UI dài hạn trên nhiều kích thước màn hình và thêm luồng hướng dẫn người
dùng mới.

## Đánh giá thiết kế server

Điểm tốt:

- server đã tách thành transport, infra, repository, service, domain;
- SQL đi qua repository;
- có migration;
- có health check và metrics;
- có test integration;
- Docker reset/rebuild được.

Điểm cần cải thiện:

- C server cần review memory an toàn hơn;
- migration chưa phải hệ thống migration production có rollback tốt;
- admin GUI mới ở mức hỗ trợ vận hành cơ bản;
- server vẫn là trung tâm metadata;
- rate limit và audit nên được thiết kế chặt hơn nếu dùng thật.

Report và moderation đã được bỏ khỏi phạm vi hiện tại. Client không còn UI
report, server không còn handler xử lý report, database không còn bảng
`user_reports`, và server GUI không còn tab report. Đây là quyết định đúng nếu
chưa có thiết kế moderation riêng cho E2EE, vì gửi plaintext hoặc bằng chứng
nhạy cảm lên server một cách tùy tiện sẽ làm sai mô hình bảo mật. Nếu sau này
cần chống abuse ở mức sản phẩm, hệ thống cần một thiết kế riêng về bằng chứng,
quyền truy cập, thời gian lưu, audit log và quy trình xử lý.

Vận hành production cũng chưa đầy đủ. SecChat hiện có health check, readiness,
metrics, rate limit cơ bản và script backup/restore database trong `tools`,
nhưng chưa có backup theo lịch, kiểm tra restore định kỳ, rollback migration,
alerting, log retention, incident response và giới hạn tài nguyên đủ chặt cho
môi trường thật. Chi tiết vận hành được ghi trong
`docs/production_operations_vi.md`.

## Đánh giá test

Bộ test hiện khá mạnh cho đồ án.

Test đang kiểm tra:

- auth và validation;
- friendship;
- group;
- E2EE history và relogin;
- offline message;
- edit event;
- pin và reaction;
- saved messages;
- privacy;
- metrics;
- crypto primitive của SecChat;
- Docker integration.

Nhưng test không thay thế formal verification. Test chứng minh các lỗi đã biết
không quay lại và luồng thường chạy đúng. Test không chứng minh giao thức an
toàn với mọi attacker.

## Đánh giá sau khi tách crypto engine

Việc thêm `CryptoSession` là bước đúng.

Trước refactor:

- `App` biết quá nhiều về file crypto;
- UI controller tự đọc/ghi key;
- test crypto phải dựng nhiều phần UI;
- rất dễ sửa UI rồi làm hỏng trạng thái E2EE.

Sau refactor:

- crypto state có owner rõ hơn;
- outbound encryption nằm ngoài UI controller;
- local encrypted storage nằm trong crypto package;
- có test riêng cho `CryptoSession`;
- ranh giới kiến trúc dễ giải thích hơn trong báo cáo.

Tuy vậy, đây mới là bước đầu. Bước tiếp theo nên là chuyển decrypt message nhận
vào, replay history, và xử lý pending edit/group key vào crypto engine. Khi đó
`App` chỉ nên gọi API mức cao và cập nhật UI.

## Kết luận cuối

SecChat hiện là một đồ án tốt để trình bày thiết kế hệ thống nhắn tin bảo mật:
nó có server, client, database, E2EE, hybrid post-quantum key agreement,
ratchet, MLS group, safety number, test regression, đặc tả giao thức và đặc
tả bảo mật toàn hệ thống.

Điểm cần nói thẳng là hệ thống chưa phải Signal, chưa phải production, chưa
formal verify, và chưa bảo vệ metadata. Nếu trình bày đúng phạm vi này, hệ
thống có nền tảng kỹ thuật hợp lý cho một đồ án về giao thức nhắn tin bảo mật.

## Việc nên làm tiếp

1. Dọn các đường legacy còn lại để crypto engine sở hữu toàn bộ pipeline mã hóa và giải mã.
2. Xóa hẳn các đường legacy khi không cần đọc dữ liệu cũ nữa.
3. Buộc test và review bám theo invariant trong đặc tả bảo mật khi sửa crypto, group, identity, backup hoặc cache.
4. Review C server theo hướng memory safety.
5. Tách metadata privacy thành một bài toán riêng, vì ẩn metadata khó hơn nhiều so với mã hóa nội dung tin nhắn.
6. Thay message list HTML bằng widget list thật nếu muốn UI mượt và đẹp hơn.
