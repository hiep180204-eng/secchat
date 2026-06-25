# Đánh giá và quyết định chuyển group sang MLS RFC 9420

## Kết luận hiện tại

SecChat đã chuyển group flow sang backend OpenMLS theo RFC 9420. Client tạo và xử lý KeyPackage, Welcome, Commit, GroupInfo và application message bằng bridge Rust `mls_bridge/`. Server chỉ kiểm tra quyền thao tác, lưu/phát vật liệu MLS và cập nhật membership sau khi nhận `apply_group_change` hợp lệ. Server không sinh group secret và không giải mã nội dung group.

Wire group vẫn dùng prefix `S3MLS:` để bọc envelope ứng dụng của SecChat, nhưng bytes bên trong là message do OpenMLS sinh ra. Vì vậy báo cáo có thể mô tả group là “MLS RFC 9420 bằng OpenMLS”, đồng thời cần nói rõ SecChat không tương thích wire-level với Signal hoặc client MLS độc lập khác do credential binding, API server và envelope ứng dụng là thiết kế riêng.

## Vì sao chọn OpenMLS

MLS đầy đủ không chỉ là đổi key theo epoch. Nó có ratchet tree, TreeKEM, proposal, commit, update path, Welcome, GroupInfo, transcript hash, confirmation tag, secret tree và quy tắc xử lý state chặt chẽ. Tự viết lại các thành phần này trong Python/C rất dễ tạo ra giao thức trông giống MLS nhưng sai chi tiết.

OpenMLS được chọn vì nó triển khai các primitive và state machine MLS thay cho lớp group tự xây. SecChat chỉ giữ phần tích hợp sản phẩm: publish/claim KeyPackage, policy friend/admin/block, mapping conversation id, lưu handshake và bọc application control message.

## Những phần đã thay đổi trong SecChat

- Client login khởi tạo hoặc nạp MLS identity, sau đó publish KeyPackage single-use.
- Tạo nhóm, thêm thành viên và kick/remove đi qua `prepare_group_change` rồi `apply_group_change`.
- Thành viên mới join bằng Welcome nhắm đúng KeyPackage đã claim.
- Thành viên bị remove không nhận secret epoch mới và không đọc được message sau khi bị remove.
- Role, tên nhóm, avatar nhóm và bio nhóm là control message mã hóa trong MLS; server chỉ cập nhật metadata sau operation hợp lệ.
- Bridge OpenMLS export/import storage và signer state vào `mls_state.bin` đã mã hóa bằng master key cục bộ, nên backup E2EE có thể mang theo MLS group state.
- Khi rotate safety key, client xóa MLS state cũ để không publish lại KeyPackage đã bind với identity cũ.

## Giới hạn vẫn cần nói rõ

SecChat không phải client MLS liên thông chung. Nó dùng OpenMLS cho state machine và cryptographic message, nhưng phần định tuyến, account identity, auditor binding, operation id, metadata server và UI đều là protocol riêng của SecChat.

Hệ thống cũng chưa có formal proof hoặc test interop với implementation MLS độc lập khác. Vì vậy cách trình bày đúng là: SecChat dùng OpenMLS theo RFC 9420 cho group E2EE, nhưng toàn bộ sản phẩm vẫn là giao thức SecChat riêng, chưa phải một client MLS liên thông chuẩn.
