# Bản đồ tài liệu tham khảo ↔ nội dung báo cáo

> Tài liệu phân tích. Mục đích: chỉ ra mỗi tài liệu trong `references.bib` được dùng để
> chống lưng cho nội dung nào, và những tài liệu **không thực sự được dùng**.
>
> **TRẠNG THÁI (đã xử lý):** Đã **bỏ 4 tài liệu không dùng** khỏi `references.bib` theo
> yêu cầu: `[4]` SPQR-blog, `[5]` SPQR-code, `[6]` Signal-formal, `[22]`
> mls-pq-ciphersuites. Danh mục hiện còn **21 mục** (báo cáo build lại sạch, 0 ref lỗi).
> Bảng bên dưới giữ nguyên để tra cứu; cột "Mức độ dùng" của 4 mục đó nay chỉ còn ý nghĩa
> lịch sử. Hai mục bối cảnh `[17]` FIPS 204, `[18]` FIPS 205 và mục lệch phiên bản
> `[10]` TLS 1.3 **vẫn được giữ** (chưa bỏ).

## 0. Lưu ý quan trọng về cách trích dẫn hiện tại

`main.tex` đang dùng **`\nocite{*}`** và **không có một lệnh `\cite{}` nội tuyến nào**.
Hệ quả:

- **Toàn bộ 25 mục** trong `references.bib` đều xuất hiện ở mục "Tài liệu tham khảo",
  bất kể có được nhắc tới trong nội dung hay không.
- Người đọc (và người chấm) **không thấy được chỗ nào trong bài dùng tài liệu nào**.
- Vì vậy, một tài liệu "thừa" (không có nội dung tương ứng) sẽ lộ ra như là *trích dẫn
  để cho đủ số lượng* — đúng rủi ro mà nhận xét trước đã cảnh báo.

Số trong ngoặc `[n]` dưới đây là **thứ tự xuất hiện** trong danh sách (do bibstyle
`unsrt` đánh số theo thứ tự trong file `.bib`).

---

## 1. Bảng map: tài liệu → nội dung được chống lưng

| [n] | Khóa BibTeX | Tài liệu | Chống lưng cho nội dung nào (chương · mục) | Mức độ dùng |
|----|-------------|----------|---------------------------------------------|-------------|
| [1] | `ref:mls-rfc9420` | RFC 9420 – MLS | **C1** §Forward secrecy, Double Ratchet và MLS (TreeKEM, ratchet tree, epoch, key schedule); **C2** §Thiết kế giao thức bảo mật – Group MLS hybrid; **C3** §Kiểm thử group MLS, §Đánh giá bảo mật | ⭐ Cốt lõi |
| [2] | `ref:pqxdh` | Signal – PQXDH | **C1** §Double Ratchet (liên hệ hậu lượng tử); **C2** §Prekey bundle kiểu PQXDH, bắt tay hybrid (≈28 lần); **C3** §Đánh giá bảo mật | ⭐ Cốt lõi |
| [3] | `ref:double-ratchet` | Signal – Double Ratchet | **C1** §Double Ratchet trong hội thoại hai người (bánh cóc đối xứng + DH); **C2** §Double Ratchet cho DM; **C3** | ⭐ Cốt lõi |
| [4] | `ref:spqr-blog` | Signal – SPQR / Triple Ratchet / ML-KEM Braid | **— không có nội dung nào trong bài nhắc tới** | ❌ KHÔNG dùng |
| [5] | `ref:spqr-code` | Signal – mã nguồn SPQR (GitHub) | **— không có nội dung nào trong bài nhắc tới** | ❌ KHÔNG dùng |
| [6] | `ref:signal-formal` | Cohn-Gordon et al. – Phân tích an toàn hình thức Signal | Không nhắc tên; *gián tiếp* liên quan tới §Forward secrecy/PCS nhưng không được dẫn | ❌ KHÔNG dùng (gián tiếp) |
| [7] | `ref:aes-gcm` | NIST SP 800-38D – AES-GCM | **C1** §Thuật toán AES và chế độ GCM (≈8 lần); **C2** §Quy trình đóng gói (ct = AES-256-GCM) | ⭐ Mạnh |
| [8] | `ref:hkdf-rfc5869` | RFC 5869 – HKDF | **C1** HKDF trong KDF_RK của Double Ratchet, ExpandWithLabel của MLS, HKDF "SecChat-PQXDH" (≈7 lần); **C2** | ⭐ Mạnh |
| [9] | `ref:pbkdf2-rfc8018` | RFC 8018 – PBKDF2 | **C1** §Hàm dẫn xuất khóa từ mật khẩu; **C2** §Mật khẩu và master key (băm 2 tầng) | ⭐ Mạnh |
| [10] | `ref:tls13-rfc8446` | RFC 8446 – TLS 1.3 | **C1** §Giao thức TLS (nhưng bài chỉ ghi "TLS" chung, **không ghi rõ phiên bản 1.3**); **C2/C3** kênh TLS | ⚠️ Dùng (lệch phiên bản) |
| [11] | `ref:eddsa-rfc8032` | RFC 8032 – Ed25519 | **C2** khóa định danh, ký prekey/credential (≈8 lần); **C3** (≈5 lần). *Lưu ý: phần "phạm vi hậu lượng tử" ở C1 từng nhắc Ed25519 nhưng nay đã bị lược; statement này còn ở C3 §Đánh giá bảo mật* | ⭐ Mạnh |
| [12] | `ref:x25519-rfc7748` | RFC 7748 – X25519/Curve25519 | **C1** DH trong Double Ratchet, PQXDH; **C2** prekey X25519, thành phần X-Wing (≈13 lần); **C3** | ⭐ Mạnh |
| [13] | `ref:shor` | Shor (1997) | **C1** §Thuật toán Shor và hệ quả; **Lời mở đầu** | ⭐ Mạnh |
| [14] | `ref:regev-lwe` | Regev – LWE | **C1** §Cơ sở toán học của mật mã trên lưới (định nghĩa LWE, quy dẫn worst-case) | ⭐ Mạnh |
| [15] | `ref:nist-pqc` | NIST – Chương trình chuẩn hóa PQC | **C1** §Chương trình chuẩn hóa của NIST | ⭐ Mạnh |
| [16] | `ref:fips203` | FIPS 203 – ML-KEM | **C1** §Chương trình chuẩn hóa + toàn bộ §Thuật toán ML-KEM (Kyber) | ⭐ Cốt lõi |
| [17] | `ref:fips204` | FIPS 204 – ML-DSA | **C1** chỉ trong câu liệt kê "FIPS 203, 204 và 205" + tên Dilithium. **Không dùng trong thiết kế** (hệ thống ký bằng Ed25519, không phải ML-DSA) | 🔸 Chỉ là bối cảnh |
| [18] | `ref:fips205` | FIPS 205 – SLH-DSA | **C1** §Các họ thuật toán (SPHINCS+) + câu "FIPS 203, 204 và 205". Không dùng trong thiết kế | 🔸 Chỉ là bối cảnh |
| [19] | `ref:kyber-paper` | CRYSTALS-Kyber (bài báo gốc) | **C1** §Thuật toán ML-KEM (toán học chi tiết: Module-LWE, biến đổi FO, kích thước) | ⭐ Mạnh |
| [20] | `ref:liboqs` | liboqs / Open Quantum Safe | **C1** §Thư viện Open Quantum Safe; **C3** §Đánh giá hiệu năng mật mã (benchmark) | ⭐ Mạnh |
| [21] | `ref:openmls` | OpenMLS (sách/thư viện) | **C2** bridge OpenMLS, validate public state (≈8 lần); **C3** group test (≈5 lần) | ⭐ Mạnh |
| [22] | `ref:mls-pq-ciphersuites` | draft-ietf-mls-pq-ciphersuites | **— không nhắc tới**; bài dùng thẳng X-Wing (draft-connolly) chứ không nhắc draft này | ❌ KHÔNG dùng |
| [23] | `ref:xwing` | draft-connolly-cfrg-xwing-kem | **C1** §Quy ước cách gọi (Kyber/ML-KEM/X-Wing); **C2** ciphersuite nhóm (≈18 lần); **C3** (≈9 lần) | ⭐ Cốt lõi |
| [24] | `ref:nist-80063b` | NIST SP 800-63B | **C1** §Hàm dẫn xuất khóa từ mật khẩu (chính sách mật khẩu) | ✅ Dùng (1 chỗ) |
| [25] | `ref:owasp-password` | OWASP Password Storage Cheat Sheet | **C1** §Hàm dẫn xuất khóa từ mật khẩu (khuyến nghị ≥ 600.000 vòng) | ✅ Dùng (1 chỗ) |

*(C1 = Chương 1 Kiến thức cơ sở, C2 = Chương 2 Phân tích & thiết kế, C3 = Chương 3 Cài đặt & đánh giá)*

---

## 2. Các tài liệu KHÔNG thực sự được dùng (cần quyết định)

Đây là những mục xuất hiện trong danh sách tham khảo nhưng **không có nội dung nào
trong báo cáo tương ứng**:

| [n] | Tài liệu | Vấn đề | Khuyến nghị |
|----|----------|--------|-------------|
| [4] | Signal SPQR (blog) | Không nhắc trong bài | **Gắn vào hoặc bỏ.** Nên thêm 1–2 câu ở **C3 §Hướng phát triển**: ratchet hiện dùng X25519 (cổ điển), hướng nâng cấp là ratchet hậu lượng tử kiểu SPQR / Triple Ratchet của Signal. Khi đó [4] (và có thể [5]) trở nên có ích. |
| [5] | Signal SPQR (mã nguồn) | Không nhắc trong bài | Chỉ giữ nếu thêm câu như trên; nếu không thì **bỏ** (trùng vai trò với [4]). |
| [6] | Cohn-Gordon – phân tích hình thức Signal | Không được dẫn; chỉ liên quan gián tiếp tới FS/PCS | **Tùy chọn.** Có thể dẫn ở chỗ khẳng định forward secrecy / post-compromise security để tăng độ tin cậy; hoặc **bỏ**. |
| [22] | draft-ietf-mls-pq-ciphersuites | Không nhắc; bài dùng thẳng X-Wing [23] | **Nên bỏ** (gần như trùng vai trò với [23]), trừ khi thêm câu nói về nỗ lý chuẩn hóa ciphersuite hậu lượng tử cho MLS nói chung. |

Ngoài ra, hai mục **chỉ mang tính bối cảnh** (không sai, nhưng yếu):

- **[17] FIPS 204 (ML-DSA)** và **[18] FIPS 205 (SLH-DSA)**: chỉ xuất hiện trong câu liệt
  kê "NIST công bố FIPS 203, 204 và 205" và qua tên Dilithium/SPHINCS+. Hệ thống không
  dùng hai chuẩn này (xác thực vẫn là Ed25519). → Giữ được vì là bối cảnh chuẩn hóa, nhưng
  nếu muốn danh mục thật "chặt" thì có thể bỏ.

- **[10] TLS 1.3 (RFC 8446)**: bài chỉ viết "TLS" chung, chưa khẳng định phiên bản 1.3.
  → Nên hoặc (a) ghi rõ "TLS 1.3" ở §Giao thức TLS để khớp tài liệu, hoặc (b) đổi sang một
  tài liệu TLS tổng quát hơn.

---

## 3. Gợi ý cải thiện cách trích dẫn (tùy chọn)

Hiện `\nocite{*}` làm mọi mục đều hiện ra. Để báo cáo "đáng tin" hơn, có thể:

1. **Thay `\nocite{*}` bằng các lệnh `\cite{}` đặt đúng chỗ** theo bảng map ở Mục 1.
   Ví dụ:
   - "...thuật toán Shor `\cite{ref:shor}`..." (C1 §Thuật toán Shor)
   - "...chuẩn hóa trong FIPS 203 `\cite{ref:fips203}`..." (C1 §ML-KEM)
   - "...Double Ratchet `\cite{ref:double-ratchet}`..." / "...MLS theo RFC 9420 `\cite{ref:mls-rfc9420}`..."
   - "...PBKDF2 `\cite{ref:pbkdf2-rfc8018}`...", "...OWASP `\cite{ref:owasp-password}`...", "...NIST SP 800-63B `\cite{ref:nist-80063b}`..."
   Khi đó danh sách chỉ liệt kê những gì thật sự được dẫn, và mỗi mục có ít nhất một chỗ
   trỏ tới — loại bỏ hoàn toàn rủi ro "trích dẫn thừa".

2. Nếu vẫn muốn giữ `\nocite{*}`, thì tối thiểu nên **xử lý 4 mục ở Mục 2** (gắn nội dung
   hoặc bỏ) để danh mục khớp với nội dung.

---

## 4. Tóm tắt

- **21/25** tài liệu có nội dung chống lưng rõ ràng (trong đó ~9 là cốt lõi).
- **4/25 không được dùng**: `[4]` SPQR-blog, `[5]` SPQR-code, `[6]` Signal-formal,
  `[22]` mls-pq-ciphersuites → cần *gắn vào hoặc bỏ*.
- **2 mục yếu/bối cảnh**: `[17]` FIPS 204, `[18]` FIPS 205.
- **1 mục lệch chi tiết**: `[10]` TLS 1.3 (bài chỉ ghi "TLS").
