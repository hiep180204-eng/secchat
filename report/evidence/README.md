# Evidence captures for Chương 3 (kiểm thử & kiểm toán)

Tất cả số liệu trong Chương 3 được chụp trực tiếp từ stack Docker đang chạy
(ngày 2026-06-11). Cách tái lập:

## 1. Kiểm thử chức năng (24/24 file PASS)
```
python tests/run_all_tests.py --category legacy,server_contract,crypto_contract
```
Log đầy đủ: `tests_run.log` (kết thúc bằng "24/24 passed, 0 failed").
- domain unit: 75 passed / 0 failed
- crypto primitive (identity/hybrid/group/kem/password): 55 / 0
- security regression: 16 / 0 ; security & metrics: 17 / 0

## 2. Bằng chứng "server không lưu plaintext"
```
docker compose exec -T db mysql -uchatuser -p<DB_PASS> --table chatdb \
  -e "SELECT COUNT(*) FROM messages;
      SELECT LEFT(body,5), COUNT(*) FROM messages GROUP BY LEFT(body,5);"
```
Kết quả: 2/2 message có prefix `S3DR:` (Double Ratchet, base64), 0 plaintext.

## 3. Kiểm toán mã nguồn C (công cụ chuẩn)
```
python tools/run_server_c_audit.py --skip-install --fuzz-runs 30000
```
hoặc từng bước trong container server (`/build`):
- `make cppcheck`           -> 37/37 file, 0 finding
- `make asan_test_domain`   -> Results: 75 passed, 0 failed
- `make fuzz_json_validation` -> 30000 runs, cov 719, 0 crash artifact
- `make fuzz_ws_frame`        -> 30000 runs, cov 64,  0 crash artifact

LƯU Ý môi trường: kernel container đặt `vm.mmap_rnd_bits=32` (ASLR tối đa) gây
xung đột shadow-memory của AddressSanitizer -> tiến trình ASan/fuzzer đôi khi
SIGSEGV NGAY LÚC KHỞI TẠO (trước log đầu tiên, không có crash artifact, không có
báo cáo ASan). Đây là vấn đề môi trường, không phải lỗi parser. Chạy lại đến khi
có lượt khởi tạo sạch; lượt sạch hoàn tất đủ 30000 vòng, 0 crash.
Log: `c_audit.log`.

## 4. OpenMLS X-Wing selftest
```
docker exec chat-client1 secchat_mls_bridge selftest
```
openmls 0.8.1; ciphersuite MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
pq_hybrid=true; validator_create_ok / rejects_bogus_commit / remove_ok = true.

## 5. Số liệu vận hành
```
curl http://localhost:18889/metrics
```
auth 242 (ok234/fail7/rl1), reg 220, msg sent 108, groups 6,
ws recv/sent 1218/1556, conns acc/peak 476/4, db queries 1125 (errors 2 từ
test fault-injection cố ý), preauth_timeout 1, validation_errors 5.
Latency trung bình: auth ~229ms, msg ~62ms, db ~19ms.
