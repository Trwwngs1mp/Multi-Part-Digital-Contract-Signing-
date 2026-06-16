# Hướng dẫn Test Suite - Multi-Part Digital Contract Signing

## Giới thiệu

Bộ kiểm thử (Test Suite) gồm **34 test cases** được viết bằng **pytest**, kiểm tra toàn diện các chức năng bảo mật của hệ thống ký số hợp đồng điện tử đa phần.

## Cấu trúc test suite

```
code/tests/
├── test_valid_flow.py      # 8 tests - Luồng chạy đúng
├── test_tampering.py        # 6 tests - Phát hiện giả mạo
├── test_replay.py           # 10 tests - Chống replay
└── test_invalid_key.py      # 7 tests - Xử lý khóa không hợp lệ
```

---

## 1. test_valid_flow.py (8 tests) - Luồng chạy đúng

Kiểm tra hệ thống hoạt động chính xác với dữ liệu hợp lệ.

| # | Tên test | Mục đích |
|---|----------|----------|
| 1 | `test_key_generation_ed25519` | Tạo cặp khóa Ed25519 thành công |
| 2 | `test_key_generation_rsa_pss` | Tạo cặp khóa RSA-PSS 2048 thành công |
| 3 | `test_sign_and_verify_part_ed25519` | Ký và xác minh 1 phần hợp đồng với Ed25519 |
| 4 | `test_sign_and_verify_part_rsa_pss` | Ký và xác minh 1 phần hợp đồng với RSA-PSS |
| 5 | `test_full_contract_flow_ed25519` | Luồng đầy đủ: chia → ký → ghép → xác minh với Ed25519 |
| 6 | `test_full_contract_flow_rsa_pss` | Luồng đầy đủ với RSA-PSS |
| 7 | `test_manifest_sign_and_verify` | Tạo và xác minh chữ ký Manifest |
| 8 | `test_contract_part_fields` | Kiểm tra các trường bắt buộc trong phần hợp đồng |

**Ví dụ**: Test `test_full_contract_flow_ed25519`:
1. Tạo khóa Ed25519
2. Chia hợp đồng mẫu thành 3 phần
3. Ký từng phần bằng private key
4. Ghép lại và xác minh bằng public key
5. **Kỳ vọng**: Xác minh PASS, hợp đồng ghép khớp với bản gốc

---

## 2. test_tampering.py (6 tests) - Phát hiện giả mạo

Kiểm tra hệ thống phát hiện các trường hợp dữ liệu bị can thiệp.

| # | Tên test | Mục đích |
|---|----------|----------|
| 1 | `test_detect_modified_content` | Phát hiện nội dung phần hợp đồng bị sửa |
| 2 | `test_detect_missing_part` | Phát hiện thiếu phần hợp đồng |
| 3 | `test_detect_reordered_parts` | Phát hiện đảo thứ tự các phần |
| 4 | `test_detect_extra_part` | Phát hiện thêm phần giả vào hợp đồng |
| 5 | `test_detect_hash_tampering` | Phát hiện mã hash bị sửa |
| 6 | `test_verify_valid_flow_still_works` | Kiểm tra luồng hợp lệ vẫn hoạt động sau các test |

**Cách phát hiện**:
- **Sửa nội dung**: So sánh SHA-256 hash của nội dung với hash đã lưu
- **Thiếu phần**: So sánh danh sách `part_id` thực tế với danh sách trong Manifest
- **Thừa phần**: Phát hiện `part_id` không có trong Manifest
- **Đảo thứ tự**: Kiểm tra `sequence_number` khớp với thứ tự trong Manifest
- **Sửa hash**: Xác minh chữ ký số sẽ thất bại vì dữ liệu không khớp

---

## 3. test_replay.py (10 tests) - Chống tấn công Replay

Kiểm tra cơ chế chống gửi lại gói tin cũ (Replay Attack).

| # | Tên test | Mục đích |
|---|----------|----------|
| 1 | `test_nonce_generation` | Nonce (số ngẫu nhiên) được tạo duy nhất |
| 2 | `test_create_packet` | Gói tin có đủ các trường bắt buộc |
| 3 | `test_valid_packet_accepted` | Gói tin hợp lệ được chấp nhận |
| 4 | `test_replay_detected` | Gói tin cũ gửi lại bị từ chối |
| 5 | `test_replay_across_packets` | Nhiều gói tin khác nhau đều được chấp nhận |
| 6 | `test_duplicate_sequence_rejected` | Số thứ tự trùng lặp bị từ chối |
| 7 | `test_different_contracts_independent` | Số thứ tự độc lập giữa các hợp đồng |
| 8 | `test_timestamp_expiry` | Gói tin hết hạn (TTL) bị từ chối |
| 9 | `test_message_id_consistency` | Phát hiện message_id không khớp |
| 10 | `test_persistence` | Nonce được lưu trữ qua các phiên làm việc |

**Cơ chế chống Replay** (3 lớp bảo vệ):
1. **Nonce** (16 byte ngẫu nhiên): Mỗi gói tin có nonce duy nhất
2. **Timestamp**: Giới hạn thời gian sống (TTL = 1 giờ)
3. **Sequence number**: Số thứ tự tăng dần, không trùng lặp

---

## 4. test_invalid_key.py (7 tests) - Xử lý khóa không hợp lệ

Kiểm tra hệ thống từ chối các khóa sai.

| # | Tên test | Mục đích |
|---|----------|----------|
| 1 | `test_wrong_public_key_fails` | Public key sai → xác minh thất bại |
| 2 | `test_correct_public_key_succeeds` | Public key đúng → xác minh thành công |
| 3 | `test_tampered_signature_fails` | Chữ ký bị sửa → phát hiện |
| 4 | `test_empty_signature_fails` | Chữ ký rỗng → phát hiện |
| 5 | `test_wrong_key_type_fails` | Dùng RSA key xác minh chữ ký Ed25519 → thất bại |
| 6 | `test_rsa_wrong_key_fails` | RSA-PSS với key sai → thất bại |
| 7 | `test_missing_key_file` | File key không tồn tại → báo lỗi |

---

## Cách chạy test

### Qua Web UI
1. Đăng nhập vào hệ thống
2. Vào mục **"🧪 Bộ kiểm thử"** (Security Test Suite)
3. Click **"▶️ Chạy Test Suite"**
4. Kết quả hiển thị sau vài giây

### Qua CLI
```bash
cd code
python -m pytest tests/ -v
```

### Kết quả mong đợi
```
34 passed in ~2-3 seconds
```

## Ý nghĩa bảo mật

| Loại test | Mô phỏng tấn công | Kết quả |
|-----------|-------------------|---------|
| **Valid Flow** | Không có (luồng chuẩn) | ✅ PASS |
| **Tampering** | Sửa nội dung, xóa/thêm/đảo phần, sửa hash | ✅ Phát hiện → FAIL |
| **Replay** | Gửi lại gói tin cũ, nonce trùng, hết hạn | ✅ Phát hiện → FAIL |
| **Invalid Key** | Sai key, sai thuật toán, chữ ký giả | ✅ Phát hiện → FAIL |

## Kết luận

Hệ thống vượt qua toàn bộ **34/34 test cases**, chứng minh khả năng:
- ✅ Ký và xác minh hợp đồng đa phần chính xác
- ✅ Phát hiện mọi hình thức giả mạo dữ liệu
- ✅ Chống tấn công replay với 3 lớp bảo vệ
- ✅ Xử lý đúng các trường hợp khóa không hợp lệ