# Protocol Design - Multi-Part Digital Contract Signing

## 1. Tổng quan giao thức

Hệ thống cho phép người gửi (Sender) ký một hợp đồng điện tử gồm nhiều phần, và người nhận (Receiver) xác minh từng phần cũng như toàn bộ hợp đồng.

## 2. Luồng xử lý

```
Sender                              Receiver
  |                                    |
  |-- 1. Generate Keys --------------->| (chia sẻ public key)
  |                                    |
  |-- 2. Split Contract (N parts)      |
  |-- 3. Sign each part                |
  |-- 4. Build manifest                |
  |-- 5. Sign manifest                 |
  |                                    |
  |-- 6. Send (parts + manifest) ----->|
  |                                    |-- 7. Verify manifest signature
  |                                    |-- 8. Verify each part signature
  |                                    |-- 9. Check: missing parts
  |                                    |-- 10. Check: extra parts
  |                                    |-- 11. Check: reordered parts
  |                                    |-- 12. Check: content integrity
  |                                    |-- 13. Reassemble contract (if OK)
  |                                    |-- 14. Log all events
  |                                    |
  |<--- 15. Result (PASS/FAIL) --------|
```

## 3. Cấu trúc dữ liệu

### 3.1 Contract Part
```json
{
  "part_id": "PART-001",
  "contract_id": "CONTRACT-ABC123",
  "sequence_number": 1,
  "content": "Nội dung phần hợp đồng...",
  "hash": "sha256_hex_digest",
  "signature": "ed25519_signature_hex",
  "algorithm": "ed25519"
}
```

### 3.2 Manifest
```json
{
  "contract_id": "CONTRACT-ABC123",
  "total_parts": 3,
  "parts": [
    {"part_id": "PART-001", "sequence_number": 1, "hash": "sha256_of_part1"},
    {"part_id": "PART-002", "sequence_number": 2, "hash": "sha256_of_part2"},
    {"part_id": "PART-003", "sequence_number": 3, "hash": "sha256_of_part3"}
  ],
  "manifest_signature": "ed25519_signature_hex",
  "signature_algorithm": "ed25519"
}
```

### 3.3 Packet (có replay protection)
```json
{
  "contract_id": "CONTRACT-ABC123",
  "part_id": "PART-001",
  "sequence_number": 1,
  "nonce": "random_16_byte_hex",
  "timestamp": 1700000000,
  "message_id": "sha256_hash",
  "payload": { ... }
}
```

## 4. Thuật toán

- **Chữ ký số**: Ed25519 (ưu tiên) / RSA-PSS
- **Hash**: SHA-256
- **Cơ chế chống replay**: nonce (16 byte) + timestamp + sequence_number
- **Log**: SecurityLogger loại bỏ mọi thông tin nhạy cảm

## 5. Kiểm tra bảo mật

1. **Manifest signature**: Xác minh chữ ký của manifest
2. **Part signature**: Xác minh chữ ký từng phần
3. **Content hash**: Kiểm tra hash của nội dung
4. **Missing parts**: So sánh danh sách part_id với manifest
5. **Extra parts**: Phát hiện part không có trong manifest
6. **Reordered parts**: Kiểm tra sequence_number khớp với manifest
7. **Replay**: Nonce uniqueness + timestamp TTL + sequence tracking