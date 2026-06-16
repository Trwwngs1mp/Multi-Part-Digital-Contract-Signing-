# Threat Model - Multi-Part Digital Contract Signing

## 1. Tài sản cần bảo vệ

| Tài sản | Mô tả | Mức độ quan trọng |
|---------|-------|-------------------|
| Hợp đồng điện tử | Nội dung các điều khoản hợp đồng | Cao |
| Chữ ký số | Chữ ký của người gửi trên từng phần hợp đồng | Cao |
| Manifest | Danh sách các phần hợp đồng đã được ký tổng | Cao |
| Private key | Khóa bí mật dùng để ký | Rất cao |
| Public key | Khóa công khai dùng để xác minh | Trung bình |

## 2. Tác nhân tham gia

| Tác nhân | Vai trò | Quyền |
|----------|---------|-------|
| Sender (Người gửi) | Chia hợp đồng, ký số, gửi | Có private key |
| Receiver (Người nhận) | Nhận, xác minh, ghép hợp đồng | Có public key |
| Attacker (Kẻ tấn công) | Cố gắng phá hoại tính toàn vẹn | Không có key hợp lệ |

## 3. Các nguy cơ bảo mật

| STT | Nguy cơ | Mô tả | Biện pháp |
|-----|---------|-------|-----------|
| 1 | **Sửa nội dung** | Attacker sửa nội dung một phần hợp đồng | SHA-256 hash + chữ ký số từng phần |
| 2 | **Thiếu phần** | Attacker xóa một phần hợp đồng | Manifest liệt kê tất cả part_id |
| 3 | **Thừa phần** | Attacker thêm phần giả vào hợp đồng | So sánh part_id với manifest |
| 4 | **Đảo thứ tự** | Attacker đảo thứ tự các phần | sequence_number + kiểm tra thứ tự |
| 5 | **Giả mạo chữ ký** | Attacker tự ký bằng key của mình | Xác minh chữ ký với public key của sender |
| 6 | **Replay attack** | Attacker gửi lại gói tin cũ | nonce + timestamp + sequence_number |
| 7 | **Manipulate manifest** | Attacker sửa manifest | Manifest được ký số riêng |
| 8 | **Lộ private key** | Key bị rò rỉ | Lưu key ngoài source code, không hard-code |

## 4. Kịch bản tấn công (Misuse Cases)

### 4.1 Tampering
1. Attacker chặn gói tin chứa PART-002
2. Attacker sửa nội dung "Giá trị: 100 triệu" → "Giá trị: 10 triệu"
3. Hệ thống phát hiện: hash của nội dung không khớp → **FAIL**

### 4.2 Missing Part
1. Attacker chặn và xóa PART-003
2. Receiver chỉ nhận được PART-001 và PART-002
3. Hệ thống phát hiện: manifest yêu cầu 3 phần → **FAIL**

### 4.3 Reorder
1. Attacker đảo thứ tự: [PART-003, PART-001, PART-002]
2. Hệ thống kiểm tra: sequence_number(003)=3 nhưng ở vị trí đầu → **FAIL**

### 4.4 Replay
1. Attacker ghi lại gói tin PART-001 cũ
2. Attacker gửi lại gói tin đó
3. Hệ thống kiểm tra: nonce đã được xử lý → **FAIL**

## 5. Giả định và giới hạn

- Kênh truyền giữa sender và receiver là không an toàn (Internet)
- Private key được lưu an toàn trên máy của sender
- Public key được chia sẻ qua kênh xác thực riêng
- Hệ thống không mã hóa nội dung hợp đồng (chỉ ký số)
- Hệ thống không có cơ chế thu hồi key (phát triển sau)