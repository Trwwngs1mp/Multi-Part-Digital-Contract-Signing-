# Multi-Part Digital Contract Signing

> **Đề tài 3 – FIT4012: Nhập môn An toàn Bảo mật Thông tin**  
> *Secure System Upgrade Challenge – Multi-Part Digital Contract Signing*

---

## 📋 Giới thiệu

Hệ thống **Multi-Part Digital Contract Signing** cho phép người gửi chia một hợp đồng điện tử thành nhiều phần, mỗi phần được ký số riêng bằng thuật toán **Ed25519/RSA-PSS**, và toàn bộ hợp đồng được đảm bảo tính toàn vẹn thông qua một **manifest được ký số tổng**.

### Tính năng chính

- ✅ Chia hợp đồng thành nhiều phần (part)
- ✅ Mỗi phần có: `part_id`, `contract_id`, `sequence_number`, `hash`, `signature`
- ✅ Chữ ký số Ed25519 / RSA-PSS cho từng phần
- ✅ Manifest toàn bộ hợp đồng được ký số
- ✅ Phát hiện: thiếu phần, thừa phần, đảo thứ tự, sửa nội dung
- ✅ Cơ chế chống replay (nonce + timestamp + sequence_number)
- ✅ Ghi log bảo mật (không chứa key/password)
- ✅ CLI thân thiện

---

## 📁 Cấu trúc Repository

```
fit4012-secure-system/
├── README.md
├── requirements.txt
│
├── prod/                       # Thư mục lên ý tưởng, spec, báo cáo, marketing
│   ├── assignment.md           # Bảng phân công công việc
│   ├── spec/
│   │   ├── protocol_design.md  # Thiết kế giao thức
│   │   └── threat_model.md     # Phân tích mối đe dọa
│   ├── report/
│   │   └── report.pdf          # Báo cáo PDF (sẽ sinh sau)
│   ├── figures/                # Sơ đồ kiến trúc, sequence diagram
│   ├── docs/
│   │   ├── test_report.md      # Test report tổng hợp
│   │   ├── benchmark.md        # Benchmark hiệu năng
│   │   └── video_demo.md       # Video demo
│   └── marketing/              # Nội dung marketing, slide
│
├── code/                       # Thư mục chứa mã nguồn
│   ├── src/
│   │   ├── client/
│   │   │   ├── __init__.py
│   │   │   ├── contract_signer.py   # Ký hợp đồng
│   │   │   └── cli.py               # Giao diện dòng lệnh
│   │   ├── server/
│   │   │   ├── __init__.py
│   │   │   ├── contract_handler.py  # Xử lý hợp đồng
│   │   │   └── manifest.py          # Quản lý manifest
│   │   ├── crypto/
│   │   │   ├── __init__.py
│   │   │   └── crypto_manager.py    # Quản lý mã hóa, chữ ký
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── logger.py            # Ghi log
│   │       └── replay_protection.py # Chống replay
│   ├── tests/
│   │   ├── test_valid_flow.py       # Test luồng hợp lệ
│   │   ├── test_tampering.py        # Test sửa nội dung
│   │   ├── test_replay.py           # Test replay
│   │   ├── test_invalid_key.py      # Test sai key
│   │   └── __init__.py
│   └── sample_data/
│       ├── contract_sample.txt      # Hợp đồng mẫu
│       └── manifest_sample.json     # Manifest mẫu
```

---

## 🚀 Hướng dẫn cài đặt

### Yêu cầu

- Python 3.9+
- pip

### Cài đặt

```bash
# Clone repository
git clone https://github.com/Trwwngs1mp/Multi-Part-Digital-Contract-Signing-.git
cd Multi-Part-Digital-Contract-Signing

# Cài đặt dependencies
pip install -r requirements.txt
```

### Chạy chương trình

```bash
# Chạy CLI
python code/src/client/cli.py --help

# Tạo key
python code/src/client/cli.py generate-keys

# Ký hợp đồng
python code/src/client/cli.py sign --contract sample_data/contract_sample.txt

# Xác minh hợp đồng
python code/src/client/cli.py verify --contract sample_data/contract_sample.txt

# Chạy tất cả test
cd code && python -m pytest tests/ -v
```

---

## 🔐 Kỹ thuật bảo mật

| Yêu cầu              | Giải pháp                              |
|----------------------|----------------------------------------|
| Mã hóa               | Không áp dụng trực tiếp (hợp đồng ký số) |
| Chữ ký số            | Ed25519 (ưu tiên) + RSA-PSS            |
| Kiểm tra toàn vẹn    | SHA-256 hash từng phần + manifest ký    |
| Chống replay         | nonce (16 byte) + timestamp + sequence_number |
| Quản lý khóa         | Tạo key bằng thư viện `cryptography`, lưu file PEM |
| Log bảo mật          | `logging` + không in key/password      |

---

## 📊 Kết quả kiểm thử (Test Coverage)

- ✅ Luồng hợp lệ: ký → xác minh → ghép hợp đồng
- ✅ Phát hiện sửa nội dung một phần
- ✅ Phát hiện thiếu phần hợp đồng
- ✅ Phát hiện đảo thứ tự các phần
- ✅ Phát hiện sai public key
- ✅ Phát hiện replay (dùng lại gói tin cũ)
- ✅ Benchmark hiệu năng

---

## 👥 Thành viên nhóm

| STT | Họ và Tên | Vai trò |
|-----|-----------|---------|
| 1   | Tên A     | Leader / Backend & Crypto |
| 2   | Tên B     | Backend - Xử lý hợp đồng & Server |
| 3   | Tên C     | Frontend / CLI / Báo cáo & Demo |

> Chi tiết phân công công việc xem tại [prod/assignment.md](prod/assignment.md)

---

## 📝 Giấy phép

Dự án học tập – FIT4012, Học kỳ ... năm học 20...