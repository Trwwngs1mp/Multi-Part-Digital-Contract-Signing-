# Multi-Part Digital Contract Signing

> **Đề tài 3 – FIT4012: Nhập môn An toàn Bảo mật Thông tin**  
> *Secure System Upgrade Challenge – Multi-Part Digital Contract Signing*

---

## 📋 Giới thiệu

Hệ thống **Multi-Part Digital Contract Signing** cho phép người gửi chia một hợp đồng điện tử thành nhiều phần, mỗi phần được ký số riêng, và toàn bộ hợp đồng được đảm bảo tính toàn vẹn thông qua một **manifest được ký số tổng**.

Hỗ trợ **3 thuật toán chữ ký số**: Ed25519, ECDSA P-256, RSA-PSS.

### Tính năng chính

- ✅ **3 thuật toán chữ ký số**: Ed25519, ECDSA P-256, RSA-PSS
- ✅ Chia hợp đồng thành nhiều phần (part)
- ✅ Mỗi phần có: `part_id`, `contract_id`, `sequence_number`, `hash`, `signature`
- ✅ Manifest toàn bộ hợp đồng được ký số
- ✅ Phát hiện: thiếu phần, thừa phần, đảo thứ tự, sửa nội dung
- ✅ **Mã hóa nội dung hợp đồng** bằng AES-GCM (256-bit)
- ✅ Cơ chế chống replay (nonce + timestamp + sequence_number)
- ✅ Ghi log bảo mật (không chứa key/password)
- ✅ **Web UI** Flask với đăng nhập/đăng ký (Cá nhân & Doanh nghiệp)
- ✅ Upload file .txt từ máy
- ✅ Gửi & nhận hợp đồng giữa các users
- ✅ Người nhận xác nhận (Accept Contract) trước khi hoàn tất
- ✅ CLI command-line interface
- ✅ **Bcrypt** cho password hashing (PBKDF2-SHA256 fallback)

---

## 📁 Cấu trúc Repository

```
fit4012-secure-system/
├── README.md
├── .gitignore
├── requirements.txt
│
├── prod/                       # Thư mục lên ý tưởng, spec, báo cáo, marketing
│   ├── assignment.md           # Bảng phân công công việc
│   ├── spec/
│   │   ├── protocol_design.md  # Thiết kế giao thức
│   │   └── threat_model.md     # Phân tích mối đe dọa
│   ├── report/                 # Báo cáo PDF (sẽ sinh sau)
│   ├── figures/                # Sơ đồ kiến trúc, sequence diagram
│   ├── docs/
│   │   ├── test_suite_guide.md # Hướng dẫn bộ kiểm thử
│   │   ├── sample_accounts.md  # Danh sách tài khoản mẫu
│   │   └── benchmark.md        # Benchmark hiệu năng
│   └── marketing/              # Nội dung marketing, slide
│
├── code/                       # Thư mục chứa mã nguồn
│   ├── src/
│   │   ├── web/                # Web UI (Flask)
│   │   │   ├── app.py          # Flask application
│   │   │   ├── user_manager.py # Quản lý user, auth, contract
│   │   │   └── templates/
│   │   │       └── index.html  # Giao diện người dùng
│   │   ├── client/
│   │   │   ├── contract_signer.py
│   │   │   └── cli.py          # Giao diện dòng lệnh
│   │   ├── server/
│   │   │   ├── contract_handler.py  # Xử lý hợp đồng
│   │   │   └── manifest.py          # Quản lý manifest
│   │   ├── crypto/
│   │   │   └── crypto_manager.py    # Quản lý mã hóa, chữ ký
│   │   └── utils/
│   │       ├── logger.py            # Ghi log bảo mật
│   │       └── replay_protection.py # Chống replay
│   ├── tests/
│   │   ├── test_valid_flow.py       # 8 tests - Luồng hợp lệ
│   │   ├── test_tampering.py        # 6 tests - Phát hiện giả mạo
│   │   ├── test_replay.py           # 10 tests - Chống replay
│   │   └── test_invalid_key.py      # 7 tests - Sai key
│   └── sample_data/
│       └── contract_sample.txt      # Hợp đồng mẫu
```

---

## 🚀 Cài đặt & Chạy

### Yêu cầu

- Python 3.9+
- pip

### Cài đặt

```bash
git clone https://github.com/Trwwngs1mp/Multi-Part-Digital-Contract-Signing-.git
cd Multi-Part-Digital-Contract-Signing
pip install -r requirements.txt
```

### Chạy Web UI (Khuyến nghị)

```bash
cd code
python -m src.web.app
# Mở trình duyệt tại http://localhost:5000
```

### Chạy CLI

```bash
cd code
python src/client/cli.py generate-keys
python src/client/cli.py sign ../sample_data/contract_sample.txt
python src/client/cli.py verify output/contract_sample/manifest.json output/contract_sample/parts/
```

### Chạy tất cả test

```bash
cd code
python -m pytest tests/ -v
```

---

## 🔐 Kỹ thuật bảo mật

| Yêu cầu              | Giải pháp                                        |
|----------------------|--------------------------------------------------|
| Mã hóa dữ liệu       | AES-GCM 256-bit cho nội dung hợp đồng khi lưu     |
| Chữ ký số            | Ed25519 / ECDSA P-256 / RSA-PSS                  |
| Kiểm tra toàn vẹn    | SHA-256 hash từng phần + manifest ký số          |
| Chống replay         | nonce (16 byte) + timestamp + sequence_number    |
| Quản lý khóa         | Lưu file PEM, không hard-code trong source       |
| Log bảo mật          | `SecurityLogger` lọc key/password khỏi log       |
| Password hashing     | Bcrypt (PBKDF2-SHA256 fallback)                  |

---

## 👥 Tài khoản mẫu

Xem danh sách đầy đủ tại [`prod/docs/sample_accounts.md`](prod/docs/sample_accounts.md)

| Username | Password | Loại |
|----------|----------|------|
| `admin` | `admin123` | Cá nhân (Quản trị) |
| `congty_abc` | `abc123` | Doanh nghiệp |
| `nguyen_van_a` | `pass123` | Cá nhân |
| `tran_thi_b` | `pass456` | Cá nhân |
| `doanhnghiep_xyz` | `xyz123` | Doanh nghiệp |
| `startup_tech` | `tech123` | Doanh nghiệp |

---

## 🧪 Kết quả kiểm thử

**34/34 tests PASSED** — Kiểm thử với pytest:

| Nhóm test | File | Số lượng |
|-----------|------|----------|
| ✅ Luồng hợp lệ | `test_valid_flow.py` | 8 tests |
| 🛡️ Phát hiện giả mạo | `test_tampering.py` | 6 tests |
| 🔄 Chống replay | `test_replay.py` | 10 tests |
| 🔑 Xử lý khóa sai | `test_invalid_key.py` | 7 tests |
| ⚡ Benchmark | (CLI built-in) | 3 algorithms |

---

## 👥 Thành viên nhóm

| STT | Họ và Tên | Vai trò |
|-----|-----------|---------|
| 1   | Thành viên A | Leader / Backend & Crypto |
| 2   | Thành viên B | Backend - Xử lý hợp đồng & Server |
| 3   | Thành viên C | Frontend / CLI / Báo cáo & Demo |

> Chi tiết phân công xem tại [`prod/assignment.md`](prod/assignment.md)

---

## 📝 Giấy phép

Dự án học tập – FIT4012, Nhập môn An toàn Bảo mật Thông tin