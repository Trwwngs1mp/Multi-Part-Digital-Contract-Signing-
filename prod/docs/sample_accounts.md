# Danh sách tài khoản mẫu
## Multi-Part Digital Contract Signing

Hệ thống khởi tạo sẵn **12 tài khoản mẫu** để thuận tiện cho việc demo và kiểm thử.

### Tài khoản quản trị

| Username | Password | Họ tên | Loại | Email |
|----------|----------|--------|------|-------|
| `admin` | `admin123` | Admin System | Cá nhân | admin@contract.com |

### Tài khoản cá nhân

| Username | Password | Họ tên | Email |
|----------|----------|--------|-------|
| `nguyen_van_a` | `pass123` | Nguyễn Văn An | an.nguyen@email.com |
| `tran_thi_b` | `pass456` | Trần Thị Bình | binh.tran@email.com |
| `le_van_c` | `pass789` | Lê Văn Cường | cuong.le@email.com |
| `pham_thi_d` | `pass000` | Phạm Thị Dung | dung.pham@email.com |
| `hoang_van_e` | `hoang123` | Hoàng Văn Em | em.hoang@email.com |
| `vu_thi_f` | `vu123` | Vũ Thị Phương | phong.vu@email.com |
| `dang_van_g` | `dang123` | Đặng Văn Giap | giap.dang@email.com |

### Tài khoản doanh nghiệp

| Username | Password | Tên doanh nghiệp | Email |
|----------|----------|-----------------|-------|
| `congty_abc` | `abc123` | Công ty TNHH ABC | abc@company.com |
| `doanhnghiep_xyz` | `xyz123` | Công ty CP XYZ | xyz@company.com |
| `startup_tech` | `tech123` | Startup Tech Solutions | tech@startup.com |
| `doanhnghiep_mnp` | `mnp123` | Tập đoàn MNP | mnp@group.com |

---

### Cách sử dụng

1. Mở trang đăng nhập tại **http://localhost:5000**
2. Nhập `Username` và `Password` từ danh sách trên
3. Click **"Đăng nhập"**

### Gợi ý luồng demo

1. Đăng nhập với **admin** để tạo khóa Ed25519
2. Đăng nhập với **congty_abc** để tạo hợp đồng, gửi cho **nguyen_van_a** và **tran_thi_b**
3. Đăng nhập với **nguyen_van_a** để xem và xác nhận hợp đồng đã nhận
4. Đăng nhập với **tran_thi_b** để xem và xác nhận
5. Quay lại **congty_abc** để xác minh hợp đồng