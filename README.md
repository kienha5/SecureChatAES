# SecureChat

Hệ thống chat bảo mật kết hợp PKI + Kerberos + E2EE, viết bằng C++.

---

## Yêu cầu

- Windows 10/11 (64-bit)
- Visual Studio 2022 (với C++ Desktop Development workload)
- Git

---

## Setup

### Bước 1 — Clone repo

```
git clone <url-repo>
cd SecureChat
```

### Bước 2 — Cài vcpkg

```
git clone https://github.com/microsoft/vcpkg
cd vcpkg
.\bootstrap-vcpkg.bat
```

### Bước 3 — Cài dependencies

```
.\vcpkg install openssl:x64-windows
.\vcpkg install nlohmann-json:x64-windows
```

### Bước 4 — Integrate với Visual Studio

```
.\vcpkg integrate install
```

> Chỉ cần chạy lệnh này **1 lần** trên mỗi máy.

### Bước 5 — Build

Mở `SecureChat.sln` trong Visual Studio, bấm **Ctrl+Shift+B** để build toàn bộ solution.

---

## Chạy chương trình (sau khi build release)

Các server và client phải được khởi động **đúng thứ tự** sau:

```
1. CA_Server.exe
2. IntermediateCA_Server.exe
3. RA_Server.exe
4. KDC_Server.exe
5. Chat_Server.exe
6. Client_GUI.exe     (hoặc Client.exe cho bản CLI)
```

Tất cả file `.exe` nằm trong thư mục `x64\Debug\` hoặc `x64\Release\`.

> **Lần đầu chạy:** Các server sẽ tự động tạo certificates và lưu vào thư mục
> `SecureChatCerts\` ở root của solution. Không cần tạo thủ công.

## Cấu hình chạy nhiều project cùng lúc (khuyến nghị)

Thay vì mở từng file `.exe` thủ công, có thể cấu hình Visual Studio
chạy tất cả server cùng lúc:

1. Chuột phải vào **Solution** trong Solution Explorer → **Properties**
2. Chọn **Common Properties → Startup Project**
3. Chọn **Multiple startup projects**
4. Cấu hình như sau:

| Project | Action |
|---|---|
| `CA_Server` | Start |
| `IntermediateCA_Server` | Start |
| `RA_Server` | Start |
| `KDC_Server` | Start |
| `Chat_Server` | Start |
| `Client_GUI` | Start |
| `Client` | None |
| `Common` | None |
| `Admin` | None |

5. Bấm **OK**
6. Bấm **F5** hoặc **Ctrl+F5** để chạy tất cả cùng lúc

> **Lưu ý:** Visual Studio khởi động tất cả project gần như cùng lúc.
> Client_GUI có sẵn delay 2 giây khi khởi động để chờ các server
> sẵn sàng. Nếu gặp lỗi kết nối, đóng tất cả và chạy lại.
---

## Sử dụng (GUI Client)

### Đăng ký tài khoản mới

1. Nhập **username** và **password**
2. Chọn tab **Register**
3. Bấm lần lượt:
   - `1. Get Certificate (RA)`
   - `2. Register Account (Chat Server)`
   - `3. Register KDC`
4. Chuyển sang tab **Login**, bấm `Login`

### Đăng nhập lần sau

1. Nhập username và password
2. Tab **Login** → bấm `Login`

### Chat

1. Sau khi login, danh sách người online hiện ở góc trên bên phải
2. Click vào tên người muốn chat → tên tự điền vào ô **Chat with**
3. Bấm **Start Chat**
4. Phía người nhận sẽ tự động nhận session

---

## Security Tests

Sau khi login, bấm nút **Security Tests** ở góc trên để mở màn hình test gồm 6 bài:

| Test | Mô tả |
|---|---|
| Replay Attack | Gửi lại nonce cũ, phải bị reject |
| Wrong Password | Sai password, TGT decrypt thất bại |
| Expired Ticket | Ticket hết hạn, login bị từ chối |
| Revoked Cert | Cert bị thu hồi, đăng ký bị từ chối |
| Chain Validation | Verify chuỗi cert Client → IntermCA → RootCA |
| MITM Detection | Cert tự ký bị reject |

> **Lưu ý cho Expired Ticket test:** Cần chạy KDC ở test mode với lifetime ngắn:
> ```
> KDC_Server.exe 10
> ```
> (10 = lifetime tính bằng giây)

---

## Cấu trúc hệ thống

```
Client  →  RA  →  IntermediateCA  →  RootCA
        →  KDC (AS + TGS)
        →  ChatServer
```

| Component | Port | Vai trò |
|---|---|---|
| CA Server | 5000 | Root Certificate Authority |
| Intermediate CA | 5004 | Intermediate Certificate Authority |
| RA Server | 5001 | Registration Authority |
| KDC Server | 5003 | Kerberos AS + TGS |
| Chat Server | 5002 | Chat relay (E2EE) |

---

## Reset hoàn toàn

Xóa thư mục `SecureChatCerts\` để tạo lại toàn bộ certificates từ đầu,
sau đó khởi động lại các server theo thứ tự như trên.
