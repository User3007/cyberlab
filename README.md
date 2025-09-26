# 🔒 Cybersecurity Learning Lab

Môi trường học tập An toàn thông tin tương tác được thiết kế đặc biệt cho sinh viên mới bắt đầu học về Cybersecurity.

## 🎯 Mục tiêu

- Cung cấp môi trường thực hành an toàn và tương tác
- Giúp sinh viên hiểu các khái niệm cơ bản về cybersecurity
- Thực hành với các công cụ và kỹ thuật thực tế
- Phát triển tư duy bảo mật thông tin

## 🚀 Tính năng chính

### 🌐 Network Security Lab
- **Port Scanner**: Học cách quét và phân tích các port mở
- **Network Discovery**: Khám phá các thiết bị trong mạng
- **Traffic Analysis**: Phân tích luồng dữ liệu mạng
- **Security Assessment**: Đánh giá bảo mật hệ thống

### 🌍 Advanced Networking Lab
- **Network Reconnaissance**: Thu thập thông tin mạng nâng cao
- **Protocol Analysis**: Phân tích các giao thức mạng chi tiết
- **Network Topology Mapping**: Vẽ bản đồ cấu trúc mạng
- **Traffic Monitoring**: Giám sát traffic real-time
- **Network Security Testing**: Test bảo mật infrastructure
- **Performance Analysis**: Phân tích hiệu suất mạng

### 📡 Wireless Security Lab
- **WiFi Network Discovery**: Quét và phát hiện mạng WiFi
- **WPA/WEP Analysis**: Phân tích bảo mật wireless protocols
- **Signal Analysis**: Phân tích chất lượng tín hiệu WiFi
- **Rogue AP Detection**: Phát hiện access point không hợp pháp
- **Wireless Security Assessment**: Đánh giá bảo mật wireless toàn diện

### 🕸️ Web Security Lab
- **SQL Injection**: Thực hành tấn công và phòng chống SQL injection
- **XSS (Cross-Site Scripting)**: Hiểu về các loại XSS và cách ngăn chặn
- **Authentication Bypass**: Kỹ thuật vượt qua xác thực
- **Directory Traversal**: Path traversal attacks và phòng chống
- **Security Headers**: Kiểm tra và cấu hình security headers

### 🔐 Cryptography Lab
- **Hash Functions**: Thực hành với MD5, SHA-256, SHA-512, BLAKE2b
- **Symmetric Encryption**: AES encryption/decryption
- **Asymmetric Encryption**: RSA key generation và encryption
- **Digital Signatures**: Tạo và verify chữ ký số
- **Password Security**: Hash passwords, strength analysis

### 🔍 Digital Forensics Lab
- **File Analysis**: Phân tích file signature, hash, entropy
- **Image Forensics**: EXIF data extraction, histogram analysis
- **Steganography**: Ẩn và trích xuất thông tin trong ảnh
- **Timeline Analysis**: Tái tạo chuỗi sự kiện
- **Evidence Collection**: Thu thập và bảo quản bằng chứng số

## 📋 Yêu cầu hệ thống

### Minimum Requirements
- **OS**: Ubuntu 18.04+ (Recommended: Ubuntu 20.04 LTS)
- **RAM**: 4GB (Recommended: 8GB+)
- **Storage**: 10GB free space
- **CPU**: 2 cores (Recommended: 4+ cores)
- **Network**: Internet connection for package installation

### Recommended VM Configuration
- **VMware Workstation** hoặc **VirtualBox**
- **RAM**: 8GB
- **Storage**: 50GB
- **Network**: NAT hoặc Bridged mode

## 🛠️ Cài đặt


1. **Clone repository:**
```bash
git clone <repository-url>
cd cybersecurity-lab
```

1. **Cài đặt Python 3.9+:**
```bash
sudo apt update
sudo apt install python3.9 python3.9-venv python3-pip
```

2. **Tạo virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Cài đặt dependencies:**
```bash
pip install -r requirements.txt
```

4. **Cài đặt security tools:**
```bash
sudo apt install nmap wireshark hashcat john hydra nikto sqlmap
```

5. **Khởi động ứng dụng:**
```bash
streamlit run main.py
```

## 🎮 Sử dụng

### Khởi động Lab

**Cách 1: Desktop Shortcut**
- Double-click vào "Cybersecurity Lab" trên desktop

**Cách 2: Terminal**
```bash
start-lab
```

**Cách 3: Manual**
```bash
cd ~/cybersecurity-lab
source venv/bin/activate
streamlit run main.py
```

### Truy cập Lab

Mở trình duyệt và truy cập: `http://localhost:8501`

### Navigation

1. **Sidebar**: Chọn lab muốn thực hành
2. **Tabs**: Mỗi lab có nhiều bài thực hành khác nhau
3. **Interactive Elements**: Buttons, inputs, file uploads
4. **Results**: Xem kết quả và phân tích

## 📚 Hướng dẫn sử dụng từng Lab

### 🌐 Network Security

#### Port Scanner
1. Nhập target IP (mặc định: 127.0.0.1)
2. Chọn loại scan (Quick/Full/Custom)
3. Điều chỉnh timeout
4. Click "Bắt đầu Scan"
5. Xem kết quả và phân tích

#### Network Discovery
1. Nhập network range (VD: 192.168.1.0/24)
2. Click "Discover Hosts"
3. Xem danh sách hosts đang hoạt động

### 🕸️ Web Security

#### SQL Injection
1. Thử các payload khác nhau trong form login
2. Quan sát SQL query được thực thi
3. Học cách phòng chống bằng prepared statements

#### XSS Testing
1. Nhập XSS payload vào comment form
2. Xem cách payload được xử lý
3. Học về HTML encoding và CSP

### 🔐 Cryptography

#### Hash Functions
1. Nhập text cần hash
2. Chọn algorithm (MD5, SHA-256, etc.)
3. So sánh hash của inputs tương tự

#### Encryption/Decryption
1. Generate hoặc nhập key
2. Encrypt plaintext
3. Decrypt ciphertext
4. So sánh symmetric vs asymmetric

### 🔍 Digital Forensics

#### File Analysis
1. Upload file cần phân tích
2. Xem file signature, hash values
3. Phân tích entropy và file type

#### Image Forensics
1. Upload ảnh
2. Xem EXIF data
3. Phân tích histogram màu

## 🔧 Troubleshooting

### Lỗi thường gặp

**1. Port 8501 đã được sử dụng**
```bash
# Tìm process đang sử dụng port
sudo lsof -i :8501
# Kill process
sudo kill -9 <PID>
```

**2. Virtual environment không hoạt động**
```bash
# Tạo lại virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**3. Permission denied với Wireshark**
```bash
# Thêm user vào group wireshark
sudo usermod -a -G wireshark $USER
# Logout và login lại
```

**4. Package installation failed**
```bash
# Update pip
pip install --upgrade pip
# Install packages individually
pip install streamlit pandas numpy matplotlib
```

### Performance Issues

**1. Lab chạy chậm**
- Tăng RAM cho VM
- Đóng các ứng dụng không cần thiết
- Sử dụng SSD thay vì HDD

**2. Browser không load được**
- Kiểm tra firewall: `sudo ufw status`
- Thử port khác: `streamlit run main.py --server.port 8502`

## 🎓 Curriculum Suggestions

### Tuần 1-2: Foundations
- Giới thiệu về cybersecurity
- Network Security basics
- Port scanning và network discovery

### Tuần 3-4: Web Security
- OWASP Top 10
- SQL Injection thực hành
- XSS và các web vulnerabilities

### Tuần 5-6: Cryptography
- Hash functions và integrity
- Symmetric vs Asymmetric encryption
- Digital signatures và PKI

### Tuần 7-8: Digital Forensics
- File analysis techniques
- Image forensics và metadata
- Evidence collection procedures

### Tuần 9-10: Advanced Topics
- Steganography
- Timeline analysis
- Incident response

## 🔒 Security Considerations

### Lab Environment Safety
- **Isolated Environment**: Chạy trong VM để tách biệt với host
- **No Real Attacks**: Tất cả đều là simulation, không attack thật
- **Educational Purpose**: Chỉ sử dụng cho mục đích học tập
- **Ethical Guidelines**: Tuân thủ các nguyên tắc ethical hacking

### Best Practices
1. **Không sử dụng lab để attack hệ thống thật**
2. **Không share credentials hoặc sensitive data**
3. **Backup VM trước khi thực hành**
4. **Update security tools thường xuyên**

## 🤝 Contributing

### Báo cáo lỗi
1. Mở issue trên GitHub
2. Mô tả chi tiết lỗi và steps to reproduce
3. Attach screenshots nếu có

### Đóng góp code
1. Fork repository
2. Tạo feature branch
3. Commit changes
4. Submit pull request

### Đề xuất tính năng mới
1. Mở issue với label "enhancement"
2. Mô tả tính năng và use case
3. Thảo luận với maintainers

## 📞 Hỗ trợ

### Documentation
- README.md (file này)
- Inline help trong từng lab
- Code comments

### Community Support
- GitHub Issues
- Discussion forums
- Email support

### Professional Training
- Workshop sessions
- Instructor-led training
- Custom curriculum development

## 📄 License

MIT License - Xem file LICENSE để biết thêm chi tiết.

## 🙏 Acknowledgments

- **Streamlit** - Web framework
- **Python Security Libraries** - Cryptography, Scapy, etc.
- **Open Source Security Tools** - Nmap, Wireshark, etc.
- **Cybersecurity Community** - For knowledge sharing

## 📈 Roadmap

### Version 2.0 (Planned)
- [ ] Malware Analysis Lab
- [ ] Penetration Testing Automation
- [ ] CTF Challenges Integration
- [ ] Multi-language Support
- [ ] Advanced Forensics Tools

### Version 2.1 (Future)
- [ ] Cloud Security Lab
- [ ] IoT Security Testing
- [ ] AI/ML Security
- [ ] Blockchain Security
- [ ] Mobile Security Testing

---

**Happy Learning! 🔒🎓**

*Cybersecurity Lab - Empowering the next generation of security professionals*
