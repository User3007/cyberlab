
# 🗺️ Lộ Trình Chi Tiết Học An Ninh Mạng cho Sinh Viên CNTT

Tài liệu này cung cấp một lộ trình học tập chi tiết, kèm theo kế hoạch và checklist, được thiết kế để giúp sinh viên CNTT xây dựng sự nghiệp trong ngành an ninh mạng từ con số không trong vòng 12-18 tháng.

---

## 🎯 **GIAI ĐOẠN 1: NỀN TẢNG VỮNG CHẮC (THÁNG 1-4)**

**Mục tiêu:** Nắm vững các kiến thức CNTT cơ bản là điều kiện tiên quyết để học an ninh mạng.

### **Tuần 1-6: Nền tảng Mạng và Hệ điều hành**
- **[ ] Checklist: Hiểu và trình bày được mô hình OSI và TCP/IP.**
- **[ ] Checklist: Sử dụng thành thạo các lệnh Linux cơ bản** (ls, cd, grep, chmod, useradd).
- **[ ] Checklist: Cài đặt và cấu hình một máy ảo** (sử dụng VirtualBox hoặc VMware).
- **[ ] Checklist: Phân tích gói tin cơ bản bằng Wireshark.**
- **Kế hoạch:**
    - **Tuần 1-2:** Học lý thuyết mạng qua series của Professor Messer (YouTube) hoặc khóa học CompTIA Network+.
    - **Tuần 3-4:** Thực hành trên các phòng lab của TryHackMe (mục Pre-Security).
    - **Tuần 5-6:** Cài đặt Kali Linux, làm quen với môi trường và các công cụ cơ bản.

### **Tuần 7-12: Lập trình và Scripting**
- **[ ] Checklist: Viết được script Python để tự động hóa tác vụ đơn giản** (ví dụ: quét port).
- **[ ] Checklist: Hiểu cú pháp cơ bản của Bash script.**
- **[ ] Checklist: Hiểu cách hoạt động của một trang web** (HTML, CSS, JavaScript) và API.
- **[ ] Checklist: Viết được câu lệnh SQL cơ bản** (SELECT, FROM, WHERE).
- **Kế hoạch:**
    - **Tuần 7-9:** Học Python qua sách "Automate the Boring Stuff with Python". Tập trung vào các thư viện `socket`, `requests`.
    - **Tuần 10:** Học về Bash scripting.
    - **Tuần 11-12:** Học về web và SQL qua các nền tảng như FreeCodeCamp, SQLBolt.

### **Tuần 13-16: Cloud và DevOps cơ bản**
- **[ ] Checklist: Trình bày được sự khác biệt giữa IaaS, PaaS, SaaS.**
- **[ ] Checklist: Tạo được một máy ảo (EC2) và một S3 bucket trên AWS Free Tier.**
- **[ ] Checklist: Hiểu khái niệm container và chạy được một Docker container.**
- **Kế hoạch:**
    - **Tuần 13-14:** Học khóa AWS Cloud Practitioner Essentials (miễn phí trên trang AWS).
    - **Tuần 15-16:** Học Docker cơ bản và khái niệm CI/CD.

---

## 🔒 **GIAI ĐOẠN 2: CỐT LÕI AN NINH (THÁNG 5-9)**

**Mục tiêu:** Xây dựng kiến thức chuyên ngành an ninh mạng, tập trung vào cả tấn công và phòng thủ.

### **Tuần 17-24: An ninh Tấn công (Offensive Security)**
- **[ ] Checklist: Trình bày và nhận diện được các lỗ hổng trong OWASP Top 10.**
- **[ ] Checklist: Sử dụng thành thạo Burp Suite để chặn và sửa đổi request.**
- **[ ] Checklist: Khai thác thành công ít nhất 5 máy trên HackTheBox hoặc VulnHub.**
- **[ ] Checklist: Hiểu và sử dụng được Metasploit Framework ở mức cơ bản.**
- **Kế hoạch:**
    - **Tuần 17-20:** "Cày" toàn bộ các bài lab miễn phí trên PortSwigger Web Security Academy. Đây là phần quan trọng nhất.
    - **Tuần 21-24:** Bắt đầu với các máy dễ trên HackTheBox (Starting Point) và các phòng lab trên TryHackMe (mục Offensive Pentesting).

### **Tuần 25-32: An ninh Phòng thủ (Defensive Security)**
- **[ ] Checklist: Hiểu vai trò và các cấp (Tier 1, 2, 3) của một SOC Analyst.**
- **[ ] Checklist: Viết được câu lệnh truy vấn cơ bản trên Splunk hoặc ELK Stack.**
- **[ ] Checklist: Phân tích được file log để tìm kiếm dấu hiệu bất thường.**
- **[ ] Checklist: Trình bày được các giai đoạn của quy trình ứng cứu sự cố (Incident Response).**
- **Kế hoạch:**
    - **Tuần 25-28:** Học Splunk Fundamentals (miễn phí) và thực hành trên các bộ dữ liệu mẫu.
    - **Tuần 29-32:** Tham gia các thử thách trên Blue Team Labs Online, CyberDefenders để thực hành điều tra, phân tích.

### **Tuần 33-36: Mật mã học và An ninh Đám mây**
- **[ ] Checklist: Phân biệt được mã hóa đối xứng, bất đối xứng và hashing.**
- **[ ] Checklist: Giải thích được cách hoạt động của SSL/TLS.**
- **[ ] Checklist: Thực hành các bài lab về lỗ hổng phổ biến trên cloud (ví dụ: S3 bucket công khai, IAM misconfiguration) qua CloudGoat.**
- **Kế hoạch:**
    - **Tuần 33-34:** Học lý thuyết mật mã học.
    - **Tuần 35-36:** Chơi CloudGoat, một dự án của Rhino Security Labs, để thực hành tấn công môi trường AWS được dựng sẵn.

---

## 🚀 **GIAI ĐOẠN 3: CHUYÊN MÔN SÂU & THỰC TẾ (THÁNG 10-12+)**

**Mục tiêu:** Chọn một hướng đi chuyên sâu, xây dựng portfolio và chuẩn bị cho công việc đầu tiên.

### **Tuần 37-44: Chọn và Đào sâu Chuyên ngành**
- **[ ] Checklist: Chọn một trong các hướng đi sau để tập trung:**
    - **Path A: Web/API Pentesting:** Tập trung vào các kỹ thuật tấn công web nâng cao, tham gia các chương trình Bug Bounty.
    - **Path B: SOC/Threat Intelligence:** Đào sâu về SIEM, Threat Hunting, phân tích mã độc.
    - **Path C: Cloud/DevSecOps Security:** Tập trung vào an ninh container, Kubernetes, tự động hóa an ninh trong CI/CD.
- **Kế hoạch:**
    - Dành 8 tuần để "cày" sâu vào chuyên ngành đã chọn. Ví dụ:
        - **Path A:** Tham gia HackerOne, Bugcrowd.
        - **Path B:** Lấy chứng chỉ CySA+, học về reverse engineering.
        - **Path C:** Học về Terraform, Ansible, lấy chứng chỉ AWS Security Specialty.

### **Tuần 45-52: Xây dựng Portfolio và Kinh nghiệm thực tế**
- **[ ] Checklist: Có một tài khoản GitHub với ít nhất 3 project nhỏ (tool tự viết, script, etc.).**
- **[ ] Checklist: Viết ít nhất 5 bài blog kỹ thuật về những gì đã học.**
- **[ ] Checklist: Tham gia và có thành tích ở một cuộc thi CTF.**
- **[ ] Checklist: Tìm và báo cáo thành công một lỗ hổng (có thể là trên các trang cho phép).**
- **Kế hoạch:**
    - Mỗi tuần dành thời gian để viết tool, viết blog, tham gia CTF cuối tuần.
    - Đóng góp cho các dự án mã nguồn mở (dịch tài liệu, tìm lỗi nhỏ).

### **Sau tháng 12: Chuẩn bị Tìm việc**
- **[ ] Checklist: Chuẩn bị CV làm nổi bật các dự án và kỹ năng thực tế.**
- **[ ] Checklist: Luyện tập trả lời các câu hỏi phỏng vấn kỹ thuật và hành vi.**
- **[ ] Checklist: Xây dựng mạng lưới quan hệ (networking) trên LinkedIn, tham gia các hội thảo, meetup.**
- **[ ] Checklist: Lấy một chứng chỉ uy tín phù hợp với chuyên ngành (ví dụ: OSCP cho pentester, CySA+ cho SOC).**
- **Kế hoạch:**
    - Bắt đầu ứng tuyển vào các vị trí thực tập sinh (intern) hoặc fresher.
    - Không ngại thất bại, mỗi lần phỏng vấn là một lần học hỏi.

---

### **Checklist Công cụ cần làm quen:**

- **[ ] Hệ điều hành:** Kali Linux, Parrot OS, Windows
- **[ ] Phân tích mạng:** Wireshark, tcpdump
- **[ ] Quét và liệt kê:** Nmap, Masscan
- **[ ] An ninh web:** Burp Suite, OWASP ZAP, sqlmap
- **[ ] Khai thác:** Metasploit Framework
- **[ ] SIEM:** Splunk, ELK Stack
- **[ ] Điều tra số:** Volatility, Autopsy
- **[ ] Cloud:** AWS CLI, Terraform
- **[ ] Container:** Docker, kubectl
- **[ ] Lập trình:** VS Code, PyCharm, Git
