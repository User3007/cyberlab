
# ⚡ Cheat Sheet An Ninh Mạng: Nguyên tắc, Tips & Tricks

Tài liệu này là một bản tóm tắt các nguyên tắc, lời khuyên và thủ thuật quan trọng nhất dành cho sinh viên và người mới bắt đầu trong ngành an ninh mạng.

---

## 🧠 **TƯ DUY & NGUYÊN TẮC CỐT LÕI**

1.  **Tư duy của Kẻ Tấn Công (Hacker Mindset):**
    *   **Tip:** Đừng chỉ hỏi "Nó hoạt động như thế nào?" mà hãy hỏi "Làm thế nào để lạm dụng nó?". Luôn tìm kiếm các trường hợp ngoại lệ, các hành vi không mong muốn.
    *   **Nguyên tắc:** Mọi hệ thống đều có thể bị phá vỡ. Vấn đề chỉ là thời gian và tài nguyên.

2.  **Phòng thủ theo chiều sâu (Defense in Depth):**
    *   **Tip:** Đừng bao giờ tin tưởng vào một lớp bảo vệ duy nhất. Hãy xây dựng nhiều lớp phòng thủ (tường lửa, IDS, EDR, xác thực, mã hóa...).
    *   **Nguyên tắc:** Nếu một lớp phòng thủ thất bại, các lớp khác sẽ làm chậm hoặc ngăn chặn kẻ tấn công.

3.  **Nguyên tắc Đặc quyền Tối thiểu (Principle of Least Privilege):**
    *   **Tip:** Khi tạo tài khoản hoặc cấp quyền, hãy tự hỏi: "Đây có phải là mức quyền thấp nhất mà người dùng/dịch vụ này cần để hoàn thành công việc không?".
    *   **Nguyên tắc:** Chỉ cấp quyền truy cập vừa đủ cho một thực thể để thực hiện nhiệm vụ được chỉ định. Không hơn, không kém.

4.  **Không bao giờ tin tưởng đầu vào của người dùng (Never Trust User Input):**
    *   **Tip:** Luôn xác thực, làm sạch (sanitize) và mã hóa (encode) mọi dữ liệu nhận được từ phía client trước khi xử lý.
    *   **Nguyên tắc:** Coi mọi dữ liệu đến từ bên ngoài là độc hại cho đến khi được chứng minh là an toàn.

5.  **Giữ mọi thứ đơn giản (Keep It Simple, Stupid - KISS):**
    *   **Tip:** Hệ thống càng phức tạp, càng có nhiều chỗ cho lỗi và lỗ hổng. Ưu tiên các giải pháp đơn giản, dễ hiểu và dễ bảo trì.
    *   **Nguyên tắc:** Bề mặt tấn công (attack surface) tăng theo độ phức tạp của hệ thống.

---

## 🚀 **TIPS & TRICKS ĐỂ HỌC NHANH**

1.  **Quy tắc 80/20 trong học tập:**
    *   **Tip:** Tập trung vào 20% kiến thức mang lại 80% kết quả. Đối với người mới: **Linux CLI, Mạng TCP/IP, Python Scripting, và OWASP Top 10.**
    *   **Trick:** Dành 1-2 tháng đầu chỉ để "cày" những chủ đề này. Nền tảng sẽ cực kỳ vững chắc.

2.  **Học qua thực hành (Learn by Doing):**
    *   **Tip:** Thời gian học nên được phân bổ: 30% đọc/xem lý thuyết, 70% thực hành trong lab.
    *   **Trick:** Sau khi học một khái niệm, hãy tìm ngay một bài lab trên TryHackMe, HackTheBox, hoặc PortSwigger để áp dụng.

3.  **Xây dựng công khai (Build in Public):**
    *   **Tip:** Ghi lại hành trình học của bạn qua blog, GitHub, hoặc Twitter. Việc này giúp bạn củng cố kiến thức và xây dựng thương hiệu cá nhân.
    *   **Trick:** Mỗi tuần, đặt mục tiêu viết một bài blog về một kỹ thuật bạn đã học hoặc một công cụ bạn đã tạo.

4.  **Sử dụng AI một cách thông minh:**
    *   **Tip:** Dùng ChatGPT/Claude như một người gia sư cá nhân. Yêu cầu nó giải thích các khái niệm phức tạp, tạo kịch bản lab, hoặc giúp debug code.
    *   **Trick:** Prompt "Hãy giải thích [khái niệm X] cho tôi như thể tôi là một đứa trẻ 5 tuổi." để có cái nhìn trực quan nhất.

5.  **Tham gia cộng đồng:**
    *   **Tip:** Đừng học một mình. Tham gia các server Discord, nhóm Telegram, hoặc diễn đàn.
    *   **Trick:** Cách học nhanh nhất là dạy lại cho người khác. Hãy thử trả lời các câu hỏi của người mới hơn bạn.

---

## 🛠️ **THỦ THUẬT VỚI CÔNG CỤ PHỔ BIẾN**

1.  **Nmap (Network Mapper):**
    *   **Tip:** Luôn bắt đầu với `nmap -sC -sV -oA <output_file> <target_ip>`. Lệnh này chạy các script mặc định, dò phiên bản dịch vụ và lưu kết quả vào 3 định dạng.
    *   **Trick:** Sử dụng `nmap --script "vuln"` để nhanh chóng tìm kiếm các lỗ hổng đã biết.

2.  **Burp Suite:**
    *   **Tip:** Sử dụng Repeater là người bạn thân nhất của bạn. Gửi lại một request hàng chục lần với các thay đổi nhỏ để tìm ra cách ứng dụng hoạt động.
    *   **Trick:** Dùng extension "Logger++" để có một lịch sử request/response có thể tìm kiếm và lọc tốt hơn nhiều so với mặc định.

3.  **Python for Security:**
    *   **Tip:** Bắt đầu với thư viện `requests` để tương tác với web và `socket` để hiểu về mạng ở mức độ thấp.
    *   **Trick:** Tạo một file `template.py` chứa các hàm thường dùng (ví dụ: gửi request, xử lý proxy) để tăng tốc độ viết tool.

4.  **Google Dorking:**
    *   **Tip:** Sử dụng các toán tử `site:`, `inurl:`, `filetype:`, `intitle:` để thu hẹp phạm vi tìm kiếm.
    *   **Trick:** `site:example.com -inurl:www` để tìm các subdomain. `site:github.com "example.com" "api_key"` để tìm API key bị lộ.

5.  **Wireshark:**
    *   **Tip:** Học các bộ lọc (filter) quan trọng nhất: `ip.addr == <ip>`, `tcp.port == <port>`, `http.request`.
    *   **Trick:** Chuột phải vào một gói tin và chọn "Follow > TCP Stream" để xem toàn bộ cuộc hội thoại một cách dễ đọc.

---

## 📜 **CHECKLIST AN NINH NHANH**

### **Đối với Lập trình viên:**
- [ ] Đã xác thực tất cả dữ liệu đầu vào từ người dùng chưa?
- [ ] Đã sử dụng Prepared Statements (tham số hóa truy vấn) để chống SQL Injection chưa?
- [ ] Đã mã hóa (encode) output hiển thị ra HTML để chống XSS chưa?
- [ ] Đã kiểm tra quyền của người dùng trước khi thực hiện hành động chưa? (Broken Access Control)
- [ ] Mật khẩu có được hash với thuật toán mạnh (bcrypt, Argon2) không?

### **Đối với Quản trị viên hệ thống:**
- [ ] Các tài khoản không cần thiết đã bị vô hiệu hóa chưa?
- [ ] Nguyên tắc đặc quyền tối thiểu có được áp dụng không?
- [ ] Hệ thống đã được cập nhật bản vá mới nhất chưa?
- [ ] Tường lửa đã được cấu hình để chỉ cho phép các traffic cần thiết chưa?
- [ ] Log có được thu thập, lưu trữ và giám sát không?

---

## 💡 **LỜI KHUYÊN VỀ SỰ NGHIỆP**

1.  **Chứng chỉ vs. Kinh nghiệm:**
    *   **Nguyên tắc:** Kinh nghiệm thực tế > Chứng chỉ. Nhưng chứng chỉ giúp bạn qua vòng gửi xe (CV).
    *   **Tip:** Hãy có một portfolio (GitHub, blog) thật tốt trước, sau đó mới lấy chứng chỉ để xác thực kiến thức. OSCP là một ngoại lệ vì nó kiểm tra kỹ năng thực hành.

2.  **Xây dựng Mạng lưới (Networking):**
    *   **Nguyên tắc:** "Your network is your net worth."
    *   **Tip:** Kết nối với các chuyên gia trên LinkedIn, nhưng đừng chỉ bấm "Connect". Hãy gửi một tin nhắn ngắn giới thiệu bản thân và lý do bạn muốn kết nối.

3.  **Luôn tò mò và học hỏi:**
    *   **Nguyên tắc:** An ninh mạng thay đổi hàng ngày. Kiến thức hôm nay có thể lỗi thời vào ngày mai.
    *   **Tip:** Dành 30 phút mỗi sáng để đọc tin tức an ninh (The Hacker News, Bleeping Computer) và theo dõi các nhà nghiên cứu trên Twitter.

> **Câu thần chú cuối cùng:** "Stay hungry, stay foolish, and stay ethical." (Luôn khao khát, luôn dại khờ, và luôn giữ đạo đức.)
