import streamlit as st
import requests
import re
import urllib.parse
import base64
import hashlib
import sqlite3
import os
from datetime import datetime

def run_lab():
    """Web Security Lab - Học về bảo mật web"""
    
    st.title("🕸️ Web Security Lab")
    st.markdown("---")
    
    # Tabs cho các bài thực hành khác nhau
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "💉 SQL Injection", 
        "🔗 XSS (Cross-Site Scripting)",
        "🔐 Authentication Bypass",
        "📄 Directory Traversal",
        "🛡️ Security Headers"
    ])
    
    with tab1:
        sql_injection_lab()
    
    with tab2:
        xss_lab()
    
    with tab3:
        auth_bypass_lab()
        
    with tab4:
        directory_traversal_lab()
        
    with tab5:
        security_headers_lab()

def sql_injection_lab():
    """Lab SQL Injection"""
    st.subheader("💉 SQL Injection Lab")
    
    # Thêm phần giải thích chi tiết
    with st.expander("📖 Lý thuyết chi tiết về SQL Injection"):
        st.markdown("""
        ### 🎯 SQL Injection là gì?
        
        **SQL Injection (SQLi)** là lỗ hổng bảo mật cho phép attacker can thiệp vào các query
        mà application gửi đến database. Đây là một trong **OWASP Top 10** vulnerabilities.
        
        ### 🔍 Cách hoạt động
        
        **Vulnerable Code Example:**
        ```python
        # VULNERABLE - Never do this!
        username = request.form['username']
        password = request.form['password']
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor.execute(query)
        ```
        
        **Attack Example:**
        ```
        Username: admin' --
        Password: anything
        
        Resulting Query:
        SELECT * FROM users WHERE username='admin' -- ' AND password='anything'
        ```
        
        ### 🔥 Các loại SQL Injection
        
        **1. Union-based SQL Injection**
        - Sử dụng UNION operator để kết hợp kết quả từ multiple queries
        - **Payload example**: `' UNION SELECT username, password FROM users --`
        - **Requirement**: Cần biết số columns và data types
        - **Impact**: Có thể extract toàn bộ database
        
        **2. Boolean-based Blind SQL Injection**
        - Dựa vào phản hồi True/False của application
        - **Payload example**: `' AND 1=1 --` (True) vs `' AND 1=2 --` (False)
        - **Technique**: Từng bit một để extract data
        - **Time**: Chậm nhưng hiệu quả
        
        **3. Time-based Blind SQL Injection**
        - Sử dụng database delay functions
        - **Payload example**: `'; WAITFOR DELAY '00:00:05' --`
        - **MySQL**: `' AND SLEEP(5) --`
        - **PostgreSQL**: `'; SELECT pg_sleep(5) --`
        
        **4. Error-based SQL Injection**
        - Dựa vào error messages từ database
        - **Payload example**: `' AND (SELECT COUNT(*) FROM information_schema.tables) --`
        - **Requirement**: Application hiển thị database errors
        - **Risk**: Information disclosure through errors
        
        **5. Second-order SQL Injection**
        - Input được store và execute sau đó
        - **Example**: User registration → Profile update
        - **Difficulty**: Harder to detect và exploit
        
        ### 🎯 Common Injection Points
        
        **1. Login Forms**
        - Username/password fields
        - "Remember me" functionality
        - Password reset forms
        
        **2. Search Functions**
        - Search queries
        - Filters và sorting
        - Pagination parameters
        
        **3. URL Parameters**
        - GET parameters: `?id=1`
        - REST API endpoints
        - Hidden form fields
        
        **4. HTTP Headers**
        - User-Agent strings
        - Referer headers
        - Custom headers
        
        **5. Cookies**
        - Session cookies
        - Preference cookies
        - Tracking cookies
        
        ### 🛡️ Prevention Techniques
        
        **1. Prepared Statements (Parameterized Queries)**
        ```python
        # SECURE
        query = "SELECT * FROM users WHERE username=? AND password=?"
        cursor.execute(query, (username, password))
        ```
        
        **2. Stored Procedures**
        ```sql
        CREATE PROCEDURE GetUser(@Username NVARCHAR(50), @Password NVARCHAR(50))
        AS
        BEGIN
            SELECT * FROM users WHERE username=@Username AND password=@Password
        END
        ```
        
        **3. Input Validation**
        ```python
        import re
        
        def validate_username(username):
            # Only allow alphanumeric and underscore
            if re.match("^[a-zA-Z0-9_]+$", username):
                return True
            return False
        ```
        
        **4. Escaping Special Characters**
        ```python
        import mysql.connector
        
        def escape_string(input_str):
            return mysql.connector.converter.MySQLConverter().escape(input_str)
        ```
        
        **5. Least Privilege Principle**
        - Database user chỉ có permissions cần thiết
        - Không sử dụng admin accounts cho applications
        - Separate databases cho different functions
        
        ### 🔍 Detection Methods
        
        **Manual Testing:**
        - Single quote (`'`) injection
        - Comment sequences (`--`, `/**/`)
        - Boolean conditions (`AND 1=1`)
        - Time delays (`SLEEP()`, `WAITFOR`)
        
        **Automated Tools:**
        - **SQLMap**: Automated SQL injection tool
        - **Burp Suite**: Web application security scanner
        - **OWASP ZAP**: Free security testing proxy
        
        ### ⚠️ Impact của SQL Injection
        
        **Data Breach:**
        - Steal sensitive customer data
        - Credit card information
        - Personal identifiable information (PII)
        
        **Data Manipulation:**
        - Modify database records
        - Delete critical data
        - Insert malicious data
        
        **Authentication Bypass:**
        - Login without valid credentials
        - Privilege escalation
        - Admin account takeover
        
        **System Compromise:**
        - Execute operating system commands
        - File system access
        - Network pivoting
        """)
    
    st.markdown("""
    ### 🚀 Thực hành SQL Injection
    
    Sử dụng vulnerable login form bên dưới để thực hành các kỹ thuật SQL injection:
    """)
    
    # Tạo database mẫu nếu chưa có
    setup_sample_database()
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🎯 Vulnerable Login Form")
        st.markdown("*Thử các payload SQL injection khác nhau:*")
        
        username = st.text_input("Username:", value="admin")
        password = st.text_input("Password:", type="password", value="password")
        
        st.markdown("**💡 Gợi ý payload:**")
        st.code("admin' --")
        st.code("admin' OR '1'='1' --")
        st.code("' UNION SELECT username, password FROM users --")
        
        if st.button("🔓 Login"):
            result = vulnerable_login(username, password)
            
            if result['success']:
                st.success("✅ Login thành công!")
                if result['data']:
                    st.markdown("**📊 Dữ liệu trả về:**")
                    for row in result['data']:
                        st.write(f"User: {row[0]}, Pass: {row[1]}")
            else:
                st.error("❌ Login thất bại!")
                
            st.markdown("**🔍 SQL Query được thực thi:**")
            st.code(result['query'])
    
    with col2:
        st.markdown("#### 🛡️ Secure Implementation")
        
        st.markdown("**Cách phòng chống SQL Injection:**")
        
        st.markdown("1. **Prepared Statements:**")
        st.code("""
# Vulnerable
query = f"SELECT * FROM users WHERE username='{username}'"

# Secure  
query = "SELECT * FROM users WHERE username=?"
cursor.execute(query, (username,))
        """)
        
        st.markdown("2. **Input Validation:**")
        st.code("""
import re

def validate_input(input_str):
    # Chỉ cho phép alphanumeric
    if re.match("^[a-zA-Z0-9]+$", input_str):
        return True
    return False
        """)
        
        st.markdown("3. **Escape Special Characters:**")
        st.code("""
import sqlite3

def escape_input(input_str):
    return sqlite3.escape_string(input_str)
        """)

def xss_lab():
    """Lab Cross-Site Scripting"""
    st.subheader("🔗 XSS (Cross-Site Scripting) Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    XSS cho phép attacker inject malicious script vào web page,
    có thể steal cookies, session tokens, hoặc thực hiện actions thay user.
    
    **Các loại XSS:**
    - **Reflected XSS**: Script được reflect ngay lập tức
    - **Stored XSS**: Script được lưu trong database
    - **DOM-based XSS**: Script thực thi ở client-side
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🎯 Vulnerable Comment Form")
        
        comment = st.text_area("Comment:", value="Hello World!")
        
        st.markdown("**💡 Gợi ý XSS payload:**")
        st.code("<script>alert('XSS')</script>")
        st.code("<img src=x onerror=alert('XSS')>")
        st.code("<svg onload=alert('XSS')>")
        
        if st.button("💬 Submit Comment"):
            # Mô phỏng vulnerable comment processing
            processed_comment = process_comment_vulnerable(comment)
            
            st.markdown("**📝 Comment đã được lưu:**")
            # Hiển thị comment (không thực thi script thật)
            if "<script>" in comment.lower() or "onerror=" in comment.lower() or "onload=" in comment.lower():
                st.warning("⚠️ XSS payload detected! Trong thực tế, script này sẽ được thực thi.")
                st.code(processed_comment)
            else:
                st.write(processed_comment)
    
    with col2:
        st.markdown("#### 🛡️ XSS Prevention")
        
        st.markdown("**Cách phòng chống XSS:**")
        
        st.markdown("1. **HTML Encoding:**")
        st.code("""
import html

def safe_output(user_input):
    return html.escape(user_input)

# < becomes &lt;
# > becomes &gt;
# & becomes &amp;
        """)
        
        st.markdown("2. **Content Security Policy (CSP):**")
        st.code("""
Content-Security-Policy: default-src 'self'; 
script-src 'self' 'unsafe-inline';
        """)
        
        st.markdown("3. **Input Validation:**")
        st.code("""
import re

def sanitize_input(user_input):
    # Remove script tags
    cleaned = re.sub(r'<script.*?</script>', '', user_input, flags=re.IGNORECASE)
    # Remove event handlers
    cleaned = re.sub(r'on\w+\s*=', '', cleaned, flags=re.IGNORECASE)
    return cleaned
        """)

def auth_bypass_lab():
    """Lab Authentication Bypass"""
    st.subheader("🔐 Authentication Bypass Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Authentication Bypass là các kỹ thuật để vượt qua cơ chế xác thực
    mà không cần credentials hợp lệ.
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🎯 Weak Authentication")
        
        auth_method = st.selectbox("Authentication Method:", [
            "Cookie-based Auth",
            "JWT Token Auth", 
            "Session-based Auth"
        ])
        
        if auth_method == "Cookie-based Auth":
            cookie_value = st.text_input("Cookie Value:", value="user=guest")
            
            st.markdown("**💡 Bypass techniques:**")
            st.code("user=admin")
            st.code("user=administrator")
            st.code("role=admin")
            
            if st.button("🔓 Test Cookie"):
                result = test_cookie_auth(cookie_value)
                display_auth_result(result)
        
        elif auth_method == "JWT Token Auth":
            jwt_token = st.text_area("JWT Token:", value="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.signature")
            
            if st.button("🔍 Analyze JWT"):
                result = analyze_jwt(jwt_token)
                st.json(result)
    
    with col2:
        st.markdown("#### 🛡️ Secure Authentication")
        
        st.markdown("**Best Practices:**")
        st.markdown("""
        1. **Strong Session Management**
        2. **Secure Cookie Attributes**
        3. **JWT Best Practices**
        4. **Multi-Factor Authentication**
        5. **Account Lockout Policies**
        """)

def directory_traversal_lab():
    """Lab Directory Traversal"""
    st.subheader("📄 Directory Traversal Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Directory Traversal (Path Traversal) cho phép attacker truy cập
    các file ngoài web root directory bằng cách manipulate file paths.
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🎯 File Download Function")
        
        filename = st.text_input("Filename:", value="document.txt")
        
        st.markdown("**💡 Traversal payloads:**")
        st.code("../../../etc/passwd")
        st.code("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts")
        st.code("....//....//....//etc/passwd")
        
        if st.button("📥 Download File"):
            result = simulate_file_download(filename)
            
            if result['success']:
                st.success(f"✅ File found: {result['path']}")
                if result['content']:
                    st.text_area("File Content:", result['content'], height=200)
            else:
                st.error(f"❌ {result['error']}")
    
    with col2:
        st.markdown("#### 🛡️ Path Traversal Prevention")
        
        st.markdown("**Secure Implementation:**")
        st.code("""
import os
import os.path

def secure_file_access(filename):
    # Whitelist allowed files
    allowed_files = ['document.txt', 'readme.md']
    
    if filename not in allowed_files:
        raise ValueError("File not allowed")
    
    # Resolve absolute path
    base_dir = "/var/www/uploads"
    file_path = os.path.join(base_dir, filename)
    file_path = os.path.abspath(file_path)
    
    # Check if path is within base directory
    if not file_path.startswith(base_dir):
        raise ValueError("Path traversal detected")
    
    return file_path
        """)

def security_headers_lab():
    """Lab Security Headers"""
    st.subheader("🛡️ Security Headers Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Security Headers giúp bảo vệ web application khỏi các attack vectors
    bằng cách cung cấp thêm layer bảo mật ở browser level.
    """)
    
    url = st.text_input("Website URL:", value="https://example.com")
    
    if st.button("🔍 Check Security Headers"):
        with st.spinner("Đang kiểm tra security headers..."):
            headers_result = check_security_headers(url)
            display_headers_result(headers_result)

# Helper Functions
def setup_sample_database():
    """Tạo database mẫu cho SQL injection lab"""
    db_path = "/tmp/sample_users.db"
    
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
        """)
        
        # Thêm dữ liệu mẫu
        users = [
            (1, 'admin', 'admin123', 'administrator'),
            (2, 'user1', 'password1', 'user'),
            (3, 'guest', 'guest123', 'guest')
        ]
        
        cursor.executemany("INSERT INTO users VALUES (?, ?, ?, ?)", users)
        conn.commit()
        conn.close()

def vulnerable_login(username, password):
    """Mô phỏng vulnerable login function"""
    db_path = "/tmp/sample_users.db"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Vulnerable query - string concatenation
        query = f"SELECT username, password FROM users WHERE username='{username}' AND password='{password}'"
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        conn.close()
        
        return {
            'success': len(results) > 0,
            'data': results,
            'query': query
        }
    except Exception as e:
        return {
            'success': False,
            'data': None,
            'query': query,
            'error': str(e)
        }

def process_comment_vulnerable(comment):
    """Mô phỏng vulnerable comment processing"""
    # Không sanitize input - vulnerable to XSS
    return comment

def test_cookie_auth(cookie_value):
    """Test cookie-based authentication bypass"""
    if "admin" in cookie_value.lower():
        return {'success': True, 'role': 'admin', 'message': 'Admin access granted!'}
    elif "user" in cookie_value.lower():
        return {'success': True, 'role': 'user', 'message': 'User access granted!'}
    else:
        return {'success': False, 'message': 'Access denied!'}

def analyze_jwt(token):
    """Phân tích JWT token"""
    try:
        # Split JWT token
        parts = token.split('.')
        
        if len(parts) != 3:
            return {'error': 'Invalid JWT format'}
        
        # Decode header and payload (không verify signature)
        header = base64.b64decode(parts[0] + '==').decode('utf-8')
        payload = base64.b64decode(parts[1] + '==').decode('utf-8')
        
        import json
        return {
            'header': json.loads(header),
            'payload': json.loads(payload),
            'signature': parts[2]
        }
    except Exception as e:
        return {'error': str(e)}

def simulate_file_download(filename):
    """Mô phỏng file download với directory traversal"""
    
    # Mô phỏng file system
    fake_files = {
        'document.txt': 'This is a sample document.',
        '../../../etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts': '127.0.0.1 localhost\n::1 localhost'
    }
    
    if filename in fake_files:
        return {
            'success': True,
            'path': filename,
            'content': fake_files[filename]
        }
    else:
        return {
            'success': False,
            'error': 'File not found'
        }

def check_security_headers(url):
    """Kiểm tra security headers của website"""
    try:
        # Mô phỏng response headers
        sample_headers = {
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'",
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        return {
            'url': url,
            'headers': sample_headers,
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {'error': str(e)}

def display_auth_result(result):
    """Hiển thị kết quả authentication test"""
    if result['success']:
        st.success(f"✅ {result['message']}")
        if 'role' in result:
            st.info(f"🔑 Role: {result['role']}")
    else:
        st.error(f"❌ {result['message']}")

def display_headers_result(result):
    """Hiển thị kết quả kiểm tra security headers"""
    if 'error' in result:
        st.error(f"❌ Error: {result['error']}")
        return
    
    st.success(f"✅ Headers checked for: {result['url']}")
    
    # Danh sách security headers quan trọng
    important_headers = [
        'X-Frame-Options',
        'X-Content-Type-Options', 
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'Referrer-Policy'
    ]
    
    st.markdown("#### 📊 Security Headers Status")
    
    for header in important_headers:
        if header in result['headers']:
            st.success(f"✅ {header}: {result['headers'][header]}")
        else:
            st.error(f"❌ {header}: Missing")
    
    # Hiển thị tất cả headers
    with st.expander("🔍 All Headers"):
        for header, value in result['headers'].items():
            st.write(f"**{header}:** {value}")
