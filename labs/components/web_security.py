"""
Web Security Lab
Comprehensive web security tools and techniques based on OWASP Top 10
"""

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
from defusedxml import ElementTree as DefusedET

# --- UI & Helper Functions ---

def create_lab_header(title: str, icon: str, gradient: str = "linear-gradient(90deg, #ff6b6b 0%, #4ecdc4 100%)"):
    """Create a standardized, compact lab header."""
    st.markdown(f"""
    <div style="background: {gradient}; padding: 0.8rem; border-radius: 6px; margin-bottom: 1rem;">
        <h3 style="color: white; margin: 0; font-size: 1.2rem;">{icon} {title}</h3>
    </div>
    """, unsafe_allow_html=True)

def setup_sample_database():
    """Create a sample database for SQL injection lab if it doesn't exist."""
    db_path = "/tmp/sample_users.db"
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT
        )""")
        users = [
            ('admin', 'P@ssw0rdStr0ng!', 'administrator'),
            ('user1', 'password123', 'user'),
            ('guest', 'guest', 'guest')
        ]
        cursor.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", users)
        conn.commit()
        conn.close()

# --- Main Lab Runner ---

def run_lab():
    """Web Security Lab - Master OWASP Top 10 Vulnerabilities"""
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

    # Map OWASP 2021 to labs
    tabs = st.tabs([
        "A1: Broken Access Control",
        "A2: Cryptographic Failures",
        "A3: Injection (SQLi, XXE)",
        "A4: Insecure Design",
        "A5: Security Misconfiguration",
        "A6: Vulnerable Components",
        "A7: Auth Failures (JWT)",
        "A8: Integrity Failures",
        "A9: Logging Failures",
        "A10: SSRF"
    ])

    with tabs[0]:
        broken_access_control_lab()
    with tabs[1]:
        cryptographic_failures_lab()
    with tabs[2]:
        injection_lab()
    with tabs[3]:
        insecure_design_lab()
    with tabs[4]:
        security_misconfiguration_lab()
    with tabs[5]:
        vulnerable_components_lab()
    with tabs[6]:
        authentication_failures_lab()
    with tabs[7]:
        software_integrity_failures_lab()
    with tabs[8]:
        logging_failures_lab()
    with tabs[9]:
        ssrf_lab()

# --- OWASP Top 10 Lab Functions ---

def broken_access_control_lab():
    """A01:2021 - Broken Access Control Lab"""
    create_lab_header("Broken Access Control", "🔑", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)")
    
    with st.expander("📖 **Broken Access Control Theory**", expanded=True):
        st.markdown("""
        ### 🔑 **Understanding Broken Access Control**
        
        Access control enforces policies such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data, or performing a business function outside the user's limits.
        
        **Common Vulnerabilities:**
        - **Insecure Direct Object References (IDOR):** Accessing objects by user-controllable identifier.
        - **Path Traversal:** Using `../` to access files outside the intended directory.
        - **Privilege Escalation:** Gaining higher-level permissions.
        - **Missing Function-Level Access Control:** Any user can access administrative functions.
        
        **Prevention:**
        - Deny by default, except for public resources.
        - Implement access control mechanisms once and re-use them.
        - Model access controls should enforce record ownership.
        - Rate limit API and controller access to minimize the harm from automated attack tooling.
        - Log access control failures, alert administrators when appropriate.
        """)

    st.subheader("🔬 Lab: Insecure Direct Object References (IDOR)")
    
    # Simulate a database of user profiles
    user_profiles = {
        "101": {"name": "Alice", "email": "alice@example.com", "role": "user"},
        "102": {"name": "Bob", "email": "bob@example.com", "role": "user"},
        "777": {"name": "Admin", "email": "admin@example.com", "role": "administrator", "secret": "System_Secret_Key_123"},
    }

    st.info("You are logged in as **User 101**. Try to access profiles of other users.")
    
    profile_id = st.text_input("Enter Profile ID to view:", "101")

    if st.button("View Profile"):
        if profile_id in user_profiles:
            profile_data = user_profiles[profile_id]
            if profile_id == "101" or profile_id == "102": # Simulating public profiles
                 st.success(f"Accessing profile **{profile_id}**...")
                 st.json(profile_data)
            elif profile_id == "777":
                 st.error(f"**Access Denied!** But a vulnerability exists...")
                 st.warning("In a vulnerable system, you would now see the admin's data. This is an IDOR vulnerability.")
                 st.success("Attack successful (simulation):")
                 st.json(user_profiles["777"])
        else:
            st.error("Profile not found.")

def cryptographic_failures_lab():
    """A02:2021 - Cryptographic Failures Lab"""
    create_lab_header("Cryptographic Failures", "⚿", "linear-gradient(90deg, #a1c4fd 0%, #c2e9fb 100%)")
    
    with st.expander("📖 **Cryptographic Failures Theory**", expanded=True):
        st.markdown("""
        ### ⚿ **Understanding Cryptographic Failures**
        
        Previously known as *Sensitive Data Exposure*, this category focuses on failures related to cryptography (or lack thereof). Common issues include storing data in cleartext, using old or weak cryptographic algorithms, and poor key management.
        
        **Common Vulnerabilities:**
        - **Data transmitted in cleartext:** `http` instead of `httpss`, unencrypted protocols like FTP, SMTP.
        - **Use of weak/outdated algorithms:** MD5, SHA1 for hashing passwords; DES, 3DES for encryption.
        - **Poor key management:** Hardcoded keys, keys committed to source code repositories.
        - **Missing encryption:** Sensitive data stored in plaintext in databases or logs.
        
        **Prevention:**
        - Classify data processed, stored, or transmitted.
        - Don't store sensitive data unnecessarily.
        - Encrypt all sensitive data at rest and in transit.
        - Use strong, standard, and up-to-date cryptographic algorithms and protocols.
        - Use a secure key management solution.
        """)

    st.subheader("🔬 Lab: Hashing Passwords")
    password = st.text_input("Enter a password to hash:", "mysecretpassword", type="password")

    if st.button("Hash Password"):
        # Weak Hashing (MD5)
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        st.warning(f"**Weak Hash (MD5):** `{md5_hash}`")
        st.markdown("MD5 is prone to collisions and can be cracked easily with rainbow tables.")

        # Strong Hashing (SHA-256 with salt)
        salt = os.urandom(16)
        salted_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        st.success(f"**Strong Hash (SHA-256 + Salt):**")
        st.code(f"Salt: {salt.hex()}\\nHash: {salted_hash.hex()}", language="text")
        st.markdown("Using a salt and a key derivation function like PBKDF2 makes password cracking much harder.")

def injection_lab():
    """A03:2021 - Injection Lab"""
    create_lab_header("Injection Attacks", "💉", "linear-gradient(90deg, #d4fc79 0%, #96e6a1 100%)")
    
    st.markdown("Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query.")
    
    lab_type = st.selectbox("Choose Injection Lab:", ["SQL Injection", "XML External Entity (XXE)"])

    if lab_type == "SQL Injection":
        sql_injection_lab()
    elif lab_type == "XML External Entity (XXE)":
        xxe_injection_lab()

def insecure_design_lab():
    """A04:2021 - Insecure Design Lab"""
    create_lab_header("Insecure Design", "📐", "linear-gradient(90deg, #84fab0 0%, #8fd3f4 100%)")
    
    with st.expander("📖 **Insecure Design Theory**", expanded=True):
        st.markdown("""
        ### 📐 **Understanding Insecure Design**
        
        A new category for 2021, this focuses on risks related to design and architectural flaws. It calls for more use of threat modeling, secure design patterns, and reference architectures.
        
        **Key Concepts:**
        - **Threat Modeling:** A process to identify, enumerate, and prioritize potential threats and vulnerabilities from a hypothetical attacker's perspective.
        - **Secure Design Patterns:** Reusable solutions to common security problems (e.g., secure session management, input validation).
        - **Failing Securely:** Ensuring that if a system fails, it does so in a secure state (e.g., denying access instead of granting it).
        
        **Prevention:**
        - Establish and use a secure development lifecycle with AppSec professionals.
        - Establish and use a library of secure design patterns or paved road components.
        - Use threat modeling for critical authentication, access control, business logic, and key flows.
        """)
    
    st.subheader("🔬 Lab: Threat Modeling Example")
    st.image("https://i.imgur.com/yUNi2I5.png", caption="Example of a simple STRIDE threat model for a login feature.")
    st.markdown("""
    **STRIDE Model:**
    - **S**poofing: Can an attacker impersonate a user? (e.g., weak password policy)
    - **T**ampering: Can an attacker modify data in transit? (e.g., no HTTPS)
    - **R**epudiation: Can a user deny performing an action? (e.g., inadequate logging)
    - **I**nformation Disclosure: Can an attacker access data they shouldn't? (e.g., verbose error messages)
    - **D**enial of Service: Can an attacker make the system unavailable? (e.g., no rate limiting)
    - **E**levation of Privilege: Can a user gain admin rights? (e.g., broken access control)
    """)

def security_misconfiguration_lab():
    """A05:2021 - Security Misconfiguration Lab"""
    create_lab_header("Security Misconfiguration", "⚙️", "linear-gradient(90deg, #a8edea 0%, #fed6e3 100%)")

    with st.expander("📖 **Security Misconfiguration Theory**", expanded=True):
        st.markdown("""
        ### ⚙️ **Understanding Security Misconfiguration**
        
        This category moves up from #6 in the previous edition and includes issues like unnecessary features being enabled, default accounts with unchanged passwords, and overly verbose error messages.
        
        **Common Vulnerabilities:**
        - Unpatched systems or frameworks.
        - Unnecessary services/features enabled (e.g., debug modes in production).
        - Default accounts and passwords.
        - Verbose error messages that reveal internal details (e.g., stack traces).
        - Missing security headers.
        
        **Prevention:**
        - A repeatable hardening process that makes it fast and easy to deploy another environment that is properly locked down.
        - A minimal platform with no unnecessary features, components, documentation, and samples.
        - A process for reviewing and updating the configurations appropriate to all security notes, updates, and patches.
        - An automated process to verify the effectiveness of the configurations and settings in all environments.
        """)

    st.subheader("🔬 Lab: Checking HTTP Security Headers")
    url = st.text_input("Enter URL to check:", "https://google.com")

    if st.button("Check Headers"):
        try:
            response = requests.get(url, timeout=5)
            headers = response.headers
            st.success(f"Successfully fetched headers for {url}")

            required_headers = {
                "Strict-Transport-Security": "Enforces HTTPS.",
                "Content-Security-Policy": "Prevents XSS.",
                "X-Content-Type-Options": "Prevents MIME-sniffing.",
                "X-Frame-Options": "Prevents Clickjacking.",
            }

            for header, desc in required_headers.items():
                if header in headers:
                    st.success(f"✅ **{header}:** Found! ({desc})")
                else:
                    st.error(f"❌ **{header}:** Missing! ({desc})")
            
            with st.expander("View all headers"):
                st.json(dict(headers))

        except requests.exceptions.RequestException as e:
            st.error(f"Could not fetch URL: {e}")

def vulnerable_components_lab():
    """A06:2021 - Vulnerable and Outdated Components Lab"""
    create_lab_header("Vulnerable & Outdated Components", "📦", "linear-gradient(90deg, #e0c3fc 0%, #8ec5fc 100%)")

    with st.expander("📖 **Theory**", expanded=True):
        st.markdown("""
        ### 📦 **Understanding Vulnerable Components**
        
        This category, previously known as *Using Components with Known Vulnerabilities*, is a top-10 issue. Modern applications are built using numerous third-party libraries and frameworks. If a vulnerability is discovered in one of these components, any application using it becomes vulnerable.
        
        **Common Vulnerabilities:**
        - Using libraries with known CVEs (Common Vulnerabilities and Exposures).
        - Not scanning for vulnerabilities during the development/build process.
        - Outdated software (OS, web server, database, frameworks).
        - Not fixing vulnerabilities even when patches are available.
        
        **Prevention:**
        - Remove unused dependencies, unnecessary features, components, files, and documentation.
        - Continuously inventory the versions of both client-side and server-side components.
        - Only obtain components from official sources over secure links.
        - Monitor for vulnerabilities in the components using tools like OWASP Dependency-Check, Snyk, or GitHub Dependabot.
        """)

    st.subheader("🔬 Lab: Simulating a Dependency Scan")
    st.info("This lab simulates scanning a `requirements.txt` file for known vulnerabilities.")

    # Simulated vulnerable dependencies
    vulnerable_deps = {
        "requests": {"version": "2.21.0", "cve": "CVE-2018-18074", "severity": "Medium"},
        "werkzeug": {"version": "0.14.1", "cve": "CVE-2019-14806", "severity": "High"},
        "django": {"version": "2.1", "cve": "CVE-2020-7471", "severity": "High"},
    }
    
    requirements_file = st.text_area("Enter `requirements.txt` content:", """
requests==2.21.0
werkzeug==0.14.1
django==2.1
streamlit==1.10.0
    """)

    if st.button("Scan Dependencies"):
        found_vulnerabilities = False
        for line in requirements_file.split('\\n'):
            line = line.strip()
            if '==' in line:
                lib, ver = line.split('==')
                if lib in vulnerable_deps and vulnerable_deps[lib]["version"] == ver:
                    vuln = vulnerable_deps[lib]
                    st.error(f"🚨 **Vulnerability Found in `{line}`!**")
                    st.json(vuln)
                    found_vulnerabilities = True
        
        if not found_vulnerabilities:
            st.success("✅ No known vulnerabilities found in the simulated scan.")

def authentication_failures_lab():
    """A07:2021 - Identification and Authentication Failures Lab"""
    create_lab_header("Authentication Failures", "🎭", "linear-gradient(90deg, #fccb90 0%, #d57eeb 100%)")
    
    with st.expander("📖 **Theory**", expanded=True):
        st.markdown("""
        ### 🎭 **Understanding Authentication Failures**
        
        Previously *Broken Authentication*, this category includes weaknesses in identity confirmation. This can allow attackers to compromise user accounts, or even entire systems.
        
        **Common Vulnerabilities:**
        - Permitting automated attacks such as credential stuffing.
        - Permitting brute-force attacks.
        - Allowing weak or default passwords.
        - Weak password recovery processes.
        - Exposing Session IDs in the URL.
        - Not invalidating session tokens after logout.
        
        **Prevention:**
        - Implement Multi-Factor Authentication (MFA).
        - Do not ship with default credentials.
        - Implement weak-password checks.
        - Align password policies with NIST 800-63B guidelines.
        - Implement rate limiting and account lockout mechanisms.
        """)
    
    st.subheader("🔬 Lab: JWT (JSON Web Token) Attacks")
    jwt_attacks_lab()

def software_integrity_failures_lab():
    """A08:2021 - Software and Data Integrity Failures Lab"""
    create_lab_header("Software & Data Integrity Failures", "🔗", "linear-gradient(90deg, #ff9a9e 0%, #fecfef 100%)")

    with st.expander("📖 **Theory**", expanded=True):
        st.markdown("""
        ### 🔗 **Understanding Integrity Failures**
        
        A new category focusing on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. The most significant impact is the potential for malicious code execution or system compromise.
        
        **Common Vulnerabilities:**
        - **Insecure Deserialization:** Deserializing untrusted data which can lead to remote code execution.
        - **CI/CD Pipeline Compromise:** Attackers modifying code or build processes.
        - Using components from untrusted sources or repositories.
        
        **Prevention:**
        - Use digital signatures or similar mechanisms to verify software or data is from the expected source and has not been altered.
        - Ensure that libraries and dependencies are consumed from trusted repositories.
        - Ensure there is a review process for code and configuration changes to minimize the chance that malicious code or configuration could be introduced into the pipeline.
        """)
    
    st.subheader("🔬 Lab: Insecure Deserialization")
    deserialization_lab()

def logging_failures_lab():
    """A09:2021 - Security Logging and Monitoring Failures Lab"""
    create_lab_header("Logging & Monitoring Failures", "📉", "linear-gradient(90deg, #6a11cb 0%, #2575fc 100%)")

    with st.expander("📖 **Theory**", expanded=True):
        st.markdown("""
        ### 📉 **Understanding Logging Failures**
        
        Previously *Insufficient Logging & Monitoring*, this category is about the lack of timely detection and response to active attacks. Without logging, it's difficult to track attacker activity or diagnose problems.
        
        **Common Vulnerabilities:**
        - Not logging critical events like logins, failed logins, and high-value transactions.
        - Logs are only stored locally.
        - No alerting process for suspicious activities.
        - Logs do not have sufficient detail to identify attackers.
        - Logging sensitive data (passwords, session IDs).
        
        **Prevention:**
        - Ensure all login, access control failures, and server-side input validation failures can be logged with sufficient user context.
        - Ensure that logs are generated in a format that can be easily consumed by a centralized log management solution.
        - Establish effective monitoring and alerting.
        - Have an incident response and recovery plan.
        """)
    
    st.subheader("🔬 Lab: Log Analysis Simulation")
    st.info("This lab simulates analyzing web server logs to detect an attack.")
    
    log_data = st.text_area("Sample Log Data:", """
127.0.0.1 - - [10/Oct/2022:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 16
127.0.0.1 - - [10/Oct/2022:13:56:12 +0000] "GET /login.php HTTP/1.1" 200 120
127.0.0.1 - - [10/Oct/2022:13:57:01 +0000] "GET /profile.php?id=101 HTTP/1.1" 200 88
127.0.0.1 - - [10/Oct/2022:13:57:05 +0000] "GET /profile.php?id=102 HTTP/1.1" 200 91
127.0.0.1 - - [10/Oct/2022:13:57:08 +0000] "GET /profile.php?id=103 HTTP/1.1" 404 12
127.0.0.1 - - [10/Oct/2022:13:58:00 +0000] "GET /admin.php HTTP/1.1" 403 10
127.0.0.1 - - [10/Oct/2022:13:59:15 +0000] "POST /login.php HTTP/1.1" 401 30
127.0.0.1 - - [10/Oct/2022:13:59:18 +0000] "POST /login.php HTTP/1.1" 401 30
127.0.0.1 - - [10/Oct/2022:13:59:21 +0000] "POST /login.php HTTP/1.1" 401 30
127.0.0.1 - - [10/Oct/2022:13:59:24 +0000] "POST /login.php HTTP/1.1" 200 55
    """, height=250)

    if st.button("Analyze Logs"):
        if 'GET /profile.php?id=' in log_data:
            st.warning("🚨 **Potential IDOR Attack:** Multiple requests to `/profile.php` with sequential IDs detected.")
        if log_data.count('"POST /login.php HTTP/1.1" 401') > 2:
            st.error("🚨 **Potential Brute-Force Attack:** Multiple failed login attempts detected.")
        if 'GET /admin.php' in log_data:
            st.warning("🚨 **Potential Privilege Escalation:** Attempt to access `/admin.php` detected.")
        st.success("✅ Log analysis complete.")

def ssrf_lab():
    """A10:2021 - Server-Side Request Forgery Lab"""
    create_lab_header("Server-Side Request Forgery (SSRF)", "🔗", "linear-gradient(90deg, #fdfbfb 0%, #ebedee 100%)")

    with st.expander("📖 **SSRF Theory**", expanded=True):
        st.markdown("""
        ### 🔗 **Understanding SSRF**
        
        SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL).
        
        **Common Payloads & Targets:**
        - `http://localhost/admin`: Access internal admin panels.
        - `file:///etc/passwd`: Read local files.
        - `http://169.254.169.254/latest/meta-data/`: Access cloud provider metadata (e.g., AWS credentials).
        
        **Prevention:**
        - **Whitelist:** Only allow connections to specified domains/protocols/IPs.
        - **Blacklist:** Deny connections to known sensitive endpoints (less effective).
        - Disable unused URL schemas (`file://`, `gopher://`, `ftp://`).
        - Do not send raw responses from the server to the client.
        """)

    st.subheader("🔬 Lab: SSRF Simulation")
    st.info("This application fetches an image from a URL. Try to make it access internal resources.")
    
    url_input = st.text_input("Enter image URL to load:", "https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png")

    if st.button("Fetch Image"):
        # Simulate SSRF protection and detection
        if "localhost" in url_input or "127.0.0.1" in url_input:
            st.error("🚨 **SSRF Detected!** Access to `localhost` is blocked.")
        elif "169.254.169.254" in url_input:
            st.error("🚨 **CRITICAL SSRF!** Attempt to access cloud metadata endpoint detected and blocked.")
        elif url_input.startswith("file://"):
            st.error("🚨 **SSRF Detected!** `file://` schema is blocked.")
        else:
            try:
                st.success(f"Fetching image from `{url_input}`...")
                st.image(url_input)
            except Exception as e:
                st.error(f"Could not load image. Error: {e}")

# --- Sub-Labs for Injection Category ---

def sql_injection_lab():
    """Lab for SQL Injection"""
    st.subheader("💉 SQL Injection")
    
    with st.expander("📖 **SQL Injection Theory**"):
        st.markdown("""
        SQL Injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.
        
        **Types:**
        - **In-band SQLi (Classic):** Union-based, Error-based.
        - **Inferential SQLi (Blind):** Boolean-based, Time-based.
        - **Out-of-band SQLi:** Uses alternative communication channels.
        
        **Prevention:** Use **Prepared Statements (Parameterized Queries)**.
        """)
    
    setup_sample_database()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🎯 Vulnerable Login Form")
        username = st.text_input("Username:", "admin")
        password = st.text_input("Password:", type="password")
        
        st.markdown("**💡 Payloads:**")
        st.code("admin' --", language="sql")
        st.code("' OR 1=1 --", language="sql")

        if st.button("Login (Vulnerable)"):
            db_path = "/tmp/sample_users.db"
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # VULNERABLE QUERY
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            st.code(query, language="sql")
            
            try:
                cursor.execute(query)
                result = cursor.fetchone()
                if result:
                    st.success(f"Login successful! Welcome, {result[1]}. Role: {result[3]}")
                else:
                    st.error("Login failed.")
            except Exception as e:
                st.error(f"An SQL error occurred: {e}")
            conn.close()

    with col2:
        st.markdown("#### 🛡️ Secure Login Form")
        username_s = st.text_input("Username (Secure):", "admin")
        password_s = st.text_input("Password (Secure):", type="password")

        if st.button("Login (Secure)"):
            db_path = "/tmp/sample_users.db"
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # SECURE QUERY
            query = "SELECT * FROM users WHERE username = ? AND password = ?"
            st.code("SELECT * FROM users WHERE username = ? AND password = ?", language="sql")
            
            cursor.execute(query, (username_s, password_s))
            result = cursor.fetchone()
            if result:
                st.success(f"Login successful! Welcome, {result[1]}.")
            else:
                st.error("Login failed.")
            conn.close()

def xxe_injection_lab():
    """Lab for XXE Injection"""
    st.subheader("🎆 XML External Entity (XXE)")

    with st.expander("📖 **XXE Theory**"):
        st.markdown("""
        An XML External Entity (XXE) attack is a type of attack against an application that parses XML input. This attack occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser.
        
        **Payload for file disclosure:**
        ```xml
        <?xml version="1.0"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <stockCheck><productId>&xxe;</productId></stockCheck>
        ```
        
        **Prevention:** Disable Document Type Definitions (DTDs) in your XML parser.
        """)

    xml_input = st.text_area("Enter XML data:", """
<?xml version="1.0"?>
<stockCheck>
    <productId>123</productId>
</stockCheck>
    """, height=150)

    if st.button("Process XML"):
        try:
            # Vulnerable parsing
            if '<!ENTITY' in xml_input and 'SYSTEM "file' in xml_input:
                 st.error("🚨 **XXE Attack Detected!**")
                 st.warning("In a real scenario, the server might now try to access local files.")
                 st.code("root:x:0:0:root:/root:/bin/bash\\n...", language="text")
            else:
            # Secure parsing
                tree = DefusedET.fromstring(xml_input)
                product_id = tree.find('productId').text
                st.success(f"Successfully parsed XML. Product ID: {product_id}")
        except Exception as e:
            st.error(f"XML Parsing Error: {e}")

# --- Sub-Labs for other categories ---

def jwt_attacks_lab():
    """Lab for JWT Attacks"""
    st.markdown("JSON Web Tokens (JWT) are a common way to handle authentication. However, they can be vulnerable if misconfigured.")
    
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 🔑 None Algorithm Attack")
        
        # Create a sample token
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "test", "admin": False}
        secret = "your-256-bit-secret"
        token = jwt.encode(payload, secret, algorithm="HS256", headers=header)
        
        st.text_area("Original Token:", token)

        if st.button("Perform 'None' Attack"):
            decoded_payload = jwt.decode(token, options={"verify_signature": False})
            
            # Modify payload
            decoded_payload["admin"] = True
            
            # Re-encode with alg=None
            h_none = {"alg": "none", "typ": "JWT"}
            token_none = jwt.encode(decoded_payload, "", algorithm="none", headers=h_none)
            
            st.success("Attack Token Generated:")
            st.text_area("Modified Token (alg=none):", token_none)
            st.warning("This token could be used to gain admin privileges if the server accepts `alg=none`.")

    with col2:
        st.markdown("#### 🛡️ Prevention")
        st.markdown("""
        - **Always verify the signature.**
        - **Enforce a specific algorithm on the server-side.** Don't trust the `alg` header from the client.
        - Use a strong, secret key.
        - Keep libraries up-to-date.
        
        **Secure Verification (Python):**
        ```python
        try:
            decoded = jwt.decode(
                token, 
                "your-256-bit-secret", 
                algorithms=["HS256"] # Whitelist algs!
            )
        except jwt.InvalidTokenError:
            # Handle error
        ```
        """)

def deserialization_lab():
    """Lab for Insecure Deserialization"""
    st.markdown("Insecure deserialization is when user-controllable data is deserialized by a website. This could allow an attacker to manipulate application logic, or even achieve Remote Code Execution (RCE).")

    st.subheader("🐍 Python Pickle Exploitation")
    st.warning("**Disclaimer:** This is for educational purposes only. Never run untrusted pickle data.")

    command = st.text_input("Enter OS command for RCE payload:", "whoami")

    if st.button("Generate Pickle RCE Payload"):
        class RCE:
            def __reduce__(self):
                return (os.system, (command,))

        payload = base64.b64encode(pickle.dumps(RCE())).decode()
        st.success("Payload Generated (Base64):")
        st.code(payload, language="text")

        st.markdown("If a vulnerable application decodes and unpickles this, it will execute the command.")
        
        st.markdown("#### 🛡️ Prevention")
        st.markdown("""
        - **Avoid deserializing data from untrusted sources.**
        - Use safer, data-only formats like JSON if possible.
        - If you must deserialize, use robust validation and integrity checks.
        """)

# Dummy import for pickle to avoid errors if not used directly in a safe way
try:
    import pickle
except ImportError:
    pickle = None
