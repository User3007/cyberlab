import streamlit as st
import socket
import threading
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import subprocess
import re
import json
import ipaddress
import struct
import random
import hashlib
import base64
from datetime import datetime, timedelta
import concurrent.futures
from typing import Dict, List, Tuple, Optional
import os
import sys

def run_lab():
    """Network Security Lab - Học về bảo mật mạng"""
    
    # Header với animation
    st.markdown("""
    <style>
    .network-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .pulse {
        animation: pulse 2s infinite;
    }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.7; }
        100% { opacity: 1; }
    }
    </style>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("""
        <div class="network-header">
            <h1 style="color: white; text-align: center; margin: 0;">
                <span class="pulse">🌐</span> Network Security Lab
            </h1>
            <p style="color: white; text-align: center; margin-top: 10px;">
                Master Network Security Fundamentals & Advanced Techniques
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    # Enhanced tabs với nhiều labs hơn
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
        "🔍 Port Scanner", 
        "📡 Network Discovery",
        "🕵️ OS Fingerprinting",
        "📊 Traffic Analysis",
        "🎭 ARP Spoofing",
        "🔐 Man-in-the-Middle",
        "💣 DoS/DDoS Simulation",
        "🛡️ Security Assessment"
    ])
    
    with tab1:
        port_scanner_lab()
    
    with tab2:
        network_discovery_lab()
    
    with tab3:
        os_fingerprinting_lab()
        
    with tab4:
        traffic_analysis_lab()
        
    with tab5:
        arp_spoofing_lab()
        
    with tab6:
        mitm_lab()
        
    with tab7:
        dos_ddos_lab()
        
    with tab8:
        security_assessment_lab()

def port_scanner_lab():
    """Lab quét port"""
    
    # Header với gradient
    st.markdown("""
    <div style="background: linear-gradient(90deg, #FF6B6B 0%, #4ECDC4 100%); 
                padding: 20px; border-radius: 10px; margin-bottom: 20px;">
        <h2 style="color: white; margin: 0;">🔍 Port Scanner Lab</h2>
        <p style="color: white; margin: 5px 0 0 0;">Explore Network Services & Vulnerabilities</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Quick Stats Cards
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🌐 Total Ports", "65,535", "TCP/UDP")
    with col2:
        st.metric("🔒 System Ports", "0-1023", "Privileged")
    with col3:
        st.metric("📊 User Ports", "1024-49151", "Registered")
    with col4:
        st.metric("🎲 Dynamic Ports", "49152-65535", "Private")
    
    # Thêm phần giải thích chi tiết với visual enhancements
    with st.expander("📖 Lý thuyết chi tiết về Port Scanning", expanded=False):
        st.markdown("""
        ### 🎯 Port Scanning là gì?
        
        **Port Scanner** là công cụ để kiểm tra các port đang mở trên một máy tính hoặc server.
        Đây là bước đầu tiên trong quá trình **reconnaissance** của penetration testing.
        
        ### 🔌 Hiểu về Ports
        
        **Port** là endpoint của communication trong networking:
        - **Range**: 0-65535 (16-bit number)
        - **Well-known ports**: 0-1023 (system ports)
        - **Registered ports**: 1024-49151 (user ports)
        - **Dynamic ports**: 49152-65535 (private ports)
        
        **Common Ports:**
        - **22**: SSH (Secure Shell)
        - **23**: Telnet (Insecure remote access)
        - **25**: SMTP (Email sending)
        - **53**: DNS (Domain Name System)
        - **80**: HTTP (Web traffic)
        - **443**: HTTPS (Secure web traffic)
        - **3389**: RDP (Remote Desktop Protocol)
        
        ### 🔍 Các loại Port Scan
        
        **1. TCP Connect Scan**
        - Thực hiện full TCP handshake (SYN → SYN-ACK → ACK)
        - **Ưu điểm**: Reliable, works through firewalls
        - **Nhược điểm**: Easily detected, logged by target
        - **Khi nào dùng**: When stealth is not required
        
        **2. SYN Scan (Half-open scan)**
        - Chỉ gửi SYN packet, không hoàn thành handshake
        - **Ưu điểm**: Stealthier, faster
        - **Nhược điểm**: Requires raw socket access
        - **Khi nào dùng**: Stealth reconnaissance
        
        **3. UDP Scan**
        - Quét các port UDP (connectionless protocol)
        - **Ưu điểm**: Finds UDP services
        - **Nhược điểm**: Slower, less reliable
        - **Khi nào dùng**: Looking for DNS, DHCP, SNMP services
        
        **4. FIN Scan**
        - Gửi FIN packet thay vì SYN
        - **Ưu điểm**: Bypasses some firewalls
        - **Nhược điểm**: Not reliable on all systems
        
        **5. NULL Scan**
        - Gửi packet không có flags
        - **Ưu điểm**: Very stealthy
        - **Nhược điểm**: OS-dependent results
        
        ### 🛡️ Port States
        
        **Open**: Port is accepting connections
        - Service is listening on this port
        - Potential entry point for attackers
        
        **Closed**: Port is not accepting connections
        - No service running on this port
        - System is reachable but port is unused
        
        **Filtered**: Cannot determine if port is open
        - Firewall or packet filter is blocking
        - No response received
        
        **Unfiltered**: Port is accessible but state unknown
        - Rare state, usually in ACK scans
        
        ### ⚖️ Legal và Ethical Considerations
        
        **✅ Legal Port Scanning:**
        - Your own systems
        - Systems you have written permission to test
        - Bug bounty programs with explicit scope
        
        **❌ Illegal Port Scanning:**
        - Systems you don't own or have permission
        - Scanning without authorization
        - Using results for malicious purposes
        
        **🔒 Detection và Prevention:**
        - **IDS/IPS**: Intrusion Detection/Prevention Systems
        - **Rate limiting**: Slow down scan attempts
        - **Port knocking**: Hide services behind sequences
        - **Fail2ban**: Automatic IP blocking
        """)
    
    st.markdown("""
    ### 🚀 Thực hành Port Scanning
    
    Sử dụng tool bên dưới để thực hành các kỹ thuật port scanning khác nhau:
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### ⚙️ Cấu hình Scan")
        target_host = st.text_input("Target Host:", value="127.0.0.1", help="IP address hoặc hostname")
        
        scan_type = st.selectbox("Loại scan:", [
            "Quick Scan (Common Ports)",
            "Full Scan (1-65535)", 
            "Custom Range"
        ])
        
        if scan_type == "Custom Range":
            port_range = st.text_input("Port Range:", value="1-1000", help="Ví dụ: 1-1000 hoặc 80,443,22")
        
        timeout = st.slider("Timeout (seconds):", 1, 10, 3)
        
        if st.button("🚀 Bắt đầu Scan", type="primary"):
            if scan_type == "Quick Scan (Common Ports)":
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
            elif scan_type == "Full Scan (1-65535)":
                ports = range(1, 65536)
            else:
                ports = parse_port_range(port_range)
            
            with st.spinner("Đang quét ports..."):
                results = scan_ports(target_host, ports, timeout)
                st.session_state['scan_results'] = results
    
    with col2:
        st.markdown("#### 📊 Kết quả Scan")
        
        if 'scan_results' in st.session_state:
            results = st.session_state['scan_results']
            
            if results['open_ports']:
                st.success(f"Tìm thấy {len(results['open_ports'])} port đang mở!")
                
                # Tạo DataFrame cho hiển thị
                df = pd.DataFrame([
                    {"Port": port, "Service": get_service_name(port), "Status": "Open"}
                    for port in results['open_ports']
                ])
                
                st.dataframe(df, width='stretch')
                
                # Biểu đồ
                fig = px.bar(df, x='Port', y=[1]*len(df), 
                           title="Open Ports Distribution",
                           labels={'y': 'Count'})
                st.plotly_chart(fig, width='stretch')
                
            else:
                st.warning("Không tìm thấy port nào đang mở.")
            
            # Thống kê
            st.info(f"""
            **Thống kê scan:**
            - Tổng ports đã quét: {results['total_scanned']}
            - Ports mở: {len(results['open_ports'])}
            - Thời gian scan: {results['scan_time']:.2f}s
            """)

def network_discovery_lab():
    """Lab khám phá mạng"""
    st.subheader("📡 Network Discovery Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Network Discovery giúp tìm ra các thiết bị đang hoạt động trong mạng.
    Đây là bước quan trọng để hiểu topology mạng và xác định target.
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🔍 Ping Sweep")
        network = st.text_input("Network Range:", value="192.168.1.0/24", 
                               help="Ví dụ: 192.168.1.0/24")
        
        if st.button("🔍 Discover Hosts"):
            with st.spinner("Đang quét mạng..."):
                hosts = ping_sweep(network)
                st.session_state['discovered_hosts'] = hosts
    
    with col2:
        st.markdown("#### 📋 Kết quả Discovery")
        
        if 'discovered_hosts' in st.session_state:
            hosts = st.session_state['discovered_hosts']
            
            if hosts:
                st.success(f"Tìm thấy {len(hosts)} host đang hoạt động!")
                
                for host in hosts:
                    st.write(f"✅ {host}")
            else:
                st.warning("Không tìm thấy host nào.")

def traffic_analysis_lab():
    """Lab phân tích traffic mạng"""
    st.subheader("📊 Traffic Analysis Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Traffic Analysis giúp hiểu về luồng dữ liệu trong mạng,
    phát hiện các hoạt động bất thường và potential threats.
    """)
    
    # Mô phỏng traffic data
    if st.button("📊 Generate Sample Traffic Data"):
        traffic_data = generate_sample_traffic()
        
        # Hiển thị bảng traffic
        st.dataframe(traffic_data, width='stretch')
        
        # Biểu đồ phân tích
        col1, col2 = st.columns(2)
        
        with col1:
            # Protocol distribution
            protocol_counts = traffic_data['Protocol'].value_counts()
            fig1 = px.pie(values=protocol_counts.values, names=protocol_counts.index,
                         title="Protocol Distribution")
            st.plotly_chart(fig1, width='stretch')
        
        with col2:
            # Traffic over time
            fig2 = px.line(traffic_data, x='Timestamp', y='Bytes',
                          title="Traffic Over Time")
            st.plotly_chart(fig2, width='stretch')

def security_assessment_lab():
    """Lab đánh giá bảo mật"""
    st.subheader("🛡️ Security Assessment Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Security Assessment bao gồm việc đánh giá các lỗ hổng bảo mật
    và đưa ra khuyến nghị để cải thiện tình hình bảo mật.
    """)
    
    assessment_type = st.selectbox("Loại đánh giá:", [
        "Basic Port Security Check",
        "Service Version Detection", 
        "Common Vulnerabilities Check"
    ])
    
    target = st.text_input("Target:", value="127.0.0.1")
    
    if st.button("🔍 Bắt đầu Assessment"):
        with st.spinner("Đang thực hiện security assessment..."):
            if assessment_type == "Basic Port Security Check":
                results = basic_security_check(target)
            elif assessment_type == "Service Version Detection":
                results = service_detection(target)
            else:
                results = vulnerability_check(target)
            
            display_assessment_results(results)

# Helper functions
def scan_ports(host, ports, timeout):
    """Quét ports trên host"""
    open_ports = []
    start_time = time.time()
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    
    # Sử dụng threading để scan nhanh hơn
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()
        
        # Giới hạn số thread đồng thời
        if len(threads) >= 50:
            for t in threads:
                t.join()
            threads = []
    
    # Đợi các thread còn lại
    for thread in threads:
        thread.join()
    
    end_time = time.time()
    
    return {
        'open_ports': sorted(open_ports),
        'total_scanned': len(ports),
        'scan_time': end_time - start_time
    }

def parse_port_range(port_range):
    """Parse port range string thành list ports"""
    ports = []
    
    if '-' in port_range:
        start, end = map(int, port_range.split('-'))
        ports = list(range(start, end + 1))
    elif ',' in port_range:
        ports = [int(p.strip()) for p in port_range.split(',')]
    else:
        ports = [int(port_range)]
    
    return ports

def get_service_name(port):
    """Lấy tên service từ port number"""
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 993: "IMAPS", 995: "POP3S",
        3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL"
    }
    return services.get(port, "Unknown")

def ping_sweep(network):
    """Thực hiện ping sweep trên network"""
    # Mô phỏng ping sweep (trong thực tế sẽ dùng subprocess để ping)
    import random
    
    # Giả lập một số host đang hoạt động
    base_ip = network.split('/')[0].rsplit('.', 1)[0]
    active_hosts = []
    
    for i in range(1, 10):  # Mô phỏng scan 10 IP đầu
        if random.random() > 0.7:  # 30% chance host đang hoạt động
            active_hosts.append(f"{base_ip}.{i}")
    
    return active_hosts

def generate_sample_traffic():
    """Tạo dữ liệu traffic mẫu"""
    import random
    from datetime import datetime, timedelta
    
    protocols = ['TCP', 'UDP', 'ICMP']
    data = []
    
    base_time = datetime.now() - timedelta(hours=1)
    
    for i in range(100):
        data.append({
            'Timestamp': base_time + timedelta(seconds=i*36),
            'Source IP': f"192.168.1.{random.randint(1, 254)}",
            'Dest IP': f"10.0.0.{random.randint(1, 254)}",
            'Protocol': random.choice(protocols),
            'Bytes': random.randint(64, 1500),
            'Port': random.choice([80, 443, 22, 21, 25])
        })
    
    return pd.DataFrame(data)

def basic_security_check(target):
    """Kiểm tra bảo mật cơ bản"""
    # Mô phỏng kết quả security check
    return {
        'status': 'completed',
        'findings': [
            {'severity': 'High', 'issue': 'SSH service running on default port 22'},
            {'severity': 'Medium', 'issue': 'HTTP service detected (unencrypted)'},
            {'severity': 'Low', 'issue': 'Banner grabbing possible'}
        ],
        'recommendations': [
            'Change SSH to non-standard port',
            'Implement HTTPS',
            'Disable service banners'
        ]
    }

def service_detection(target):
    """Phát hiện version của services"""
    return {
        'services': [
            {'port': 22, 'service': 'SSH', 'version': 'OpenSSH 8.2'},
            {'port': 80, 'service': 'HTTP', 'version': 'Apache 2.4.41'},
            {'port': 443, 'service': 'HTTPS', 'version': 'Apache 2.4.41'}
        ]
    }

def vulnerability_check(target):
    """Kiểm tra lỗ hổng phổ biến"""
    return {
        'vulnerabilities': [
            {'cve': 'CVE-2021-44228', 'severity': 'Critical', 'description': 'Log4j RCE'},
            {'cve': 'CVE-2021-34527', 'severity': 'High', 'description': 'PrintNightmare'}
        ]
    }

def display_assessment_results(results):
    """Hiển thị kết quả assessment"""
    if 'findings' in results:
        st.markdown("#### 🔍 Security Findings")
        for finding in results['findings']:
            if finding['severity'] == 'High':
                st.error(f"🔴 **{finding['severity']}**: {finding['issue']}")
            elif finding['severity'] == 'Medium':
                st.warning(f"🟡 **{finding['severity']}**: {finding['issue']}")
            else:
                st.info(f"🔵 **{finding['severity']}**: {finding['issue']}")
    
    if 'services' in results:
        st.markdown("#### 🔧 Detected Services")
        df = pd.DataFrame(results['services'])
        st.dataframe(df, width='stretch')
    
    if 'vulnerabilities' in results:
        st.markdown("#### ⚠️ Vulnerabilities")
        for vuln in results['vulnerabilities']:
            st.error(f"**{vuln['cve']}** ({vuln['severity']}): {vuln['description']}")

# New lab functions for enhanced security testing
def os_fingerprinting_lab():
    """Lab OS Fingerprinting - Xác định hệ điều hành"""
    
    st.markdown("""
    <div style="background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); 
                padding: 20px; border-radius: 10px; margin-bottom: 20px;">
        <h2 style="color: white; margin: 0;">🕵️ OS Fingerprinting Lab</h2>
        <p style="color: white; margin: 5px 0 0 0;">Identify Operating Systems Through Network Analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Theory Section with Visual Cards
    with st.expander("📚 **Advanced OS Fingerprinting Theory**", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ### 🎯 **Active Fingerprinting**
            
            #### **TCP/IP Stack Analysis**
            ```
            ┌─────────────────┐
            │   Application   │
            ├─────────────────┤
            │   Transport     │ ← TCP Options
            ├─────────────────┤
            │    Network      │ ← TTL Values
            ├─────────────────┤
            │   Data Link     │ ← Frame Size
            └─────────────────┘
            ```
            
            **🔍 Key Indicators:**
            - **TTL (Time To Live):** 
                - Windows: 128
                - Linux: 64
                - Cisco: 255
            - **TCP Window Size:** OS-specific defaults
            - **TCP Options Order:** Unique patterns
            - **DF Flag:** Don't Fragment behavior
            """)
        
        with col2:
            st.markdown("""
            ### 🌐 **Passive Fingerprinting**
            
            #### **P0f Technique**
            ```python
            # TCP SYN packet analysis
            packet = {
                'window_size': 65535,
                'ttl': 128,
                'df': True,
                'options': ['MSS', 'NOP', 'WS', 'SACK']
            }
            # → Likely Windows 10
            ```
            
            **📊 Fingerprinting Methods:**
            - **Banner Grabbing:** Service responses
            - **ICMP Analysis:** Error message formats
            - **HTTP Headers:** Server information
            - **SSL/TLS:** Cipher suite preferences
            """)
    
    # Practical Lab Section
    st.markdown("### 🔬 **Practical OS Detection**")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### ⚙️ **Configuration**")
        
        target_ip = st.text_input("🎯 Target IP:", value="192.168.1.1")
        
        technique = st.selectbox("🛠️ Detection Technique:", [
            "TCP/IP Stack Fingerprinting",
            "Banner Grabbing",
            "Nmap OS Detection",
            "P0f Passive Analysis",
            "ICMP Fingerprinting",
            "Combined Analysis"
        ])
        
        aggressive_mode = st.checkbox("⚡ Aggressive Mode", help="Faster but more detectable")
        
        if st.button("🚀 **Start OS Detection**", type="primary"):
            with st.spinner("Analyzing target system..."):
                results = perform_os_fingerprinting(target_ip, technique, aggressive_mode)
                st.session_state['os_results'] = results
    
    with col2:
        st.markdown("#### 📊 **Detection Results**")
        
        if 'os_results' in st.session_state:
            results = st.session_state['os_results']
            
            # OS Detection Confidence
            confidence = results.get('confidence', 0)
            st.progress(confidence / 100)
            st.metric("🎯 Detection Confidence", f"{confidence}%")
            
            # Detected OS
            st.success(f"**🖥️ Detected OS:** {results['os']}")
            st.info(f"**📌 Version:** {results.get('version', 'Unknown')}")
            
            # Technical Details
            with st.expander("🔍 **Technical Analysis**"):
                st.json(results.get('technical_details', {}))
            
            # Visualization
            if 'fingerprint_data' in results:
                fig = create_fingerprint_visualization(results['fingerprint_data'])
                st.plotly_chart(fig, use_container_width=True)

def arp_spoofing_lab():
    """Lab ARP Spoofing - Tấn công ARP"""
    
    st.markdown("""
    <div style="background: linear-gradient(90deg, #f093fb 0%, #f5576c 100%); 
                padding: 20px; border-radius: 10px; margin-bottom: 20px;">
        <h2 style="color: white; margin: 0;">🎭 ARP Spoofing Lab</h2>
        <p style="color: white; margin: 5px 0 0 0;">Understanding ARP Cache Poisoning Attacks</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Warning Box
    st.warning("""
    ⚠️ **Legal Warning:** This lab is for educational purposes only. 
    ARP spoofing on networks you don't own is illegal and unethical.
    """)
    
    # Theory with Diagrams
    with st.expander("📚 **ARP Spoofing Theory & Techniques**", expanded=False):
        st.markdown("""
        ### 🔄 **How ARP Works**
        
        ```
        Normal ARP Process:
        ┌──────────┐  Who has 192.168.1.1?  ┌──────────┐
        │ Host A   │ ─────────────────────> │ Broadcast│
        │192.168.1.2│                        │   FF:FF  │
        └──────────┘                        └──────────┘
                ↑                                 ↓
                │   I am 192.168.1.1             │
                │   MAC: AA:BB:CC:DD:EE:FF       │
                └─────────────────────────────────┘
        
        ARP Spoofing Attack:
        ┌──────────┐                        ┌──────────┐
        │ Victim   │ <──── Fake ARP ────── │ Attacker │
        │192.168.1.2│   "I am Gateway"      │192.168.1.5│
        └──────────┘                        └──────────┘
                ↓                                 ↑
                └──────── All Traffic ────────────┘
        ```
        
        ### 🎯 **Attack Vectors**
        
        | Attack Type | Description | Impact |
        |------------|-------------|---------|
        | **MITM** | Intercept all traffic | High |
        | **DoS** | Disrupt network connectivity | Medium |
        | **Session Hijacking** | Steal active sessions | Critical |
        | **DNS Spoofing** | Redirect to malicious sites | High |
        """)
    
    # Lab Interface
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🎯 **Attack Configuration**")
        
        victim_ip = st.text_input("👤 Victim IP:", value="192.168.1.100")
        gateway_ip = st.text_input("🌐 Gateway IP:", value="192.168.1.1")
        
        attack_mode = st.radio("⚔️ Attack Mode:", [
            "🔍 Passive Monitoring",
            "🎭 Active MITM",
            "💣 DoS Attack",
            "📡 Traffic Redirection"
        ])
        
        packet_forward = st.checkbox("📨 Enable Packet Forwarding", value=True)
        
        if st.button("🚀 **Launch ARP Attack**", type="primary"):
            st.error("⛔ This is a simulation only - no actual attack performed")
            results = simulate_arp_attack(victim_ip, gateway_ip, attack_mode)
            st.session_state['arp_results'] = results
    
    with col2:
        st.markdown("#### 📊 **Attack Results**")
        
        if 'arp_results' in st.session_state:
            results = st.session_state['arp_results']
            
            # Attack Status
            st.success("✅ **Attack Simulation Complete**")
            
            # Statistics
            col_a, col_b = st.columns(2)
            with col_a:
                st.metric("📦 Packets Sent", results['packets_sent'])
            with col_b:
                st.metric("🎯 Success Rate", f"{results['success_rate']}%")
            
            # Captured Traffic Preview
            st.markdown("**📡 Simulated Captured Traffic:**")
            traffic_df = pd.DataFrame(results['captured_traffic'])
            st.dataframe(traffic_df, use_container_width=True)
            
            # Mitigation Strategies
            with st.expander("🛡️ **Defense Mechanisms**"):
                st.markdown("""
                **Prevention Methods:**
                - 🔒 Static ARP entries
                - 🛡️ ARP inspection (DAI)
                - 📊 Network monitoring
                - 🔐 Port security
                - 🌐 VLANs segmentation
                """)

def mitm_lab():
    """Lab Man-in-the-Middle Attack"""
    
    st.markdown("""
    <div style="background: linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%); 
                padding: 20px; border-radius: 10px; margin-bottom: 20px;">
        <h2 style="color: white; margin: 0;">🔓 Man-in-the-Middle Lab</h2>
        <p style="color: white; margin: 5px 0 0 0;">Intercepting and Analyzing Network Communications</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Interactive MITM Diagram
    st.markdown("""
    ### 🎯 **MITM Attack Flow**
    
    ```mermaid
    graph LR
        A[👤 Victim] -->|Encrypted Traffic| B[🦹 Attacker]
        B -->|Decrypted/Modified| C[🌐 Server]
        C -->|Response| B
        B -->|Modified Response| A
        
        style B fill:#ff6b6b,stroke:#fff,stroke-width:2px
    ```
    """)
    
    tabs = st.tabs(["🔐 SSL/TLS MITM", "🌐 DNS Hijacking", "📡 WiFi MITM", "🍪 Session Hijacking"])
    
    with tabs[0]:
        st.markdown("#### 🔐 **SSL/TLS Interception**")
        
        col1, col2 = st.columns(2)
        with col1:
            target_site = st.text_input("🎯 Target Website:", value="https://example.com")
            cert_method = st.selectbox("📜 Certificate Method:", [
                "Self-Signed Certificate",
                "Cloned Certificate",
                "Subdomain Takeover",
                "BGP Hijacking"
            ])
            
            if st.button("🚀 Start SSL MITM"):
                results = simulate_ssl_mitm(target_site, cert_method)
                st.json(results)
        
        with col2:
            st.info("""
            **🛡️ SSL Pinning Bypass:**
            - Frida Framework
            - Objection Toolkit
            - Certificate Transparency
            - HPKP Headers
            """)
    
    with tabs[1]:
        st.markdown("#### 🌐 **DNS Hijacking Attack**")
        
        dns_target = st.text_input("🎯 Target Domain:", value="bank.example.com")
        redirect_ip = st.text_input("➡️ Redirect to IP:", value="192.168.1.100")
        
        if st.button("🎭 Hijack DNS"):
            st.code(f"""
            # DNS Response Injection
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                if "{dns_target}" in packet[DNS].qd.qname:
                    spoofed = IP(dst=packet[IP].src)/\\
                              UDP(dport=packet[UDP].sport)/\\
                              DNS(id=packet[DNS].id, qr=1, 
                                  an=DNSRR(name=packet[DNS].qd.qname,
                                          rdata='{redirect_ip}'))
                    send(spoofed)
            """, language="python")

def dos_ddos_lab():
    """Lab DoS/DDoS Simulation"""
    
    st.markdown("""
    <div style="background: linear-gradient(90deg, #ff6a00 0%, #ee0979 100%); 
                padding: 20px; border-radius: 10px; margin-bottom: 20px;">
        <h2 style="color: white; margin: 0;">💣 DoS/DDoS Simulation Lab</h2>
        <p style="color: white; margin: 5px 0 0 0;">Understanding Denial of Service Attack Patterns</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Attack Types Grid
    st.markdown("### 🎯 **Attack Vector Selection**")
    
    attack_types = {
        "🌊 SYN Flood": "TCP SYN packets overwhelming the target",
        "📦 UDP Flood": "High volume UDP packet bombardment",
        "🌐 HTTP Flood": "Application layer resource exhaustion",
        "💥 Smurf Attack": "ICMP amplification attack",
        "🔄 Slowloris": "Keeping connections open indefinitely",
        "⚡ Ping of Death": "Oversized ICMP packets"
    }
    
    cols = st.columns(3)
    for idx, (attack, desc) in enumerate(attack_types.items()):
        with cols[idx % 3]:
            if st.button(attack, use_container_width=True):
                st.info(f"**{attack}:** {desc}")
                simulate_dos_attack(attack)
    
    # Real-time Attack Metrics
    st.markdown("### 📊 **Attack Metrics Dashboard**")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📦 Packets/sec", "10,000", "↑ 500%")
    with col2:
        st.metric("🔥 Bandwidth", "1.2 Gbps", "↑ 1200%")
    with col3:
        st.metric("🎯 Success Rate", "87%", "↓ 13%")
    with col4:
        st.metric("⏱️ Response Time", "5000ms", "↑ 4500ms")
    
    # Mitigation Strategies
    with st.expander("🛡️ **DDoS Mitigation Strategies**"):
        st.markdown("""
        ### **Prevention & Mitigation**
        
        | Strategy | Description | Effectiveness |
        |----------|-------------|---------------|
        | **Rate Limiting** | Limit requests per IP | 🟡 Medium |
        | **CDN/Proxy** | Distribute traffic load | 🟢 High |
        | **Blackholing** | Drop malicious traffic | 🟢 High |
        | **SYN Cookies** | Prevent SYN flood | 🟢 High |
        | **Anycast** | Geographic distribution | 🟢 High |
        | **Machine Learning** | Anomaly detection | 🟡 Medium |
        """)

# Helper functions for new labs
def perform_os_fingerprinting(target_ip: str, technique: str, aggressive: bool) -> Dict:
    """Simulate OS fingerprinting"""
    os_signatures = {
        "Windows 10": {"ttl": 128, "window": 65535, "df": True, "confidence": 95},
        "Ubuntu Linux": {"ttl": 64, "window": 29200, "df": True, "confidence": 88},
        "macOS": {"ttl": 64, "window": 65535, "df": True, "confidence": 82},
        "FreeBSD": {"ttl": 64, "window": 65535, "df": False, "confidence": 75},
        "Cisco IOS": {"ttl": 255, "window": 4096, "df": True, "confidence": 90}
    }
    
    # Simulate detection
    detected_os = random.choice(list(os_signatures.keys()))
    signature = os_signatures[detected_os]
    
    return {
        "os": detected_os,
        "version": f"{detected_os} {'Pro' if 'Windows' in detected_os else 'LTS'}",
        "confidence": signature["confidence"] + random.randint(-5, 5),
        "technical_details": {
            "ttl": signature["ttl"],
            "window_size": signature["window"],
            "df_flag": signature["df"],
            "tcp_options": ["MSS", "SACK", "Timestamp", "NOP", "WScale"],
            "open_ports": [22, 80, 443, 3389] if "Windows" in detected_os else [22, 80, 443]
        },
        "fingerprint_data": signature
    }

def create_fingerprint_visualization(data: Dict):
    """Create OS fingerprint visualization"""
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=("TTL Analysis", "Window Size", "TCP Options", "Port Signature"),
        specs=[[{"type": "bar"}, {"type": "scatter"}],
               [{"type": "pie"}, {"type": "heatmap"}]]
    )
    
    # TTL comparison
    fig.add_trace(
        go.Bar(x=["Target", "Windows", "Linux", "macOS"], 
               y=[data.get("ttl", 64), 128, 64, 64],
               marker_color=["red", "blue", "green", "orange"]),
        row=1, col=1
    )
    
    # Window size timeline
    fig.add_trace(
        go.Scatter(x=list(range(10)), 
                   y=[data.get("window", 65535) + random.randint(-1000, 1000) for _ in range(10)],
                   mode="lines+markers"),
        row=1, col=2
    )
    
    # TCP Options distribution
    options = ["MSS", "SACK", "Timestamp", "WScale", "NOP"]
    values = [random.randint(10, 30) for _ in options]
    fig.add_trace(
        go.Pie(labels=options, values=values),
        row=2, col=1
    )
    
    fig.update_layout(height=600, showlegend=False)
    return fig

def simulate_arp_attack(victim_ip: str, gateway_ip: str, mode: str) -> Dict:
    """Simulate ARP spoofing attack"""
    return {
        "packets_sent": random.randint(100, 1000),
        "success_rate": random.randint(75, 95),
        "captured_traffic": [
            {"Time": f"00:00:{i:02d}", "Source": victim_ip, "Dest": gateway_ip, 
             "Protocol": random.choice(["HTTP", "HTTPS", "DNS", "SSH"]),
             "Info": f"Packet {i+1}"}
            for i in range(10)
        ]
    }

def simulate_ssl_mitm(target: str, method: str) -> Dict:
    """Simulate SSL/TLS MITM attack"""
    return {
        "target": target,
        "method": method,
        "certificate_info": {
            "issuer": "Fake CA",
            "subject": target.replace("https://", ""),
            "valid_from": datetime.now().isoformat(),
            "valid_to": (datetime.now() + timedelta(days=365)).isoformat(),
            "fingerprint": hashlib.sha256(target.encode()).hexdigest()[:40]
        },
        "intercepted_data": {
            "cookies": ["session_id=abc123", "auth_token=xyz789"],
            "headers": {"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
            "form_data": {"username": "victim", "password": "***hidden***"}
        }
    }

def simulate_dos_attack(attack_type: str) -> None:
    """Simulate DoS attack visualization"""
    # Create real-time attack visualization
    placeholder = st.empty()
    for i in range(10):
        with placeholder.container():
            st.metric("🎯 Attack Progress", f"{i*10}%", f"↑ {i*100} packets")
            time.sleep(0.5)
    st.success("✅ Attack simulation completed!")
