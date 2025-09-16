import streamlit as st
import socket
import threading
import time
import pandas as pd
import plotly.express as px
import subprocess
import re
from datetime import datetime

def run_lab():
    """Network Security Lab - Học về bảo mật mạng"""
    
    st.title("🌐 Network Security Lab")
    st.markdown("---")
    
    # Tabs cho các bài thực hành khác nhau
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔍 Port Scanner", 
        "📡 Network Discovery", 
        "📊 Traffic Analysis",
        "🛡️ Security Assessment"
    ])
    
    with tab1:
        port_scanner_lab()
    
    with tab2:
        network_discovery_lab()
    
    with tab3:
        traffic_analysis_lab()
        
    with tab4:
        security_assessment_lab()

def port_scanner_lab():
    """Lab quét port"""
    st.subheader("🔍 Port Scanner Lab")
    
    # Thêm phần giải thích chi tiết
    with st.expander("📖 Lý thuyết chi tiết về Port Scanning"):
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
