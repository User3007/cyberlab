import streamlit as st
import socket
import struct
import threading
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import subprocess
import re
import json
from datetime import datetime, timedelta
import ipaddress
import random

def run_lab():
    """Advanced Networking Lab - Học về mạng nâng cao"""
    
    st.title("🌐 Advanced Networking Lab")
    st.markdown("---")
    
    # Tabs cho các bài thực hành khác nhau
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🔍 Network Reconnaissance", 
        "📡 Protocol Analysis",
        "🌍 Network Topology Mapping", 
        "🚦 Traffic Monitoring",
        "🔒 Network Security Testing",
        "📊 Network Performance Analysis"
    ])
    
    with tab1:
        network_reconnaissance_lab()
    
    with tab2:
        protocol_analysis_lab()
    
    with tab3:
        network_topology_lab()
        
    with tab4:
        traffic_monitoring_lab()
        
    with tab5:
        network_security_testing_lab()
        
    with tab6:
        network_performance_lab()

def network_reconnaissance_lab():
    """Lab Network Reconnaissance"""
    st.subheader("🔍 Network Reconnaissance Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Network Reconnaissance là giai đoạn đầu tiên trong penetration testing,
    bao gồm việc thu thập thông tin về target network mà không tương tác trực tiếp.
    
    **Các kỹ thuật chính:**
    - **Passive Reconnaissance**: Thu thập thông tin không tương tác trực tiếp
    - **Active Reconnaissance**: Tương tác trực tiếp với target
    - **OSINT (Open Source Intelligence)**: Sử dụng nguồn mở
    - **DNS Enumeration**: Khám phá DNS records
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🎯 Target Configuration")
        
        recon_type = st.selectbox("Reconnaissance Type:", [
            "DNS Enumeration",
            "Subdomain Discovery", 
            "Port Range Analysis",
            "Service Fingerprinting",
            "OS Detection"
        ])
        
        target_domain = st.text_input("Target Domain/IP:", value="example.com")
        
        if st.button("🚀 Start Reconnaissance"):
            with st.spinner(f"Performing {recon_type}..."):
                if recon_type == "DNS Enumeration":
                    results = dns_enumeration(target_domain)
                elif recon_type == "Subdomain Discovery":
                    results = subdomain_discovery(target_domain)
                elif recon_type == "Port Range Analysis":
                    results = port_range_analysis(target_domain)
                elif recon_type == "Service Fingerprinting":
                    results = service_fingerprinting(target_domain)
                else:
                    results = os_detection(target_domain)
                
                st.session_state['recon_results'] = results
    
    with col2:
        st.markdown("#### 📊 Reconnaissance Results")
        
        if 'recon_results' in st.session_state:
            results = st.session_state['recon_results']
            
            if results['success']:
                st.success("✅ Reconnaissance completed!")
                
                # Hiển thị kết quả dựa trên loại reconnaissance
                if 'dns_records' in results:
                    st.markdown("**🌐 DNS Records:**")
                    for record_type, records in results['dns_records'].items():
                        if records:
                            st.write(f"**{record_type}:**")
                            for record in records:
                                st.write(f"  • {record}")
                
                if 'subdomains' in results:
                    st.markdown("**🔍 Discovered Subdomains:**")
                    for subdomain in results['subdomains']:
                        st.write(f"  • {subdomain}")
                
                if 'open_ports' in results:
                    st.markdown("**🚪 Open Ports:**")
                    df = pd.DataFrame(results['open_ports'])
                    st.dataframe(df, width='stretch')
                
                if 'services' in results:
                    st.markdown("**🔧 Detected Services:**")
                    for service in results['services']:
                        st.write(f"  • Port {service['port']}: {service['service']} ({service['version']})")
                
                if 'os_info' in results:
                    st.markdown("**💻 OS Information:**")
                    st.info(f"Detected OS: {results['os_info']['os']}")
                    st.info(f"Confidence: {results['os_info']['confidence']}%")
            else:
                st.error(f"❌ Reconnaissance failed: {results.get('error', 'Unknown error')}")

def protocol_analysis_lab():
    """Lab Protocol Analysis"""
    st.subheader("📡 Protocol Analysis Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Protocol Analysis giúp hiểu cách các giao thức mạng hoạt động
    và phát hiện các anomalies trong network traffic.
    
    **Các giao thức phổ biến:**
    - **TCP/UDP**: Transport layer protocols
    - **HTTP/HTTPS**: Web protocols
    - **DNS**: Domain Name System
    - **ICMP**: Internet Control Message Protocol
    - **ARP**: Address Resolution Protocol
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 📊 Protocol Statistics")
        
        if st.button("📈 Generate Protocol Statistics"):
            protocol_stats = generate_protocol_statistics()
            st.session_state['protocol_stats'] = protocol_stats
        
        st.markdown("#### 🔍 Packet Analysis")
        
        protocol_filter = st.selectbox("Protocol Filter:", [
            "All Protocols", "TCP", "UDP", "HTTP", "DNS", "ICMP"
        ])
        
        if st.button("🔍 Analyze Packets"):
            packet_analysis = analyze_packets(protocol_filter)
            st.session_state['packet_analysis'] = packet_analysis
    
    with col2:
        st.markdown("#### 📊 Analysis Results")
        
        if 'protocol_stats' in st.session_state:
            stats = st.session_state['protocol_stats']
            
            # Protocol distribution pie chart
            fig_pie = px.pie(
                values=list(stats['distribution'].values()),
                names=list(stats['distribution'].keys()),
                title="Protocol Distribution"
            )
            st.plotly_chart(fig_pie, width='stretch')
            
            # Traffic over time
            fig_line = px.line(
                x=stats['timeline']['time'],
                y=stats['timeline']['packets'],
                title="Packet Count Over Time"
            )
            st.plotly_chart(fig_line, width='stretch')
        
        if 'packet_analysis' in st.session_state:
            analysis = st.session_state['packet_analysis']
            
            st.markdown("**📦 Packet Details:**")
            df = pd.DataFrame(analysis['packets'])
            st.dataframe(df, width='stretch')
            
            st.markdown("**⚠️ Anomalies Detected:**")
            for anomaly in analysis['anomalies']:
                st.warning(f"🚨 {anomaly}")

def network_topology_lab():
    """Lab Network Topology Mapping"""
    st.subheader("🌍 Network Topology Mapping Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Network Topology Mapping giúp hiểu cấu trúc và layout của mạng,
    xác định các thiết bị, connections và potential attack paths.
    
    **Kỹ thuật mapping:**
    - **Traceroute**: Xác định đường đi của packets
    - **TTL Analysis**: Phân tích Time-to-Live values
    - **Network Discovery**: Tìm kiếm active hosts
    - **Route Analysis**: Phân tích routing tables
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🗺️ Topology Discovery")
        
        network_range = st.text_input("Network Range:", value="192.168.1.0/24")
        
        mapping_method = st.selectbox("Mapping Method:", [
            "Ping Sweep + Traceroute",
            "ARP Discovery",
            "SNMP Walking",
            "Route Table Analysis"
        ])
        
        if st.button("🗺️ Map Network Topology"):
            with st.spinner("Mapping network topology..."):
                topology = map_network_topology(network_range, mapping_method)
                st.session_state['network_topology'] = topology
    
    with col2:
        st.markdown("#### 🌐 Topology Visualization")
        
        if 'network_topology' in st.session_state:
            topology = st.session_state['network_topology']
            
            # Network topology graph
            fig = create_topology_graph(topology)
            st.plotly_chart(fig, width='stretch')
            
            # Device summary
            st.markdown("**📱 Discovered Devices:**")
            device_df = pd.DataFrame(topology['devices'])
            st.dataframe(device_df, width='stretch')
            
            # Network statistics
            st.markdown("**📊 Network Statistics:**")
            st.info(f"""
            **Total Devices:** {len(topology['devices'])}
            **Active Hosts:** {topology['stats']['active_hosts']}
            **Network Segments:** {topology['stats']['segments']}
            **Potential Gateways:** {topology['stats']['gateways']}
            """)

def traffic_monitoring_lab():
    """Lab Traffic Monitoring"""
    st.subheader("🚦 Traffic Monitoring Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Traffic Monitoring giúp theo dõi và phân tích network traffic
    để phát hiện patterns, anomalies và potential security threats.
    
    **Metrics quan trọng:**
    - **Bandwidth Utilization**: Sử dụng băng thông
    - **Packet Loss**: Tỷ lệ mất gói tin
    - **Latency**: Độ trễ mạng
    - **Connection Patterns**: Patterns kết nối
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 📊 Monitoring Configuration")
        
        monitor_duration = st.slider("Monitoring Duration (minutes):", 1, 60, 5)
        
        metrics_to_monitor = st.multiselect("Metrics to Monitor:", [
            "Bandwidth Usage",
            "Packet Count",
            "Connection Count", 
            "Protocol Distribution",
            "Top Talkers",
            "Anomaly Detection"
        ], default=["Bandwidth Usage", "Packet Count"])
        
        if st.button("📊 Start Monitoring"):
            with st.spinner(f"Monitoring traffic for {monitor_duration} minutes..."):
                monitoring_data = simulate_traffic_monitoring(monitor_duration, metrics_to_monitor)
                st.session_state['monitoring_data'] = monitoring_data
    
    with col2:
        st.markdown("#### 📈 Real-time Metrics")
        
        if 'monitoring_data' in st.session_state:
            data = st.session_state['monitoring_data']
            
            # Bandwidth utilization
            if "Bandwidth Usage" in data:
                fig_bw = px.line(
                    x=data["Bandwidth Usage"]['time'],
                    y=data["Bandwidth Usage"]['usage'],
                    title="Bandwidth Utilization Over Time",
                    labels={'y': 'Mbps', 'x': 'Time'}
                )
                st.plotly_chart(fig_bw, width='stretch')
            
            # Packet count
            if "Packet Count" in data:
                fig_packets = px.bar(
                    x=data["Packet Count"]['intervals'],
                    y=data["Packet Count"]['counts'],
                    title="Packet Count per Interval"
                )
                st.plotly_chart(fig_packets, width='stretch')
            
            # Top talkers
            if "Top Talkers" in data:
                st.markdown("**🗣️ Top Talkers:**")
                talkers_df = pd.DataFrame(data["Top Talkers"])
                st.dataframe(talkers_df, width='stretch')

def network_security_testing_lab():
    """Lab Network Security Testing"""
    st.subheader("🔒 Network Security Testing Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Network Security Testing đánh giá security posture của network infrastructure
    và xác định các vulnerabilities có thể bị exploit.
    
    **Các loại test:**
    - **Vulnerability Scanning**: Quét lỗ hổng bảo mật
    - **Penetration Testing**: Thử nghiệm xâm nhập
    - **Configuration Review**: Kiểm tra cấu hình
    - **Compliance Testing**: Kiểm tra tuân thủ
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🛡️ Security Test Configuration")
        
        test_type = st.selectbox("Security Test Type:", [
            "Network Vulnerability Scan",
            "Firewall Rule Testing",
            "Wireless Security Assessment",
            "Network Segmentation Test",
            "DDoS Simulation"
        ])
        
        target_network = st.text_input("Target Network:", value="192.168.1.0/24")
        
        test_intensity = st.selectbox("Test Intensity:", [
            "Light (Safe)", "Medium (Moderate)", "Aggressive (Thorough)"
        ])
        
        if st.button("🔒 Run Security Test"):
            with st.spinner(f"Running {test_type}..."):
                security_results = run_security_test(test_type, target_network, test_intensity)
                st.session_state['security_results'] = security_results
    
    with col2:
        st.markdown("#### 🛡️ Security Assessment Results")
        
        if 'security_results' in st.session_state:
            results = st.session_state['security_results']
            
            # Security score
            score = results['security_score']
            if score >= 80:
                st.success(f"🟢 Security Score: {score}/100 - Good")
            elif score >= 60:
                st.warning(f"🟡 Security Score: {score}/100 - Fair")
            else:
                st.error(f"🔴 Security Score: {score}/100 - Poor")
            
            # Vulnerabilities found
            st.markdown("**⚠️ Vulnerabilities Found:**")
            for vuln in results['vulnerabilities']:
                severity_color = {
                    'Critical': '🔴',
                    'High': '🟠', 
                    'Medium': '🟡',
                    'Low': '🟢'
                }
                st.write(f"{severity_color.get(vuln['severity'], '⚪')} **{vuln['severity']}**: {vuln['description']}")
            
            # Recommendations
            st.markdown("**💡 Security Recommendations:**")
            for rec in results['recommendations']:
                st.write(f"• {rec}")
            
            # Compliance status
            if 'compliance' in results:
                st.markdown("**📋 Compliance Status:**")
                compliance_df = pd.DataFrame(results['compliance'])
                st.dataframe(compliance_df, width='stretch')

def network_performance_lab():
    """Lab Network Performance Analysis"""
    st.subheader("📊 Network Performance Analysis Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Network Performance Analysis đo lường và đánh giá hiệu suất mạng
    để tối ưu hóa performance và user experience.
    
    **Metrics chính:**
    - **Throughput**: Lượng dữ liệu truyền được
    - **Latency**: Thời gian trễ
    - **Jitter**: Biến động độ trễ
    - **Packet Loss**: Tỷ lệ mất gói tin
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### ⚡ Performance Testing")
        
        test_target = st.text_input("Test Target:", value="8.8.8.8")
        
        performance_tests = st.multiselect("Performance Tests:", [
            "Ping Test (Latency)",
            "Bandwidth Test", 
            "Jitter Analysis",
            "Packet Loss Test",
            "Route Performance"
        ], default=["Ping Test (Latency)", "Bandwidth Test"])
        
        test_duration = st.slider("Test Duration (seconds):", 10, 300, 60)
        
        if st.button("⚡ Run Performance Tests"):
            with st.spinner("Running performance tests..."):
                perf_results = run_performance_tests(test_target, performance_tests, test_duration)
                st.session_state['perf_results'] = perf_results
    
    with col2:
        st.markdown("#### 📈 Performance Metrics")
        
        if 'perf_results' in st.session_state:
            results = st.session_state['perf_results']
            
            # Performance summary
            st.markdown("**📊 Performance Summary:**")
            if 'ping' in results:
                ping_data = results['ping']
                st.metric("Average Latency", f"{ping_data['avg_latency']:.2f} ms")
                st.metric("Packet Loss", f"{ping_data['packet_loss']:.1f}%")
            
            if 'bandwidth' in results:
                bw_data = results['bandwidth']
                st.metric("Download Speed", f"{bw_data['download']:.2f} Mbps")
                st.metric("Upload Speed", f"{bw_data['upload']:.2f} Mbps")
            
            # Performance over time charts
            if 'ping' in results:
                fig_latency = px.line(
                    x=results['ping']['timestamps'],
                    y=results['ping']['latencies'],
                    title="Latency Over Time",
                    labels={'y': 'Latency (ms)', 'x': 'Time'}
                )
                st.plotly_chart(fig_latency, width='stretch')
            
            # Performance grade
            grade = calculate_performance_grade(results)
            grade_colors = {'A': '🟢', 'B': '🟡', 'C': '🟠', 'D': '🔴', 'F': '⚫'}
            st.markdown(f"**🎯 Performance Grade: {grade_colors.get(grade, '⚪')} {grade}**")

# Helper Functions
def dns_enumeration(domain):
    """Simulate DNS enumeration"""
    try:
        # Simulate DNS record discovery
        dns_records = {
            'A': [f"{domain} -> 192.168.1.100", f"www.{domain} -> 192.168.1.101"],
            'MX': [f"mail.{domain} -> 192.168.1.102"],
            'NS': [f"ns1.{domain}", f"ns2.{domain}"],
            'TXT': [f"v=spf1 include:_spf.{domain} ~all"],
            'CNAME': [f"ftp.{domain} -> www.{domain}"]
        }
        
        return {
            'success': True,
            'dns_records': dns_records,
            'total_records': sum(len(records) for records in dns_records.values())
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def subdomain_discovery(domain):
    """Simulate subdomain discovery"""
    common_subdomains = [
        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 
        'api', 'blog', 'shop', 'support', 'cdn', 'static'
    ]
    
    # Simulate discovery results
    discovered = random.sample(common_subdomains, random.randint(3, 8))
    subdomains = [f"{sub}.{domain}" for sub in discovered]
    
    return {
        'success': True,
        'subdomains': subdomains,
        'total_found': len(subdomains)
    }

def port_range_analysis(target):
    """Simulate port range analysis"""
    # Simulate common open ports
    common_ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
    open_ports = []
    
    for port in random.sample(common_ports, random.randint(2, 6)):
        service_map = {
            22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 3389: 'RDP', 5432: 'PostgreSQL', 3306: 'MySQL'
        }
        
        open_ports.append({
            'port': port,
            'service': service_map.get(port, 'Unknown'),
            'state': 'Open',
            'protocol': 'TCP'
        })
    
    return {
        'success': True,
        'open_ports': open_ports,
        'total_scanned': 65535,
        'total_open': len(open_ports)
    }

def service_fingerprinting(target):
    """Simulate service fingerprinting"""
    services = [
        {'port': 22, 'service': 'SSH', 'version': 'OpenSSH 8.2'},
        {'port': 80, 'service': 'HTTP', 'version': 'Apache 2.4.41'},
        {'port': 443, 'service': 'HTTPS', 'version': 'Apache 2.4.41'},
        {'port': 3306, 'service': 'MySQL', 'version': 'MySQL 8.0.25'}
    ]
    
    detected_services = random.sample(services, random.randint(2, 4))
    
    return {
        'success': True,
        'services': detected_services,
        'total_services': len(detected_services)
    }

def os_detection(target):
    """Simulate OS detection"""
    os_options = [
        {'os': 'Ubuntu 20.04 LTS', 'confidence': 95},
        {'os': 'Windows Server 2019', 'confidence': 88},
        {'os': 'CentOS 8', 'confidence': 92},
        {'os': 'Debian 10', 'confidence': 87}
    ]
    
    detected_os = random.choice(os_options)
    
    return {
        'success': True,
        'os_info': detected_os
    }

def generate_protocol_statistics():
    """Generate sample protocol statistics"""
    protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'ARP']
    
    # Generate random distribution
    distribution = {}
    for protocol in protocols:
        distribution[protocol] = random.randint(5, 30)
    
    # Normalize to percentages
    total = sum(distribution.values())
    distribution = {k: round(v/total*100, 1) for k, v in distribution.items()}
    
    # Generate timeline data
    timeline = {
        'time': [datetime.now() - timedelta(minutes=i) for i in range(60, 0, -5)],
        'packets': [random.randint(100, 1000) for _ in range(12)]
    }
    
    return {
        'distribution': distribution,
        'timeline': timeline,
        'total_packets': sum(timeline['packets'])
    }

def analyze_packets(protocol_filter):
    """Simulate packet analysis"""
    packets = []
    anomalies = []
    
    # Generate sample packets
    for i in range(20):
        packet = {
            'timestamp': (datetime.now() - timedelta(seconds=i*5)).strftime('%H:%M:%S'),
            'source': f"192.168.1.{random.randint(1, 254)}",
            'destination': f"10.0.0.{random.randint(1, 254)}",
            'protocol': random.choice(['TCP', 'UDP', 'HTTP', 'DNS']),
            'size': random.randint(64, 1500),
            'flags': random.choice(['SYN', 'ACK', 'FIN', 'RST', 'PSH'])
        }
        packets.append(packet)
    
    # Generate anomalies
    if random.random() > 0.7:
        anomalies.append("Unusual traffic pattern detected from 192.168.1.50")
    if random.random() > 0.8:
        anomalies.append("Potential port scan detected")
    if random.random() > 0.9:
        anomalies.append("Suspicious DNS queries observed")
    
    return {
        'packets': packets,
        'anomalies': anomalies,
        'total_analyzed': len(packets)
    }

def map_network_topology(network_range, method):
    """Simulate network topology mapping"""
    # Generate sample network devices
    devices = []
    device_types = ['Router', 'Switch', 'Server', 'Workstation', 'Printer', 'Access Point']
    
    try:
        network = ipaddress.IPv4Network(network_range, strict=False)
        sample_ips = random.sample(list(network.hosts()), min(10, network.num_addresses-2))
        
        for i, ip in enumerate(sample_ips):
            device = {
                'ip': str(ip),
                'hostname': f"device-{i+1}.local",
                'type': random.choice(device_types),
                'mac': f"00:1B:44:11:3A:{i+10:02X}",
                'vendor': random.choice(['Cisco', 'HP', 'Dell', 'Netgear', 'D-Link']),
                'status': 'Active'
            }
            devices.append(device)
    except:
        # Fallback for invalid network range
        for i in range(5):
            device = {
                'ip': f"192.168.1.{i+10}",
                'hostname': f"device-{i+1}.local", 
                'type': random.choice(device_types),
                'mac': f"00:1B:44:11:3A:{i+10:02X}",
                'vendor': random.choice(['Cisco', 'HP', 'Dell', 'Netgear', 'D-Link']),
                'status': 'Active'
            }
            devices.append(device)
    
    stats = {
        'active_hosts': len(devices),
        'segments': random.randint(1, 3),
        'gateways': random.randint(1, 2)
    }
    
    return {
        'devices': devices,
        'stats': stats,
        'method_used': method
    }

def create_topology_graph(topology):
    """Create network topology visualization"""
    devices = topology['devices']
    
    # Create a simple network graph
    fig = go.Figure()
    
    # Add nodes for devices
    x_coords = []
    y_coords = []
    text_labels = []
    colors = []
    
    color_map = {
        'Router': 'red',
        'Switch': 'blue', 
        'Server': 'green',
        'Workstation': 'orange',
        'Printer': 'purple',
        'Access Point': 'cyan'
    }
    
    for i, device in enumerate(devices):
        # Arrange in a circle
        angle = 2 * 3.14159 * i / len(devices)
        x = 5 * (1 + 0.5 * (i % 2)) * (1 if i < len(devices)/2 else -1)
        y = 3 * (i % 3 - 1)
        
        x_coords.append(x)
        y_coords.append(y)
        text_labels.append(f"{device['hostname']}<br>{device['ip']}<br>{device['type']}")
        colors.append(color_map.get(device['type'], 'gray'))
    
    fig.add_trace(go.Scatter(
        x=x_coords,
        y=y_coords,
        mode='markers+text',
        marker=dict(size=20, color=colors),
        text=[d['hostname'] for d in devices],
        textposition="bottom center",
        hovertext=text_labels,
        name="Network Devices"
    ))
    
    # Add connections (simplified)
    for i in range(len(devices)-1):
        fig.add_trace(go.Scatter(
            x=[x_coords[i], x_coords[i+1]],
            y=[y_coords[i], y_coords[i+1]],
            mode='lines',
            line=dict(color='gray', width=1),
            showlegend=False,
            hoverinfo='none'
        ))
    
    fig.update_layout(
        title="Network Topology Map",
        showlegend=False,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=400
    )
    
    return fig

def simulate_traffic_monitoring(duration, metrics):
    """Simulate traffic monitoring data"""
    monitoring_data = {}
    
    if "Bandwidth Usage" in metrics:
        time_points = [datetime.now() - timedelta(minutes=i) for i in range(duration, 0, -1)]
        usage_values = [random.uniform(10, 100) for _ in range(duration)]
        
        monitoring_data["Bandwidth Usage"] = {
            'time': time_points,
            'usage': usage_values
        }
    
    if "Packet Count" in metrics:
        intervals = [f"{i}-{i+1}min" for i in range(0, duration, 5)]
        counts = [random.randint(1000, 10000) for _ in intervals]
        
        monitoring_data["Packet Count"] = {
            'intervals': intervals,
            'counts': counts
        }
    
    if "Top Talkers" in metrics:
        talkers = []
        for i in range(5):
            talker = {
                'IP Address': f"192.168.1.{random.randint(1, 254)}",
                'Bytes Sent': f"{random.randint(1, 100)} MB",
                'Bytes Received': f"{random.randint(1, 100)} MB",
                'Connections': random.randint(10, 500)
            }
            talkers.append(talker)
        
        monitoring_data["Top Talkers"] = talkers
    
    return monitoring_data

def run_security_test(test_type, target_network, intensity):
    """Simulate network security testing"""
    
    # Generate vulnerabilities based on test type
    vulnerabilities = []
    recommendations = []
    
    if test_type == "Network Vulnerability Scan":
        vulns = [
            {'severity': 'High', 'description': 'Unpatched SSH service detected'},
            {'severity': 'Medium', 'description': 'Weak SSL/TLS configuration'},
            {'severity': 'Low', 'description': 'Information disclosure in HTTP headers'}
        ]
        vulnerabilities = random.sample(vulns, random.randint(1, 3))
        
        recommendations = [
            "Update SSH to latest version",
            "Implement strong SSL/TLS configuration", 
            "Remove sensitive information from HTTP headers"
        ]
    
    elif test_type == "Firewall Rule Testing":
        vulns = [
            {'severity': 'Critical', 'description': 'Firewall allows unrestricted access to port 22'},
            {'severity': 'Medium', 'description': 'Overly permissive outbound rules detected'}
        ]
        vulnerabilities = random.sample(vulns, random.randint(1, 2))
        
        recommendations = [
            "Restrict SSH access to specific IP ranges",
            "Review and tighten outbound firewall rules"
        ]
    
    # Calculate security score
    severity_weights = {'Critical': 25, 'High': 15, 'Medium': 10, 'Low': 5}
    penalty = sum(severity_weights.get(v['severity'], 0) for v in vulnerabilities)
    security_score = max(0, 100 - penalty)
    
    # Generate compliance data
    compliance = [
        {'Standard': 'PCI DSS', 'Status': 'Compliant' if security_score > 80 else 'Non-Compliant'},
        {'Standard': 'ISO 27001', 'Status': 'Compliant' if security_score > 70 else 'Partial'},
        {'Standard': 'NIST', 'Status': 'Compliant' if security_score > 75 else 'Non-Compliant'}
    ]
    
    return {
        'security_score': security_score,
        'vulnerabilities': vulnerabilities,
        'recommendations': recommendations,
        'compliance': compliance,
        'test_type': test_type,
        'target': target_network
    }

def run_performance_tests(target, tests, duration):
    """Simulate network performance testing"""
    results = {}
    
    if "Ping Test (Latency)" in tests:
        # Simulate ping test results
        latencies = [random.uniform(10, 100) for _ in range(duration)]
        timestamps = [datetime.now() - timedelta(seconds=i) for i in range(duration, 0, -1)]
        
        results['ping'] = {
            'avg_latency': sum(latencies) / len(latencies),
            'min_latency': min(latencies),
            'max_latency': max(latencies),
            'packet_loss': random.uniform(0, 5),
            'latencies': latencies,
            'timestamps': timestamps
        }
    
    if "Bandwidth Test" in tests:
        # Simulate bandwidth test
        results['bandwidth'] = {
            'download': random.uniform(50, 1000),
            'upload': random.uniform(20, 500),
            'test_duration': duration
        }
    
    if "Jitter Analysis" in tests:
        # Simulate jitter analysis
        results['jitter'] = {
            'avg_jitter': random.uniform(1, 20),
            'max_jitter': random.uniform(20, 50)
        }
    
    return results

def calculate_performance_grade(results):
    """Calculate overall performance grade"""
    score = 100
    
    if 'ping' in results:
        avg_latency = results['ping']['avg_latency']
        packet_loss = results['ping']['packet_loss']
        
        if avg_latency > 100:
            score -= 20
        elif avg_latency > 50:
            score -= 10
        
        if packet_loss > 2:
            score -= 15
        elif packet_loss > 1:
            score -= 5
    
    if 'bandwidth' in results:
        download = results['bandwidth']['download']
        
        if download < 50:
            score -= 20
        elif download < 100:
            score -= 10
    
    # Convert score to grade
    if score >= 90:
        return 'A'
    elif score >= 80:
        return 'B'
    elif score >= 70:
        return 'C'
    elif score >= 60:
        return 'D'
    else:
        return 'F'
