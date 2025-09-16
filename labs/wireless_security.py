import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import random
import hashlib
import base64
from datetime import datetime, timedelta
import json

def run_lab():
    """Wireless Security Lab - Học về bảo mật mạng không dây"""
    
    st.title("📡 Wireless Security Lab")
    st.markdown("---")
    
    # Tabs cho các bài thực hành khác nhau
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔍 WiFi Network Discovery", 
        "🔐 WPA/WEP Analysis",
        "📊 Signal Analysis", 
        "🚫 Rogue AP Detection",
        "🛡️ Wireless Security Assessment"
    ])
    
    with tab1:
        wifi_discovery_lab()
    
    with tab2:
        wpa_wep_analysis_lab()
    
    with tab3:
        signal_analysis_lab()
        
    with tab4:
        rogue_ap_detection_lab()
        
    with tab5:
        wireless_security_assessment_lab()

def wifi_discovery_lab():
    """Lab WiFi Network Discovery"""
    st.subheader("🔍 WiFi Network Discovery Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    WiFi Network Discovery là quá trình tìm kiếm và thu thập thông tin
    về các mạng không dây trong khu vực để đánh giá security posture.
    
    **Thông tin thu thập được:**
    - **SSID (Service Set Identifier)**: Tên mạng WiFi
    - **BSSID (Basic Service Set Identifier)**: MAC address của AP
    - **Channel**: Kênh tần số sử dụng
    - **Signal Strength**: Cường độ tín hiệu
    - **Security Type**: Loại bảo mật (Open, WEP, WPA, WPA2, WPA3)
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 📡 Scanning Configuration")
        
        scan_mode = st.selectbox("Scan Mode:", [
            "Passive Scan (Stealth)",
            "Active Scan (Probe Request)",
            "Monitor Mode Scan"
        ])
        
        scan_duration = st.slider("Scan Duration (seconds):", 5, 60, 15)
        
        channel_range = st.selectbox("Channel Range:", [
            "All Channels (1-14)",
            "2.4GHz Only (1-11)", 
            "5GHz Only (36-165)",
            "Custom Range"
        ])
        
        if channel_range == "Custom Range":
            custom_channels = st.text_input("Custom Channels:", value="1,6,11")
        
        if st.button("📡 Start WiFi Scan"):
            with st.spinner(f"Scanning for {scan_duration} seconds..."):
                scan_results = perform_wifi_scan(scan_mode, scan_duration, channel_range)
                st.session_state['wifi_scan_results'] = scan_results
    
    with col2:
        st.markdown("#### 📊 Scan Results")
        
        if 'wifi_scan_results' in st.session_state:
            results = st.session_state['wifi_scan_results']
            
            st.success(f"✅ Found {len(results['networks'])} WiFi networks")
            
            # Create DataFrame for display
            df = pd.DataFrame(results['networks'])
            st.dataframe(df, width='stretch')
            
            # Security type distribution
            if len(results['networks']) > 0:
                security_counts = df['Security'].value_counts()
                fig_pie = px.pie(
                    values=security_counts.values,
                    names=security_counts.index,
                    title="Security Types Distribution"
                )
                st.plotly_chart(fig_pie, width='stretch')
            
            # Signal strength visualization
            if len(results['networks']) > 0:
                fig_signal = px.bar(
                    df, x='SSID', y='Signal (dBm)',
                    title="Signal Strength by Network",
                    color='Security'
                )
                fig_signal.update_xaxis(tickangle=45)
                st.plotly_chart(fig_signal, width='stretch')

def wpa_wep_analysis_lab():
    """Lab WPA/WEP Analysis"""
    st.subheader("🔐 WPA/WEP Analysis Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    WPA/WEP Analysis giúp đánh giá độ bảo mật của các giao thức
    mã hóa WiFi và phát hiện các weaknesses.
    
    **Các giao thức WiFi:**
    - **Open**: Không mã hóa (rất không an toàn)
    - **WEP**: Wired Equivalent Privacy (đã lỗi thời, dễ crack)
    - **WPA**: WiFi Protected Access (cải thiện từ WEP)
    - **WPA2**: WPA version 2 (hiện tại phổ biến)
    - **WPA3**: WPA version 3 (mới nhất, an toàn nhất)
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🎯 Target Network Selection")
        
        # Simulate available networks
        if 'wifi_scan_results' in st.session_state:
            networks = st.session_state['wifi_scan_results']['networks']
            network_options = [f"{net['SSID']} ({net['Security']})" for net in networks]
        else:
            network_options = [
                "TestNetwork (WPA2)",
                "OldRouter (WEP)", 
                "PublicWiFi (Open)",
                "SecureNet (WPA3)"
            ]
        
        selected_network = st.selectbox("Select Target Network:", network_options)
        
        analysis_type = st.selectbox("Analysis Type:", [
            "Security Protocol Analysis",
            "Handshake Capture Simulation",
            "Dictionary Attack Simulation",
            "Vulnerability Assessment"
        ])
        
        if st.button("🔍 Analyze Network"):
            with st.spinner("Analyzing network security..."):
                analysis_results = analyze_network_security(selected_network, analysis_type)
                st.session_state['security_analysis'] = analysis_results
    
    with col2:
        st.markdown("#### 🔒 Security Analysis Results")
        
        if 'security_analysis' in st.session_state:
            results = st.session_state['security_analysis']
            
            # Security score
            score = results['security_score']
            if score >= 80:
                st.success(f"🟢 Security Score: {score}/100 - Strong")
            elif score >= 60:
                st.warning(f"🟡 Security Score: {score}/100 - Moderate")
            else:
                st.error(f"🔴 Security Score: {score}/100 - Weak")
            
            # Protocol details
            st.markdown("**🔐 Protocol Analysis:**")
            protocol_info = results['protocol_info']
            st.info(f"""
            **Protocol:** {protocol_info['type']}
            **Encryption:** {protocol_info['encryption']}
            **Key Length:** {protocol_info['key_length']} bits
            **Authentication:** {protocol_info['auth_method']}
            """)
            
            # Vulnerabilities
            if results['vulnerabilities']:
                st.markdown("**⚠️ Vulnerabilities Found:**")
                for vuln in results['vulnerabilities']:
                    severity_colors = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}
                    st.write(f"{severity_colors.get(vuln['severity'], '⚪')} **{vuln['severity']}**: {vuln['description']}")
            
            # Recommendations
            st.markdown("**💡 Security Recommendations:**")
            for rec in results['recommendations']:
                st.write(f"• {rec}")

def signal_analysis_lab():
    """Lab Signal Analysis"""
    st.subheader("📊 Signal Analysis Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Signal Analysis giúp hiểu về chất lượng tín hiệu WiFi,
    interference và optimization opportunities.
    
    **Metrics quan trọng:**
    - **RSSI (Received Signal Strength Indicator)**: Cường độ tín hiệu nhận được
    - **SNR (Signal-to-Noise Ratio)**: Tỷ lệ tín hiệu/nhiễu
    - **Channel Utilization**: Mức độ sử dụng kênh
    - **Interference**: Nhiễu từ các nguồn khác
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 📡 Signal Monitoring")
        
        monitoring_mode = st.selectbox("Monitoring Mode:", [
            "Real-time Monitoring",
            "Spectrum Analysis",
            "Channel Survey",
            "Interference Detection"
        ])
        
        monitor_duration = st.slider("Monitor Duration (minutes):", 1, 30, 5)
        
        if st.button("📊 Start Signal Monitoring"):
            with st.spinner(f"Monitoring signals for {monitor_duration} minutes..."):
                signal_data = monitor_wifi_signals(monitoring_mode, monitor_duration)
                st.session_state['signal_data'] = signal_data
    
    with col2:
        st.markdown("#### 📈 Signal Analysis Results")
        
        if 'signal_data' in st.session_state:
            data = st.session_state['signal_data']
            
            # Signal strength over time
            if 'rssi_timeline' in data:
                fig_rssi = px.line(
                    x=data['rssi_timeline']['time'],
                    y=data['rssi_timeline']['values'],
                    title="RSSI Over Time",
                    labels={'y': 'RSSI (dBm)', 'x': 'Time'}
                )
                st.plotly_chart(fig_rssi, width='stretch')
            
            # Channel utilization
            if 'channel_utilization' in data:
                fig_channel = px.bar(
                    x=data['channel_utilization']['channels'],
                    y=data['channel_utilization']['utilization'],
                    title="Channel Utilization",
                    labels={'y': 'Utilization (%)', 'x': 'Channel'}
                )
                st.plotly_chart(fig_channel, width='stretch')
            
            # Signal quality metrics
            st.markdown("**📊 Signal Quality Metrics:**")
            metrics = data['quality_metrics']
            
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("Average RSSI", f"{metrics['avg_rssi']:.1f} dBm")
            with col_b:
                st.metric("SNR", f"{metrics['snr']:.1f} dB")
            with col_c:
                st.metric("Signal Quality", f"{metrics['quality']:.0f}%")

def rogue_ap_detection_lab():
    """Lab Rogue AP Detection"""
    st.subheader("🚫 Rogue AP Detection Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Rogue Access Point Detection giúp phát hiện các AP không được ủy quyền
    có thể được sử dụng cho evil twin attacks hoặc unauthorized access.
    
    **Dấu hiệu của Rogue AP:**
    - **Unknown BSSID**: MAC address không có trong whitelist
    - **Suspicious SSID**: Tên mạng giống với mạng hợp pháp
    - **Unusual Signal Pattern**: Tín hiệu bất thường
    - **Security Mismatch**: Cấu hình bảo mật khác thường
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🔍 Rogue AP Detection")
        
        # Authorized networks configuration
        st.markdown("**📋 Authorized Networks:**")
        authorized_networks = st.text_area(
            "Enter authorized SSIDs (one per line):",
            value="CompanyWiFi\nGuestNetwork\nSecureOffice"
        ).split('\n')
        
        detection_method = st.selectbox("Detection Method:", [
            "SSID Comparison",
            "BSSID Whitelist Check",
            "Signal Pattern Analysis",
            "Comprehensive Scan"
        ])
        
        if st.button("🚫 Scan for Rogue APs"):
            with st.spinner("Scanning for rogue access points..."):
                rogue_results = detect_rogue_aps(authorized_networks, detection_method)
                st.session_state['rogue_results'] = rogue_results
    
    with col2:
        st.markdown("#### 🚨 Detection Results")
        
        if 'rogue_results' in st.session_state:
            results = st.session_state['rogue_results']
            
            # Summary
            total_aps = len(results['all_aps'])
            rogue_aps = len(results['rogue_aps'])
            authorized_aps = total_aps - rogue_aps
            
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("Total APs", total_aps)
            with col_b:
                st.metric("Authorized", authorized_aps, delta=None)
            with col_c:
                st.metric("Rogue APs", rogue_aps, delta=None)
            
            # Rogue APs details
            if rogue_aps > 0:
                st.error(f"🚨 {rogue_aps} Rogue Access Point(s) Detected!")
                
                rogue_df = pd.DataFrame(results['rogue_aps'])
                st.dataframe(rogue_df, width='stretch')
                
                # Risk assessment
                st.markdown("**⚠️ Risk Assessment:**")
                for ap in results['rogue_aps']:
                    risk_level = assess_rogue_ap_risk(ap)
                    risk_colors = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}
                    st.write(f"{risk_colors.get(risk_level, '⚪')} **{ap['SSID']}**: {risk_level} Risk")
            else:
                st.success("✅ No rogue access points detected!")
            
            # All APs visualization
            if total_aps > 0:
                all_aps_df = pd.DataFrame(results['all_aps'])
                fig_scatter = px.scatter(
                    all_aps_df, x='Channel', y='Signal (dBm)',
                    color='Status', size='Signal (dBm)',
                    hover_data=['SSID', 'BSSID'],
                    title="Access Points Overview"
                )
                st.plotly_chart(fig_scatter, width='stretch')

def wireless_security_assessment_lab():
    """Lab Wireless Security Assessment"""
    st.subheader("🛡️ Wireless Security Assessment Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Wireless Security Assessment đánh giá toàn diện security posture
    của wireless infrastructure và đưa ra recommendations.
    
    **Assessment Areas:**
    - **Configuration Security**: Cấu hình AP và controller
    - **Encryption Strength**: Độ mạnh của mã hóa
    - **Access Control**: Kiểm soát truy cập
    - **Monitoring & Logging**: Giám sát và ghi log
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🔍 Assessment Configuration")
        
        assessment_scope = st.multiselect("Assessment Scope:", [
            "Network Discovery",
            "Security Protocol Analysis", 
            "Rogue AP Detection",
            "Signal Quality Assessment",
            "Compliance Check"
        ], default=["Network Discovery", "Security Protocol Analysis"])
        
        compliance_standard = st.selectbox("Compliance Standard:", [
            "PCI DSS",
            "ISO 27001",
            "NIST Cybersecurity Framework",
            "Custom Requirements"
        ])
        
        if st.button("🛡️ Run Security Assessment"):
            with st.spinner("Running comprehensive wireless security assessment..."):
                assessment_results = run_wireless_assessment(assessment_scope, compliance_standard)
                st.session_state['assessment_results'] = assessment_results
    
    with col2:
        st.markdown("#### 📊 Assessment Report")
        
        if 'assessment_results' in st.session_state:
            results = st.session_state['assessment_results']
            
            # Overall security score
            overall_score = results['overall_score']
            if overall_score >= 85:
                st.success(f"🟢 Overall Security Score: {overall_score}/100 - Excellent")
            elif overall_score >= 70:
                st.warning(f"🟡 Overall Security Score: {overall_score}/100 - Good")
            elif overall_score >= 50:
                st.warning(f"🟠 Overall Security Score: {overall_score}/100 - Fair")
            else:
                st.error(f"🔴 Overall Security Score: {overall_score}/100 - Poor")
            
            # Category scores
            st.markdown("**📊 Category Scores:**")
            categories = results['category_scores']
            
            fig_radar = go.Figure()
            fig_radar.add_trace(go.Scatterpolar(
                r=list(categories.values()),
                theta=list(categories.keys()),
                fill='toself',
                name='Security Scores'
            ))
            fig_radar.update_layout(
                polar=dict(
                    radialaxis=dict(visible=True, range=[0, 100])
                ),
                title="Security Assessment Radar Chart"
            )
            st.plotly_chart(fig_radar, width='stretch')
            
            # Findings summary
            st.markdown("**🔍 Key Findings:**")
            for finding in results['key_findings']:
                severity_colors = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢', 'Info': '🔵'}
                st.write(f"{severity_colors.get(finding['severity'], '⚪')} **{finding['severity']}**: {finding['description']}")
            
            # Compliance status
            st.markdown(f"**📋 {compliance_standard} Compliance:**")
            compliance_score = results['compliance_score']
            if compliance_score >= 90:
                st.success(f"✅ Compliant ({compliance_score}%)")
            else:
                st.error(f"❌ Non-Compliant ({compliance_score}%)")
            
            # Action items
            st.markdown("**🎯 Priority Action Items:**")
            for i, action in enumerate(results['action_items'][:5], 1):
                st.write(f"{i}. {action}")

# Helper Functions
def perform_wifi_scan(scan_mode, duration, channel_range):
    """Simulate WiFi network scanning"""
    
    # Generate sample WiFi networks
    sample_networks = [
        {"SSID": "HomeNetwork", "BSSID": "AA:BB:CC:DD:EE:01", "Channel": 6, "Signal (dBm)": -45, "Security": "WPA2"},
        {"SSID": "OfficeWiFi", "BSSID": "AA:BB:CC:DD:EE:02", "Channel": 11, "Signal (dBm)": -52, "Security": "WPA3"},
        {"SSID": "GuestNetwork", "BSSID": "AA:BB:CC:DD:EE:03", "Channel": 1, "Signal (dBm)": -38, "Security": "WPA2"},
        {"SSID": "PublicHotspot", "BSSID": "AA:BB:CC:DD:EE:04", "Channel": 6, "Signal (dBm)": -65, "Security": "Open"},
        {"SSID": "OldRouter", "BSSID": "AA:BB:CC:DD:EE:05", "Channel": 3, "Signal (dBm)": -72, "Security": "WEP"},
        {"SSID": "SecureCorpNet", "BSSID": "AA:BB:CC:DD:EE:06", "Channel": 36, "Signal (dBm)": -48, "Security": "WPA2-Enterprise"},
        {"SSID": "NeighborWiFi", "BSSID": "AA:BB:CC:DD:EE:07", "Channel": 9, "Signal (dBm)": -78, "Security": "WPA2"},
    ]
    
    # Simulate scan results based on parameters
    detected_networks = random.sample(sample_networks, random.randint(3, len(sample_networks)))
    
    # Add some randomization to signal strength
    for network in detected_networks:
        network["Signal (dBm)"] += random.randint(-10, 10)
    
    return {
        "networks": detected_networks,
        "scan_mode": scan_mode,
        "duration": duration,
        "timestamp": datetime.now().isoformat()
    }

def analyze_network_security(network_info, analysis_type):
    """Analyze security of selected network"""
    
    # Extract security type from network info
    security_type = network_info.split('(')[-1].rstrip(')')
    
    # Security scoring based on protocol
    security_scores = {
        'Open': 0,
        'WEP': 20,
        'WPA': 60,
        'WPA2': 80,
        'WPA3': 95,
        'WPA2-Enterprise': 90
    }
    
    base_score = security_scores.get(security_type, 50)
    
    # Protocol information
    protocol_info = {
        'Open': {'type': 'None', 'encryption': 'None', 'key_length': 0, 'auth_method': 'None'},
        'WEP': {'type': 'WEP', 'encryption': 'RC4', 'key_length': 64, 'auth_method': 'Shared Key'},
        'WPA': {'type': 'WPA', 'encryption': 'TKIP', 'key_length': 128, 'auth_method': 'PSK'},
        'WPA2': {'type': 'WPA2', 'encryption': 'AES-CCMP', 'key_length': 256, 'auth_method': 'PSK'},
        'WPA3': {'type': 'WPA3', 'encryption': 'AES-GCMP', 'key_length': 256, 'auth_method': 'SAE'},
        'WPA2-Enterprise': {'type': 'WPA2', 'encryption': 'AES-CCMP', 'key_length': 256, 'auth_method': '802.1X'}
    }
    
    # Vulnerabilities based on security type
    vulnerabilities = []
    recommendations = []
    
    if security_type == 'Open':
        vulnerabilities = [
            {'severity': 'Critical', 'description': 'No encryption - all traffic visible'},
            {'severity': 'High', 'description': 'No authentication required'},
            {'severity': 'High', 'description': 'Susceptible to man-in-the-middle attacks'}
        ]
        recommendations = [
            'Implement WPA3 or WPA2 encryption',
            'Use strong pre-shared key or enterprise authentication',
            'Enable MAC address filtering as additional layer'
        ]
    elif security_type == 'WEP':
        vulnerabilities = [
            {'severity': 'Critical', 'description': 'WEP encryption easily crackable'},
            {'severity': 'High', 'description': 'Weak IV (Initialization Vector) implementation'},
            {'severity': 'Medium', 'description': 'No forward secrecy'}
        ]
        recommendations = [
            'Upgrade to WPA2 or WPA3 immediately',
            'Use strong authentication methods',
            'Implement network segmentation'
        ]
    elif security_type == 'WPA':
        vulnerabilities = [
            {'severity': 'Medium', 'description': 'TKIP encryption has known weaknesses'},
            {'severity': 'Low', 'description': 'Susceptible to dictionary attacks with weak passwords'}
        ]
        recommendations = [
            'Upgrade to WPA2 with AES encryption',
            'Use strong, complex passwords',
            'Enable WPS protection'
        ]
    elif security_type in ['WPA2', 'WPA2-Enterprise']:
        vulnerabilities = [
            {'severity': 'Low', 'description': 'Potential KRACK vulnerability if not patched'}
        ]
        recommendations = [
            'Ensure all devices are patched against KRACK',
            'Consider upgrading to WPA3 when available',
            'Use strong passwords or certificates'
        ]
    elif security_type == 'WPA3':
        recommendations = [
            'Excellent security choice',
            'Ensure all client devices support WPA3',
            'Monitor for future security updates'
        ]
    
    return {
        'security_score': base_score,
        'protocol_info': protocol_info.get(security_type, {}),
        'vulnerabilities': vulnerabilities,
        'recommendations': recommendations,
        'analysis_type': analysis_type
    }

def monitor_wifi_signals(mode, duration):
    """Simulate WiFi signal monitoring"""
    
    # Generate RSSI timeline
    time_points = [datetime.now() - timedelta(minutes=i) for i in range(duration, 0, -1)]
    rssi_values = [-50 + random.randint(-20, 20) for _ in range(duration)]
    
    # Generate channel utilization data
    channels = list(range(1, 12)) + [36, 40, 44, 48]
    utilization = [random.randint(10, 90) for _ in channels]
    
    # Calculate quality metrics
    avg_rssi = sum(rssi_values) / len(rssi_values)
    snr = random.uniform(20, 40)
    quality = max(0, min(100, (avg_rssi + 100) * 2))
    
    return {
        'rssi_timeline': {'time': time_points, 'values': rssi_values},
        'channel_utilization': {'channels': channels, 'utilization': utilization},
        'quality_metrics': {
            'avg_rssi': avg_rssi,
            'snr': snr,
            'quality': quality
        },
        'mode': mode,
        'duration': duration
    }

def detect_rogue_aps(authorized_networks, detection_method):
    """Simulate rogue AP detection"""
    
    # Generate all detected APs
    all_aps = [
        {"SSID": "CompanyWiFi", "BSSID": "AA:BB:CC:DD:EE:01", "Channel": 6, "Signal (dBm)": -45, "Security": "WPA2", "Status": "Authorized"},
        {"SSID": "GuestNetwork", "BSSID": "AA:BB:CC:DD:EE:02", "Channel": 11, "Signal (dBm)": -52, "Security": "WPA2", "Status": "Authorized"},
        {"SSID": "CompanyWiFi", "BSSID": "BB:CC:DD:EE:FF:01", "Channel": 6, "Signal (dBm)": -48, "Security": "Open", "Status": "Rogue"},
        {"SSID": "FreeWiFi", "BSSID": "CC:DD:EE:FF:AA:01", "Channel": 1, "Signal (dBm)": -65, "Security": "Open", "Status": "Rogue"},
        {"SSID": "SecureOffice", "BSSID": "AA:BB:CC:DD:EE:03", "Channel": 36, "Signal (dBm)": -38, "Security": "WPA3", "Status": "Authorized"},
    ]
    
    # Identify rogue APs
    rogue_aps = [ap for ap in all_aps if ap["Status"] == "Rogue"]
    
    return {
        'all_aps': all_aps,
        'rogue_aps': rogue_aps,
        'authorized_networks': authorized_networks,
        'detection_method': detection_method
    }

def assess_rogue_ap_risk(ap):
    """Assess risk level of rogue AP"""
    risk_score = 0
    
    # Security type risk
    if ap['Security'] == 'Open':
        risk_score += 30
    elif ap['Security'] == 'WEP':
        risk_score += 20
    
    # Signal strength risk (stronger signal = higher risk)
    if ap['Signal (dBm)'] > -50:
        risk_score += 25
    elif ap['Signal (dBm)'] > -70:
        risk_score += 15
    
    # SSID similarity risk
    if 'WiFi' in ap['SSID'] or 'Free' in ap['SSID']:
        risk_score += 20
    
    # Channel conflict risk
    common_channels = [1, 6, 11]
    if ap['Channel'] in common_channels:
        risk_score += 10
    
    if risk_score >= 50:
        return 'High'
    elif risk_score >= 30:
        return 'Medium'
    else:
        return 'Low'

def run_wireless_assessment(scope, compliance_standard):
    """Run comprehensive wireless security assessment"""
    
    # Category scores
    category_scores = {
        'Network Discovery': random.randint(70, 95),
        'Protocol Security': random.randint(60, 90),
        'Access Control': random.randint(65, 85),
        'Monitoring': random.randint(50, 80),
        'Configuration': random.randint(70, 90)
    }
    
    # Calculate overall score
    overall_score = sum(category_scores.values()) // len(category_scores)
    
    # Generate findings
    key_findings = [
        {'severity': 'High', 'description': 'WEP encryption detected on legacy access point'},
        {'severity': 'Medium', 'description': 'Guest network lacks proper isolation'},
        {'severity': 'Low', 'description': 'Some access points using default SNMP community strings'},
        {'severity': 'Info', 'description': 'WPA3 available but not fully deployed'}
    ]
    
    # Compliance score
    compliance_score = random.randint(75, 95)
    
    # Action items
    action_items = [
        'Upgrade all WEP-enabled devices to WPA2/WPA3',
        'Implement proper guest network segmentation',
        'Change default SNMP community strings',
        'Deploy WPA3 across all compatible devices',
        'Implement wireless intrusion detection system'
    ]
    
    return {
        'overall_score': overall_score,
        'category_scores': category_scores,
        'key_findings': key_findings,
        'compliance_score': compliance_score,
        'compliance_standard': compliance_standard,
        'action_items': action_items,
        'assessment_scope': scope
    }
