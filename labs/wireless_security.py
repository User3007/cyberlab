import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import random
import hashlib
import base64
import binascii
import hmac
import struct
import socket
from datetime import datetime, timedelta
import json
import re
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import numpy as np
import concurrent.futures
import asyncio

def create_lab_header(title: str, icon: str, gradient: str = "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"):
    """Create compact lab header"""
    return f"""
    <div style="background: {gradient}; 
                padding: 0.8rem; border-radius: 6px; margin-bottom: 1rem;">
        <h3 style="color: white; margin: 0; font-size: 1.2rem;">{icon} {title}</h3>
    </div>
    """

def run_lab():
    """Wireless Security Lab - Master WiFi Security & Attack Techniques"""
    
    # Compact Header
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 1rem; border-radius: 8px; margin-bottom: 1rem; text-align: center;">
        <h2 style="color: white; margin: 0; font-size: 1.5rem;">
            📡 Wireless Security Lab
        </h2>
        <p style="color: white; margin: 0; font-size: 0.9rem; opacity: 0.9;">
            WiFi Hacking, Defense & Forensics
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced tabs with more labs
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10 = st.tabs([
        "🔍 WiFi Discovery",
        "🔐 WPA/WEP Cracking",
        "📊 Signal Analysis",
        "🚫 Rogue AP Detection",
        "🎯 Evil Twin Attack",
        "🔑 WPS Attack",
        "📡 Deauth Attack",
        "🕵️ WiFi Forensics",
        "🛡️ Defense Strategies",
        "📊 Security Assessment"
    ])
    
    with tab1:
        wifi_discovery_lab()
    
    with tab2:
        wpa_wep_cracking_lab()
    
    with tab3:
        signal_analysis_lab()
        
    with tab4:
        rogue_ap_detection_lab()
        
    with tab5:
        evil_twin_attack_lab()
        
    with tab6:
        wps_attack_lab()
        
    with tab7:
        deauth_attack_lab()
        
    with tab8:
        wifi_forensics_lab()
        
    with tab9:
        defense_strategies_lab()
        
    with tab10:
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

def wpa_wep_cracking_lab():
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

# New advanced wireless security labs
def evil_twin_attack_lab():
    """Lab for Evil Twin Attack simulation"""
    
    st.markdown(create_lab_header("Evil Twin Attack Lab", "🎯", "linear-gradient(90deg, #ff6a00 0%, #ee0979 100%)"), unsafe_allow_html=True)
    
    # Warning message
    st.error("""
    ⚠️ **CRITICAL WARNING**: Evil Twin attacks are illegal without explicit permission.
    This lab is for educational purposes only in controlled environments.
    """)
    
    # Theory section with diagrams
    with st.expander("📚 **Evil Twin Attack Theory**", expanded=False):
        st.markdown("""
        ### 🎭 **How Evil Twin Works**
        
        ```
        Attack Flow:
        ┌──────────┐     Deauth     ┌──────────┐
        │ Victim   │ <-------------- │ Attacker │
        └──────────┘                 └──────────┘
             │                            │
             │   Connect to Fake AP       │
             └──────────────────────────>│
             │                            │
             │   Enter Credentials        │
             └──────────────────────────>│
                                          │
                              Harvest Credentials
        ```
        
        ### 🛠️ **Attack Components**
        
        | Component | Purpose | Tools |
        |-----------|---------|-------|
        | **Deauth Attack** | Force disconnection | aireplay-ng |
        | **Fake AP** | Impersonate legitimate AP | hostapd |
        | **Captive Portal** | Credential harvesting | Apache/nginx |
        | **DNS Server** | Redirect all traffic | dnsmasq |
        
        ### 📡 **Attack Stages**
        
        1. **Reconnaissance**: Identify target network
        2. **Deauthentication**: Disconnect legitimate users
        3. **AP Cloning**: Create identical fake AP
        4. **Portal Setup**: Deploy phishing page
        5. **Credential Harvest**: Capture passwords
        """)
    
    # Attack configuration
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### ⚙️ **Attack Configuration**")
        
        target_ssid = st.text_input("🎯 Target SSID:", value="CompanyWiFi")
        target_bssid = st.text_input("📡 Target BSSID:", value="AA:BB:CC:DD:EE:FF")
        
        attack_mode = st.selectbox("🎭 Attack Mode:", [
            "Basic Evil Twin",
            "WPA2 Enterprise Evil Twin",
            "Captive Portal with SSL",
            "Advanced KARMA Attack"
        ])
        
        portal_template = st.selectbox("📄 Portal Template:", [
            "Generic WiFi Login",
            "Corporate Portal",
            "Hotel WiFi",
            "Airport WiFi",
            "Coffee Shop",
            "Custom HTML"
        ])
        
        if st.button("🚀 **Launch Evil Twin**", type="primary"):
            st.error("⛔ This is a simulation only - no actual attack performed")
            results = simulate_evil_twin(target_ssid, attack_mode, portal_template)
            st.session_state['evil_twin_results'] = results
    
    with col2:
        st.markdown("#### 📊 **Attack Results**")
        
        if 'evil_twin_results' in st.session_state:
            results = st.session_state['evil_twin_results']
            
            # Attack metrics
            col_a, col_b = st.columns(2)
            with col_a:
                st.metric("👥 Victims Connected", results['victims_connected'])
            with col_b:
                st.metric("🔑 Credentials Captured", results['credentials_captured'])
            
            # Captured credentials (simulated)
            st.markdown("**📋 Captured Credentials (Simulated):**")
            creds_df = pd.DataFrame(results['credentials'])
            st.dataframe(creds_df, use_container_width=True)
            
            # Detection indicators
            with st.expander("🔍 **Detection Indicators**"):
                st.markdown("""
                **Signs of Evil Twin Attack:**
                - 🔴 Duplicate SSIDs with different BSSIDs
                - 🟡 Sudden disconnections
                - 🟠 Certificate warnings
                - 🔵 Unusual captive portal
                - 🟣 Signal strength anomalies
                """)

def wps_attack_lab():
    """Lab for WPS Attack techniques"""
    
    st.markdown(create_lab_header("WPS Attack Lab", "🔑", "linear-gradient(90deg, #4facfe 0%, #00f2fe 100%)"), unsafe_allow_html=True)
    
    # WPS Theory
    with st.expander("📚 **WPS Vulnerability Theory**"):
        st.markdown("""
        ### 🔓 **WPS PIN Structure**
        
        ```
        8-digit PIN: XXXX XXXX
                     ↓     ↓
                   Part1  Part2
                   
        Total combinations: 10^8 = 100,000,000
        BUT... with vulnerability:
        Part1: 10^4 = 10,000 attempts
        Part2: 10^3 = 1,000 attempts
        Total: 11,000 attempts (max)
        ```
        
        ### 🎯 **Attack Methods**
        
        | Attack | Description | Time | Success Rate |
        |--------|-------------|------|--------------|
        | **Online Brute Force** | Try all PINs | 4-10 hours | High |
        | **Pixie Dust** | Exploit weak RNG | < 1 minute | Medium |
        | **Offline Attack** | Capture & crack | Variable | High |
        | **NULL PIN** | Some routers accept empty PIN | Instant | Low |
        """)
    
    # WPS Attack Interface
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🎯 **Target Selection**")
        
        # Scan for WPS-enabled APs
        if st.button("📡 Scan for WPS Networks"):
            wps_networks = scan_wps_networks()
            st.session_state['wps_networks'] = wps_networks
        
        if 'wps_networks' in st.session_state:
            wps_df = pd.DataFrame(st.session_state['wps_networks'])
            selected_network = st.selectbox(
                "Select Target:",
                wps_df['SSID'].tolist() if not wps_df.empty else []
            )
            
            attack_method = st.selectbox("🔨 Attack Method:", [
                "Reaver (Online Brute Force)",
                "Pixie Dust Attack",
                "Bully Attack",
                "Custom PIN List"
            ])
            
            if attack_method == "Custom PIN List":
                custom_pins = st.text_area(
                    "Enter PIN list:",
                    value="12345670\n00000000\n11111111"
                )
            
            if st.button("⚡ **Start WPS Attack**"):
                attack_results = simulate_wps_attack(selected_network, attack_method)
                st.session_state['wps_attack_results'] = attack_results
    
    with col2:
        st.markdown("#### 📊 **Attack Progress**")
        
        if 'wps_attack_results' in st.session_state:
            results = st.session_state['wps_attack_results']
            
            # Progress bar
            progress = results['progress']
            st.progress(progress / 100)
            st.metric("📌 PINs Tested", f"{results['pins_tested']}/11000")
            
            if results['cracked']:
                st.success(f"✅ **WPS PIN Found:** {results['pin']}")
                st.success(f"🔑 **PSK:** {results['psk']}")
            else:
                st.warning("⏳ Attack in progress...")
            
            # Attack log
            st.markdown("**📝 Attack Log:**")
            st.code(results['log'], language="text")

def deauth_attack_lab():
    """Lab for Deauthentication Attack"""
    
    st.markdown(create_lab_header("Deauthentication Attack Lab", "📡", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Deauth Theory
    with st.expander("📚 **802.11 Deauthentication Theory**"):
        st.markdown("""
        ### 📡 **802.11 Management Frames**
        
        ```
        Deauth Frame Structure:
        ┌────────────┬────────────┬────────────┬────────────┐
        │ Frame Ctrl │ Duration   │ Dest Addr  │ Src Addr   │
        │ (2 bytes)  │ (2 bytes)  │ (6 bytes)  │ (6 bytes)  │
        ├────────────┼────────────┼────────────┴────────────┤
        │ BSSID      │ Seq Ctrl   │ Reason Code              │
        │ (6 bytes)  │ (2 bytes)  │ (2 bytes)                │
        └────────────┴────────────┴──────────────────────────┘
        ```
        
        ### 🔴 **Reason Codes**
        
        | Code | Description | Use Case |
        |------|-------------|----------|
        | 1 | Unspecified reason | Generic disconnect |
        | 2 | Previous auth invalid | Force reauth |
        | 3 | Station leaving | Clean disconnect |
        | 4 | Inactivity | Timeout simulation |
        | 6 | Class 2 frame error | Protocol violation |
        | 7 | Class 3 frame error | Association required |
        """)
    
    # Deauth Attack Interface
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### ⚙️ **Attack Parameters**")
        
        target_ap = st.text_input("🎯 Target AP MAC:", value="AA:BB:CC:DD:EE:FF")
        target_client = st.text_input("👤 Target Client MAC:", value="11:22:33:44:55:66")
        
        attack_type = st.radio("🎭 Attack Type:", [
            "Targeted (Single Client)",
            "Broadcast (All Clients)",
            "AP Impersonation"
        ])
        
        reason_code = st.selectbox("📝 Reason Code:", [
            "1 - Unspecified",
            "2 - Previous Auth Invalid",
            "3 - Station Leaving",
            "4 - Inactivity",
            "6 - Class 2 Frame Error",
            "7 - Class 3 Frame Error"
        ])
        
        packet_count = st.slider("📦 Packets to Send:", 1, 1000, 100)
        
        if st.button("💥 **Send Deauth Packets**"):
            results = simulate_deauth_attack(
                target_ap, target_client, attack_type, 
                int(reason_code.split(' ')[0]), packet_count
            )
            st.session_state['deauth_results'] = results
    
    with col2:
        st.markdown("#### 📊 **Attack Results**")
        
        if 'deauth_results' in st.session_state:
            results = st.session_state['deauth_results']
            
            # Attack statistics
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("📤 Packets Sent", results['packets_sent'])
            with col_b:
                st.metric("✅ Success Rate", f"{results['success_rate']}%")
            with col_c:
                st.metric("⏱️ Duration", f"{results['duration']}s")
            
            # Packet hexdump
            st.markdown("**🔍 Sample Deauth Frame (Hex):**")
            st.code(results['packet_hex'], language="text")
            
            # Defense recommendations
            with st.expander("🛡️ **Defense Against Deauth**"):
                st.markdown("""
                **Protection Methods:**
                - ✅ **802.11w (PMF)**: Management Frame Protection
                - 🔐 **WPA3**: Includes PMF by default
                - 📡 **Channel Monitoring**: Detect anomalies
                - 🚫 **MAC Filtering**: Limited effectiveness
                - 📊 **IDS/IPS**: Detect attack patterns
                """)

def wifi_forensics_lab():
    """Lab for WiFi Forensics and Analysis"""
    
    st.markdown(create_lab_header("WiFi Forensics Lab", "🕵️", "linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%)"), unsafe_allow_html=True)
    
    tabs = st.tabs(["📦 Packet Analysis", "🔑 Handshake Capture", "📊 Traffic Patterns", "🗺️ Device Tracking"])
    
    with tabs[0]:
        st.markdown("#### 📦 **PCAP Analysis**")
        
        # File upload simulation
        st.markdown("**📁 Upload PCAP File:**")
        uploaded_file = st.file_uploader("Choose PCAP file", type=['pcap', 'pcapng', 'cap'])
        
        if uploaded_file or st.button("📊 Use Sample PCAP"):
            # Analyze PCAP
            pcap_analysis = analyze_pcap_file(uploaded_file)
            
            # Display statistics
            st.markdown("**📊 Capture Statistics:**")
            stats_df = pd.DataFrame([pcap_analysis['stats']])
            st.dataframe(stats_df, use_container_width=True)
            
            # Protocol distribution
            fig = px.pie(
                values=list(pcap_analysis['protocols'].values()),
                names=list(pcap_analysis['protocols'].keys()),
                title="Protocol Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Suspicious activities
            if pcap_analysis['suspicious']:
                st.warning("⚠️ **Suspicious Activities Detected:**")
                for activity in pcap_analysis['suspicious']:
                    st.write(f"- {activity}")
    
    with tabs[1]:
        st.markdown("#### 🔑 **WPA Handshake Analysis**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🎯 Handshake Components:**")
            
            handshake_parts = {
                "EAPOL 1": st.checkbox("Message 1 (ANonce)", value=True),
                "EAPOL 2": st.checkbox("Message 2 (SNonce + MIC)", value=True),
                "EAPOL 3": st.checkbox("Message 3 (GTK)", value=False),
                "EAPOL 4": st.checkbox("Message 4 (Confirmation)", value=False)
            }
            
            if st.button("🔍 Analyze Handshake"):
                analysis = analyze_handshake(handshake_parts)
                st.session_state['handshake_analysis'] = analysis
        
        with col2:
            if 'handshake_analysis' in st.session_state:
                analysis = st.session_state['handshake_analysis']
                
                st.markdown("**📊 Handshake Quality:**")
                quality_score = analysis['quality']
                st.progress(quality_score / 100)
                
                if quality_score >= 75:
                    st.success("✅ Valid handshake captured!")
                    st.info(f"**PMK:** {analysis['pmk'][:16]}...")
                    st.info(f"**PTK:** {analysis['ptk'][:16]}...")
                else:
                    st.error("❌ Incomplete handshake")

def defense_strategies_lab():
    """Lab for WiFi Defense Strategies"""
    
    st.markdown(create_lab_header("WiFi Defense Strategies Lab", "🛡️"), unsafe_allow_html=True)
    
    # Defense categories
    defense_categories = {
        "🔐 Encryption": ["WPA3", "802.11w PMF", "VPN over WiFi", "Certificate-based Auth"],
        "📡 Network Design": ["VLAN Segmentation", "Guest Isolation", "Hidden SSID", "MAC Filtering"],
        "📊 Monitoring": ["WIDS/WIPS", "Rogue AP Detection", "Anomaly Detection", "Log Analysis"],
        "⚙️ Configuration": ["Strong PSK", "Disable WPS", "Regular Updates", "Secure Management"]
    }
    
    st.markdown("### 🎯 **Security Hardening Checklist**")
    
    total_items = sum(len(items) for items in defense_categories.values())
    checked_items = 0
    
    for category, items in defense_categories.items():
        st.markdown(f"#### {category}")
        cols = st.columns(2)
        for i, item in enumerate(items):
            with cols[i % 2]:
                if st.checkbox(item, key=f"defense_{item}"):
                    checked_items += 1
    
    # Security score
    security_score = (checked_items / total_items) * 100
    
    st.markdown("---")
    st.markdown("### 📊 **Security Posture Score**")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🔒 Security Score", f"{security_score:.0f}%")
    with col2:
        st.metric("✅ Implemented", f"{checked_items}/{total_items}")
    with col3:
        if security_score >= 80:
            st.success("🟢 Excellent")
        elif security_score >= 60:
            st.warning("🟡 Good")
        else:
            st.error("🔴 Needs Improvement")
    
    # Generate security report
    if st.button("📄 **Generate Security Report**"):
        report = generate_security_report(checked_items, total_items, security_score)
        st.markdown("### 📋 **WiFi Security Assessment Report**")
        st.code(report, language="markdown")

# Helper functions for new labs
def simulate_evil_twin(ssid: str, mode: str, template: str) -> Dict:
    """Simulate Evil Twin attack results"""
    return {
        'victims_connected': random.randint(5, 20),
        'credentials_captured': random.randint(2, 10),
        'credentials': [
            {'Time': f"00:{i:02d}:00", 'Username': f"user{i}", 'Password': "***hidden***", 'IP': f"192.168.1.{100+i}"}
            for i in range(random.randint(2, 5))
        ],
        'attack_duration': random.randint(10, 60)
    }

def scan_wps_networks() -> List[Dict]:
    """Scan for WPS-enabled networks"""
    networks = []
    ssids = ["HomeRouter", "NETGEAR_5G", "Linksys_2.4G", "TP-LINK_Guest", "D-Link_Office"]
    
    for ssid in random.sample(ssids, random.randint(2, 5)):
        networks.append({
            'SSID': ssid,
            'BSSID': f"{random.randint(0,255):02X}:{random.randint(0,255):02X}:{random.randint(0,255):02X}:{random.randint(0,255):02X}:{random.randint(0,255):02X}:{random.randint(0,255):02X}",
            'Channel': random.randint(1, 11),
            'WPS': 'Enabled',
            'WPS_Version': f"2.{random.randint(0, 1)}",
            'Locked': random.choice(['No', 'Yes']) if random.random() > 0.7 else 'No'
        })
    
    return networks

def simulate_wps_attack(network: str, method: str) -> Dict:
    """Simulate WPS attack"""
    pins_tested = random.randint(100, 5000)
    progress = min(100, (pins_tested / 11000) * 100)
    cracked = random.random() > 0.3
    
    log = f"""
[+] Starting WPS attack on {network}
[+] Attack method: {method}
[+] WPS PIN attack started
[*] Trying PIN: 12345670
[*] Trying PIN: 00000000
[*] Trying PIN: 11111111
[*] Trying PIN: 87654321
[*] Progress: {pins_tested}/11000 PINs tested
    """.strip()
    
    if cracked:
        pin = f"{random.randint(10000000, 99999999)}"
        psk = hashlib.md5(f"{network}{pin}".encode()).hexdigest()[:16]
        log += f"\n[+] WPS PIN found: {pin}\n[+] PSK: {psk}"
    
    return {
        'progress': progress,
        'pins_tested': pins_tested,
        'cracked': cracked,
        'pin': f"{random.randint(10000000, 99999999)}" if cracked else None,
        'psk': hashlib.md5(f"{network}".encode()).hexdigest()[:16] if cracked else None,
        'log': log
    }

def simulate_deauth_attack(ap: str, client: str, attack_type: str, reason: int, count: int) -> Dict:
    """Simulate deauthentication attack"""
    
    # Generate sample deauth frame hex
    packet_hex = f"""
0000   c0 00 3a 01 {client.replace(':', ' ')}
0010   {ap.replace(':', ' ')} {ap.replace(':', ' ')}
0020   00 00 {reason:02x} 00
    """.strip()
    
    return {
        'packets_sent': count,
        'success_rate': random.randint(85, 100),
        'duration': count * 0.01,
        'packet_hex': packet_hex,
        'clients_affected': random.randint(1, 10) if attack_type == "Broadcast (All Clients)" else 1
    }

def analyze_pcap_file(file) -> Dict:
    """Analyze PCAP file for forensics"""
    return {
        'stats': {
            'Total Packets': random.randint(1000, 50000),
            'Duration': f"{random.randint(1, 60)} minutes",
            'Unique MACs': random.randint(10, 100),
            'Unique SSIDs': random.randint(5, 20)
        },
        'protocols': {
            'Management': random.randint(100, 1000),
            'Control': random.randint(50, 500),
            'Data': random.randint(500, 10000),
            'Encrypted': random.randint(300, 5000)
        },
        'suspicious': [
            "Deauthentication flood detected",
            "Possible Evil Twin (duplicate SSID)",
            "WPS brute force attempt",
            "Unusual beacon interval"
        ] if random.random() > 0.5 else []
    }

def analyze_handshake(parts: Dict) -> Dict:
    """Analyze WPA handshake"""
    complete = sum(1 for v in parts.values() if v)
    quality = (complete / 4) * 100
    
    return {
        'quality': quality,
        'complete': complete == 4,
        'pmk': hashlib.sha256(b"pairwise_master_key").hexdigest(),
        'ptk': hashlib.sha256(b"pairwise_transient_key").hexdigest(),
        'messages_captured': complete
    }

def generate_security_report(implemented: int, total: int, score: float) -> str:
    """Generate WiFi security report"""
    grade = 'A' if score >= 90 else 'B' if score >= 80 else 'C' if score >= 70 else 'D' if score >= 60 else 'F'
    
    return f"""
# WiFi Security Assessment Report

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Overall Score:** {score:.1f}%
**Grade:** {grade}

## Security Metrics
- Controls Implemented: {implemented}/{total}
- Critical Findings: {random.randint(0, 3)}
- Medium Findings: {random.randint(2, 5)}
- Low Findings: {random.randint(3, 8)}

## Recommendations
1. Upgrade to WPA3 for enhanced security
2. Implement 802.11w for management frame protection
3. Deploy wireless IDS/IPS system
4. Regular security audits and updates
5. Employee security awareness training

## Compliance Status
- PCI DSS: {'Compliant' if score >= 80 else 'Non-Compliant'}
- ISO 27001: {'Compliant' if score >= 75 else 'Partial'}
- NIST: {'Compliant' if score >= 70 else 'Non-Compliant'}
    """.strip()
