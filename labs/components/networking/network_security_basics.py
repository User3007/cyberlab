import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_network_security_basics():
    """Network Security Basics using TDD pattern"""
    
    st.markdown("## Network Security Basics")
    st.markdown("**Definition:** Fundamental security measures and technologies designed to protect network infrastructure, data in transit, and network resources from unauthorized access, attacks, and threats.")
    
    st.markdown("---")
    
    # Security Threats Overview
    st.markdown("### Common Network Security Threats")
    
    threats_data = {
        "Threat Type": ["Eavesdropping", "Man-in-the-Middle", "DDoS", "Port Scanning", "Packet Sniffing"],
        "Description": [
            "Intercepting and reading network communications",
            "Attacker positions between two communicating parties",
            "Overwhelming network/service with traffic",
            "Probing network for open ports and services",
            "Capturing and analyzing network packets"
        ],
        "Impact": [
            "Data theft, credential compromise",
            "Data manipulation, credential theft",
            "Service unavailability, resource exhaustion",
            "Network reconnaissance, vulnerability discovery",
            "Sensitive information exposure"
        ],
        "Prevention": [
            "Encryption (TLS/SSL), secure protocols",
            "Certificate validation, secure channels",
            "Rate limiting, traffic filtering, CDN",
            "Firewall rules, port security, monitoring",
            "Network segmentation, encryption"
        ],
        "Detection": [
            "Traffic analysis, anomaly detection",
            "Certificate monitoring, traffic inspection",
            "Traffic volume monitoring, rate analysis",
            "IDS/IPS alerts, log analysis",
            "Network monitoring, traffic baselines"
        ]
    }
    
    df = pd.DataFrame(threats_data)
    st.dataframe(df, use_container_width=True)
    
    # Security Controls Visualization
    st.markdown("### Network Security Controls Effectiveness")
    
    # Create security controls effectiveness chart
    controls = ['Firewall', 'IDS/IPS', 'VPN', 'Network Segmentation', 'Access Control']
    threat_types = ['External Attacks', 'Insider Threats', 'Malware', 'Data Breach', 'DoS Attacks']
    
    # Effectiveness scores (0-10)
    effectiveness = {
        'Firewall': [9, 4, 6, 5, 7],
        'IDS/IPS': [8, 7, 8, 6, 8],
        'VPN': [6, 3, 4, 9, 3],
        'Network Segmentation': [7, 8, 7, 8, 6],
        'Access Control': [8, 9, 5, 7, 5]
    }
    
    fig = go.Figure()
    
    for control in controls:
        fig.add_trace(go.Scatterpolar(
            r=effectiveness[control],
            theta=threat_types,
            fill='toself',
            name=control
        ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 10]
            )
        ),
        title="Security Controls Effectiveness Against Threats",
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Firewall Types and Rules
    st.markdown("### Firewall Types and Configuration")
    
    firewall_data = {
        "Firewall Type": ["Packet Filter", "Stateful Inspection", "Application Layer", "Next-Gen Firewall"],
        "OSI Layer": ["Layer 3-4", "Layer 3-4", "Layer 7", "Layer 3-7"],
        "Inspection Method": [
            "Header information only",
            "Connection state tracking",
            "Application protocol analysis",
            "Deep packet inspection + threat intelligence"
        ],
        "Advantages": [
            "Fast, low overhead, simple rules",
            "Connection awareness, better security",
            "Application-specific control, content filtering",
            "Comprehensive security, threat prevention"
        ],
        "Disadvantages": [
            "No connection state, limited security",
            "Resource intensive, complex state table",
            "High latency, resource intensive",
            "Complex configuration, expensive"
        ],
        "Use Cases": [
            "Basic filtering, high-speed networks",
            "Most enterprise networks, VPN termination",
            "Web filtering, email security",
            "Advanced threat protection, compliance"
        ]
    }
    
    df2 = pd.DataFrame(firewall_data)
    st.dataframe(df2, use_container_width=True)
    
    # VPN Technologies
    st.markdown("### VPN Technologies Comparison")
    
    vpn_data = {
        "VPN Type": ["IPSec Site-to-Site", "IPSec Remote Access", "SSL/TLS VPN", "MPLS VPN"],
        "Use Case": [
            "Connect branch offices to headquarters",
            "Remote workers to corporate network",
            "Web-based remote access",
            "Service provider managed VPN"
        ],
        "Encryption": [
            "ESP (AES), AH (authentication)",
            "ESP (AES), IKE key exchange",
            "TLS encryption, certificate-based",
            "Label switching, optional encryption"
        ],
        "Client Requirements": [
            "VPN gateway devices",
            "VPN client software",
            "Web browser (clientless)",
            "Provider equipment"
        ],
        "Advantages": [
            "Secure, scalable, cost-effective",
            "Strong security, full network access",
            "Easy deployment, no client software",
            "High performance, QoS support"
        ],
        "Disadvantages": [
            "Complex configuration, static IP needed",
            "Client management, compatibility issues",
            "Limited application support",
            "Expensive, provider dependency"
        ]
    }
    
    df3 = pd.DataFrame(vpn_data)
    st.dataframe(df3, use_container_width=True)
    
    # Intrusion Detection/Prevention
    st.markdown("### IDS vs IPS Comparison")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Intrusion Detection System (IDS):**
        - **Function** - Monitor and alert on suspicious activity
        - **Deployment** - Out-of-band (passive monitoring)
        - **Response** - Alert generation, logging
        - **Impact** - No network performance impact
        - **Detection Methods** - Signature-based, anomaly-based
        """)
        
        st.markdown("""
        **Network-based IDS (NIDS):**
        - Monitors network traffic
        - Deployed at network choke points
        - Can see all network communications
        - Requires network TAPs or SPAN ports
        """)
    
    with col2:
        st.markdown("""
        **Intrusion Prevention System (IPS):**
        - **Function** - Detect and actively block threats
        - **Deployment** - Inline (in the data path)
        - **Response** - Block, drop, reset connections
        - **Impact** - Can affect network performance
        - **Detection Methods** - Signature-based, behavioral analysis
        """)
        
        st.markdown("""
        **Network-based IPS (NIPS):**
        - Actively blocks malicious traffic
        - Deployed inline with network traffic
        - Can stop attacks in real-time
        - Single point of failure consideration
        """)
    
    # Network Segmentation
    st.markdown("### Network Segmentation Strategies")
    
    segmentation_data = {
        "Segmentation Type": ["Physical Segmentation", "VLAN Segmentation", "Subnet Segmentation", "Micro-segmentation"],
        "Implementation": [
            "Separate physical networks/switches",
            "Virtual LANs with separate broadcast domains",
            "Different IP subnets with routing control",
            "Software-defined perimeters, zero trust"
        ],
        "Granularity": [
            "Coarse - department/building level",
            "Medium - functional groups",
            "Medium - logical network divisions",
            "Fine - individual workloads/applications"
        ],
        "Cost": ["High", "Low", "Medium", "Medium"],
        "Flexibility": ["Low", "High", "Medium", "Very High"],
        "Security Level": ["High", "Medium", "Medium", "Very High"],
        "Management Complexity": ["Low", "Medium", "Medium", "High"]
    }
    
    df4 = pd.DataFrame(segmentation_data)
    st.dataframe(df4, use_container_width=True)
    
    # Security Monitoring and Logging
    st.markdown("### Security Monitoring Best Practices")
    
    monitoring_data = {
        "Component": ["SIEM System", "Network Monitoring", "Log Management", "Threat Intelligence", "Incident Response"],
        "Purpose": [
            "Centralized security event correlation",
            "Real-time network traffic analysis",
            "Centralized log collection and analysis",
            "External threat information integration",
            "Structured response to security incidents"
        ],
        "Key Features": [
            "Event correlation, alerting, dashboards",
            "Bandwidth monitoring, anomaly detection",
            "Log aggregation, search, retention",
            "IOC feeds, reputation services",
            "Playbooks, forensics, communication"
        ],
        "Technologies": [
            "Splunk, QRadar, ArcSight, ELK Stack",
            "SolarWinds, PRTG, Nagios, Zabbix",
            "Syslog, Fluentd, Logstash, Graylog",
            "MISP, ThreatConnect, STIX/TAXII",
            "TheHive, Phantom, Demisto"
        ]
    }
    
    df5 = pd.DataFrame(monitoring_data)
    st.dataframe(df5, use_container_width=True)
    
    # Wireless Security
    st.markdown("### Wireless Network Security")
    
    wireless_data = {
        "Security Protocol": ["WEP", "WPA", "WPA2", "WPA3"],
        "Encryption": ["RC4 (40/104-bit)", "TKIP + RC4", "AES-CCMP", "AES-GCMP"],
        "Authentication": ["Open/Shared Key", "PSK/802.1X", "PSK/802.1X", "SAE/802.1X"],
        "Security Level": ["Very Weak", "Weak", "Strong", "Very Strong"],
        "Vulnerabilities": [
            "Easily cracked, IV reuse",
            "TKIP vulnerabilities, weak RC4",
            "WPS vulnerabilities, KRACK attack",
            "Improved against known attacks"
        ],
        "Recommendations": [
            "Never use - deprecated",
            "Avoid - upgrade to WPA2/3",
            "Acceptable with proper configuration",
            "Preferred for new deployments"
        ]
    }
    
    df6 = pd.DataFrame(wireless_data)
    st.dataframe(df6, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Defense in Depth:</strong> Use multiple layers of security controls</li>
            <li><strong>Network Segmentation:</strong> Limit attack spread and improve security posture</li>
            <li><strong>Continuous Monitoring:</strong> Implement comprehensive logging and monitoring</li>
            <li><strong>Regular Updates:</strong> Keep security controls and signatures current</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
