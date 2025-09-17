"""
Network Fundamentals Lab
Comprehensive networking basics and core concepts
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
from datetime import datetime, timedelta
import ipaddress
import struct
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
    """Network Fundamentals Lab - Master Networking Basics"""
    
    # Compact Header
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 1rem; border-radius: 8px; margin-bottom: 1rem; text-align: center;">
        <h2 style="color: white; margin: 0; font-size: 1.5rem;">
            🌐 Network Fundamentals Lab
        </h2>
        <p style="color: white; margin: 0; font-size: 0.9rem; opacity: 0.9;">
            Master Networking Basics, Protocols & Architecture
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Tabs for different topics
    tabs = st.tabs([
        "🔌 OSI Model",
        "📡 TCP/IP Stack", 
        "🔢 IP Addressing",
        "🌍 Subnetting",
        "🚦 Routing Basics",
        "🔄 Switching",
        "📮 DNS & DHCP",
        "🌐 HTTP/HTTPS",
        "📧 Email Protocols",
        "🔍 Network Tools",
        "📊 Protocol Analysis",
        "🎮 Network Simulator"
    ])
    
    with tabs[0]:
        osi_model_lab()
    
    with tabs[1]:
        tcp_ip_stack_lab()
    
    with tabs[2]:
        ip_addressing_lab()
    
    with tabs[3]:
        subnetting_lab()
    
    with tabs[4]:
        routing_basics_lab()
    
    with tabs[5]:
        switching_lab()
    
    with tabs[6]:
        dns_dhcp_lab()
    
    with tabs[7]:
        http_https_lab()
    
    with tabs[8]:
        email_protocols_lab()
    
    with tabs[9]:
        network_tools_lab()
    
    with tabs[10]:
        protocol_analysis_lab()
    
    with tabs[11]:
        network_simulator_lab()

def osi_model_lab():
    """OSI Model Deep Dive"""
    
    st.markdown(create_lab_header("OSI Model Lab", "🔌", "linear-gradient(90deg, #FF6B6B 0%, #4ECDC4 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **OSI Model Theory**", expanded=True):
        st.markdown("""
        ### 🏗️ **The 7 Layers of OSI Model**
        
        The OSI (Open Systems Interconnection) model is a conceptual framework that standardizes 
        the functions of a telecommunication or computing system into seven abstraction layers.
        
        **Why OSI Model?**
        - Standardization across vendors
        - Troubleshooting framework
        - Protocol development guide
        - Educational tool
        """)
    
    # Interactive OSI Layers
    st.markdown("### 🎯 **Interactive OSI Layers**")
    
    layers_data = {
        "Layer": [7, 6, 5, 4, 3, 2, 1],
        "Name": ["Application", "Presentation", "Session", "Transport", "Network", "Data Link", "Physical"],
        "Function": [
            "User interface, network services",
            "Data translation, encryption, compression",
            "Session management, synchronization",
            "Reliable delivery, error recovery",
            "Routing, logical addressing",
            "Framing, error detection",
            "Bit transmission, physical media"
        ],
        "Protocols": [
            "HTTP, FTP, SMTP, DNS",
            "SSL/TLS, JPEG, GIF",
            "SQL, RPC, NetBIOS",
            "TCP, UDP, SPX",
            "IP, ICMP, OSPF, BGP",
            "Ethernet, PPP, ARP",
            "Ethernet cables, WiFi"
        ],
        "PDU": ["Data", "Data", "Data", "Segment", "Packet", "Frame", "Bits"]
    }
    
    df = pd.DataFrame(layers_data)
    
    # Display as interactive table
    selected_layer = st.selectbox("Select a layer to explore:", df["Name"].tolist())
    
    if selected_layer:
        layer_info = df[df["Name"] == selected_layer].iloc[0]
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Layer Number", layer_info["Layer"])
        
        with col2:
            st.metric("PDU Type", layer_info["PDU"])
        
        with col3:
            st.metric("Key Protocols", layer_info["Protocols"].split(",")[0])
        
        st.info(f"**Function:** {layer_info['Function']}")
        st.code(f"Common Protocols: {layer_info['Protocols']}", language="text")
    
    # Visualization
    fig = go.Figure(data=[
        go.Table(
            header=dict(
                values=list(df.columns),
                fill_color='paleturquoise',
                align='left'
            ),
            cells=dict(
                values=[df[col] for col in df.columns],
                fill_color='lavender',
                align='left'
            )
        )
    ])
    
    fig.update_layout(title="OSI Model Layers", height=400)
    st.plotly_chart(fig, use_container_width=True)
    
    # Encapsulation Demo
    st.markdown("### 📦 **Data Encapsulation Process**")
    
    encap_process = st.radio("Select process:", ["Encapsulation (Sending)", "Decapsulation (Receiving)"])
    
    if encap_process == "Encapsulation (Sending)":
        st.code("""
        Application Layer: User Data
                ↓
        Presentation Layer: User Data + Formatting
                ↓
        Session Layer: User Data + Session Info
                ↓
        Transport Layer: [TCP Header | User Data] = Segment
                ↓
        Network Layer: [IP Header | TCP Header | User Data] = Packet
                ↓
        Data Link Layer: [Frame Header | IP Header | TCP Header | User Data | Frame Trailer] = Frame
                ↓
        Physical Layer: 101010101... (Bits)
        """, language="text")
    else:
        st.code("""
        Physical Layer: 101010101... (Bits)
                ↓
        Data Link Layer: Extract Frame → Remove Headers/Trailer
                ↓
        Network Layer: Extract Packet → Remove IP Header
                ↓
        Transport Layer: Extract Segment → Remove TCP Header
                ↓
        Session Layer: Process Session Info
                ↓
        Presentation Layer: Format Data
                ↓
        Application Layer: User Data
        """, language="text")

def tcp_ip_stack_lab():
    """TCP/IP Protocol Stack"""
    
    st.markdown(create_lab_header("TCP/IP Stack Lab", "📡", "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"), unsafe_allow_html=True)
    
    # Theory
    with st.expander("📖 **TCP/IP Model Theory**", expanded=False):
        st.markdown("""
        ### 📡 **TCP/IP Protocol Stack**
        
        The TCP/IP model is the practical implementation model used in modern networks.
        
        **4 Layers of TCP/IP:**
        1. **Application Layer** - Combines OSI layers 5-7
        2. **Transport Layer** - Same as OSI layer 4
        3. **Internet Layer** - Same as OSI layer 3
        4. **Network Access Layer** - Combines OSI layers 1-2
        """)
    
    # TCP vs UDP Comparison
    st.markdown("### ⚖️ **TCP vs UDP Comparison**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### **TCP (Transmission Control Protocol)**")
        st.success("✅ **Connection-oriented**")
        st.code("""
        Features:
        • Reliable delivery
        • Ordered packets
        • Error checking
        • Flow control
        • Congestion control
        
        Use Cases:
        • Web browsing (HTTP/HTTPS)
        • Email (SMTP, POP3, IMAP)
        • File transfer (FTP)
        • Remote access (SSH, Telnet)
        """, language="text")
    
    with col2:
        st.markdown("#### **UDP (User Datagram Protocol)**")
        st.warning("⚡ **Connectionless**")
        st.code("""
        Features:
        • Fast transmission
        • No connection setup
        • No guaranteed delivery
        • No ordering
        • Lower overhead
        
        Use Cases:
        • Video streaming
        • Online gaming
        • VoIP
        • DNS queries
        """, language="text")
    
    # TCP Three-Way Handshake
    st.markdown("### 🤝 **TCP Three-Way Handshake**")
    
    handshake_step = st.slider("Handshake Step", 0, 3, 0)
    
    handshake_stages = [
        "Initial State: Client and Server ready",
        "Step 1: Client → Server [SYN, Seq=x]",
        "Step 2: Server → Client [SYN-ACK, Seq=y, Ack=x+1]",
        "Step 3: Client → Server [ACK, Seq=x+1, Ack=y+1]"
    ]
    
    st.info(handshake_stages[handshake_step])
    
    # Visual representation
    if handshake_step > 0:
        fig = go.Figure()
        
        # Add client and server
        fig.add_trace(go.Scatter(
            x=[0, 10], y=[5, 5],
            mode='markers+text',
            marker=dict(size=30),
            text=['Client', 'Server'],
            textposition="bottom center"
        ))
        
        # Add arrows based on step
        if handshake_step >= 1:
            fig.add_annotation(
                x=10, y=5, ax=0, ay=5,
                xref="x", yref="y", axref="x", ayref="y",
                text="SYN",
                showarrow=True,
                arrowhead=2,
                arrowsize=1,
                arrowwidth=2,
                arrowcolor="blue"
            )
        
        if handshake_step >= 2:
            fig.add_annotation(
                x=0, y=4.5, ax=10, ay=4.5,
                xref="x", yref="y", axref="x", ayref="y",
                text="SYN-ACK",
                showarrow=True,
                arrowhead=2,
                arrowsize=1,
                arrowwidth=2,
                arrowcolor="green"
            )
        
        if handshake_step >= 3:
            fig.add_annotation(
                x=10, y=4, ax=0, ay=4,
                xref="x", yref="y", axref="x", ayref="y",
                text="ACK",
                showarrow=True,
                arrowhead=2,
                arrowsize=1,
                arrowwidth=2,
                arrowcolor="red"
            )
        
        fig.update_layout(
            showlegend=False,
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
            height=300
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    # Port Numbers
    st.markdown("### 🔌 **Common Port Numbers**")
    
    ports_data = {
        "Service": ["HTTP", "HTTPS", "FTP", "SSH", "Telnet", "SMTP", "DNS", "DHCP", "POP3", "IMAP"],
        "Port": [80, 443, 21, 22, 23, 25, 53, 67, 110, 143],
        "Protocol": ["TCP", "TCP", "TCP", "TCP", "TCP", "TCP", "TCP/UDP", "UDP", "TCP", "TCP"],
        "Description": [
            "Web traffic",
            "Secure web",
            "File transfer",
            "Secure shell",
            "Remote access",
            "Email sending",
            "Domain names",
            "IP assignment",
            "Email retrieval",
            "Email access"
        ]
    }
    
    df_ports = pd.DataFrame(ports_data)
    st.dataframe(df_ports, use_container_width=True)

def ip_addressing_lab():
    """IP Addressing Fundamentals"""
    
    st.markdown(create_lab_header("IP Addressing Lab", "🔢", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # IPv4 vs IPv6
    st.markdown("### 🌐 **IPv4 vs IPv6**")
    
    ip_version = st.radio("Select IP Version:", ["IPv4", "IPv6"])
    
    if ip_version == "IPv4":
        st.markdown("#### **IPv4 Addressing**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.code("""
            Format: 32 bits (4 octets)
            Example: 192.168.1.1
            Range: 0.0.0.0 to 255.255.255.255
            Total addresses: 2^32 = 4,294,967,296
            """, language="text")
        
        with col2:
            # IPv4 Classes
            st.markdown("**Address Classes:**")
            classes = {
                "Class": ["A", "B", "C", "D", "E"],
                "Range": ["0-127", "128-191", "192-223", "224-239", "240-255"],
                "Default Mask": ["255.0.0.0", "255.255.0.0", "255.255.255.0", "N/A", "N/A"],
                "Purpose": ["Large networks", "Medium networks", "Small networks", "Multicast", "Reserved"]
            }
            st.dataframe(pd.DataFrame(classes), use_container_width=True)
        
        # Private IP Ranges
        st.markdown("**Private IP Ranges (RFC 1918):**")
        st.code("""
        Class A: 10.0.0.0 - 10.255.255.255 (10.0.0.0/8)
        Class B: 172.16.0.0 - 172.31.255.255 (172.16.0.0/12)
        Class C: 192.168.0.0 - 192.168.255.255 (192.168.0.0/16)
        """, language="text")
        
    else:  # IPv6
        st.markdown("#### **IPv6 Addressing**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.code("""
            Format: 128 bits (8 groups of 4 hex digits)
            Example: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
            Shortened: 2001:db8:85a3::8a2e:370:7334
            Total addresses: 2^128 = 3.4×10^38
            """, language="text")
        
        with col2:
            st.markdown("**IPv6 Address Types:**")
            st.code("""
            • Unicast - One-to-one
            • Multicast - One-to-many
            • Anycast - One-to-nearest
            
            Special Addresses:
            ::1 - Loopback
            :: - Unspecified
            fe80::/10 - Link-local
            fc00::/7 - Unique local
            """, language="text")
    
    # IP Address Calculator
    st.markdown("### 🧮 **IP Address Calculator**")
    
    ip_input = st.text_input("Enter IP Address:", "192.168.1.100")
    
    if st.button("Analyze IP", key="analyze_ip"):
        try:
            ip = ipaddress.ip_address(ip_input)
            network = ipaddress.ip_network(f"{ip_input}/24", strict=False)
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("IP Version", ip.version)
                st.metric("Is Private", ip.is_private)
            
            with col2:
                st.metric("Is Global", ip.is_global)
                st.metric("Is Multicast", ip.is_multicast)
            
            with col3:
                st.metric("Binary", format(int(ip), '032b')[:16] + "...")
                st.metric("Hex", hex(int(ip)))
            
            # Network info
            st.markdown("**Network Information:**")
            st.code(f"""
            Network: {network.network_address}
            Broadcast: {network.broadcast_address}
            Netmask: {network.netmask}
            Host bits: {network.num_addresses - 2}
            First host: {list(network.hosts())[0] if network.num_addresses > 2 else 'N/A'}
            Last host: {list(network.hosts())[-1] if network.num_addresses > 2 else 'N/A'}
            """, language="text")
            
        except Exception as e:
            st.error(f"Invalid IP address: {e}")

def subnetting_lab():
    """Subnetting Calculator and Tutorial"""
    
    st.markdown(create_lab_header("Subnetting Lab", "🌍", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Theory
    with st.expander("📖 **Subnetting Theory**", expanded=False):
        st.markdown("""
        ### 🌍 **What is Subnetting?**
        
        Subnetting is the process of dividing a network into smaller subnetworks.
        
        **Benefits:**
        - Better network organization
        - Improved security
        - Reduced broadcast domains
        - Efficient IP address utilization
        
        **CIDR Notation:**
        - /24 = 255.255.255.0 (256 addresses, 254 hosts)
        - /25 = 255.255.255.128 (128 addresses, 126 hosts)
        - /26 = 255.255.255.192 (64 addresses, 62 hosts)
        """)
    
    # Subnet Calculator
    st.markdown("### 🧮 **Subnet Calculator**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        network_input = st.text_input("Network Address:", "192.168.1.0")
        cidr = st.slider("CIDR Prefix:", 8, 30, 24)
    
    with col2:
        num_subnets = st.number_input("Number of Subnets Needed:", 1, 256, 4)
        hosts_per_subnet = st.number_input("Hosts per Subnet:", 1, 65536, 50)
    
    if st.button("Calculate Subnets", key="calc_subnets"):
        try:
            network = ipaddress.ip_network(f"{network_input}/{cidr}", strict=False)
            
            # Calculate required bits
            subnet_bits = (num_subnets - 1).bit_length()
            host_bits = (hosts_per_subnet + 2 - 1).bit_length()  # +2 for network and broadcast
            
            new_prefix = cidr + subnet_bits
            
            if new_prefix <= 30:  # Maximum useful prefix
                subnets = list(network.subnets(new_prefix=new_prefix))[:num_subnets]
                
                st.success(f"✅ Created {len(subnets)} subnets with /{new_prefix} prefix")
                
                # Display subnet information
                subnet_data = []
                for i, subnet in enumerate(subnets):
                    hosts = list(subnet.hosts())
                    subnet_data.append({
                        "Subnet #": i + 1,
                        "Network": str(subnet.network_address),
                        "Broadcast": str(subnet.broadcast_address),
                        "First Host": str(hosts[0]) if hosts else "N/A",
                        "Last Host": str(hosts[-1]) if hosts else "N/A",
                        "Total Hosts": len(hosts)
                    })
                
                df = pd.DataFrame(subnet_data)
                st.dataframe(df, use_container_width=True)
                
                # Visual representation
                fig = go.Figure(data=[go.Pie(
                    labels=[f"Subnet {i+1}" for i in range(len(subnets))],
                    values=[subnet.num_addresses for subnet in subnets],
                    hole=.3
                )])
                
                fig.update_layout(title="Subnet Size Distribution")
                st.plotly_chart(fig, use_container_width=True)
                
            else:
                st.error(f"Cannot create {num_subnets} subnets with {hosts_per_subnet} hosts each in /{cidr} network")
                
        except Exception as e:
            st.error(f"Error: {e}")
    
    # VLSM Calculator
    st.markdown("### 📐 **VLSM (Variable Length Subnet Mask)**")
    
    vlsm_input = st.text_area("Enter subnet requirements (name,hosts per line):", 
                               "Sales,50\nMarketing,25\nIT,10\nManagement,5")
    
    if st.button("Calculate VLSM", key="calc_vlsm"):
        try:
            base_network = ipaddress.ip_network(f"{network_input}/{cidr}", strict=False)
            requirements = []
            
            for line in vlsm_input.strip().split('\n'):
                name, hosts = line.split(',')
                requirements.append((name.strip(), int(hosts.strip())))
            
            # Sort by hosts needed (largest first)
            requirements.sort(key=lambda x: x[1], reverse=True)
            
            current_network = base_network
            vlsm_results = []
            
            for name, hosts_needed in requirements:
                # Calculate required prefix
                host_bits = (hosts_needed + 2 - 1).bit_length()
                subnet_prefix = 32 - host_bits
                
                # Create subnet
                subnet = ipaddress.ip_network(f"{current_network.network_address}/{subnet_prefix}", strict=False)
                
                vlsm_results.append({
                    "Department": name,
                    "Hosts Needed": hosts_needed,
                    "Network": str(subnet),
                    "Usable Hosts": subnet.num_addresses - 2,
                    "Waste": subnet.num_addresses - 2 - hosts_needed
                })
                
                # Get next available network
                current_network = ipaddress.ip_network(
                    f"{subnet.network_address + subnet.num_addresses}/{cidr}", 
                    strict=False
                )
            
            df_vlsm = pd.DataFrame(vlsm_results)
            st.dataframe(df_vlsm, use_container_width=True)
            
            # Efficiency metric
            total_hosts_needed = sum(r[1] for r in requirements)
            total_hosts_allocated = sum(r["Usable Hosts"] for r in vlsm_results)
            efficiency = (total_hosts_needed / total_hosts_allocated) * 100
            
            st.metric("Address Efficiency", f"{efficiency:.1f}%")
            
        except Exception as e:
            st.error(f"Error in VLSM calculation: {e}")

def routing_basics_lab():
    """Routing Fundamentals"""
    
    st.markdown(create_lab_header("Routing Basics Lab", "🚦", "linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%)"), unsafe_allow_html=True)
    
    # Routing Concepts
    st.markdown("### 📍 **Routing Concepts**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### **Static Routing**")
        st.code("""
        Advantages:
        ✓ No overhead (CPU/bandwidth)
        ✓ Secure (no advertisements)
        ✓ Predictable
        
        Disadvantages:
        ✗ No automatic failover
        ✗ Manual configuration
        ✗ Not scalable
        
        Configuration:
        ip route 192.168.2.0 255.255.255.0 10.0.0.2
        """, language="text")
    
    with col2:
        st.markdown("#### **Dynamic Routing**")
        st.code("""
        Advantages:
        ✓ Automatic updates
        ✓ Failover capability
        ✓ Scalable
        
        Disadvantages:
        ✗ Resource overhead
        ✗ Less secure
        ✗ Complex configuration
        
        Protocols:
        • RIP, OSPF, EIGRP, BGP
        """, language="text")
    
    # Routing Table Simulator
    st.markdown("### 📋 **Routing Table Simulator**")
    
    # Sample routing table
    routing_table = pd.DataFrame({
        "Destination": ["0.0.0.0/0", "192.168.1.0/24", "192.168.2.0/24", "10.0.0.0/8"],
        "Gateway": ["192.168.1.1", "0.0.0.0", "192.168.1.254", "10.0.0.1"],
        "Interface": ["eth0", "eth1", "eth0", "eth2"],
        "Metric": [10, 0, 1, 5],
        "Type": ["Default", "Connected", "Static", "Static"]
    })
    
    st.dataframe(routing_table, use_container_width=True)
    
    # Route lookup
    dest_ip = st.text_input("Enter destination IP to find route:", "192.168.2.50")
    
    if st.button("Find Route", key="find_route"):
        st.info(f"🔍 Looking up route for {dest_ip}...")
        
        # Simulate route lookup
        for _, route in routing_table.iterrows():
            network = ipaddress.ip_network(route["Destination"])
            try:
                if ipaddress.ip_address(dest_ip) in network:
                    st.success(f"""
                    ✅ **Route Found:**
                    - Destination Network: {route['Destination']}
                    - Next Hop: {route['Gateway']}
                    - Exit Interface: {route['Interface']}
                    - Metric: {route['Metric']}
                    """)
                    break
            except:
                pass
        else:
            st.warning("No specific route found. Using default route.")
    
    # Routing Protocols Comparison
    st.markdown("### 🔄 **Routing Protocols Comparison**")
    
    protocols_data = {
        "Protocol": ["RIP v2", "OSPF", "EIGRP", "BGP"],
        "Type": ["Distance Vector", "Link State", "Hybrid", "Path Vector"],
        "Metric": ["Hop Count", "Cost", "Composite", "Path Attributes"],
        "Admin Distance": [120, 110, 90, 20],
        "Convergence": ["Slow", "Fast", "Very Fast", "Slow"],
        "Use Case": ["Small networks", "Enterprise", "Cisco networks", "Internet/ISP"]
    }
    
    df_protocols = pd.DataFrame(protocols_data)
    st.dataframe(df_protocols, use_container_width=True)

def switching_lab():
    """Switching and VLANs"""
    
    st.markdown(create_lab_header("Switching Lab", "🔄", "linear-gradient(90deg, #FC466B 0%, #3F5EFB 100%)"), unsafe_allow_html=True)
    
    # Switching Concepts
    st.markdown("### 🔄 **Switching Fundamentals**")
    
    with st.expander("📖 **How Switches Work**", expanded=True):
        st.markdown("""
        **Switch Operation:**
        1. **Learning** - Builds MAC address table
        2. **Flooding** - Unknown destination = broadcast
        3. **Forwarding** - Known destination = unicast
        4. **Filtering** - Same segment = no forward
        5. **Aging** - Removes old entries (300 seconds)
        """)
    
    # MAC Address Table
    st.markdown("### 📑 **MAC Address Table Simulator**")
    
    if 'mac_table' not in st.session_state:
        st.session_state.mac_table = pd.DataFrame({
            "MAC Address": ["00:1B:44:11:3A:B7", "00:1B:44:11:3A:B8", "00:1B:44:11:3A:B9"],
            "Port": ["Fa0/1", "Fa0/2", "Fa0/3"],
            "VLAN": [1, 1, 10],
            "Type": ["Dynamic", "Dynamic", "Static"]
        })
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.dataframe(st.session_state.mac_table, use_container_width=True)
    
    with col2:
        new_mac = st.text_input("MAC Address:", "00:1B:44:11:3A:BA")
        new_port = st.selectbox("Port:", ["Fa0/1", "Fa0/2", "Fa0/3", "Fa0/4"])
        new_vlan = st.number_input("VLAN:", 1, 4094, 1)
        
        if st.button("Add Entry", key="add_mac"):
            new_entry = pd.DataFrame({
                "MAC Address": [new_mac],
                "Port": [new_port],
                "VLAN": [new_vlan],
                "Type": ["Dynamic"]
            })
            st.session_state.mac_table = pd.concat([st.session_state.mac_table, new_entry], ignore_index=True)
            st.rerun()
    
    # VLAN Configuration
    st.markdown("### 🏷️ **VLAN Configuration**")
    
    vlan_data = {
        "VLAN ID": [1, 10, 20, 30, 99],
        "Name": ["Default", "Sales", "Marketing", "IT", "Management"],
        "Ports": ["Fa0/1-8", "Fa0/9-16", "Fa0/17-20", "Fa0/21-23", "Fa0/24"],
        "IP Range": ["192.168.1.0/24", "192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24", "192.168.99.0/24"]
    }
    
    df_vlan = pd.DataFrame(vlan_data)
    st.dataframe(df_vlan, use_container_width=True)
    
    # STP Visualization
    st.markdown("### 🌳 **Spanning Tree Protocol (STP)**")
    
    stp_state = st.selectbox("Port State:", ["Blocking", "Listening", "Learning", "Forwarding", "Disabled"])
    
    state_info = {
        "Blocking": "🔴 Port does not forward frames, receives BPDUs only",
        "Listening": "🟡 Port transitions, processes BPDUs, no MAC learning",
        "Learning": "🟡 Port learns MAC addresses, no forwarding yet",
        "Forwarding": "🟢 Port forwards frames and learns MAC addresses",
        "Disabled": "⚫ Port is administratively down"
    }
    
    st.info(state_info[stp_state])
    
    # STP Timer
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Hello Timer", "2 seconds")
    with col2:
        st.metric("Forward Delay", "15 seconds")
    with col3:
        st.metric("Max Age", "20 seconds")

def dns_dhcp_lab():
    """DNS and DHCP Services"""
    
    st.markdown(create_lab_header("DNS & DHCP Lab", "📮", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    service = st.radio("Select Service:", ["DNS", "DHCP"])
    
    if service == "DNS":
        st.markdown("### 🌐 **DNS (Domain Name System)**")
        
        # DNS Query Simulator
        st.markdown("#### **DNS Query Simulator**")
        
        domain = st.text_input("Enter domain name:", "www.example.com")
        query_type = st.selectbox("Query Type:", ["A", "AAAA", "MX", "CNAME", "NS", "TXT"])
        
        if st.button("Resolve DNS", key="resolve_dns"):
            with st.spinner("Resolving..."):
                # Simulate DNS resolution
                st.code(f"""
                Query: {domain} ({query_type} record)
                
                1. Check local cache... Not found
                2. Query local DNS server (192.168.1.1)
                3. Root server query (.com)
                4. TLD server query (example.com)
                5. Authoritative server response
                
                Result:
                {domain} → 93.184.216.34 (A record)
                TTL: 3600 seconds
                """, language="text")
        
        # DNS Record Types
        st.markdown("#### **DNS Record Types**")
        
        dns_records = {
            "Type": ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "TXT"],
            "Purpose": [
                "IPv4 address",
                "IPv6 address",
                "Canonical name (alias)",
                "Mail exchange",
                "Name server",
                "Reverse DNS",
                "Start of authority",
                "Text information"
            ],
            "Example": [
                "example.com → 192.168.1.1",
                "example.com → 2001:db8::1",
                "www → example.com",
                "10 mail.example.com",
                "ns1.example.com",
                "1.1.168.192.in-addr.arpa",
                "Primary NS, admin email",
                "SPF, DKIM records"
            ]
        }
        
        st.dataframe(pd.DataFrame(dns_records), use_container_width=True)
        
    else:  # DHCP
        st.markdown("### 📡 **DHCP (Dynamic Host Configuration Protocol)**")
        
        # DHCP Process
        st.markdown("#### **DHCP DORA Process**")
        
        dhcp_step = st.slider("DHCP Step", 1, 4, 1)
        
        steps = {
            1: ("Discover", "Client broadcasts DHCPDISCOVER to find servers"),
            2: ("Offer", "Server responds with DHCPOFFER containing IP configuration"),
            3: ("Request", "Client broadcasts DHCPREQUEST to accept offer"),
            4: ("Acknowledge", "Server sends DHCPACK confirming the lease")
        }
        
        st.info(f"**Step {dhcp_step}: {steps[dhcp_step][0]}**\n{steps[dhcp_step][1]}")
        
        # DHCP Configuration
        st.markdown("#### **DHCP Pool Configuration**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            pool_start = st.text_input("Pool Start:", "192.168.1.100")
            pool_end = st.text_input("Pool End:", "192.168.1.200")
            subnet_mask = st.text_input("Subnet Mask:", "255.255.255.0")
        
        with col2:
            gateway = st.text_input("Default Gateway:", "192.168.1.1")
            dns_server = st.text_input("DNS Server:", "8.8.8.8")
            lease_time = st.number_input("Lease Time (hours):", 1, 168, 24)
        
        if st.button("Generate DHCP Config", key="gen_dhcp"):
            st.code(f"""
            # DHCP Server Configuration
            
            ip dhcp pool LAN_POOL
                network 192.168.1.0 255.255.255.0
                default-router {gateway}
                dns-server {dns_server}
                lease 0 {lease_time} 0
            
            ip dhcp excluded-address 192.168.1.1 192.168.1.99
            ip dhcp excluded-address 192.168.1.201 192.168.1.254
            
            # Available IPs: {pool_start} - {pool_end}
            # Total addresses: 101
            """, language="text")

def http_https_lab():
    """HTTP/HTTPS Protocols"""
    
    st.markdown(create_lab_header("HTTP/HTTPS Lab", "🌐", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # HTTP Methods
    st.markdown("### 📨 **HTTP Methods**")
    
    methods_data = {
        "Method": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
        "Purpose": [
            "Retrieve resource",
            "Submit data",
            "Update resource",
            "Delete resource",
            "Get headers only",
            "Get allowed methods",
            "Partial update"
        ],
        "Body": ["No", "Yes", "Yes", "No", "No", "No", "Yes"],
        "Idempotent": ["Yes", "No", "Yes", "Yes", "Yes", "Yes", "No"],
        "Safe": ["Yes", "No", "No", "No", "Yes", "Yes", "No"]
    }
    
    st.dataframe(pd.DataFrame(methods_data), use_container_width=True)
    
    # HTTP Request Builder
    st.markdown("### 🔨 **HTTP Request Builder**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        method = st.selectbox("Method:", ["GET", "POST", "PUT", "DELETE"])
        url = st.text_input("URL:", "https://api.example.com/users")
        headers = st.text_area("Headers (JSON):", '{"Content-Type": "application/json"}')
    
    with col2:
        if method in ["POST", "PUT"]:
            body = st.text_area("Body (JSON):", '{"name": "John", "email": "john@example.com"}')
        else:
            body = None
    
    if st.button("Build Request", key="build_http"):
        st.code(f"""
        {method} {url} HTTP/1.1
        Host: api.example.com
        {headers}
        
        {body if body else ''}
        """, language="http")
    
    # Status Codes
    st.markdown("### 📊 **HTTP Status Codes**")
    
    status_categories = {
        "1xx": "Informational",
        "2xx": "Success",
        "3xx": "Redirection",
        "4xx": "Client Error",
        "5xx": "Server Error"
    }
    
    category = st.selectbox("Category:", list(status_categories.keys()))
    
    status_codes = {
        "1xx": {"100": "Continue", "101": "Switching Protocols"},
        "2xx": {"200": "OK", "201": "Created", "204": "No Content"},
        "3xx": {"301": "Moved Permanently", "302": "Found", "304": "Not Modified"},
        "4xx": {"400": "Bad Request", "401": "Unauthorized", "403": "Forbidden", "404": "Not Found"},
        "5xx": {"500": "Internal Server Error", "502": "Bad Gateway", "503": "Service Unavailable"}
    }
    
    for code, description in status_codes[category].items():
        st.write(f"**{code}** - {description}")
    
    # HTTPS/TLS
    st.markdown("### 🔒 **HTTPS & TLS**")
    
    with st.expander("TLS Handshake Process"):
        st.code("""
        1. Client Hello
           - TLS version, cipher suites, random number
        
        2. Server Hello
           - Selected cipher suite, server random
        
        3. Server Certificate
           - Server's public certificate
        
        4. Server Key Exchange (if needed)
           - Additional key exchange data
        
        5. Client Key Exchange
           - Pre-master secret (encrypted)
        
        6. Change Cipher Spec
           - Switch to encrypted communication
        
        7. Finished
           - Verify handshake integrity
        """, language="text")

def email_protocols_lab():
    """Email Protocols - SMTP, POP3, IMAP"""
    
    st.markdown(create_lab_header("Email Protocols Lab", "📧", "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"), unsafe_allow_html=True)
    
    # Protocol Comparison
    st.markdown("### 📮 **Email Protocol Comparison**")
    
    protocols = {
        "Protocol": ["SMTP", "POP3", "IMAP"],
        "Port": ["25/587", "110/995", "143/993"],
        "Purpose": ["Send mail", "Receive mail", "Receive mail"],
        "Direction": ["Outgoing", "Incoming", "Incoming"],
        "Storage": ["N/A", "Download & Delete", "Server-side"],
        "Multi-device": ["Yes", "No", "Yes"]
    }
    
    st.dataframe(pd.DataFrame(protocols), use_container_width=True)
    
    # Email Flow Simulator
    st.markdown("### 📬 **Email Flow Simulator**")
    
    sender = st.text_input("From:", "alice@example.com")
    recipient = st.text_input("To:", "bob@example.org")
    
    if st.button("Trace Email Path", key="trace_email"):
        st.code(f"""
        Email Journey: {sender} → {recipient}
        
        1. Alice composes email in client (Outlook/Gmail)
           ↓
        2. Client connects to SMTP server (smtp.example.com:587)
           ↓
        3. SMTP authentication and TLS encryption
           ↓
        4. DNS MX lookup for example.org
           ↓
        5. SMTP relay to bob's mail server (mail.example.org:25)
           ↓
        6. Email stored in Bob's mailbox
           ↓
        7. Bob retrieves via IMAP (mail.example.org:993) or POP3 (mail.example.org:995)
        """, language="text")
    
    # SMTP Commands
    st.markdown("### 💬 **SMTP Commands**")
    
    smtp_commands = {
        "Command": ["HELO", "EHLO", "MAIL FROM", "RCPT TO", "DATA", "QUIT", "AUTH", "STARTTLS"],
        "Purpose": [
            "Identify client (old)",
            "Extended hello",
            "Sender address",
            "Recipient address",
            "Message content",
            "Close connection",
            "Authentication",
            "Enable TLS"
        ],
        "Example": [
            "HELO client.example.com",
            "EHLO client.example.com",
            "MAIL FROM:<alice@example.com>",
            "RCPT TO:<bob@example.org>",
            "DATA\\n[message]\\n.",
            "QUIT",
            "AUTH LOGIN",
            "STARTTLS"
        ]
    }
    
    st.dataframe(pd.DataFrame(smtp_commands), use_container_width=True)

def network_tools_lab():
    """Network Diagnostic Tools"""
    
    st.markdown(create_lab_header("Network Tools Lab", "🔍", "linear-gradient(90deg, #FF6B6B 0%, #4ECDC4 100%)"), unsafe_allow_html=True)
    
    # Tool Selection
    tool = st.selectbox("Select Tool:", ["ping", "traceroute", "nslookup", "netstat", "arp", "route"])
    
    if tool == "ping":
        st.markdown("### 🏓 **Ping Tool**")
        
        target = st.text_input("Target Host:", "8.8.8.8")
        count = st.slider("Packet Count:", 1, 10, 4)
        
        if st.button("Run Ping", key="run_ping"):
            with st.spinner("Pinging..."):
                # Simulate ping output
                st.code(f"""
                PING {target}: 56 data bytes
                64 bytes from {target}: icmp_seq=0 ttl=118 time=14.2 ms
                64 bytes from {target}: icmp_seq=1 ttl=118 time=13.8 ms
                64 bytes from {target}: icmp_seq=2 ttl=118 time=14.5 ms
                64 bytes from {target}: icmp_seq=3 ttl=118 time=13.9 ms
                
                --- {target} ping statistics ---
                {count} packets transmitted, {count} packets received, 0.0% packet loss
                round-trip min/avg/max/stddev = 13.8/14.1/14.5/0.3 ms
                """, language="text")
        
        # Ping Analysis
        st.markdown("**What Ping Tells Us:**")
        col1, col2 = st.columns(2)
        with col1:
            st.info("✅ **Connectivity** - Host is reachable")
            st.info("⏱️ **Latency** - Round-trip time")
        with col2:
            st.info("📊 **Packet Loss** - Network reliability")
            st.info("🔢 **TTL** - Hop count estimate")
    
    elif tool == "traceroute":
        st.markdown("### 🗺️ **Traceroute Tool**")
        
        target = st.text_input("Target Host:", "google.com")
        max_hops = st.slider("Max Hops:", 10, 30, 20)
        
        if st.button("Run Traceroute", key="run_trace"):
            with st.spinner("Tracing route..."):
                # Simulate traceroute
                hops = [
                    ("192.168.1.1", "gateway.local", "1.2 ms"),
                    ("10.0.0.1", "isp-router1", "8.5 ms"),
                    ("72.14.234.20", "google-peer", "15.3 ms"),
                    ("142.250.185.14", "google.com", "18.7 ms")
                ]
                
                st.code("Tracing route to " + target)
                for i, (ip, name, time) in enumerate(hops, 1):
                    st.code(f"{i:2d}  {name} [{ip}]  {time}", language="text")
    
    elif tool == "nslookup":
        st.markdown("### 🔍 **NSLookup Tool**")
        
        domain = st.text_input("Domain Name:", "google.com")
        record_type = st.selectbox("Record Type:", ["A", "AAAA", "MX", "NS", "TXT"])
        
        if st.button("Lookup DNS", key="run_nslookup"):
            st.code(f"""
            Server:  8.8.8.8
            Address: 8.8.8.8#53
            
            Non-authoritative answer:
            Name:    {domain}
            Address: 142.250.185.14
            """, language="text")
    
    elif tool == "netstat":
        st.markdown("### 📊 **Netstat Tool**")
        
        option = st.selectbox("Display:", ["All Connections", "Listening Ports", "Statistics"])
        
        if st.button("Run Netstat", key="run_netstat"):
            if option == "Listening Ports":
                st.code("""
                Proto  Local Address          State
                TCP    0.0.0.0:22            LISTENING
                TCP    0.0.0.0:80            LISTENING
                TCP    0.0.0.0:443           LISTENING
                TCP    127.0.0.1:3306        LISTENING
                UDP    0.0.0.0:53            *:*
                UDP    0.0.0.0:67            *:*
                """, language="text")

def protocol_analysis_lab():
    """Protocol Analysis and Packet Inspection"""
    
    st.markdown(create_lab_header("Protocol Analysis Lab", "📊", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Packet Structure
    st.markdown("### 📦 **Packet Structure Analysis**")
    
    protocol = st.selectbox("Select Protocol:", ["Ethernet", "IP", "TCP", "UDP", "HTTP"])
    
    if protocol == "Ethernet":
        st.code("""
        Ethernet Frame Structure (14 bytes header):
        
        [Preamble: 7 bytes] [SFD: 1 byte] | [Destination MAC: 6 bytes] [Source MAC: 6 bytes] [Type: 2 bytes] | [Payload: 46-1500 bytes] | [FCS: 4 bytes]
        
        Example:
        Dest MAC: 00:1B:44:11:3A:B7
        Src MAC:  00:1B:44:11:3A:B8
        Type:     0x0800 (IPv4)
        """, language="text")
    
    elif protocol == "IP":
        st.code("""
        IPv4 Header Structure (20 bytes minimum):
        
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Version|  IHL  |Type of Service|          Total Length         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Identification        |Flags|      Fragment Offset    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Time to Live |    Protocol   |         Header Checksum       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Source Address                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Destination Address                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """, language="text")
    
    # Wireshark Filter Generator
    st.markdown("### 🔍 **Wireshark Filter Generator**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        filter_type = st.selectbox("Filter Type:", ["IP Address", "Port", "Protocol", "HTTP", "Custom"])
        
        if filter_type == "IP Address":
            ip_addr = st.text_input("IP Address:", "192.168.1.100")
            direction = st.radio("Direction:", ["Source", "Destination", "Any"])
            
            if direction == "Source":
                filter_str = f"ip.src == {ip_addr}"
            elif direction == "Destination":
                filter_str = f"ip.dst == {ip_addr}"
            else:
                filter_str = f"ip.addr == {ip_addr}"
        
        elif filter_type == "Port":
            port = st.number_input("Port Number:", 1, 65535, 80)
            filter_str = f"tcp.port == {port} or udp.port == {port}"
        
        elif filter_type == "Protocol":
            proto = st.selectbox("Protocol:", ["tcp", "udp", "icmp", "arp", "dns", "http"])
            filter_str = proto
        
        else:
            filter_str = st.text_input("Custom Filter:", "tcp.flags.syn == 1")
    
    with col2:
        st.markdown("**Generated Filter:**")
        st.code(filter_str, language="text")
        
        st.markdown("**Common Filters:**")
        st.code("""
        # TCP SYN packets
        tcp.flags.syn == 1
        
        # HTTP GET requests
        http.request.method == "GET"
        
        # DNS queries
        dns.flags.response == 0
        
        # ARP requests
        arp.opcode == 1
        
        # ICMP echo
        icmp.type == 8
        """, language="text")

def network_simulator_lab():
    """Interactive Network Simulator"""
    
    st.markdown(create_lab_header("Network Simulator Lab", "🎮", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Network Topology Builder
    st.markdown("### 🏗️ **Network Topology Builder**")
    
    topology = st.selectbox("Select Topology:", ["Star", "Bus", "Ring", "Mesh", "Tree", "Hybrid"])
    num_nodes = st.slider("Number of Nodes:", 3, 10, 5)
    
    # Create visualization based on topology
    fig = go.Figure()
    
    if topology == "Star":
        # Central node
        fig.add_trace(go.Scatter(
            x=[0], y=[0],
            mode='markers+text',
            marker=dict(size=30, color='red'),
            text=['Switch'],
            textposition="bottom center",
            name='Switch'
        ))
        
        # End nodes
        angles = np.linspace(0, 2*np.pi, num_nodes, endpoint=False)
        x_nodes = np.cos(angles) * 2
        y_nodes = np.sin(angles) * 2
        
        fig.add_trace(go.Scatter(
            x=x_nodes, y=y_nodes,
            mode='markers+text',
            marker=dict(size=20, color='blue'),
            text=[f'PC{i+1}' for i in range(num_nodes)],
            textposition="bottom center",
            name='Nodes'
        ))
        
        # Add connections
        for i in range(num_nodes):
            fig.add_trace(go.Scatter(
                x=[0, x_nodes[i]], y=[0, y_nodes[i]],
                mode='lines',
                line=dict(color='gray', width=1),
                showlegend=False
            ))
    
    fig.update_layout(
        title=f"{topology} Topology with {num_nodes} Nodes",
        showlegend=True,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Network Simulation
    st.markdown("### 🎯 **Packet Flow Simulation**")
    
    source = st.selectbox("Source Node:", [f"PC{i+1}" for i in range(num_nodes)])
    dest = st.selectbox("Destination Node:", [f"PC{i+1}" for i in range(num_nodes) if f"PC{i+1}" != source])
    packet_type = st.selectbox("Packet Type:", ["ICMP Echo", "TCP SYN", "UDP", "ARP Request"])
    
    if st.button("Send Packet", key="send_packet"):
        with st.spinner("Simulating packet flow..."):
            progress = st.progress(0)
            status = st.empty()
            
            steps = [
                f"📤 {source} creates {packet_type} packet",
                f"🔍 ARP resolution for {dest}",
                f"📦 Packet encapsulated in Ethernet frame",
                f"🔄 Frame sent to switch",
                f"🔍 Switch looks up MAC address table",
                f"➡️ Frame forwarded to {dest}",
                f"📥 {dest} receives and processes packet",
                f"✅ Communication successful!"
            ]
            
            for i, step in enumerate(steps):
                progress.progress((i + 1) / len(steps))
                status.info(step)
                time.sleep(0.5)
            
            status.success("✅ Packet delivered successfully!")
    
    # Network Calculations
    st.markdown("### 🧮 **Network Calculations**")
    
    calc_type = st.selectbox("Calculation Type:", ["Bandwidth", "Latency", "Throughput", "Utilization"])
    
    if calc_type == "Bandwidth":
        file_size = st.number_input("File Size (MB):", 1, 1000, 100)
        bandwidth = st.number_input("Bandwidth (Mbps):", 1, 1000, 100)
        
        if st.button("Calculate Transfer Time", key="calc_bandwidth"):
            transfer_time = (file_size * 8) / bandwidth
            st.success(f"Transfer Time: {transfer_time:.2f} seconds")
            
            if transfer_time < 60:
                st.info(f"That's {transfer_time:.2f} seconds")
            else:
                st.info(f"That's {transfer_time/60:.2f} minutes")

if __name__ == "__main__":
    run_lab()
