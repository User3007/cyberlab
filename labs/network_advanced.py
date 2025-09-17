"""
Network Advanced Lab
Advanced networking topics and enterprise technologies
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import time
from datetime import datetime, timedelta
import ipaddress
import random
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
    """Network Advanced Lab - Enterprise Networking & Advanced Topics"""
    
    # Compact Header
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 1rem; border-radius: 8px; margin-bottom: 1rem; text-align: center;">
        <h2 style="color: white; margin: 0; font-size: 1.5rem;">
            🌍 Network Advanced Lab
        </h2>
        <p style="color: white; margin: 0; font-size: 0.9rem; opacity: 0.9;">
            Enterprise Networking, Advanced Protocols & Technologies
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Advanced topics tabs
    tabs = st.tabs([
        "🔧 BGP & Routing",
        "🏢 OSPF & EIGRP",
        "🌐 MPLS",
        "📡 QoS",
        "🔒 VPN Technologies",
        "☁️ SDN & NFV",
        "🌊 Load Balancing",
        "📊 Network Monitoring",
        "🚀 IPv6 Advanced",
        "🔄 Redundancy",
        "📈 Performance",
        "🎯 Troubleshooting"
    ])
    
    with tabs[0]:
        bgp_routing_lab()
    
    with tabs[1]:
        ospf_eigrp_lab()
    
    with tabs[2]:
        mpls_lab()
    
    with tabs[3]:
        qos_lab()
    
    with tabs[4]:
        vpn_technologies_lab()
    
    with tabs[5]:
        sdn_nfv_lab()
    
    with tabs[6]:
        load_balancing_lab()
    
    with tabs[7]:
        network_monitoring_lab()
    
    with tabs[8]:
        ipv6_advanced_lab()
    
    with tabs[9]:
        redundancy_lab()
    
    with tabs[10]:
        performance_lab()
    
    with tabs[11]:
        troubleshooting_lab()

def bgp_routing_lab():
    """BGP and Advanced Routing"""
    
    st.markdown(create_lab_header("BGP & Advanced Routing Lab", "🔧", "linear-gradient(90deg, #FF6B6B 0%, #4ECDC4 100%)"), unsafe_allow_html=True)
    
    # BGP Theory
    with st.expander("📖 **BGP Theory**", expanded=True):
        st.markdown("""
        ### 🌐 **Border Gateway Protocol (BGP)**
        
        BGP is the routing protocol of the Internet, used to exchange routing information between autonomous systems (AS).
        
        **Key Concepts:**
        - **AS (Autonomous System)** - Collection of networks under single administration
        - **eBGP** - External BGP between different AS
        - **iBGP** - Internal BGP within same AS
        - **Path Vector Protocol** - Maintains path information
        """)
    
    # BGP Attributes
    st.markdown("### 📊 **BGP Attributes & Path Selection**")
    
    attributes = {
        "Priority": [1, 2, 3, 4, 5, 6, 7, 8],
        "Attribute": ["Weight", "Local Preference", "Originate", "AS Path", "Origin Type", "MED", "eBGP over iBGP", "IGP Metric"],
        "Scope": ["Local", "AS", "Local", "Global", "Global", "Between AS", "Local", "Local"],
        "Higher/Lower": ["Higher", "Higher", "Local", "Shorter", "IGP>EGP>?", "Lower", "eBGP", "Lower"],
        "Default": ["0", "100", "N/A", "N/A", "i/e/?", "0", "N/A", "N/A"]
    }
    
    df_bgp = pd.DataFrame(attributes)
    st.dataframe(df_bgp, use_container_width=True)
    
    # AS Path Simulator
    st.markdown("### 🛤️ **AS Path Simulator**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        source_as = st.number_input("Source AS:", 1, 65535, 100)
        dest_as = st.number_input("Destination AS:", 1, 65535, 200)
    
    with col2:
        num_paths = st.slider("Number of Paths:", 1, 5, 3)
    
    if st.button("Generate AS Paths", key="gen_paths"):
        paths = []
        for i in range(num_paths):
            # Generate random path
            path_length = random.randint(2, 6)
            path = [source_as]
            for _ in range(path_length - 1):
                path.append(random.randint(1, 65535))
            path.append(dest_as)
            paths.append(path)
        
        # Display paths
        st.markdown("**Available Paths:**")
        best_path = min(paths, key=len)
        
        for i, path in enumerate(paths):
            path_str = " → ".join(map(str, path))
            if path == best_path:
                st.success(f"✅ Path {i+1}: {path_str} (Best - Shortest)")
            else:
                st.info(f"Path {i+1}: {path_str}")
    
    # BGP Configuration
    st.markdown("### ⚙️ **BGP Configuration Example**")
    
    config_type = st.selectbox("Configuration Type:", ["Basic eBGP", "iBGP with Route Reflector", "BGP Filtering"])
    
    if config_type == "Basic eBGP":
        st.code("""
        ! Router 1 (AS 100)
        router bgp 100
         bgp router-id 1.1.1.1
         neighbor 10.0.0.2 remote-as 200
         neighbor 10.0.0.2 description eBGP to AS200
         network 192.168.1.0 mask 255.255.255.0
         
        ! Router 2 (AS 200)
        router bgp 200
         bgp router-id 2.2.2.2
         neighbor 10.0.0.1 remote-as 100
         neighbor 10.0.0.1 description eBGP to AS100
         network 192.168.2.0 mask 255.255.255.0
        """, language="text")
    
    elif config_type == "iBGP with Route Reflector":
        st.code("""
        ! Route Reflector
        router bgp 100
         bgp router-id 1.1.1.1
         neighbor RR-CLIENTS peer-group
         neighbor RR-CLIENTS remote-as 100
         neighbor RR-CLIENTS route-reflector-client
         neighbor 10.1.1.2 peer-group RR-CLIENTS
         neighbor 10.1.1.3 peer-group RR-CLIENTS
         
        ! Client Router
        router bgp 100
         bgp router-id 2.2.2.2
         neighbor 10.1.1.1 remote-as 100
         neighbor 10.1.1.1 next-hop-self
        """, language="text")

def ospf_eigrp_lab():
    """OSPF and EIGRP Protocols"""
    
    st.markdown(create_lab_header("OSPF & EIGRP Lab", "🏢", "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **OSPF & EIGRP Theory**", expanded=True):
        st.markdown("""
        ### 🔄 **Understanding OSPF and EIGRP**
        
        OSPF (Open Shortest Path First) and EIGRP (Enhanced Interior Gateway Routing Protocol) are 
        dynamic routing protocols that automatically discover and maintain network routes.
        
        **OSPF vs EIGRP Comparison:**
        
        | Feature | OSPF | EIGRP |
        |---------|------|-------|
        | Type | Link-State | Advanced Distance Vector |
        | Standard | Open (RFC 2328) | Cisco Proprietary* |
        | Algorithm | Dijkstra SPF | DUAL |
        | Metric | Cost (bandwidth) | Composite (K-values) |
        | Convergence | Fast | Very Fast |
        | Scalability | Very High | High |
        | CPU Usage | Higher | Lower |
        | Memory | Higher | Lower |
        (* Now open standard)
        
        **OSPF Characteristics:**
        - **Areas** - Hierarchical design (Area 0 backbone)
        - **LSA Types** - 11 different Link State Advertisements
        - **DR/BDR** - Designated Router election
        - **Hello Timer** - 10 sec (broadcast), 30 sec (NBMA)
        - **Dead Timer** - 4x Hello timer
        
        **EIGRP Features:**
        - **Feasible Successor** - Backup routes ready
        - **Unequal Cost Load Balancing** - Variance command
        - **Stuck in Active (SIA)** - Query limiting
        - **K-Values** - Bandwidth, delay, reliability, load, MTU
        
        **OSPF Area Types:**
        1. **Backbone (Area 0)** - Must connect all areas
        2. **Standard** - Normal areas
        3. **Stub** - No external routes
        4. **Totally Stubby** - No external or inter-area
        5. **NSSA** - Stub with redistribution
        
        **EIGRP Tables:**
        - **Neighbor Table** - Adjacent routers
        - **Topology Table** - All learned routes
        - **Routing Table** - Best routes only
        
        **Convergence Process:**
        
        **OSPF:**
        1. Hello packets establish neighbors
        2. DBD packets exchange database info
        3. LSR/LSU for missing info
        4. SPF algorithm calculates routes
        
        **EIGRP:**
        1. Hello packets discover neighbors
        2. Update packets exchange routes
        3. DUAL algorithm ensures loop-free
        4. Query/Reply for lost routes
        
        **Best Practices:**
        - Use OSPF for multi-vendor environments
        - Use EIGRP for Cisco-only networks
        - Implement authentication (MD5/SHA)
        - Summarize at area boundaries
        - Tune timers carefully
        - Monitor convergence times
        """)
    
    protocol = st.radio("Select Protocol:", ["OSPF", "EIGRP"])
    
    if protocol == "OSPF":
        st.markdown("### 🦉 **OSPF (Open Shortest Path First)**")
        
        # OSPF Areas
        st.markdown("#### **OSPF Area Design**")
        
        area_type = st.selectbox("Area Type:", ["Backbone (Area 0)", "Standard Area", "Stub Area", "Totally Stubby", "NSSA"])
        
        area_info = {
            "Backbone (Area 0)": "Must exist, all other areas connect to it",
            "Standard Area": "Normal area with all LSA types",
            "Stub Area": "No external routes (Type 5 LSA)",
            "Totally Stubby": "No external or inter-area routes",
            "NSSA": "Stub area that can originate external routes"
        }
        
        st.info(area_info[area_type])
        
        # LSA Types
        st.markdown("#### **OSPF LSA Types**")
        
        lsa_data = {
            "Type": [1, 2, 3, 4, 5, 7],
            "Name": ["Router", "Network", "Summary", "ASBR Summary", "External", "NSSA External"],
            "Generated By": ["All routers", "DR", "ABR", "ABR", "ASBR", "ASBR in NSSA"],
            "Scope": ["Area", "Area", "Area", "Area", "Domain", "NSSA"]
        }
        
        st.dataframe(pd.DataFrame(lsa_data), use_container_width=True)
        
        # OSPF Cost Calculator
        st.markdown("#### **OSPF Cost Calculator**")
        
        bandwidth = st.selectbox("Interface Bandwidth:", ["10 Mbps", "100 Mbps", "1 Gbps", "10 Gbps"])
        reference = st.number_input("Reference Bandwidth (Mbps):", 100, 100000, 100)
        
        bandwidth_values = {"10 Mbps": 10, "100 Mbps": 100, "1 Gbps": 1000, "10 Gbps": 10000}
        cost = reference / bandwidth_values[bandwidth]
        
        st.metric("OSPF Cost", int(cost))
        
    else:  # EIGRP
        st.markdown("### 🚀 **EIGRP (Enhanced Interior Gateway Routing Protocol)**")
        
        # EIGRP Metrics
        st.markdown("#### **EIGRP Composite Metric**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            bandwidth_eigrp = st.number_input("Bandwidth (Kbps):", 1, 10000000, 1544)
            delay_eigrp = st.number_input("Delay (μs):", 1, 100000, 20000)
        
        with col2:
            reliability = st.slider("Reliability:", 1, 255, 255)
            load = st.slider("Load:", 1, 255, 1)
        
        # Calculate metric (simplified)
        metric = (10000000 / bandwidth_eigrp + delay_eigrp / 10) * 256
        
        st.metric("EIGRP Metric", f"{int(metric):,}")
        
        # EIGRP Tables
        st.markdown("#### **EIGRP Tables**")
        
        table = st.selectbox("Select Table:", ["Neighbor Table", "Topology Table", "Routing Table"])
        
        if table == "Neighbor Table":
            st.code("""
            Address         Interface    Hold  Uptime   SRTT   RTO   Q
            10.1.1.2       Gi0/0        13    00:45:20  12    200   0
            10.1.2.2       Gi0/1        14    00:45:18  15    200   0
            """, language="text")
        
        elif table == "Topology Table":
            st.code("""
            P 192.168.1.0/24, 1 successors, FD is 2816
              via 10.1.1.2 (2816/2560), GigabitEthernet0/0
              via 10.1.2.2 (3072/2816), GigabitEthernet0/1 (Feasible Successor)
            """, language="text")

def mpls_lab():
    """MPLS Technology"""
    
    st.markdown(create_lab_header("MPLS Lab", "🌐", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # MPLS Theory
    with st.expander("📖 **MPLS Theory**", expanded=True):
        st.markdown("""
        ### 🏷️ **Multiprotocol Label Switching (MPLS)**
        
        MPLS is a data forwarding technology that speeds up network traffic flow using labels rather than complex routing lookups.
        
        **Components:**
        - **LER** - Label Edge Router (PE - Provider Edge)
        - **LSR** - Label Switching Router (P - Provider)
        - **LSP** - Label Switched Path
        - **FEC** - Forwarding Equivalence Class
        """)
    
    # Label Stack
    st.markdown("### 📚 **MPLS Label Stack**")
    
    num_labels = st.slider("Number of Labels:", 1, 3, 1)
    
    labels = []
    for i in range(num_labels):
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            label = st.number_input(f"Label {i+1}:", 16, 1048575, 100+i, key=f"label_{i}")
        with col2:
            exp = st.selectbox(f"EXP {i+1}:", list(range(8)), key=f"exp_{i}")
        with col3:
            s_bit = 1 if i == num_labels - 1 else 0
            st.metric(f"S-bit {i+1}", s_bit)
        with col4:
            ttl = st.number_input(f"TTL {i+1}:", 1, 255, 255, key=f"ttl_{i}")
        
        labels.append({"Label": label, "EXP": exp, "S": s_bit, "TTL": ttl})
    
    # Display label stack
    st.markdown("**Label Stack Structure:**")
    for i, label in enumerate(labels):
        st.code(f"Label {i+1}: [{label['Label']:20b} | {label['EXP']:3b} | {label['S']} | {label['TTL']:8b}]", language="text")
    
    # MPLS Operations
    st.markdown("### 🔄 **MPLS Operations**")
    
    operation = st.selectbox("Operation:", ["Push", "Swap", "Pop", "PHP (Penultimate Hop Popping)"])
    
    operations_info = {
        "Push": "Add label to packet (at ingress LER)",
        "Swap": "Replace label with new label (at LSR)",
        "Pop": "Remove label from packet (at egress LER)",
        "PHP": "Remove label at second-to-last hop"
    }
    
    st.info(f"**{operation}:** {operations_info[operation]}")
    
    # MPLS VPN
    st.markdown("### 🔐 **MPLS VPN (L3VPN)**")
    
    st.code("""
    ! PE Router Configuration
    ip vrf CUSTOMER_A
     rd 100:1
     route-target export 100:1
     route-target import 100:1
    
    interface GigabitEthernet0/0
     ip vrf forwarding CUSTOMER_A
     ip address 192.168.1.1 255.255.255.0
    
    router bgp 100
     address-family vpnv4
      neighbor 10.0.0.2 activate
      neighbor 10.0.0.2 send-community extended
    
     address-family ipv4 vrf CUSTOMER_A
      redistribute connected
    """, language="text")

def qos_lab():
    """Quality of Service"""
    
    st.markdown(create_lab_header("QoS Lab", "📡", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **QoS Theory**", expanded=True):
        st.markdown("""
        ### 📡 **Understanding Quality of Service (QoS)**
        
        QoS is a set of technologies that manage network resources by prioritizing certain types of traffic, 
        ensuring critical applications get the bandwidth and low latency they need.
        
        **Why QoS is Critical:**
        - 🎥 **Real-time Applications** - VoIP, video need low latency
        - 💼 **Business Critical** - ERP, databases need guaranteed bandwidth
        - 🎮 **User Experience** - Gaming, streaming need consistency
        - 💰 **Cost Optimization** - Better use of existing bandwidth
        
        **QoS Parameters:**
        
        1. **Bandwidth** - Minimum guaranteed rate
        2. **Latency** - End-to-end delay (< 150ms for VoIP)
        3. **Jitter** - Variation in delay (< 30ms for VoIP)
        4. **Packet Loss** - Acceptable loss rate (< 1% for VoIP)
        
        **QoS Models:**
        
        | Model | Approach | Scalability | Use Case |
        |-------|----------|-------------|----------|
        | Best Effort | No QoS | Excellent | Internet |
        | IntServ | Per-flow reservation | Poor | Small networks |
        | DiffServ | Per-class marking | Good | Enterprise/ISP |
        
        **Traffic Classification:**
        - **EF (Expedited Forwarding)** - Low latency (VoIP)
        - **AF (Assured Forwarding)** - Guaranteed delivery
        - **CS (Class Selector)** - Backward compatible
        - **BE (Best Effort)** - Default treatment
        
        **QoS Mechanisms:**
        - **Classification** - Identify traffic types
        - **Marking** - Tag packets (DSCP, CoS)
        - **Policing** - Drop excess traffic
        - **Shaping** - Smooth traffic bursts
        - **Queuing** - Prioritize packets (WFQ, PQ, CBWFQ)
        
        **Best Practices:**
        - Classify traffic close to source
        - Use DSCP marking consistently
        - Police at network edge
        - Shape at WAN interfaces
        - Monitor QoS effectiveness
        """)
    
    # QoS Models
    st.markdown("### 🎯 **QoS Models**")
    
    model = st.selectbox("QoS Model:", ["Best Effort", "IntServ", "DiffServ"])
    
    if model == "Best Effort":
        st.warning("No QoS - First Come, First Served")
    elif model == "IntServ":
        st.info("Integrated Services - Per-flow reservation (RSVP)")
    else:  # DiffServ
        st.success("Differentiated Services - Per-class QoS")
        
        # DSCP Values
        st.markdown("#### **DSCP Values**")
        
        dscp_data = {
            "Class": ["EF", "AF41", "AF31", "AF21", "AF11", "CS0"],
            "DSCP": [46, 34, 26, 18, 10, 0],
            "Binary": ["101110", "100010", "011010", "010010", "001010", "000000"],
            "Application": ["Voice", "Video", "Critical Data", "Bulk Data", "Standard", "Best Effort"]
        }
        
        st.dataframe(pd.DataFrame(dscp_data), use_container_width=True)
    
    # QoS Mechanisms
    st.markdown("### 🛠️ **QoS Mechanisms**")
    
    mechanism = st.selectbox("Mechanism:", ["Classification", "Marking", "Policing", "Shaping", "Queuing"])
    
    if mechanism == "Classification":
        st.code("""
        class-map match-any VOICE
         match dscp ef
         match protocol rtp
        
        class-map match-all VIDEO
         match dscp af41
         match access-group 101
        """, language="text")
    
    elif mechanism == "Policing":
        cir = st.number_input("CIR (Mbps):", 1, 1000, 10)
        burst = st.number_input("Burst (KB):", 1, 1000, 100)
        
        st.code(f"""
        policy-map POLICE_TRAFFIC
         class BULK_DATA
          police cir {cir}000000 bc {burst}000
           conform-action transmit
           exceed-action drop
        """, language="text")
    
    elif mechanism == "Queuing":
        st.markdown("#### **Queuing Methods**")
        
        queue_method = st.radio("Method:", ["FIFO", "PQ", "WFQ", "CBWFQ", "LLQ"])
        
        queue_info = {
            "FIFO": "First In, First Out - No prioritization",
            "PQ": "Priority Queuing - Strict priority",
            "WFQ": "Weighted Fair Queuing - Flow-based",
            "CBWFQ": "Class-Based WFQ - Guaranteed bandwidth",
            "LLQ": "Low Latency Queuing - Priority + CBWFQ"
        }
        
        st.info(queue_info[queue_method])

def vpn_technologies_lab():
    """VPN Technologies"""
    
    st.markdown(create_lab_header("VPN Technologies Lab", "🔒", "linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **VPN Theory**", expanded=True):
        st.markdown("""
        ### 🔐 **Understanding VPN Technologies**
        
        Virtual Private Networks (VPNs) create secure, encrypted tunnels over public networks, enabling 
        private communication and extending corporate networks across the Internet.
        
        **VPN Use Cases:**
        - 🏢 **Site-to-Site** - Connect branch offices
        - 👤 **Remote Access** - Work from home/anywhere
        - 🌐 **Extranet** - Partner connectivity
        - 🔒 **Privacy** - Hide traffic from ISP
        
        **VPN Types:**
        
        1. **IPSec VPN**
           - Layer 3 encryption
           - Site-to-site primary use
           - IKEv1/IKEv2 key exchange
           - ESP/AH protocols
           - Hardware accelerated
        
        2. **SSL/TLS VPN**
           - Layer 4-7 encryption
           - Clientless access
           - Browser-based
           - Easier firewall traversal
           - Remote access focus
        
        3. **MPLS VPN**
           - Layer 2.5 technology
           - Service provider managed
           - QoS guaranteed
           - No encryption by default
           - Enterprise WAN
        
        **VPN Protocols Comparison:**
        
        | Protocol | Speed | Security | NAT Friendly | Use Case |
        |----------|-------|----------|--------------|----------|
        | IPSec | Fast | Excellent | No | Site-to-site |
        | OpenVPN | Good | Excellent | Yes | Remote access |
        | WireGuard | Fastest | Good | Yes | Modern VPN |
        | L2TP/IPSec | Slow | Good | Limited | Legacy |
        | PPTP | Fast | Poor | Yes | Deprecated |
        
        **IPSec Components:**
        - **IKE** - Key exchange and SA establishment
        - **ESP** - Encryption and authentication
        - **AH** - Authentication only
        - **SA** - Security associations
        
        **VPN Security Considerations:**
        - Strong encryption (AES-256)
        - Perfect Forward Secrecy (PFS)
        - Certificate-based authentication
        - Split tunneling risks
        - DNS leak prevention
        
        **Best Practices:**
        - Use IKEv2 over IKEv1
        - Implement DPD (Dead Peer Detection)
        - Regular key rotation
        - Monitor VPN logs
        - Test failover scenarios
        """)
    
    # VPN Types
    vpn_type = st.selectbox("VPN Type:", ["IPSec", "SSL/TLS", "MPLS VPN", "DMVPN", "SD-WAN"])
    
    if vpn_type == "IPSec":
        st.markdown("### 🔐 **IPSec VPN**")
        
        # IPSec Phases
        st.markdown("#### **IPSec Phases**")
        
        phase = st.radio("Phase:", ["Phase 1 (IKE)", "Phase 2 (IPSec)"])
        
        if phase == "Phase 1 (IKE)":
            st.code("""
            crypto isakmp policy 10
             encr aes 256
             authentication pre-share
             group 14
             lifetime 86400
            
            crypto isakmp key MySecretKey address 203.0.113.1
            """, language="text")
        else:
            st.code("""
            crypto ipsec transform-set AES256-SHA esp-aes 256 esp-sha-hmac
             mode tunnel
            
            crypto map MYMAP 10 ipsec-isakmp
             set peer 203.0.113.1
             set transform-set AES256-SHA
             match address VPN-TRAFFIC
            """, language="text")
        
        # IPSec Modes
        st.markdown("#### **IPSec Modes**")
        
        mode = st.radio("Mode:", ["Tunnel Mode", "Transport Mode"])
        
        if mode == "Tunnel Mode":
            st.info("Entire IP packet encrypted and encapsulated - Used for site-to-site")
        else:
            st.info("Only payload encrypted - Used for host-to-host")
    
    elif vpn_type == "SSL/TLS":
        st.markdown("### 🌐 **SSL/TLS VPN**")
        
        st.code("""
        ! ASA SSL VPN Configuration
        webvpn
         enable outside
         anyconnect image disk0:/anyconnect.pkg
         anyconnect enable
         tunnel-group-list enable
        
        group-policy SSL_VPN_POLICY internal
        group-policy SSL_VPN_POLICY attributes
         vpn-tunnel-protocol ssl-client
         address-pools value VPN_POOL
         
        username john password P@ssw0rd123
        username john attributes
         vpn-group-policy SSL_VPN_POLICY
        """, language="text")
    
    elif vpn_type == "DMVPN":
        st.markdown("### 🌟 **Dynamic Multipoint VPN**")
        
        st.code("""
        ! Hub Configuration
        interface Tunnel0
         ip address 10.0.0.1 255.255.255.0
         ip nhrp map multicast dynamic
         ip nhrp network-id 100
         tunnel source GigabitEthernet0/0
         tunnel mode gre multipoint
         tunnel key 100
        
        ! Spoke Configuration
        interface Tunnel0
         ip address 10.0.0.2 255.255.255.0
         ip nhrp map 10.0.0.1 203.0.113.1
         ip nhrp map multicast 203.0.113.1
         ip nhrp network-id 100
         ip nhrp nhs 10.0.0.1
         tunnel source GigabitEthernet0/0
         tunnel mode gre multipoint
         tunnel key 100
        """, language="text")

def sdn_nfv_lab():
    """Software-Defined Networking and NFV"""
    
    st.markdown(create_lab_header("SDN & NFV Lab", "☁️", "linear-gradient(90deg, #FC466B 0%, #3F5EFB 100%)"), unsafe_allow_html=True)
    
    # SDN Architecture
    st.markdown("### 🏗️ **SDN Architecture**")
    
    layer = st.selectbox("SDN Layer:", ["Application Layer", "Control Layer", "Infrastructure Layer"])
    
    layer_info = {
        "Application Layer": {
            "Components": "Business Applications, Network Services",
            "Examples": "Load balancers, Firewalls, Monitoring",
            "Interface": "Northbound APIs (REST)"
        },
        "Control Layer": {
            "Components": "SDN Controller, Network OS",
            "Examples": "OpenDaylight, ONOS, Floodlight",
            "Interface": "Southbound APIs (OpenFlow)"
        },
        "Infrastructure Layer": {
            "Components": "Network Devices, Switches",
            "Examples": "OpenFlow switches, Virtual switches",
            "Interface": "Data plane forwarding"
        }
    }
    
    info = layer_info[layer]
    for key, value in info.items():
        st.info(f"**{key}:** {value}")
    
    # OpenFlow
    st.markdown("### 🔄 **OpenFlow Protocol**")
    
    st.code("""
    # OpenFlow Flow Entry Structure
    
    Match Fields:
    - In Port: 1
    - Src MAC: 00:11:22:33:44:55
    - Dst MAC: 66:77:88:99:AA:BB
    - Eth Type: 0x0800 (IPv4)
    - Src IP: 192.168.1.100
    - Dst IP: 10.0.0.50
    - Protocol: TCP (6)
    - Src Port: 12345
    - Dst Port: 80
    
    Actions:
    - Set VLAN ID: 100
    - Output: Port 2
    
    Priority: 1000
    Cookie: 0x1234
    Idle Timeout: 300
    Hard Timeout: 0
    """, language="yaml")
    
    # NFV
    st.markdown("### 📦 **Network Functions Virtualization**")
    
    vnf = st.selectbox("Virtual Network Function:", ["vRouter", "vFirewall", "vLoad Balancer", "vIDS/IPS"])
    
    vnf_config = {
        "vRouter": """
        # Virtual Router Configuration
        interfaces:
          - name: eth0
            ip: 192.168.1.1/24
          - name: eth1
            ip: 10.0.0.1/24
        
        routing:
          static:
            - dest: 0.0.0.0/0
              gateway: 192.168.1.254
        """,
        "vFirewall": """
        # Virtual Firewall Rules
        rules:
          - action: allow
            source: 192.168.1.0/24
            dest: any
            protocol: tcp
            port: 80,443
          
          - action: deny
            source: any
            dest: any
            protocol: all
        """
    }
    
    if vnf in vnf_config:
        st.code(vnf_config[vnf], language="yaml")

def load_balancing_lab():
    """Load Balancing Technologies"""
    
    st.markdown(create_lab_header("Load Balancing Lab", "🌊", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Load Balancing Theory**", expanded=True):
        st.markdown("""
        ### ⚖️ **Understanding Load Balancing**
        
        Load balancing distributes network traffic across multiple servers to ensure no single server 
        becomes overwhelmed, improving application availability, reliability, and scalability.
        
        **Why Load Balancing?**
        - 🚀 **Scalability** - Handle more traffic
        - 🛡️ **High Availability** - No single point of failure
        - 🎯 **Performance** - Optimal resource utilization
        - 🔧 **Maintenance** - Zero-downtime updates
        
        **Load Balancing Algorithms:**
        
        1. **Round Robin**
           - Sequential distribution
           - Simple, equal distribution
           - Ignores server capacity
           - Good for uniform servers
        
        2. **Weighted Round Robin**
           - Capacity-based distribution
           - Higher weight = more traffic
           - Better for mixed hardware
        
        3. **Least Connections**
           - Routes to least busy server
           - Good for long-lived connections
           - Considers current load
        
        4. **IP Hash**
           - Client IP determines server
           - Session persistence
           - Uneven distribution possible
        
        5. **Least Response Time**
           - Fastest server gets traffic
           - Optimal user experience
           - Complex to implement
        
        **Load Balancer Types:**
        
        | Type | OSI Layer | Pros | Cons | Use Case |
        |------|-----------|------|------|----------|
        | L4 (Network) | Layer 4 | Fast, simple | No app awareness | TCP/UDP traffic |
        | L7 (Application) | Layer 7 | Content-based | Higher latency | HTTP/HTTPS |
        | Global | Multi-site | Geo-distribution | Complex | CDN, DR |
        | DNS | Layer 3 | Simple | No health checks | Basic distribution |
        
        **Health Checks:**
        - **ICMP Ping** - Basic connectivity
        - **TCP Check** - Port availability
        - **HTTP/HTTPS** - Application response
        - **Custom Scripts** - Complex validation
        
        **Session Persistence:**
        - **Source IP** - Same client → same server
        - **Cookie-based** - HTTP cookie tracking
        - **SSL Session ID** - SSL persistence
        
        **Best Practices:**
        - Implement health checks
        - Use session persistence wisely
        - Monitor server metrics
        - Plan for failure scenarios
        - Regular capacity planning
        """)
    
    # Load Balancing Algorithms
    st.markdown("### ⚖️ **Load Balancing Algorithms**")
    
    algorithm = st.selectbox("Algorithm:", ["Round Robin", "Least Connections", "Weighted", "IP Hash", "Least Response Time"])
    
    # Simulate load distribution
    num_servers = st.slider("Number of Servers:", 2, 6, 3)
    num_requests = st.slider("Number of Requests:", 10, 100, 50)
    
    if st.button("Simulate Load Distribution", key="sim_load"):
        servers = [f"Server-{i+1}" for i in range(num_servers)]
        distribution = {}
        
        if algorithm == "Round Robin":
            for i in range(num_requests):
                server = servers[i % num_servers]
                distribution[server] = distribution.get(server, 0) + 1
        
        elif algorithm == "Weighted":
            weights = [random.randint(1, 5) for _ in range(num_servers)]
            st.info(f"Server weights: {dict(zip(servers, weights))}")
            
            weighted_servers = []
            for server, weight in zip(servers, weights):
                weighted_servers.extend([server] * weight)
            
            for i in range(num_requests):
                server = weighted_servers[i % len(weighted_servers)]
                distribution[server] = distribution.get(server, 0) + 1
        
        else:  # Random for demonstration
            for _ in range(num_requests):
                server = random.choice(servers)
                distribution[server] = distribution.get(server, 0) + 1
        
        # Visualize distribution
        fig = go.Figure(data=[go.Bar(
            x=list(distribution.keys()),
            y=list(distribution.values()),
            text=list(distribution.values()),
            textposition='auto'
        )])
        
        fig.update_layout(
            title=f"Request Distribution - {algorithm}",
            xaxis_title="Server",
            yaxis_title="Number of Requests"
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    # Health Checks
    st.markdown("### 🏥 **Health Check Configuration**")
    
    check_type = st.selectbox("Check Type:", ["TCP", "HTTP", "HTTPS", "Ping"])
    
    col1, col2 = st.columns(2)
    
    with col1:
        interval = st.number_input("Check Interval (s):", 1, 60, 5)
        timeout = st.number_input("Timeout (s):", 1, 30, 3)
    
    with col2:
        retries = st.number_input("Retries:", 1, 10, 3)
        
    if check_type == "HTTP":
        path = st.text_input("Health Check Path:", "/health")
        expected_code = st.number_input("Expected Status Code:", 100, 599, 200)
        
        st.code(f"""
        health_check:
          type: {check_type}
          path: {path}
          expected: {expected_code}
          interval: {interval}
          timeout: {timeout}
          retries: {retries}
        """, language="yaml")

def network_monitoring_lab():
    """Network Monitoring and Management"""
    
    st.markdown(create_lab_header("Network Monitoring Lab", "📊", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # SNMP
    st.markdown("### 📡 **SNMP Monitoring**")
    
    snmp_version = st.selectbox("SNMP Version:", ["SNMPv1", "SNMPv2c", "SNMPv3"])
    
    if snmp_version == "SNMPv3":
        st.code("""
        ! SNMPv3 Configuration
        snmp-server group MONITOR v3 priv
        snmp-server user admin MONITOR v3 auth sha AuthPass123 priv aes 128 PrivPass123
        snmp-server host 192.168.1.100 version 3 priv admin
        
        ! Common OIDs
        sysDescr:    1.3.6.1.2.1.1.1.0
        sysUpTime:   1.3.6.1.2.1.1.3.0
        ifInOctets:  1.3.6.1.2.1.2.2.1.10
        ifOutOctets: 1.3.6.1.2.1.2.2.1.16
        """, language="text")
    
    # NetFlow
    st.markdown("### 🌊 **NetFlow/IPFIX**")
    
    st.code("""
    ! NetFlow Configuration
    flow record NETFLOW-RECORD
     match ipv4 source address
     match ipv4 destination address
     match transport source-port
     match transport destination-port
     match ipv4 protocol
     collect counter bytes
     collect counter packets
     collect timestamp sys-uptime first
     collect timestamp sys-uptime last
    
    flow exporter NETFLOW-EXPORTER
     destination 192.168.1.100
     source GigabitEthernet0/0
     transport udp 2055
    
    flow monitor NETFLOW-MONITOR
     record NETFLOW-RECORD
     exporter NETFLOW-EXPORTER
    
    interface GigabitEthernet0/1
     ip flow monitor NETFLOW-MONITOR input
     ip flow monitor NETFLOW-MONITOR output
    """, language="text")
    
    # Monitoring Metrics
    st.markdown("### 📈 **Key Performance Indicators**")
    
    # Simulate metrics
    metrics = {
        "Metric": ["Bandwidth Utilization", "Packet Loss", "Latency", "Jitter", "CPU Usage", "Memory Usage"],
        "Current": [f"{random.randint(30, 90)}%", f"{random.random():.2f}%", f"{random.randint(10, 50)}ms", 
                   f"{random.randint(1, 10)}ms", f"{random.randint(20, 80)}%", f"{random.randint(40, 85)}%"],
        "Threshold": ["80%", "1%", "100ms", "20ms", "85%", "90%"],
        "Status": ["🟢", "🟢", "🟢", "🟢", "🟡", "🟢"]
    }
    
    df_metrics = pd.DataFrame(metrics)
    st.dataframe(df_metrics, use_container_width=True)

def ipv6_advanced_lab():
    """IPv6 Advanced Topics"""
    
    st.markdown(create_lab_header("IPv6 Advanced Lab", "🚀", "linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%)"), unsafe_allow_html=True)
    
    # IPv6 Addressing
    st.markdown("### 🔢 **IPv6 Address Types**")
    
    addr_type = st.selectbox("Address Type:", ["Global Unicast", "Link-Local", "Unique Local", "Multicast", "Anycast"])
    
    addr_info = {
        "Global Unicast": {
            "Range": "2000::/3",
            "Purpose": "Internet routable addresses",
            "Example": "2001:db8:1234:5678::1/64"
        },
        "Link-Local": {
            "Range": "fe80::/10",
            "Purpose": "Single link communication",
            "Example": "fe80::1234:5678:90ab:cdef%eth0"
        },
        "Unique Local": {
            "Range": "fc00::/7",
            "Purpose": "Private addressing",
            "Example": "fd00:1234:5678::1/64"
        },
        "Multicast": {
            "Range": "ff00::/8",
            "Purpose": "One-to-many communication",
            "Example": "ff02::1 (all nodes), ff02::2 (all routers)"
        }
    }
    
    if addr_type in addr_info:
        info = addr_info[addr_type]
        for key, value in info.items():
            st.info(f"**{key}:** {value}")
    
    # IPv6 Transition
    st.markdown("### 🔄 **IPv6 Transition Mechanisms**")
    
    mechanism = st.selectbox("Transition Mechanism:", ["Dual Stack", "Tunneling", "NAT64/DNS64", "6to4", "Teredo"])
    
    if mechanism == "Dual Stack":
        st.code("""
        interface GigabitEthernet0/0
         ip address 192.168.1.1 255.255.255.0
         ipv6 address 2001:db8:1234::1/64
         ipv6 enable
        
        ! Both IPv4 and IPv6 running simultaneously
        """, language="text")
    
    elif mechanism == "Tunneling":
        st.code("""
        interface Tunnel0
         ipv6 address 2001:db8:abcd::1/64
         tunnel source 203.0.113.1
         tunnel destination 198.51.100.1
         tunnel mode ipv6ip
        """, language="text")
    
    # IPv6 Features
    st.markdown("### ✨ **IPv6 Features**")
    
    feature = st.selectbox("Feature:", ["Stateless Autoconfiguration", "Neighbor Discovery", "DHCPv6", "IPv6 Security"])
    
    if feature == "Stateless Autoconfiguration":
        st.code("""
        1. Router sends Router Advertisement (RA)
        2. Host generates link-local address (fe80::)
        3. Host performs DAD (Duplicate Address Detection)
        4. Host configures global address using prefix from RA
        5. Host uses router as default gateway
        
        ! Router configuration
        interface GigabitEthernet0/0
         ipv6 address 2001:db8:1234::1/64
         ipv6 nd prefix 2001:db8:1234::/64
         no ipv6 nd suppress-ra
        """, language="text")

def redundancy_lab():
    """Network Redundancy Protocols"""
    
    st.markdown(create_lab_header("Redundancy Lab", "🔄", "linear-gradient(90deg, #FC466B 0%, #3F5EFB 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Redundancy Theory**", expanded=True):
        st.markdown("""
        ### 🔄 **Understanding Network Redundancy**
        
        Network redundancy eliminates single points of failure by providing alternate paths and backup 
        systems, ensuring high availability and business continuity.
        
        **Why Redundancy?**
        - 🛡️ **High Availability** - 99.999% uptime (5 nines)
        - 🔄 **Failover** - Automatic recovery
        - ⚖️ **Load Balancing** - Distribute traffic
        - 🔧 **Maintenance** - Zero downtime updates
        - 💰 **Business Continuity** - Prevent revenue loss
        
        **First Hop Redundancy Protocols (FHRP):**
        
        | Protocol | Vendor | Priority | Preempt | Load Balance | Virtual MAC |
        |----------|---------|----------|---------|--------------|-------------|
        | HSRP | Cisco | 0-255 | Yes | Groups | 0000.0c07.acXX |
        | VRRP | Standard | 1-254 | Yes | Multiple | 0000.5e00.01XX |
        | GLBP | Cisco | 0-255 | Yes | Per-host | 0007.b400.XXYY |
        
        **HSRP States:**
        1. **Initial** - Starting state
        2. **Learn** - Learning virtual IP
        3. **Listen** - Monitoring hellos
        4. **Speak** - Sending hellos
        5. **Standby** - Backup router
        6. **Active** - Forwarding traffic
        
        **Spanning Tree Protocol (STP):**
        - **Purpose** - Prevent Layer 2 loops
        - **Root Bridge** - Lowest bridge ID
        - **Port States** - Blocking, Listening, Learning, Forwarding
        - **Convergence** - 30-50 seconds (classic)
        
        **STP Variants:**
        - **STP (802.1D)** - Original, slow convergence
        - **RSTP (802.1w)** - Rapid convergence (< 2 sec)
        - **MSTP (802.1s)** - Multiple instances
        - **PVST+** - Per-VLAN spanning tree
        
        **Link Aggregation (LAG):**
        - **LACP (802.3ad)** - Standard protocol
        - **PAgP** - Cisco proprietary
        - **Static** - Manual configuration
        - **Benefits** - Increased bandwidth, redundancy
        
        **Redundancy Design Patterns:**
        
        1. **Active/Passive**
           - One active, one standby
           - Simple failover
           - 50% resource utilization
        
        2. **Active/Active**
           - Both processing traffic
           - Load balanced
           - 100% resource utilization
        
        3. **N+1**
           - N active, 1 spare
           - Cost effective
           - Good for multiple systems
        
        **Convergence Times:**
        - HSRP: 3-10 seconds
        - VRRP: < 3 seconds
        - GLBP: 3-10 seconds
        - RSTP: < 2 seconds
        - LACP: < 1 second
        
        **Best Practices:**
        - Implement multiple redundancy layers
        - Test failover regularly
        - Monitor redundancy protocols
        - Document failover procedures
        - Use consistent priorities
        - Enable preemption carefully
        """)
    
    # HSRP/VRRP/GLBP
    protocol = st.selectbox("Redundancy Protocol:", ["HSRP", "VRRP", "GLBP"])
    
    if protocol == "HSRP":
        st.markdown("### 🔄 **Hot Standby Router Protocol**")
        
        priority = st.slider("Priority:", 1, 255, 100)
        preempt = st.checkbox("Preemption Enabled", value=True)
        
        st.code(f"""
        interface GigabitEthernet0/0
         ip address 192.168.1.2 255.255.255.0
         standby 1 ip 192.168.1.1
         standby 1 priority {priority}
         {'standby 1 preempt' if preempt else '! preempt disabled'}
         standby 1 authentication md5 key-string MySecret
         standby 1 track 1 decrement 10
        """, language="text")
        
        # HSRP States
        st.markdown("#### **HSRP States**")
        states = ["Initial", "Learn", "Listen", "Speak", "Standby", "Active"]
        current_state = st.select_slider("State Transition:", states)
        
        state_info = {
            "Initial": "Starting state",
            "Learn": "Waiting for hello from active router",
            "Listen": "Router knows virtual IP",
            "Speak": "Sending hellos, participating in election",
            "Standby": "Backup router, monitoring active",
            "Active": "Forwarding packets for virtual IP"
        }
        
        st.info(state_info[current_state])
    
    elif protocol == "VRRP":
        st.markdown("### 🔄 **Virtual Router Redundancy Protocol**")
        
        st.code("""
        interface GigabitEthernet0/0
         ip address 192.168.1.2 255.255.255.0
         vrrp 1 ip 192.168.1.1
         vrrp 1 priority 120
         vrrp 1 preempt
         vrrp 1 authentication text MyPassword
        """, language="text")
    
    else:  # GLBP
        st.markdown("### 🔄 **Gateway Load Balancing Protocol**")
        
        st.code("""
        interface GigabitEthernet0/0
         ip address 192.168.1.2 255.255.255.0
         glbp 1 ip 192.168.1.1
         glbp 1 priority 120
         glbp 1 preempt
         glbp 1 load-balancing round-robin
         glbp 1 authentication md5 key-string MySecret
        """, language="text")

def performance_lab():
    """Network Performance Optimization"""
    
    st.markdown(create_lab_header("Performance Lab", "📈", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Performance Theory**", expanded=True):
        st.markdown("""
        ### 📈 **Understanding Network Performance**
        
        Network performance optimization involves measuring, analyzing, and improving various metrics 
        to ensure optimal data transmission and user experience.
        
        **Key Performance Indicators (KPIs):**
        
        1. **Bandwidth**
           - Theoretical maximum capacity
           - Measured in bps, Mbps, Gbps
           - Shared vs dedicated
           - Symmetric vs asymmetric
        
        2. **Throughput**
           - Actual data transfer rate
           - Always less than bandwidth
           - Affected by protocol overhead
           - Goodput = useful data only
        
        3. **Latency**
           - Round-trip time (RTT)
           - One-way delay
           - Components: Propagation + Transmission + Processing + Queuing
           - Target: < 150ms for VoIP
        
        4. **Jitter**
           - Variation in latency
           - Critical for real-time apps
           - Target: < 30ms for VoIP
           - Buffer to compensate
        
        5. **Packet Loss**
           - Dropped packets percentage
           - Causes: Congestion, errors, QoS
           - Target: < 1% for VoIP
           - < 0.1% for video
        
        **Performance Testing Methods:**
        
        | Test Type | Tool | Measures | Use Case |
        |-----------|------|----------|----------|
        | Speed Test | iPerf | Throughput | Bandwidth validation |
        | Ping | ICMP | Latency, Loss | Basic connectivity |
        | Traceroute | ICMP/UDP | Path, Hop latency | Route analysis |
        | NetFlow | Flow data | Traffic patterns | Capacity planning |
        | SNMP | Polling | Interface stats | Monitoring |
        
        **Optimization Techniques:**
        
        1. **TCP Tuning**
           - Window scaling
           - Selective ACK (SACK)
           - TCP timestamps
           - Congestion control (BBR, CUBIC)
        
        2. **Buffer Management**
           - Buffer bloat prevention
           - Active Queue Management (AQM)
           - RED, CoDel algorithms
           - Optimal buffer sizing
        
        3. **MTU Optimization**
           - Standard: 1500 bytes
           - Jumbo frames: 9000 bytes
           - Path MTU Discovery
           - Fragmentation avoidance
        
        4. **Load Distribution**
           - ECMP (Equal Cost Multi-Path)
           - LAG (Link Aggregation)
           - Traffic engineering
           - Anycast routing
        
        **Common Bottlenecks:**
        - **WAN Links** - Limited bandwidth
        - **Firewall** - Deep inspection overhead
        - **DNS** - Resolution delays
        - **Application** - Processing limits
        - **Database** - Query performance
        
        **Performance Formulas:**
        - **Bandwidth-Delay Product** = Bandwidth × RTT
        - **TCP Window Size** = BDP for optimal performance
        - **Serialization Delay** = Frame Size / Link Speed
        - **Propagation Delay** = Distance / Speed of Light
        
        **Best Practices:**
        - Baseline normal performance
        - Monitor continuously
        - Capacity planning (70% rule)
        - Regular performance testing
        - Document changes impact
        - Use CDN for content delivery
        """)
    
    # TCP Optimization
    st.markdown("### 🚀 **TCP Performance Tuning**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        window_size = st.number_input("TCP Window Size (KB):", 1, 1024, 64)
        mss = st.number_input("MSS (bytes):", 100, 9000, 1460)
    
    with col2:
        rtt = st.number_input("RTT (ms):", 1, 1000, 50)
        packet_loss = st.slider("Packet Loss (%):", 0.0, 10.0, 0.1)
    
    # Calculate throughput
    if st.button("Calculate Throughput", key="calc_throughput"):
        # Simplified calculation
        bandwidth = (window_size * 1024 * 8) / (rtt / 1000)  # bits per second
        effective_bandwidth = bandwidth * (1 - packet_loss / 100)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Theoretical Throughput", f"{bandwidth/1000000:.2f} Mbps")
        with col2:
            st.metric("Effective Throughput", f"{effective_bandwidth/1000000:.2f} Mbps")
        with col3:
            st.metric("Efficiency", f"{(1 - packet_loss/100)*100:.1f}%")
    
    # Jumbo Frames
    st.markdown("### 📦 **Jumbo Frames Configuration**")
    
    jumbo_size = st.selectbox("Jumbo Frame Size:", ["9000", "9216", "9600"])
    
    st.code(f"""
    ! Switch Configuration
    system mtu jumbo {jumbo_size}
    
    ! Interface Configuration
    interface GigabitEthernet0/1
     mtu {jumbo_size}
    
    ! Linux Configuration
    sudo ifconfig eth0 mtu {jumbo_size}
    # or
    sudo ip link set dev eth0 mtu {jumbo_size}
    """, language="text")
    
    # Buffer Tuning
    st.markdown("### 💾 **Buffer Tuning**")
    
    st.code("""
    ! Cisco Buffer Tuning
    buffers small permanent 50
    buffers small max-free 100
    buffers middle permanent 25
    buffers middle max-free 50
    buffers big permanent 50
    buffers big max-free 75
    
    ! Linux TCP Buffer Tuning
    # /etc/sysctl.conf
    net.core.rmem_max = 134217728
    net.core.wmem_max = 134217728
    net.ipv4.tcp_rmem = 4096 87380 134217728
    net.ipv4.tcp_wmem = 4096 65536 134217728
    """, language="text")

def troubleshooting_lab():
    """Network Troubleshooting Guide"""
    
    st.markdown(create_lab_header("Troubleshooting Lab", "🎯", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Troubleshooting Methodology
    st.markdown("### 🔍 **Troubleshooting Methodology**")
    
    step = st.selectbox("Step:", [
        "1. Define Problem",
        "2. Gather Information",
        "3. Analyze Information",
        "4. Eliminate Possibilities",
        "5. Propose Hypothesis",
        "6. Test Hypothesis",
        "7. Solve Problem"
    ])
    
    step_details = {
        "1. Define Problem": "Clearly identify symptoms and affected services",
        "2. Gather Information": "Collect logs, configs, topology info",
        "3. Analyze Information": "Look for patterns and anomalies",
        "4. Eliminate Possibilities": "Rule out working components",
        "5. Propose Hypothesis": "Form theory about root cause",
        "6. Test Hypothesis": "Verify theory with targeted tests",
        "7. Solve Problem": "Implement and verify solution"
    }
    
    st.info(step_details[step])
    
    # Common Issues
    st.markdown("### ⚠️ **Common Network Issues**")
    
    issue = st.selectbox("Issue Type:", ["Connectivity", "Performance", "Intermittent", "Configuration", "Security"])
    
    if issue == "Connectivity":
        st.markdown("#### **Connectivity Troubleshooting**")
        
        st.code("""
        # Layer 1 - Physical
        show interface status
        show interface gi0/1 | include errors
        
        # Layer 2 - Data Link
        show mac address-table
        show spanning-tree
        show vlan brief
        
        # Layer 3 - Network
        show ip route
        show ip arp
        ping 192.168.1.1
        traceroute 8.8.8.8
        
        # Layer 4 - Transport
        show ip sockets
        netstat -an
        telnet 192.168.1.1 80
        """, language="text")
    
    elif issue == "Performance":
        st.markdown("#### **Performance Troubleshooting**")
        
        st.code("""
        # Interface statistics
        show interface gi0/1 | include rate
        show interface gi0/1 | include drops|errors
        
        # CPU and Memory
        show processes cpu history
        show memory statistics
        
        # QoS verification
        show policy-map interface
        show queue interface
        
        # Buffer statistics
        show buffers
        show interface gi0/1 | include queue
        """, language="text")
    
    # Debug Commands
    st.markdown("### 🐛 **Debug Commands**")
    
    st.warning("⚠️ **Warning:** Debug commands can impact device performance. Use with caution!")
    
    debug_category = st.selectbox("Debug Category:", ["Routing", "Switching", "Security", "QoS"])
    
    debug_commands = {
        "Routing": """
        debug ip routing
        debug ip ospf events
        debug ip bgp updates
        debug ip eigrp packets
        """,
        "Switching": """
        debug spanning-tree events
        debug vlan packets
        debug etherchannel events
        """,
        "Security": """
        debug crypto ipsec
        debug crypto isakmp
        debug aaa authentication
        """,
        "QoS": """
        debug qos
        debug priority
        debug queue
        """
    }
    
    if debug_category in debug_commands:
        st.code(debug_commands[debug_category], language="text")
    
    # Always remember to disable debug
    st.code("undebug all  # Always disable debug when done!", language="text")

if __name__ == "__main__":
    run_lab()
