
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

def run_lab():
    """Theory & Concepts Lab - Học các khái niệm và thủ thuật cybersecurity"""
    
    st.title("📚 Theory & Concepts Lab")
    st.markdown("---")
    
    # Tabs cho các chủ đề khác nhau
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🌐 Network Fundamentals", 
        "🔒 Security Principles",
        "🛡️ Attack Methodologies", 
        "🔐 Cryptography Concepts",
        "📊 Risk Assessment",
        "⚖️ Legal & Ethics"
    ])
    
    with tab1:
        network_fundamentals()
    
    with tab2:
        security_principles()
    
    with tab3:
        attack_methodologies()
        
    with tab4:
        cryptography_concepts()
        
    with tab5:
        risk_assessment()
        
    with tab6:
        legal_ethics()

def network_fundamentals():
    """Khái niệm cơ bản về mạng"""
    st.subheader("🌐 Network Fundamentals")
    
    concept_choice = st.selectbox("Chọn khái niệm:", [
        "OSI Model",
        "TCP/IP Stack", 
        "Network Protocols",
        "IP Addressing",
        "Routing & Switching",
        "Network Topologies"
    ])
    
    if concept_choice == "OSI Model":
        explain_osi_model()
    elif concept_choice == "TCP/IP Stack":
        explain_tcpip_stack()
    elif concept_choice == "Network Protocols":
        explain_network_protocols()
    elif concept_choice == "IP Addressing":
        explain_ip_addressing()
    elif concept_choice == "Routing & Switching":
        explain_routing_switching()
    elif concept_choice == "Network Topologies":
        explain_network_topologies()

def explain_osi_model():
    """Giải thích OSI Model"""
    st.markdown("### 📊 OSI Model (Open Systems Interconnection)")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("""
        **OSI Model** là mô hình 7 tầng mô tả cách dữ liệu được truyền qua mạng:
        
        **🎯 Mục đích:**
        - Chuẩn hóa giao tiếp mạng
        - Tách biệt các chức năng
        - Dễ dàng troubleshooting
        - Interoperability giữa các vendor
        """)
        
        # OSI Layers data
        osi_layers = [
            {"Layer": 7, "Name": "Application", "Function": "User Interface", "Examples": "HTTP, FTP, SMTP", "Attacks": "Phishing, Malware"},
            {"Layer": 6, "Name": "Presentation", "Function": "Data Format", "Examples": "SSL/TLS, JPEG", "Attacks": "Encryption attacks"},
            {"Layer": 5, "Name": "Session", "Function": "Session Management", "Examples": "NetBIOS, RPC", "Attacks": "Session hijacking"},
            {"Layer": 4, "Name": "Transport", "Function": "End-to-end Delivery", "Examples": "TCP, UDP", "Attacks": "Port scanning"},
            {"Layer": 3, "Name": "Network", "Function": "Routing", "Examples": "IP, ICMP", "Attacks": "IP spoofing"},
            {"Layer": 2, "Name": "Data Link", "Function": "Frame Delivery", "Examples": "Ethernet, WiFi", "Attacks": "MAC spoofing"},
            {"Layer": 1, "Name": "Physical", "Function": "Bits Transmission", "Examples": "Cables, Radio", "Attacks": "Wire tapping"}
        ]
        
        df = pd.DataFrame(osi_layers)
        st.dataframe(df, width='stretch')
    
    with col2:
        # Create OSI Model visualization
        fig = go.Figure()
        
        colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#98D8C8']
        
        for i, layer in enumerate(osi_layers):
            fig.add_trace(go.Bar(
                x=[layer['Name']],
                y=[1],
                name=f"Layer {layer['Layer']}: {layer['Name']}",
                marker_color=colors[i],
                text=f"L{layer['Layer']}: {layer['Name']}<br>{layer['Function']}",
                textposition='inside',
                showlegend=False
            ))
        
        fig.update_layout(
            title="OSI Model Layers",
            xaxis_title="Layers",
            yaxis_title="",
            barmode='stack',
            height=400,
            yaxis=dict(showticklabels=False)
        )
        
        st.plotly_chart(fig, width='stretch')
        
        st.markdown("""
        **🔍 Security Implications:**
        - Mỗi layer có các attack vectors riêng
        - Defense in depth strategy
        - Layer-specific security controls
        - Troubleshooting network issues
        """)

def explain_tcpip_stack():
    """Giải thích TCP/IP Stack"""
    st.markdown("### 🌐 TCP/IP Protocol Stack")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("""
        **TCP/IP Stack** là foundation của Internet, gồm 4 layers:
        
        **📚 So sánh với OSI:**
        - Practical implementation của networking
        - Được sử dụng rộng rãi trên Internet
        - Đơn giản hơn OSI (4 vs 7 layers)
        """)
        
        tcpip_layers = [
            {"Layer": 4, "Name": "Application", "OSI Equivalent": "5,6,7", "Protocols": "HTTP, FTP, SMTP, DNS", "Security": "Application firewalls"},
            {"Layer": 3, "Name": "Transport", "OSI Equivalent": "4", "Protocols": "TCP, UDP", "Security": "Port filtering"},
            {"Layer": 2, "Name": "Internet", "OSI Equivalent": "3", "Protocols": "IP, ICMP, ARP", "Security": "Packet filtering"},
            {"Layer": 1, "Name": "Network Access", "OSI Equivalent": "1,2", "Protocols": "Ethernet, WiFi", "Security": "Physical security"}
        ]
        
        df = pd.DataFrame(tcpip_layers)
        st.dataframe(df, width='stretch')
    
    with col2:
        st.markdown("""
        **🔒 Security tại mỗi layer:**
        
        **Application Layer:**
        - Input validation
        - Authentication & Authorization
        - Encryption (HTTPS, FTPS)
        
        **Transport Layer:**
        - Port security
        - Connection state tracking
        - Rate limiting
        
        **Internet Layer:**
        - IP filtering
        - Anti-spoofing
        - Routing security
        
        **Network Access Layer:**
        - Physical security
        - MAC filtering
        - VLAN segmentation
        """)
        
        # TCP vs UDP comparison
        st.markdown("#### 🔄 TCP vs UDP")
        
        comparison_data = {
            "Aspect": ["Connection", "Reliability", "Speed", "Overhead", "Use Cases"],
            "TCP": ["Connection-oriented", "Reliable", "Slower", "High", "Web, Email, File Transfer"],
            "UDP": ["Connectionless", "Best-effort", "Faster", "Low", "DNS, DHCP, Streaming"]
        }
        
        comp_df = pd.DataFrame(comparison_data)
        st.dataframe(comp_df, width='stretch')

def explain_network_protocols():
    """Giải thích các giao thức mạng"""
    st.markdown("### 📡 Network Protocols")
    
    protocol_category = st.selectbox("Chọn nhóm giao thức:", [
        "Application Layer Protocols",
        "Transport Layer Protocols",
        "Network Layer Protocols",
        "Security Protocols"
    ])
    
    if protocol_category == "Application Layer Protocols":
        st.markdown("""
        #### 🌐 Application Layer Protocols
        
        **HTTP/HTTPS (HyperText Transfer Protocol)**
        - **Mục đích:** Web communication
        - **Port:** 80 (HTTP), 443 (HTTPS)
        - **Security Issues:** Plaintext transmission (HTTP), Man-in-the-middle
        - **Mitigation:** Use HTTPS, HSTS headers
        
        **FTP/SFTP (File Transfer Protocol)**
        - **Mục đích:** File transfer
        - **Port:** 21 (FTP), 22 (SFTP)
        - **Security Issues:** Plaintext credentials, data transmission
        - **Mitigation:** Use SFTP or FTPS
        
        **SMTP (Simple Mail Transfer Protocol)**
        - **Mục đích:** Email transmission
        - **Port:** 25, 587, 465
        - **Security Issues:** Email spoofing, spam
        - **Mitigation:** SPF, DKIM, DMARC
        
        **DNS (Domain Name System)**
        - **Mục đích:** Domain name resolution
        - **Port:** 53
        - **Security Issues:** DNS poisoning, DDoS amplification
        - **Mitigation:** DNSSEC, DNS filtering
        """)
        
    elif protocol_category == "Security Protocols":
        st.markdown("""
        #### 🔒 Security Protocols
        
        **SSL/TLS (Secure Sockets Layer/Transport Layer Security)**
        - **Mục đích:** Encrypt communication
        - **Versions:** TLS 1.2, TLS 1.3 (recommended)
        - **Features:** Authentication, Encryption, Integrity
        - **Vulnerabilities:** POODLE, BEAST, Heartbleed
        
        **IPSec (Internet Protocol Security)**
        - **Mục đích:** IP layer security
        - **Modes:** Transport mode, Tunnel mode
        - **Protocols:** AH (Authentication Header), ESP (Encapsulating Security Payload)
        - **Use Cases:** VPNs, Site-to-site connections
        
        **SSH (Secure Shell)**
        - **Mục đích:** Secure remote access
        - **Port:** 22
        - **Features:** Authentication, Encryption, Tunneling
        - **Security:** Key-based authentication, disable root login
        """)

def explain_ip_addressing():
    """Giải thích IP Addressing"""
    st.markdown("### 🌐 IP Addressing & Subnetting")
    
    with st.expander("📖 Lý thuyết chi tiết về IP Addressing"):
        st.markdown("""
        ### 📍 IPv4 Addressing
        
        **IPv4 Structure:**
        - **32-bit address**: 4 octets (0-255 each)
        - **Format**: xxx.xxx.xxx.xxx
        - **Total addresses**: ~4.3 billion
        
        **IPv4 Classes:**
        
        **Class A**: 1.0.0.0 to 126.255.255.255
        - **Network bits**: 8, **Host bits**: 24
        - **Subnet mask**: 255.0.0.0 (/8)
        - **Networks**: 126, **Hosts per network**: 16,777,214
        
        **Class B**: 128.0.0.0 to 191.255.255.255
        - **Network bits**: 16, **Host bits**: 16
        - **Subnet mask**: 255.255.0.0 (/16)
        - **Networks**: 16,384, **Hosts per network**: 65,534
        
        **Class C**: 192.0.0.0 to 223.255.255.255
        - **Network bits**: 24, **Host bits**: 8
        - **Subnet mask**: 255.255.255.0 (/24)
        - **Networks**: 2,097,152, **Hosts per network**: 254
        
        ### 🔢 CIDR (Classless Inter-Domain Routing)
        
        **CIDR Notation:**
        - **Format**: IP/prefix (e.g., 192.168.1.0/24)
        - **Prefix**: Number of network bits
        - **Benefits**: Efficient address allocation, route aggregation
        
        **Common CIDR Blocks:**
        - **/30**: 4 addresses (2 usable) - Point-to-point links
        - **/29**: 8 addresses (6 usable) - Small networks
        - **/28**: 16 addresses (14 usable) - Small office
        - **/24**: 256 addresses (254 usable) - Standard subnet
        - **/16**: 65,536 addresses - Large network
        
        ### 🌍 IPv6 Addressing
        
        **IPv6 Structure:**
        - **128-bit address**: 8 groups of 4 hexadecimal digits
        - **Format**: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
        - **Total addresses**: ~340 undecillion
        
        **IPv6 Address Types:**
        - **Unicast**: One-to-one communication
        - **Multicast**: One-to-many communication
        - **Anycast**: One-to-nearest communication
        
        ### 🏠 Private vs Public IP
        
        **Private IP Ranges (RFC 1918):**
        - **10.0.0.0/8**: 10.0.0.0 - 10.255.255.255
        - **172.16.0.0/12**: 172.16.0.0 - 172.31.255.255
        - **192.168.0.0/16**: 192.168.0.0 - 192.168.255.255
        
        **Special IP Addresses:**
        - **127.0.0.1**: Loopback (localhost)
        - **0.0.0.0**: Default route
        - **255.255.255.255**: Broadcast
        - **169.254.x.x**: APIPA (Automatic Private IP)
        """)
    
    # IP Calculator
    st.markdown("#### 🧮 IP Subnet Calculator")
    
    col1, col2 = st.columns(2)
    
    with col1:
        ip_input = st.text_input("Enter IP Address:", "192.168.1.0")
        cidr_input = st.number_input("CIDR Prefix:", min_value=1, max_value=30, value=24)
    
    with col2:
        if st.button("Calculate Subnet"):
            try:
                # Simple subnet calculation
                network_bits = cidr_input
                host_bits = 32 - network_bits
                total_hosts = 2 ** host_bits
                usable_hosts = total_hosts - 2
                
                st.success(f"""
                **Subnet Information:**
                - Network: {ip_input}/{cidr_input}
                - Total addresses: {total_hosts}
                - Usable hosts: {usable_hosts}
                - Network bits: {network_bits}
                - Host bits: {host_bits}
                """)
            except:
                st.error("Invalid IP address format")

def explain_routing_switching():
    """Giải thích Routing & Switching"""
    st.markdown("### 🔄 Routing & Switching")
    
    with st.expander("📖 Lý thuyết chi tiết về Routing & Switching"):
        st.markdown("""
        ### 🌐 Routing Fundamentals
        
        **What is Routing?**
        - Process of selecting paths in a network
        - Determines best path for data packets
        - Operates at Layer 3 (Network Layer)
        
        **Routing Table Components:**
        - **Destination Network**: Target network address
        - **Next Hop**: Next router IP address
        - **Metric**: Cost of the route
        - **Interface**: Outgoing network interface
        
        **Types of Routing:**
        
        **1. Static Routing**
        - **Pros**: Simple, secure, no bandwidth overhead
        - **Cons**: Manual configuration, no automatic failover
        - **Use case**: Small networks, stub networks
        
        **2. Dynamic Routing**
        - **Pros**: Automatic updates, fault tolerance
        - **Cons**: Complex, bandwidth overhead, security risks
        - **Use case**: Large networks, redundant paths
        
        ### 📡 Routing Protocols
        
        **Distance Vector Protocols:**
        - **RIP (Routing Information Protocol)**
          - Metric: Hop count (max 15)
          - Update: Every 30 seconds
          - Convergence: Slow
        
        **Link State Protocols:**
        - **OSPF (Open Shortest Path First)**
          - Metric: Cost (bandwidth-based)
          - Algorithm: Dijkstra's shortest path
          - Convergence: Fast
        
        **Path Vector Protocols:**
        - **BGP (Border Gateway Protocol)**
          - Use: Internet routing between ISPs
          - Metric: AS path, policies
          - Scalability: Internet-scale
        
        ### 🔌 Switching Fundamentals
        
        **What is Switching?**
        - Forwards frames within a LAN
        - Operates at Layer 2 (Data Link Layer)
        - Uses MAC addresses for forwarding
        
        **Switch Operations:**
        
        **1. Learning**
        - Builds MAC address table
        - Associates MAC with port
        - Dynamic learning from source addresses
        
        **2. Flooding**
        - Unknown unicast frames
        - Broadcast frames
        - Multicast frames (unless configured)
        
        **3. Forwarding**
        - Known unicast frames
        - Direct to specific port
        - Based on MAC address table
        
        **4. Filtering**
        - Frames destined for same segment
        - Reduces network congestion
        - Improves security
        
        ### 🌳 Spanning Tree Protocol (STP)
        
        **Purpose:**
        - Prevents switching loops
        - Provides redundancy
        - Ensures single active path
        
        **STP States:**
        - **Blocking**: Receives BPDUs only
        - **Listening**: Processes BPDUs
        - **Learning**: Builds MAC table
        - **Forwarding**: Normal operation
        - **Disabled**: Port shutdown
        
        ### 🏷️ VLANs (Virtual LANs)
        
        **Benefits:**
        - **Segmentation**: Logical network separation
        - **Security**: Isolate sensitive traffic
        - **Performance**: Reduce broadcast domains
        - **Flexibility**: Easy reconfiguration
        
        **VLAN Types:**
        - **Data VLAN**: User traffic
        - **Voice VLAN**: VoIP traffic
        - **Management VLAN**: Switch management
        - **Native VLAN**: Untagged traffic
        """)
    
    # Routing table simulation
    st.markdown("#### 📊 Routing Table Example")
    
    routing_data = [
        {"Destination": "0.0.0.0/0", "Next Hop": "192.168.1.1", "Metric": "1", "Interface": "eth0", "Protocol": "Static"},
        {"Destination": "192.168.1.0/24", "Next Hop": "0.0.0.0", "Metric": "0", "Interface": "eth0", "Protocol": "Connected"},
        {"Destination": "10.0.0.0/8", "Next Hop": "192.168.1.10", "Metric": "2", "Interface": "eth0", "Protocol": "OSPF"},
        {"Destination": "172.16.0.0/16", "Next Hop": "192.168.1.20", "Metric": "3", "Interface": "eth1", "Protocol": "RIP"}
    ]
    
    df = pd.DataFrame(routing_data)
    st.dataframe(df, width='stretch')

def explain_network_topologies():
    """Giải thích Network Topologies"""
    st.markdown("### 🕸️ Network Topologies")
    
    with st.expander("📖 Lý thuyết chi tiết về Network Topologies"):
        st.markdown("""
        ### 🔗 Physical vs Logical Topologies
        
        **Physical Topology:**
        - Actual physical layout of cables and devices
        - How devices are physically connected
        - Determines cable requirements and costs
        
        **Logical Topology:**
        - How data flows through the network
        - Independent of physical layout
        - Determines network protocols and behavior
        
        ### 📐 Common Network Topologies
        
        **1. Bus Topology**
        - **Structure**: All devices connected to single cable
        - **Pros**: Simple, inexpensive, easy to implement
        - **Cons**: Single point of failure, collision domain
        - **Use case**: Legacy Ethernet (10BASE2, 10BASE5)
        
        **2. Star Topology**
        - **Structure**: All devices connected to central hub/switch
        - **Pros**: Easy troubleshooting, no single point of failure
        - **Cons**: Central device dependency, more cables
        - **Use case**: Modern Ethernet networks
        
        **3. Ring Topology**
        - **Structure**: Devices connected in circular fashion
        - **Pros**: Equal access, predictable performance
        - **Cons**: Single break affects all, difficult expansion
        - **Use case**: Token Ring, FDDI
        
        **4. Mesh Topology**
        - **Structure**: Every device connected to every other device
        - **Types**: Full mesh, Partial mesh
        - **Pros**: High redundancy, fault tolerance
        - **Cons**: Expensive, complex configuration
        - **Use case**: WAN connections, critical networks
        
        **5. Tree/Hierarchical Topology**
        - **Structure**: Combination of star topologies
        - **Levels**: Core, Distribution, Access
        - **Pros**: Scalable, organized, fault isolation
        - **Cons**: Dependency on higher levels
        - **Use case**: Enterprise networks
        
        **6. Hybrid Topology**
        - **Structure**: Combination of multiple topologies
        - **Pros**: Flexible, scalable, optimized for needs
        - **Cons**: Complex design and management
        - **Use case**: Large enterprise networks
        
        ### 🏢 Network Architecture Models
        
        **Three-Tier Architecture:**
        
        **1. Core Layer**
        - **Function**: High-speed backbone
        - **Characteristics**: Fast switching, redundancy
        - **Devices**: High-end routers/switches
        
        **2. Distribution Layer**
        - **Function**: Policy enforcement, routing
        - **Characteristics**: Access control, QoS
        - **Devices**: Layer 3 switches, routers
        
        **3. Access Layer**
        - **Function**: End-user connectivity
        - **Characteristics**: Port density, PoE
        - **Devices**: Access switches, wireless APs
        
        ### 🌐 WAN Topologies
        
        **Point-to-Point**
        - Direct connection between two sites
        - High bandwidth, low latency
        - Expensive for multiple sites
        
        **Hub and Spoke**
        - Central hub connects to multiple spokes
        - Cost-effective, centralized management
        - Hub is single point of failure
        
        **Full Mesh**
        - Every site connected to every other site
        - High redundancy, optimal paths
        - Expensive, complex management
        
        **Partial Mesh**
        - Some sites have multiple connections
        - Balance of cost and redundancy
        - Strategic redundancy placement
        
        ### 📊 Topology Selection Criteria
        
        **Factors to Consider:**
        - **Cost**: Equipment, cabling, maintenance
        - **Scalability**: Future growth requirements
        - **Reliability**: Fault tolerance needs
        - **Performance**: Bandwidth and latency requirements
        - **Security**: Isolation and access control
        - **Management**: Complexity and troubleshooting
        """)
    
    # Topology comparison chart
    st.markdown("#### 📊 Topology Comparison")
    
    topology_data = [
        {"Topology": "Bus", "Cost": "Low", "Reliability": "Low", "Scalability": "Poor", "Performance": "Shared"},
        {"Topology": "Star", "Cost": "Medium", "Reliability": "High", "Scalability": "Good", "Performance": "Dedicated"},
        {"Topology": "Ring", "Cost": "Medium", "Reliability": "Medium", "Scalability": "Fair", "Performance": "Shared"},
        {"Topology": "Mesh", "Cost": "High", "Reliability": "Very High", "Scalability": "Excellent", "Performance": "Dedicated"},
        {"Topology": "Tree", "Cost": "Medium-High", "Reliability": "Good", "Scalability": "Excellent", "Performance": "Hierarchical"}
    ]
    
    df = pd.DataFrame(topology_data)
    st.dataframe(df, width='stretch')

def security_principles():
    """Nguyên tắc bảo mật"""
    st.subheader("🔒 Security Principles")
    
    principle_choice = st.selectbox("Chọn nguyên tắc:", [
        "CIA Triad",
        "Defense in Depth",
        "Principle of Least Privilege",
        "Zero Trust Architecture",
        "Security by Design",
        "Risk Management"
    ])
    
    if principle_choice == "CIA Triad":
        explain_cia_triad()
    elif principle_choice == "Defense in Depth":
        explain_defense_in_depth()
    elif principle_choice == "Principle of Least Privilege":
        explain_least_privilege()
    elif principle_choice == "Zero Trust Architecture":
        explain_zero_trust()
    elif principle_choice == "Security by Design":
        explain_security_by_design()
    elif principle_choice == "Risk Management":
        explain_risk_management_principles()

def explain_cia_triad():
    """Enhanced CIA Triad explanation using TDD pattern"""
    st.markdown("### CIA Triad")
    
    # 1. Visual Banner (Theory & Concepts color scheme)
    st.markdown("""
    <div style="background: linear-gradient(90deg, #ff7b7b 0%, #ff6b6b 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            CIA Triad
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Foundation of Information Security
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 2. Visual Diagram (Enhanced triangle with better design)
    st.markdown("#### Security Triangle")
    
    fig = go.Figure()
    
    # Create enhanced triangle for CIA
    triangle_points = [(0.5, 0.8), (0.2, 0.2), (0.8, 0.2), (0.5, 0.8)]  # Close the triangle
    x_coords = [p[0] for p in triangle_points]
    y_coords = [p[1] for p in triangle_points]
    
    # Add triangle shape with gradient effect
    fig.add_shape(
        type="path",
        path=f"M {x_coords[0]},{y_coords[0]} L {x_coords[1]},{y_coords[1]} L {x_coords[2]},{y_coords[2]} Z",
        fillcolor="rgba(255, 107, 107, 0.3)",
        line=dict(color="#ff6b6b", width=3)
    )
    
    # Add CIA labels at triangle vertices with enhanced styling
    cia_labels = [
        ("Confidentiality", 0.5, 0.85, "#ff4757"),
        ("Integrity", 0.15, 0.15, "#2ed573"), 
        ("Availability", 0.85, 0.15, "#3742fa")
    ]
    
    for label, x, y, color in cia_labels:
        fig.add_annotation(
            x=x, y=y,
            text=f"<b>{label}</b>",
            showarrow=False,
            font=dict(size=14, color=color),
            bgcolor="white",
            bordercolor=color,
            borderwidth=2,
            borderpad=4
        )
    
    # Add center text
    fig.add_annotation(
        x=0.5, y=0.4,
        text="<b>Information<br>Security</b>",
        showarrow=False,
        font=dict(size=12, color="#333"),
        bgcolor="rgba(255,255,255,0.8)",
        bordercolor="#333",
        borderwidth=1,
        borderpad=4
    )
    
    fig.update_layout(
        xaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=350,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # 3. Clean Content with expandable details
    with st.expander("Chi tiết về CIA Triad"):
        st.markdown("""
        ## CIA Triad Fundamentals
        
        **Definition:** CIA Triad là ba nguyên tắc cốt lõi của information security, tạo nền tảng cho mọi biện pháp bảo mật thông tin.
        
        ---
        
        ## Core Components
        
        ### **Confidentiality (Tính bảo mật)**
        **Purpose:** Đảm bảo thông tin chỉ được truy cập bởi những người có quyền
        **Implementation:** Encryption, access controls, authentication mechanisms
        **Benefits:** Bảo vệ dữ liệu nhạy cảm, tuân thủ quy định pháp lý
        
        ### **Integrity (Tính toàn vẹn)**  
        **Purpose:** Đảm bảo thông tin không bị thay đổi trái phép hoặc tham nhũng
        **Implementation:** Digital signatures, checksums, version control systems
        **Benefits:** Tin cậy vào tính chính xác của dữ liệu, phát hiện thay đổi trái phép
        
        ### **Availability (Tính khả dụng)**
        **Purpose:** Đảm bảo thông tin và hệ thống luôn sẵn sàng khi cần thiết
        **Implementation:** Redundancy, backup systems, disaster recovery plans
        **Benefits:** Continuous business operations, user satisfaction
        
        ---
        
        ## Real-world Examples
        
        **Banking System:**
        - **Confidentiality:** Customer account data encryption
        - **Integrity:** Transaction verification và audit trails
        - **Availability:** 24/7 online banking services
        
        **Healthcare System:**
        - **Confidentiality:** Patient medical record protection (HIPAA compliance)
        - **Integrity:** Accurate medication dosage và medical history
        - **Availability:** Emergency access to critical patient information
        """)
    
    # 4. Enhanced Cheat Sheets with highlighted keywords
    st.markdown("---")
    st.markdown("## CIA Triad Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["Core Principles", "Threats & Controls", "Implementation Guide"])
    
    with tab1:
        st.markdown("### Core Principles")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Principle** | **Definition** | **Key Focus** | **Primary Goal** | **Methods** | **Example** |
        |---------------|----------------|---------------|------------------|-------------|-------------|
        | **Confidentiality** | Information is accessible only to **authorized** individuals | **Data Protection** | Prevent **unauthorized disclosure** | `encryption`, `access_controls`, `authentication` | **Password protection**, encrypted databases |
        | **Integrity** | Information remains **accurate** and **unmodified** | **Data Accuracy** | Prevent **unauthorized modifications** | `checksums`, `digital_signatures`, `version_control` | **Hash verification**, audit trails |
        | **Availability** | Information is **accessible** when needed | **System Uptime** | Ensure **continuous access** | `redundancy`, `backup_systems`, `load_balancing` | **24/7 services**, disaster recovery |
        """)
        
        # Additional highlighted information
        st.markdown("""
        #### **Key Terminology**
        - **Asset**: `valuable_information` - Data, systems, or resources that need protection
        - **Threat**: `potential_danger` - Anything that could harm confidentiality, integrity, or availability  
        - **Vulnerability**: `system_weakness` - Flaws that threats can exploit to cause damage
        """)
    
    with tab2:
        st.markdown("### Threats & Controls")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **CIA Component** | **Common Threats** | **Security Controls** | **Detection Methods** | **Prevention Strategy** | **Example Attack** |
        |-------------------|--------------------|-----------------------|-----------------------|-------------------------|---------------------|
        | **Confidentiality** | **Data breaches**, unauthorized access, **social engineering** | `encryption`, `access_controls`, `MFA` | **Access logs**, anomaly detection | **Least privilege**, data classification | **Phishing** để đánh cắp credentials |
        | **Integrity** | **Data tampering**, corruption, **malware injection** | `digital_signatures`, `checksums`, `backup` | **Hash verification**, file monitoring | **Input validation**, change management | **Man-in-the-middle** attack modifying data |
        | **Availability** | **DoS attacks**, system failures, **natural disasters** | `redundancy`, `load_balancing`, `DRP` | **Performance monitoring**, uptime tracking | **Capacity planning**, fault tolerance | **DDoS** attack overwhelming servers |
        """)
    
    with tab3:
        st.markdown("### Implementation Guide")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Implementation Area** | **Confidentiality** | **Integrity** | **Availability** | **Difficulty Level** | **Cost Impact** |
        |-------------------------|---------------------|---------------|------------------|---------------------|-----------------|
        | **Technical Controls** | `AES_encryption`, `TLS/SSL`, `VPN` | `SHA-256_hashing`, `digital_certificates` | `clustering`, `CDN`, `auto_scaling` | **Medium** | Moderate |
        | **Administrative Controls** | Security policies, **access management** | Change control, **approval workflows** | **SLA management**, incident response | **High** | Low |
        | **Physical Controls** | **Secure facilities**, locked cabinets | **Environmental controls**, UPS systems | **Redundant power**, backup generators | **Low** | High |
        """)
    
    # 5. Interactive Demo
    st.markdown("---")
    st.markdown("## Interactive Demo")
    
    with st.expander("CIA Triad Scenario Analysis"):
        st.markdown("### Analyze Security Scenarios")
        
        # Simple interactive element
        scenario = st.selectbox(
            "Choose a security scenario:", 
            ["E-commerce Website", "Hospital Database", "Corporate Email System", "Banking Application"]
        )
        
        if scenario == "E-commerce Website":
            st.markdown("**E-commerce Security Analysis:**")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("**🔒 Confidentiality**")
                st.markdown("- Customer payment info")
                st.markdown("- Personal addresses") 
                st.markdown("- Purchase history")
                
            with col2:
                st.markdown("**🔧 Integrity**")
                st.markdown("- Product prices")
                st.markdown("- Order details")
                st.markdown("- Inventory counts")
                
            with col3:
                st.markdown("**⚡ Availability**")
                st.markdown("- 24/7 shopping access")
                st.markdown("- Payment processing")
                st.markdown("- Customer support")
                
            st.success("✅ **E-commerce** requires all three CIA components for **customer trust** và **business continuity**!")
            
        elif scenario == "Hospital Database":
            st.markdown("**Hospital Database Security Analysis:**")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("**🔒 Confidentiality**")
                st.markdown("- Patient medical records")
                st.markdown("- HIPAA compliance") 
                st.markdown("- Personal health info")
                
            with col2:
                st.markdown("**🔧 Integrity**")
                st.markdown("- Accurate diagnoses")
                st.markdown("- Medication dosages")
                st.markdown("- Treatment histories")
                
            with col3:
                st.markdown("**⚡ Availability**")
                st.markdown("- Emergency access")
                st.markdown("- Real-time updates")
                st.markdown("- Critical care systems")
                
            st.success("✅ **Healthcare** systems prioritize **patient safety** through comprehensive CIA implementation!")
            
        elif scenario == "Corporate Email System":
            st.markdown("**Corporate Email Security Analysis:**")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("**🔒 Confidentiality**")
                st.markdown("- Business communications")
                st.markdown("- Trade secrets") 
                st.markdown("- Employee personal info")
                
            with col2:
                st.markdown("**🔧 Integrity**")
                st.markdown("- Message authenticity")
                st.markdown("- Attachment safety")
                st.markdown("- Email threading")
                
            with col3:
                st.markdown("**⚡ Availability**")
                st.markdown("- Business continuity")
                st.markdown("- Communication flow")
                st.markdown("- Remote work support")
                
            st.success("✅ **Corporate email** enables **secure business communication** với full CIA protection!")
            
        elif scenario == "Banking Application":
            st.markdown("**Banking Application Security Analysis:**")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("**🔒 Confidentiality**")
                st.markdown("- Account balances")
                st.markdown("- Transaction history") 
                st.markdown("- Personal identification")
                
            with col2:
                st.markdown("**🔧 Integrity**")
                st.markdown("- Transaction accuracy")
                st.markdown("- Account balances")
                st.markdown("- Transfer amounts")
                
            with col3:
                st.markdown("**⚡ Availability**")
                st.markdown("- 24/7 banking services")
                st.markdown("- ATM networks")
                st.markdown("- Mobile banking")
                
            st.success("✅ **Banking** systems require **maximum CIA protection** for **financial security**!")
    
    # 6. Key Takeaways
    st.markdown("---")
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1.5rem; border-radius: 10px; border-left: 5px solid #1f77b4;">
        <h4 style="margin-top: 0; color: #1f77b4;">Key Takeaways</h4>
        <ul>
            <li><strong>Foundation Principle</strong>: CIA Triad forms the cornerstone of all information security strategies</li>
            <li><strong>Balanced Approach</strong>: All three components must work together - weakness in one affects overall security</li>
            <li><strong>Context-Dependent</strong>: Different systems may prioritize different CIA components based on business needs</li>
            <li><strong>Risk Management</strong>: CIA helps identify, assess, and mitigate information security risks systematically</li>
            <li><strong>Compliance Framework</strong>: Most security standards và regulations are built around CIA principles</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_defense_in_depth():
    """Giải thích Defense in Depth"""
    st.markdown("### 🛡️ Defense in Depth")
    
    st.markdown("""
    **Defense in Depth** là strategy sử dụng multiple layers of security controls:
    
    **🎯 Core Concept:**
    - Không dựa vào single point of failure
    - Multiple independent layers of protection
    - If one layer fails, others still protect
    """)
    
    # Defense layers
    defense_layers = [
        {"Layer": "Physical", "Controls": "Guards, Locks, Cameras", "Purpose": "Prevent physical access"},
        {"Layer": "Perimeter", "Controls": "Firewalls, IDS/IPS", "Purpose": "Network boundary protection"},
        {"Layer": "Network", "Controls": "Segmentation, VLANs", "Purpose": "Internal network security"},
        {"Layer": "Host", "Controls": "Antivirus, Patching", "Purpose": "Individual system protection"},
        {"Layer": "Application", "Controls": "Input validation, WAF", "Purpose": "Application-level security"},
        {"Layer": "Data", "Controls": "Encryption, DLP", "Purpose": "Data protection"},
        {"Layer": "Policies", "Controls": "Training, Procedures", "Purpose": "Human factor security"}
    ]
    
    df = pd.DataFrame(defense_layers)
    st.dataframe(df, width='stretch')
    
    # Visualization
    fig = px.funnel(
        df, x='Purpose', y='Layer',
        title="Defense in Depth Layers"
    )
    st.plotly_chart(fig, width='stretch')

def explain_least_privilege():
    """Giải thích Principle of Least Privilege"""
    st.markdown("### 🔐 Principle of Least Privilege")
    
    with st.expander("📖 Lý thuyết chi tiết về Least Privilege"):
        st.markdown("""
        ### 🎯 What is Least Privilege?
        
        **Definition:**
        - Users and systems should have only the minimum access rights needed
        - Temporary elevation when necessary
        - Regular review and adjustment of permissions
        
        **Core Principles:**
        
        **1. Minimum Necessary Access**
        - Grant only required permissions
        - No "just in case" permissions
        - Time-limited access when possible
        
        **2. Need-to-Know Basis**
        - Access based on job requirements
        - Compartmentalization of information
        - Regular access reviews
        
        **3. Default Deny**
        - Start with no access
        - Explicitly grant permissions
        - Remove unused permissions
        
        ### 🔧 Implementation Strategies
        
        **User Access Management:**
        - **Role-Based Access Control (RBAC)**: Permissions based on roles
        - **Attribute-Based Access Control (ABAC)**: Dynamic permissions
        - **Just-In-Time (JIT) Access**: Temporary elevated permissions
        - **Privileged Access Management (PAM)**: Special handling for admin accounts
        
        **System-Level Implementation:**
        - **Service Accounts**: Minimal permissions for applications
        - **Network Segmentation**: Limit lateral movement
        - **Application Sandboxing**: Isolate application processes
        - **Container Security**: Minimal container privileges
        
        **Administrative Controls:**
        - **Separation of Duties**: Multiple people for critical tasks
        - **Dual Control**: Two-person authorization
        - **Regular Audits**: Periodic permission reviews
        - **Automated Provisioning**: Consistent access management
        
        ### 📊 Benefits of Least Privilege
        
        **Security Benefits:**
        - **Reduced Attack Surface**: Fewer entry points for attackers
        - **Limited Blast Radius**: Contain damage from breaches
        - **Insider Threat Mitigation**: Reduce malicious insider impact
        - **Compliance**: Meet regulatory requirements
        
        **Operational Benefits:**
        - **Reduced Errors**: Fewer accidental changes
        - **Better Accountability**: Clear audit trails
        - **Improved Stability**: Prevent unauthorized modifications
        - **Cost Reduction**: Efficient resource utilization
        
        ### 🚫 Common Implementation Challenges
        
        **Technical Challenges:**
        - **Legacy Systems**: Outdated access controls
        - **Complex Dependencies**: Application interconnections
        - **Performance Impact**: Additional authentication overhead
        - **User Experience**: Balance security with usability
        
        **Organizational Challenges:**
        - **Cultural Resistance**: Users want more access
        - **Business Pressure**: "Emergency" access requests
        - **Resource Constraints**: Limited IT staff for management
        - **Training Requirements**: User education needs
        
        ### 🛠️ Best Practices
        
        **Implementation Guidelines:**
        - **Start Small**: Pilot with non-critical systems
        - **Document Everything**: Clear access policies
        - **Automate When Possible**: Reduce manual errors
        - **Monitor Continuously**: Real-time access monitoring
        - **Regular Reviews**: Quarterly access audits
        - **Emergency Procedures**: Break-glass access protocols
        """)
    
    # Privilege escalation example
    st.markdown("#### 🔍 Access Control Matrix Example")
    
    access_data = [
        {"Role": "End User", "File Access": "Read Own", "System Config": "None", "User Management": "None", "Network Access": "Limited"},
        {"Role": "Power User", "File Access": "Read/Write Own", "System Config": "View Only", "User Management": "None", "Network Access": "Standard"},
        {"Role": "IT Support", "File Access": "Read All", "System Config": "Limited", "User Management": "Reset Passwords", "Network Access": "Extended"},
        {"Role": "System Admin", "File Access": "Full Control", "System Config": "Full Control", "User Management": "Create/Delete", "Network Access": "Full"},
        {"Role": "Security Admin", "File Access": "Audit Only", "System Config": "Security Only", "User Management": "Full Control", "Network Access": "Monitor All"}
    ]
    
    df = pd.DataFrame(access_data)
    st.dataframe(df, width='stretch')

def explain_zero_trust():
    """Zero Trust Architecture - Never Trust, Always Verify"""
    
    # Visual Banner
    st.markdown("""
    <div style="background: linear-gradient(90deg, #e74c3c 0%, #c0392b 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            🚫 Zero Trust Architecture
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Never Trust, Always Verify Security Model
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Zero Trust vs Traditional Architecture Diagram
    st.markdown("#### 🏗️ Architecture Comparison")
    
    fig = go.Figure()
    
    # Traditional Model (Left side)
    fig.add_shape(
        type="rect",
        x0=0.05, y0=0.3, x1=0.45, y1=0.9,
        fillcolor="#ffcccc", opacity=0.7,
        line=dict(color="#e74c3c", width=3)
    )
    fig.add_annotation(
        x=0.25, y=0.95,
        text="<b>Traditional Perimeter Model</b>",
        showarrow=False,
        font=dict(size=14, color="#e74c3c")
    )
    
    # Internal network (trusted)
    fig.add_shape(
        type="circle",
        x0=0.15, y0=0.5, x1=0.35, y1=0.7,
        fillcolor="#90EE90", opacity=0.6,
        line=dict(color="#27ae60", width=2)
    )
    fig.add_annotation(
        x=0.25, y=0.6,
        text="<b>Trusted Zone</b><br>Internal Network",
        showarrow=False,
        font=dict(size=10)
    )
    
    # Firewall
    fig.add_shape(
        type="rect",
        x0=0.05, y0=0.35, x1=0.08, y1=0.85,
        fillcolor="#ff6b6b", opacity=0.8,
        line=dict(color="#e74c3c", width=2)
    )
    fig.add_annotation(
        x=0.065, y=0.25,
        text="Firewall",
        showarrow=False,
        font=dict(size=9)
    )
    
    # Zero Trust Model (Right side)
    fig.add_shape(
        type="rect",
        x0=0.55, y0=0.3, x1=0.95, y1=0.9,
        fillcolor="#cce5ff", opacity=0.7,
        line=dict(color="#3498db", width=3)
    )
    fig.add_annotation(
        x=0.75, y=0.95,
        text="<b>Zero Trust Model</b>",
        showarrow=False,
        font=dict(size=14, color="#3498db")
    )
    
    # Micro-segments
    segments = [(0.6, 0.7), (0.8, 0.7), (0.6, 0.5), (0.8, 0.5)]
    segment_colors = ['#ff9ff3', '#54a0ff', '#5f27cd', '#00d2d3']
    
    for i, ((x, y), color) in enumerate(zip(segments, segment_colors)):
        fig.add_shape(
            type="circle",
            x0=x-0.06, y0=y-0.06, x1=x+0.06, y1=y+0.06,
            fillcolor=color, opacity=0.7,
            line=dict(color=color, width=2)
        )
        fig.add_annotation(
            x=x, y=y,
            text=f"<b>Seg{i+1}</b>",
            showarrow=False,
            font=dict(size=8, color="white")
        )
    
    fig.update_layout(
        title="Traditional vs Zero Trust Security Models",
        xaxis=dict(showgrid=False, showticklabels=False, zeroline=False, range=[0, 1]),
        yaxis=dict(showgrid=False, showticklabels=False, zeroline=False, range=[0, 1]),
        showlegend=False,
        height=400,
        margin=dict(l=20, r=20, t=50, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Core Principles Table
    st.markdown("#### 🎯 Zero Trust Core Principles")
    
    principles_data = pd.DataFrame({
        '**Principle**': ['**Never Trust**', '**Always Verify**', '**Least Privilege**', '**Assume Breach**', '**Continuous Monitoring**'],
        '**Description**': [
            '**No implicit trust** based on network location or device type',
            '**Verify every request** regardless of source or destination',
            '**Minimal access** required to perform specific tasks',
            '**Assume attackers** are already inside the network',
            '**Real-time monitoring** and risk assessment of all activities'
        ],
        '**Implementation**': [
            '**Identity verification**, device authentication',
            '**Multi-factor authentication**, certificate validation',
            '**Role-based access**, time-limited permissions',
            '**Micro-segmentation**, lateral movement prevention',
            '**SIEM integration**, behavioral analytics'
        ]
    })
    
    st.dataframe(principles_data, use_container_width=True)
    
    # Interactive Zero Trust Demo
    st.markdown("#### 🎮 Interactive Zero Trust Demo")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        access_scenario = st.selectbox("Select Access Scenario:", [
            "Employee Login",
            "Remote Access",
            "Device Connection",
            "Application Access",
            "Data Access"
        ])
        
    with col2:
        if st.button("🔐 Analyze Zero Trust Flow"):
            scenarios = {
                'Employee Login': {
                    'steps': ['**Identity verification**', '**Device trust check**', '**Location analysis**', '**Risk assessment**', '**Conditional access**'],
                    'controls': 'MFA, Device compliance, Geo-location',
                    'outcome': '**Granted/Denied** based on risk score'
                },
                'Remote Access': {
                    'steps': ['**VPN-less access**', '**Application-specific**', '**Session monitoring**', '**Dynamic policies**', '**Continuous verification**'],
                    'controls': 'Identity proxy, App-level security',
                    'outcome': '**Secure tunnel** to specific resources only'
                },
                'Device Connection': {
                    'steps': ['**Device fingerprinting**', '**Compliance check**', '**Health assessment**', '**Certificate validation**', '**Network segmentation**'],
                    'controls': 'Device certificates, EDR agents',
                    'outcome': '**Limited network access** based on device trust'
                },
                'Application Access': {
                    'steps': ['**User authentication**', '**App authorization**', '**Data classification**', '**Access logging**', '**Session timeout**'],
                    'controls': 'OAuth/SAML, API gateways',
                    'outcome': '**Granular permissions** per application'
                },
                'Data Access': {
                    'steps': ['**Data classification**', '**Sensitivity labels**', '**Access policies**', '**Encryption check**', '**Audit logging**'],
                    'controls': 'DLP, Rights management',
                    'outcome': '**Protected data access** with full audit trail'
                }
            }
            
            scenario = scenarios[access_scenario]
            st.success(f"""
            **Scenario**: {access_scenario}
            
            **Zero Trust Flow**:
            {' → '.join(scenario['steps'])}
            
            **Security Controls**: {scenario['controls']}
            
            **Expected Outcome**: {scenario['outcome']}
            """)
    
    # Zero Trust vs Traditional Comparison
    st.markdown("#### ⚖️ Traditional vs Zero Trust")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.info("""
        **🏰 Traditional Perimeter Model:**
        - **Castle & Moat** approach
        - **Trust internal network**
        - **VPN for remote access**
        - **Firewall-based security**
        - **Static security policies**
        """)
    
    with col2:
        st.success("""
        **🚫 Zero Trust Model:**
        - **Never trust, always verify**
        - **Identity-centric security**
        - **Micro-segmentation**
        - **Continuous verification**
        - **Dynamic risk assessment**
        """)
    
    # Implementation Components
    st.markdown("#### 🛠️ Zero Trust Implementation Stack")
    
    components_data = pd.DataFrame({
        '**Layer**': ['**Identity**', '**Device**', '**Network**', '**Application**', '**Data**'],
        '**Technologies**': [
            '**IAM, MFA, SSO**, Identity governance',
            '**MDM, EDR, Device compliance**, Certificate management',
            '**SASE, SD-WAN, Micro-segmentation**, Network access control',
            '**CASB, API Gateway, App proxy**, Zero trust network access',
            '**DLP, Encryption, Rights management**, Data classification'
        ],
        '**Key Controls**': [
            '**Strong authentication**, Privileged access management',
            '**Device trust**, Endpoint protection and monitoring',
            '**Least privilege**, Network isolation and monitoring',
            '**App-level security**, API protection and monitoring',
            '**Data protection**, Access control and audit logging'
        ]
    })
    
    st.dataframe(components_data, use_container_width=True)
    
    # Key Takeaways
    st.markdown("""
    <div style="background-color: #f0f2f6; padding: 1.5rem; border-radius: 10px; margin-top: 2rem;">
        <h4 style="color: #e74c3c; margin-bottom: 1rem;">🎯 Key Takeaways</h4>
        <ul style="color: #2c3e50; line-height: 1.8;">
            <li><strong>Paradigm shift</strong>: From perimeter-based to identity-centric security</li>
            <li><strong>Core principle</strong>: Never trust, always verify every access request</li>
            <li><strong>Implementation</strong>: Requires comprehensive identity, device, and data controls</li>
            <li><strong>Benefits</strong>: Reduced attack surface, improved compliance, better visibility</li>
            <li><strong>Challenge</strong>: Complex implementation requiring cultural and technical changes</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_defense_in_depth():
    """Defense in Depth - Layered Security Strategy"""
    
    # Visual Banner
    st.markdown("""
    <div style="background: linear-gradient(90deg, #2c3e50 0%, #34495e 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            🛡️ Defense in Depth
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Layered Security Architecture Strategy
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Defense Layers Visualization
    st.markdown("#### 🏰 Defense Layers Architecture")
    
    fig = go.Figure()
    
    # Create concentric defense layers
    layers = [
        ('Physical', 0.5, 0.5, 0.45, '#e74c3c'),
        ('Network', 0.5, 0.5, 0.35, '#f39c12'),
        ('Host', 0.5, 0.5, 0.25, '#f1c40f'),
        ('Application', 0.5, 0.5, 0.15, '#27ae60'),
        ('Data', 0.5, 0.5, 0.08, '#3498db')
    ]
    
    for layer, x, y, radius, color in layers:
        fig.add_shape(
            type="circle",
            x0=x-radius, y0=y-radius, x1=x+radius, y1=y+radius,
            fillcolor=color, opacity=0.3,
            line=dict(color=color, width=3)
        )
        fig.add_annotation(
            x=x, y=y+radius-0.05,
            text=f"<b>{layer}</b>",
            showarrow=False,
            font=dict(size=12, color=color)
        )
    
    # Add threat arrows from outside
    threat_positions = [(0.1, 0.8), (0.9, 0.8), (0.1, 0.2), (0.9, 0.2)]
    for i, (x, y) in enumerate(threat_positions):
        fig.add_annotation(
            x=x, y=y,
            ax=0.5, ay=0.5,
            arrowhead=2, arrowsize=1.5, arrowwidth=2,
            arrowcolor="#e74c3c",
            text="🎯"
        )
    
    fig.update_layout(
        title="Defense in Depth - Layered Security Model",
        xaxis=dict(showgrid=False, showticklabels=False, zeroline=False, range=[0, 1]),
        yaxis=dict(showgrid=False, showticklabels=False, zeroline=False, range=[0, 1]),
        showlegend=False,
        height=500,
        margin=dict(l=20, r=20, t=50, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Defense Layers Table
    st.markdown("#### 🎯 Security Layers & Controls")
    
    layers_data = pd.DataFrame({
        '**Layer**': ['**Physical**', '**Network**', '**Host/Endpoint**', '**Application**', '**Data**'],
        '**Security Controls**': [
            '**Access controls**, security guards, **CCTV**, locks, biometrics',
            '**Firewalls**, IPS/IDS, **VPNs**, network segmentation, **WAF**',
            '**Antivirus**, EDR, **host firewalls**, patch management, **hardening**',
            '**Input validation**, authentication, **authorization**, secure coding',
            '**Encryption**, DLP, **backup**, access controls, **classification**'
        ],
        '**Threat Mitigation**': [
            '**Unauthorized access**, theft, **physical tampering**',
            '**Network attacks**, malware, **unauthorized traffic**',
            '**Malware**, exploits, **privilege escalation**',
            '**Injection attacks**, broken authentication, **OWASP Top 10**',
            '**Data breaches**, unauthorized access, **data loss**'
        ]
    })
    
    st.dataframe(layers_data, use_container_width=True)
    
    # Interactive Defense Demo
    st.markdown("#### 🎮 Interactive Defense Scenario")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        attack_scenario = st.selectbox("Select Attack Scenario:", [
            "External Network Attack",
            "Malware Infection",
            "Insider Threat",
            "Physical Breach",
            "Application Attack"
        ])
        
    with col2:
        if st.button("🛡️ Analyze Defense Layers"):
            defense_scenarios = {
                'External Network Attack': {
                    'attack': 'Attacker tries to **penetrate network** from internet',
                    'layers': ['**Firewall** blocks malicious traffic', '**IDS** detects intrusion attempts', '**Network segmentation** limits access', '**Host firewall** provides additional protection'],
                    'outcome': '**Multi-layer protection** prevents or contains the attack'
                },
                'Malware Infection': {
                    'attack': 'Malicious software attempts to **compromise systems**',
                    'layers': ['**Email filtering** blocks malicious attachments', '**Antivirus** detects known malware', '**EDR** identifies suspicious behavior', '**Application controls** prevent execution'],
                    'outcome': '**Layered detection** catches malware at multiple points'
                },
                'Insider Threat': {
                    'attack': 'Authorized user attempts **unauthorized access**',
                    'layers': ['**Access controls** limit permissions', '**Monitoring** tracks user activity', '**DLP** prevents data exfiltration', '**Audit logs** provide evidence'],
                    'outcome': '**Principle of least privilege** and monitoring contain threat'
                },
                'Physical Breach': {
                    'attack': 'Attacker gains **physical access** to facilities',
                    'layers': ['**Physical barriers** delay access', '**Access controls** require authentication', '**CCTV** provides monitoring', '**Host controls** protect even if accessed'],
                    'outcome': '**Physical + logical controls** provide comprehensive protection'
                },
                'Application Attack': {
                    'attack': 'Web application faces **injection attacks**',
                    'layers': ['**WAF** filters malicious requests', '**Input validation** prevents injection', '**Database controls** limit access', '**Monitoring** detects anomalies'],
                    'outcome': '**Application-layer defenses** work together to prevent compromise'
                }
            }
            
            scenario = defense_scenarios[attack_scenario]
            st.warning(f"**🎯 Attack**: {scenario['attack']}")
            st.success("**🛡️ Defense Layers:**")
            for i, layer in enumerate(scenario['layers'], 1):
                st.write(f"{i}. {layer}")
            st.info(f"**✅ Result**: {scenario['outcome']}")
    
    # Defense Principles
    st.markdown("#### 📋 Core Defense in Depth Principles")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **🎯 Key Principles:**
        - **No single point of failure**
        - **Redundant security controls**
        - **Layered protection approach**
        - **Fail-safe mechanisms**
        - **Continuous monitoring**
        """)
    
    with col2:
        st.markdown("""
        **💡 Implementation Tips:**
        - **Diverse security technologies**
        - **Regular security assessments**
        - **Incident response planning**
        - **Security awareness training**
        - **Continuous improvement**
        """)
    
    # Benefits vs Challenges
    st.markdown("#### ⚖️ Benefits vs Challenges")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.success("""
        **✅ Benefits:**
        - **Comprehensive protection**
        - **Attack containment**
        - **Reduced single points of failure**
        - **Compliance alignment**
        - **Risk mitigation**
        """)
    
    with col2:
        st.warning("""
        **⚠️ Challenges:**
        - **Complexity management**
        - **Higher costs**
        - **Performance impact**
        - **Integration challenges**
        - **Maintenance overhead**
        """)
    
    # Key Takeaways
    st.markdown("""
    <div style="background-color: #f0f2f6; padding: 1.5rem; border-radius: 10px; margin-top: 2rem;">
        <h4 style="color: #2c3e50; margin-bottom: 1rem;">🎯 Key Takeaways</h4>
        <ul style="color: #2c3e50; line-height: 1.8;">
            <li><strong>Layered approach</strong>: Multiple security layers provide better protection than any single control</li>
            <li><strong>Redundancy</strong>: If one layer fails, others continue to provide protection</li>
            <li><strong>Comprehensive coverage</strong>: Address security at physical, network, host, application, and data levels</li>
            <li><strong>Threat containment</strong>: Limit the scope and impact of successful attacks</li>
            <li><strong>Risk management</strong>: Balance security investment across multiple layers based on risk assessment</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def attack_methodologies():
    """Phương pháp tấn công"""
    st.subheader("🛡️ Attack Methodologies")
    
    attack_type = st.selectbox("Chọn loại tấn công:", [
        "Cyber Kill Chain",
        "MITRE ATT&CK Framework",
        "Common Attack Vectors",
        "Social Engineering",
        "Advanced Persistent Threats (APT)"
    ])
    
    if attack_type == "Cyber Kill Chain":
        explain_cyber_kill_chain()
    elif attack_type == "MITRE ATT&CK Framework":
        explain_mitre_attack()
    elif attack_type == "Common Attack Vectors":
        explain_attack_vectors()
    elif attack_type == "Social Engineering":
        explain_social_engineering()
    elif attack_type == "Advanced Persistent Threats (APT)":
        explain_advanced_persistent_threats()

def explain_cyber_kill_chain():
    """Giải thích Cyber Kill Chain"""
    st.markdown("### ⛓️ Cyber Kill Chain")
    
    st.markdown("""
    **Cyber Kill Chain** mô tả các bước của một cuộc tấn công cyber:
    
    **🎯 Developed by:** Lockheed Martin
    **📊 Purpose:** Understand and defend against attacks
    """)
    
    kill_chain_steps = [
        {
            "Step": 1,
            "Phase": "Reconnaissance", 
            "Description": "Thu thập thông tin về target",
            "Techniques": "OSINT, Social media research, DNS enumeration",
            "Defenses": "Limit public information, Monitor for reconnaissance"
        },
        {
            "Step": 2,
            "Phase": "Weaponization",
            "Description": "Tạo payload để exploit vulnerability", 
            "Techniques": "Malware creation, Exploit development",
            "Defenses": "Threat intelligence, Signature updates"
        },
        {
            "Step": 3,
            "Phase": "Delivery",
            "Description": "Gửi weapon đến target",
            "Techniques": "Email attachments, Malicious websites, USB drops",
            "Defenses": "Email filtering, Web filtering, User training"
        },
        {
            "Step": 4,
            "Phase": "Exploitation",
            "Description": "Kích hoạt vulnerability",
            "Techniques": "Buffer overflow, SQL injection, Zero-day exploits",
            "Defenses": "Patching, Input validation, Sandboxing"
        },
        {
            "Step": 5,
            "Phase": "Installation",
            "Description": "Cài đặt backdoor/malware",
            "Techniques": "Remote access tools, Rootkits, Persistence mechanisms",
            "Defenses": "Antivirus, Host-based IDS, Application whitelisting"
        },
        {
            "Step": 6,
            "Phase": "Command & Control",
            "Description": "Thiết lập communication channel",
            "Techniques": "HTTP/HTTPS beaconing, DNS tunneling, P2P networks",
            "Defenses": "Network monitoring, DNS filtering, Egress filtering"
        },
        {
            "Step": 7,
            "Phase": "Actions on Objectives",
            "Description": "Thực hiện mục tiêu cuối cùng",
            "Techniques": "Data exfiltration, System destruction, Lateral movement",
            "Defenses": "DLP, Network segmentation, Monitoring"
        }
    ]
    
    df = pd.DataFrame(kill_chain_steps)
    st.dataframe(df, width='stretch')
    
    # Visualization
    fig = px.funnel(
        df, x='Phase', y='Step',
        title="Cyber Kill Chain Phases",
        color='Step'
    )
    st.plotly_chart(fig, width='stretch')

def explain_mitre_attack():
    """Giải thích MITRE ATT&CK Framework"""
    st.markdown("### 🎯 MITRE ATT&CK Framework")
    
    with st.expander("📖 Lý thuyết chi tiết về MITRE ATT&CK"):
        st.markdown("""
        ### 🎯 What is MITRE ATT&CK?
        
        **Definition:**
        - **ATT&CK**: Adversarial Tactics, Techniques, and Common Knowledge
        - Globally accessible knowledge base of adversary tactics and techniques
        - Based on real-world observations of cyber attacks
        
        **Framework Structure:**
        
        **Tactics (Why):**
        - The adversary's tactical goals during an attack
        - High-level categories of attack objectives
        - Answer the question "What is the adversary trying to achieve?"
        
        **Techniques (How):**
        - How an adversary achieves a tactical goal
        - Specific methods used to accomplish tactics
        - Answer the question "How does the adversary achieve this?"
        
        **Sub-techniques:**
        - More specific descriptions of techniques
        - Granular implementation details
        - Platform-specific variations
        
        ### 🔄 ATT&CK Tactics (14 Categories)
        
        **1. Initial Access (TA0001)**
        - **Goal**: Gain foothold in the network
        - **Examples**: Spear phishing, exploit public-facing applications
        
        **2. Execution (TA0002)**
        - **Goal**: Run malicious code
        - **Examples**: Command line interface, PowerShell
        
        **3. Persistence (TA0003)**
        - **Goal**: Maintain access across restarts
        - **Examples**: Registry run keys, scheduled tasks
        
        **4. Privilege Escalation (TA0004)**
        - **Goal**: Gain higher-level permissions
        - **Examples**: Process injection, access token manipulation
        
        **5. Defense Evasion (TA0005)**
        - **Goal**: Avoid detection
        - **Examples**: Obfuscated files, disable security tools
        
        **6. Credential Access (TA0006)**
        - **Goal**: Steal account credentials
        - **Examples**: Credential dumping, brute force
        
        **7. Discovery (TA0007)**
        - **Goal**: Gather information about the environment
        - **Examples**: System information discovery, network discovery
        
        **8. Lateral Movement (TA0008)**
        - **Goal**: Move through the network
        - **Examples**: Remote services, pass the hash
        
        **9. Collection (TA0009)**
        - **Goal**: Gather data of interest
        - **Examples**: Data from local system, screen capture
        
        **10. Command and Control (TA0011)**
        - **Goal**: Communicate with compromised systems
        - **Examples**: Application layer protocol, encrypted channel
        
        **11. Exfiltration (TA0010)**
        - **Goal**: Steal data from the network
        - **Examples**: Data compressed, exfiltration over C2 channel
        
        **12. Impact (TA0040)**
        - **Goal**: Manipulate, interrupt, or destroy systems/data
        - **Examples**: Data destruction, service stop
        
        ### 🛠️ Using ATT&CK for Defense
        
        **Threat Modeling:**
        - Map potential attack paths
        - Identify critical assets and attack vectors
        - Prioritize security controls
        
        **Detection Engineering:**
        - Develop detection rules based on techniques
        - Create analytics for specific adversary behaviors
        - Test detection capabilities
        
        **Threat Hunting:**
        - Proactively search for adversary techniques
        - Develop hunting hypotheses
        - Validate security controls
        
        **Red Team Exercises:**
        - Simulate real adversary techniques
        - Test defensive capabilities
        - Improve incident response
        
        ### 📊 ATT&CK Matrices
        
        **Enterprise Matrix:**
        - Windows, macOS, Linux environments
        - Cloud platforms (AWS, Azure, GCP)
        - Network infrastructure
        
        **Mobile Matrix:**
        - Android and iOS platforms
        - Mobile-specific techniques
        - Device management challenges
        
        **ICS Matrix:**
        - Industrial Control Systems
        - SCADA environments
        - Critical infrastructure
        
        ### 🔍 Practical Implementation
        
        **Security Operations:**
        - **SIEM Rules**: Map alerts to ATT&CK techniques
        - **Incident Response**: Categorize incidents by tactics
        - **Threat Intelligence**: Attribute adversary techniques
        - **Security Metrics**: Measure coverage by technique
        
        **Risk Assessment:**
        - **Technique Prioritization**: Focus on high-risk techniques
        - **Control Mapping**: Map security controls to techniques
        - **Gap Analysis**: Identify coverage gaps
        - **Investment Planning**: Justify security investments
        """)
    
    # ATT&CK tactics visualization
    st.markdown("#### 🎯 ATT&CK Tactics Overview")
    
    tactics_data = [
        {"Tactic": "Initial Access", "ID": "TA0001", "Techniques": "9", "Description": "Gain foothold"},
        {"Tactic": "Execution", "ID": "TA0002", "Techniques": "12", "Description": "Run malicious code"},
        {"Tactic": "Persistence", "ID": "TA0003", "Techniques": "19", "Description": "Maintain access"},
        {"Tactic": "Privilege Escalation", "ID": "TA0004", "Techniques": "13", "Description": "Gain higher permissions"},
        {"Tactic": "Defense Evasion", "ID": "TA0005", "Techniques": "42", "Description": "Avoid detection"},
        {"Tactic": "Credential Access", "ID": "TA0006", "Techniques": "15", "Description": "Steal credentials"},
        {"Tactic": "Discovery", "ID": "TA0007", "Techniques": "29", "Description": "Gather information"},
        {"Tactic": "Lateral Movement", "ID": "TA0008", "Techniques": "9", "Description": "Move through network"},
        {"Tactic": "Collection", "ID": "TA0009", "Techniques": "17", "Description": "Gather data"},
        {"Tactic": "Command & Control", "ID": "TA0011", "Techniques": "16", "Description": "Communicate with systems"},
        {"Tactic": "Exfiltration", "ID": "TA0010", "Techniques": "9", "Description": "Steal data"},
        {"Tactic": "Impact", "ID": "TA0040", "Techniques": "13", "Description": "Destroy/manipulate"}
    ]
    
    df = pd.DataFrame(tactics_data)
    st.dataframe(df, width='stretch')

def explain_attack_vectors():
    """Giải thích Common Attack Vectors"""
    st.markdown("### 🎯 Common Attack Vectors")
    
    with st.expander("📖 Lý thuyết chi tiết về Attack Vectors"):
        st.markdown("""
        ### 🎯 What are Attack Vectors?
        
        **Definition:**
        - Path or means by which attackers gain access to systems
        - Entry points that attackers exploit
        - Methods used to deliver attacks or gain unauthorized access
        
        ### 🌐 Network-Based Attack Vectors
        
        **1. Malware Distribution**
        - **Email Attachments**: Malicious files via email
        - **Drive-by Downloads**: Compromised websites
        - **USB/Removable Media**: Physical malware delivery
        - **Network Shares**: Lateral movement via shared folders
        
        **2. Network Exploitation**
        - **Unpatched Vulnerabilities**: Exploit known security flaws
        - **Weak Protocols**: Exploit insecure network protocols
        - **Man-in-the-Middle**: Intercept network communications
        - **DNS Poisoning**: Redirect traffic to malicious servers
        
        **3. Remote Access Attacks**
        - **Brute Force**: Password guessing attacks
        - **Credential Stuffing**: Use stolen credential databases
        - **VPN Exploitation**: Compromise remote access systems
        - **RDP Attacks**: Exploit Remote Desktop Protocol
        
        ### 👥 Human-Based Attack Vectors
        
        **1. Social Engineering**
        - **Phishing**: Deceptive emails to steal credentials
        - **Spear Phishing**: Targeted phishing attacks
        - **Pretexting**: Create false scenarios to gain trust
        - **Baiting**: Offer something enticing to victims
        
        **2. Physical Attacks**
        - **Tailgating**: Follow authorized personnel
        - **Dumpster Diving**: Search for sensitive information in trash
        - **Shoulder Surfing**: Observe credentials being entered
        - **Device Theft**: Steal laptops, phones, or storage devices
        
        **3. Insider Threats**
        - **Malicious Insiders**: Employees with harmful intent
        - **Compromised Insiders**: Employees under external control
        - **Negligent Insiders**: Unintentional security violations
        - **Third-Party Risks**: Vendor or contractor access abuse
        
        ### 💻 Application-Based Attack Vectors
        
        **1. Web Application Attacks**
        - **SQL Injection**: Manipulate database queries
        - **Cross-Site Scripting (XSS)**: Inject malicious scripts
        - **Cross-Site Request Forgery (CSRF)**: Force unwanted actions
        - **Directory Traversal**: Access unauthorized files
        
        **2. Software Vulnerabilities**
        - **Buffer Overflows**: Exploit memory management flaws
        - **Zero-Day Exploits**: Use unknown vulnerabilities
        - **Supply Chain Attacks**: Compromise software dependencies
        - **API Vulnerabilities**: Exploit application interfaces
        
        **3. Mobile Application Attacks**
        - **Malicious Apps**: Trojan applications
        - **App Store Poisoning**: Compromise legitimate app stores
        - **Side-loading**: Install apps from untrusted sources
        - **Mobile Malware**: Device-specific malicious software
        
        ### ☁️ Cloud-Based Attack Vectors
        
        **1. Cloud Misconfigurations**
        - **Open Storage Buckets**: Publicly accessible data
        - **Weak Access Controls**: Overprivileged accounts
        - **Insecure APIs**: Vulnerable cloud interfaces
        - **Default Credentials**: Unchanged default passwords
        
        **2. Cloud Service Attacks**
        - **Account Takeover**: Compromise cloud accounts
        - **Resource Hijacking**: Use cloud resources for attacks
        - **Data Breaches**: Steal data from cloud storage
        - **Service Disruption**: Denial of service attacks
        
        ### 🔧 IoT and Emerging Attack Vectors
        
        **1. Internet of Things (IoT)**
        - **Weak Device Security**: Default passwords, no updates
        - **Insecure Communications**: Unencrypted data transmission
        - **Physical Access**: Direct device manipulation
        - **Botnet Recruitment**: Use IoT devices for attacks
        
        **2. Emerging Technologies**
        - **AI/ML Poisoning**: Manipulate training data
        - **Blockchain Attacks**: Exploit cryptocurrency systems
        - **5G Vulnerabilities**: New network attack surfaces
        - **Edge Computing**: Distributed system vulnerabilities
        
        ### 🛡️ Attack Vector Mitigation Strategies
        
        **Technical Controls:**
        - **Patch Management**: Keep systems updated
        - **Network Segmentation**: Limit attack spread
        - **Access Controls**: Implement least privilege
        - **Monitoring**: Detect suspicious activities
        
        **Administrative Controls:**
        - **Security Policies**: Define security requirements
        - **Training Programs**: Educate users about threats
        - **Incident Response**: Prepare for security incidents
        - **Risk Assessments**: Identify and prioritize risks
        
        **Physical Controls:**
        - **Access Controls**: Secure physical locations
        - **Surveillance**: Monitor physical areas
        - **Environmental**: Protect against environmental threats
        - **Device Security**: Secure endpoints and devices
        """)
    
    # Attack vector frequency chart
    st.markdown("#### 📊 Attack Vector Frequency (2023 Data)")
    
    attack_vector_data = [
        {"Vector": "Phishing/Social Engineering", "Frequency": "45%", "Severity": "High", "Trend": "Increasing"},
        {"Vector": "Unpatched Vulnerabilities", "Frequency": "25%", "Severity": "Critical", "Trend": "Stable"},
        {"Vector": "Weak/Stolen Credentials", "Frequency": "20%", "Severity": "High", "Trend": "Increasing"},
        {"Vector": "Malware/Ransomware", "Frequency": "15%", "Severity": "Critical", "Trend": "Increasing"},
        {"Vector": "Insider Threats", "Frequency": "10%", "Severity": "Medium", "Trend": "Stable"},
        {"Vector": "Physical Attacks", "Frequency": "5%", "Severity": "Medium", "Trend": "Decreasing"},
        {"Vector": "Supply Chain", "Frequency": "8%", "Severity": "High", "Trend": "Increasing"},
        {"Vector": "Cloud Misconfigurations", "Frequency": "12%", "Severity": "High", "Trend": "Increasing"}
    ]
    
    df = pd.DataFrame(attack_vector_data)
    st.dataframe(df, width='stretch')

def explain_social_engineering():
    """Giải thích Social Engineering"""
    st.markdown("### 🎭 Social Engineering")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("""
        **Social Engineering** là nghệ thuật manipulate con người để reveal information:
        
        **🧠 Psychology Principles:**
        - **Authority:** People obey authority figures
        - **Reciprocity:** People return favors
        - **Social Proof:** People follow others
        - **Scarcity:** Limited time/availability creates urgency
        - **Liking:** People say yes to people they like
        - **Commitment:** People align with commitments
        """)
        
        se_techniques = [
            {"Technique": "Phishing", "Method": "Fraudulent emails", "Target": "Credentials, Personal info"},
            {"Technique": "Pretexting", "Method": "Fabricated scenario", "Target": "Sensitive information"},
            {"Technique": "Baiting", "Method": "Malicious media/downloads", "Target": "System access"},
            {"Technique": "Quid Pro Quo", "Method": "Service for information", "Target": "Access credentials"},
            {"Technique": "Tailgating", "Method": "Physical following", "Target": "Physical access"},
            {"Technique": "Vishing", "Method": "Voice/phone calls", "Target": "Verbal information"}
        ]
        
        df = pd.DataFrame(se_techniques)
        st.dataframe(df, width='stretch')
    
    with col2:
        st.markdown("""
        **🛡️ Defense Strategies:**
        
        **Technical Controls:**
        - Email filtering and authentication
        - Multi-factor authentication
        - Access controls and monitoring
        - Security awareness tools
        
        **Administrative Controls:**
        - Security policies and procedures
        - Regular security training
        - Incident response plans
        - Background checks
        
        **Physical Controls:**
        - Badge systems and escorts
        - Security cameras
        - Secure disposal of documents
        - Clean desk policies
        """)
        
        st.markdown("""
        **🚨 Red Flags:**
        - Urgency and pressure tactics
        - Requests for sensitive information
        - Unusual communication methods
        - Too good to be true offers
        - Requests to bypass security procedures
        """)

def cryptography_concepts():
    """Khái niệm mật mã học"""
    st.subheader("🔐 Cryptography Concepts")
    
    crypto_topic = st.selectbox("Chọn chủ đề:", [
        "Symmetric vs Asymmetric Encryption",
        "Hash Functions & Digital Signatures",
        "Key Management",
        "Cryptographic Attacks",
        "Modern Cryptography Standards"
    ])
    
    if crypto_topic == "Symmetric vs Asymmetric Encryption":
        explain_encryption_types()
    elif crypto_topic == "Hash Functions & Digital Signatures":
        explain_hash_signatures()
    elif crypto_topic == "Key Management":
        explain_key_management()
    elif crypto_topic == "Cryptographic Attacks":
        explain_cryptographic_attacks()
    elif crypto_topic == "Modern Cryptography Standards":
        explain_modern_cryptography_standards()

def explain_encryption_types():
    """Enhanced Encryption Types explanation using TDD pattern"""
    st.markdown("### Encryption Types")
    
    # 1. Visual Banner (Theory & Concepts color scheme)
    st.markdown("""
    <div style="background: linear-gradient(90deg, #ff6b6b 0%, #feca57 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            Encryption Types
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Symmetric vs Asymmetric Cryptography
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 2. Visual Diagram (Enhanced encryption comparison)
    st.markdown("#### Encryption Methods Comparison")
    
    fig = go.Figure()
    
    # Create side-by-side encryption visualization
    # Symmetric encryption side
    fig.add_shape(
        type="rect",
        x0=0.5, y0=2, x1=2.5, y1=4,
        fillcolor="#3498db",
        opacity=0.8,
        line=dict(color="white", width=2)
    )
    
    fig.add_annotation(
        x=1.5, y=3.5,
        text="<b>Symmetric<br>Encryption</b>",
        showarrow=False,
        font=dict(size=12, color="white")
    )
    
    # Symmetric key visualization
    fig.add_shape(
        type="circle",
        x0=1.2, y0=2.8, x1=1.8, y1=3.2,
        fillcolor="#e74c3c",
        opacity=0.9,
        line=dict(color="white", width=1)
    )
    
    fig.add_annotation(
        x=1.5, y=3,
        text="🔑",
        showarrow=False,
        font=dict(size=16)
    )
    
    fig.add_annotation(
        x=1.5, y=2.5,
        text="Same Key",
        showarrow=False,
        font=dict(size=8, color="#2c3e50")
    )
    
    # Asymmetric encryption side
    fig.add_shape(
        type="rect",
        x0=3.5, y0=2, x1=5.5, y1=4,
        fillcolor="#9b59b6",
        opacity=0.8,
        line=dict(color="white", width=2)
    )
    
    fig.add_annotation(
        x=4.5, y=3.5,
        text="<b>Asymmetric<br>Encryption</b>",
        showarrow=False,
        font=dict(size=12, color="white")
    )
    
    # Asymmetric keys visualization
    fig.add_shape(
        type="circle",
        x0=3.8, y0=2.8, x1=4.2, y1=3.2,
        fillcolor="#f39c12",
        opacity=0.9,
        line=dict(color="white", width=1)
    )
    
    fig.add_shape(
        type="circle",
        x0=4.8, y0=2.8, x1=5.2, y1=3.2,
        fillcolor="#2ecc71",
        opacity=0.9,
        line=dict(color="white", width=1)
    )
    
    fig.add_annotation(
        x=4, y=3,
        text="🔑",
        showarrow=False,
        font=dict(size=12)
    )
    
    fig.add_annotation(
        x=5, y=3,
        text="🔓",
        showarrow=False,
        font=dict(size=12)
    )
    
    fig.add_annotation(
        x=4.5, y=2.5,
        text="Public + Private Keys",
        showarrow=False,
        font=dict(size=8, color="#2c3e50")
    )
    
    # Add characteristics below each type
    symmetric_chars = ["⚡ Fast", "🔒 Secure", "🗝️ Key Distribution Challenge"]
    asymmetric_chars = ["🐌 Slower", "🔐 Key Exchange", "📈 Scalable"]
    
    for i, char in enumerate(symmetric_chars):
        fig.add_annotation(
            x=1.5, y=1.6 - (i * 0.2),
            text=char,
            showarrow=False,
            font=dict(size=9, color="#2c3e50"),
            bgcolor="rgba(255,255,255,0.8)",
            bordercolor="#3498db",
            borderwidth=1,
            borderpad=2
        )
    
    for i, char in enumerate(asymmetric_chars):
        fig.add_annotation(
            x=4.5, y=1.6 - (i * 0.2),
            text=char,
            showarrow=False,
            font=dict(size=9, color="#2c3e50"),
            bgcolor="rgba(255,255,255,0.8)",
            bordercolor="#9b59b6",
            borderwidth=1,
            borderpad=2
        )
    
    # Add title and hybrid approach
    fig.add_annotation(
        x=3, y=4.5,
        text="<b>Modern Approach: Hybrid Encryption</b><br>Use asymmetric for key exchange, symmetric for data",
        showarrow=False,
        font=dict(size=10, color="#e67e22"),
        bgcolor="rgba(255,255,255,0.9)",
        bordercolor="#e67e22",
        borderwidth=2,
        borderpad=5
    )
    
    fig.update_layout(
        xaxis=dict(range=[0, 6], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0.5, 5], showgrid=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=400,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # 3. Clean Content with expandable details
    with st.expander("Chi tiết về Encryption Types"):
        st.markdown("""
        ## Modern Encryption Fundamentals
        
        **Definition:** Encryption là process of converting plaintext into ciphertext using mathematical algorithms và keys để protect data confidentiality.
        
        ---
        
        ## Symmetric Encryption (Private Key Cryptography)
        
        ### **Core Concept**
        **Same Key for Both Operations:** Encryption và decryption use the identical secret key
        **Speed Advantage:** Significantly faster than asymmetric encryption
        **Key Challenge:** Secure key distribution và management
        
        ### **Modern Symmetric Algorithms (2024)**
        
        #### **AES (Advanced Encryption Standard)** - Industry Standard
        **Key Sizes:** `128-bit`, `192-bit`, `256-bit` (AES-256 recommended)
        **Block Size:** 128-bit blocks với multiple operation modes
        **Performance:** Hardware acceleration available on modern CPUs
        **Security Status:** **NIST approved**, quantum-resistant for near term
        **Use Cases:** File encryption, database encryption, **TLS/SSL**, VPN tunnels
        
        #### **ChaCha20-Poly1305** - Modern Stream Cipher
        **Key Size:** 256-bit key với 96-bit nonce
        **Performance:** **Excellent on mobile devices**, software-optimized
        **Authentication:** Built-in AEAD (Authenticated Encryption với Associated Data)
        **Security Status:** **Google adoption**, TLS 1.3 cipher suite
        **Use Cases:** **Mobile apps**, IoT devices, **real-time communications**
        
        #### **Legacy Algorithms (Avoid)**
        **DES:** 56-bit key - **DEPRECATED** (broken in 1999)
        **3DES:** Triple DES - **Legacy only** (NIST deprecated 2023)
        **RC4:** Stream cipher - **Severely compromised**
        
        ### **Symmetric Encryption Modes**
        **CBC (Cipher Block Chaining):** Sequential processing với IV
        **GCM (Galois/Counter Mode):** **Parallel processing** với authentication
        **CTR (Counter Mode):** Stream-like operation, **high performance**
        **XTS:** Disk encryption mode, **sector-based protection**
        
        ---
        
        ## Asymmetric Encryption (Public Key Cryptography)
        
        ### **Core Concept**
        **Key Pair System:** Mathematically related public và private keys
        **Key Exchange Solution:** Eliminates pre-shared secret requirement
        **Digital Signatures:** Non-repudiation và authenticity verification
        
        ### **Modern Asymmetric Algorithms (2024)**
        
        #### **RSA (Rivest-Shamir-Adleman)** - Widely Deployed
        **Key Sizes:** `2048-bit` (minimum), `3072-bit`, `4096-bit` (future-proof)
        **Mathematical Basis:** Integer factorization problem
        **Performance:** Slower than ECC, **broad compatibility**
        **Quantum Threat:** **Vulnerable to Shor's algorithm**
        **Use Cases:** **TLS certificates**, email encryption (PGP), **legacy systems**
        
        #### **ECC (Elliptic Curve Cryptography)** - Modern Standard
        **Key Sizes:** `256-bit` (equivalent to 3072-bit RSA)
        **Curves:** `P-256`, `P-384`, `Curve25519` (recommended)
        **Performance:** **Faster than RSA**, lower power consumption
        **Mobile Advantage:** **Smaller keys**, efficient on constrained devices
        **Use Cases:** **Modern TLS**, mobile apps, **IoT security**, blockchain
        
        #### **Post-Quantum Algorithms** - Future-Ready
        **NIST Standards:** Kyber (key encapsulation), Dilithium (signatures)
        **Purpose:** **Quantum-resistant** cryptography
        **Status:** Standardization complete (2024), **early adoption phase**
        **Timeline:** Migration expected by 2030-2035
        
        ### **Key Exchange Protocols**
        **ECDH (Elliptic Curve Diffie-Hellman):** **Perfect Forward Secrecy**
        **RSA Key Transport:** Legacy method, **no forward secrecy**
        **X25519:** Modern curve for key exchange, **high performance**
        
        ---
        
        ## Hybrid Encryption (Modern Best Practice)
        
        ### **Why Hybrid?**
        **Performance:** Use symmetric for data, asymmetric for keys
        **Security:** Combine benefits of both approaches
        **Scalability:** Practical for large-scale systems
        
        ### **Common Implementations**
        **TLS/SSL:** RSA/ECDH key exchange + AES data encryption
        **PGP/GPG:** RSA/ECC key encryption + AES message encryption
        **Signal Protocol:** X25519 key exchange + AES-256-GCM messages
        **WhatsApp:** Double Ratchet với X25519 + AES-256
        """)
    
    # 4. Enhanced Cheat Sheets with highlighted keywords
    st.markdown("---")
    st.markdown("## Encryption Types Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["Algorithm Comparison", "Security Standards", "Implementation Guide"])
    
    with tab1:
        st.markdown("### Encryption Algorithms Comparison")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Algorithm** | **Type** | **Key Size** | **Performance** | **Security Level** | **Use Cases** | **Status (2024)** |
        |---------------|----------|--------------|-----------------|-------------------|---------------|--------------------|
        | **AES-256** | **Symmetric** | **256-bit** | **Very Fast** | **Very High** | **Bulk encryption**, databases, files | **Recommended** |
        | **ChaCha20** | **Symmetric** | **256-bit** | **Fast** (mobile) | **High** | **Mobile apps**, IoT, **real-time** | **Modern Choice** |
        | **RSA-2048** | **Asymmetric** | **2048-bit** | **Slow** | **Medium** (quantum threat) | **Legacy TLS**, certificates | **Minimum Standard** |
        | **RSA-4096** | **Asymmetric** | **4096-bit** | **Very Slow** | **High** (quantum threat) | **High-security** applications | **Future-proof** |
        | **ECC P-256** | **Asymmetric** | **256-bit** | **Medium** | **High** | **Modern TLS**, mobile, **IoT** | **Recommended** |
        | **X25519** | **Key Exchange** | **256-bit** | **Fast** | **Very High** | **Perfect Forward Secrecy** | **Best Practice** |
        | **Kyber-768** | **Post-Quantum** | **768-bit** | **Medium** | **Quantum-Safe** | **Future migration** | **NIST Standard** |
        | **DES** | **Symmetric** | **56-bit** | **Fast** | **Broken** | **None** (legacy only) | **DEPRECATED** |
        """)
        
        # Algorithm selection guide
        st.markdown("""
        #### **Algorithm Selection Guide**
        - **New Projects**: `AES-256` + `X25519` - modern hybrid approach
        - **Mobile/IoT**: `ChaCha20-Poly1305` - optimized for constrained devices
        - **Legacy Support**: `RSA-2048` + `AES-128` - broad compatibility
        - **Future-Proof**: Start planning `post-quantum` migration
        """)
    
    with tab2:
        st.markdown("### Security Standards & Compliance")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Standard/Framework** | **Symmetric Requirements** | **Asymmetric Requirements** | **Key Exchange** | **Compliance** |
        |------------------------|----------------------------|------------------------------|------------------|----------------|
        | **NIST SP 800-57** | **AES-128/256**, ChaCha20 | **RSA-2048+**, ECC P-256+ | **ECDH**, RSA-OAEP | **US Federal** |
        | **FIPS 140-2** | **AES only** (certified implementations) | **RSA, ECDSA** (approved curves) | **ECDH, RSA** | **Government** |
        | **Common Criteria** | **AES-256**, approved algorithms | **ECC P-384+**, RSA-3072+ | **ECDH** preferred | **International** |
        | **PCI DSS** | **AES-128+** for cardholder data | **RSA-2048+** for key transport | **Strong cryptography** | **Payment Industry** |
        | **HIPAA** | **AES-256** recommended | **RSA-2048+** minimum | **Secure key exchange** | **Healthcare** |
        | **GDPR** | **State-of-the-art** encryption | **Strong public key** systems | **Perfect Forward Secrecy** | **EU Data Protection** |
        | **SOX** | **Strong encryption** for financial data | **Multi-factor** key protection | **Secure protocols** | **Financial Reporting** |
        | **ISO 27001** | **Risk-based** algorithm selection | **Regular key rotation** | **Secure key management** | **Information Security** |
        """)
        
        st.markdown("""
        #### **Compliance Implementation Tips**
        - **Document Algorithm Selection**: Justify choices based on risk assessment
        - **Regular Security Reviews**: Update algorithms as standards evolve
        - **Key Management**: Implement proper key lifecycle management
        - **Audit Trails**: Maintain logs of cryptographic operations
        """)
    
    with tab3:
        st.markdown("### Implementation Best Practices")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Implementation Aspect** | **Symmetric Best Practices** | **Asymmetric Best Practices** | **Common Pitfalls** | **Mitigation** |
        |---------------------------|-------------------------------|--------------------------------|---------------------|----------------|
        | **Key Generation** | **Cryptographically secure** RNG | **Proper entropy** for key pairs | **Weak random numbers** | Use **hardware RNG** when available |
        | **Key Storage** | **HSM** or secure key vault | **Private key protection** | **Plaintext key storage** | **Encrypt keys at rest** |
        | **Key Rotation** | **Regular rotation** (quarterly) | **Certificate renewal** process | **Stale keys** in production | **Automated rotation** |
        | **IV/Nonce Management** | **Unique IV** for each operation | **N/A** (not applicable) | **IV reuse attacks** | **Counter-based** or random IV |
        | **Padding** | **PKCS#7** for block ciphers | **OAEP** for RSA encryption | **Padding oracle attacks** | Use **authenticated encryption** |
        | **Side-Channel Protection** | **Constant-time** implementations | **Blinding techniques** | **Timing attacks** | **Vetted crypto libraries** |
        | **Performance** | **Hardware acceleration** (AES-NI) | **ECC over RSA** for new projects | **Inefficient implementations** | **Benchmark và optimize** |
        | **Error Handling** | **Fail securely**, no info leakage | **Consistent error messages** | **Information disclosure** | **Generic error responses** |
        """)
        
        st.markdown("""
        #### **Development Guidelines**
        - **Never Roll Your Own Crypto**: Use established, audited libraries
        - **Library Selection**: `libsodium`, `OpenSSL`, `Bouncy Castle`
        - **Code Reviews**: Specialized security review for crypto code
        - **Testing**: Include cryptographic test vectors và edge cases
        """)
    
    # 5. Interactive Demo
    st.markdown("---")
    st.markdown("## Interactive Demo")
    
    with st.expander("Encryption Algorithm Selector"):
        st.markdown("### Choose the Right Encryption for Your Use Case")
        
        # Use case selector
        use_case = st.selectbox(
            "Select your use case:",
            ["Web Application (HTTPS)", "Mobile App", "IoT Device", "File Storage", "Database Encryption", "Messaging App"]
        )
        
        # Security requirements
        security_level = st.selectbox("Security Requirements:", ["Standard", "High Security", "Government/Military"])
        
        # Performance requirements
        performance = st.selectbox("Performance Priority:", ["Speed Critical", "Balanced", "Security Over Speed"])
        
        if st.button("Get Encryption Recommendation"):
            st.markdown(f"### Recommended Encryption for: **{use_case}**")
            
            if use_case == "Web Application (HTTPS)":
                st.markdown("""
                **🌐 Web Application Encryption Strategy:**
                
                **TLS Configuration:**
                - **TLS 1.3** với modern cipher suites
                - **Certificate**: ECC P-256 or RSA-2048
                - **Key Exchange**: X25519 (ECDH)
                - **Symmetric**: AES-256-GCM or ChaCha20-Poly1305
                
                **Application Layer:**
                - **Session Data**: AES-256-GCM với secure session management
                - **Database**: AES-256 for sensitive fields
                - **API Tokens**: JWT với RS256 or ES256 signatures
                """)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("TLS Version", "1.3")
                with col2:
                    st.metric("Cipher Suite", "ChaCha20-Poly1305")
                with col3:
                    st.metric("Key Exchange", "X25519")
                    
            elif use_case == "Mobile App":
                st.markdown("""
                **📱 Mobile App Encryption Strategy:**
                
                **Network Communication:**
                - **Certificate Pinning** với TLS 1.3
                - **ChaCha20-Poly1305** for optimal mobile performance
                - **X25519** key exchange for Perfect Forward Secrecy
                
                **Local Storage:**
                - **Keystore/Keychain** integration for key management
                - **AES-256-GCM** for local database encryption
                - **Biometric** authentication for key unlock
                
                **End-to-End Messaging:**
                - **Signal Protocol** implementation
                - **Double Ratchet** for forward và backward secrecy
                """)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Battery Impact", "Low")
                with col2:
                    st.metric("Key Storage", "Secure Enclave")
                with col3:
                    st.metric("E2E Encryption", "Signal Protocol")
                    
            elif use_case == "IoT Device":
                st.markdown("""
                **🔗 IoT Device Encryption Strategy:**
                
                **Constrained Device Optimization:**
                - **ChaCha20** for software-only implementations
                - **ECC P-256** for minimal key storage
                - **DTLS 1.3** for UDP-based communication
                
                **Device Authentication:**
                - **Device certificates** với ECC keys
                - **Mutual TLS** for device-to-cloud authentication
                - **Hardware security** modules when available
                
                **Power Management:**
                - **Session resumption** to minimize handshakes
                - **Efficient cipher suites** for battery life
                """)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Power Efficiency", "Optimized")
                with col2:
                    st.metric("Memory Usage", "Minimal")
                with col3:
                    st.metric("Key Size", "256-bit ECC")
                    
        # Show security recommendations based on selections
        st.markdown("### Security Recommendations:")
        if security_level == "Government/Military":
            st.warning("🔒 **High Security**: Consider FIPS 140-2 certified implementations và post-quantum planning")
        elif security_level == "High Security":
            st.info("🛡️ **Enhanced Security**: Use AES-256, RSA-4096, và implement perfect forward secrecy")
        else:
            st.success("✅ **Standard Security**: AES-128/256 và RSA-2048 provide excellent protection")
    
    # 6. Key Takeaways
    st.markdown("---")
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1.5rem; border-radius: 10px; border-left: 5px solid #1f77b4;">
        <h4 style="margin-top: 0; color: #1f77b4;">Key Takeaways</h4>
        <ul>
            <li><strong>Hybrid Approach</strong>: Modern systems use asymmetric encryption for key exchange và symmetric for data encryption</li>
            <li><strong>Algorithm Selection</strong>: Choose based on use case, performance requirements, và compliance needs</li>
            <li><strong>Key Management</strong>: Proper key generation, storage, và rotation are critical for security</li>
            <li><strong>Future Planning</strong>: Start preparing for post-quantum cryptography migration by 2030</li>
            <li><strong>Implementation Security</strong>: Use established crypto libraries và follow security best practices</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_hash_signatures():
    """Enhanced Hash Functions & Digital Signatures explanation using TDD pattern"""
    st.markdown("### Hash Functions & Digital Signatures")
    
    # 1. Visual Banner (Theory & Concepts color scheme)
    st.markdown("""
    <div style="background: linear-gradient(90deg, #ff6b6b 0%, #feca57 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            Hash Functions & Digital Signatures
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Data Integrity và Authentication Mechanisms
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 2. Visual Diagram (Enhanced hash function và signature process)
    st.markdown("#### Hash Functions & Digital Signature Process")
    
    fig = go.Figure()
    
    # Hash Function Process (Left side)
    fig.add_annotation(
        x=1.5, y=4.5,
        text="<b>Hash Function Process</b>",
        showarrow=False,
        font=dict(size=14, color="#2c3e50"),
        bgcolor="rgba(52, 152, 219, 0.1)",
        bordercolor="#3498db",
        borderwidth=2,
        borderpad=5
    )
    
    # Input data
    fig.add_shape(
        type="rect",
        x0=0.5, y0=3.5, x1=2.5, y1=4,
        fillcolor="#3498db",
        opacity=0.8,
        line=dict(color="white", width=2)
    )
    
    fig.add_annotation(
        x=1.5, y=3.75,
        text="Input Data (Any Size)",
        showarrow=False,
        font=dict(size=10, color="white")
    )
    
    # Hash function
    fig.add_shape(
        type="circle",
        x0=1.2, y0=2.8, x1=1.8, y1=3.2,
        fillcolor="#e74c3c",
        opacity=0.9,
        line=dict(color="white", width=2)
    )
    
    fig.add_annotation(
        x=1.5, y=3,
        text="Hash\nFunction",
        showarrow=False,
        font=dict(size=9, color="white")
    )
    
    # Hash output
    fig.add_shape(
        type="rect",
        x0=0.8, y0=2, x1=2.2, y1=2.4,
        fillcolor="#2ecc71",
        opacity=0.8,
        line=dict(color="white", width=2)
    )
    
    fig.add_annotation(
        x=1.5, y=2.2,
        text="Fixed-Size Hash",
        showarrow=False,
        font=dict(size=10, color="white")
    )
    
    # Arrows for hash process
    fig.add_annotation(
        x=1.5, y=2.65,
        ax=1.5, ay=3.4,
        arrowhead=2, arrowsize=1.5, arrowwidth=2, arrowcolor="#34495e",
        showarrow=True, text=""
    )
    
    fig.add_annotation(
        x=1.5, y=2.55,
        ax=1.5, ay=2.8,
        arrowhead=2, arrowsize=1.5, arrowwidth=2, arrowcolor="#34495e",
        showarrow=True, text=""
    )
    
    # Digital Signature Process (Right side)
    fig.add_annotation(
        x=4.5, y=4.5,
        text="<b>Digital Signature Process</b>",
        showarrow=False,
        font=dict(size=14, color="#2c3e50"),
        bgcolor="rgba(155, 89, 182, 0.1)",
        bordercolor="#9b59b6",
        borderwidth=2,
        borderpad=5
    )
    
    # Message
    fig.add_shape(
        type="rect",
        x0=3.5, y0=3.8, x1=5.5, y1=4.2,
        fillcolor="#3498db",
        opacity=0.8,
        line=dict(color="white", width=2)
    )
    
    fig.add_annotation(
        x=4.5, y=4,
        text="Message",
        showarrow=False,
        font=dict(size=10, color="white")
    )
    
    # Hash + Private Key
    fig.add_shape(
        type="rect",
        x0=3.8, y0=3.2, x1=5.2, y1=3.6,
        fillcolor="#f39c12",
        opacity=0.8,
        line=dict(color="white", width=2)
    )
    
    fig.add_annotation(
        x=4.5, y=3.4,
        text="Hash + Private Key",
        showarrow=False,
        font=dict(size=9, color="white")
    )
    
    # Digital Signature
    fig.add_shape(
        type="rect",
        x0=3.8, y0=2.4, x1=5.2, y1=2.8,
        fillcolor="#9b59b6",
        opacity=0.8,
        line=dict(color="white", width=2)
    )
    
    fig.add_annotation(
        x=4.5, y=2.6,
        text="Digital Signature",
        showarrow=False,
        font=dict(size=10, color="white")
    )
    
    # Arrows for signature process
    fig.add_annotation(
        x=4.5, y=3.65,
        ax=4.5, ay=3.8,
        arrowhead=2, arrowsize=1.5, arrowwidth=2, arrowcolor="#34495e",
        showarrow=True, text=""
    )
    
    fig.add_annotation(
        x=4.5, y=3.05,
        ax=4.5, ay=3.2,
        arrowhead=2, arrowsize=1.5, arrowwidth=2, arrowcolor="#34495e",
        showarrow=True, text=""
    )
    
    # Hash properties annotations
    hash_properties = ["Deterministic", "Fixed Size", "One-Way", "Avalanche Effect"]
    for i, prop in enumerate(hash_properties):
        fig.add_annotation(
            x=1.5, y=1.5 - (i * 0.2),
            text=f"• {prop}",
            showarrow=False,
            font=dict(size=8, color="#2c3e50"),
            bgcolor="rgba(255,255,255,0.8)",
            bordercolor="#3498db",
            borderwidth=1,
            borderpad=2
        )
    
    # Signature properties annotations  
    sig_properties = ["Authentication", "Non-repudiation", "Integrity", "Timestamping"]
    for i, prop in enumerate(sig_properties):
        fig.add_annotation(
            x=4.5, y=1.5 - (i * 0.2),
            text=f"• {prop}",
            showarrow=False,
            font=dict(size=8, color="#2c3e50"),
            bgcolor="rgba(255,255,255,0.8)",
            bordercolor="#9b59b6",
            borderwidth=1,
            borderpad=2
        )
    
    fig.update_layout(
        xaxis=dict(range=[0, 6], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0, 5], showgrid=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=450,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # 3. Clean Content with expandable details
    with st.expander("Chi tiết về Hash Functions & Digital Signatures"):
        st.markdown("""
        ## Modern Hash Functions & Digital Signatures
        
        **Definition:** Hash functions create fixed-size digital fingerprints of data, while digital signatures provide authentication và integrity verification using asymmetric cryptography.
        
        ---
        
        ## Hash Functions Fundamentals
        
        ### **Core Properties (Security Requirements)**
        
        #### **1. Deterministic**
        **Definition:** Same input always produces identical output
        **Importance:** Consistency for verification và integrity checking
        **Example:** `SHA-256("hello")` always equals `2cf24dba4f21d4288094e6a2b0fcb6a`
        
        #### **2. Fixed Output Size**
        **Definition:** Output length remains constant regardless of input size
        **Benefits:** Predictable storage requirements, uniform security level
        **Examples:** SHA-256 always produces 256 bits (64 hex characters)
        
        #### **3. Pre-image Resistance (One-Way)**
        **Definition:** Computationally infeasible to find input from hash output
        **Security Level:** Should require 2^n operations for n-bit hash
        **Real-world Impact:** Passwords can be stored as hashes safely
        
        #### **4. Second Pre-image Resistance**
        **Definition:** Cannot find different input với same hash as given input
        **Attack Prevention:** Prevents malicious file substitution
        **Requirement:** 2^n operations for n-bit security
        
        #### **5. Collision Resistance**
        **Definition:** Extremely difficult to find any two inputs với same hash
        **Attack Prevention:** Prevents hash-based forgeries
        **Security Level:** 2^(n/2) operations due to birthday paradox
        
        #### **6. Avalanche Effect**
        **Definition:** Small input change causes dramatic output change
        **Benefit:** Detects minimal data modifications
        **Example:** `SHA-256("hello")` vs `SHA-256("Hello")` completely different
        
        ---
        
        ## Modern Hash Algorithms (2024 Status)
        
        ### **Recommended Algorithms**
        
        #### **SHA-2 Family (Current Standard)**
        **SHA-256:** 256-bit output, **widely deployed**, hardware acceleration
        **SHA-384:** 384-bit output, **high security** applications
        **SHA-512:** 512-bit output, **maximum security**, 64-bit optimized
        **Security Status:** **NIST approved**, quantum-resistant for near term
        **Use Cases:** TLS/SSL, Bitcoin, **general purpose** hashing
        
        #### **SHA-3 (Keccak) - Latest NIST Standard**
        **Design:** **Different construction** from SHA-2 (sponge function)
        **Variants:** SHA3-256, SHA3-384, SHA3-512, SHAKE128/256
        **Advantage:** **Backup standard** if SHA-2 vulnerabilities found
        **Performance:** Slightly slower than SHA-2, **better security margin**
        **Use Cases:** **New systems**, cryptographic protocols, **long-term security**
        
        #### **BLAKE2 - High Performance**
        **Variants:** BLAKE2b (64-bit), BLAKE2s (32-bit)
        **Performance:** **Faster than SHA-2**, comparable security
        **Features:** Built-in keyed hashing, **personalization**, tree hashing
        **Use Cases:** **High-throughput** applications, file systems, **password hashing**
        
        ### **Legacy Algorithms (Avoid)**
        **MD5:** 128-bit - **BROKEN** (collision attacks practical since 2004)
        **SHA-1:** 160-bit - **DEPRECATED** (collision demonstrated 2017)
        **MD4:** 128-bit - **SEVERELY COMPROMISED**
        
        ---
        
        ## Digital Signatures Deep Dive
        
        ### **Digital Signature Process**
        
        #### **Signing Process**
        1. **Hash the Message:** Apply cryptographic hash function
        2. **Apply Private Key:** Encrypt hash với signer's private key
        3. **Attach Signature:** Combine original message với signature
        4. **Timestamp (Optional):** Add trusted timestamp for non-repudiation
        
        #### **Verification Process**
        1. **Extract Components:** Separate message, signature, và metadata
        2. **Hash Message:** Apply same hash function to received message
        3. **Decrypt Signature:** Use signer's public key to decrypt signature
        4. **Compare Hashes:** Verify computed hash matches decrypted hash
        5. **Check Certificate:** Validate signer's public key certificate
        
        ### **Modern Signature Algorithms (2024)**
        
        #### **RSA Signatures - Widely Supported**
        **Key Sizes:** `2048-bit` (minimum), `3072-bit`, `4096-bit`
        **Hash Functions:** SHA-256, SHA-384, SHA-512
        **Padding:** **PSS** (preferred) or PKCS#1 v1.5 (legacy)
        **Performance:** Slow signing/verification, **large signatures**
        **Quantum Threat:** **Vulnerable** to Shor's algorithm
        
        #### **ECDSA - Modern Standard**
        **Curves:** P-256, P-384, P-521 (NIST), secp256k1 (Bitcoin)
        **Performance:** **Faster than RSA**, smaller signatures
        **Security:** Based on elliptic curve discrete logarithm
        **Use Cases:** **TLS certificates**, mobile devices, **blockchain**
        
        #### **EdDSA - Next Generation**
        **Variants:** **Ed25519** (256-bit), Ed448 (448-bit)
        **Advantages:** **Faster verification**, deterministic signatures
        **Security Features:** Built-in protection against side-channel attacks
        **Use Cases:** **SSH**, modern protocols, **high-performance** applications
        
        #### **Post-Quantum Signatures**
        **NIST Standards:** **Dilithium**, Falcon, SPHINCS+
        **Purpose:** Quantum-resistant digital signatures
        **Status:** **Standardized 2024**, early deployment phase
        **Timeline:** Migration recommended by **2030-2035**
        
        ### **Security Properties Provided**
        
        #### **Authentication**
        **Verification:** Confirms identity of message sender
        **Non-forgery:** Only private key holder can create valid signatures
        **Trust Model:** Based on PKI certificate validation
        
        #### **Non-repudiation**
        **Legal Proof:** Signer cannot deny creating signature
        **Timestamp Integration:** Proves when signature was created
        **Audit Trail:** Cryptographic evidence for legal proceedings
        
        #### **Message Integrity**
        **Tamper Detection:** Any message modification invalidates signature
        **Completeness:** Ensures entire message is authentic
        **Granular Protection:** Can sign specific parts of documents
        """)
    
    # 4. Enhanced Cheat Sheets with highlighted keywords
def explain_key_management():
    """Giải thích Key Management"""
    st.markdown("### 🔑 Key Management")
    
    with st.expander("📖 Lý thuyết chi tiết về Key Management"):
        st.markdown("""
        ### 🔑 What is Key Management?
        
        **Definition:**
        - Process of generating, distributing, storing, and destroying cryptographic keys
        - Critical component of any cryptographic system
        - Ensures confidentiality, integrity, and availability of keys
        
        **Key Management Lifecycle:**
        
        **1. Key Generation**
        - Create cryptographically strong keys
        - Use secure random number generators
        - Appropriate key length for security level
        
        **2. Key Distribution**
        - Securely deliver keys to authorized parties
        - Prevent interception during transmission
        - Authenticate key recipients
        
        **3. Key Storage**
        - Protect keys from unauthorized access
        - Use hardware security modules (HSMs)
        - Implement access controls and auditing
        
        **4. Key Usage**
        - Control how and when keys are used
        - Implement key separation principles
        - Monitor key usage patterns
        
        **5. Key Rotation**
        - Regularly replace keys with new ones
        - Maintain backward compatibility
        - Minimize exposure window
        
        **6. Key Destruction**
        - Securely delete keys when no longer needed
        - Ensure complete removal from all systems
        - Maintain audit trails
        
        ### 🏗️ Key Management Architecture
        
        **Centralized Key Management**
        - **Advantages**: Consistent policies, easier auditing
        - **Disadvantages**: Single point of failure, scalability issues
        - **Use Case**: Small to medium organizations
        
        **Distributed Key Management**
        - **Advantages**: Better scalability, fault tolerance
        - **Disadvantages**: Complex synchronization, policy enforcement
        - **Use Case**: Large enterprises, cloud environments
        
        **Hierarchical Key Management**
        - **Structure**: Master keys protect lower-level keys
        - **Advantages**: Efficient key distribution, reduced complexity
        - **Use Case**: PKI systems, enterprise environments
        
        ### 🔐 Key Types and Purposes
        
        **Master Keys (KEK - Key Encryption Keys)**
        - Encrypt other keys
        - Highest security level
        - Rarely used directly for data
        
        **Data Encryption Keys (DEK)**
        - Encrypt actual data
        - Generated frequently
        - Protected by master keys
        
        **Session Keys**
        - Temporary keys for single session
        - Generated dynamically
        - Destroyed after use
        
        **Authentication Keys**
        - Verify identity
        - Used for digital signatures
        - Long-term validity
        
        ### 🛡️ Key Storage Solutions
        
        **Hardware Security Modules (HSMs)**
        - **Features**: Tamper-resistant hardware, secure key generation
        - **Types**: Network-attached, PCIe cards, USB tokens
        - **Use Case**: High-security environments, compliance requirements
        
        **Key Management Services (KMS)**
        - **Cloud KMS**: AWS KMS, Azure Key Vault, Google Cloud KMS
        - **Features**: Scalable, managed service, integration with cloud services
        - **Use Case**: Cloud-native applications
        
        **Software-Based Key Stores**
        - **Examples**: PKCS#12 files, Java KeyStore, Windows Certificate Store
        - **Features**: Cost-effective, flexible
        - **Use Case**: Development, testing, low-security environments
        
        **Smart Cards and Tokens**
        - **Features**: Portable, user-controlled
        - **Use Case**: User authentication, mobile workers
        
        ### 🔄 Key Rotation Strategies
        
        **Time-Based Rotation**
        - Rotate keys at regular intervals
        - Reduces exposure window
        - Balances security and operational overhead
        
        **Usage-Based Rotation**
        - Rotate after specific number of operations
        - Prevents cryptanalytic attacks
        - Suitable for high-volume systems
        
        **Event-Based Rotation**
        - Rotate when security events occur
        - Employee termination, suspected compromise
        - Immediate response to threats
        
        ### 📋 Key Management Best Practices
        
        **Security Principles:**
        
        **1. Separation of Duties**
        - Multiple people required for key operations
        - Prevents single person from compromising system
        - Implement dual control mechanisms
        
        **2. Least Privilege**
        - Grant minimum necessary key access
        - Role-based access control
        - Regular access reviews
        
        **3. Defense in Depth**
        - Multiple layers of key protection
        - Combine technical and procedural controls
        - Redundant security measures
        
        **Operational Practices:**
        
        **1. Key Escrow**
        - Secure backup of keys for recovery
        - Legal and regulatory compliance
        - Balance between security and accessibility
        
        **2. Key Recovery**
        - Procedures for key restoration
        - Business continuity planning
        - Minimize data loss scenarios
        
        **3. Audit and Monitoring**
        - Log all key operations
        - Regular security assessments
        - Compliance reporting
        
        ### 🚨 Common Key Management Vulnerabilities
        
        **Weak Key Generation**
        - Predictable random number generators
        - Insufficient entropy sources
        - Inadequate key length
        
        **Insecure Key Storage**
        - Plaintext key storage
        - Weak access controls
        - Inadequate physical security
        
        **Poor Key Distribution**
        - Unencrypted key transmission
        - Lack of authentication
        - Man-in-the-middle attacks
        
        **Inadequate Key Rotation**
        - Keys used too long
        - No rotation procedures
        - Backward compatibility issues
        
        ### 📊 Compliance and Standards
        
        **FIPS 140-2**
        - US government standard for cryptographic modules
        - Four security levels (1-4)
        - Hardware and software requirements
        
        **Common Criteria**
        - International standard for security evaluation
        - Protection profiles for key management
        - Evaluation assurance levels
        
        **Industry Standards**
        - **PKCS#11**: Cryptographic token interface
        - **KMIP**: Key Management Interoperability Protocol
        - **IEEE 1619**: Key management for storage devices
        """)
    
    # Key lifecycle visualization
    st.markdown("#### 🔄 Key Lifecycle Management")
    
    lifecycle_data = [
        {"Phase": "Generation", "Duration": "Minutes", "Security Level": "Critical", "Automation": "High"},
        {"Phase": "Distribution", "Duration": "Hours", "Security Level": "Critical", "Automation": "Medium"},
        {"Phase": "Storage", "Duration": "Months/Years", "Security Level": "High", "Automation": "High"},
        {"Phase": "Usage", "Duration": "Continuous", "Security Level": "Medium", "Automation": "High"},
        {"Phase": "Rotation", "Duration": "Days/Months", "Security Level": "High", "Automation": "Medium"},
        {"Phase": "Destruction", "Duration": "Minutes", "Security Level": "Critical", "Automation": "Medium"}
    ]
    
    df = pd.DataFrame(lifecycle_data)
    st.dataframe(df, width='stretch')
    
    # Key management comparison
    st.markdown("#### 🏗️ Key Management Solutions Comparison")
    
    solutions_data = [
        {"Solution": "Hardware HSM", "Security": "Very High", "Cost": "High", "Scalability": "Medium", "Complexity": "High"},
        {"Solution": "Cloud KMS", "Security": "High", "Cost": "Medium", "Scalability": "Very High", "Complexity": "Low"},
        {"Solution": "Software KMS", "Security": "Medium", "Cost": "Low", "Scalability": "High", "Complexity": "Medium"},
        {"Solution": "Smart Cards", "Security": "High", "Cost": "Medium", "Scalability": "Low", "Complexity": "Medium"}
    ]
    
    df2 = pd.DataFrame(solutions_data)
    st.dataframe(df2, width='stretch')

def explain_cryptographic_attacks():
    """Giải thích Cryptographic Attacks"""
    st.markdown("### ⚔️ Cryptographic Attacks")
    
    with st.expander("📖 Lý thuyết chi tiết về Cryptographic Attacks"):
        st.markdown("""
        ### 🎯 Types of Cryptographic Attacks
        
        **Attack Classifications:**
        
        **1. By Attack Model:**
        - **Ciphertext-only**: Only encrypted data available
        - **Known-plaintext**: Some plaintext-ciphertext pairs known
        - **Chosen-plaintext**: Attacker can encrypt chosen plaintexts
        - **Chosen-ciphertext**: Attacker can decrypt chosen ciphertexts
        
        **2. By Target:**
        - **Key Recovery**: Recover the secret key
        - **Plaintext Recovery**: Recover specific plaintext
        - **Distinguishing**: Distinguish from random data
        - **Forgery**: Create valid signatures/MACs
        
        ### 🔓 Classical Cipher Attacks
        
        **Frequency Analysis:**
        - **Target**: Substitution ciphers
        - **Method**: Analyze letter frequency patterns
        - **Countermeasure**: Polyalphabetic ciphers
        - **Tools**: Statistical analysis, pattern matching
        
        **Brute Force Attack:**
        - **Method**: Try all possible keys
        - **Feasibility**: Depends on key space size
        - **Time Complexity**: O(2^n) for n-bit keys
        - **Countermeasure**: Larger key sizes
        
        **Dictionary Attack:**
        - **Target**: Password-based encryption
        - **Method**: Try common passwords/phrases
        - **Enhancement**: Rainbow tables
        - **Countermeasure**: Strong, random passwords
        
        ### 🔐 Modern Cryptographic Attacks
        
        **Differential Cryptanalysis:**
        - **Target**: Block ciphers (DES, AES)
        - **Method**: Analyze input/output differences
        - **Requirements**: Many plaintext-ciphertext pairs
        - **Countermeasure**: Resistance built into modern ciphers
        
        **Linear Cryptanalysis:**
        - **Target**: Block ciphers
        - **Method**: Find linear approximations
        - **Requirements**: Large amounts of data
        - **Countermeasure**: Non-linear S-boxes
        
        **Meet-in-the-Middle Attack:**
        - **Target**: Multiple encryption (2DES)
        - **Method**: Attack from both ends
        - **Complexity**: Reduces from 2^(2n) to 2^(n+1)
        - **Example**: Why 2DES is not secure
        
        **Birthday Attack:**
        - **Target**: Hash functions, digital signatures
        - **Method**: Exploit birthday paradox
        - **Complexity**: O(2^(n/2)) for n-bit hash
        - **Countermeasure**: Larger hash output sizes
        
        ### 🔑 Key-Related Attacks
        
        **Weak Key Attack:**
        - **Target**: Algorithms with weak keys
        - **Examples**: DES weak keys, RSA small factors
        - **Method**: Exploit mathematical properties
        - **Countermeasure**: Key validation, proper generation
        
        **Related Key Attack:**
        - **Method**: Use keys with known relationships
        - **Target**: Key schedules with weaknesses
        - **Application**: Some AES variants vulnerable
        - **Countermeasure**: Strong key schedule design
        
        **Key Recovery Attack:**
        - **Goal**: Extract the secret key
        - **Methods**: Various cryptanalytic techniques
        - **Impact**: Complete compromise of system
        - **Detection**: Often difficult to detect
        
        ### 📱 Implementation Attacks
        
        **Side-Channel Attacks:**
        
        **Timing Attacks:**
        - **Method**: Analyze execution time variations
        - **Target**: RSA, AES implementations
        - **Information**: Key bits from timing differences
        - **Countermeasure**: Constant-time implementations
        
        **Power Analysis:**
        - **Simple Power Analysis (SPA)**: Direct power traces
        - **Differential Power Analysis (DPA)**: Statistical analysis
        - **Target**: Smart cards, embedded devices
        - **Countermeasure**: Power analysis resistant implementations
        
        **Electromagnetic Analysis:**
        - **Method**: Analyze EM emissions
        - **Target**: Any electronic device
        - **Range**: Near-field and far-field attacks
        - **Countermeasure**: Shielding, noise injection
        
        **Fault Injection Attacks:**
        - **Method**: Induce computational errors
        - **Techniques**: Voltage glitching, clock manipulation
        - **Target**: Smart cards, secure processors
        - **Countermeasure**: Error detection and correction
        
        ### 🌐 Protocol-Level Attacks
        
        **Man-in-the-Middle (MITM):**
        - **Method**: Intercept and relay communications
        - **Target**: Key exchange protocols
        - **Requirements**: Network access or compromise
        - **Countermeasure**: Authentication, certificate pinning
        
        **Replay Attack:**
        - **Method**: Resend previously captured messages
        - **Target**: Authentication protocols
        - **Impact**: Unauthorized access or transactions
        - **Countermeasure**: Timestamps, nonces, sequence numbers
        
        **Padding Oracle Attack:**
        - **Target**: CBC mode with padding
        - **Method**: Exploit padding validation errors
        - **Examples**: POODLE, Lucky 13
        - **Countermeasure**: Authenticated encryption
        
        ### 🛡️ Defense Strategies
        
        **Cryptographic Defenses:**
        - **Algorithm Selection**: Use proven, standardized algorithms
        - **Key Management**: Proper generation, distribution, rotation
        - **Mode Selection**: Authenticated encryption modes
        - **Parameter Choices**: Adequate key sizes, secure parameters
        
        **Implementation Defenses:**
        - **Constant-Time**: Eliminate timing variations
        - **Masking**: Randomize intermediate values
        - **Redundancy**: Error detection and correction
        - **Physical Security**: Tamper resistance, shielding
        
        **Protocol Defenses:**
        - **Authentication**: Verify communicating parties
        - **Freshness**: Use nonces, timestamps
        - **Integrity**: Message authentication codes
        - **Forward Secrecy**: Ephemeral key exchange
        
        ### 📊 Attack Complexity Analysis
        
        **Time Complexity:**
        - **Polynomial**: Efficient attacks (broken crypto)
        - **Exponential**: Infeasible attacks (secure crypto)
        - **Sub-exponential**: Borderline (factoring, discrete log)
        
        **Data Complexity:**
        - **Amount of data needed for attack**
        - **Plaintext-ciphertext pairs required**
        - **Queries to encryption/decryption oracles**
        
        **Success Probability:**
        - **Probability of attack success**
        - **Trade-off with time/data complexity**
        - **Acceptable security levels**
        """)
    
    # Attack comparison table
    st.markdown("#### ⚔️ Cryptographic Attack Comparison")
    
    attack_data = [
        {"Attack Type": "Brute Force", "Target": "Any cipher", "Complexity": "2^n", "Data Required": "Minimal", "Countermeasure": "Large keys"},
        {"Attack Type": "Frequency Analysis", "Target": "Substitution", "Complexity": "Polynomial", "Data Required": "Medium", "Countermeasure": "Polyalphabetic"},
        {"Attack Type": "Differential", "Target": "Block ciphers", "Complexity": "2^n/2", "Data Required": "High", "Countermeasure": "Resistant design"},
        {"Attack Type": "Birthday", "Target": "Hash functions", "Complexity": "2^n/2", "Data Required": "Medium", "Countermeasure": "Larger output"},
        {"Attack Type": "Side-channel", "Target": "Implementation", "Complexity": "Low", "Data Required": "Variable", "Countermeasure": "Secure coding"},
        {"Attack Type": "MITM", "Target": "Protocols", "Complexity": "Low", "Data Required": "Real-time", "Countermeasure": "Authentication"}
    ]
    
    df = pd.DataFrame(attack_data)
    st.dataframe(df, width='stretch')

def explain_modern_cryptography_standards():
    """Giải thích Modern Cryptography Standards"""
    st.markdown("### 📋 Modern Cryptography Standards")
    
    with st.expander("📖 Lý thuyết chi tiết về Modern Cryptography Standards"):
        st.markdown("""
        ### 🏛️ Standardization Organizations
        
        **NIST (National Institute of Standards and Technology)**
        - **Role**: US federal cryptographic standards
        - **Standards**: FIPS 140, FIPS 197 (AES), SP 800 series
        - **Process**: Public competitions, rigorous evaluation
        - **Impact**: Widely adopted globally
        
        **ISO/IEC (International Organization for Standardization)**
        - **Role**: International cryptographic standards
        - **Standards**: ISO/IEC 18033 (encryption), 14888 (signatures)
        - **Scope**: Global harmonization of crypto standards
        - **Collaboration**: Works with national standards bodies
        
        **IETF (Internet Engineering Task Force)**
        - **Role**: Internet protocol cryptography
        - **Standards**: RFC series (TLS, IPSec, SSH)
        - **Process**: Open, consensus-based development
        - **Focus**: Practical internet security protocols
        
        **IEEE (Institute of Electrical and Electronics Engineers)**
        - **Role**: Wireless and network security standards
        - **Standards**: 802.11i (WPA2), 802.1X (network access)
        - **Focus**: Communication and network security
        
        ### 🔐 Current Encryption Standards
        
        **AES (Advanced Encryption Standard)**
        - **Standard**: FIPS 197, ISO/IEC 18033-3
        - **Algorithm**: Rijndael cipher
        - **Key Sizes**: 128, 192, 256 bits
        - **Block Size**: 128 bits
        - **Status**: Current standard, widely deployed
        - **Applications**: Government, commercial, embedded systems
        
        **ChaCha20**
        - **Designer**: Daniel J. Bernstein
        - **Type**: Stream cipher
        - **Key Size**: 256 bits
        - **Advantages**: Software performance, constant-time
        - **Applications**: TLS 1.3, mobile devices
        
        **RSA Encryption**
        - **Standard**: PKCS #1, RFC 8017
        - **Key Sizes**: 2048, 3072, 4096 bits (minimum 2048)
        - **Applications**: Key exchange, digital signatures
        - **Status**: Still secure but being phased out
        
        **Elliptic Curve Cryptography (ECC)**
        - **Standards**: FIPS 186-4, SEC 1/2, RFC 6090
        - **Curves**: P-256, P-384, P-521 (NIST), Curve25519, Curve448
        - **Advantages**: Smaller keys, better performance
        - **Applications**: Modern protocols, mobile devices
        
        ### 🔒 Hash Function Standards
        
        **SHA-2 Family**
        - **Standard**: FIPS 180-4
        - **Variants**: SHA-224, SHA-256, SHA-384, SHA-512
        - **Status**: Current standard
        - **Applications**: Digital signatures, certificates, blockchain
        
        **SHA-3 (Keccak)**
        - **Standard**: FIPS 202
        - **Variants**: SHA3-224, SHA3-256, SHA3-384, SHA3-512
        - **Design**: Sponge construction (different from SHA-2)
        - **Status**: Alternative to SHA-2, not replacement
        
        **BLAKE2**
        - **Type**: Cryptographic hash function
        - **Variants**: BLAKE2b (64-bit), BLAKE2s (32-bit)
        - **Performance**: Faster than SHA-2, secure as SHA-3
        - **Applications**: High-performance applications
        
        ### ✍️ Digital Signature Standards
        
        **RSA Signatures**
        - **Standards**: PKCS #1, FIPS 186-4
        - **Padding**: PSS (preferred), PKCS #1 v1.5 (legacy)
        - **Key Sizes**: 2048+ bits
        - **Hash**: SHA-256 or stronger
        
        **ECDSA (Elliptic Curve DSA)**
        - **Standard**: FIPS 186-4, ANSI X9.62
        - **Curves**: P-256, P-384, P-521
        - **Advantages**: Smaller signatures, faster verification
        - **Applications**: TLS certificates, blockchain
        
        **EdDSA (Edwards-curve DSA)**
        - **Standard**: RFC 8032
        - **Variants**: Ed25519, Ed448
        - **Advantages**: Faster, more secure, deterministic
        - **Applications**: SSH, modern protocols
        
        ### 🔑 Key Exchange Standards
        
        **Diffie-Hellman (DH)**
        - **Standards**: RFC 2631, FIPS 186-4
        - **Groups**: MODP groups (RFC 3526), ECC groups
        - **Security**: 2048+ bit groups, perfect forward secrecy
        - **Applications**: TLS, IPSec, SSH
        
        **ECDH (Elliptic Curve DH)**
        - **Standards**: RFC 6090, SP 800-56A
        - **Curves**: P-256, P-384, P-521, X25519, X448
        - **Advantages**: Smaller keys, better performance
        - **Applications**: Modern TLS, messaging apps
        
        ### 🛡️ Authenticated Encryption Standards
        
        **AES-GCM (Galois/Counter Mode)**
        - **Standard**: SP 800-38D
        - **Features**: Encryption + authentication in one pass
        - **Performance**: Hardware acceleration available
        - **Applications**: TLS 1.2/1.3, IPSec, storage encryption
        
        **ChaCha20-Poly1305**
        - **Standard**: RFC 8439
        - **Components**: ChaCha20 cipher + Poly1305 MAC
        - **Advantages**: Software performance, constant-time
        - **Applications**: TLS 1.3, mobile protocols
        
        **AES-CCM (Counter with CBC-MAC)**
        - **Standard**: SP 800-38C
        - **Features**: Encryption + authentication
        - **Applications**: 802.11i (WPA2), Bluetooth LE
        
        ### 🌐 Protocol Standards
        
        **TLS 1.3**
        - **Standard**: RFC 8446
        - **Improvements**: Simplified handshake, forward secrecy
        - **Crypto**: Modern algorithms only, deprecated legacy
        - **Performance**: Reduced round trips, better security
        
        **IPSec**
        - **Standards**: RFC 4301-4309
        - **Protocols**: AH (authentication), ESP (encryption)
        - **Key Management**: IKEv2 (RFC 7296)
        - **Applications**: VPNs, site-to-site connections
        
        **SSH**
        - **Standard**: RFC 4251-4254
        - **Key Exchange**: DH, ECDH
        - **Encryption**: AES, ChaCha20
        - **Authentication**: RSA, ECDSA, Ed25519
        
        ### 🔮 Post-Quantum Cryptography
        
        **NIST PQC Standardization**
        - **Process**: Multi-round competition (2016-2022)
        - **Selected Algorithms**: CRYSTALS-Kyber (KEM), CRYSTALS-Dilithium (signatures)
        - **Timeline**: Standards published 2024
        - **Urgency**: Quantum computer threat
        
        **Quantum-Resistant Algorithms:**
        - **Lattice-based**: CRYSTALS-Kyber, CRYSTALS-Dilithium
        - **Hash-based**: SPHINCS+ (signatures)
        - **Code-based**: Classic McEliece (KEM)
        - **Multivariate**: Rainbow (signatures) - broken
        
        ### 📊 Algorithm Lifecycle Management
        
        **Security Levels:**
        - **Level 1**: 128-bit security (AES-128, P-256)
        - **Level 3**: 192-bit security (AES-192, P-384)
        - **Level 5**: 256-bit security (AES-256, P-521)
        
        **Deprecation Timeline:**
        - **Immediate**: DES, MD5, SHA-1, RC4
        - **2030**: RSA-2048, 1024-bit DH
        - **Post-quantum era**: All current public-key crypto
        
        **Migration Strategy:**
        - **Crypto-agility**: Design for algorithm changes
        - **Hybrid approaches**: Classical + post-quantum
        - **Gradual transition**: Phase out legacy algorithms
        """)
    
    # Standards comparison table
    st.markdown("#### 📋 Current Cryptographic Standards")
    
    standards_data = [
        {"Category": "Symmetric Encryption", "Algorithm": "AES", "Key Size": "128/192/256", "Standard": "FIPS 197", "Status": "Current"},
        {"Category": "Hash Functions", "Algorithm": "SHA-2", "Output Size": "224-512", "Standard": "FIPS 180-4", "Status": "Current"},
        {"Category": "Hash Functions", "Algorithm": "SHA-3", "Output Size": "224-512", "Standard": "FIPS 202", "Status": "Alternative"},
        {"Category": "Public Key", "Algorithm": "RSA", "Key Size": "2048+", "Standard": "FIPS 186-4", "Status": "Legacy"},
        {"Category": "Public Key", "Algorithm": "ECDSA", "Key Size": "256+", "Standard": "FIPS 186-4", "Status": "Current"},
        {"Category": "Key Exchange", "Algorithm": "ECDH", "Key Size": "256+", "Standard": "SP 800-56A", "Status": "Current"},
        {"Category": "Authenticated Encryption", "Algorithm": "AES-GCM", "Key Size": "128/256", "Standard": "SP 800-38D", "Status": "Current"},
        {"Category": "Post-Quantum", "Algorithm": "Kyber", "Security Level": "1/3/5", "Standard": "FIPS 203", "Status": "Future"}
    ]
    
    df = pd.DataFrame(standards_data)
    st.dataframe(df, width='stretch')

def risk_assessment():
    """Đánh giá rủi ro"""
    st.subheader("📊 Risk Assessment")
    
    st.markdown("""
    ### 🎯 Risk Assessment Framework
    
    **Risk = Threat × Vulnerability × Impact**
    
    **🔍 Components:**
    - **Asset:** What needs protection
    - **Threat:** What could cause harm
    - **Vulnerability:** Weakness that can be exploited
    - **Impact:** Consequence if risk materializes
    - **Likelihood:** Probability of occurrence
    """)
    
    # Risk matrix
    st.markdown("#### 📈 Risk Matrix")
    
    # Create risk matrix data
    likelihood_levels = ['Very Low', 'Low', 'Medium', 'High', 'Very High']
    impact_levels = ['Very Low', 'Low', 'Medium', 'High', 'Very High']
    
    risk_matrix = []
    for i, impact in enumerate(impact_levels):
        for j, likelihood in enumerate(likelihood_levels):
            risk_score = (i + 1) * (j + 1)
            if risk_score <= 5:
                risk_level = 'Low'
                color = 'green'
            elif risk_score <= 15:
                risk_level = 'Medium'
                color = 'yellow'
            else:
                risk_level = 'High'
                color = 'red'
            
            risk_matrix.append({
                'Impact': impact,
                'Likelihood': likelihood,
                'Risk Score': risk_score,
                'Risk Level': risk_level,
                'Color': color
            })
    
    df_risk = pd.DataFrame(risk_matrix)
    
    # Create heatmap
    pivot_table = df_risk.pivot(index='Impact', columns='Likelihood', values='Risk Score')
    
    fig = px.imshow(
        pivot_table,
        title="Risk Assessment Matrix",
        color_continuous_scale=['green', 'yellow', 'red'],
        aspect='auto'
    )
    
    st.plotly_chart(fig, width='stretch')

def legal_ethics():
    """Pháp lý và đạo đức"""
    st.subheader("⚖️ Legal & Ethics")
    
    legal_topic = st.selectbox("Chọn chủ đề:", [
        "Cybersecurity Laws & Regulations",
        "Ethical Hacking Guidelines", 
        "Privacy & Data Protection",
        "Incident Response Legal Considerations"
    ])
    
    if legal_topic == "Cybersecurity Laws & Regulations":
        st.markdown("""
        ### 📜 Cybersecurity Laws & Regulations
        
        **🌍 International:**
        - **GDPR (General Data Protection Regulation)**
          - EU regulation for data protection
          - Heavy fines for violations
          - Right to be forgotten
        
        - **ISO 27001/27002**
          - International security standards
          - Risk management approach
          - Certification framework
        
        **🇺🇸 United States:**
        - **HIPAA (Health Insurance Portability and Accountability Act)**
          - Healthcare data protection
          - Security and privacy rules
        
        - **SOX (Sarbanes-Oxley Act)**
          - Financial reporting controls
          - IT general controls
        
        - **FISMA (Federal Information Security Management Act)**
          - Federal agency security
          - NIST framework compliance
        
        **🇻🇳 Vietnam:**
        - **Cybersecurity Law 2018**
          - Data localization requirements
          - Incident reporting obligations
        
        - **Personal Data Protection Decree**
          - Privacy protection rules
          - Consent requirements
        """)
    
    elif legal_topic == "Ethical Hacking Guidelines":
        explain_ethical_hacking_guidelines()
    elif legal_topic == "Privacy & Data Protection":
        explain_privacy_data_protection()
    elif legal_topic == "Incident Response Legal Considerations":
        explain_incident_response_legal()

def explain_ethical_hacking_guidelines():
    """Giải thích Ethical Hacking Guidelines"""
    st.markdown("### ⚖️ Ethical Hacking Guidelines")
    
    with st.expander("📖 Lý thuyết chi tiết về Ethical Hacking"):
        st.markdown("""
        ### 🎯 Ethical Hacking Guidelines
        
        **✅ Ethical Hacking Principles:**
        
        **1. Authorization**
        - Always get written permission
        - Define scope clearly
        - Respect boundaries
        
        **2. Minimize Harm**
        - Don't damage systems
        - Don't access sensitive data unnecessarily
        - Report vulnerabilities responsibly
        
        **3. Confidentiality**
        - Protect client information
        - Don't share findings publicly
        - Follow disclosure timelines
        
        **4. Professional Conduct**
        - Follow industry standards
        - Continuous learning
        - Maintain certifications
        
        **🚫 Unethical Activities:**
        - Unauthorized access
        - Data theft or destruction
        - Selling vulnerabilities to criminals
        - Using findings for personal gain
        
        **📋 Legal Framework:**
        - Penetration testing agreements
        - Rules of engagement
        - Liability limitations
        - Insurance considerations
        """)

def explain_privacy_data_protection():
    """Giải thích Privacy & Data Protection"""
    st.markdown("### 🔒 Privacy & Data Protection")
    
    with st.expander("📖 Lý thuyết chi tiết về Privacy & Data Protection"):
        st.markdown("""
        ### 🎯 Privacy Fundamentals
        
        **Privacy vs Security:**
        - **Privacy**: Control over personal information
        - **Security**: Protection from threats and attacks
        - **Relationship**: Privacy requires security, but security doesn't guarantee privacy
        - **Balance**: Need both for comprehensive protection
        
        ### 📋 Major Privacy Regulations
        
        **GDPR (General Data Protection Regulation)**
        - **Scope**: EU residents' data worldwide
        - **Key Principles**: Lawfulness, fairness, transparency
        - **Rights**: Access, rectification, erasure, portability
        - **Penalties**: Up to 4% of annual revenue or €20M
        - **Requirements**: Consent, data minimization, privacy by design
        
        **CCPA (California Consumer Privacy Act)**
        - **Scope**: California residents
        - **Rights**: Know, delete, opt-out, non-discrimination
        - **Businesses**: $25M+ revenue or 50K+ consumers
        - **Penalties**: Up to $7,500 per violation
        - **Enforcement**: California Attorney General
        
        **PIPEDA (Personal Information Protection and Electronic Documents Act)**
        - **Scope**: Canada federal privacy law
        - **Principles**: Accountability, consent, limiting collection
        - **Rights**: Access, correction, complaint
        - **Enforcement**: Privacy Commissioner of Canada
        
        **Other Regional Laws:**
        - **Brazil**: LGPD (Lei Geral de Proteção de Dados)
        - **India**: Personal Data Protection Bill
        - **Japan**: Act on Protection of Personal Information
        - **South Korea**: Personal Information Protection Act
        
        ### 🔐 Data Protection Principles
        
        **Data Minimization:**
        - **Collect**: Only necessary data
        - **Process**: For specified purposes only
        - **Retain**: For limited time periods
        - **Delete**: When no longer needed
        
        **Purpose Limitation:**
        - **Specify**: Clear purpose for collection
        - **Limit**: Use only for stated purposes
        - **Consent**: Required for new purposes
        - **Document**: All processing activities
        
        **Consent Management:**
        - **Informed**: Clear, understandable language
        - **Specific**: Granular consent options
        - **Freely Given**: No coercion or bundling
        - **Withdrawable**: Easy to revoke consent
        
        **Data Subject Rights:**
        - **Right to Access**: Know what data is processed
        - **Right to Rectification**: Correct inaccurate data
        - **Right to Erasure**: "Right to be forgotten"
        - **Right to Portability**: Transfer data between services
        - **Right to Object**: Opt-out of processing
        
        ### 🛡️ Technical Privacy Protection
        
        **Privacy by Design:**
        - **Proactive**: Anticipate privacy issues
        - **Default**: Privacy as default setting
        - **Embedded**: Built into system design
        - **Full Functionality**: No trade-offs with functionality
        - **End-to-End**: Secure throughout lifecycle
        - **Visibility**: Transparent to stakeholders
        - **Respect**: User privacy above all
        
        **Data Anonymization:**
        - **Pseudonymization**: Replace identifiers with pseudonyms
        - **K-anonymity**: Each record indistinguishable from k-1 others
        - **L-diversity**: Ensure diversity in sensitive attributes
        - **T-closeness**: Distribution of sensitive attributes
        - **Differential Privacy**: Mathematical privacy guarantee
        
        **Encryption for Privacy:**
        - **Data at Rest**: Encrypt stored data
        - **Data in Transit**: Encrypt communications
        - **Data in Use**: Homomorphic encryption, secure enclaves
        - **Key Management**: Separate from data storage
        
        **Access Controls:**
        - **Role-Based**: Access based on job function
        - **Attribute-Based**: Fine-grained access control
        - **Need-to-Know**: Minimum necessary access
        - **Audit Trails**: Log all data access
        
        ### 🌐 Cross-Border Data Transfers
        
        **Adequacy Decisions:**
        - **EU Adequacy**: Countries with adequate protection
        - **Examples**: Canada, Japan, UK, Switzerland
        - **Benefits**: Free flow of data
        - **Requirements**: Maintain adequate protection level
        
        **Transfer Mechanisms:**
        - **Standard Contractual Clauses (SCCs)**: EU-approved contracts
        - **Binding Corporate Rules (BCRs)**: Internal company rules
        - **Certification Schemes**: Privacy certification programs
        - **Codes of Conduct**: Industry-specific guidelines
        
        **Data Localization:**
        - **Requirements**: Keep data within borders
        - **Examples**: Russia, China, India
        - **Challenges**: Technical and business complexity
        - **Compliance**: Local data centers, cloud regions
        
        ### 📱 Sector-Specific Privacy
        
        **Healthcare (HIPAA):**
        - **Scope**: US healthcare data
        - **Protected Health Information (PHI)**
        - **Minimum Necessary Rule**
        - **Business Associate Agreements**
        - **Breach Notification Requirements**
        
        **Financial Services:**
        - **GLBA**: Gramm-Leach-Bliley Act (US)
        - **PCI DSS**: Payment card data security
        - **Open Banking**: API data sharing
        - **Consumer Protection**: Fair lending, privacy notices
        
        **Education (FERPA):**
        - **Student Records**: Educational privacy
        - **Parental Rights**: Access and control
        - **Directory Information**: Limited disclosure
        - **Consent Requirements**: For non-directory info
        
        ### 🚨 Privacy Incident Response
        
        **Breach Notification:**
        - **Timeline**: 72 hours (GDPR), varies by jurisdiction
        - **Authorities**: Data protection authorities
        - **Individuals**: If high risk to rights and freedoms
        - **Content**: Nature, consequences, measures taken
        
        **Risk Assessment:**
        - **Likelihood**: Probability of harm
        - **Severity**: Impact on individuals
        - **Factors**: Data sensitivity, number of people affected
        - **Mitigation**: Steps to reduce risk
        
        **Communication Strategy:**
        - **Internal**: Legal, PR, technical teams
        - **External**: Regulators, media, customers
        - **Transparency**: Clear, honest communication
        - **Updates**: Regular status updates
        
        ### 🔍 Privacy Impact Assessments (PIAs)
        
        **When Required:**
        - **High Risk Processing**: Large scale, sensitive data
        - **New Technologies**: AI, biometrics, IoT
        - **Systematic Monitoring**: Tracking, profiling
        - **Legal Requirement**: GDPR Article 35
        
        **Assessment Process:**
        - **Describe Processing**: Purpose, data, recipients
        - **Assess Necessity**: Proportionality, alternatives
        - **Identify Risks**: Privacy risks to individuals
        - **Mitigation Measures**: Technical and organizational
        - **Consultation**: Data protection officer, stakeholders
        
        ### 📊 Privacy Metrics and KPIs
        
        **Compliance Metrics:**
        - **Consent Rates**: Percentage of users consenting
        - **Response Times**: Data subject request handling
        - **Training Completion**: Staff privacy training
        - **Audit Results**: Internal and external assessments
        
        **Privacy by Design Metrics:**
        - **Default Settings**: Privacy-protective defaults
        - **Data Minimization**: Reduction in data collection
        - **Retention Compliance**: Automated data deletion
        - **Access Controls**: Principle of least privilege
        """)
    
    # Privacy regulation comparison
    st.markdown("#### 📋 Privacy Regulation Comparison")
    
    privacy_data = [
        {"Regulation": "GDPR", "Jurisdiction": "EU", "Max Fine": "4% revenue/€20M", "Key Rights": "Access, Erasure, Portability", "Scope": "Global (EU residents)"},
        {"Regulation": "CCPA", "Jurisdiction": "California", "Max Fine": "$7,500/violation", "Key Rights": "Know, Delete, Opt-out", "Scope": "California residents"},
        {"Regulation": "PIPEDA", "Jurisdiction": "Canada", "Max Fine": "Varies", "Key Rights": "Access, Correction", "Scope": "Federal Canada"},
        {"Regulation": "LGPD", "Jurisdiction": "Brazil", "Max Fine": "2% revenue", "Key Rights": "Similar to GDPR", "Scope": "Brazil residents"},
        {"Regulation": "HIPAA", "Jurisdiction": "US Healthcare", "Max Fine": "$1.5M/violation", "Key Rights": "Access, Amendment", "Scope": "Healthcare data"}
    ]
    
    df = pd.DataFrame(privacy_data)
    st.dataframe(df, width='stretch')

def explain_incident_response_legal():
    """Giải thích Incident Response Legal Considerations"""
    st.markdown("### ⚖️ Incident Response Legal Considerations")
    
    with st.expander("📖 Lý thuyết chi tiết về Incident Response Legal"):
        st.markdown("""
        ### 🎯 Legal Framework for Incident Response
        
        **Legal Obligations:**
        - **Breach Notification Laws**: Mandatory reporting requirements
        - **Regulatory Compliance**: Industry-specific regulations
        - **Contractual Obligations**: Customer and vendor agreements
        - **Insurance Requirements**: Cyber insurance policy terms
        
        ### 📋 Notification Requirements
        
        **Regulatory Notifications:**
        
        **GDPR (EU):**
        - **Timeline**: 72 hours to supervisory authority
        - **Threshold**: Risk to rights and freedoms
        - **Content**: Nature, categories, consequences, measures
        - **Individual Notification**: If high risk
        
        **State Breach Laws (US):**
        - **Varies by State**: Different requirements per state
        - **Common Elements**: Personal information compromise
        - **Timeline**: "Without unreasonable delay"
        - **Method**: Written notice, email, or substitute notice
        
        **Sector-Specific:**
        - **HIPAA**: 60 days for individuals, 60 days for HHS
        - **GLBA**: Prompt notification to customers
        - **SOX**: Material weakness disclosure
        - **PCI DSS**: Immediate notification to card brands
        
        **International Requirements:**
        - **Canada (PIPEDA)**: Real risk of significant harm
        - **Australia (NDB)**: Eligible data breaches
        - **Japan**: Personal information protection authorities
        - **Singapore**: Data protection authorities
        
        ### 🔍 Evidence Preservation
        
        **Legal Hold:**
        - **Trigger**: Reasonable anticipation of litigation
        - **Scope**: All relevant documents and data
        - **Communication**: Notify custodians of preservation duty
        - **Documentation**: Maintain records of hold process
        
        **Chain of Custody:**
        - **Documentation**: Who, what, when, where, why
        - **Integrity**: Maintain evidence integrity
        - **Access Control**: Limit access to authorized personnel
        - **Transfer**: Proper handoff procedures
        
        **Forensic Considerations:**
        - **Imaging**: Bit-for-bit copies of storage media
        - **Hash Values**: Verify data integrity
        - **Write Protection**: Prevent evidence contamination
        - **Expert Testimony**: Qualified forensic examiners
        
        ### 👥 Stakeholder Communication
        
        **Internal Communications:**
        - **Executive Leadership**: Board, C-suite notification
        - **Legal Counsel**: Attorney-client privilege protection
        - **IT Security**: Technical response coordination
        - **HR**: Employee-related incidents
        - **Public Relations**: External communication strategy
        
        **External Communications:**
        - **Regulators**: Mandatory breach notifications
        - **Customers**: Breach notification letters
        - **Partners**: Vendor/supplier notifications
        - **Media**: Public relations management
        - **Law Enforcement**: Criminal activity reporting
        
        **Privilege Considerations:**
        - **Attorney-Client**: Legal advice communications
        - **Work Product**: Litigation preparation materials
        - **Common Interest**: Shared defense arrangements
        - **Waiver Risks**: Inadvertent privilege loss
        
        ### 📄 Documentation Requirements
        
        **Incident Documentation:**
        - **Timeline**: Chronological sequence of events
        - **Actions Taken**: Response and remediation steps
        - **Evidence**: Logs, screenshots, forensic images
        - **Communications**: All internal and external communications
        - **Decisions**: Rationale for key decisions
        
        **Legal Documentation:**
        - **Breach Notifications**: Copies of all notifications sent
        - **Regulatory Correspondence**: Communications with authorities
        - **Legal Holds**: Documentation of preservation efforts
        - **Expert Reports**: Forensic and technical analysis
        - **Settlement Agreements**: Resolution documentation
        
        ### ⚖️ Liability Considerations
        
        **Negligence Claims:**
        - **Duty of Care**: Reasonable security measures
        - **Breach of Duty**: Failure to meet standard
        - **Causation**: Link between breach and harm
        - **Damages**: Actual harm to plaintiffs
        
        **Contractual Liability:**
        - **Service Level Agreements**: Performance standards
        - **Data Processing Agreements**: GDPR requirements
        - **Vendor Contracts**: Third-party liability
        - **Insurance Policies**: Coverage and exclusions
        
        **Regulatory Penalties:**
        - **GDPR**: Up to 4% of annual revenue
        - **State AGs**: Varies by jurisdiction
        - **FTC**: Unfair or deceptive practices
        - **Industry Regulators**: Sector-specific penalties
        
        ### 🛡️ Cyber Insurance
        
        **Coverage Types:**
        - **First-Party**: Direct losses to organization
        - **Third-Party**: Claims by others
        - **Business Interruption**: Lost revenue
        - **Cyber Extortion**: Ransomware payments
        
        **Notification Requirements:**
        - **Immediate Notice**: As soon as reasonably possible
        - **Formal Notice**: Written notice within specified time
        - **Cooperation**: Assist with investigation
        - **No Voluntary Payments**: Without insurer consent
        
        **Coverage Exclusions:**
        - **War and Terrorism**: Excluded in many policies
        - **Prior Knowledge**: Known vulnerabilities
        - **Criminal Acts**: Intentional wrongdoing
        - **Regulatory Fines**: May be excluded
        
        ### 🌐 Cross-Border Considerations
        
        **Jurisdictional Issues:**
        - **Data Location**: Where data is stored/processed
        - **Company Location**: Headquarters and subsidiaries
        - **Affected Individuals**: Residence of data subjects
        - **Applicable Law**: Which laws apply
        
        **International Cooperation:**
        - **MLATs**: Mutual Legal Assistance Treaties
        - **Law Enforcement**: Cross-border investigations
        - **Regulatory Cooperation**: Information sharing agreements
        - **Diplomatic Channels**: Government-to-government communication
        
        **Data Sovereignty:**
        - **Local Laws**: Data localization requirements
        - **Government Access**: Lawful access provisions
        - **Conflicting Laws**: US CLOUD Act vs EU GDPR
        - **Safe Harbors**: Adequacy decisions and frameworks
        
        ### 📊 Legal Risk Assessment
        
        **Risk Factors:**
        - **Data Sensitivity**: PII, PHI, financial data
        - **Number of Records**: Scale of potential impact
        - **Jurisdiction**: Applicable laws and regulations
        - **Industry**: Sector-specific requirements
        - **Response Quality**: Adequacy of response measures
        
        **Mitigation Strategies:**
        - **Rapid Response**: Quick containment and notification
        - **Transparency**: Honest and complete disclosure
        - **Cooperation**: Work with regulators and law enforcement
        - **Remediation**: Address root causes
        - **Communication**: Effective stakeholder management
        
        ### 📋 Incident Response Legal Checklist
        
        **Immediate Actions:**
        - [ ] Engage legal counsel
        - [ ] Implement legal hold
        - [ ] Assess notification requirements
        - [ ] Contact cyber insurance carrier
        - [ ] Preserve evidence
        
        **Short-term Actions:**
        - [ ] Prepare breach notifications
        - [ ] Coordinate with regulators
        - [ ] Manage media relations
        - [ ] Document response efforts
        - [ ] Assess legal exposure
        
        **Long-term Actions:**
        - [ ] Conduct lessons learned
        - [ ] Update policies and procedures
        - [ ] Enhance security controls
        - [ ] Review insurance coverage
        - [ ] Monitor for litigation
        """)
    
    # Legal timeline comparison
    st.markdown("#### ⏰ Breach Notification Timeline Requirements")
    
    timeline_data = [
        {"Jurisdiction": "GDPR (EU)", "Authority Timeline": "72 hours", "Individual Timeline": "Without undue delay", "Threshold": "Risk to rights/freedoms"},
        {"Jurisdiction": "California (US)", "Authority Timeline": "Immediately", "Individual Timeline": "Without unreasonable delay", "Threshold": "Personal information"},
        {"Jurisdiction": "HIPAA (US)", "Authority Timeline": "60 days", "Individual Timeline": "60 days", "Threshold": "PHI compromise"},
        {"Jurisdiction": "Canada (PIPEDA)", "Authority Timeline": "ASAP", "Individual Timeline": "ASAP", "Threshold": "Real risk of significant harm"},
        {"Jurisdiction": "Australia (NDB)", "Authority Timeline": "30 days", "Individual Timeline": "ASAP", "Threshold": "Eligible data breach"}
    ]
    
    df = pd.DataFrame(timeline_data)
    st.dataframe(df, width='stretch')

def explain_security_by_design():
    """Giải thích Security by Design"""
    st.markdown("### 🏗️ Security by Design")
    
    with st.expander("📖 Lý thuyết chi tiết về Security by Design"):
        st.markdown("""
        ### 🎯 Security by Design Principles
        
        **Core Philosophy:**
        - **Proactive**: Anticipate and prevent security issues
        - **Default**: Security as the default state
        - **Embedded**: Built into system architecture
        - **Holistic**: Consider entire system lifecycle
        
        ### 📋 Fundamental Principles
        
        **1. Minimize Attack Surface**
        - **Reduce Complexity**: Simpler systems are more secure
        - **Remove Unnecessary Features**: Eliminate unused functionality
        - **Limit Interfaces**: Minimize external access points
        - **Principle of Least Privilege**: Minimum necessary access
        
        **2. Establish Secure Defaults**
        - **Fail Securely**: Default to secure state on failure
        - **Secure Configuration**: Out-of-box security
        - **Opt-in Security**: Users choose to reduce security
        - **Conservative Permissions**: Restrictive by default
        
        **3. Defense in Depth**
        - **Multiple Layers**: No single point of failure
        - **Diverse Controls**: Different types of protection
        - **Redundancy**: Backup security measures
        - **Complementary**: Controls work together
        
        **4. Fail Securely**
        - **Graceful Degradation**: Maintain security during failures
        - **Error Handling**: Don't reveal sensitive information
        - **Recovery Procedures**: Secure restoration processes
        - **Monitoring**: Detect and respond to failures
        
        **5. Don't Trust Services**
        - **Zero Trust**: Verify everything
        - **Input Validation**: Never trust external data
        - **Authentication**: Verify all entities
        - **Authorization**: Check permissions continuously
        
        **6. Separation of Duties**
        - **Role Segregation**: Divide critical functions
        - **Dual Control**: Require multiple approvals
        - **Check and Balance**: Independent verification
        - **Conflict of Interest**: Prevent abuse of power
        
        **7. Avoid Security by Obscurity**
        - **Open Design**: Security through design, not secrecy
        - **Transparency**: Clear security mechanisms
        - **Standards**: Use proven security methods
        - **Peer Review**: Allow security evaluation
        
        **8. Keep Security Simple**
        - **KISS Principle**: Keep It Simple and Secure
        - **Understandable**: Easy to implement correctly
        - **Maintainable**: Simple to update and patch
        - **Auditable**: Easy to verify and test
        
        ### 🏗️ Secure Development Lifecycle (SDL)
        
        **Planning Phase:**
        - **Threat Modeling**: Identify potential threats
        - **Security Requirements**: Define security needs
        - **Risk Assessment**: Evaluate security risks
        - **Architecture Review**: Secure design patterns
        
        **Design Phase:**
        - **Security Architecture**: Overall security design
        - **Data Flow Analysis**: Understand data movement
        - **Trust Boundaries**: Identify security perimeters
        - **Attack Surface Analysis**: Minimize exposure
        
        **Implementation Phase:**
        - **Secure Coding**: Follow security best practices
        - **Code Reviews**: Peer review for security
        - **Static Analysis**: Automated code scanning
        - **Unit Testing**: Test security functions
        
        **Testing Phase:**
        - **Security Testing**: Dedicated security tests
        - **Penetration Testing**: Simulated attacks
        - **Vulnerability Scanning**: Automated security scans
        - **Fuzz Testing**: Input validation testing
        
        **Deployment Phase:**
        - **Secure Configuration**: Hardened deployment
        - **Environment Security**: Secure infrastructure
        - **Access Controls**: Proper permissions
        - **Monitoring**: Security event detection
        
        **Maintenance Phase:**
        - **Patch Management**: Regular security updates
        - **Vulnerability Management**: Ongoing assessment
        - **Incident Response**: Security incident handling
        - **Continuous Monitoring**: Ongoing security oversight
        
        ### 🔒 Secure Architecture Patterns
        
        **Layered Architecture:**
        - **Presentation Layer**: User interface security
        - **Business Logic**: Application security
        - **Data Access**: Database security
        - **Infrastructure**: System security
        
        **Service-Oriented Architecture (SOA):**
        - **Service Security**: Individual service protection
        - **Message Security**: Secure communication
        - **Identity Management**: Centralized authentication
        - **Policy Enforcement**: Consistent security policies
        
        **Microservices Security:**
        - **Service Mesh**: Secure service communication
        - **API Gateway**: Centralized security controls
        - **Container Security**: Secure containerization
        - **Distributed Tracing**: Security monitoring
        
        **Zero Trust Architecture:**
        - **Never Trust**: Always verify
        - **Always Verify**: Continuous authentication
        - **Least Privilege**: Minimum necessary access
        - **Assume Breach**: Plan for compromise
        
        ### 🛡️ Security Controls Integration
        
        **Preventive Controls:**
        - **Access Controls**: Authentication and authorization
        - **Encryption**: Data protection at rest and in transit
        - **Firewalls**: Network traffic filtering
        - **Input Validation**: Prevent injection attacks
        
        **Detective Controls:**
        - **Logging**: Security event recording
        - **Monitoring**: Real-time threat detection
        - **Intrusion Detection**: Automated threat identification
        - **Auditing**: Regular security assessments
        
        **Corrective Controls:**
        - **Incident Response**: Security incident handling
        - **Backup and Recovery**: Data restoration
        - **Patch Management**: Vulnerability remediation
        - **Business Continuity**: Operational resilience
        
        ### 📊 Security Metrics and KPIs
        
        **Design Metrics:**
        - **Threat Model Coverage**: Percentage of threats addressed
        - **Security Requirements**: Number implemented
        - **Architecture Reviews**: Frequency and findings
        - **Security Patterns**: Usage of secure patterns
        
        **Implementation Metrics:**
        - **Code Review Coverage**: Percentage of code reviewed
        - **Static Analysis**: Vulnerabilities found and fixed
        - **Security Testing**: Test coverage and results
        - **Secure Coding**: Compliance with standards
        
        **Operational Metrics:**
        - **Vulnerability Density**: Vulnerabilities per KLOC
        - **Time to Patch**: Average remediation time
        - **Security Incidents**: Frequency and severity
        - **Compliance**: Adherence to security standards
        
        ### 🔄 Continuous Security Improvement
        
        **Security Feedback Loop:**
        - **Monitor**: Continuous security monitoring
        - **Analyze**: Security data analysis
        - **Learn**: Extract security insights
        - **Improve**: Enhance security measures
        
        **Threat Intelligence Integration:**
        - **External Sources**: Industry threat feeds
        - **Internal Sources**: Organizational security data
        - **Analysis**: Threat landscape assessment
        - **Action**: Proactive security measures
        
        **Security Culture:**
        - **Training**: Regular security education
        - **Awareness**: Security consciousness
        - **Responsibility**: Everyone owns security
        - **Continuous Learning**: Stay current with threats
        
        ### 🌐 Emerging Security Challenges
        
        **Cloud Security:**
        - **Shared Responsibility**: Cloud provider vs customer
        - **Configuration Management**: Secure cloud setup
        - **Data Sovereignty**: Data location and control
        - **Multi-Cloud**: Consistent security across providers
        
        **IoT Security:**
        - **Device Security**: Secure embedded systems
        - **Communication Security**: Secure protocols
        - **Update Mechanisms**: Secure device updates
        - **Privacy**: Personal data protection
        
        **AI/ML Security:**
        - **Model Security**: Protect ML models
        - **Data Privacy**: Training data protection
        - **Adversarial Attacks**: Robust model design
        - **Explainability**: Transparent AI decisions
        """)
    
    # Security by Design principles comparison
    st.markdown("#### 🏗️ Security by Design Implementation")
    
    implementation_data = [
        {"Phase": "Planning", "Security Activity": "Threat Modeling", "Deliverable": "Threat Model", "Effort": "High"},
        {"Phase": "Design", "Security Activity": "Security Architecture", "Deliverable": "Security Design", "Effort": "High"},
        {"Phase": "Implementation", "Security Activity": "Secure Coding", "Deliverable": "Secure Code", "Effort": "Medium"},
        {"Phase": "Testing", "Security Activity": "Security Testing", "Deliverable": "Test Results", "Effort": "Medium"},
        {"Phase": "Deployment", "Security Activity": "Secure Configuration", "Deliverable": "Hardened System", "Effort": "Low"},
        {"Phase": "Maintenance", "Security Activity": "Continuous Monitoring", "Deliverable": "Security Reports", "Effort": "Ongoing"}
    ]
    
    df = pd.DataFrame(implementation_data)
    st.dataframe(df, width='stretch')

def explain_risk_management_principles():
    """Giải thích Risk Management Principles"""
    st.markdown("### 📊 Risk Management Principles")
    
    with st.expander("📖 Lý thuyết chi tiết về Risk Management"):
        st.markdown("""
        ### 🎯 Risk Management Fundamentals
        
        **Risk Definition:**
        - **Risk = Threat × Vulnerability × Impact**
        - **Uncertainty**: Potential for loss or gain
        - **Probability**: Likelihood of occurrence
        - **Impact**: Consequence if risk materializes
        
        **Risk Components:**
        - **Assets**: What needs protection
        - **Threats**: What can cause harm
        - **Vulnerabilities**: Weaknesses that can be exploited
        - **Controls**: Measures to reduce risk
        
        ### 📋 Risk Management Process
        
        **1. Risk Identification**
        - **Asset Inventory**: Catalog all assets
        - **Threat Assessment**: Identify potential threats
        - **Vulnerability Assessment**: Find weaknesses
        - **Risk Register**: Document all identified risks
        
        **2. Risk Analysis**
        - **Qualitative Analysis**: Subjective risk assessment
        - **Quantitative Analysis**: Numerical risk calculation
        - **Risk Modeling**: Mathematical risk models
        - **Scenario Analysis**: What-if scenarios
        
        **3. Risk Evaluation**
        - **Risk Criteria**: Acceptable risk levels
        - **Risk Appetite**: Organization's risk tolerance
        - **Risk Prioritization**: Rank risks by importance
        - **Risk Acceptance**: Decide which risks to accept
        
        **4. Risk Treatment**
        - **Risk Avoidance**: Eliminate the risk
        - **Risk Mitigation**: Reduce risk likelihood/impact
        - **Risk Transfer**: Share risk with others
        - **Risk Acceptance**: Accept the risk as-is
        
        **5. Risk Monitoring**
        - **Key Risk Indicators (KRIs)**: Early warning signals
        - **Risk Reporting**: Regular risk status updates
        - **Risk Reviews**: Periodic risk assessments
        - **Continuous Monitoring**: Ongoing risk oversight
        
        ### 📊 Risk Assessment Methods
        
        **Qualitative Methods:**
        - **Risk Matrix**: Probability vs Impact grid
        - **Expert Judgment**: Subject matter expert opinions
        - **Delphi Method**: Structured expert consensus
        - **Scenario Analysis**: Narrative risk scenarios
        
        **Quantitative Methods:**
        - **Annual Loss Expectancy (ALE)**: Expected annual loss
        - **Single Loss Expectancy (SLE)**: Loss per incident
        - **Annual Rate of Occurrence (ARO)**: Frequency per year
        - **Monte Carlo Simulation**: Statistical risk modeling
        
        **Hybrid Methods:**
        - **FAIR (Factor Analysis of Information Risk)**: Structured quantitative
        - **OCTAVE**: Operationally Critical Threat Assessment
        - **NIST Risk Management Framework**: Comprehensive approach
        - **ISO 27005**: International risk management standard
        
        ### 🎯 Risk Treatment Strategies
        
        **Risk Avoidance:**
        - **Eliminate Activity**: Stop risky activities
        - **Change Design**: Redesign to avoid risk
        - **Alternative Approach**: Use different methods
        - **Examples**: Don't store sensitive data, avoid risky technologies
        
        **Risk Mitigation:**
        - **Preventive Controls**: Reduce likelihood
        - **Detective Controls**: Early detection
        - **Corrective Controls**: Minimize impact
        - **Examples**: Firewalls, monitoring, backup systems
        
        **Risk Transfer:**
        - **Insurance**: Transfer financial risk
        - **Contracts**: Shift liability to others
        - **Outsourcing**: Transfer operational risk
        - **Examples**: Cyber insurance, vendor agreements
        
        **Risk Acceptance:**
        - **Informed Decision**: Conscious choice to accept
        - **Residual Risk**: Risk remaining after treatment
        - **Cost-Benefit**: Treatment cost exceeds benefit
        - **Examples**: Low-impact risks, acceptable residual risk
        
        ### 📈 Risk Metrics and KPIs
        
        **Risk Exposure Metrics:**
        - **Total Risk Exposure**: Sum of all risks
        - **Risk by Category**: Risks grouped by type
        - **High/Medium/Low Risks**: Risk distribution
        - **Trend Analysis**: Risk changes over time
        
        **Risk Treatment Metrics:**
        - **Mitigation Effectiveness**: Control performance
        - **Treatment Coverage**: Percentage of risks treated
        - **Cost of Controls**: Investment in risk reduction
        - **Return on Security Investment (ROSI)**: Control value
        
        **Risk Performance Metrics:**
        - **Risk Incidents**: Actual risk materializations
        - **Near Misses**: Almost-incidents
        - **Control Failures**: Security control breakdowns
        - **Recovery Time**: Time to restore operations
        
        ### 🏢 Enterprise Risk Management (ERM)
        
        **ERM Framework:**
        - **Governance**: Risk oversight structure
        - **Strategy**: Risk-informed decision making
        - **Performance**: Risk and performance integration
        - **Review**: Continuous improvement
        
        **Risk Governance:**
        - **Board Oversight**: Executive risk responsibility
        - **Risk Committee**: Dedicated risk governance
        - **Risk Officers**: Chief Risk Officer (CRO)
        - **Risk Culture**: Organization-wide risk awareness
        
        **Risk Integration:**
        - **Strategic Planning**: Risk in strategy development
        - **Business Processes**: Risk in operations
        - **Decision Making**: Risk-informed choices
        - **Performance Management**: Risk-adjusted metrics
        
        ### 🔄 Risk Management Lifecycle
        
        **Continuous Process:**
        - **Plan**: Establish risk management approach
        - **Do**: Implement risk treatments
        - **Check**: Monitor and review risks
        - **Act**: Improve risk management process
        
        **Risk Communication:**
        - **Risk Reporting**: Regular risk status updates
        - **Stakeholder Engagement**: Involve relevant parties
        - **Risk Awareness**: Educate organization
        - **Escalation**: Communicate significant risks
        
        **Risk Documentation:**
        - **Risk Register**: Central risk repository
        - **Risk Policies**: Risk management guidelines
        - **Risk Procedures**: Detailed risk processes
        - **Risk Reports**: Regular risk communications
        
        ### 🌐 Emerging Risk Considerations
        
        **Cyber Risk:**
        - **Digital Transformation**: New technology risks
        - **Remote Work**: Distributed workforce risks
        - **Supply Chain**: Third-party risks
        - **Regulatory**: Compliance and privacy risks
        
        **Operational Risk:**
        - **Business Continuity**: Operational resilience
        - **Process Risk**: Operational failures
        - **Human Risk**: People-related risks
        - **Technology Risk**: System failures
        
        **Strategic Risk:**
        - **Market Risk**: Competitive threats
        - **Reputation Risk**: Brand damage
        - **Innovation Risk**: Technology disruption
        - **Regulatory Risk**: Changing regulations
        
        ### 📋 Risk Management Best Practices
        
        **Leadership Commitment:**
        - **Tone at the Top**: Executive risk commitment
        - **Resource Allocation**: Adequate risk resources
        - **Risk Culture**: Promote risk awareness
        - **Accountability**: Clear risk responsibilities
        
        **Risk-Based Approach:**
        - **Proportionate Response**: Match treatment to risk
        - **Cost-Effective**: Efficient resource use
        - **Dynamic**: Adapt to changing risks
        - **Integrated**: Embed in business processes
        
        **Continuous Improvement:**
        - **Lessons Learned**: Learn from incidents
        - **Best Practices**: Adopt proven methods
        - **Benchmarking**: Compare with peers
        - **Innovation**: Explore new approaches
        """)
    
    # Risk treatment comparison
    st.markdown("#### 📊 Risk Treatment Options Comparison")
    
    treatment_data = [
        {"Strategy": "Avoidance", "Cost": "Variable", "Effectiveness": "100%", "Applicability": "Limited", "Example": "Don't store sensitive data"},
        {"Strategy": "Mitigation", "Cost": "Medium-High", "Effectiveness": "Partial", "Applicability": "Most risks", "Example": "Implement firewalls"},
        {"Strategy": "Transfer", "Cost": "Low-Medium", "Effectiveness": "High", "Applicability": "Insurable risks", "Example": "Cyber insurance"},
        {"Strategy": "Acceptance", "Cost": "Low", "Effectiveness": "0%", "Applicability": "Low risks", "Example": "Accept residual risk"}
    ]
    
    df = pd.DataFrame(treatment_data)
    st.dataframe(df, width='stretch')

def explain_advanced_persistent_threats():
    """Giải thích Advanced Persistent Threats (APT)"""
    st.markdown("### 🎯 Advanced Persistent Threats (APT)")
    
    with st.expander("📖 Lý thuyết chi tiết về APT"):
        st.markdown("""
        ### 🎯 APT Characteristics
        
        **Advanced:**
        - **Sophisticated Techniques**: Custom malware, zero-day exploits
        - **Multiple Attack Vectors**: Various entry points
        - **Evasion Capabilities**: Bypass security controls
        - **Professional Operations**: Well-funded, organized groups
        
        **Persistent:**
        - **Long-term Presence**: Months or years in networks
        - **Maintain Access**: Multiple backdoors and persistence mechanisms
        - **Stealth Operations**: Avoid detection
        - **Patience**: Wait for optimal opportunities
        
        **Threat:**
        - **Targeted Attacks**: Specific organizations or individuals
        - **High-value Targets**: Government, military, corporations
        - **Strategic Objectives**: Espionage, sabotage, financial gain
        - **Significant Impact**: National security, economic damage
        
        ### 🏗️ APT Attack Lifecycle
        
        **1. Initial Reconnaissance**
        - **Target Selection**: Choose specific victims
        - **Information Gathering**: OSINT, social media research
        - **Infrastructure Mapping**: Network topology, key personnel
        - **Vulnerability Research**: Find attack vectors
        
        **2. Initial Compromise**
        - **Spear Phishing**: Targeted email attacks
        - **Watering Hole**: Compromise frequently visited sites
        - **Supply Chain**: Attack through vendors/partners
        - **Zero-day Exploits**: Unknown vulnerabilities
        
        **3. Establish Foothold**
        - **Malware Deployment**: Install persistent backdoors
        - **Command and Control**: Establish C2 communications
        - **Privilege Escalation**: Gain higher-level access
        - **Defense Evasion**: Avoid security tools
        
        **4. Lateral Movement**
        - **Network Exploration**: Map internal networks
        - **Credential Harvesting**: Steal user credentials
        - **System Compromise**: Infect additional systems
        - **Trust Exploitation**: Abuse trusted relationships
        
        **5. Data Collection**
        - **Target Identification**: Find valuable data
        - **Data Staging**: Prepare for exfiltration
        - **Compression/Encryption**: Prepare data for transfer
        - **Timing**: Wait for optimal exfiltration windows
        
        **6. Data Exfiltration**
        - **Covert Channels**: Hidden communication methods
        - **Legitimate Protocols**: Use normal network traffic
        - **Small Transfers**: Avoid detection thresholds
        - **External Storage**: Cloud services, compromised sites
        
        **7. Maintain Presence**
        - **Multiple Backdoors**: Redundant access methods
        - **Update Malware**: Evolve to avoid detection
        - **Monitor Defenses**: Track security improvements
        - **Long-term Operations**: Sustained access
        
        ### 🎭 APT Actor Categories
        
        **Nation-State Actors:**
        - **Government Sponsored**: State intelligence agencies
        - **Strategic Objectives**: National security, economic advantage
        - **Resources**: Significant funding and expertise
        - **Examples**: APT1 (China), Lazarus (North Korea), Cozy Bear (Russia)
        
        **Cybercriminal Groups:**
        - **Financial Motivation**: Profit-driven attacks
        - **Ransomware Operations**: Encrypt data for payment
        - **Banking Trojans**: Steal financial information
        - **Examples**: FIN7, Carbanak, Evil Corp
        
        **Hacktivists:**
        - **Political Motivation**: Ideological objectives
        - **Public Attention**: High-profile attacks
        - **Data Leaks**: Expose sensitive information
        - **Examples**: Anonymous, Lizard Squad
        
        **Insider Threats:**
        - **Internal Access**: Legitimate system access
        - **Privileged Information**: Knowledge of defenses
        - **Various Motivations**: Financial, ideological, coercion
        - **Detection Challenges**: Authorized access patterns
        
        ### 🛠️ APT Techniques and Tools
        
        **Initial Access:**
        - **Spear Phishing**: Targeted email campaigns
        - **Supply Chain Compromise**: SolarWinds, CCleaner
        - **Public-Facing Applications**: Web application exploits
        - **External Remote Services**: VPN, RDP compromise
        
        **Persistence:**
        - **Registry Modification**: Windows registry entries
        - **Scheduled Tasks**: Automated execution
        - **Service Creation**: Windows services
        - **Bootkit/Rootkit**: Low-level system access
        
        **Defense Evasion:**
        - **Code Obfuscation**: Hide malware functionality
        - **Living off the Land**: Use legitimate tools
        - **Process Injection**: Hide in legitimate processes
        - **Anti-Analysis**: Detect and evade sandboxes
        
        **Credential Access:**
        - **Credential Dumping**: Extract stored credentials
        - **Keylogging**: Capture typed passwords
        - **Brute Force**: Password guessing attacks
        - **Kerberoasting**: Exploit Kerberos protocol
        
        **Discovery:**
        - **Network Service Scanning**: Find network services
        - **System Information Discovery**: Gather system details
        - **Account Discovery**: Enumerate user accounts
        - **Network Share Discovery**: Find shared resources
        
        **Lateral Movement:**
        - **Remote Services**: Use legitimate remote access
        - **Pass-the-Hash**: Reuse authentication hashes
        - **WMI**: Windows Management Instrumentation
        - **PowerShell**: Abuse administrative tools
        
        **Collection:**
        - **Data from Local System**: File system access
        - **Screen Capture**: Screenshot collection
        - **Audio Capture**: Microphone recording
        - **Clipboard Data**: Copy/paste monitoring
        
        **Command and Control:**
        - **Standard Protocols**: HTTP/HTTPS, DNS
        - **Encrypted Channels**: TLS, custom encryption
        - **Domain Fronting**: Hide C2 infrastructure
        - **Social Media**: Use platforms for communication
        
        **Exfiltration:**
        - **Web Service**: Cloud storage services
        - **DNS Tunneling**: Hide data in DNS queries
        - **Physical Media**: USB drives, removable media
        - **Alternative Protocols**: FTP, email attachments
        
        ### 🔍 APT Detection Strategies
        
        **Behavioral Analysis:**
        - **Anomaly Detection**: Unusual network/system behavior
        - **User Behavior Analytics**: Abnormal user activities
        - **Network Traffic Analysis**: Suspicious communications
        - **Process Monitoring**: Unusual process execution
        
        **Threat Hunting:**
        - **Proactive Search**: Hunt for hidden threats
        - **Hypothesis-driven**: Test threat scenarios
        - **IOC Hunting**: Search for indicators of compromise
        - **Threat Intelligence**: Use external threat data
        
        **Advanced Analytics:**
        - **Machine Learning**: AI-powered detection
        - **Statistical Analysis**: Identify outliers
        - **Graph Analysis**: Relationship mapping
        - **Timeline Analysis**: Sequence of events
        
        **Threat Intelligence:**
        - **IOCs**: Indicators of Compromise
        - **TTPs**: Tactics, Techniques, and Procedures
        - **Attribution**: Link to known threat actors
        - **Contextual Information**: Campaign details
        
        ### 🛡️ APT Defense Strategies
        
        **Prevention:**
        - **Email Security**: Advanced anti-phishing
        - **Endpoint Protection**: Next-gen antivirus
        - **Network Segmentation**: Limit lateral movement
        - **Patch Management**: Close vulnerability windows
        
        **Detection:**
        - **SIEM**: Security Information and Event Management
        - **EDR**: Endpoint Detection and Response
        - **NDR**: Network Detection and Response
        - **Deception Technology**: Honeypots and decoys
        
        **Response:**
        - **Incident Response**: Rapid containment
        - **Forensics**: Detailed investigation
        - **Threat Hunting**: Proactive threat search
        - **Recovery**: System restoration
        
        **Intelligence:**
        - **Threat Intelligence Platforms**: Centralized intel
        - **Information Sharing**: Industry collaboration
        - **Attribution**: Identify threat actors
        - **Predictive Analysis**: Anticipate future attacks
        
        ### 📊 APT Impact Assessment
        
        **Direct Costs:**
        - **Incident Response**: Investigation and remediation
        - **System Recovery**: Rebuild compromised systems
        - **Data Recovery**: Restore lost/corrupted data
        - **Legal Costs**: Litigation and regulatory fines
        
        **Indirect Costs:**
        - **Business Disruption**: Operational downtime
        - **Reputation Damage**: Customer trust loss
        - **Competitive Disadvantage**: Stolen intellectual property
        - **Regulatory Impact**: Compliance violations
        
        **Strategic Impact:**
        - **National Security**: Government/military targets
        - **Economic Espionage**: Trade secrets theft
        - **Critical Infrastructure**: Power, water, transportation
        - **Supply Chain**: Vendor/partner compromise
        
        ### 🌐 Notable APT Campaigns
        
        **APT1 (Comment Crew):**
        - **Attribution**: China PLA Unit 61398
        - **Targets**: Intellectual property theft
        - **Duration**: 2006-2013 (discovered)
        - **Impact**: 141 companies across 20 industries
        
        **Stuxnet:**
        - **Attribution**: US/Israel (alleged)
        - **Target**: Iranian nuclear facilities
        - **Method**: Industrial control system sabotage
        - **Impact**: Physical damage to centrifuges
        
        **SolarWinds (SUNBURST):**
        - **Attribution**: APT29/Cozy Bear (Russia)
        - **Method**: Supply chain compromise
        - **Scope**: 18,000+ organizations
        - **Duration**: March 2020 - December 2020
        
        **NotPetya:**
        - **Attribution**: Russia (Sandworm)
        - **Target**: Ukraine (collateral global damage)
        - **Method**: Destructive ransomware
        - **Impact**: $10+ billion in damages
        """)
    
    # APT lifecycle visualization
    st.markdown("#### 🔄 APT Attack Lifecycle Stages")
    
    apt_data = [
        {"Stage": "Reconnaissance", "Duration": "Weeks-Months", "Detectability": "Low", "Key Activities": "Target research, OSINT"},
        {"Stage": "Initial Compromise", "Duration": "Hours-Days", "Detectability": "Medium", "Key Activities": "Spear phishing, exploits"},
        {"Stage": "Establish Foothold", "Duration": "Hours-Days", "Detectability": "Medium", "Key Activities": "Malware deployment, C2"},
        {"Stage": "Lateral Movement", "Duration": "Days-Weeks", "Detectability": "Medium", "Key Activities": "Network exploration, privilege escalation"},
        {"Stage": "Data Collection", "Duration": "Days-Months", "Detectability": "Low", "Key Activities": "Data identification, staging"},
        {"Stage": "Exfiltration", "Duration": "Hours-Days", "Detectability": "High", "Key Activities": "Data transfer, covert channels"},
        {"Stage": "Maintain Presence", "Duration": "Months-Years", "Detectability": "Low", "Key Activities": "Persistence, evasion"}
    ]
    
    df = pd.DataFrame(apt_data)
    st.dataframe(df, width='stretch')

# Helper function to create interactive concept maps
def create_concept_map(concepts, relationships):
    """Create interactive concept map"""
    fig = go.Figure()
    
    # Add nodes
    for concept in concepts:
        fig.add_trace(go.Scatter(
            x=[concept['x']],
            y=[concept['y']],
            mode='markers+text',
            text=[concept['name']],
            textposition='middle center',
            marker=dict(size=50, color=concept['color']),
            showlegend=False
        ))
    
    # Add relationships
    for rel in relationships:
        fig.add_trace(go.Scatter(
            x=[rel['from_x'], rel['to_x']],
            y=[rel['from_y'], rel['to_y']],
            mode='lines',
            line=dict(color='gray', width=2),
            showlegend=False
        ))
    
    fig.update_layout(
        title="Concept Map",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=400
    )
    
    return fig
