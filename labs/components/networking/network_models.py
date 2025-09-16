import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_network_models():
    """Network Models using TDD pattern"""
    
    st.markdown("## Network Models")
    st.markdown("**Definition:** Conceptual frameworks that describe network communication through layered architectures, with OSI and TCP/IP being the most fundamental models.")
    
    st.markdown("---")
    
    # OSI vs TCP/IP Model
    st.markdown("### OSI vs TCP/IP Model Comparison")
    
    models_data = {
        "OSI Layer": ["7. Application", "6. Presentation", "5. Session", "4. Transport", "3. Network", "2. Data Link", "1. Physical"],
        "TCP/IP Layer": ["Application", "Application", "Application", "Transport", "Internet", "Network Access", "Network Access"],
        "Function": [
            "Network services to applications",
            "Data translation, encryption, compression",
            "Session management, dialogue control",
            "Reliable data transfer, error recovery",
            "Routing, logical addressing",
            "Frame formatting, error detection",
            "Physical transmission of raw bits"
        ],
        "Protocols": [
            "HTTP, HTTPS, FTP, SMTP, DNS",
            "SSL/TLS, JPEG, MPEG, ASCII",
            "NetBIOS, RPC, SQL sessions",
            "TCP, UDP, SCTP",
            "IP, ICMP, ARP, OSPF, BGP",
            "Ethernet, WiFi, PPP, Frame Relay",
            "Cables, fiber, radio, electrical signals"
        ],
        "Examples": [
            "Web browsers, email clients",
            "Data encryption, file compression",
            "Database connections, video calls",
            "Port numbers, flow control",
            "IP addresses, routing tables",
            "MAC addresses, switches",
            "Network cables, wireless signals"
        ]
    }
    
    df = pd.DataFrame(models_data)
    st.dataframe(df, use_container_width=True)
    
    # Layer Interaction Visualization
    st.markdown("### Data Flow Through Network Layers")
    
    # Create layer interaction diagram
    layers = ['Application', 'Transport', 'Network', 'Data Link', 'Physical']
    sending_process = [100, 85, 70, 55, 40]
    receiving_process = [40, 55, 70, 85, 100]
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=list(range(len(layers))),
        y=sending_process,
        mode='lines+markers',
        name='Sending Process',
        line=dict(color='blue'),
        marker=dict(size=10)
    ))
    
    fig.add_trace(go.Scatter(
        x=list(range(len(layers))),
        y=receiving_process,
        mode='lines+markers',
        name='Receiving Process',
        line=dict(color='red'),
        marker=dict(size=10)
    ))
    
    fig.update_layout(
        title="Data Encapsulation/Decapsulation Process",
        xaxis=dict(
            tickmode='array',
            tickvals=list(range(len(layers))),
            ticktext=layers
        ),
        yaxis_title="Process Flow",
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Protocol Data Units (PDUs)
    st.markdown("### Protocol Data Units (PDUs)")
    
    pdu_data = {
        "Layer": ["Application", "Transport", "Network", "Data Link", "Physical"],
        "PDU Name": ["Data", "Segment", "Packet", "Frame", "Bits"],
        "Header Added": ["Application Header", "TCP/UDP Header", "IP Header", "Ethernet Header", "Electrical Signals"],
        "Key Information": [
            "Application-specific data",
            "Port numbers, sequence numbers",
            "Source/destination IP addresses",
            "MAC addresses, frame check sequence",
            "Physical transmission medium"
        ],
        "Size Considerations": [
            "Variable, application dependent",
            "20-60 bytes header + data",
            "20-60 bytes header + payload",
            "14-18 bytes header + payload + 4 bytes trailer",
            "Bit-level transmission"
        ]
    }
    
    df2 = pd.DataFrame(pdu_data)
    st.dataframe(df2, use_container_width=True)
    
    # Network Model Benefits
    st.markdown("### Benefits of Layered Network Models")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Design Benefits:**
        - **Modularity** - Each layer has specific responsibilities
        - **Interoperability** - Standards enable different vendors
        - **Abstraction** - Hide complexity from upper layers
        - **Flexibility** - Change one layer without affecting others
        """)
    
    with col2:
        st.markdown("""
        **Implementation Benefits:**
        - **Troubleshooting** - Isolate problems to specific layers
        - **Development** - Parallel development of different layers
        - **Testing** - Test each layer independently
        - **Maintenance** - Easier to update and maintain
        """)
    
    # Common Network Protocols by Layer
    st.markdown("### Common Protocols by Layer")
    
    protocols_data = {
        "Layer": ["Application (L7)", "Transport (L4)", "Network (L3)", "Data Link (L2)"],
        "Common Protocols": [
            "HTTP/HTTPS, FTP, SMTP, POP3, IMAP, DNS, DHCP, SNMP",
            "TCP (reliable), UDP (fast), SCTP (advanced)",
            "IPv4, IPv6, ICMP, ARP, OSPF, BGP, RIP",
            "Ethernet, WiFi (802.11), PPP, MPLS"
        ],
        "Security Protocols": [
            "HTTPS, FTPS, SSH, TLS/SSL",
            "TLS, DTLS",
            "IPSec, VPN protocols",
            "WPA2/WPA3, 802.1X, MACsec"
        ],
        "Port Numbers": [
            "80 (HTTP), 443 (HTTPS), 21 (FTP), 25 (SMTP)",
            "TCP/UDP ports 0-65535",
            "N/A (uses IP addresses)",
            "N/A (uses MAC addresses)"
        ]
    }
    
    df3 = pd.DataFrame(protocols_data)
    st.dataframe(df3, use_container_width=True)
    
    # Network Model Applications
    st.markdown("### Practical Applications")
    
    applications_data = {
        "Use Case": ["Network Troubleshooting", "Security Analysis", "Protocol Development", "Network Design"],
        "OSI Model Application": [
            "Isolate issues layer by layer from physical to application",
            "Apply security controls at appropriate layers",
            "Design protocols that fit specific layer requirements",
            "Plan network architecture with proper layer separation"
        ],
        "TCP/IP Model Application": [
            "Focus on practical implementation issues",
            "Implement security at transport and application layers",
            "Develop internet-compatible protocols",
            "Design networks for internet connectivity"
        ],
        "Tools Used": [
            "Wireshark, ping, traceroute, netstat",
            "Firewalls, IDS/IPS, packet analyzers",
            "Protocol analyzers, development frameworks",
            "Network simulators, design software"
        ]
    }
    
    df4 = pd.DataFrame(applications_data)
    st.dataframe(df4, use_container_width=True)
    
    # Modern Network Considerations
    st.markdown("### Modern Network Model Considerations")
    
    modern_data = {
        "Trend": ["Software-Defined Networking", "Network Function Virtualization", "Cloud Networking", "IoT Networks"],
        "Impact on Models": [
            "Separates control and data planes",
            "Virtualizes network functions across layers",
            "Abstracts physical network infrastructure",
            "Requires lightweight protocol stacks"
        ],
        "New Challenges": [
            "Dynamic network configuration",
            "Service chaining across virtual functions",
            "Multi-tenant network isolation",
            "Resource-constrained devices"
        ],
        "Solutions": [
            "OpenFlow, NETCONF protocols",
            "Container networking, service mesh",
            "Overlay networks, tunneling",
            "Compressed headers, edge computing"
        ]
    }
    
    df5 = pd.DataFrame(modern_data)
    st.dataframe(df5, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Layered Approach:</strong> Network models provide structured approach to complex networking</li>
            <li><strong>Practical Focus:</strong> TCP/IP model reflects real-world internet implementation</li>
            <li><strong>Troubleshooting Tool:</strong> Layer isolation helps identify and resolve network issues</li>
            <li><strong>Evolution Continues:</strong> Models adapt to new technologies like SDN and cloud computing</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
