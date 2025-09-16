import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_routing_switching():
    """Routing & Switching using TDD pattern"""
    
    st.markdown("## Routing & Switching")
    st.markdown("**Definition:** Network technologies that direct data packets between networks (routing) and forward frames within networks (switching) to enable communication across interconnected systems.")
    
    st.markdown("---")
    
    # Routing vs Switching
    st.markdown("### Routing vs Switching Comparison")
    
    comparison_data = {
        "Aspect": ["OSI Layer", "Primary Function", "Data Unit", "Decision Based On", "Scope"],
        "Switching": [
            "Layer 2 (Data Link)",
            "Forward frames within same network",
            "Ethernet frames",
            "MAC addresses",
            "Local network segment"
        ],
        "Routing": [
            "Layer 3 (Network)",
            "Route packets between different networks",
            "IP packets",
            "IP addresses and routing tables",
            "Multiple networks (internetwork)"
        ]
    }
    
    df = pd.DataFrame(comparison_data)
    st.dataframe(df, use_container_width=True)
    
    # Device and Table Comparison
    st.markdown("### Device and Table Types")
    
    device_data = {
        "Technology": ["Switching", "Routing"],
        "Device Examples": [
            "Network switches, bridges, Layer 2 switches",
            "Routers, Layer 3 switches, multilayer switches"
        ],
        "Table Type": [
            "MAC address table (CAM table)",
            "Routing table (RIB/FIB)"
        ],
        "Learning Method": [
            "Dynamic MAC learning from source addresses",
            "Static configuration, dynamic routing protocols"
        ]
    }
    
    df_devices = pd.DataFrame(device_data)
    st.dataframe(df_devices, use_container_width=True)
    
    # Switching Concepts
    st.markdown("### Switching Concepts and Technologies")
    
    switching_data = {
        "Technology": ["Store-and-Forward", "Cut-Through", "Fragment-Free", "VLAN", "STP"],
        "Description": [
            "Receive entire frame before forwarding",
            "Forward frame as soon as destination MAC is read",
            "Forward after first 64 bytes (collision window)",
            "Virtual LANs for network segmentation",
            "Spanning Tree Protocol prevents loops"
        ],
        "Advantages": [
            "Error checking, collision detection",
            "Low latency, high speed",
            "Balance of speed and error detection",
            "Broadcast domain separation, security",
            "Loop-free topology, redundancy"
        ],
        "Disadvantages": [
            "Higher latency due to buffering",
            "May forward corrupted frames",
            "Still vulnerable to some errors",
            "Configuration complexity",
            "Convergence time during topology changes"
        ],
        "Use Cases": [
            "Most modern switches, quality networks",
            "High-performance, low-latency applications",
            "Moderate performance requirements",
            "Network segmentation, multi-tenant",
            "Redundant network topologies"
        ]
    }
    
    df2 = pd.DataFrame(switching_data)
    st.dataframe(df2, use_container_width=True)
    
    # Routing Protocols Comparison
    st.markdown("### Routing Protocols Overview")
    
    # Create routing protocol comparison chart
    protocols = ['Static', 'RIP', 'OSPF', 'EIGRP', 'BGP']
    metrics = ['Simplicity', 'Scalability', 'Convergence Speed', 'Resource Usage', 'Security']
    
    protocol_scores = {
        'Static': [10, 2, 10, 10, 8],
        'RIP': [8, 3, 4, 8, 4],
        'OSPF': [4, 9, 8, 5, 7],
        'EIGRP': [5, 8, 9, 6, 6],
        'BGP': [2, 10, 6, 4, 8]
    }
    
    fig = go.Figure()
    
    for protocol in protocols:
        fig.add_trace(go.Scatterpolar(
            r=protocol_scores[protocol],
            theta=metrics,
            fill='toself',
            name=protocol
        ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 10]
            )
        ),
        title="Routing Protocols Comparison",
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Routing Protocols Details
    st.markdown("### Routing Protocols Detailed Comparison")
    
    routing_protocols_data = {
        "Protocol": ["Static Routing", "RIP v2", "OSPF", "EIGRP", "BGP"],
        "Type": ["Manual", "Distance Vector", "Link State", "Hybrid", "Path Vector"],
        "Metric": ["Administrative", "Hop Count", "Cost (Bandwidth)", "Composite", "AS Path"],
        "Max Hops": ["Unlimited", "15", "Unlimited", "255", "Unlimited"],
        "Convergence": ["Instant", "Slow (30-180s)", "Fast (5-10s)", "Very Fast (1-3s)", "Slow (minutes)"],
        "Use Case": [
            "Small networks, specific routes",
            "Very small networks, legacy",
            "Enterprise networks, ISPs",
            "Cisco enterprise networks",
            "Internet backbone, ISP peering"
        ]
    }
    
    df3 = pd.DataFrame(routing_protocols_data)
    st.dataframe(df3, use_container_width=True)
    
    # VLAN Configuration
    st.markdown("### VLAN Types and Configuration")
    
    vlan_data = {
        "VLAN Type": ["Data VLAN", "Voice VLAN", "Management VLAN", "Native VLAN", "Default VLAN"],
        "Purpose": [
            "Regular user data traffic",
            "VoIP phone traffic with QoS",
            "Network device management",
            "Untagged traffic on trunk ports",
            "All ports belong by default"
        ],
        "VLAN ID Range": [
            "1-4094 (except reserved)",
            "Typically separate from data",
            "Usually dedicated VLAN",
            "Often VLAN 1 (not recommended)",
            "VLAN 1"
        ],
        "Security Considerations": [
            "Isolate departments/functions",
            "Separate voice from data",
            "Restrict management access",
            "Should not be VLAN 1",
            "Change from VLAN 1 for security"
        ],
        "Best Practices": [
            "Plan VLAN numbering scheme",
            "Configure QoS for voice",
            "Use dedicated management VLAN",
            "Use unused VLAN as native",
            "Create new default VLAN"
        ]
    }
    
    df4 = pd.DataFrame(vlan_data)
    st.dataframe(df4, use_container_width=True)
    
    # Network Topologies
    st.markdown("### Common Network Topologies")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Physical Topologies:**
        - **Star** - Central hub/switch design
        - **Mesh** - Multiple interconnections
        - **Ring** - Circular connection pattern
        - **Bus** - Single shared medium
        """)
        
        st.markdown("""
        **Redundancy Designs:**
        - **Active-Active** - Load sharing
        - **Active-Passive** - Standby backup
        - **HSRP/VRRP** - Gateway redundancy
        - **Port Channels** - Link aggregation
        """)
    
    with col2:
        st.markdown("""
        **Logical Topologies:**
        - **Flat Network** - Single broadcast domain
        - **Hierarchical** - Core/Distribution/Access
        - **Spine-Leaf** - Modern data center design
        - **Software-Defined** - Centralized control
        """)
        
        st.markdown("""
        **Modern Approaches:**
        - **Fabric** - Any-to-any connectivity
        - **Overlay Networks** - Virtual topologies
        - **SD-WAN** - Software-defined WAN
        - **Intent-Based** - Policy-driven networking
        """)
    
    # Troubleshooting Commands
    st.markdown("### Common Troubleshooting Commands")
    
    troubleshooting_data = {
        "Command": ["ping", "traceroute", "show ip route", "show mac address-table", "show spanning-tree"],
        "Purpose": [
            "Test connectivity and latency",
            "Trace packet path through network",
            "Display routing table entries",
            "Show MAC address learning",
            "Display STP status and topology"
        ],
        "Example Usage": [
            "ping 192.168.1.1",
            "traceroute google.com",
            "show ip route 10.0.0.0/8",
            "show mac address-table vlan 10",
            "show spanning-tree vlan 1"
        ],
        "What to Look For": [
            "Packet loss, high latency",
            "Routing loops, slow hops",
            "Missing routes, wrong next-hop",
            "MAC address learning, flooding",
            "Root bridge, blocked ports"
        ]
    }
    
    df5 = pd.DataFrame(troubleshooting_data)
    st.dataframe(df5, use_container_width=True)
    
    # Performance Optimization
    st.markdown("### Performance Optimization Techniques")
    
    optimization_data = {
        "Technique": ["Link Aggregation", "QoS Implementation", "VLAN Optimization", "Routing Optimization"],
        "Description": [
            "Bundle multiple links for bandwidth/redundancy",
            "Prioritize critical traffic types",
            "Optimize VLAN design and trunk usage",
            "Tune routing metrics and protocols"
        ],
        "Implementation": [
            "EtherChannel, LACP, PAgP configuration",
            "Traffic classification, queuing, shaping",
            "Minimize VLANs per trunk, prune unused",
            "Adjust OSPF cost, EIGRP bandwidth"
        ],
        "Benefits": [
            "Increased bandwidth, load balancing",
            "Better user experience, SLA compliance",
            "Reduced broadcast traffic, better security",
            "Optimal path selection, faster convergence"
        ]
    }
    
    df6 = pd.DataFrame(optimization_data)
    st.dataframe(df6, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Layer Separation:</strong> Switching operates at Layer 2, routing at Layer 3</li>
            <li><strong>Protocol Selection:</strong> Choose routing protocol based on network size and requirements</li>
            <li><strong>VLAN Benefits:</strong> VLANs provide segmentation, security, and broadcast control</li>
            <li><strong>Redundancy Planning:</strong> Design networks with appropriate redundancy and failover</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
