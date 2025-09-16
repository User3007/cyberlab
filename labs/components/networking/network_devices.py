"""
Network Devices - Compact Component
Enhanced với TDD pattern, drawer gọn gàng
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_network_devices():
    """Network Devices - Compact Design"""
    
    # Compact Visual Banner
    st.markdown("""
    <div style="background: linear-gradient(90deg, #27ae60 0%, #2ecc71 100%); padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
        <h3 style="color: white; text-align: center; margin: 0;">🌐 Network Devices</h3>
        <p style="color: white; text-align: center; margin: 0.3rem 0 0 0; opacity: 0.9; font-size: 0.9rem;">
            Routers, Switches, Hubs & More
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Compact Tabs
    tab1, tab2, tab3 = st.tabs(["🔧 Core Devices", "📊 Comparison", "🏗️ Network Design"])
    
    with tab1:
        # Network Topology Visualization
        fig = go.Figure()
        
        # Device positions
        devices = [
            ("Internet", 0.5, 0.9, "#e74c3c", "☁️"),
            ("Router", 0.5, 0.7, "#f39c12", "📡"),
            ("Switch", 0.3, 0.5, "#3498db", "🔀"),
            ("Hub", 0.7, 0.5, "#95a5a6", "⭕"),
            ("PC1", 0.1, 0.3, "#27ae60", "💻"),
            ("PC2", 0.3, 0.3, "#27ae60", "💻"),
            ("PC3", 0.7, 0.3, "#27ae60", "💻"),
            ("Server", 0.9, 0.3, "#9b59b6", "🖥️")
        ]
        
        # Draw devices
        for name, x, y, color, icon in devices:
            fig.add_shape(
                type="circle",
                x0=x-0.05, y0=y-0.05, x1=x+0.05, y1=y+0.05,
                fillcolor=color, opacity=0.8,
                line=dict(color="white", width=2)
            )
            fig.add_annotation(
                x=x, y=y-0.1, text=f"{icon}<br><b>{name}</b>",
                showarrow=False, font=dict(size=10)
            )
        
        # Draw connections
        connections = [
            (0.5, 0.9, 0.5, 0.7),  # Internet to Router
            (0.5, 0.7, 0.3, 0.5),  # Router to Switch
            (0.5, 0.7, 0.7, 0.5),  # Router to Hub
            (0.3, 0.5, 0.1, 0.3),  # Switch to PC1
            (0.3, 0.5, 0.3, 0.3),  # Switch to PC2
            (0.7, 0.5, 0.7, 0.3),  # Hub to PC3
            (0.7, 0.5, 0.9, 0.3),  # Hub to Server
        ]
        
        for x1, y1, x2, y2 in connections:
            fig.add_shape(
                type="line",
                x0=x1, y0=y1, x1=x2, y1=y2,
                line=dict(color="#34495e", width=2)
            )
        
        fig.update_layout(
            title="Network Device Topology",
            xaxis=dict(showgrid=False, showticklabels=False, zeroline=False, range=[0, 1]),
            yaxis=dict(showgrid=False, showticklabels=False, zeroline=False, range=[0.2, 1]),
            height=300, margin=dict(l=10, r=10, t=30, b=10)
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Device Functions - Compact Grid
        col1, col2 = st.columns(2)
        with col1:
            st.info("""
            **📡 Router:**
            • Connects different networks
            • Routes packets between networks
            • NAT & firewall functions
            """)
            st.success("""
            **🔀 Switch:**
            • Connects devices in same network
            • MAC address learning
            • Full-duplex communication
            """)
        with col2:
            st.warning("""
            **⭕ Hub:**
            • Simple connection device
            • Half-duplex, shared bandwidth
            • Collision domain issues
            """)
            st.error("""
            **🔥 Firewall:**
            • Network security device
            • Packet filtering rules
            • Intrusion prevention
            """)
    
    with tab2:
        # Device Comparison Table
        comparison_data = pd.DataFrame({
            '**Device**': ['**Router**', '**Switch**', '**Hub**', '**Bridge**', '**Firewall**'],
            '**OSI Layer**': ['**Layer 3**', '**Layer 2**', '**Layer 1**', '**Layer 2**', '**Layer 3-7**'],
            '**Function**': [
                '**Inter-network** routing',
                '**Intra-network** switching', 
                '**Signal** repeating',
                '**Segment** bridging',
                '**Security** filtering'
            ],
            '**Collision Domain**': ['**Separate**', '**Separate**', '**Single**', '**Separate**', '**Separate**'],
            '**Broadcast Domain**': ['**Separate**', '**Single**', '**Single**', '**Single**', '**Configurable**']
        })
        st.dataframe(comparison_data, use_container_width=True, height=220)
        
        # Performance Comparison Chart
        devices = ['Router', 'Switch', 'Hub', 'Firewall']
        speed = [85, 95, 30, 70]
        security = [70, 40, 10, 95]
        cost = [60, 80, 95, 40]  # Higher = more affordable
        
        fig = go.Figure()
        fig.add_trace(go.Bar(name='Speed', x=devices, y=speed, marker_color='#3498db'))
        fig.add_trace(go.Bar(name='Security', x=devices, y=security, marker_color='#e74c3c'))
        fig.add_trace(go.Bar(name='Affordability', x=devices, y=cost, marker_color='#27ae60'))
        
        fig.update_layout(
            title='Device Performance Comparison',
            yaxis_title='Score (%)',
            barmode='group',
            height=300
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        # Network Design Scenarios
        st.markdown("**🏗️ Network Design Scenarios:**")
        
        scenario = st.selectbox("Choose Scenario:", [
            "Small Office (10-20 devices)",
            "Medium Business (50-100 devices)",
            "Enterprise (500+ devices)",
            "Data Center"
        ])
        
        designs = {
            "Small Office (10-20 devices)": {
                "devices": "1 Router + 1 Switch + 1 Wireless AP",
                "topology": "Simple star topology",
                "features": "Basic NAT, DHCP, simple firewall",
                "cost": "$200-500",
                "diagram": "Internet → Router → Switch → Devices"
            },
            "Medium Business (50-100 devices)": {
                "devices": "1 Router + 2-3 Switches + Multiple APs + Firewall",
                "topology": "Hierarchical with VLANs",
                "features": "VLANs, managed switches, enterprise firewall",
                "cost": "$2,000-5,000", 
                "diagram": "Internet → Firewall → Router → Core Switch → Access Switches"
            },
            "Enterprise (500+ devices)": {
                "devices": "Multiple Routers + Layer 3 Switches + Firewalls + Load Balancers",
                "topology": "Three-tier architecture",
                "features": "Redundancy, QoS, advanced security",
                "cost": "$50,000+",
                "diagram": "Internet → Edge → Distribution → Access → End Devices"
            },
            "Data Center": {
                "devices": "High-end switches + Routers + Firewalls + Load Balancers",
                "topology": "Spine-leaf or traditional 3-tier",
                "features": "10/40/100 Gbps, SDN, virtualization",
                "cost": "$100,000+",
                "diagram": "Spine Switches ↔ Leaf Switches → Servers"
            }
        }
        
        design = designs[scenario]
        
        col1, col2 = st.columns([1.2, 1])
        with col1:
            st.info(f"""
            **🏢 Scenario**: {scenario}
            
            **🔧 Required Devices**: {design['devices']}
            **🌐 Topology**: {design['topology']}
            **⚡ Key Features**: {design['features']}
            **💰 Estimated Cost**: {design['cost']}
            """)
        
        with col2:
            st.success(f"""
            **📋 Network Flow:**
            
            {design['diagram']}
            
            **💡 Best Practices:**
            • Plan for 30% growth
            • Implement redundancy
            • Consider security layers
            • Document everything
            """)
    
    # Compact Key Points
    st.markdown("""
    <div style="background-color: #f8f9fa; padding: 1rem; border-radius: 8px; margin-top: 1rem;">
        <h4 style="color: #2c3e50; margin-bottom: 0.5rem;">🎯 Key Points</h4>
        <ul style="color: #2c3e50; line-height: 1.6; margin-bottom: 0;">
            <li><strong>Layer Understanding</strong>: Each device operates at different OSI layers</li>
            <li><strong>Right Tool</strong>: Choose devices based on network requirements and scale</li>
            <li><strong>Future Planning</strong>: Design networks with growth and redundancy in mind</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
