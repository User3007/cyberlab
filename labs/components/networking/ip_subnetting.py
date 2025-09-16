"""
IP Subnetting - Compact Component
Enhanced với TDD pattern, drawer gọn gàng
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_ip_subnetting():
    """IP Subnetting - Compact Design"""
    
    # Compact Visual Banner
    st.markdown("""
    <div style="background: linear-gradient(90deg, #3498db 0%, #2980b9 100%); padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
        <h3 style="color: white; text-align: center; margin: 0;">🌐 IP Subnetting</h3>
        <p style="color: white; text-align: center; margin: 0.3rem 0 0 0; opacity: 0.9; font-size: 0.9rem;">
            Network Segmentation & Address Planning
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Compact Tabs
    tab1, tab2, tab3 = st.tabs(["📊 Basics", "🔢 Calculator", "🎯 Examples"])
    
    with tab1:
        # IP Classes - Compact Table
        col1, col2 = st.columns([1.2, 1])
        
        with col1:
            ip_classes = pd.DataFrame({
                '**Class**': ['**A**', '**B**', '**C**', '**D**', '**E**'],
                '**Range**': ['**1-126**', '**128-191**', '**192-223**', '**224-239**', '**240-255**'],
                '**Default Mask**': ['**/8**', '**/16**', '**/24**', '**Multicast**', '**Reserved**'],
                '**Hosts**': ['**16M**', '**65K**', '**254**', '**-**', '**-**']
            })
            st.dataframe(ip_classes, use_container_width=True, height=200)
        
        with col2:
            st.markdown("**🎯 Key Concepts:**")
            st.info("""
            **Network ID**: Identifies the network
            **Host ID**: Identifies the device
            **Subnet Mask**: Separates network/host
            **CIDR**: Classless notation (/24)
            """)
            
            st.markdown("**📝 Private Ranges:**")
            st.success("""
            • **10.0.0.0/8** - Class A
            • **172.16.0.0/12** - Class B  
            • **192.168.0.0/16** - Class C
            """)
    
    with tab2:
        # Subnet Calculator - Interactive
        st.markdown("**🔢 Subnet Calculator:**")
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            network_ip = st.text_input("Network IP:", value="192.168.1.0")
            subnet_mask = st.selectbox("Subnet Mask:", [
                "/24 (255.255.255.0)",
                "/25 (255.255.255.128)", 
                "/26 (255.255.255.192)",
                "/27 (255.255.255.224)",
                "/28 (255.255.255.240)",
                "/29 (255.255.255.248)",
                "/30 (255.255.255.252)"
            ])
        
        with col2:
            if st.button("🔍 Calculate Subnets"):
                # Extract CIDR notation
                cidr = int(subnet_mask.split('/')[1])
                host_bits = 32 - cidr
                num_hosts = (2 ** host_bits) - 2  # -2 for network and broadcast
                num_subnets = 2 ** (cidr - 24) if cidr > 24 else 1
                
                st.success(f"""
                **📊 Subnet Information:**
                
                **Network**: {network_ip}{subnet_mask.split()[0]}
                **Hosts per subnet**: {num_hosts}
                **Number of subnets**: {num_subnets}
                **Host bits**: {host_bits}
                **Network bits**: {cidr}
                """)
                
                # Show first few subnets
                if cidr >= 24:
                    base_ip = ".".join(network_ip.split(".")[:-1])
                    st.markdown("**🌐 First 4 Subnets:**")
                    for i in range(min(4, num_subnets)):
                        subnet_id = i * (256 // num_subnets)
                        st.write(f"• **Subnet {i+1}**: {base_ip}.{subnet_id}/{cidr}")
    
    with tab3:
        # Real-world Examples
        st.markdown("**🎯 Real-world Subnetting Examples:**")
        
        example_choice = st.selectbox("Choose Scenario:", [
            "Small Office (50 devices)",
            "Medium Company (200 devices)", 
            "Large Enterprise (1000+ devices)",
            "Data Center (Multiple VLANs)"
        ])
        
        examples = {
            "Small Office (50 devices)": {
                "network": "192.168.1.0/26",
                "hosts": "62 hosts available",
                "subnets": "4 subnets possible",
                "usage": "Perfect for small office with room to grow",
                "ranges": [
                    "192.168.1.0/26 (1-62)",
                    "192.168.1.64/26 (65-126)", 
                    "192.168.1.128/26 (129-190)",
                    "192.168.1.192/26 (193-254)"
                ]
            },
            "Medium Company (200 devices)": {
                "network": "192.168.0.0/23",
                "hosts": "510 hosts available", 
                "subnets": "Can be divided into smaller subnets",
                "usage": "Covers 192.168.0.0 and 192.168.1.0",
                "ranges": [
                    "Dept A: 192.168.0.0/24 (254 hosts)",
                    "Dept B: 192.168.1.0/25 (126 hosts)",
                    "Servers: 192.168.1.128/26 (62 hosts)",
                    "Printers: 192.168.1.192/28 (14 hosts)"
                ]
            },
            "Large Enterprise (1000+ devices)": {
                "network": "10.0.0.0/16",
                "hosts": "65,534 hosts available",
                "subnets": "Multiple departments/floors",
                "usage": "Class A private network with VLSM",
                "ranges": [
                    "Floor 1: 10.0.1.0/24",
                    "Floor 2: 10.0.2.0/24",
                    "Servers: 10.0.10.0/24", 
                    "DMZ: 10.0.100.0/24"
                ]
            },
            "Data Center (Multiple VLANs)": {
                "network": "172.16.0.0/12",
                "hosts": "1,048,574 hosts available",
                "subnets": "Hierarchical design",
                "usage": "Class B private with multiple VLANs",
                "ranges": [
                    "Web Servers: 172.16.1.0/24",
                    "Database: 172.16.2.0/24",
                    "Management: 172.16.10.0/24",
                    "Storage: 172.16.20.0/24"
                ]
            }
        }
        
        example = examples[example_choice]
        
        st.info(f"""
        **🏢 Scenario**: {example_choice}
        
        **🌐 Network**: {example['network']}
        **👥 Capacity**: {example['hosts']}
        **📊 Design**: {example['subnets']}
        **💡 Best for**: {example['usage']}
        """)
        
        st.markdown("**📋 Subnet Allocation:**")
        for subnet_range in example['ranges']:
            st.write(f"• {subnet_range}")
    
    # Compact Key Points
    st.markdown("""
    <div style="background-color: #f8f9fa; padding: 1rem; border-radius: 8px; margin-top: 1rem;">
        <h4 style="color: #2c3e50; margin-bottom: 0.5rem;">🎯 Key Points</h4>
        <ul style="color: #2c3e50; line-height: 1.6; margin-bottom: 0;">
            <li><strong>Subnetting</strong>: Divides large networks into smaller, manageable segments</li>
            <li><strong>VLSM</strong>: Variable Length Subnet Masking for efficient IP usage</li>
            <li><strong>Planning</strong>: Always plan for future growth when designing subnets</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
