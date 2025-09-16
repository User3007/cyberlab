"""
Routing and Switching Component
Network routing and switching fundamentals
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from typing import Dict, List, Any

from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class RoutingSwitchingComponent(ComponentTemplate):
    """Routing and Switching component - network infrastructure"""
    
    def __init__(self):
        super().__init__(
            component_name="🔀 Routing & Switching",
            description="Network routing and switching concepts for data forwarding",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="20 minutes"
        )
        
        self.set_key_concepts([
            "Layer 2 Switching", "Layer 3 Routing", "Protocols", "Network Design"
        ])
    
    def render_content(self):
        """Render Routing and Switching content"""
        
        # Switching vs Routing comparison
        st.markdown("#### ⚖️ Switching vs Routing Comparison")
        
        comparison = [
            {"Aspect": "OSI Layer", "Switching": "Layer 2 (Data Link)", "Routing": "Layer 3 (Network)"},
            {"Aspect": "Addressing", "Switching": "MAC addresses", "Routing": "IP addresses"},
            {"Aspect": "Scope", "Switching": "Local network (LAN)", "Routing": "Between networks (WAN)"},
            {"Aspect": "Decision Method", "Switching": "MAC address table", "Routing": "Routing table"},
            {"Aspect": "Broadcast Domain", "Switching": "Forwards broadcasts", "Routing": "Blocks broadcasts"},
            {"Aspect": "Speed", "Switching": "Hardware-based (fast)", "Routing": "Software-based (slower)"}
        ]
        
        df = pd.DataFrame(comparison)
        st.dataframe(df, use_container_width=True)
        
        # Switching concepts
        col1, col2 = st.columns(2)
        
        with col1:
            create_info_card(
                "🔄 Layer 2 Switching",
                "Forwards frames based on MAC addresses within a LAN",
                "primary", self.color_scheme
            )
            
            st.markdown("**Key Concepts:**")
            switching_concepts = [
                "MAC Address Learning",
                "Frame Forwarding",
                "Flooding and Filtering",
                "Spanning Tree Protocol (STP)",
                "VLANs (Virtual LANs)"
            ]
            for concept in switching_concepts:
                st.markdown(f"• {concept}")
        
        with col2:
            create_info_card(
                "🌐 Layer 3 Routing",
                "Routes packets between different networks using IP addresses",
                "info", self.color_scheme
            )
            
            st.markdown("**Key Concepts:**")
            routing_concepts = [
                "Routing Table",
                "Static vs Dynamic Routing",
                "Routing Protocols (RIP, OSPF, BGP)",
                "Default Gateway",
                "Route Metrics"
            ]
            for concept in routing_concepts:
                st.markdown(f"• {concept}")
        
        # Common protocols
        st.markdown("#### 📡 Common Routing Protocols")
        
        routing_protocols = [
            {"Protocol": "RIP", "Type": "Distance Vector", "Metric": "Hop Count", "Max Hops": "15", "Use Case": "Small networks"},
            {"Protocol": "OSPF", "Type": "Link State", "Metric": "Cost (bandwidth)", "Max Hops": "No limit", "Use Case": "Enterprise networks"},
            {"Protocol": "EIGRP", "Type": "Hybrid", "Metric": "Composite", "Max Hops": "100 (default)", "Use Case": "Cisco networks"},
            {"Protocol": "BGP", "Type": "Path Vector", "Metric": "Path attributes", "Max Hops": "No limit", "Use Case": "Internet routing"}
        ]
        
        protocols_df = pd.DataFrame(routing_protocols)
        st.dataframe(protocols_df, use_container_width=True)
        
        # Network devices
        st.markdown("#### 🖥️ Network Devices")
        
        devices = {
            "Hub": {
                "layer": "Physical (Layer 1)",
                "function": "Repeats signals to all ports",
                "collision_domain": "Single large collision domain",
                "security": "Low - all traffic visible to all ports"
            },
            "Switch": {
                "layer": "Data Link (Layer 2)", 
                "function": "Forwards frames based on MAC addresses",
                "collision_domain": "Each port is separate collision domain",
                "security": "Medium - MAC address filtering, VLANs"
            },
            "Router": {
                "layer": "Network (Layer 3)",
                "function": "Routes packets between networks",
                "collision_domain": "Each interface is separate network",
                "security": "High - ACLs, firewall capabilities"
            }
        }
        
        device_selector = st.selectbox("🔍 Explore Network Device:", list(devices.keys()), key="network_device_selector")
        device_info = devices[device_selector]
        
        st.markdown(f"""
        <div style="background: {self.color_scheme['background']}; padding: 1.5rem; border-radius: 8px; margin: 1rem 0; border-left: 5px solid {self.color_scheme['primary']};">
            <h4 style="color: {self.color_scheme['primary']}; margin-top: 0;">🖥️ {device_selector}</h4>
            <p><strong>Layer:</strong> {device_info['layer']}</p>
            <p><strong>Function:</strong> {device_info['function']}</p>
            <p><strong>Collision Domain:</strong> {device_info['collision_domain']}</p>
            <p><strong>Security:</strong> {device_info['security']}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Security considerations
        st.markdown("#### 🛡️ Security Considerations")
        
        security_issues = [
            "**MAC Flooding:** Overwhelming switch MAC table to force hub-like behavior",
            "**VLAN Hopping:** Unauthorized access to other VLANs",
            "**Spanning Tree Attacks:** Manipulating STP to become root bridge",
            "**Routing Table Poisoning:** Injecting false routes",
            "**ARP Spoofing:** Redirecting traffic through attacker's system"
        ]
        
        for issue in security_issues:
            st.markdown(issue)
        
        # Best practices
        st.markdown("#### ✅ Best Practices")
        
        best_practices = [
            "Implement port security on switches",
            "Use VLANs for network segmentation", 
            "Configure access control lists (ACLs)",
            "Enable routing protocol authentication",
            "Monitor for unusual routing changes",
            "Implement network access control (NAC)"
        ]
        
        for practice in best_practices:
            st.markdown(f"• {practice}")


def explain_routing_switching():
    """Main function for Routing and Switching"""
    component = RoutingSwitchingComponent()
    
    summary_points = [
        "Switching operates at Layer 2 using MAC addresses for local network forwarding",
        "Routing operates at Layer 3 using IP addresses to connect different networks",
        "Dynamic routing protocols (OSPF, BGP) automatically adapt to network changes",
        "Network security requires proper device configuration and monitoring"
    ]
    
    resources = [
        {"title": "Cisco Networking Academy", "description": "Comprehensive networking education"},
        {"title": "RFC 2328 - OSPF Version 2", "description": "Open Shortest Path First protocol"}
    ]
    
    component.render_full_component(summary_points, resources)
