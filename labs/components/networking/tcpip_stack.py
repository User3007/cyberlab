"""
TCP/IP Protocol Stack Component
Core internet protocol suite - focused explanation
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from typing import Dict, List, Any

from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class TCPIPStackComponent(ComponentTemplate):
    """TCP/IP Stack component - internet protocol foundation"""
    
    def __init__(self):
        super().__init__(
            component_name=" TCP/IP Protocol Stack",
            description="Internet protocol suite - the foundation of modern networking",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="15 minutes"
        )
        
        self.set_key_concepts([
            "4-Layer Model", "Protocol Encapsulation", "Internet Protocols", "Port Numbers"
        ])
    
    def render_content(self):
        """Render TCP/IP Stack content"""
        
        # TCP/IP layers vs OSI comparison
        layers_comparison = [
            {"TCP/IP Layer": "Application", "OSI Equivalent": "Application + Presentation + Session", "Protocols": "HTTP, HTTPS, FTP, SMTP, DNS", "Function": "User applications"},
            {"TCP/IP Layer": "Transport", "OSI Equivalent": "Transport", "Protocols": "TCP, UDP", "Function": "End-to-end communication"},
            {"TCP/IP Layer": "Internet", "OSI Equivalent": "Network", "Protocols": "IP, ICMP, ARP", "Function": "Routing and addressing"},
            {"TCP/IP Layer": "Network Access", "OSI Equivalent": "Data Link + Physical", "Protocols": "Ethernet, WiFi", "Function": "Physical transmission"}
        ]
        
        # Layer visualization
        fig = go.Figure()
        colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']
        
        for i, layer in enumerate(layers_comparison):
            fig.add_shape(
                type="rect",
                x0=0, y0=i, x1=6, y1=i+0.8,
                fillcolor=colors[i], opacity=0.7,
                line=dict(color=colors[i], width=2)
            )
            
            fig.add_annotation(
                x=3, y=i+0.4,
                text=f"<b>{layer['TCP/IP Layer']}</b><br>{layer['Function']}",
                showarrow=False, font=dict(size=12, color="white")
            )
        
        fig.update_layout(
            title="TCP/IP 4-Layer Model",
            xaxis=dict(showgrid=False, showticklabels=False, range=[0, 6]),
            yaxis=dict(showgrid=False, showticklabels=False, range=[0, 4]),
            height=300, showlegend=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Detailed layer comparison
        df = pd.DataFrame(layers_comparison)
        st.dataframe(df, use_container_width=True)
        
        # Key protocols
        col1, col2 = st.columns(2)
        
        with col1:
            create_info_card(
                " TCP (Transmission Control Protocol)",
                "Reliable, connection-oriented protocol for data delivery",
                "primary", self.color_scheme
            )
            st.markdown("**Features:** Connection-oriented, Reliable delivery, Flow control, Error correction")
        
        with col2:
            create_info_card(
                " UDP (User Datagram Protocol)",
                "Fast, connectionless protocol for simple data transmission",
                "info", self.color_scheme
            )
            st.markdown("**Features:** Connectionless, Fast delivery, No error correction, Minimal overhead")
        
        # Common ports
        st.markdown("####  Common Port Numbers")
        
        common_ports = [
            {"Port": "80", "Protocol": "HTTP", "Service": "Web traffic", "Security": "Unencrypted"},
            {"Port": "443", "Protocol": "HTTPS", "Service": "Secure web traffic", "Security": "Encrypted"},
            {"Port": "22", "Protocol": "SSH", "Service": "Secure shell", "Security": "Encrypted"},
            {"Port": "25", "Protocol": "SMTP", "Service": "Email sending", "Security": "Usually unencrypted"},
            {"Port": "53", "Protocol": "DNS", "Service": "Domain name resolution", "Security": "Usually unencrypted"},
            {"Port": "21", "Protocol": "FTP", "Service": "File transfer", "Security": "Unencrypted"}
        ]
        
        ports_df = pd.DataFrame(common_ports)
        st.dataframe(ports_df, use_container_width=True)
        
        # Security implications
        st.markdown("####  Security Implications")
        
        security_points = [
            "**IP Spoofing:** Attackers can forge source IP addresses",
            "**Port Scanning:** Identify open services and potential vulnerabilities",
            "**Protocol Vulnerabilities:** Each protocol has specific security weaknesses",
            "**Unencrypted Protocols:** Many protocols transmit data in plaintext"
        ]
        
        for point in security_points:
            st.markdown(point)


def explain_tcpip_stack():
    """Main function for TCP/IP Stack"""
    component = TCPIPStackComponent()
    
    summary_points = [
        "TCP/IP is a 4-layer model that forms the foundation of internet communication",
        "TCP provides reliable delivery while UDP offers speed for real-time applications",
        "Understanding port numbers is crucial for network security and troubleshooting",
        "Many protocols lack built-in encryption, requiring additional security measures"
    ]
    
    resources = [
        {"title": "RFC 793 - TCP Specification", "description": "Original TCP protocol specification"},
        {"title": "RFC 768 - UDP Specification", "description": "User Datagram Protocol specification"}
    ]
    
    component.render_full_component(summary_points, resources)
