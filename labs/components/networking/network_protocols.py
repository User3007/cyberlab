"""
Network Protocols Component
Core networking protocols and their security implications
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from typing import Dict, List, Any

from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class NetworkProtocolsComponent(ComponentTemplate):
    """Network Protocols component - essential networking protocols"""
    
    def __init__(self):
        super().__init__(
            component_name="🌐 Network Protocols",
            description="Essential networking protocols and their security considerations",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="20 minutes"
        )
        
        self.set_key_concepts([
            "Protocol Stack", "Port Numbers", "Security Implications", "Protocol Analysis"
        ])
    
    def render_content(self):
        """Render Network Protocols content"""
        
        # Protocol categories
        protocol_categories = {
            "Application Layer": {
                "protocols": [
                    {"Name": "HTTP", "Port": "80", "Purpose": "Web traffic", "Security": "Unencrypted", "Risk": "High"},
                    {"Name": "HTTPS", "Port": "443", "Purpose": "Secure web", "Security": "TLS encrypted", "Risk": "Low"},
                    {"Name": "DNS", "Port": "53", "Purpose": "Domain resolution", "Security": "Usually unencrypted", "Risk": "Medium"},
                    {"Name": "SMTP", "Port": "25", "Purpose": "Email sending", "Security": "Usually unencrypted", "Risk": "Medium"},
                    {"Name": "FTP", "Port": "21", "Purpose": "File transfer", "Security": "Unencrypted", "Risk": "High"}
                ]
            },
            "Transport Layer": {
                "protocols": [
                    {"Name": "TCP", "Port": "N/A", "Purpose": "Reliable delivery", "Security": "No encryption", "Risk": "Medium"},
                    {"Name": "UDP", "Port": "N/A", "Purpose": "Fast delivery", "Security": "No encryption", "Risk": "Medium"},
                    {"Name": "TLS", "Port": "443/993/995", "Purpose": "Transport security", "Security": "Strong encryption", "Risk": "Low"}
                ]
            },
            "Network Layer": {
                "protocols": [
                    {"Name": "IP", "Port": "N/A", "Purpose": "Routing/addressing", "Security": "No encryption", "Risk": "Medium"},
                    {"Name": "ICMP", "Port": "N/A", "Purpose": "Error messages", "Security": "No encryption", "Risk": "Medium"},
                    {"Name": "ARP", "Port": "N/A", "Purpose": "MAC resolution", "Security": "No authentication", "Risk": "High"}
                ]
            }
        }
        
        # Interactive protocol explorer
        selected_category = st.selectbox(
            "🔍 Explore Protocol Category:",
            list(protocol_categories.keys()),
            key="protocol_category_selector"
        )
        
        category_protocols = protocol_categories[selected_category]["protocols"]
        
        create_info_card(
            f"📊 {selected_category} Protocols",
            f"Essential protocols operating at the {selected_category.lower()}",
            "primary", self.color_scheme
        )
        
        # Protocol details table
        df = pd.DataFrame(category_protocols)
        st.dataframe(df, use_container_width=True)
        
        # Security risk visualization
        risk_counts = {"High": 0, "Medium": 0, "Low": 0}
        for protocol in category_protocols:
            risk_counts[protocol["Risk"]] += 1
        
        if any(risk_counts.values()):
            fig = px.pie(
                values=list(risk_counts.values()),
                names=list(risk_counts.keys()),
                title=f"{selected_category} - Security Risk Distribution",
                color_discrete_map={"High": "#FF4444", "Medium": "#FFAA00", "Low": "#44FF44"}
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Common protocol vulnerabilities
        st.markdown("#### ⚠️ Common Protocol Vulnerabilities")
        
        vulnerabilities = {
            "HTTP": "Man-in-the-middle, data interception, session hijacking",
            "DNS": "DNS spoofing, cache poisoning, tunneling attacks",
            "SMTP": "Email spoofing, relay attacks, credential theft",
            "FTP": "Credential sniffing, man-in-the-middle, bounce attacks",
            "ARP": "ARP spoofing, man-in-the-middle, network reconnaissance",
            "ICMP": "Ping of death, ICMP tunneling, network mapping"
        }
        
        for protocol, vulnerability in vulnerabilities.items():
            st.markdown(f"**{protocol}:** {vulnerability}")
        
        # Protocol analysis tools
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🔧 Network Analysis Tools:**")
            tools = ["Wireshark - Packet analysis", "Nmap - Network scanning", 
                    "Netstat - Connection monitoring", "TCPdump - Traffic capture"]
            for tool in tools:
                st.markdown(f"• {tool}")
        
        with col2:
            st.markdown("**🛡️ Security Best Practices:**")
            practices = ["Use encrypted protocols (HTTPS, SFTP)", "Implement network segmentation",
                        "Monitor unusual protocol usage", "Regular security assessments"]
            for practice in practices:
                st.markdown(f"• {practice}")
        
        # Protocol security comparison
        if st.button("📊 Show Protocol Security Comparison"):
            st.markdown("#### 🔒 Secure vs Insecure Protocol Alternatives")
            
            alternatives = [
                {"Insecure": "HTTP", "Secure": "HTTPS", "Improvement": "TLS encryption", "Port Change": "80 → 443"},
                {"Insecure": "FTP", "Secure": "SFTP/FTPS", "Improvement": "SSH/TLS encryption", "Port Change": "21 → 22/990"},
                {"Insecure": "Telnet", "Secure": "SSH", "Improvement": "Encrypted terminal", "Port Change": "23 → 22"},
                {"Insecure": "SMTP", "Secure": "SMTPS", "Improvement": "TLS encryption", "Port Change": "25 → 465/587"},
                {"Insecure": "POP3", "Secure": "POP3S", "Improvement": "TLS encryption", "Port Change": "110 → 995"}
            ]
            
            alt_df = pd.DataFrame(alternatives)
            st.dataframe(alt_df, use_container_width=True)


def explain_network_protocols():
    """Main function for Network Protocols"""
    component = NetworkProtocolsComponent()
    
    summary_points = [
        "Network protocols enable communication between systems across different layers",
        "Many legacy protocols lack built-in security and transmit data in plaintext",
        "Secure alternatives exist for most insecure protocols (HTTP→HTTPS, FTP→SFTP)",
        "Protocol analysis tools help identify security risks and unusual network behavior"
    ]
    
    resources = [
        {"title": "RFC Index", "description": "Official protocol specifications", "url": "https://www.rfc-editor.org/"},
        {"title": "Wireshark Documentation", "description": "Network protocol analysis guide"}
    ]
    
    component.render_full_component(summary_points, resources)
