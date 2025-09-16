"""
IP Addressing Component
IP addressing concepts and subnetting fundamentals
"""

import streamlit as st
import pandas as pd
import ipaddress
from typing import Dict, List, Any

from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class IPAddressingComponent(ComponentTemplate):
    """IP Addressing component - networking fundamentals"""
    
    def __init__(self):
        super().__init__(
            component_name=" IP Addressing",
            description="IP addressing, subnetting, and network design fundamentals",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="25 minutes"
        )
        
        self.set_key_concepts([
            "IPv4/IPv6", "Subnetting", "CIDR Notation", "Private Networks"
        ])
    
    def render_content(self):
        """Render IP Addressing content"""
        
        # IP version comparison
        st.markdown("####  IPv4 vs IPv6 Comparison")
        
        ip_comparison = [
            {"Aspect": "Address Length", "IPv4": "32 bits (4 bytes)", "IPv6": "128 bits (16 bytes)"},
            {"Aspect": "Address Space", "IPv4": "4.3 billion addresses", "IPv6": "340 undecillion addresses"},
            {"Aspect": "Format", "IPv4": "192.168.1.1", "IPv6": "2001:db8::1"},
            {"Aspect": "Header Size", "IPv4": "20-60 bytes", "IPv6": "40 bytes (fixed)"},
            {"Aspect": "Security", "IPv4": "Optional (IPSec)", "IPv6": "Built-in IPSec"},
            {"Aspect": "NAT Required", "IPv4": "Yes (address shortage)", "IPv6": "No (abundant addresses)"}
        ]
        
        df = pd.DataFrame(ip_comparison)
        st.dataframe(df, use_container_width=True)
        
        # IPv4 address classes
        st.markdown("####  IPv4 Address Classes")
        
        address_classes = [
            {"Class": "A", "Range": "1.0.0.0 - 126.255.255.255", "Default Mask": "/8 (255.0.0.0)", "Networks": "126", "Hosts": "16.7M"},
            {"Class": "B", "Range": "128.0.0.0 - 191.255.255.255", "Default Mask": "/16 (255.255.0.0)", "Networks": "16,384", "Hosts": "65,534"},
            {"Class": "C", "Range": "192.0.0.0 - 223.255.255.255", "Default Mask": "/24 (255.255.255.0)", "Networks": "2M", "Hosts": "254"}
        ]
        
        classes_df = pd.DataFrame(address_classes)
        st.dataframe(classes_df, use_container_width=True)
        
        # Private IP ranges
        col1, col2 = st.columns(2)
        
        with col1:
            create_info_card(
                " Private IP Ranges",
                "Non-routable addresses for internal networks",
                "info", self.color_scheme
            )
            
            private_ranges = [
                "**Class A:** 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)",
                "**Class B:** 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)",
                "**Class C:** 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)"
            ]
            
            for range_info in private_ranges:
                st.markdown(range_info)
        
        with col2:
            create_info_card(
                " Special IP Ranges",
                "Reserved and special-purpose addresses",
                "warning", self.color_scheme
            )
            
            special_ranges = [
                "**Loopback:** 127.0.0.0/8 (localhost)",
                "**Link-Local:** 169.254.0.0/16 (APIPA)",
                "**Multicast:** 224.0.0.0/4",
                "**Broadcast:** 255.255.255.255"
            ]
            
            for range_info in special_ranges:
                st.markdown(range_info)
        
        # Interactive subnet calculator
        st.markdown("####  Interactive Subnet Calculator")
        
        col1, col2 = st.columns(2)
        
        with col1:
            ip_input = st.text_input("Enter IP Address:", value="192.168.1.0")
            subnet_input = st.number_input("Subnet Mask (CIDR):", min_value=8, max_value=30, value=24)
        
        with col2:
            if st.button(" Calculate Subnets"):
                try:
                    network = ipaddress.IPv4Network(f"{ip_input}/{subnet_input}", strict=False)
                    
                    st.markdown("** Network Information:**")
                    st.markdown(f" **Network:** {network.network_address}")
                    st.markdown(f" **Broadcast:** {network.broadcast_address}")
                    st.markdown(f" **Netmask:** {network.netmask}")
                    st.markdown(f" **Host Count:** {network.num_addresses - 2}")
                    st.markdown(f" **First Host:** {network.network_address + 1}")
                    st.markdown(f" **Last Host:** {network.broadcast_address - 1}")
                    
                except Exception as e:
                    st.error(f"Invalid IP address or subnet: {e}")
        
        # Subnetting examples
        st.markdown("####  Common Subnetting Examples")
        
        subnetting_examples = [
            {"Network": "192.168.1.0/24", "Subnets": "2", "New Mask": "/25", "Hosts per Subnet": "126", "Use Case": "Split network in half"},
            {"Network": "192.168.1.0/24", "Subnets": "4", "New Mask": "/26", "Hosts per Subnet": "62", "Use Case": "Department networks"},
            {"Network": "192.168.1.0/24", "Subnets": "8", "New Mask": "/27", "Hosts per Subnet": "30", "Use Case": "Small office networks"},
            {"Network": "10.0.0.0/8", "Subnets": "256", "New Mask": "/16", "Hosts per Subnet": "65,534", "Use Case": "Large enterprise"},
        ]
        
        subnetting_df = pd.DataFrame(subnetting_examples)
        st.dataframe(subnetting_df, use_container_width=True)
        
        # Security considerations
        st.markdown("####  IP Addressing Security Considerations")
        
        security_considerations = [
            "**IP Spoofing:** Attackers can forge source IP addresses",
            "**Network Reconnaissance:** IP ranges reveal network structure",
            "**Private IP Exposure:** Internal IPs leaked through headers/logs",
            "**Geolocation:** Public IPs can reveal approximate location"
        ]
        
        for consideration in security_considerations:
            st.markdown(consideration)
        
        # Best practices
        st.markdown("####  IP Addressing Best Practices")
        
        best_practices = [
            "Use private IP ranges for internal networks",
            "Implement proper network segmentation",
            "Document IP address assignments",
            "Use DHCP reservations for servers",
            "Plan for IPv6 transition",
            "Monitor for IP conflicts and unauthorized usage"
        ]
        
        for practice in best_practices:
            st.markdown(f" {practice}")


def explain_ip_addressing():
    """Main function for IP Addressing"""
    component = IPAddressingComponent()
    
    summary_points = [
        "IPv4 provides 4.3 billion addresses using 32-bit addressing scheme",
        "Subnetting allows efficient use of IP address space through network division",
        "Private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x) are non-routable",
        "IPv6 adoption is essential due to IPv4 address exhaustion"
    ]
    
    resources = [
        {"title": "RFC 791 - Internet Protocol", "description": "Original IPv4 specification"},
        {"title": "RFC 4291 - IPv6 Addressing", "description": "IPv6 address architecture"},
        {"title": "Subnet Calculator Tools", "description": "Online subnetting calculators and tools"}
    ]
    
    component.render_full_component(summary_points, resources)
