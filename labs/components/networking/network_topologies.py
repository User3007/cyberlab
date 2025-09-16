"""
Network Topologies Component
Network design patterns and architectures
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from typing import Dict, List, Any

from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class NetworkTopologiesComponent(ComponentTemplate):
    """Network Topologies component - network design patterns"""
    
    def __init__(self):
        super().__init__(
            component_name=" Network Topologies",
            description="Network design patterns and their characteristics",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="15 minutes"
        )
        
        self.set_key_concepts([
            "Physical Topologies", "Logical Topologies", "Scalability", "Fault Tolerance"
        ])
    
    def render_header(self):
        """Render a compact header to minimize vertical space."""
        create_banner(
            title=self.component_name,
            description=self.description,
            color_scheme=self.color_scheme,
            icon="",
            estimated_time=self.estimated_time
        )
    
    def render_content(self):
        """Render Network Topologies content"""
        
        # Topology comparison
        topologies = {
            "Bus": {
                "description": "All devices connected to a single cable",
                "advantages": ["Simple to install", "Cost-effective", "Less cable required"],
                "disadvantages": ["Single point of failure", "Performance degrades with more devices", "Difficult to troubleshoot"],
                "use_case": "Legacy networks, small temporary setups",
                "fault_tolerance": "Low"
            },
            "Star": {
                "description": "All devices connected to central hub/switch",
                "advantages": ["Easy to troubleshoot", "Failure isolation", "Easy to add/remove devices"],
                "disadvantages": ["Central device failure affects all", "More cable required", "Hub/switch cost"],
                "use_case": "Most common in modern LANs",
                "fault_tolerance": "Medium"
            },
            "Ring": {
                "description": "Devices connected in circular fashion",
                "advantages": ["Equal access for all devices", "No collisions", "Predictable performance"],
                "disadvantages": ["Single break affects all", "Difficult to troubleshoot", "Adding devices disrupts network"],
                "use_case": "Token Ring networks (legacy), fiber optic rings",
                "fault_tolerance": "Low (single ring), High (dual ring)"
            },
            "Mesh": {
                "description": "Multiple connections between devices",
                "advantages": ["High fault tolerance", "Multiple paths", "Load distribution"],
                "disadvantages": ["Complex to configure", "Expensive", "Difficult to maintain"],
                "use_case": "Critical networks, Internet backbone, wireless networks",
                "fault_tolerance": "Very High"
            },
            "Hybrid": {
                "description": "Combination of multiple topologies",
                "advantages": ["Flexible design", "Scalable", "Can optimize for specific needs"],
                "disadvantages": ["Complex design", "Higher cost", "Difficult to maintain"],
                "use_case": "Enterprise networks, campus networks",
                "fault_tolerance": "Varies by design"
            }
        }
        
        # Interactive topology explorer
        selected_topology = st.selectbox(
            " Explore Network Topology:",
            list(topologies.keys()),
            key="network_topology_selector"
        )
        
        topology_info = topologies[selected_topology]
        
        create_info_card(
            f" {selected_topology} Topology",
            topology_info['description'],
            "primary", self.color_scheme
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("** Advantages:**")
            for advantage in topology_info['advantages']:
                st.markdown(f" {advantage}")
        
        with col2:
            st.markdown("** Disadvantages:**")
            for disadvantage in topology_info['disadvantages']:
                st.markdown(f" {disadvantage}")
        
        st.markdown(f"** Use Case:** {topology_info['use_case']}")
        st.markdown(f"** Fault Tolerance:** {topology_info['fault_tolerance']}")
        
        # Topology comparison table
        st.markdown("####  Topology Comparison Matrix")
        
        comparison_data = [
            {"Topology": "Bus", "Cost": "Low", "Scalability": "Poor", "Fault Tolerance": "Low", "Performance": "Degrades", "Maintenance": "Difficult"},
            {"Topology": "Star", "Cost": "Medium", "Scalability": "Good", "Fault Tolerance": "Medium", "Performance": "Good", "Maintenance": "Easy"},
            {"Topology": "Ring", "Cost": "Medium", "Scalability": "Fair", "Fault Tolerance": "Low", "Performance": "Consistent", "Maintenance": "Difficult"},
            {"Topology": "Mesh", "Cost": "High", "Scalability": "Excellent", "Fault Tolerance": "Very High", "Performance": "Excellent", "Maintenance": "Complex"},
            {"Topology": "Hybrid", "Cost": "Variable", "Scalability": "Excellent", "Fault Tolerance": "Variable", "Performance": "Variable", "Maintenance": "Complex"}
        ]
        
        comparison_df = pd.DataFrame(comparison_data)
        st.dataframe(comparison_df, use_container_width=True)
        
        # Modern network architectures
        st.markdown("####  Modern Network Architectures")
        
        modern_architectures = {
            "Three-Tier": "Core, Distribution, Access layers for hierarchical design",
            "Spine-Leaf": "High-bandwidth, low-latency data center architecture",
            "Software-Defined (SDN)": "Centralized control plane, programmable networks",
            "Cloud-Native": "Distributed, microservices-based network design",
            "Zero Trust": "Never trust, always verify network security model"
        }
        
        for architecture, description in modern_architectures.items():
            st.markdown(f"**{architecture}:** {description}")
        
        # Security implications
        st.markdown("####  Security Implications by Topology")
        
        security_implications = [
            "**Bus Topology:** Shared medium - all traffic visible to all devices",
            "**Star Topology:** Central point monitoring possible, but switch isolation provides security",
            "**Ring Topology:** Token-based access control, but single point monitoring possible",
            "**Mesh Topology:** Multiple paths complicate monitoring but provide redundancy",
            "**Hybrid Topology:** Security varies by implementation - requires comprehensive strategy"
        ]
        
        for implication in security_implications:
            st.markdown(implication)
        
        # Design considerations
        if st.button(" Show Design Considerations"):
            st.markdown("####  Network Design Considerations")
            
            considerations = [
                {"Factor": "Business Requirements", "Consideration": "Bandwidth needs, application requirements, growth plans"},
                {"Factor": "Budget Constraints", "Consideration": "Initial cost, ongoing maintenance, upgrade costs"},
                {"Factor": "Scalability", "Consideration": "Future expansion, device additions, performance growth"},
                {"Factor": "Reliability", "Consideration": "Uptime requirements, redundancy needs, fault tolerance"},
                {"Factor": "Security", "Consideration": "Data sensitivity, compliance requirements, threat landscape"},
                {"Factor": "Management", "Consideration": "Administrative overhead, monitoring capabilities, troubleshooting"}
            ]
            
            considerations_df = pd.DataFrame(considerations)
            st.dataframe(considerations_df, use_container_width=True)


def explain_network_topologies():
    """Main function for Network Topologies"""
    component = NetworkTopologiesComponent()
    
    summary_points = [
        "Network topology choice impacts performance, cost, and fault tolerance",
        "Star topology is most common in modern LANs due to easy management",
        "Mesh topology provides highest fault tolerance but at increased complexity",
        "Modern architectures combine multiple topologies for optimal performance"
    ]
    
    resources = [
        {"title": "Network Design Fundamentals", "description": "Cisco network design guidelines"},
        {"title": "Data Center Architecture", "description": "Modern spine-leaf design patterns"}
    ]
    
    component.render_full_component(summary_points, resources)
