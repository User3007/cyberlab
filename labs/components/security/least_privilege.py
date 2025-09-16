"""
Principle of Least Privilege Component
Core security principle for access control
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from typing import Dict, List, Any

from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class LeastPrivilegeComponent(ComponentTemplate):
    """Least Privilege principle component"""
    
    def __init__(self):
        super().__init__(
            component_name=" Principle of Least Privilege",
            description="Grant minimum access rights needed for job functions",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="20 minutes"
        )
        
        self.set_key_concepts([
            "Minimum Access", "Need-to-Know", "Role-Based Access", "Regular Reviews"
        ])
    
    def render_content(self):
        """Render Least Privilege content"""
        
        # Core principles
        st.markdown("####  Core Principles")
        
        principles = {
            "Minimum Necessary Access": "Grant only permissions required for specific tasks",
            "Need-to-Know Basis": "Access based on job requirements and data sensitivity",
            "Default Deny": "Start with no access, explicitly grant permissions",
            "Regular Reviews": "Periodic audits and access certification"
        }
        
        for principle, description in principles.items():
            create_info_card(principle, description, "primary", self.color_scheme)
        
        # Access control matrix example
        st.markdown("####  Access Control Matrix")
        
        access_data = [
            {"Role": "End User", "File Access": "Read Own", "System Config": "None", "Admin Rights": "None"},
            {"Role": "Supervisor", "Role": "Read Team", "System Config": "View Only", "Admin Rights": "None"},
            {"Role": "IT Support", "File Access": "Read All", "System Config": "Limited", "Admin Rights": "Local"},
            {"Role": "System Admin", "File Access": "Full Control", "System Config": "Full", "Admin Rights": "Domain"},
            {"Role": "Security Admin", "File Access": "Audit Only", "System Config": "Security", "Admin Rights": "Security"}
        ]
        
        df = pd.DataFrame(access_data)
        st.dataframe(df, use_container_width=True)
        
        # Implementation strategies
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("** Implementation Methods:**")
            methods = ["Role-Based Access Control (RBAC)", "Attribute-Based Access Control (ABAC)", 
                      "Just-In-Time (JIT) Access", "Privileged Access Management (PAM)"]
            for method in methods:
                st.markdown(f" {method}")
        
        with col2:
            st.markdown("** Benefits:**")
            benefits = ["Reduced attack surface", "Limited blast radius", "Compliance alignment", 
                       "Better accountability"]
            for benefit in benefits:
                st.markdown(f" {benefit}")
        
        # Common challenges
        st.markdown("####  Implementation Challenges")
        
        challenges = {
            "User Resistance": "Users want more access than needed",
            "Business Pressure": "Emergency access requests bypass controls",
            "Legacy Systems": "Outdated systems lack granular controls",
            "Operational Overhead": "Managing permissions requires resources"
        }
        
        for challenge, description in challenges.items():
            st.markdown(f"**{challenge}:** {description}")


def explain_least_privilege():
    """Main function for Least Privilege"""
    component = LeastPrivilegeComponent()
    
    summary_points = [
        "Least privilege limits access to minimum necessary for job functions",
        "Default deny approach provides stronger security baseline",
        "Regular access reviews ensure permissions remain appropriate",
        "Balance security requirements with operational efficiency"
    ]
    
    resources = [
        {"title": "NIST SP 800-53", "description": "Access control guidelines"},
        {"title": "SANS Access Control", "description": "Best practices for access management"}
    ]
    
    component.render_full_component(summary_points, resources)
