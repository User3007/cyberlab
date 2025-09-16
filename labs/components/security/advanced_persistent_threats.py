"""
Advanced Persistent Threats (APT) Component
Long-term, sophisticated cyber campaigns
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from typing import Dict, List, Any

from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class APTComponent(ComponentTemplate):
    """Advanced Persistent Threats component"""
    
    def __init__(self):
        super().__init__(
            component_name="🎭 Advanced Persistent Threats",
            description="Sophisticated, long-term cyber campaigns by skilled adversaries",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="20 minutes"
        )
        
        self.set_key_concepts([
            "Persistence", "Advanced Techniques", "Targeted Attacks", "Nation-State Actors"
        ])
    
    def render_content(self):
        """Render APT content"""
        
        # APT characteristics
        st.markdown("#### 🎯 APT Characteristics")
        
        characteristics = {
            "Advanced": "Sophisticated tools, techniques, and procedures",
            "Persistent": "Long-term presence, often months or years",
            "Targeted": "Specific organizations, industries, or individuals",
            "Stealthy": "Designed to evade detection and maintain access",
            "Well-Resourced": "Significant funding and skilled personnel",
            "Motivated": "Clear objectives (espionage, sabotage, financial gain)"
        }
        
        for char, description in characteristics.items():
            create_info_card(char, description, "warning", self.color_scheme)
        
        # APT lifecycle
        st.markdown("#### 🔄 APT Attack Lifecycle")
        
        lifecycle_phases = [
            {"Phase": "1. Reconnaissance", "Description": "Target research and intelligence gathering", "Duration": "Weeks to months"},
            {"Phase": "2. Initial Compromise", "Description": "Gain initial foothold in target network", "Duration": "Days to weeks"},
            {"Phase": "3. Establish Foothold", "Description": "Install backdoors and maintain access", "Duration": "Hours to days"},
            {"Phase": "4. Escalate Privileges", "Description": "Gain higher-level access and permissions", "Duration": "Days to weeks"},
            {"Phase": "5. Internal Reconnaissance", "Description": "Map network and identify valuable assets", "Duration": "Weeks to months"},
            {"Phase": "6. Lateral Movement", "Description": "Spread to other systems and networks", "Duration": "Weeks to months"},
            {"Phase": "7. Maintain Presence", "Description": "Establish persistent access mechanisms", "Duration": "Months to years"},
            {"Phase": "8. Complete Mission", "Description": "Achieve primary objectives", "Duration": "Ongoing"}
        ]
        
        lifecycle_df = pd.DataFrame(lifecycle_phases)
        st.dataframe(lifecycle_df, use_container_width=True)
        
        # Notable APT groups
        st.markdown("#### 🏴‍☠️ Notable APT Groups")
        
        apt_groups = {
            "APT1 (Comment Crew)": {
                "Attribution": "Chinese PLA Unit 61398",
                "Targets": "Intellectual property theft from 141+ organizations",
                "Active Since": "2006",
                "Notable Campaign": "Operation Aurora (Google, Adobe)"
            },
            "APT28 (Fancy Bear)": {
                "Attribution": "Russian GRU Unit 26165",
                "Targets": "Government, military, security organizations",
                "Active Since": "2004",
                "Notable Campaign": "2016 US Election interference"
            },
            "APT29 (Cozy Bear)": {
                "Attribution": "Russian SVR",
                "Targets": "Government, think tanks, healthcare",
                "Active Since": "2008", 
                "Notable Campaign": "SolarWinds supply chain attack"
            },
            "Lazarus Group": {
                "Attribution": "North Korean RGB",
                "Targets": "Financial institutions, cryptocurrency",
                "Active Since": "2009",
                "Notable Campaign": "Sony Pictures hack, WannaCry"
            }
        }
        
        selected_apt = st.selectbox(
            "🔍 Explore APT Group:",
            list(apt_groups.keys()),
            key="apt_group_selector"
        )
        
        apt_info = apt_groups[selected_apt]
        
        st.markdown(f"""
        <div style="background: {self.color_scheme['background']}; padding: 1.5rem; border-radius: 8px; margin: 1rem 0; border-left: 5px solid {self.color_scheme['primary']};">
            <h4 style="color: {self.color_scheme['primary']}; margin-top: 0;">🏴‍☠️ {selected_apt} Profile</h4>
            <p><strong>Attribution:</strong> {apt_info['Attribution']}</p>
            <p><strong>Primary Targets:</strong> {apt_info['Targets']}</p>
            <p><strong>Active Since:</strong> {apt_info['Active Since']}</p>
            <p><strong>Notable Campaign:</strong> {apt_info['Notable Campaign']}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Defense strategies
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🛡️ Detection Strategies:**")
            detection = [
                "Behavioral analytics and anomaly detection",
                "Threat hunting and proactive monitoring", 
                "Network traffic analysis and forensics",
                "Endpoint detection and response (EDR)"
            ]
            for strategy in detection:
                st.markdown(f"• {strategy}")
        
        with col2:
            st.markdown("**🔒 Prevention Measures:**")
            prevention = [
                "Zero trust architecture implementation",
                "Regular security assessments and penetration testing",
                "Employee security awareness training",
                "Incident response and recovery planning"
            ]
            for measure in prevention:
                st.markdown(f"• {measure}")
        
        # APT vs regular attacks
        if st.button("📊 APT vs Regular Cyber Attacks"):
            st.markdown("#### ⚖️ APT vs Regular Cyber Attacks Comparison")
            
            comparison_data = [
                {"Aspect": "Duration", "Regular Attacks": "Minutes to hours", "APT": "Months to years"},
                {"Aspect": "Sophistication", "Regular Attacks": "Automated tools", "APT": "Custom tools and techniques"},
                {"Aspect": "Targeting", "Regular Attacks": "Opportunistic", "APT": "Highly targeted"},
                {"Aspect": "Motivation", "Regular Attacks": "Financial gain", "APT": "Espionage, sabotage, strategic"},
                {"Aspect": "Resources", "Regular Attacks": "Individual/small group", "APT": "Nation-state/organized group"},
                {"Aspect": "Detection", "Regular Attacks": "Often detected quickly", "APT": "Designed to evade detection"}
            ]
            
            comparison_df = pd.DataFrame(comparison_data)
            st.dataframe(comparison_df, use_container_width=True)


def explain_advanced_persistent_threats():
    """Main function for APT"""
    component = APTComponent()
    
    summary_points = [
        "APTs are sophisticated, long-term campaigns by well-resourced adversaries",
        "APT attacks follow a multi-phase lifecycle spanning months to years",
        "Nation-state actors are primary APT operators with strategic objectives",
        "Defense requires proactive hunting, behavioral analytics, and zero trust architecture"
    ]
    
    resources = [
        {"title": "Mandiant APT1 Report", "description": "Groundbreaking report exposing Chinese APT operations"},
        {"title": "MITRE ATT&CK for Enterprise", "description": "APT technique mapping and analysis"}
    ]
    
    component.render_full_component(summary_points, resources)
