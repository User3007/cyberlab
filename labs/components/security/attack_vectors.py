"""
Attack Vectors Component
Common attack methods and entry points
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from typing import Dict, List, Any

from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class AttackVectorsComponent(ComponentTemplate):
    """Attack Vectors component - focused on common attack methods"""
    
    def __init__(self):
        super().__init__(
            component_name="🎯 Common Attack Vectors",
            description="Primary methods attackers use to compromise systems",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="25 minutes"
        )
        
        self.set_key_concepts([
            "Attack Surface", "Entry Points", "Exploitation Methods", "Defense Strategies"
        ])
    
    def render_content(self):
        """Render Attack Vectors content"""
        
        # Major attack categories
        attack_categories = {
            "Network-Based Attacks": {
                "description": "Attacks targeting network infrastructure and protocols",
                "vectors": ["DDoS/DoS", "Man-in-the-Middle", "DNS Poisoning", "ARP Spoofing", "Port Scanning"],
                "defenses": ["Firewalls", "IDS/IPS", "Network Segmentation", "Encrypted Communications"]
            },
            "Application-Based Attacks": {
                "description": "Attacks targeting software applications and web services",
                "vectors": ["SQL Injection", "XSS", "CSRF", "Buffer Overflow", "API Abuse"],
                "defenses": ["Input Validation", "WAF", "Secure Coding", "Regular Updates"]
            },
            "Social Engineering": {
                "description": "Attacks targeting human psychology and behavior",
                "vectors": ["Phishing", "Pretexting", "Baiting", "Tailgating", "Vishing"],
                "defenses": ["Security Awareness", "Email Filtering", "Verification Procedures"]
            },
            "Physical Attacks": {
                "description": "Attacks requiring physical access to systems",
                "vectors": ["USB Drops", "Shoulder Surfing", "Device Theft", "Dumpster Diving"],
                "defenses": ["Physical Security", "Access Controls", "Device Encryption"]
            },
            "Insider Threats": {
                "description": "Attacks from authorized users with legitimate access",
                "vectors": ["Data Theft", "Sabotage", "Credential Abuse", "Privilege Escalation"],
                "defenses": ["Background Checks", "Monitoring", "Least Privilege", "Separation of Duties"]
            }
        }
        
        # Interactive category explorer
        selected_category = st.selectbox(
            "🔍 Explore Attack Category:",
            list(attack_categories.keys()),
            key="attack_category_selector"
        )
        
        category_info = attack_categories[selected_category]
        
        create_info_card(
            f"🎯 {selected_category}",
            category_info['description'],
            "warning", self.color_scheme
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**⚔️ Common Vectors:**")
            for vector in category_info['vectors']:
                st.markdown(f"• {vector}")
        
        with col2:
            st.markdown("**🛡️ Key Defenses:**")
            for defense in category_info['defenses']:
                st.markdown(f"• {defense}")
        
        # Attack frequency statistics (simulated)
        st.markdown("#### 📊 Attack Vector Frequency (2024)")
        
        frequency_data = {
            "Attack Vector": ["Phishing", "Malware", "Credential Theft", "DDoS", "SQL Injection", "Insider Threat"],
            "Frequency %": [85, 72, 68, 45, 38, 25],
            "Severity": ["High", "Critical", "Critical", "Medium", "High", "Critical"]
        }
        
        df = pd.DataFrame(frequency_data)
        
        fig = px.bar(
            df, x="Attack Vector", y="Frequency %", color="Severity",
            title="Most Common Attack Vectors",
            color_discrete_map={"Critical": "#FF4444", "High": "#FF8800", "Medium": "#FFBB00"}
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Attack vector cheat sheet
        cheat_sheets = {
            "Top Attack Vectors": {
                "commands": [
                    {"Vector": "Phishing", "Method": "Email/SMS deception", "Target": "Credentials/malware", "Defense": "Email security + training"},
                    {"Vector": "Malware", "Method": "Malicious software", "Target": "System compromise", "Defense": "Antivirus + EDR"},
                    {"Vector": "Credential Theft", "Method": "Password attacks", "Target": "Account access", "Defense": "MFA + password policies"},
                    {"Vector": "SQL Injection", "Method": "Database queries", "Target": "Data access", "Defense": "Input validation + WAF"},
                    {"Vector": "DDoS", "Method": "Traffic flooding", "Target": "Service disruption", "Defense": "DDoS protection + CDN"}
                ]
            }
        }
        
        create_cheat_sheet_tabs(cheat_sheets, self.color_scheme)


def explain_attack_vectors():
    """Main function for Attack Vectors"""
    component = AttackVectorsComponent()
    
    summary_points = [
        "Attack vectors are methods used to gain unauthorized access to systems",
        "Most attacks combine multiple vectors for higher success rates",
        "Social engineering remains the most effective attack vector",
        "Defense requires layered approach addressing all vector categories"
    ]
    
    resources = [
        {"title": "OWASP Top 10", "description": "Most critical web application risks", "url": "https://owasp.org/Top10/"},
        {"title": "MITRE ATT&CK", "description": "Comprehensive attack technique database"}
    ]
    
    component.render_full_component(summary_points, resources)
