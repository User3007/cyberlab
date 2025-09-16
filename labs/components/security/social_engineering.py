"""
Social Engineering Component
Human-based attack techniques and psychology
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from typing import Dict, List, Any

from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class SocialEngineeringComponent(ComponentTemplate):
    """Social Engineering component - human factor attacks"""
    
    def __init__(self):
        super().__init__(
            component_name="🎭 Social Engineering",
            description="Human-based attack techniques exploiting psychology and trust",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="20 minutes"
        )
        
        self.set_key_concepts([
            "Human Psychology", "Trust Exploitation", "Information Gathering", "Defense Training"
        ])
    
    def render_content(self):
        """Render Social Engineering content"""
        
        # Core techniques
        techniques = {
            "Phishing": {
                "description": "Fraudulent emails/messages to steal credentials or install malware",
                "variants": ["Email phishing", "Spear phishing", "Whaling", "Smishing (SMS)", "Vishing (Voice)"],
                "success_rate": "85%",
                "defenses": ["Email filtering", "User training", "Multi-factor authentication"]
            },
            "Pretexting": {
                "description": "Creating fake scenarios to extract information",
                "variants": ["Tech support calls", "Survey scams", "Authority impersonation"],
                "success_rate": "60%",
                "defenses": ["Verification procedures", "Awareness training", "Callback protocols"]
            },
            "Baiting": {
                "description": "Offering something enticing to trigger malicious actions",
                "variants": ["USB drops", "Free software", "Fake promotions"],
                "success_rate": "45%",
                "defenses": ["USB restrictions", "Download policies", "Security awareness"]
            },
            "Tailgating": {
                "description": "Following authorized personnel into secure areas",
                "variants": ["Physical following", "Piggybacking", "Door holding"],
                "success_rate": "70%",
                "defenses": ["Access controls", "Security guards", "Badge verification"]
            }
        }
        
        # Interactive technique explorer
        selected_technique = st.selectbox(
            "🎯 Explore Social Engineering Technique:",
            list(techniques.keys()),
            key="social_engineering_technique_selector"
        )
        
        technique_info = techniques[selected_technique]
        
        create_info_card(
            f"🎭 {selected_technique}",
            technique_info['description'],
            "warning", self.color_scheme
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🔧 Common Variants:**")
            for variant in technique_info['variants']:
                st.markdown(f"• {variant}")
            
            st.metric("Success Rate", technique_info['success_rate'])
        
        with col2:
            st.markdown("**🛡️ Key Defenses:**")
            for defense in technique_info['defenses']:
                st.markdown(f"• {defense}")
        
        # Psychological principles
        st.markdown("#### 🧠 Psychological Principles Exploited")
        
        psychology_principles = {
            "Authority": "People comply with requests from authority figures",
            "Urgency": "Time pressure reduces critical thinking",
            "Trust": "Exploiting existing relationships and rapport",
            "Fear": "Creating anxiety to prompt immediate action",
            "Curiosity": "Human desire to know or explore",
            "Greed": "Promise of financial gain or benefits"
        }
        
        for principle, description in psychology_principles.items():
            st.markdown(f"**{principle}:** {description}")
        
        # Defense strategies
        st.markdown("#### 🛡️ Defense Strategies")
        
        defense_layers = [
            "Security Awareness Training - Regular education on social engineering tactics",
            "Verification Procedures - Always verify identity through independent channels", 
            "Technical Controls - Email filtering, USB restrictions, access controls",
            "Incident Reporting - Easy reporting mechanisms for suspicious activities",
            "Regular Testing - Simulated phishing and social engineering exercises"
        ]
        
        for i, defense in enumerate(defense_layers, 1):
            st.markdown(f"**{i}.** {defense}")
        
        # Quick assessment
        if st.button("🧪 Quick Vulnerability Assessment"):
            st.markdown("#### 📊 Social Engineering Vulnerability Factors")
            
            vulnerability_factors = [
                {"Factor": "Employee Training", "Risk Level": "Medium", "Recommendation": "Implement regular awareness training"},
                {"Factor": "Email Security", "Risk Level": "Low", "Recommendation": "Deploy advanced email filtering"},
                {"Factor": "Physical Security", "Risk Level": "High", "Recommendation": "Improve access controls and monitoring"},
                {"Factor": "Incident Response", "Risk Level": "Medium", "Recommendation": "Establish clear reporting procedures"},
                {"Factor": "Testing Program", "Risk Level": "High", "Recommendation": "Start simulated phishing campaigns"}
            ]
            
            df = pd.DataFrame(vulnerability_factors)
            st.dataframe(df, use_container_width=True)


def explain_social_engineering():
    """Main function for Social Engineering"""
    component = SocialEngineeringComponent()
    
    summary_points = [
        "Social engineering exploits human psychology rather than technical vulnerabilities",
        "Phishing remains the most successful social engineering technique (85% success)",
        "Defense requires combination of training, procedures, and technical controls",
        "Regular testing helps identify and address human vulnerabilities"
    ]
    
    resources = [
        {"title": "Social Engineering Toolkit", "description": "Educational framework for SE awareness"},
        {"title": "KnowBe4 Security Awareness", "description": "Phishing simulation and training platform"}
    ]
    
    component.render_full_component(summary_points, resources)
