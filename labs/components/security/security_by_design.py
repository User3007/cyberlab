"""
Security by Design Component
Proactive security integration in development
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from typing import Dict, List, Any

from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class SecurityByDesignComponent(ComponentTemplate):
    """Security by Design component - proactive security"""
    
    def __init__(self):
        super().__init__(
            component_name="🛡️ Security by Design",
            description="Integrate security from the beginning of system development",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="25 minutes"
        )
        
        self.set_key_concepts([
            "Proactive Security", "Secure SDLC", "Threat Modeling", "Security Controls"
        ])
    
    def render_content(self):
        """Render Security by Design content"""
        
        # Core principles
        st.markdown("#### 🎯 Core Principles")
        
        principles = {
            "Security from Start": "Integrate security considerations from project inception",
            "Threat Modeling": "Identify and address threats during design phase",
            "Secure Defaults": "Default configurations should be secure",
            "Defense in Depth": "Multiple layers of security controls",
            "Fail Securely": "System failures should not compromise security",
            "Least Privilege": "Grant minimum necessary access rights"
        }
        
        for principle, description in principles.items():
            create_info_card(principle, description, "primary", self.color_scheme)
        
        # SDLC integration
        st.markdown("#### 🔄 Secure SDLC Integration")
        
        sdlc_phases = [
            {"Phase": "Requirements", "Security Activities": "Security requirements, compliance needs, risk assessment", "Deliverables": "Security requirements document"},
            {"Phase": "Design", "Security Activities": "Threat modeling, security architecture, control design", "Deliverables": "Security design, threat model"},
            {"Phase": "Development", "Security Activities": "Secure coding, code review, static analysis", "Deliverables": "Secure code, review reports"},
            {"Phase": "Testing", "Security Activities": "Security testing, penetration testing, vulnerability assessment", "Deliverables": "Security test results"},
            {"Phase": "Deployment", "Security Activities": "Security configuration, monitoring setup", "Deliverables": "Secure deployment"},
            {"Phase": "Maintenance", "Security Activities": "Security updates, monitoring, incident response", "Deliverables": "Security patches, reports"}
        ]
        
        df = pd.DataFrame(sdlc_phases)
        st.dataframe(df, use_container_width=True)
        
        # Threat modeling process
        st.markdown("#### 🎯 Threat Modeling Process")
        
        threat_steps = [
            "**1. Define Scope** - Identify system boundaries and assets",
            "**2. Create Model** - Develop system architecture diagrams",
            "**3. Identify Threats** - Use STRIDE or other frameworks",
            "**4. Assess Risk** - Evaluate likelihood and impact",
            "**5. Design Controls** - Select appropriate mitigations",
            "**6. Validate** - Test and verify security controls"
        ]
        
        for step in threat_steps:
            st.markdown(step)
        
        # STRIDE threat categories
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🎭 STRIDE Threat Categories:**")
            stride = [
                "**S**poofing - Identity impersonation",
                "**T**ampering - Data modification", 
                "**R**epudiation - Denial of actions",
                "**I**nformation Disclosure - Data exposure",
                "**D**enial of Service - Availability attacks",
                "**E**levation of Privilege - Unauthorized access"
            ]
            for threat in stride:
                st.markdown(f"• {threat}")
        
        with col2:
            st.markdown("**🔧 Security Controls:**")
            controls = [
                "Authentication & Authorization",
                "Input Validation & Sanitization",
                "Logging & Monitoring", 
                "Encryption & Data Protection",
                "Rate Limiting & Throttling",
                "Access Controls & Permissions"
            ]
            for control in controls:
                st.markdown(f"• {control}")
        
        # Implementation challenges
        st.markdown("#### ⚠️ Common Implementation Challenges")
        
        challenges = {
            "Time Pressure": "Security activities seen as delaying delivery",
            "Cost Concerns": "Security measures increase development costs",
            "Skill Gaps": "Developers lack security expertise",
            "Legacy Systems": "Existing systems hard to retrofit with security",
            "Changing Requirements": "Security needs evolve during development"
        }
        
        for challenge, description in challenges.items():
            st.markdown(f"**{challenge}:** {description}")
        
        # Benefits analysis
        if st.button("📊 Show Benefits Analysis"):
            st.markdown("#### 💰 Security by Design Benefits")
            
            benefits_data = {
                "Metric": ["Cost of Security Fix", "Time to Market", "Security Incidents", "Compliance Effort"],
                "Traditional Approach": ["100x (production)", "Faster initially", "Higher frequency", "Reactive compliance"],
                "Security by Design": ["1x (design phase)", "Stable long-term", "Lower frequency", "Built-in compliance"],
                "Improvement": ["99% cost reduction", "Better predictability", "60% fewer incidents", "80% less effort"]
            }
            
            df = pd.DataFrame(benefits_data)
            st.dataframe(df, use_container_width=True)


def explain_security_by_design():
    """Main function for Security by Design"""
    component = SecurityByDesignComponent()
    
    summary_points = [
        "Security by Design integrates security from project inception, not as an afterthought",
        "Threat modeling during design phase identifies risks before implementation",
        "Security controls built into system architecture are more effective and cheaper",
        "Secure SDLC practices reduce vulnerabilities and compliance costs significantly"
    ]
    
    resources = [
        {"title": "OWASP SAMM", "description": "Software Assurance Maturity Model", "url": "https://owaspsamm.org/"},
        {"title": "Microsoft SDL", "description": "Security Development Lifecycle practices"},
        {"title": "NIST Secure Software Development", "description": "Framework for secure development"}
    ]
    
    component.render_full_component(summary_points, resources)
