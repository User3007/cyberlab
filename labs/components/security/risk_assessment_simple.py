"""
Risk Assessment Component - Simplified Version
Core risk assessment concepts without complex visualizations
"""

import streamlit as st
import pandas as pd
from typing import Dict, List, Any

from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class RiskAssessmentComponent(ComponentTemplate):
    """Risk Assessment component - simplified and stable"""
    
    def __init__(self):
        super().__init__(
            component_name="📊 Risk Assessment",
            description="Systematic evaluation of security risks and mitigation strategies",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="25 minutes"
        )
        
        self.set_key_concepts([
            "Risk = Threat × Vulnerability × Impact", "Risk Matrix", "Risk Treatment", "Continuous Monitoring"
        ])
    
    def render_content(self):
        """Render Risk Assessment content"""
        
        # Risk fundamentals
        self._render_risk_fundamentals()
        
        # Risk assessment process
        self._render_assessment_process()
        
        # Risk treatment strategies
        self._render_treatment_strategies()
        
        # Risk monitoring
        self._render_monitoring()
    
    def _render_risk_fundamentals(self):
        """Render risk assessment fundamentals"""
        st.subheader("📊 Risk Assessment Fundamentals")
        
        # Risk equation
        st.markdown("#### 🧮 Risk Calculation Formula")
        
        st.markdown("""
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem; border-radius: 12px; margin: 1.5rem 0; color: white; text-align: center;">
            <h3 style="margin: 0;">Risk = Threat × Vulnerability × Impact</h3>
            <p style="margin: 0.5rem 0 0 0; opacity: 0.9;">Where each factor is rated on a scale of 1-5</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Risk components
        col1, col2, col3 = st.columns(3)
        
        with col1:
            create_info_card(
                "⚠️ Threat",
                "Potential danger that could exploit vulnerabilities",
                "warning", self.color_scheme
            )
            threats = ["Hackers", "Malware", "Natural disasters", "Insider threats", "System failures"]
            for threat in threats:
                st.markdown(f"• {threat}")
        
        with col2:
            create_info_card(
                "🔓 Vulnerability",
                "Weaknesses that can be exploited by threats",
                "danger", self.color_scheme
            )
            vulnerabilities = ["Software bugs", "Weak passwords", "Unpatched systems", "Poor configuration", "Human error"]
            for vuln in vulnerabilities:
                st.markdown(f"• {vuln}")
        
        with col3:
            create_info_card(
                "💥 Impact",
                "Consequences if risk materializes",
                "info", self.color_scheme
            )
            impacts = ["Data loss", "Financial loss", "Reputation damage", "Operational disruption", "Legal liability"]
            for impact in impacts:
                st.markdown(f"• {impact}")
        
        # Risk matrix
        st.markdown("#### 📊 Risk Assessment Matrix")
        
        risk_matrix = [
            {"Impact\\Likelihood": "Critical", "Rare": "Medium", "Unlikely": "High", "Possible": "Critical", "Likely": "Critical", "Almost Certain": "Critical"},
            {"Impact\\Likelihood": "High", "Rare": "Low", "Unlikely": "Medium", "Possible": "High", "Likely": "High", "Almost Certain": "Critical"},
            {"Impact\\Likelihood": "Medium", "Rare": "Low", "Unlikely": "Low", "Possible": "Medium", "Likely": "Medium", "Almost Certain": "High"},
            {"Impact\\Likelihood": "Low", "Rare": "Low", "Unlikely": "Low", "Possible": "Low", "Likely": "Low", "Almost Certain": "Medium"}
        ]
        
        df = pd.DataFrame(risk_matrix)
        st.dataframe(df, use_container_width=True)
    
    def _render_assessment_process(self):
        """Render risk assessment process"""
        st.subheader("🔄 Risk Assessment Process")
        
        process_steps = [
            {
                "step": "1. Asset Identification",
                "description": "Identify and catalog all assets (data, systems, people)",
                "activities": ["Asset inventory", "Asset classification", "Asset valuation"],
                "deliverables": "Asset register"
            },
            {
                "step": "2. Threat Identification", 
                "description": "Identify potential threats to assets",
                "activities": ["Threat modeling", "Historical analysis", "Intelligence gathering"],
                "deliverables": "Threat catalog"
            },
            {
                "step": "3. Vulnerability Assessment",
                "description": "Identify weaknesses that could be exploited",
                "activities": ["Vulnerability scanning", "Penetration testing", "Code review"],
                "deliverables": "Vulnerability report"
            },
            {
                "step": "4. Risk Analysis",
                "description": "Evaluate likelihood and impact of risks",
                "activities": ["Probability assessment", "Impact analysis", "Risk calculation"],
                "deliverables": "Risk register"
            },
            {
                "step": "5. Risk Evaluation",
                "description": "Compare risks against acceptance criteria",
                "activities": ["Risk ranking", "Priority setting", "Treatment decisions"],
                "deliverables": "Risk treatment plan"
            }
        ]
        
        for step_info in process_steps:
            with st.expander(f"📋 {step_info['step']}"):
                st.markdown(f"**Description:** {step_info['description']}")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**Activities:**")
                    for activity in step_info['activities']:
                        st.markdown(f"• {activity}")
                
                with col2:
                    st.markdown(f"**Deliverable:** {step_info['deliverables']}")
    
    def _render_treatment_strategies(self):
        """Render risk treatment strategies"""
        st.subheader("🛡️ Risk Treatment Strategies")
        
        treatment_options = {
            "Accept": {
                "description": "Acknowledge risk and take no action",
                "when_to_use": "Risk is within acceptable tolerance",
                "example": "Accept minor website downtime risk",
                "cost": "None",
                "effectiveness": "N/A"
            },
            "Avoid": {
                "description": "Eliminate the risk by removing the source",
                "when_to_use": "Risk is too high and cannot be mitigated",
                "example": "Stop using vulnerable software",
                "cost": "High (opportunity cost)",
                "effectiveness": "100%"
            },
            "Mitigate": {
                "description": "Reduce likelihood or impact of risk",
                "when_to_use": "Most common approach for manageable risks",
                "example": "Install firewalls, train users",
                "cost": "Medium",
                "effectiveness": "Variable"
            },
            "Transfer": {
                "description": "Share risk with third party",
                "when_to_use": "Risk is significant but manageable by others",
                "example": "Cyber insurance, cloud services",
                "cost": "Low to Medium",
                "effectiveness": "Depends on coverage"
            }
        }
        
        # Treatment strategy selector
        selected_strategy = st.selectbox(
            "🔍 Explore Risk Treatment Strategy:",
            list(treatment_options.keys()),
            key="risk_treatment_strategy_selector_unique"
        )
        
        strategy_info = treatment_options[selected_strategy]
        
        create_info_card(
            f"🛡️ {selected_strategy} Strategy",
            strategy_info['description'],
            card_type="primary",
            color_scheme=self.color_scheme
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"**When to Use:** {strategy_info['when_to_use']}")
            st.markdown(f"**Example:** {strategy_info['example']}")
        
        with col2:
            st.markdown(f"**Cost:** {strategy_info['cost']}")
            st.markdown(f"**Effectiveness:** {strategy_info['effectiveness']}")
    
    def _render_monitoring(self):
        """Render risk monitoring"""
        st.subheader("👁️ Continuous Risk Monitoring")
        
        monitoring_activities = [
            "**Risk Register Updates** - Regular review and update of identified risks",
            "**Threat Intelligence** - Monitor for new and emerging threats",
            "**Vulnerability Scanning** - Automated and manual vulnerability assessments",
            "**Security Metrics** - Track key risk indicators and trends",
            "**Incident Analysis** - Learn from security incidents and near misses",
            "**Control Effectiveness** - Evaluate performance of security controls"
        ]
        
        for activity in monitoring_activities:
            st.markdown(activity)
        
        # Key risk indicators
        st.markdown("#### 📈 Key Risk Indicators (KRIs)")
        
        kri_examples = [
            {"Indicator": "Patch Management", "Metric": "% of systems with current patches", "Target": "> 95%"},
            {"Indicator": "User Training", "Metric": "% of users completing security training", "Target": "100%"},
            {"Indicator": "Incident Response", "Metric": "Mean time to detect (MTTD)", "Target": "< 1 hour"},
            {"Indicator": "Access Control", "Metric": "% of accounts with appropriate privileges", "Target": "100%"},
            {"Indicator": "Data Protection", "Metric": "% of sensitive data encrypted", "Target": "100%"}
        ]
        
        kri_df = pd.DataFrame(kri_examples)
        st.dataframe(kri_df, use_container_width=True)


def explain_risk_assessment():
    """Main function for Risk Assessment"""
    component = RiskAssessmentComponent()
    
    summary_points = [
        "Risk assessment systematically evaluates threats, vulnerabilities, and impacts",
        "Risk = Threat × Vulnerability × Impact provides quantitative risk calculation",
        "Four main treatment strategies: Accept, Avoid, Mitigate, Transfer",
        "Continuous monitoring ensures risk management remains effective over time"
    ]
    
    resources = [
        {"title": "NIST Risk Management Framework", "description": "Comprehensive risk management guidance"},
        {"title": "ISO 27005", "description": "Information security risk management standard"},
        {"title": "FAIR (Factor Analysis of Information Risk)", "description": "Quantitative risk analysis methodology"}
    ]
    
    component.render_full_component(summary_points, resources)
