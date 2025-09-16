"""
Zero Trust Security Component
Extracted from theory_concepts.py - Enhanced with shared utilities
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Any, Optional

# Import shared utilities
from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_takeaways, create_info_card, create_progress_indicator
from ...shared.diagram_utils import create_basic_figure, add_architecture_diagram
from ...templates.component_template import ComponentTemplate


class ZeroTrustComponent(ComponentTemplate):
    """Zero Trust Architecture component using enhanced template"""
    
    def __init__(self):
        super().__init__(
            component_name="🚫 Zero Trust Architecture",
            description="Never trust, always verify - Modern security architecture approach",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="30 minutes"
        )
        
        self.set_prerequisites([
            "Understanding of network security concepts",
            "Familiarity with identity and access management",
            "Knowledge of traditional perimeter security models"
        ])
        
        self.set_learning_objectives([
            "Understand Zero Trust principles and philosophy",
            "Compare traditional vs Zero Trust security models",
            "Identify key components of Zero Trust architecture",
            "Plan Zero Trust implementation strategy",
            "Assess Zero Trust maturity levels"
        ])
        
        self.set_key_concepts([
            "Never Trust Always Verify", "Identity-Centric Security", "Micro-segmentation",
            "Continuous Verification", "Least Privilege Access", "Risk-Based Authentication"
        ])
    
    def render_content(self):
        """Render the Zero Trust content"""
        
        # Core principles explanation
        self._render_core_principles()
        
        # Traditional vs Zero Trust comparison
        self._render_model_comparison()
        
        # Architecture components
        self._render_architecture_components()
        
        # Implementation roadmap
        self._render_implementation_roadmap()
        
        # Maturity assessment
        self._render_maturity_assessment()
    
    def _render_core_principles(self):
        """Render Zero Trust core principles"""
        st.subheader("🎯 Core Zero Trust Principles")
        
        principles = {
            "Never Trust, Always Verify": {
                "description": "No implicit trust based on network location or previous authentication",
                "implementation": ["Continuous authentication", "Real-time risk assessment", "Dynamic access controls"],
                "icon": "🔐"
            },
            "Least Privilege Access": {
                "description": "Grant minimal access rights necessary for users to perform their job functions", 
                "implementation": ["Role-based access control", "Just-in-time access", "Regular access reviews"],
                "icon": "🔒"
            },
            "Assume Breach": {
                "description": "Operate under the assumption that threats exist within the network",
                "implementation": ["Continuous monitoring", "Threat hunting", "Incident response readiness"],
                "icon": "🚨"
            },
            "Verify Explicitly": {
                "description": "Make access decisions based on all available data points",
                "implementation": ["Multi-factor authentication", "Device compliance", "User behavior analytics"],
                "icon": "✅"
            }
        }
        
        # Display principles in expandable cards
        for principle, details in principles.items():
            with st.expander(f"{details['icon']} {principle}", expanded=False):
                create_info_card(
                    principle,
                    details['description'],
                    card_type="primary",
                    color_scheme=self.color_scheme
                )
                
                st.markdown("**Implementation Approaches:**")
                for approach in details['implementation']:
                    st.markdown(f"• {approach}")
    
    def _render_model_comparison(self):
        """Render traditional vs Zero Trust model comparison"""
        st.subheader("⚖️ Traditional vs Zero Trust Security Models")
        
        comparison_data = [
            {
                "Aspect": "Trust Model",
                "Traditional": "Perimeter-based trust",
                "Zero Trust": "Identity-based verification",
                "Impact": "Eliminates implicit trust"
            },
            {
                "Aspect": "Network Access",
                "Traditional": "VPN with broad access",
                "Zero Trust": "Micro-segmented access",
                "Impact": "Reduces lateral movement"
            },
            {
                "Aspect": "Authentication",
                "Traditional": "Single sign-on at perimeter",
                "Zero Trust": "Continuous verification",
                "Impact": "Dynamic security posture"
            },
            {
                "Aspect": "Device Management",
                "Traditional": "Trust managed devices",
                "Zero Trust": "Verify all devices",
                "Impact": "Enhanced device security"
            },
            {
                "Aspect": "Data Protection",
                "Traditional": "Perimeter-focused",
                "Zero Trust": "Data-centric controls",
                "Impact": "Granular data protection"
            }
        ]
        
        df = pd.DataFrame(comparison_data)
        
        # Create interactive comparison
        st.dataframe(df, use_container_width=True)
        
        # Visualization
        fig = go.Figure()
        
        categories = df['Aspect'].tolist()
        
        fig.add_trace(go.Scatterpolar(
            r=[3, 2, 2, 2, 2],  # Traditional model scores
            theta=categories,
            fill='toself',
            name='Traditional Model',
            line_color=self.color_scheme['secondary']
        ))
        
        fig.add_trace(go.Scatterpolar(
            r=[5, 5, 5, 4, 5],  # Zero Trust scores
            theta=categories,
            fill='toself',
            name='Zero Trust Model', 
            line_color=self.color_scheme['primary']
        ))
        
        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 5]
                )),
            showlegend=True,
            title="Security Model Comparison",
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def _render_architecture_components(self):
        """Render Zero Trust architecture components"""
        st.subheader("🏗️ Zero Trust Architecture Components")
        
        # Architecture layers
        architecture_layers = [
            {
                "name": "Identity & Access Management",
                "description": "Centralized identity verification and access control",
                "components": ["Multi-Factor Authentication", "Single Sign-On", "Privileged Access Management"]
            },
            {
                "name": "Device Security",
                "description": "Comprehensive endpoint protection and compliance",
                "components": ["Device Registration", "Compliance Checking", "Endpoint Detection"]
            },
            {
                "name": "Network Security", 
                "description": "Micro-segmentation and encrypted communications",
                "components": ["Micro-segmentation", "Software-Defined Perimeter", "Network Access Control"]
            },
            {
                "name": "Application Security",
                "description": "Application-level controls and API security",
                "components": ["Application Controls", "API Security", "Web Application Firewall"]
            },
            {
                "name": "Data Security",
                "description": "Data classification, encryption, and loss prevention",
                "components": ["Data Classification", "Encryption", "Data Loss Prevention"]
            }
        ]
        
        # Create architecture diagram
        fig = create_basic_figure("Zero Trust Architecture", self.color_scheme, height=600)
        fig = add_architecture_diagram(fig, architecture_layers, self.color_scheme)
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Interactive component explorer
        selected_component = st.selectbox(
            "Explore architecture component:",
            [layer["name"] for layer in architecture_layers]
        )
        
        component_info = next(layer for layer in architecture_layers if layer["name"] == selected_component)
        
        create_info_card(
            f"🔍 {component_info['name']}",
            component_info['description'],
            card_type="info",
            color_scheme=self.color_scheme
        )
        
        st.markdown("**Key Technologies:**")
        for component in component_info['components']:
            st.markdown(f"• {component}")
    
    def _render_implementation_roadmap(self):
        """Render Zero Trust implementation roadmap"""
        st.subheader("🛣️ Zero Trust Implementation Roadmap")
        
        implementation_phases = [
            {
                "phase": "Phase 1: Assessment & Planning",
                "duration": "2-3 months",
                "activities": [
                    "Asset discovery and inventory",
                    "Risk assessment and threat modeling",
                    "Gap analysis against Zero Trust principles",
                    "Roadmap development and stakeholder buy-in"
                ],
                "deliverables": ["Asset inventory", "Risk assessment report", "Implementation roadmap"]
            },
            {
                "phase": "Phase 2: Identity & Access",
                "duration": "3-4 months", 
                "activities": [
                    "Deploy centralized identity management",
                    "Implement multi-factor authentication",
                    "Establish privileged access management",
                    "Develop access control policies"
                ],
                "deliverables": ["IAM system", "MFA deployment", "Access policies"]
            },
            {
                "phase": "Phase 3: Network & Device",
                "duration": "4-6 months",
                "activities": [
                    "Implement network micro-segmentation",
                    "Deploy endpoint detection and response",
                    "Establish device compliance checking",
                    "Configure monitoring and alerting"
                ],
                "deliverables": ["Micro-segmented network", "EDR deployment", "Device policies"]
            },
            {
                "phase": "Phase 4: Applications & Data",
                "duration": "3-5 months",
                "activities": [
                    "Implement application security controls",
                    "Deploy data classification system",
                    "Configure data loss prevention",
                    "Establish encryption standards"
                ],
                "deliverables": ["Application security", "Data protection", "DLP system"]
            }
        ]
        
        # Progress indicator
        current_phase = st.slider(
            "Select implementation phase to explore:",
            min_value=1,
            max_value=len(implementation_phases),
            value=1
        )
        
        create_progress_indicator(
            current_phase,
            len(implementation_phases),
            [phase["phase"] for phase in implementation_phases],
            self.color_scheme
        )
        
        # Display phase details
        phase_info = implementation_phases[current_phase - 1]
        
        create_info_card(
            phase_info["phase"],
            f"Duration: {phase_info['duration']}",
            card_type="primary",
            color_scheme=self.color_scheme
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**📋 Key Activities:**")
            for activity in phase_info["activities"]:
                st.markdown(f"• {activity}")
        
        with col2:
            st.markdown("**📦 Deliverables:**")
            for deliverable in phase_info["deliverables"]:
                st.markdown(f"• {deliverable}")
    
    def _render_maturity_assessment(self):
        """Render Zero Trust maturity assessment"""
        st.subheader("📊 Zero Trust Maturity Assessment")
        
        st.markdown("Assess your organization's Zero Trust maturity:")
        
        maturity_areas = {
            "Identity Management": [
                "Basic username/password authentication",
                "Multi-factor authentication deployed",
                "Risk-based authentication with continuous verification"
            ],
            "Device Security": [
                "Basic antivirus protection",
                "Endpoint detection and response deployed",
                "Continuous device compliance monitoring"
            ],
            "Network Security": [
                "Perimeter firewall protection",
                "Network segmentation implemented",
                "Micro-segmentation with zero trust network access"
            ],
            "Application Security": [
                "Basic application firewalls",
                "Application-specific access controls",
                "Runtime application protection and monitoring"
            ],
            "Data Protection": [
                "Basic data backup procedures",
                "Data classification and encryption",
                "Dynamic data protection with real-time monitoring"
            ]
        }
        
        maturity_scores = {}
        
        for area, levels in maturity_areas.items():
            st.markdown(f"**{area}:**")
            maturity_scores[area] = st.radio(
                f"Current maturity level for {area}:",
                levels,
                key=f"maturity_{area}",
                index=0
            )
        
        if st.button("📈 Calculate Maturity Score"):
            # Calculate overall maturity
            total_score = 0
            max_score = len(maturity_areas) * 3
            
            for area, selection in maturity_scores.items():
                levels = maturity_areas[area]
                score = levels.index(selection) + 1
                total_score += score
            
            maturity_percentage = (total_score / max_score) * 100
            
            # Display results
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Maturity Score", f"{total_score}/{max_score}")
            with col2:
                st.metric("Maturity Level", f"{maturity_percentage:.0f}%")
            with col3:
                if maturity_percentage >= 80:
                    maturity_level = "Advanced"
                    level_color = "success"
                elif maturity_percentage >= 60:
                    maturity_level = "Intermediate"
                    level_color = "warning"
                else:
                    maturity_level = "Basic"
                    level_color = "danger"
                
                st.metric("Classification", maturity_level)
            
            # Recommendations based on maturity
            st.markdown("### 🎯 Recommendations")
            
            if maturity_percentage < 40:
                st.error("**Focus on Foundation:** Start with basic identity management and network segmentation.")
            elif maturity_percentage < 70:
                st.warning("**Enhance Controls:** Implement advanced authentication and micro-segmentation.")
            else:
                st.success("**Optimize and Monitor:** Focus on continuous improvement and advanced analytics.")
            
            # Create maturity radar chart
            fig = go.Figure()
            
            areas = list(maturity_areas.keys())
            scores = [maturity_areas[area].index(maturity_scores[area]) + 1 for area in areas]
            
            fig.add_trace(go.Scatterpolar(
                r=scores,
                theta=areas,
                fill='toself',
                name='Current Maturity',
                line_color=self.color_scheme['primary']
            ))
            
            fig.add_trace(go.Scatterpolar(
                r=[3] * len(areas),
                theta=areas,
                fill='toself',
                name='Target Maturity',
                line_color=self.color_scheme['accent'],
                opacity=0.3
            ))
            
            fig.update_layout(
                polar=dict(
                    radialaxis=dict(
                        visible=True,
                        range=[0, 3]
                    )),
                showlegend=True,
                title="Zero Trust Maturity Assessment",
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)


def explain_zero_trust():
    """Main function to render Zero Trust component"""
    component = ZeroTrustComponent()
    
    # Summary points for the component
    summary_points = [
        "Zero Trust eliminates implicit trust and continuously validates every transaction",
        "Identity becomes the new security perimeter in Zero Trust architecture",
        "Micro-segmentation limits lateral movement and contains potential breaches",
        "Implementation requires a phased approach with proper planning and assessment",
        "Zero Trust is a journey, not a destination - continuous improvement is key"
    ]
    
    # Additional resources
    resources = [
        {
            "title": "NIST Zero Trust Architecture",
            "description": "Official NIST guidance on Zero Trust implementation",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-207/final"
        },
        {
            "title": "CISA Zero Trust Maturity Model",
            "description": "Cybersecurity and Infrastructure Security Agency guidance"
        }
    ]
    
    # Render the complete component
    component.render_full_component(summary_points, resources)
