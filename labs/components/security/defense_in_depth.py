"""
Defense in Depth Security Component
Extracted from theory_concepts.py - Enhanced with shared utilities
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from typing import Dict, List, Any, Optional

# Import shared utilities
from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_takeaways, create_info_card
from ...shared.diagram_utils import create_basic_figure, add_architecture_diagram
from ...templates.component_template import ComponentTemplate


class DefenseInDepthComponent(ComponentTemplate):
    """Defense in Depth component using enhanced template"""
    
    def __init__(self):
        super().__init__(
            component_name="🛡️ Defense in Depth",
            description="Layered security strategy using multiple defensive measures",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="25 minutes"
        )
        
        self.set_prerequisites([
            "Understanding of basic security concepts",
            "Familiarity with network architecture",
            "Knowledge of security controls"
        ])
        
        self.set_learning_objectives([
            "Understand the layered security approach",
            "Identify different types of security controls",
            "Design defense in depth strategies",
            "Evaluate the effectiveness of layered defenses"
        ])
        
        self.set_key_concepts([
            "Layered Security", "Security Controls", "Preventive Controls",
            "Detective Controls", "Corrective Controls", "Compensating Controls"
        ])
    
    def render_content(self):
        """Render the Defense in Depth content"""
        
        # Layered architecture diagram
        self._render_defense_layers()
        
        # Control types explanation
        self._render_control_types()
        
        # Interactive layer builder
        self._render_layer_builder()
        
        # Real-world implementation
        self._render_implementation_examples()
        
        # Assessment and planning
        self._render_assessment_tool()
    
    def _render_defense_layers(self):
        """Render the defense in depth layers visualization"""
        st.subheader("🏰 Defense Layers Architecture")
        
        # Create layered architecture diagram
        layers = [
            {
                "name": "Physical Security",
                "description": "Guards, locks, cameras, access controls",
                "components": ["Security Guards", "Biometric Scanners", "CCTV", "Secure Facilities"]
            },
            {
                "name": "Perimeter Security", 
                "description": "Firewalls, IDS/IPS, network segmentation",
                "components": ["Firewalls", "IDS/IPS", "DMZ", "VPN Gateways"]
            },
            {
                "name": "Network Security",
                "description": "Internal network monitoring and controls",
                "components": ["Network Monitoring", "VLAN Segmentation", "NAC", "Wireless Security"]
            },
            {
                "name": "Host Security",
                "description": "Endpoint protection and hardening",
                "components": ["Antivirus", "Host Firewalls", "OS Hardening", "Patch Management"]
            },
            {
                "name": "Application Security",
                "description": "Secure coding and application controls",
                "components": ["Input Validation", "Authentication", "Session Management", "Encryption"]
            },
            {
                "name": "Data Security",
                "description": "Data classification and protection",
                "components": ["Encryption", "DLP", "Backup", "Access Controls"]
            }
        ]
        
        fig = create_basic_figure("Defense in Depth Layers", self.color_scheme, height=500)
        fig = add_architecture_diagram(fig, layers, self.color_scheme)
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Interactive layer exploration
        selected_layer = st.selectbox(
            "Explore a security layer:",
            [layer["name"] for layer in layers]
        )
        
        layer_info = next(layer for layer in layers if layer["name"] == selected_layer)
        
        create_info_card(
            f"🔍 {layer_info['name']}",
            layer_info['description'],
            card_type="info",
            color_scheme=self.color_scheme
        )
        
        st.markdown("**Key Components:**")
        for component in layer_info['components']:
            st.markdown(f"• {component}")
    
    def _render_control_types(self):
        """Render security control types explanation"""
        st.subheader("🎛️ Types of Security Controls")
        
        control_types = {
            "Preventive Controls": {
                "purpose": "Prevent security incidents from occurring",
                "examples": ["Firewalls", "Access controls", "Encryption", "Security awareness training"],
                "icon": "🚫",
                "color": self.color_scheme['primary']
            },
            "Detective Controls": {
                "purpose": "Detect and alert on security incidents",
                "examples": ["IDS/IPS", "SIEM systems", "Log monitoring", "Vulnerability scanners"],
                "icon": "🔍",
                "color": self.color_scheme['secondary']
            },
            "Corrective Controls": {
                "purpose": "Respond to and recover from security incidents",
                "examples": ["Incident response", "Backup restoration", "Patch management", "Quarantine"],
                "icon": "🔧",
                "color": self.color_scheme['accent']
            },
            "Compensating Controls": {
                "purpose": "Alternative controls when primary controls aren't feasible",
                "examples": ["Manual procedures", "Additional monitoring", "Alternative technologies"],
                "icon": "⚖️",
                "color": self.color_scheme['info']
            }
        }
        
        # Create tabs for each control type
        tabs = st.tabs(list(control_types.keys()))
        
        for tab, (control_name, control_info) in zip(tabs, control_types.items()):
            with tab:
                create_info_card(
                    f"{control_info['icon']} {control_name}",
                    control_info['purpose'],
                    card_type="primary",
                    color_scheme=self.color_scheme
                )
                
                st.markdown("**Examples:**")
                for example in control_info['examples']:
                    st.markdown(f"• {example}")
    
    def _render_layer_builder(self):
        """Render interactive defense layer builder"""
        st.subheader("🏗️ Interactive Defense Layer Builder")
        
        st.markdown("Build your own defense in depth strategy:")
        
        # Organization type selection
        org_type = st.selectbox(
            "Select organization type:",
            ["Small Business", "Enterprise", "Government", "Healthcare", "Financial Services"]
        )
        
        # Risk level
        risk_level = st.select_slider(
            "Risk tolerance level:",
            options=["Low", "Medium", "High", "Critical"],
            value="Medium"
        )
        
        # Budget consideration
        budget = st.select_slider(
            "Security budget level:",
            options=["Limited", "Moderate", "Substantial", "Unlimited"],
            value="Moderate"
        )
        
        if st.button("🚀 Generate Defense Strategy"):
            strategy = self._generate_defense_strategy(org_type, risk_level, budget)
            
            st.markdown("### 📋 Recommended Defense Strategy")
            
            for i, layer in enumerate(strategy['layers'], 1):
                with st.expander(f"Layer {i}: {layer['name']}", expanded=True):
                    st.markdown(f"**Priority:** {layer['priority']}")
                    st.markdown(f"**Cost:** {layer['cost']}")
                    st.markdown(f"**Implementation Time:** {layer['timeline']}")
                    
                    st.markdown("**Recommended Controls:**")
                    for control in layer['controls']:
                        st.markdown(f"• {control}")
            
            # Display strategy summary
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Layers", len(strategy['layers']))
            with col2:
                st.metric("Estimated Cost", strategy['total_cost'])
            with col3:
                st.metric("Implementation Time", strategy['timeline'])
    
    def _generate_defense_strategy(self, org_type: str, risk_level: str, budget: str) -> Dict[str, Any]:
        """Generate defense strategy based on parameters"""
        
        # Base strategy templates
        strategies = {
            "Small Business": {
                "layers": [
                    {
                        "name": "Basic Perimeter Security",
                        "priority": "High",
                        "cost": "$5K-10K",
                        "timeline": "2-4 weeks",
                        "controls": ["Firewall", "Antivirus", "Basic monitoring", "Employee training"]
                    },
                    {
                        "name": "Endpoint Protection",
                        "priority": "High", 
                        "cost": "$2K-5K",
                        "timeline": "1-2 weeks",
                        "controls": ["Endpoint security", "Patch management", "Backup solution"]
                    }
                ],
                "total_cost": "$7K-15K",
                "timeline": "4-6 weeks"
            },
            "Enterprise": {
                "layers": [
                    {
                        "name": "Advanced Perimeter Security",
                        "priority": "Critical",
                        "cost": "$50K-100K",
                        "timeline": "8-12 weeks",
                        "controls": ["Next-gen firewalls", "IDS/IPS", "DLP", "Network segmentation"]
                    },
                    {
                        "name": "Identity & Access Management",
                        "priority": "Critical",
                        "cost": "$30K-75K", 
                        "timeline": "6-10 weeks",
                        "controls": ["SSO", "MFA", "Privileged access management", "Identity governance"]
                    },
                    {
                        "name": "Security Operations Center",
                        "priority": "High",
                        "cost": "$100K-200K",
                        "timeline": "12-16 weeks", 
                        "controls": ["SIEM", "SOC analysts", "Incident response", "Threat intelligence"]
                    }
                ],
                "total_cost": "$180K-375K",
                "timeline": "16-20 weeks"
            }
        }
        
        base_strategy = strategies.get(org_type, strategies["Small Business"])
        
        # Adjust based on risk level and budget
        if risk_level == "Critical":
            base_strategy['total_cost'] = base_strategy['total_cost'].replace('K', 'K+')
        
        return base_strategy
    
    def _render_implementation_examples(self):
        """Render real-world implementation examples"""
        st.subheader("🌍 Real-world Implementation Examples")
        
        examples = {
            "Banking Institution": {
                "scenario": "Large bank implementing comprehensive defense in depth",
                "layers": [
                    "Physical security with biometric access",
                    "Network segmentation with multiple DMZs", 
                    "Application-level security with WAF",
                    "Database encryption and access logging",
                    "24/7 SOC with threat hunting",
                    "Regular penetration testing"
                ],
                "challenges": ["Regulatory compliance", "Legacy system integration", "High availability requirements"],
                "outcomes": ["99.9% uptime", "Zero data breaches", "Regulatory compliance achieved"]
            },
            "Healthcare Network": {
                "scenario": "Hospital network protecting patient data (HIPAA compliance)",
                "layers": [
                    "Physical access controls to server rooms",
                    "Network segmentation isolating medical devices",
                    "Endpoint protection on all workstations",
                    "Encrypted data transmission and storage",
                    "Role-based access controls for staff",
                    "Audit logging and monitoring"
                ],
                "challenges": ["Legacy medical devices", "Staff training", "Emergency access procedures"],
                "outcomes": ["HIPAA compliance maintained", "Improved incident response", "Enhanced patient trust"]
            },
            "E-commerce Platform": {
                "scenario": "Online retailer protecting customer and payment data",
                "layers": [
                    "CDN and DDoS protection",
                    "Web application firewall (WAF)",
                    "Secure payment processing (PCI DSS)",
                    "Customer data encryption",
                    "Fraud detection systems",
                    "Regular security assessments"
                ],
                "challenges": ["High traffic volumes", "PCI DSS compliance", "Third-party integrations"],
                "outcomes": ["PCI DSS certification", "Reduced fraud losses", "Customer confidence improved"]
            }
        }
        
        selected_example = st.selectbox(
            "Select an implementation example:",
            list(examples.keys())
        )
        
        example = examples[selected_example]
        
        create_info_card(
            f"📊 {selected_example}",
            example['scenario'],
            card_type="info",
            color_scheme=self.color_scheme
        )
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**🛡️ Defense Layers:**")
            for layer in example['layers']:
                st.markdown(f"• {layer}")
        
        with col2:
            st.markdown("**⚠️ Challenges:**")
            for challenge in example['challenges']:
                st.markdown(f"• {challenge}")
        
        with col3:
            st.markdown("**✅ Outcomes:**")
            for outcome in example['outcomes']:
                st.markdown(f"• {outcome}")
    
    def _render_assessment_tool(self):
        """Render defense assessment tool"""
        st.subheader("📊 Defense in Depth Assessment")
        
        st.markdown("Evaluate your current defense posture:")
        
        assessment_areas = [
            "Physical Security Controls",
            "Network Perimeter Security", 
            "Endpoint Protection",
            "Identity & Access Management",
            "Data Protection",
            "Monitoring & Detection",
            "Incident Response",
            "Security Awareness Training"
        ]
        
        scores = {}
        for area in assessment_areas:
            scores[area] = st.slider(
                f"{area} (1=Poor, 5=Excellent):",
                min_value=1,
                max_value=5,
                value=3,
                key=f"assess_{area}"
            )
        
        if st.button("📈 Calculate Defense Score"):
            total_score = sum(scores.values())
            max_score = len(assessment_areas) * 5
            percentage = (total_score / max_score) * 100
            
            st.metric("Overall Defense Score", f"{total_score}/{max_score}", f"{percentage:.1f}%")
            
            # Provide recommendations based on score
            if percentage >= 90:
                st.success("🟢 Excellent defense posture! Continue monitoring and improvement.")
            elif percentage >= 70:
                st.info("🟡 Good defense posture with room for improvement.")
            elif percentage >= 50:
                st.warning("🟠 Moderate defense posture. Consider strengthening weak areas.")
            else:
                st.error("🔴 Poor defense posture. Immediate action required!")
            
            # Identify weakest areas
            weak_areas = [area for area, score in scores.items() if score <= 2]
            if weak_areas:
                st.markdown("**🎯 Priority Areas for Improvement:**")
                for area in weak_areas:
                    st.markdown(f"• {area}")


def explain_defense_in_depth():
    """Main function to render Defense in Depth component"""
    component = DefenseInDepthComponent()
    
    # Summary points for the component
    summary_points = [
        "Defense in depth uses multiple layers of security controls",
        "Different control types (preventive, detective, corrective) work together",
        "No single security control is sufficient for complete protection",
        "Layered defenses provide redundancy and reduce single points of failure",
        "Implementation should be tailored to organization type and risk profile"
    ]
    
    # Additional resources
    resources = [
        {
            "title": "NIST Special Publication 800-53",
            "description": "Security controls catalog for federal information systems",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "title": "SANS Defense in Depth",
            "description": "Comprehensive guide to layered security strategies"
        }
    ]
    
    # Render the complete component
    component.render_full_component(summary_points, resources)
