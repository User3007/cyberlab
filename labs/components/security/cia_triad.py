"""
CIA Triad Security Component
Extracted from theory_concepts.py - Enhanced with shared utilities
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from typing import Dict, List, Any, Optional

# Import shared utilities
from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_takeaways, create_info_card
from ...shared.diagram_utils import create_basic_figure, add_security_triangle
from ...templates.component_template import ComponentTemplate


class CIATriadComponent(ComponentTemplate):
    """CIA Triad component using enhanced template"""
    
    def __init__(self):
        super().__init__(
            component_name=" CIA Triad",
            description="Confidentiality, Integrity, and Availability - The foundation of information security",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="20 minutes"
        )
        
        self.set_prerequisites([
            "Basic understanding of information security",
            "Familiarity with security concepts"
        ])
        
        self.set_learning_objectives([
            "Understand the three pillars of information security",
            "Identify real-world examples of CIA Triad violations",
            "Apply CIA Triad principles to security design",
            "Recognize the balance between security and usability"
        ])
        
        self.set_key_concepts([
            "Confidentiality", "Integrity", "Availability",
            "Security Controls", "Risk Assessment", "Security Design"
        ])
    
    def render_content(self):
        """Render the CIA Triad content"""
        
        # Interactive CIA Triangle
        self._render_cia_triangle()
        
        # Detailed explanations
        self._render_detailed_explanations()
        
        # Real-world examples
        self._render_examples()
        
        # Interactive assessment
        self._render_assessment()
        
        # Security controls mapping
        self._render_security_controls()
    
    def _render_cia_triangle(self):
        """Render interactive CIA Triangle"""
        st.subheader(" CIA Triad Visualization")
        
        # Create the security triangle
        fig = create_basic_figure("CIA Triad - Information Security Foundation", 
                                self.color_scheme, height=400)
        fig = add_security_triangle(fig, color_scheme=self.color_scheme)
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Interactive selection
        selected_pillar = st.selectbox(
            "Select a pillar to explore:",
            ["Confidentiality", "Integrity", "Availability"]
        )
        
        self._display_pillar_details(selected_pillar)
    
    def _display_pillar_details(self, pillar: str):
        """Display detailed information for selected pillar"""
        
        pillar_info = {
            "Confidentiality": {
                "definition": "Ensuring that information is accessible only to those authorized to have access",
                "threats": ["Data breaches", "Unauthorized access", "Eavesdropping", "Social engineering"],
                "controls": ["Encryption", "Access controls", "Authentication", "Data classification"],
                "examples": [
                    "Medical records protection",
                    "Financial information security", 
                    "Trade secrets protection",
                    "Personal data privacy"
                ],
                "icon": "",
                "color": self.color_scheme['primary']
            },
            "Integrity": {
                "definition": "Safeguarding the accuracy and completeness of information and processing methods",
                "threats": ["Data tampering", "Unauthorized modification", "Corruption", "Malware"],
                "controls": ["Digital signatures", "Checksums", "Version control", "Access logging"],
                "examples": [
                    "Financial transaction accuracy",
                    "Software code integrity",
                    "Database consistency",
                    "Document authenticity"
                ],
                "icon": "",
                "color": self.color_scheme['secondary']
            },
            "Availability": {
                "definition": "Ensuring that authorized users have access to information and resources when needed",
                "threats": ["DDoS attacks", "System failures", "Natural disasters", "Power outages"],
                "controls": ["Redundancy", "Load balancing", "Backup systems", "Disaster recovery"],
                "examples": [
                    "24/7 online banking",
                    "Emergency services systems",
                    "E-commerce platforms",
                    "Critical infrastructure"
                ],
                "icon": "",
                "color": self.color_scheme['accent']
            }
        }
        
        info = pillar_info[pillar]
        
        create_info_card(
            f"{info['icon']} {pillar}",
            info['definition'],
            card_type="primary",
            color_scheme=self.color_scheme
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"** Common Threats:**")
            for threat in info['threats']:
                st.markdown(f" {threat}")
        
        with col2:
            st.markdown(f"** Security Controls:**")
            for control in info['controls']:
                st.markdown(f" {control}")
        
        st.markdown(f"** Real-world Examples:**")
        for example in info['examples']:
            st.markdown(f" {example}")
    
    def _render_detailed_explanations(self):
        """Render detailed explanations with examples"""
        st.subheader(" Detailed Analysis")
        
        with st.expander(" CIA Triad in Practice", expanded=False):
            st.markdown("""
            ### Understanding the Balance
            
            The CIA Triad represents a fundamental trade-off in security design:
            
            **Security Triangle:**
            - **High Confidentiality** may reduce availability (complex authentication)
            - **High Availability** may compromise confidentiality (easier access)
            - **High Integrity** may impact availability (extensive validation)
            
            **Business Impact:**
            - Different organizations prioritize different aspects
            - Context determines the appropriate balance
            - Risk assessment guides implementation decisions
            """)
            
            # Create comparison table
            comparison_data = [
                {
                    "Scenario": "Banking System",
                    "Confidentiality": "Critical",
                    "Integrity": "Critical", 
                    "Availability": "High",
                    "Priority": "Confidentiality & Integrity"
                },
                {
                    "Scenario": "Emergency Services",
                    "Confidentiality": "Medium",
                    "Integrity": "High",
                    "Availability": "Critical",
                    "Priority": "Availability"
                },
                {
                    "Scenario": "Public Website",
                    "Confidentiality": "Low",
                    "Integrity": "Medium",
                    "Availability": "High", 
                    "Priority": "Availability"
                },
                {
                    "Scenario": "Research Database",
                    "Confidentiality": "Critical",
                    "Integrity": "Critical",
                    "Availability": "Medium",
                    "Priority": "Confidentiality & Integrity"
                }
            ]
            
            df = pd.DataFrame(comparison_data)
            st.dataframe(df, use_container_width=True)
    
    def _render_examples(self):
        """Render real-world examples and case studies"""
        st.subheader(" Real-world Case Studies")
        
        case_studies = {
            "Confidentiality Breach": {
                "title": "Data Breach Example",
                "description": "Unauthorized access to customer personal information",
                "impact": "Privacy violations, regulatory fines, reputation damage",
                "lessons": "Strong access controls, encryption, monitoring"
            },
            "Integrity Compromise": {
                "title": "Data Tampering Example", 
                "description": "Malicious modification of financial records",
                "impact": "Financial losses, audit failures, legal issues",
                "lessons": "Digital signatures, audit trails, validation"
            },
            "Availability Disruption": {
                "title": "System Outage Example",
                "description": "DDoS attack causing service interruption",
                "impact": "Business disruption, revenue loss, customer dissatisfaction", 
                "lessons": "Redundancy, DDoS protection, incident response"
            }
        }
        
        selected_case = st.selectbox(
            "Select a case study:",
            list(case_studies.keys())
        )
        
        case = case_studies[selected_case]
        
        create_info_card(
            case['title'],
            case['description'],
            card_type="warning",
            color_scheme=self.color_scheme
        )
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"** Impact:**\n{case['impact']}")
        with col2:
            st.markdown(f"** Lessons Learned:**\n{case['lessons']}")
    
    def _render_assessment(self):
        """Render interactive assessment"""
        st.subheader(" Knowledge Assessment")
        
        questions = [
            {
                "question": "Which CIA pillar is most concerned with preventing unauthorized access?",
                "options": ["Confidentiality", "Integrity", "Availability"],
                "correct": "Confidentiality",
                "explanation": "Confidentiality focuses on ensuring information is only accessible to authorized users."
            },
            {
                "question": "A DDoS attack primarily threatens which aspect of the CIA Triad?",
                "options": ["Confidentiality", "Integrity", "Availability"],
                "correct": "Availability",
                "explanation": "DDoS attacks make systems unavailable to legitimate users."
            },
            {
                "question": "Digital signatures primarily protect which CIA pillar?",
                "options": ["Confidentiality", "Integrity", "Availability"],
                "correct": "Integrity",
                "explanation": "Digital signatures ensure data hasn't been tampered with, protecting integrity."
            }
        ]
        
        score = 0
        for i, q in enumerate(questions):
            st.markdown(f"**Question {i+1}:** {q['question']}")
            answer = st.radio(f"Select answer for Q{i+1}:", q['options'], key=f"q{i}")
            
            if st.button(f"Check Answer {i+1}", key=f"check{i}"):
                if answer == q['correct']:
                    st.success(" Correct!")
                    score += 1
                else:
                    st.error(f" Incorrect. The correct answer is: {q['correct']}")
                
                st.info(f" **Explanation:** {q['explanation']}")
        
        if st.button("Show Final Score"):
            percentage = (score / len(questions)) * 100
            st.metric("Assessment Score", f"{score}/{len(questions)}", f"{percentage:.1f}%")
    
    def _render_security_controls(self):
        """Render security controls mapping"""
        st.subheader(" Security Controls Mapping")
        
        controls_data = [
            {"Control": "Encryption", "Confidentiality": "High", "Integrity": "Medium", "Availability": "Low"},
            {"Control": "Access Controls", "Confidentiality": "High", "Integrity": "Medium", "Availability": "Medium"},
            {"Control": "Backup Systems", "Confidentiality": "Low", "Integrity": "High", "Availability": "High"},
            {"Control": "Digital Signatures", "Confidentiality": "Low", "Integrity": "High", "Availability": "Low"},
            {"Control": "Load Balancing", "Confidentiality": "Low", "Integrity": "Low", "Availability": "High"},
            {"Control": "Audit Logging", "Confidentiality": "Medium", "Integrity": "High", "Availability": "Medium"},
        ]
        
        df = pd.DataFrame(controls_data)
        
        # Style the dataframe
        def highlight_high(val):
            if val == "High":
                return 'background-color: #d4edda; color: #155724'
            elif val == "Medium":
                return 'background-color: #fff3cd; color: #856404'
            else:
                return 'background-color: #f8d7da; color: #721c24'
        
        styled_df = df.style.applymap(highlight_high, subset=['Confidentiality', 'Integrity', 'Availability'])
        st.dataframe(styled_df, use_container_width=True)
        
        st.markdown("""
        **Legend:**
        -  **High**: Primary protection for this pillar
        -  **Medium**: Moderate protection for this pillar  
        -  **Low**: Minimal protection for this pillar
        """)


def explain_cia_triad():
    """Main function to render CIA Triad component"""
    component = CIATriadComponent()
    
    # Summary points for the component
    summary_points = [
        "CIA Triad forms the foundation of information security",
        "Balance between the three pillars depends on business context",
        "Different threats target different pillars of the CIA Triad",
        "Security controls should address all three aspects appropriately",
        "Regular assessment ensures CIA requirements are met"
    ]
    
    # Additional resources
    resources = [
        {
            "title": "NIST Cybersecurity Framework",
            "description": "Official framework incorporating CIA principles",
            "url": "https://www.nist.gov/cyberframework"
        },
        {
            "title": "ISO 27001 Standard",
            "description": "International standard for information security management"
        }
    ]
    
    # Render the complete component
    component.render_full_component(summary_points, resources)
