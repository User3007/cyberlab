"""
Risk Assessment Security Component
Extracted from theory_concepts.py - Enhanced with shared utilities
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
from typing import Dict, List, Any, Optional, Tuple

# Import shared utilities
from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_takeaways, create_info_card
from ...shared.diagram_utils import create_basic_figure, create_metrics_dashboard
from ...shared.data_utils import generate_demo_data, calculate_security_score
from ...templates.component_template import ComponentTemplate


class RiskAssessmentComponent(ComponentTemplate):
    """Risk Assessment component using enhanced template"""
    
    def __init__(self):
        super().__init__(
            component_name=" Risk Assessment",
            description="Systematic evaluation of security risks and vulnerabilities",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="35 minutes"
        )
        
        self.set_prerequisites([
            "Understanding of basic security concepts",
            "Familiarity with business operations",
            "Knowledge of threat landscape"
        ])
        
        self.set_learning_objectives([
            "Understand risk assessment methodologies",
            "Learn to identify and analyze security risks",
            "Calculate risk scores and prioritize remediation",
            "Develop risk treatment strategies",
            "Create risk assessment reports"
        ])
        
        self.set_key_concepts([
            "Risk = Threat  Vulnerability  Impact", "Risk Matrix", "Qualitative vs Quantitative",
            "Risk Appetite", "Risk Treatment", "Residual Risk"
        ])
    
    def render_content(self):
        """Render the Risk Assessment content"""
        
        # Risk fundamentals
        self._render_risk_fundamentals()
        
        # Risk assessment methodologies
        self._render_assessment_methodologies()
        
        # Interactive risk calculator
        self._render_risk_calculator()
        
        # Risk matrix visualization
        self._render_risk_matrix()
        
        # Risk treatment strategies
        self._render_treatment_strategies()
        
        # Assessment report generator
        self._render_report_generator()
    
    def _render_risk_fundamentals(self):
        """Render risk assessment fundamentals"""
        st.subheader(" Risk Assessment Fundamentals")
        
        # Risk equation visualization
        st.markdown("### Risk Equation")
        
        fig = go.Figure()
        
        # Create risk equation visualization
        equation_elements = [
            {"name": "Threat", "value": 0.3, "color": self.color_scheme['danger']},
            {"name": "", "value": 0.1, "color": "#666666"},
            {"name": "Vulnerability", "value": 0.3, "color": self.color_scheme['warning']},
            {"name": "", "value": 0.1, "color": "#666666"},
            {"name": "Impact", "value": 0.3, "color": self.color_scheme['primary']},
            {"name": "=", "value": 0.1, "color": "#666666"},
            {"name": "Risk", "value": 0.4, "color": self.color_scheme['accent']}
        ]
        
        x_pos = 0
        for element in equation_elements:
            if element["name"] not in ["", "="]:
                fig.add_shape(
                    type="rect",
                    x0=x_pos, y0=0.4,
                    x1=x_pos + element["value"], y1=0.6,
                    fillcolor=element["color"],
                    opacity=0.7,
                    line=dict(color=element["color"], width=2)
                )
            
            fig.add_annotation(
                x=x_pos + element["value"]/2,
                y=0.5,
                text=f"<b>{element['name']}</b>",
                showarrow=False,
                font=dict(size=14, color="white" if element["name"] not in ["", "="] else element["color"])
            )
            
            x_pos += element["value"]
        
        fig.update_layout(
            xaxis=dict(range=[0, 1.7], showgrid=False, showticklabels=False),
            yaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
            height=200,
            margin=dict(l=20, r=20, t=20, b=20),
            showlegend=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Risk components explanation
        risk_components = {
            "Threat": {
                "definition": "Potential danger that could exploit a vulnerability",
                "examples": ["Hackers", "Malware", "Natural disasters", "Insider threats"],
                "factors": ["Capability", "Motivation", "Opportunity"]
            },
            "Vulnerability": {
                "definition": "Weakness that can be exploited by a threat",
                "examples": ["Software bugs", "Weak passwords", "Unpatched systems", "Human error"],
                "factors": ["Ease of exploitation", "Detection difficulty", "Prevalence"]
            },
            "Impact": {
                "definition": "Potential consequences if a threat exploits a vulnerability",
                "examples": ["Financial loss", "Data breach", "Service disruption", "Reputation damage"],
                "factors": ["Confidentiality", "Integrity", "Availability"]
            }
        }
        
        selected_component = st.selectbox(
            "Explore risk component:",
            list(risk_components.keys())
        )
        
        component_info = risk_components[selected_component]
        
        create_info_card(
            f" {selected_component}",
            component_info['definition'],
            card_type="info",
            color_scheme=self.color_scheme
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("** Examples:**")
            for example in component_info['examples']:
                st.markdown(f" {example}")
        
        with col2:
            st.markdown("** Assessment Factors:**")
            for factor in component_info['factors']:
                st.markdown(f" {factor}")
    
    def _render_assessment_methodologies(self):
        """Render risk assessment methodologies"""
        st.subheader(" Risk Assessment Methodologies")
        
        methodologies = {
            "Qualitative Assessment": {
                "description": "Uses descriptive scales and expert judgment",
                "pros": ["Quick to perform", "Easy to understand", "Good for initial assessments"],
                "cons": ["Subjective results", "Difficult to compare", "Less precise"],
                "scales": ["Low/Medium/High", "1-5 Rating", "Color-coded matrix"],
                "use_cases": ["Initial risk screening", "Non-technical stakeholders", "Limited data availability"]
            },
            "Quantitative Assessment": {
                "description": "Uses numerical values and statistical analysis",
                "pros": ["Objective results", "Precise measurements", "Cost-benefit analysis"],
                "cons": ["Time consuming", "Requires data", "Complex calculations"],
                "scales": ["Annual Loss Expectancy (ALE)", "Return on Investment (ROI)", "Probability percentages"],
                "use_cases": ["Financial decisions", "Regulatory compliance", "Detailed analysis"]
            },
            "Semi-Quantitative Assessment": {
                "description": "Combines qualitative and quantitative approaches",
                "pros": ["Balanced approach", "More precise than qualitative", "Less complex than quantitative"],
                "cons": ["Still somewhat subjective", "Moderate complexity", "Requires some data"],
                "scales": ["Weighted scoring", "Numerical ranges", "Hybrid matrices"],
                "use_cases": ["Most business environments", "Regular assessments", "Mixed stakeholder groups"]
            }
        }
        
        # Create comparison table
        comparison_data = []
        for method, details in methodologies.items():
            comparison_data.append({
                "Methodology": method,
                "Complexity": "Low" if "Quick" in str(details['pros']) else "High" if "Complex" in str(details['cons']) else "Medium",
                "Precision": "High" if "Precise" in str(details['pros']) else "Low" if "Subjective" in str(details['cons']) else "Medium",
                "Time Required": "Low" if "Quick" in str(details['pros']) else "High" if "Time consuming" in str(details['cons']) else "Medium",
                "Data Requirements": "Low" if "Limited data" in str(details['use_cases']) else "High" if "Requires data" in str(details['cons']) else "Medium"
            })
        
        df = pd.DataFrame(comparison_data)
        st.dataframe(df, use_container_width=True)
        
        # Detailed methodology exploration
        selected_methodology = st.selectbox(
            "Explore methodology in detail:",
            list(methodologies.keys())
        )
        
        methodology_info = methodologies[selected_methodology]
        
        create_info_card(
            f" {selected_methodology}",
            methodology_info['description'],
            card_type="primary",
            color_scheme=self.color_scheme
        )
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("** Advantages:**")
            for pro in methodology_info['pros']:
                st.markdown(f" {pro}")
        
        with col2:
            st.markdown("** Limitations:**")
            for con in methodology_info['cons']:
                st.markdown(f" {con}")
        
        with col3:
            st.markdown("** Best Use Cases:**")
            for use_case in methodology_info['use_cases']:
                st.markdown(f" {use_case}")
    
    def _render_risk_calculator(self):
        """Render interactive risk calculator"""
        st.subheader(" Interactive Risk Calculator")
        
        st.markdown("Calculate risk scores using different methodologies:")
        
        # Methodology selection
        calc_method = st.radio(
            "Select calculation method:",
            ["Qualitative (Low/Medium/High)", "Semi-Quantitative (1-10 Scale)", "Quantitative (ALE)"]
        )
        
        if calc_method == "Qualitative (Low/Medium/High)":
            self._render_qualitative_calculator()
        elif calc_method == "Semi-Quantitative (1-10 Scale)":
            self._render_semiquantitative_calculator()
        else:
            self._render_quantitative_calculator()
    
    def _render_qualitative_calculator(self):
        """Render qualitative risk calculator"""
        st.markdown("#### Qualitative Risk Assessment")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            threat_level = st.selectbox("Threat Level:", ["Low", "Medium", "High"])
        with col2:
            vulnerability_level = st.selectbox("Vulnerability Level:", ["Low", "Medium", "High"])
        with col3:
            impact_level = st.selectbox("Impact Level:", ["Low", "Medium", "High"])
        
        if st.button("Calculate Qualitative Risk"):
            # Risk calculation logic
            risk_matrix = {
                ("Low", "Low", "Low"): "Very Low",
                ("Low", "Low", "Medium"): "Low",
                ("Low", "Low", "High"): "Low",
                ("Low", "Medium", "Low"): "Low",
                ("Low", "Medium", "Medium"): "Medium",
                ("Low", "Medium", "High"): "Medium",
                ("Low", "High", "Low"): "Low",
                ("Low", "High", "Medium"): "Medium",
                ("Low", "High", "High"): "High",
                ("Medium", "Low", "Low"): "Low",
                ("Medium", "Low", "Medium"): "Medium",
                ("Medium", "Low", "High"): "Medium",
                ("Medium", "Medium", "Low"): "Medium",
                ("Medium", "Medium", "Medium"): "Medium",
                ("Medium", "Medium", "High"): "High",
                ("Medium", "High", "Low"): "Medium",
                ("Medium", "High", "Medium"): "High",
                ("Medium", "High", "High"): "Very High",
                ("High", "Low", "Low"): "Medium",
                ("High", "Low", "Medium"): "Medium",
                ("High", "Low", "High"): "High",
                ("High", "Medium", "Low"): "Medium",
                ("High", "Medium", "Medium"): "High",
                ("High", "Medium", "High"): "Very High",
                ("High", "High", "Low"): "High",
                ("High", "High", "Medium"): "Very High",
                ("High", "High", "High"): "Critical"
            }
            
            risk_level = risk_matrix.get((threat_level, vulnerability_level, impact_level), "Medium")
            
            # Display result with color coding
            risk_colors = {
                "Very Low": "success",
                "Low": "success", 
                "Medium": "warning",
                "High": "danger",
                "Very High": "danger",
                "Critical": "danger"
            }
            
            if risk_level in ["Very Low", "Low"]:
                st.success(f" Risk Level: **{risk_level}**")
            elif risk_level == "Medium":
                st.warning(f" Risk Level: **{risk_level}**")
            else:
                st.error(f" Risk Level: **{risk_level}**")
            
            # Recommendations
            recommendations = {
                "Very Low": "Monitor periodically. No immediate action required.",
                "Low": "Monitor regularly. Consider preventive measures.",
                "Medium": "Implement controls within 6 months. Regular monitoring required.",
                "High": "Implement controls within 3 months. Frequent monitoring required.",
                "Very High": "Implement controls within 1 month. Continuous monitoring required.",
                "Critical": "Implement immediate controls. Daily monitoring required."
            }
            
            st.info(f" **Recommendation:** {recommendations[risk_level]}")
    
    def _render_semiquantitative_calculator(self):
        """Render semi-quantitative risk calculator"""
        st.markdown("#### Semi-Quantitative Risk Assessment")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            threat_score = st.slider("Threat Score (1-10):", 1, 10, 5)
        with col2:
            vulnerability_score = st.slider("Vulnerability Score (1-10):", 1, 10, 5)
        with col3:
            impact_score = st.slider("Impact Score (1-10):", 1, 10, 5)
        
        if st.button("Calculate Semi-Quantitative Risk"):
            # Calculate risk score (geometric mean)
            risk_score = (threat_score * vulnerability_score * impact_score) ** (1/3)
            risk_score_normalized = (risk_score / 10) * 100
            
            # Display results
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Risk Score", f"{risk_score:.2f}/10")
            with col2:
                st.metric("Risk Percentage", f"{risk_score_normalized:.1f}%")
            
            # Risk level classification
            if risk_score <= 3:
                risk_level = "Low Risk"
                st.success(f" {risk_level}")
            elif risk_score <= 6:
                risk_level = "Medium Risk"
                st.warning(f" {risk_level}")
            elif risk_score <= 8:
                risk_level = "High Risk"
                st.error(f" {risk_level}")
            else:
                risk_level = "Critical Risk"
                st.error(f" {risk_level}")
            
            # Create risk visualization
            fig = go.Figure(go.Indicator(
                mode = "gauge+number+delta",
                value = risk_score,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "Risk Score"},
                gauge = {
                    'axis': {'range': [None, 10]},
                    'bar': {'color': self.color_scheme['primary']},
                    'steps': [
                        {'range': [0, 3], 'color': "lightgreen"},
                        {'range': [3, 6], 'color': "yellow"},
                        {'range': [6, 8], 'color': "orange"},
                        {'range': [8, 10], 'color': "red"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 8
                    }
                }
            ))
            
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
    
    def _render_quantitative_calculator(self):
        """Render quantitative risk calculator (ALE)"""
        st.markdown("#### Quantitative Risk Assessment (Annual Loss Expectancy)")
        
        st.markdown("**ALE = SLE  ARO**")
        st.markdown("- **SLE** = Single Loss Expectancy (cost of one incident)")
        st.markdown("- **ARO** = Annual Rate of Occurrence (incidents per year)")
        
        col1, col2 = st.columns(2)
        
        with col1:
            sle = st.number_input("Single Loss Expectancy ($):", min_value=0, value=100000, step=1000)
        with col2:
            aro = st.number_input("Annual Rate of Occurrence:", min_value=0.0, value=0.1, step=0.01, format="%.2f")
        
        if st.button("Calculate ALE"):
            ale = sle * aro
            
            st.metric("Annual Loss Expectancy (ALE)", f"${ale:,.2f}")
            
            # Risk tolerance assessment
            if ale < 10000:
                st.success(" **Low Financial Risk** - Acceptable risk level")
            elif ale < 100000:
                st.warning(" **Medium Financial Risk** - Consider risk mitigation")
            elif ale < 500000:
                st.error(" **High Financial Risk** - Risk mitigation recommended")
            else:
                st.error(" **Critical Financial Risk** - Immediate action required")
            
            # Cost-benefit analysis helper
            st.markdown("#### Cost-Benefit Analysis")
            
            control_cost = st.number_input("Annual cost of security control ($):", min_value=0, value=50000, step=1000)
            control_effectiveness = st.slider("Control effectiveness (%):", 0, 100, 80)
            
            risk_reduction = ale * (control_effectiveness / 100)
            net_benefit = risk_reduction - control_cost
            roi = (net_benefit / control_cost) * 100 if control_cost > 0 else 0
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Risk Reduction", f"${risk_reduction:,.2f}")
            with col2:
                st.metric("Net Benefit", f"${net_benefit:,.2f}")
            with col3:
                st.metric("ROI", f"{roi:.1f}%")
            
            if net_benefit > 0:
                st.success(" **Control is cost-effective** - Implement recommended")
            else:
                st.warning(" **Control may not be cost-effective** - Consider alternatives")
    
    def _render_risk_matrix(self):
        """Render risk matrix visualization"""
        st.subheader(" Risk Matrix Visualization")
        
        # Generate sample risk data
        risks_data = [
            {"Risk": "Data Breach", "Probability": 3, "Impact": 5, "Category": "Data Security"},
            {"Risk": "DDoS Attack", "Probability": 4, "Impact": 3, "Category": "Network Security"},
            {"Risk": "Insider Threat", "Probability": 2, "Impact": 4, "Category": "Personnel Security"},
            {"Risk": "Malware Infection", "Probability": 4, "Impact": 3, "Category": "Endpoint Security"},
            {"Risk": "Physical Breach", "Probability": 1, "Impact": 3, "Category": "Physical Security"},
            {"Risk": "Supply Chain Attack", "Probability": 2, "Impact": 5, "Category": "Third Party"},
            {"Risk": "Social Engineering", "Probability": 3, "Impact": 3, "Category": "Human Factor"},
            {"Risk": "System Failure", "Probability": 2, "Impact": 4, "Category": "Infrastructure"}
        ]
        
        # Create interactive risk matrix
        fig = px.scatter(
            risks_data,
            x="Probability",
            y="Impact", 
            color="Category",
            size=[15] * len(risks_data),
            hover_name="Risk",
            hover_data={"Probability": True, "Impact": True, "Category": True},
            title="Risk Matrix - Probability vs Impact"
        )
        
        # Add risk zones
        fig.add_shape(type="rect", x0=0, y0=0, x1=2, y1=2, fillcolor="green", opacity=0.2, line_width=0)
        fig.add_shape(type="rect", x0=2, y0=0, x1=5, y1=2, fillcolor="yellow", opacity=0.2, line_width=0)
        fig.add_shape(type="rect", x0=0, y0=2, x1=2, y1=5, fillcolor="yellow", opacity=0.2, line_width=0)
        fig.add_shape(type="rect", x0=2, y0=2, x1=5, y1=5, fillcolor="red", opacity=0.2, line_width=0)
        
        # Add zone labels
        fig.add_annotation(x=1, y=1, text="Low Risk", showarrow=False, font=dict(size=12, color="green"))
        fig.add_annotation(x=3.5, y=1, text="Medium Risk", showarrow=False, font=dict(size=12, color="orange"))
        fig.add_annotation(x=1, y=3.5, text="Medium Risk", showarrow=False, font=dict(size=12, color="orange"))
        fig.add_annotation(x=3.5, y=3.5, text="High Risk", showarrow=False, font=dict(size=12, color="red"))
        
        fig.update_layout(
            xaxis=dict(range=[0, 5], title="Probability (1=Very Low, 5=Very High)"),
            yaxis=dict(range=[0, 5], title="Impact (1=Very Low, 5=Very High)"),
            height=500
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Risk prioritization
        st.markdown("#### Risk Prioritization")
        
        # Calculate risk scores
        for risk in risks_data:
            risk['Risk_Score'] = risk['Probability'] * risk['Impact']
        
        # Sort by risk score
        sorted_risks = sorted(risks_data, key=lambda x: x['Risk_Score'], reverse=True)
        
        # Display prioritized risks
        priority_df = pd.DataFrame(sorted_risks)[['Risk', 'Category', 'Probability', 'Impact', 'Risk_Score']]
        priority_df['Priority'] = ['High' if score >= 15 else 'Medium' if score >= 9 else 'Low' for score in priority_df['Risk_Score']]
        
        st.dataframe(priority_df, use_container_width=True)
    
    def _render_treatment_strategies(self):
        """Render risk treatment strategies"""
        st.subheader(" Risk Treatment Strategies")
        
        treatment_options = {
            "Risk Mitigation": {
                "description": "Implement controls to reduce the likelihood or impact of risks",
                "examples": ["Install firewalls", "Implement access controls", "Deploy monitoring systems"],
                "when_to_use": "When risk reduction is cost-effective",
                "cost": "Medium to High",
                "effectiveness": "High"
            },
            "Risk Avoidance": {
                "description": "Eliminate the risk by removing the cause or changing the approach",
                "examples": ["Discontinue risky services", "Change business processes", "Avoid high-risk technologies"],
                "when_to_use": "When risks are unacceptable and cannot be mitigated",
                "cost": "Variable",
                "effectiveness": "Very High"
            },
            "Risk Transfer": {
                "description": "Shift the risk to another party through insurance or contracts",
                "examples": ["Cyber insurance", "Outsource to third parties", "Service level agreements"],
                "when_to_use": "When risks are too expensive to mitigate internally",
                "cost": "Low to Medium",
                "effectiveness": "Medium"
            },
            "Risk Acceptance": {
                "description": "Accept the risk and its consequences without additional controls",
                "examples": ["Document acceptance", "Establish monitoring", "Prepare contingency plans"],
                "when_to_use": "When mitigation costs exceed potential losses",
                "cost": "Very Low",
                "effectiveness": "Low"
            }
        }
        
        # Create treatment comparison
        treatment_data = []
        for strategy, details in treatment_options.items():
            treatment_data.append({
                "Strategy": strategy,
                "Cost": details["cost"],
                "Effectiveness": details["effectiveness"],
                "When to Use": details["when_to_use"]
            })
        
        df = pd.DataFrame(treatment_data)
        st.dataframe(df, use_container_width=True)
        
        # Interactive treatment selector
        selected_treatment = st.selectbox(
            "Explore treatment strategy:",
            list(treatment_options.keys())
        )
        
        treatment_info = treatment_options[selected_treatment]
        
        create_info_card(
            f" {selected_treatment}",
            treatment_info['description'],
            card_type="info",
            color_scheme=self.color_scheme
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("** Examples:**")
            for example in treatment_info['examples']:
                st.markdown(f" {example}")
        
        with col2:
            st.markdown("** Characteristics:**")
            st.markdown(f" **Cost:** {treatment_info['cost']}")
            st.markdown(f" **Effectiveness:** {treatment_info['effectiveness']}")
            st.markdown(f" **Best Used:** {treatment_info['when_to_use']}")
    
    def _render_report_generator(self):
        """Render risk assessment report generator"""
        st.subheader(" Risk Assessment Report Generator")
        
        st.markdown("Generate a comprehensive risk assessment report:")
        
        # Report parameters
        col1, col2 = st.columns(2)
        
        with col1:
            organization = st.text_input("Organization Name:", value="Sample Organization")
            assessment_scope = st.text_area("Assessment Scope:", value="IT Infrastructure and Data Security")
        
        with col2:
            assessor = st.text_input("Lead Assessor:", value="Security Team")
            assessment_date = st.date_input("Assessment Date:")
        
        # Risk summary metrics
        st.markdown("#### Risk Summary Metrics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_risks = st.number_input("Total Risks Identified:", min_value=0, value=25)
        with col2:
            high_risks = st.number_input("High Risk Items:", min_value=0, value=5)
        with col3:
            medium_risks = st.number_input("Medium Risk Items:", min_value=0, value=12)
        with col4:
            low_risks = st.number_input("Low Risk Items:", min_value=0, value=8)
        
        if st.button(" Generate Report"):
            # Create report content
            st.markdown("---")
            st.markdown("## Risk Assessment Report")
            
            # Executive summary
            st.markdown("### Executive Summary")
            
            risk_distribution = {
                "Risk Level": ["High", "Medium", "Low"],
                "Count": [high_risks, medium_risks, low_risks],
                "Percentage": [
                    f"{(high_risks/total_risks*100):.1f}%" if total_risks > 0 else "0%",
                    f"{(medium_risks/total_risks*100):.1f}%" if total_risks > 0 else "0%",
                    f"{(low_risks/total_risks*100):.1f}%" if total_risks > 0 else "0%"
                ]
            }
            
            df = pd.DataFrame(risk_distribution)
            st.dataframe(df, use_container_width=True)
            
            # Risk distribution chart
            fig = px.pie(
                values=[high_risks, medium_risks, low_risks],
                names=["High", "Medium", "Low"],
                title="Risk Distribution",
                color_discrete_map={
                    "High": "#ff4444",
                    "Medium": "#ffaa00", 
                    "Low": "#44ff44"
                }
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Key findings
            st.markdown("### Key Findings")
            
            if high_risks > 0:
                st.error(f" **{high_risks} High Risk items** require immediate attention and should be addressed within 30 days.")
            
            if medium_risks > 0:
                st.warning(f" **{medium_risks} Medium Risk items** should be addressed within 90 days through appropriate controls.")
            
            if low_risks > 0:
                st.success(f" **{low_risks} Low Risk items** can be monitored and addressed as resources permit.")
            
            # Recommendations
            st.markdown("### Recommendations")
            
            recommendations = [
                "Implement immediate controls for all high-risk items",
                "Develop a risk treatment plan with timelines and responsibilities",
                "Establish regular risk monitoring and review processes",
                "Provide security awareness training to address human factors",
                "Consider cyber insurance for risks that cannot be fully mitigated"
            ]
            
            for i, recommendation in enumerate(recommendations, 1):
                st.markdown(f"{i}. {recommendation}")
            
            # Report metadata
            st.markdown("### Report Information")
            st.markdown(f"- **Organization:** {organization}")
            st.markdown(f"- **Assessment Scope:** {assessment_scope}")
            st.markdown(f"- **Lead Assessor:** {assessor}")
            st.markdown(f"- **Assessment Date:** {assessment_date}")
            st.markdown(f"- **Report Generated:** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")


def explain_risk_assessment():
    """Main function to render Risk Assessment component"""
    component = RiskAssessmentComponent()
    
    # Summary points for the component
    summary_points = [
        "Risk assessment systematically identifies and evaluates security risks",
        "Risk = Threat  Vulnerability  Impact provides the foundation for calculations",
        "Different methodologies (qualitative, quantitative, semi-quantitative) serve different needs",
        "Risk treatment strategies include mitigation, avoidance, transfer, and acceptance",
        "Regular risk assessments are essential for maintaining effective security posture"
    ]
    
    # Additional resources
    resources = [
        {
            "title": "NIST Risk Management Framework",
            "description": "Comprehensive guide to organizational risk management",
            "url": "https://csrc.nist.gov/projects/risk-management/about-rmf"
        },
        {
            "title": "ISO 27005 Risk Management",
            "description": "International standard for information security risk management"
        }
    ]
    
    # Render the complete component
    component.render_full_component(summary_points, resources)
