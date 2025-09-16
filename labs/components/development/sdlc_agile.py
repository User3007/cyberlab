"""
SDLC & Agile Development Component
Extracted from software_development.py - Enhanced with shared utilities
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Any, Optional

# Import shared utilities
from ...shared.color_schemes import SOFTWARE_DEV_COLORS
from ...shared.ui_components import create_banner, create_takeaways, create_info_card
from ...shared.diagram_utils import create_basic_figure, add_process_flow
from ...templates.component_template import ComponentTemplate


class SDLCAgileComponent(ComponentTemplate):
    """SDLC & Agile component using enhanced template"""
    
    def __init__(self):
        super().__init__(
            component_name="🏗️ SDLC & Agile Methodologies",
            description="Software Development Life Cycle and Agile development approaches",
            color_scheme=SOFTWARE_DEV_COLORS,
            estimated_time="30 minutes"
        )
        
        self.set_prerequisites([
            "Basic understanding of software development",
            "Familiarity with project management concepts"
        ])
        
        self.set_learning_objectives([
            "Understand SDLC phases and methodologies",
            "Learn Agile principles and practices",
            "Compare different development approaches",
            "Apply security considerations in development"
        ])
        
        self.set_key_concepts([
            "SDLC Phases", "Waterfall Model", "Agile Principles", 
            "Scrum Framework", "DevOps Integration", "Security by Design"
        ])
    
    def render_content(self):
        """Render the SDLC & Agile content"""
        
        # SDLC overview
        self._render_sdlc_overview()
        
        # Methodology comparison
        self._render_methodology_comparison()
        
        # Agile deep dive
        self._render_agile_principles()
        
        # Security integration
        self._render_security_integration()
        
        # Interactive project planner
        self._render_project_planner()
    
    def _render_sdlc_overview(self):
        """Render SDLC overview"""
        st.subheader("🔄 Software Development Life Cycle (SDLC)")
        
        # SDLC phases
        sdlc_phases = [
            {
                "name": "Planning",
                "description": "Define project scope, requirements, and resources",
                "activities": ["Requirement gathering", "Feasibility analysis", "Resource planning", "Risk assessment"],
                "deliverables": ["Project plan", "Requirements document", "Resource allocation"]
            },
            {
                "name": "Analysis",
                "description": "Analyze requirements and design system architecture",
                "activities": ["System analysis", "Architecture design", "Technology selection", "Security planning"],
                "deliverables": ["System design", "Technical specifications", "Security requirements"]
            },
            {
                "name": "Design",
                "description": "Create detailed design and user interface mockups",
                "activities": ["UI/UX design", "Database design", "API design", "Security controls design"],
                "deliverables": ["Design documents", "Prototypes", "Security architecture"]
            },
            {
                "name": "Implementation",
                "description": "Write code and develop the software system",
                "activities": ["Coding", "Unit testing", "Code review", "Security testing"],
                "deliverables": ["Source code", "Unit tests", "Security tests"]
            },
            {
                "name": "Testing",
                "description": "Comprehensive testing and quality assurance",
                "activities": ["Integration testing", "System testing", "Performance testing", "Security testing"],
                "deliverables": ["Test reports", "Bug fixes", "Security assessment"]
            },
            {
                "name": "Deployment",
                "description": "Deploy the system to production environment",
                "activities": ["Environment setup", "Deployment", "User training", "Security hardening"],
                "deliverables": ["Production system", "Deployment guide", "Security configuration"]
            },
            {
                "name": "Maintenance",
                "description": "Ongoing support, updates, and improvements",
                "activities": ["Bug fixes", "Updates", "Performance monitoring", "Security patches"],
                "deliverables": ["Maintenance plan", "Updates", "Security patches"]
            }
        ]
        
        # Create SDLC process flow
        fig = create_basic_figure("SDLC Process Flow", self.color_scheme, height=300)
        fig = add_process_flow(fig, sdlc_phases, self.color_scheme)
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Interactive phase explorer
        selected_phase = st.selectbox(
            "Explore SDLC phase:",
            [phase["name"] for phase in sdlc_phases]
        )
        
        phase_info = next(phase for phase in sdlc_phases if phase["name"] == selected_phase)
        
        create_info_card(
            f"📋 {phase_info['name']} Phase",
            phase_info['description'],
            card_type="primary",
            color_scheme=self.color_scheme
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**📋 Key Activities:**")
            for activity in phase_info['activities']:
                st.markdown(f"• {activity}")
        
        with col2:
            st.markdown("**📦 Deliverables:**")
            for deliverable in phase_info['deliverables']:
                st.markdown(f"• {deliverable}")
    
    def _render_methodology_comparison(self):
        """Render development methodology comparison"""
        st.subheader("⚖️ Development Methodology Comparison")
        
        methodologies = {
            "Waterfall": {
                "description": "Sequential, linear approach with distinct phases",
                "advantages": ["Clear structure", "Well-documented", "Easy to manage", "Predictable timeline"],
                "disadvantages": ["Inflexible", "Late testing", "No early feedback", "Risk of obsolescence"],
                "best_for": ["Well-defined requirements", "Stable technology", "Regulatory environments"],
                "timeline": "6-24 months",
                "team_size": "Large teams"
            },
            "Agile": {
                "description": "Iterative, flexible approach with continuous feedback",
                "advantages": ["Flexible", "Early feedback", "Continuous improvement", "Customer collaboration"],
                "disadvantages": ["Less predictable", "Requires experience", "Can lack documentation", "Scope creep"],
                "best_for": ["Evolving requirements", "Innovative projects", "Customer-focused products"],
                "timeline": "2-6 months per release",
                "team_size": "Small to medium teams"
            },
            "DevOps": {
                "description": "Integration of development and operations with automation",
                "advantages": ["Fast delivery", "High quality", "Automated processes", "Continuous monitoring"],
                "disadvantages": ["Complex setup", "Cultural change needed", "Tool complexity", "Security challenges"],
                "best_for": ["Continuous delivery", "Cloud applications", "Microservices"],
                "timeline": "Continuous delivery",
                "team_size": "Cross-functional teams"
            }
        }
        
        # Create comparison table
        comparison_data = []
        for method, details in methodologies.items():
            comparison_data.append({
                "Methodology": method,
                "Timeline": details["timeline"],
                "Team Size": details["team_size"],
                "Flexibility": "High" if method == "Agile" else "Medium" if method == "DevOps" else "Low",
                "Documentation": "High" if method == "Waterfall" else "Medium",
                "Risk": "Low" if method == "Waterfall" else "Medium" if method == "Agile" else "High"
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
            f"🚀 {selected_methodology} Methodology",
            methodology_info['description'],
            card_type="info",
            color_scheme=self.color_scheme
        )
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**✅ Advantages:**")
            for advantage in methodology_info['advantages']:
                st.markdown(f"• {advantage}")
        
        with col2:
            st.markdown("**⚠️ Challenges:**")
            for disadvantage in methodology_info['disadvantages']:
                st.markdown(f"• {disadvantage}")
        
        with col3:
            st.markdown("**🎯 Best For:**")
            for use_case in methodology_info['best_for']:
                st.markdown(f"• {use_case}")
    
    def _render_agile_principles(self):
        """Render Agile principles and practices"""
        st.subheader("⚡ Agile Principles & Practices")
        
        # Agile Manifesto
        st.markdown("#### 📜 Agile Manifesto Values")
        
        manifesto_values = [
            {
                "value": "Individuals and interactions",
                "over": "processes and tools",
                "explanation": "People and communication are more important than rigid processes"
            },
            {
                "value": "Working software",
                "over": "comprehensive documentation",
                "explanation": "Functional software takes priority over extensive documentation"
            },
            {
                "value": "Customer collaboration",
                "over": "contract negotiation",
                "explanation": "Working with customers is better than rigid contracts"
            },
            {
                "value": "Responding to change",
                "over": "following a plan",
                "explanation": "Adaptability is more valuable than strict adherence to plans"
            }
        ]
        
        for i, item in enumerate(manifesto_values, 1):
            st.markdown(f"""
            **{i}. {item['value']}** over *{item['over']}*
            
            {item['explanation']}
            """)
        
        # Agile practices
        st.markdown("#### 🔄 Common Agile Practices")
        
        agile_practices = {
            "Sprint Planning": {
                "description": "Team plans work for upcoming sprint iteration",
                "duration": "2-4 hours per sprint",
                "participants": "Scrum Master, Product Owner, Development Team"
            },
            "Daily Standups": {
                "description": "Brief daily synchronization meetings",
                "duration": "15 minutes",
                "participants": "Development Team, Scrum Master"
            },
            "Sprint Review": {
                "description": "Demonstrate completed work to stakeholders",
                "duration": "1-2 hours",
                "participants": "Team, stakeholders, customers"
            },
            "Retrospective": {
                "description": "Team reflects on process and identifies improvements",
                "duration": "1-2 hours",
                "participants": "Development Team, Scrum Master"
            }
        }
        
        practice_data = []
        for practice, details in agile_practices.items():
            practice_data.append({
                "Practice": practice,
                "Duration": details["duration"],
                "Participants": details["participants"],
                "Purpose": details["description"]
            })
        
        df = pd.DataFrame(practice_data)
        st.dataframe(df, use_container_width=True)
    
    def _render_security_integration(self):
        """Render security integration in development"""
        st.subheader("🔒 Security Integration in Development")
        
        security_practices = {
            "Secure SDLC (SSDLC)": {
                "description": "Integration of security practices throughout development lifecycle",
                "practices": [
                    "Security requirements analysis",
                    "Threat modeling in design phase",
                    "Secure coding standards",
                    "Security testing and code review",
                    "Security deployment and monitoring"
                ],
                "benefits": ["Early vulnerability detection", "Reduced security debt", "Compliance alignment"]
            },
            "DevSecOps": {
                "description": "Integration of security into DevOps practices",
                "practices": [
                    "Automated security testing",
                    "Security as code",
                    "Continuous security monitoring",
                    "Infrastructure security scanning",
                    "Container security"
                ],
                "benefits": ["Continuous security", "Faster remediation", "Scalable security"]
            },
            "Shift-Left Security": {
                "description": "Moving security considerations earlier in development",
                "practices": [
                    "Security training for developers",
                    "IDE security plugins",
                    "Pre-commit security hooks",
                    "Security unit tests",
                    "Early threat modeling"
                ],
                "benefits": ["Lower fix costs", "Better security awareness", "Proactive approach"]
            }
        }
        
        # Display security approaches
        for approach, details in security_practices.items():
            with st.expander(f"🔍 {approach}", expanded=False):
                create_info_card(
                    approach,
                    details['description'],
                    card_type="warning",
                    color_scheme=self.color_scheme
                )
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**🛠️ Key Practices:**")
                    for practice in details['practices']:
                        st.markdown(f"• {practice}")
                
                with col2:
                    st.markdown("**💡 Benefits:**")
                    for benefit in details['benefits']:
                        st.markdown(f"• {benefit}")
    
    def _render_project_planner(self):
        """Render interactive project planner"""
        st.subheader("📋 Interactive Project Planner")
        
        st.markdown("Plan your development project:")
        
        # Project parameters
        col1, col2 = st.columns(2)
        
        with col1:
            project_type = st.selectbox(
                "Project Type:",
                ["Web Application", "Mobile App", "Desktop Software", "API/Microservice", "Data Analytics"]
            )
            
            team_size = st.slider("Team Size:", 2, 20, 6)
            
        with col2:
            methodology = st.selectbox(
                "Development Methodology:",
                ["Agile/Scrum", "Waterfall", "DevOps", "Hybrid"]
            )
            
            project_duration = st.slider("Project Duration (months):", 1, 24, 6)
        
        # Requirements complexity
        requirements_complexity = st.select_slider(
            "Requirements Complexity:",
            options=["Simple", "Moderate", "Complex", "Very Complex"],
            value="Moderate"
        )
        
        if st.button("🚀 Generate Project Plan"):
            # Generate project recommendations
            st.markdown("### 📊 Project Analysis & Recommendations")
            
            # Calculate project metrics
            complexity_multiplier = {
                "Simple": 1.0,
                "Moderate": 1.3,
                "Complex": 1.7,
                "Very Complex": 2.2
            }
            
            base_effort = project_duration * team_size * 20  # Base person-days
            adjusted_effort = base_effort * complexity_multiplier[requirements_complexity]
            
            # Display metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Estimated Effort", f"{adjusted_effort:.0f} person-days")
            with col2:
                st.metric("Sprints (2 weeks)", f"{project_duration * 2:.0f}")
            with col3:
                st.metric("Cost Estimate", f"${adjusted_effort * 500:,.0f}")
            with col4:
                risk_level = "High" if complexity_multiplier[requirements_complexity] > 1.5 else "Medium" if complexity_multiplier[requirements_complexity] > 1.2 else "Low"
                st.metric("Risk Level", risk_level)
            
            # Methodology recommendations
            if methodology == "Agile/Scrum":
                st.success("✅ **Agile/Scrum** is well-suited for this project type and complexity")
                recommendations = [
                    "Use 2-week sprints for iterative development",
                    "Implement daily standups for team coordination",
                    "Plan for regular stakeholder demos",
                    "Maintain a prioritized product backlog"
                ]
            elif methodology == "Waterfall":
                if requirements_complexity in ["Simple", "Moderate"]:
                    st.success("✅ **Waterfall** can work for well-defined requirements")
                else:
                    st.warning("⚠️ **Waterfall** may be risky for complex requirements")
                
                recommendations = [
                    "Invest heavily in upfront requirements analysis",
                    "Create detailed technical specifications",
                    "Plan for comprehensive testing phase",
                    "Establish clear milestone gates"
                ]
            
            st.markdown("#### 💡 Recommendations:")
            for recommendation in recommendations:
                st.markdown(f"• {recommendation}")
            
            # Security considerations
            st.markdown("#### 🔒 Security Considerations:")
            security_recommendations = [
                "Implement secure coding standards from day one",
                "Plan for regular security testing and code reviews",
                "Consider threat modeling in design phase",
                "Establish security deployment and monitoring practices"
            ]
            
            for rec in security_recommendations:
                st.markdown(f"• {rec}")


def explain_sdlc():
    """Main function to render SDLC component"""
    component = SDLCAgileComponent()
    
    # Summary points for the component
    summary_points = [
        "SDLC provides structure and predictability to software development",
        "Different methodologies suit different project types and requirements",
        "Agile approaches offer flexibility and continuous feedback",
        "Security must be integrated throughout the development lifecycle",
        "Team size, complexity, and timeline affect methodology choice"
    ]
    
    # Additional resources
    resources = [
        {
            "title": "Agile Manifesto",
            "description": "Original Agile Manifesto and principles",
            "url": "https://agilemanifesto.org/"
        },
        {
            "title": "NIST Secure Software Development Framework",
            "description": "Guidelines for secure software development practices"
        }
    ]
    
    # Render the complete component
    component.render_full_component(summary_points, resources)


def explain_agile():
    """Alias function for Agile-specific content"""
    explain_sdlc()  # Same component covers both SDLC and Agile
