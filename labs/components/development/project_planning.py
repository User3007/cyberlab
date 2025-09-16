"""
Project Planning Component
Software project management and planning methodologies
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
from typing import Dict, List, Any

from ...shared.color_schemes import SOFTWARE_DEVELOPMENT_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class ProjectPlanningComponent(ComponentTemplate):
    """Project Planning component with methodologies and tools"""
    
    def __init__(self):
        super().__init__(
            component_name=" Project Planning",
            description="Software project management methodologies, planning techniques, and best practices",
            color_scheme=SOFTWARE_DEVELOPMENT_COLORS,
            estimated_time="25 minutes"
        )
        
        # Project methodologies data
        self.methodologies = {
            "Agile": {
                "description": "Iterative development with flexible planning and continuous feedback",
                "principles": [
                    "Individuals and interactions over processes and tools",
                    "Working software over comprehensive documentation", 
                    "Customer collaboration over contract negotiation",
                    "Responding to change over following a plan"
                ],
                "frameworks": ["Scrum", "Kanban", "XP", "SAFe"],
                "best_for": "Dynamic requirements, small to medium teams, frequent releases",
                "timeline": "2-4 week sprints",
                "pros": ["Flexibility", "Fast delivery", "Customer satisfaction", "Risk reduction"],
                "cons": ["Less predictability", "Requires discipline", "Documentation gaps"]
            },
            "Waterfall": {
                "description": "Sequential development with distinct phases and comprehensive planning",
                "principles": [
                    "Sequential phase completion",
                    "Comprehensive documentation",
                    "Detailed upfront planning",
                    "Change control processes"
                ],
                "frameworks": ["Traditional Waterfall", "V-Model", "Modified Waterfall"],
                "best_for": "Stable requirements, regulated industries, large projects",
                "timeline": "6-18 months phases",
                "pros": ["Predictability", "Clear milestones", "Comprehensive docs", "Budget control"],
                "cons": ["Inflexibility", "Late feedback", "Risk of obsolescence"]
            },
            "DevOps": {
                "description": "Culture combining development and operations for continuous delivery",
                "principles": [
                    "Collaboration and communication",
                    "Automation and tooling",
                    "Continuous integration and deployment",
                    "Monitoring and feedback"
                ],
                "frameworks": ["CI/CD", "Infrastructure as Code", "GitOps", "Site Reliability Engineering"],
                "best_for": "Cloud-native apps, microservices, high-frequency deployments",
                "timeline": "Continuous delivery",
                "pros": ["Fast delivery", "High quality", "Reduced risk", "Better collaboration"],
                "cons": ["Cultural change needed", "Tool complexity", "Security challenges"]
            }
        }
        
        # Project phases
        self.project_phases = {
            "Initiation": {
                "description": "Define project scope, objectives, and feasibility",
                "activities": [
                    "Project charter creation",
                    "Stakeholder identification",
                    "Initial requirements gathering",
                    "Feasibility study",
                    "Risk assessment"
                ],
                "deliverables": ["Project Charter", "Stakeholder Register", "Initial Requirements"],
                "duration": "1-2 weeks"
            },
            "Planning": {
                "description": "Detailed planning of project execution",
                "activities": [
                    "Work breakdown structure",
                    "Timeline and milestones",
                    "Resource allocation",
                    "Risk management plan",
                    "Communication plan"
                ],
                "deliverables": ["Project Plan", "WBS", "Risk Register", "Resource Plan"],
                "duration": "2-4 weeks"
            },
            "Execution": {
                "description": "Implementation of project deliverables",
                "activities": [
                    "Development work",
                    "Quality assurance",
                    "Progress monitoring",
                    "Stakeholder communication",
                    "Change management"
                ],
                "deliverables": ["Software Product", "Test Results", "Progress Reports"],
                "duration": "60-80% of project"
            },
            "Monitoring": {
                "description": "Track progress and manage changes",
                "activities": [
                    "Performance monitoring",
                    "Quality control",
                    "Risk monitoring",
                    "Change control",
                    "Status reporting"
                ],
                "deliverables": ["Status Reports", "Quality Metrics", "Change Logs"],
                "duration": "Ongoing"
            },
            "Closure": {
                "description": "Formal project completion and handover",
                "activities": [
                    "Final deliverable review",
                    "Documentation handover",
                    "Lessons learned",
                    "Resource release",
                    "Project evaluation"
                ],
                "deliverables": ["Final Product", "Documentation", "Lessons Learned"],
                "duration": "1-2 weeks"
            }
        }
        
        # Planning tools
        self.planning_tools = {
            "Requirements": ["User Stories", "Use Cases", "BRD", "Functional Specs", "Acceptance Criteria"],
            "Estimation": ["Story Points", "T-Shirt Sizing", "Planning Poker", "Expert Judgment", "Analogical"],
            "Scheduling": ["Gantt Charts", "Kanban Boards", "Burndown Charts", "Milestone Charts", "PERT"],
            "Collaboration": ["Jira", "Azure DevOps", "Trello", "Asana", "Monday.com"],
            "Documentation": ["Confluence", "Notion", "GitBook", "Wiki", "SharePoint"]
        }

    def render_content(self):
        """Render the main component content"""
        self._render_methodology_overview()
        self._render_project_phases()
        self._render_planning_tools()
        self._render_estimation_guide()

    def _render_methodology_overview(self):
        """Render project methodologies overview"""
        st.subheader(" Project Methodologies")
        
        # Methodology selector
        methodology = st.selectbox(
            "Select Methodology to Explore:",
            list(self.methodologies.keys()),
            key="methodology_selector"
        )
        
        method_data = self.methodologies[methodology]
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown(f"### {methodology} Methodology")
            st.markdown(f"**Description:** {method_data['description']}")
            
            st.markdown("####  Core Principles")
            for principle in method_data['principles']:
                st.markdown(f" {principle}")
            
            st.markdown(f"**Best For:** {method_data['best_for']}")
            st.markdown(f"**Typical Timeline:** {method_data['timeline']}")
        
        with col2:
            # Pros and Cons
            st.markdown("####  Advantages")
            for pro in method_data['pros']:
                st.markdown(f" {pro}")
            
            st.markdown("####  Challenges")
            for con in method_data['cons']:
                st.markdown(f" {con}")
        
        # Frameworks comparison
        st.subheader(" Framework Comparison")
        
        comparison_data = []
        for name, data in self.methodologies.items():
            comparison_data.append({
                "Methodology": name,
                "Flexibility": "High" if name == "Agile" else "Medium" if name == "DevOps" else "Low",
                "Documentation": "Light" if name == "Agile" else "Medium" if name == "DevOps" else "Heavy",
                "Timeline": data["timeline"],
                "Best For": data["best_for"][:30] + "..."
            })
        
        df = pd.DataFrame(comparison_data)
        st.dataframe(df, use_container_width=True)

    def _render_project_phases(self):
        """Render project phases breakdown"""
        st.subheader(" Project Phases")
        
        # Phase selector
        phase = st.selectbox(
            "Select Project Phase:",
            list(self.project_phases.keys()),
            key="project_phase_selector"
        )
        
        phase_data = self.project_phases[phase]
        
        col1, col2 = st.columns(2)
        
        with col1:
            create_info_card(
                f" {phase} Phase",
                phase_data["description"],
                card_type="info",
                color_scheme=self.color_scheme
            )
            
            st.markdown("####  Key Activities")
            for activity in phase_data["activities"]:
                st.markdown(f" {activity}")
        
        with col2:
            st.markdown("####  Deliverables")
            for deliverable in phase_data["deliverables"]:
                st.markdown(f" {deliverable}")
            
            st.markdown(f"** Duration:** {phase_data['duration']}")
        
        # Project timeline visualization
        st.subheader(" Project Timeline Example")
        
        # Sample project timeline
        phases = list(self.project_phases.keys())
        durations = [2, 3, 12, 12, 1]  # weeks
        
        fig = go.Figure()
        
        start_date = datetime.now()
        cumulative = 0
        
        for i, (phase_name, duration) in enumerate(zip(phases, durations)):
            fig.add_trace(go.Scatter(
                x=[start_date + timedelta(weeks=cumulative), 
                   start_date + timedelta(weeks=cumulative + duration)],
                y=[phase_name, phase_name],
                mode='lines+markers',
                name=phase_name,
                line=dict(width=8),
                marker=dict(size=10)
            ))
            cumulative += duration
        
        fig.update_layout(
            title="Sample Project Timeline (30 weeks)",
            xaxis_title="Timeline",
            yaxis_title="Project Phases",
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)

    def _render_planning_tools(self):
        """Render planning tools and techniques"""
        st.subheader(" Planning Tools & Techniques")
        
        # Tools by category
        tool_category = st.selectbox(
            "Select Tool Category:",
            list(self.planning_tools.keys()),
            key="tool_category_selector"
        )
        
        tools = self.planning_tools[tool_category]
        
        st.markdown(f"### {tool_category} Tools")
        
        cols = st.columns(min(3, len(tools)))
        for i, tool in enumerate(tools):
            with cols[i % 3]:
                st.markdown(f"**{tool}**")
                
                # Add descriptions for key tools
                descriptions = {
                    "User Stories": "As a [user], I want [goal] so that [benefit]",
                    "Story Points": "Relative effort estimation (Fibonacci: 1,2,3,5,8,13)",
                    "Gantt Charts": "Timeline visualization with dependencies",
                    "Kanban Boards": "Visual workflow management (To Do, In Progress, Done)",
                    "Burndown Charts": "Progress tracking over time"
                }
                
                if tool in descriptions:
                    st.caption(descriptions[tool])
        
        # Tool recommendations by project type
        st.subheader(" Tool Recommendations by Project Type")
        
        recommendations = {
            "Small Team (2-5 people)": {
                "Planning": "Trello, Notion",
                "Communication": "Slack, Discord", 
                "Code": "GitHub, GitLab",
                "Estimation": "T-Shirt Sizing"
            },
            "Medium Team (6-15 people)": {
                "Planning": "Jira, Azure DevOps",
                "Communication": "Microsoft Teams, Slack",
                "Code": "GitHub Enterprise, Bitbucket",
                "Estimation": "Story Points, Planning Poker"
            },
            "Large Team (15+ people)": {
                "Planning": "Jira, Azure DevOps, Monday.com",
                "Communication": "Microsoft Teams, Confluence",
                "Code": "GitHub Enterprise, Azure Repos",
                "Estimation": "Expert Judgment, Analogical"
            }
        }
        
        for team_size, tools in recommendations.items():
            with st.expander(f" {team_size}"):
                for category, tool_list in tools.items():
                    st.markdown(f"**{category}:** {tool_list}")

    def _render_estimation_guide(self):
        """Render estimation techniques guide"""
        st.subheader(" Estimation Techniques")
        
        tabs = st.tabs(["Story Points", "Planning Poker", "T-Shirt Sizing", "Best Practices"])
        
        with tabs[0]:
            st.markdown("""
            ####  Story Points
            
            **Concept:** Relative estimation using Fibonacci sequence
            
            **Scale:** 1, 2, 3, 5, 8, 13, 21, 34, 55, 89
            
            **Guidelines:**
            - **1 Point:** Trivial task (30 min - 1 hour)
            - **2 Points:** Simple task (2-4 hours)
            - **3 Points:** Small feature (4-8 hours)
            - **5 Points:** Medium feature (1-2 days)
            - **8 Points:** Large feature (2-3 days)
            - **13 Points:** Very large (3-5 days)
            - **21+ Points:** Epic - needs breakdown
            
            **Benefits:**
            - Relative comparison easier than absolute time
            - Accounts for complexity, uncertainty, effort
            - Team velocity tracking
            """)
        
        with tabs[1]:
            st.markdown("""
            ####  Planning Poker
            
            **Process:**
            1. Product Owner reads user story
            2. Team discusses requirements and clarifies questions
            3. Each member selects estimate card privately
            4. All reveal simultaneously
            5. Discuss differences (especially high/low outliers)
            6. Re-estimate until consensus
            
            **Cards:** 0, , 1, 2, 3, 5, 8, 13, 20, 40, 100, ?, 
            
            **Special Cards:**
            - **?** - Need more information
            - **** - Need a break
            - **0** - Already done
            - **** - Too big, needs breakdown
            """)
        
        with tabs[2]:
            st.markdown("""
            ####  T-Shirt Sizing
            
            **Scale:** XS, S, M, L, XL, XXL
            
            **Mapping:**
            - **XS:** 1-2 hours (bug fixes)
            - **S:** Half day (small features)
            - **M:** 1-2 days (medium features)
            - **L:** 3-5 days (large features)
            - **XL:** 1-2 weeks (major features)
            - **XXL:** Epic - needs breakdown
            
            **When to Use:**
            - Early planning stages
            - Non-technical stakeholders
            - High-level roadmap planning
            """)
        
        with tabs[3]:
            st.markdown("""
            ####  Estimation Best Practices
            
            ** Do:**
            - Include whole team in estimation
            - Consider complexity, risk, and effort
            - Use historical data for calibration
            - Re-estimate when requirements change
            - Track actual vs estimated for learning
            
            ** Don't:**
            - Convert story points to hours directly
            - Compare velocity between teams
            - Use estimates for performance evaluation
            - Estimate without understanding requirements
            - Ignore team feedback on estimates
            
            ** Tips:**
            - Start with reference stories
            - Break down large items (>13 points)
            - Consider dependencies and risks
            - Update estimates as you learn
            - Use multiple estimation techniques
            """)


def explain_project_planning():
    """Main function to display project planning component"""
    component = ProjectPlanningComponent()
    
    # Summary points for the banner
    summary_points = [
        " Project management methodologies",
        " Planning phases and deliverables",
        " Tools and estimation techniques",
        " Best practices and frameworks"
    ]
    
    # Learning resources
    resources = [
        {
            "title": " PMI Project Management Guide",
            "url": "https://www.pmi.org/pmbok-guide-standards",
            "description": "Industry standard project management practices"
        },
        {
            "title": " Agile Alliance Resources",
            "url": "https://www.agilealliance.org/agile101/",
            "description": "Comprehensive agile methodology guide"
        },
        {
            "title": " Atlassian Project Management",
            "url": "https://www.atlassian.com/project-management",
            "description": "Modern project management tools and techniques"
        }
    ]
    
    component.render_full_component(summary_points, resources)


if __name__ == "__main__":
    explain_project_planning()
