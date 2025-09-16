import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_pm_fundamentals():
    """Project Management Fundamentals using TDD pattern"""
    
    st.markdown("## Project Management Fundamentals")
    st.markdown("**Definition:** Systematic approach to planning, executing, and closing projects using established processes, tools, and techniques to achieve specific goals within constraints.")
    
    st.markdown("---")
    
    # PM Knowledge Areas
    st.markdown("### Project Management Knowledge Areas")
    
    knowledge_areas_data = {
        "Knowledge Area": ["Integration", "Scope", "Schedule", "Cost", "Quality", "Resource", "Communications", "Risk", "Procurement", "Stakeholder"],
        "Description": [
            "Coordinate all project elements",
            "Define what work is required",
            "Plan and control project timeline",
            "Estimate, budget, and control costs",
            "Ensure deliverables meet requirements",
            "Acquire and manage team members",
            "Plan and manage information flow",
            "Identify and respond to uncertainties",
            "Acquire goods and services",
            "Identify and engage project stakeholders"
        ],
        "Key Processes": [
            "Develop charter, manage changes",
            "Collect requirements, create WBS",
            "Define activities, develop schedule",
            "Estimate costs, determine budget",
            "Plan quality, perform QA/QC",
            "Estimate resources, acquire team",
            "Plan communications, manage info",
            "Identify risks, perform analysis",
            "Plan procurement, conduct procurements",
            "Identify stakeholders, manage engagement"
        ],
        "Primary Output": [
            "Project charter, change requests",
            "Scope statement, WBS",
            "Project schedule, schedule baseline",
            "Cost baseline, budget",
            "Quality management plan, metrics",
            "Resource calendar, team assignments",
            "Communications management plan",
            "Risk register, risk responses",
            "Procurement documents, contracts",
            "Stakeholder register, engagement plan"
        ]
    }
    
    df = pd.DataFrame(knowledge_areas_data)
    st.dataframe(df, use_container_width=True)
    
    # Project Life Cycle
    st.markdown("### Project Life Cycle Phases")
    
    lifecycle_data = {
        "Phase": ["Initiation", "Planning", "Execution", "Monitoring & Control", "Closure"],
        "Purpose": [
            "Authorize project and define high-level scope",
            "Define detailed scope and create project plan",
            "Complete work defined in project plan",
            "Track progress and manage changes",
            "Finalize activities and close project"
        ],
        "Key Activities": [
            "Develop charter, identify stakeholders",
            "Create WBS, schedule, budget, plans",
            "Direct work, manage team, communications",
            "Monitor progress, control changes",
            "Close contracts, document lessons learned"
        ],
        "Major Deliverables": [
            "Project charter, stakeholder register",
            "Project management plan, baselines",
            "Project deliverables, status reports",
            "Change requests, performance reports",
            "Final product, project closure documents"
        ]
    }
    
    df2 = pd.DataFrame(lifecycle_data)
    st.dataframe(df2, use_container_width=True)
    
    # PM Methodologies Comparison
    st.markdown("### Project Management Methodologies")
    
    methodologies_data = {
        "Methodology": ["Waterfall", "Agile", "Scrum", "Kanban", "PRINCE2", "PMI/PMBOK"],
        "Best For": [
            "Well-defined requirements, stable scope",
            "Changing requirements, iterative development",
            "Software development, cross-functional teams",
            "Continuous flow, visual workflow",
            "Controlled environments, governance focus",
            "Traditional projects, process standardization"
        ],
        "Key Characteristics": [
            "Sequential phases, detailed upfront planning",
            "Iterative, adaptive, customer collaboration",
            "Sprints, daily standups, retrospectives",
            "Visual boards, WIP limits, flow optimization",
            "Defined roles, stage gates, business case",
            "Process groups, knowledge areas, best practices"
        ],
        "Advantages": [
            "Clear structure, predictable timeline",
            "Flexibility, early value delivery",
            "Team collaboration, regular feedback",
            "Visual management, continuous improvement",
            "Risk management, quality focus",
            "Comprehensive framework, industry standard"
        ]
    }
    
    df3 = pd.DataFrame(methodologies_data)
    st.dataframe(df3, use_container_width=True)
    
    # Project Success Factors
    st.markdown("### Critical Success Factors")
    
    # Create radar chart for success factors
    factors = ['Clear Objectives', 'Stakeholder Support', 'Skilled Team', 'Adequate Resources', 'Effective Communication', 'Risk Management']
    importance_scores = [9.5, 9.0, 8.5, 8.0, 8.8, 7.5]
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatterpolar(
        r=importance_scores,
        theta=factors,
        fill='toself',
        name='Importance Score',
        line_color='rgb(0, 123, 255)'
    ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 10]
            )
        ),
        title="Project Success Factors (Importance Score out of 10)",
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # PM Tools and Techniques
    st.markdown("### Essential PM Tools and Techniques")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Planning Tools:**
        - Work Breakdown Structure (WBS)
        - Gantt Charts
        - Network Diagrams
        - Resource Histograms
        - Risk Matrices
        """)
    
    with col2:
        st.markdown("""
        **Control Tools:**
        - Earned Value Management
        - Milestone Reviews
        - Status Reports
        - Change Control Board
        - Lessons Learned
        """)
    
    # PM Competencies
    st.markdown("### Project Manager Competencies")
    
    competencies_data = {
        "Competency Area": ["Technical", "Leadership", "Strategic & Business", "Communication"],
        "Skills": [
            "PM processes, tools, techniques",
            "Team building, motivation, conflict resolution",
            "Business acumen, organizational awareness",
            "Verbal, written, presentation, negotiation"
        ],
        "Development Methods": [
            "PM certification, training, practice",
            "Leadership courses, mentoring, experience",
            "Business education, cross-functional exposure",
            "Communication training, public speaking"
        ]
    }
    
    df4 = pd.DataFrame(competencies_data)
    st.dataframe(df4, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Structured Approach:</strong> PM provides systematic framework for project success</li>
            <li><strong>Balance Triple Constraint:</strong> Manage scope, time, and cost effectively</li>
            <li><strong>Stakeholder Focus:</strong> Engage stakeholders throughout project lifecycle</li>
            <li><strong>Continuous Improvement:</strong> Learn from each project to improve future performance</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
