import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_scrum():
    """Scrum Framework using TDD pattern"""
    
    st.markdown("## Scrum Framework")
    st.markdown("**Definition:** Agile framework for managing complex product development using iterative and incremental practices with cross-functional teams.")
    
    st.markdown("---")
    
    # Scrum Roles
    st.markdown("### Scrum Roles")
    
    roles_data = {
        "Role": ["Product Owner", "Scrum Master", "Development Team"],
        "Responsibilities": [
            "Define product vision, manage backlog, prioritize features",
            "Facilitate process, remove impediments, coach team",
            "Build product, self-organize, cross-functional collaboration"
        ],
        "Key Activities": [
            "Write user stories, accept/reject work, stakeholder communication",
            "Run ceremonies, protect team, ensure Scrum practices",
            "Sprint planning, daily work, retrospectives, deliver increment"
        ],
        "Success Metrics": [
            "Business value delivered, stakeholder satisfaction",
            "Team velocity, impediment resolution time",
            "Sprint goals met, code quality, team collaboration"
        ]
    }
    
    df = pd.DataFrame(roles_data)
    st.dataframe(df, use_container_width=True)
    
    # Scrum Events
    st.markdown("### Scrum Events (Ceremonies)")
    
    events_data = {
        "Event": ["Sprint Planning", "Daily Scrum", "Sprint Review", "Sprint Retrospective"],
        "Duration": ["2-4 hours", "15 minutes", "1-2 hours", "1-1.5 hours"],
        "Participants": [
            "Entire Scrum Team",
            "Development Team (PO/SM optional)",
            "Scrum Team + Stakeholders", 
            "Entire Scrum Team"
        ],
        "Purpose": [
            "Plan sprint work and commit to sprint goal",
            "Synchronize work and identify impediments",
            "Demonstrate increment and gather feedback",
            "Inspect team process and identify improvements"
        ],
        "Key Outputs": [
            "Sprint backlog, sprint goal, capacity plan",
            "Updated task status, identified blockers",
            "Stakeholder feedback, product insights",
            "Action items, process improvements"
        ]
    }
    
    df2 = pd.DataFrame(events_data)
    st.dataframe(df2, use_container_width=True)
    
    # Scrum Artifacts
    st.markdown("### Scrum Artifacts")
    
    artifacts_data = {
        "Artifact": ["Product Backlog", "Sprint Backlog", "Product Increment"],
        "Owner": ["Product Owner", "Development Team", "Development Team"],
        "Description": [
            "Ordered list of features needed in product",
            "Sprint goal + selected backlog items + plan",
            "Working product at end of sprint"
        ],
        "Characteristics": [
            "Prioritized, estimated, detailed, evolving",
            "Committed, achievable, transparent, focused",
            "Done, tested, potentially shippable, valuable"
        ]
    }
    
    df3 = pd.DataFrame(artifacts_data)
    st.dataframe(df3, use_container_width=True)
    
    # Sprint Flow Visualization
    st.markdown("### Sprint Flow")
    
    # Create sprint timeline
    days = list(range(1, 15))  # 2-week sprint
    planned_work = [100 - (i * 7) for i in range(14)]  # Ideal burndown
    actual_work = [100, 95, 85, 80, 75, 78, 70, 65, 55, 45, 40, 30, 15, 0]  # Realistic burndown
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=days,
        y=planned_work,
        mode='lines',
        name='Ideal Burndown',
        line=dict(color='blue', dash='dash')
    ))
    
    fig.add_trace(go.Scatter(
        x=days,
        y=actual_work,
        mode='lines+markers',
        name='Actual Progress',
        line=dict(color='red')
    ))
    
    fig.update_layout(
        title="Sprint Burndown Chart",
        xaxis_title="Sprint Days",
        yaxis_title="Remaining Work (Story Points)",
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Scrum Values
    st.markdown("### Scrum Values")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Core Values:**
        - **Commitment** - Dedicated to achieving team goals
        - **Courage** - Do the right thing and work on tough problems
        - **Focus** - Concentrate on sprint work and goals
        """)
    
    with col2:
        st.markdown("""
        **Additional Values:**
        - **Openness** - Transparent about work and challenges
        - **Respect** - Value diverse skills and opinions
        """)
    
    # Implementation Best Practices
    st.markdown("### Scrum Implementation Best Practices")
    
    practices_data = {
        "Area": ["Team Formation", "Sprint Planning", "Daily Scrums", "Sprint Review", "Retrospectives"],
        "Best Practices": [
            "Cross-functional, 5-9 people, co-located if possible",
            "Prepare backlog, estimate capacity, define clear goals",
            "Same time/place, focus on progress/impediments",
            "Demo working software, gather feedback",
            "Safe environment, actionable improvements"
        ],
        "Common Pitfalls": [
            "Too large teams, missing skills, geographic dispersion",
            "Unprepared backlog, unrealistic commitments",
            "Status meetings, problem-solving in daily",
            "PowerPoint demos, no stakeholder engagement",
            "Blame games, no follow-through on actions"
        ]
    }
    
    df4 = pd.DataFrame(practices_data)
    st.dataframe(df4, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Empirical Process:</strong> Scrum is based on transparency, inspection, and adaptation</li>
            <li><strong>Self-Organization:</strong> Teams are empowered to determine how to accomplish work</li>
            <li><strong>Continuous Improvement:</strong> Regular retrospectives drive process improvements</li>
            <li><strong>Customer Focus:</strong> Frequent delivery ensures customer needs are met</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
