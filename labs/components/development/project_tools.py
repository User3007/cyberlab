import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_project_tools():
    """Project Management Tools and Software using TDD pattern"""
    
    st.markdown("## Project Management Tools & Software")
    st.markdown("**Definition:** Digital platforms and software applications designed to help project managers plan, execute, monitor, and close projects efficiently.")
    
    st.markdown("---")
    
    # Tool Categories
    st.markdown("### PM Tool Categories")
    
    categories_data = {
        "Category": ["Planning Tools", "Collaboration Tools", "Time Tracking", "Resource Management", "Reporting Tools"],
        "Purpose": [
            "Create schedules, define tasks, set dependencies",
            "Team communication, file sharing, meetings",
            "Track work hours, monitor productivity",
            "Allocate resources, manage workloads",
            "Generate reports, dashboards, analytics"
        ],
        "Key Features": [
            "Gantt charts, critical path, milestones",
            "Chat, video calls, document sharing",
            "Timesheets, automated tracking, billing",
            "Resource calendars, capacity planning",
            "Real-time dashboards, custom reports"
        ],
        "Popular Tools": [
            "Microsoft Project, Smartsheet, Monday.com",
            "Slack, Microsoft Teams, Zoom",
            "Toggl, RescueTime, Clockify",
            "Resource Guru, Float, Hub Planner",
            "Power BI, Tableau, Google Analytics"
        ]
    }
    
    df = pd.DataFrame(categories_data)
    st.dataframe(df, use_container_width=True)
    
    # Popular PM Software Comparison
    st.markdown("### Popular Project Management Software")
    
    pm_tools_data = {
        "Tool": ["Microsoft Project", "Jira", "Asana", "Trello", "Monday.com", "Smartsheet"],
        "Best For": [
            "Complex projects, enterprise",
            "Software development, agile",
            "Team collaboration, workflows",
            "Simple task management",
            "Visual project tracking",
            "Spreadsheet-like interface"
        ],
        "Pricing": [
            "$10-55/user/month",
            "$7-14/user/month",
            "$10.99-24.99/user/month",
            "Free-$17.50/user/month",
            "$8-24/user/month",
            "$7-25/user/month"
        ],
        "Key Strengths": [
            "Advanced scheduling, resource management",
            "Issue tracking, agile boards",
            "User-friendly, team collaboration",
            "Simple Kanban boards, visual",
            "Customizable workflows, automation",
            "Familiar interface, powerful features"
        ],
        "Limitations": [
            "Steep learning curve, expensive",
            "Complex for non-technical users",
            "Limited advanced PM features",
            "Basic reporting capabilities",
            "Can become overwhelming",
            "Less intuitive than competitors"
        ]
    }
    
    df2 = pd.DataFrame(pm_tools_data)
    st.dataframe(df2, use_container_width=True)
    
    # Tool Selection Matrix
    st.markdown("### Tool Selection Criteria")
    
    # Create comparison chart
    tools = ['MS Project', 'Jira', 'Asana', 'Trello', 'Monday.com']
    criteria = ['Ease of Use', 'Features', 'Collaboration', 'Reporting', 'Value for Money']
    
    # Scores out of 10
    scores = {
        'MS Project': [6, 10, 7, 9, 6],
        'Jira': [7, 9, 8, 8, 8],
        'Asana': [9, 8, 9, 7, 8],
        'Trello': [10, 6, 8, 5, 9],
        'Monday.com': [8, 8, 8, 8, 7]
    }
    
    fig = go.Figure()
    
    for tool in tools:
        fig.add_trace(go.Scatterpolar(
            r=scores[tool],
            theta=criteria,
            fill='toself',
            name=tool
        ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 10]
            )
        ),
        title="Project Management Tools Comparison",
        height=600
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Implementation Strategy
    st.markdown("### Tool Implementation Strategy")
    
    implementation_data = {
        "Phase": ["Assessment", "Selection", "Pilot", "Training", "Rollout", "Optimization"],
        "Activities": [
            "Analyze current processes, identify needs",
            "Evaluate tools, conduct trials",
            "Test with small team, gather feedback",
            "Train users, create documentation",
            "Deploy organization-wide",
            "Monitor usage, continuous improvement"
        ],
        "Duration": ["2-4 weeks", "3-6 weeks", "4-8 weeks", "2-4 weeks", "4-12 weeks", "Ongoing"],
        "Key Success Factors": [
            "Clear requirements, stakeholder input",
            "Objective evaluation, proof of concept",
            "User feedback, iterative improvements",
            "Comprehensive training, support materials",
            "Change management, executive support",
            "Regular reviews, user feedback loops"
        ]
    }
    
    df3 = pd.DataFrame(implementation_data)
    st.dataframe(df3, use_container_width=True)
    
    # Integration Considerations
    st.markdown("### Integration and Ecosystem")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Common Integrations:**
        - Email systems (Outlook, Gmail)
        - File storage (OneDrive, Google Drive)
        - Communication tools (Slack, Teams)
        - Time tracking applications
        - Financial systems (ERP, accounting)
        """)
    
    with col2:
        st.markdown("""
        **Integration Benefits:**
        - Reduced data entry
        - Improved data accuracy
        - Streamlined workflows
        - Better visibility
        - Enhanced productivity
        """)
    
    # ROI and Metrics
    st.markdown("### ROI and Success Metrics")
    
    metrics_data = {
        "Metric Category": ["Efficiency", "Quality", "Communication", "Visibility"],
        "Key Metrics": [
            "Time to complete projects, resource utilization",
            "Defect rates, rework percentage",
            "Response time, meeting effectiveness",
            "Project status accuracy, reporting time"
        ],
        "Expected Improvement": [
            "15-30% faster delivery",
            "20-40% fewer defects",
            "50% faster communication",
            "80% better visibility"
        ]
    }
    
    df4 = pd.DataFrame(metrics_data)
    st.dataframe(df4, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Right Tool for Right Job:</strong> Select tools based on project complexity and team needs</li>
            <li><strong>User Adoption is Key:</strong> Focus on training and change management for success</li>
            <li><strong>Integration Matters:</strong> Choose tools that work well with existing systems</li>
            <li><strong>Measure Success:</strong> Track metrics to demonstrate ROI and continuous improvement</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
