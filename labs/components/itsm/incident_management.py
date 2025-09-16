import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_incident_management():
    """Incident Management using TDD pattern"""
    
    st.markdown("## Incident Management")
    st.markdown("**Definition:** Process to restore normal service operation as quickly as possible following an unplanned interruption or reduction in service quality.")
    
    st.markdown("---")
    
    # Incident Lifecycle
    st.markdown("### Incident Management Process")
    
    process_data = {
        "Stage": ["Detection", "Logging", "Categorization", "Prioritization", "Investigation", "Resolution", "Closure"],
        "Description": [
            "Incident identified through monitoring or user reports",
            "Record incident details in service management tool",
            "Classify incident type and affected services",
            "Determine urgency and impact to set priority",
            "Diagnose root cause and identify solution",
            "Implement fix and restore service",
            "Verify resolution and document lessons learned"
        ],
        "Key Activities": [
            "Monitoring alerts, user calls, automated detection",
            "Incident ticket creation, initial documentation",
            "Service mapping, impact assessment",
            "Priority matrix application, resource allocation",
            "Technical analysis, escalation if needed",
            "Change implementation, service restoration",
            "User confirmation, knowledge base update"
        ]
    }
    
    df = pd.DataFrame(process_data)
    st.dataframe(df, use_container_width=True)
    
    # Priority Matrix
    st.markdown("### Incident Priority Matrix")
    
    priority_data = {
        "Impact/Urgency": ["High Impact", "Medium Impact", "Low Impact"],
        "High Urgency": ["Critical (P1)", "High (P2)", "Medium (P3)"],
        "Medium Urgency": ["High (P2)", "Medium (P3)", "Low (P4)"],
        "Low Urgency": ["Medium (P3)", "Low (P4)", "Low (P4)"]
    }
    
    df2 = pd.DataFrame(priority_data)
    st.dataframe(df2, use_container_width=True)
    
    # Response Times
    st.markdown("### Typical Response and Resolution Times")
    
    sla_data = {
        "Priority": ["P1 - Critical", "P2 - High", "P3 - Medium", "P4 - Low"],
        "Response Time": ["15 minutes", "1 hour", "4 hours", "24 hours"],
        "Resolution Time": ["4 hours", "24 hours", "72 hours", "1 week"],
        "Examples": [
            "System down, critical service outage",
            "Major functionality impaired",
            "Minor functionality affected",
            "Cosmetic issues, enhancement requests"
        ]
    }
    
    df3 = pd.DataFrame(sla_data)
    st.dataframe(df3, use_container_width=True)
    
    # Incident Roles
    st.markdown("### Key Roles and Responsibilities")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Service Desk:**
        - First point of contact
        - Initial incident logging
        - User communication
        - Basic troubleshooting
        """)
    
    with col2:
        st.markdown("""
        **Technical Teams:**
        - Advanced investigation
        - Root cause analysis
        - Solution implementation
        - Knowledge transfer
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Speed is Critical:</strong> Focus on service restoration over root cause analysis</li>
            <li><strong>Communication:</strong> Keep stakeholders informed throughout the process</li>
            <li><strong>Documentation:</strong> Record all actions for future reference and improvement</li>
            <li><strong>Continuous Improvement:</strong> Learn from incidents to prevent recurrence</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
