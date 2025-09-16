import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_change_management():
    """Change Management using TDD pattern"""
    
    st.markdown("## Change Management")
    st.markdown("**Definition:** Systematic approach to managing changes to IT infrastructure, applications, and services to minimize risk and business disruption.")
    
    st.markdown("---")
    
    # Change Types
    st.markdown("### Types of Changes")
    
    change_types_data = {
        "Change Type": ["Standard", "Normal", "Emergency", "Major"],
        "Approval Process": [
            "Pre-approved, automated",
            "Change Advisory Board review",
            "Emergency CAB approval",
            "Executive/Board approval"
        ],
        "Risk Level": ["Low", "Medium", "High", "Very High"],
        "Timeline": [
            "Immediate implementation",
            "1-4 weeks planning",
            "Hours to days",
            "Months of planning"
        ],
        "Examples": [
            "Password resets, standard patches",
            "Software updates, configuration changes",
            "Security patches, system outages",
            "Infrastructure overhauls, major upgrades"
        ]
    }
    
    df = pd.DataFrame(change_types_data)
    st.dataframe(df, use_container_width=True)
    
    # Change Process
    st.markdown("### Change Management Process")
    
    process_data = {
        "Phase": ["Request", "Assessment", "Approval", "Planning", "Implementation", "Review"],
        "Activities": [
            "Submit change request with business justification",
            "Analyze impact, risk, and resource requirements",
            "Change Advisory Board reviews and approves/rejects",
            "Develop detailed implementation and rollback plans",
            "Execute change according to approved plan",
            "Evaluate success and document lessons learned"
        ],
        "Key Deliverables": [
            "Change request form, business case",
            "Impact assessment, risk analysis",
            "Approval decision, conditions",
            "Implementation plan, rollback procedures",
            "Change record, test results",
            "Post-implementation review, knowledge update"
        ]
    }
    
    df2 = pd.DataFrame(process_data)
    st.dataframe(df2, use_container_width=True)
    
    # Change Advisory Board
    st.markdown("### Change Advisory Board (CAB)")
    
    cab_data = {
        "Role": ["Change Manager", "Technical Representatives", "Business Representatives", "Security Team", "Operations Team"],
        "Responsibilities": [
            "Facilitate meetings, coordinate approvals",
            "Assess technical impact and feasibility",
            "Evaluate business impact and timing",
            "Review security implications",
            "Assess operational impact and scheduling"
        ]
    }
    
    df3 = pd.DataFrame(cab_data)
    st.dataframe(df3, use_container_width=True)
    
    # Success Metrics
    st.markdown("### Change Management Metrics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Success Metrics:**
        - Change success rate (>95%)
        - Emergency changes (<5%)
        - Unauthorized changes (0%)
        - Change-related incidents
        """)
    
    with col2:
        st.markdown("""
        **Performance Metrics:**
        - Average approval time
        - Implementation success rate
        - Rollback frequency
        - Stakeholder satisfaction
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Risk Management:</strong> Systematic assessment prevents costly failures</li>
            <li><strong>Stakeholder Involvement:</strong> Include all affected parties in decision making</li>
            <li><strong>Documentation:</strong> Maintain detailed records for audit and improvement</li>
            <li><strong>Continuous Improvement:</strong> Learn from successes and failures</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
