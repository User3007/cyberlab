import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_risk_management_pm():
    """Project Risk Management using TDD pattern"""
    
    st.markdown("## Project Risk Management")
    st.markdown("**Definition:** Process of identifying, analyzing, and responding to project risks to minimize their impact on project success.")
    
    st.markdown("---")
    
    # Risk Management Process
    st.markdown("### Risk Management Process")
    
    process_data = {
        "Step": ["1. Risk Identification", "2. Risk Analysis", "3. Risk Assessment", "4. Risk Response", "5. Risk Monitoring"],
        "Description": [
            "Identify potential project risks",
            "Analyze probability and impact",
            "Prioritize risks by severity",
            "Develop response strategies",
            "Track and review risks"
        ],
        "Tools": [
            "Brainstorming, checklists",
            "Probability/impact matrix",
            "Risk register",
            "Mitigation, avoidance, acceptance",
            "Risk dashboard, reports"
        ]
    }
    
    df = pd.DataFrame(process_data)
    st.dataframe(df, use_container_width=True)
    
    # Risk Response Strategies
    st.markdown("### Risk Response Strategies")
    
    strategies_data = {
        "Strategy": ["Avoid", "Mitigate", "Transfer", "Accept"],
        "Description": [
            "Eliminate the risk entirely",
            "Reduce probability or impact",
            "Shift risk to third party",
            "Acknowledge and monitor risk"
        ],
        "When to Use": [
            "High impact, low probability",
            "Medium impact risks",
            "Financial or legal risks",
            "Low impact, high probability"
        ]
    }
    
    df2 = pd.DataFrame(strategies_data)
    st.dataframe(df2, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Proactive Approach:</strong> Identify risks early in project lifecycle</li>
            <li><strong>Regular Review:</strong> Continuously monitor and update risk register</li>
            <li><strong>Team Involvement:</strong> Engage entire team in risk identification</li>
            <li><strong>Documentation:</strong> Maintain detailed risk documentation</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
