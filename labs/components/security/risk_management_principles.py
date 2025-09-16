import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_risk_management_principles():
    """Risk Management Principles using TDD pattern"""
    
    st.markdown("## Risk Management Principles")
    st.markdown("**Definition:** Fundamental concepts and practices for identifying, assessing, and managing security risks.")
    
    st.markdown("---")
    
    # Risk Management Framework
    st.markdown("### Risk Management Framework")
    
    framework_data = {
        "Phase": ["Identify", "Assess", "Treat", "Monitor", "Review"],
        "Activities": [
            "Identify assets, threats, and vulnerabilities",
            "Analyze likelihood and impact",
            "Implement risk treatment strategies",
            "Continuously monitor risk indicators",
            "Regular review and update of risk profile"
        ],
        "Outputs": [
            "Risk register, asset inventory",
            "Risk assessment matrix",
            "Risk treatment plan",
            "Risk dashboard, reports",
            "Updated risk register"
        ]
    }
    
    df = pd.DataFrame(framework_data)
    st.dataframe(df, use_container_width=True)
    
    # Risk Treatment Strategies
    st.markdown("### Risk Treatment Strategies")
    
    strategies_data = {
        "Strategy": ["Accept", "Avoid", "Mitigate", "Transfer"],
        "Description": [
            "Accept the risk and its consequences",
            "Eliminate the risk source",
            "Reduce likelihood or impact",
            "Share risk with third party"
        ],
        "When to Use": [
            "Low impact, acceptable cost",
            "High impact, avoidable",
            "Medium impact, controllable",
            "Financial or specialized risks"
        ]
    }
    
    df2 = pd.DataFrame(strategies_data)
    st.dataframe(df2, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Risk Appetite:</strong> Define acceptable risk levels</li>
            <li><strong>Continuous Process:</strong> Risk management is ongoing</li>
            <li><strong>Business Alignment:</strong> Align with business objectives</li>
            <li><strong>Stakeholder Involvement:</strong> Engage all relevant parties</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
