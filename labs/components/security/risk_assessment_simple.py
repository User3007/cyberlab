import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_risk_assessment():
    """Main function for Risk Assessment"""
    
    st.markdown("## Risk Assessment")
    st.markdown("**Definition:** Systematic process of identifying, analyzing, and evaluating risks to information assets.")
    
    st.markdown("---")
    
    # Risk Assessment Process
    st.markdown("### Risk Assessment Process")
    
    steps_data = {
        "Step": ["1. Asset Identification", "2. Threat Analysis", "3. Vulnerability Assessment", "4. Risk Calculation", "5. Risk Treatment"],
        "Description": [
            "Identify and catalog information assets",
            "Identify potential threats and threat actors",
            "Assess system vulnerabilities",
            "Calculate risk levels",
            "Develop risk treatment strategies"
        ]
    }
    
    df = pd.DataFrame(steps_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Systematic Approach:</strong> Follow structured risk assessment methodology</li>
            <li><strong>Quantitative Analysis:</strong> Use risk formulas for objective evaluation</li>
            <li><strong>Continuous Process:</strong> Regular reassessment as threats evolve</li>
            <li><strong>Business Alignment:</strong> Align risk management with business objectives</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
