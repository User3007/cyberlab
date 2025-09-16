import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_cyber_kill_chain():
    """Main function to render Cyber Kill Chain component"""
    
    st.markdown("## Cyber Kill Chain")
    st.markdown("**Definition:** Framework for understanding and defending against cyber attacks through their progression stages.")
    
    st.markdown("---")
    
    # Kill Chain Stages
    st.markdown("### Kill Chain Stages")
    
    stages_data = {
        "Stage": ["1. Reconnaissance", "2. Weaponization", "3. Delivery", "4. Exploitation", "5. Installation", "6. C&C", "7. Actions"],
        "Description": [
            "Gather information about target",
            "Create malicious payload",
            "Deliver payload to target",
            "Exploit vulnerability",
            "Install persistent access",
            "Establish command and control",
            "Achieve objectives"
        ]
    }
    
    df = pd.DataFrame(stages_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Early Detection:</strong> Focus on early stages for prevention</li>
            <li><strong>Layered Defense:</strong> Implement controls at each stage</li>
            <li><strong>Threat Intelligence:</strong> Use framework for attack analysis</li>
            <li><strong>Continuous Monitoring:</strong> Track progression through stages</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
