import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_mitre_attack():
    """MITRE ATT&CK Framework using TDD pattern"""
    
    st.markdown("## MITRE ATT&CK Framework")
    st.markdown("**Definition:** Globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.")
    
    st.markdown("---")
    
    # ATT&CK Tactics
    st.markdown("### ATT&CK Tactics")
    
    tactics_data = {
        "Tactic": ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"],
        "Description": [
            "Gain initial access to target",
            "Execute malicious code",
            "Maintain persistent access",
            "Escalate privileges",
            "Evade security controls",
            "Access credentials",
            "Gather information",
            "Move through network",
            "Gather data of interest",
            "Communicate with C2",
            "Steal data",
            "Disrupt operations"
        ]
    }
    
    df = pd.DataFrame(tactics_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Comprehensive Coverage:</strong> Covers entire attack lifecycle</li>
            <li><strong>Real-world Based:</strong> Based on actual attack observations</li>
            <li><strong>Defense Mapping:</strong> Helps map defensive controls</li>
            <li><strong>Threat Intelligence:</strong> Supports threat hunting and analysis</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
