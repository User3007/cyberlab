import streamlit as st
import pandas as pd

def explain_key_management():
    """Key Management using TDD pattern"""
    
    st.markdown("## Key Management")
    st.markdown("**Definition:** Processes and procedures for generating, storing, distributing, and destroying cryptographic keys.")
    
    st.markdown("---")
    
    # Key Management Lifecycle
    st.markdown("### Key Management Lifecycle")
    
    lifecycle_data = {
        "Phase": ["Generation", "Distribution", "Storage", "Rotation", "Revocation", "Destruction"],
        "Description": [
            "Create cryptographically strong keys",
            "Securely deliver keys to authorized parties",
            "Protect keys from unauthorized access",
            "Replace keys periodically",
            "Invalidate compromised keys",
            "Permanently delete old keys"
        ]
    }
    
    df = pd.DataFrame(lifecycle_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Security is Critical:</strong> Key compromise affects entire system</li>
            <li><strong>Lifecycle Management:</strong> Proper handling throughout key life</li>
            <li><strong>Access Control:</strong> Limit key access to authorized personnel</li>
            <li><strong>Regular Rotation:</strong> Change keys periodically for security</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
