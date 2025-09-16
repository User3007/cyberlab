import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_cryptographic_attacks():
    """Cryptographic Attacks using TDD pattern"""
    
    st.markdown("## Cryptographic Attacks")
    st.markdown("**Definition:** Methods used to break or exploit cryptographic systems and algorithms.")
    
    st.markdown("---")
    
    # Attack Types
    st.markdown("### Attack Types")
    
    attacks_data = {
        "Attack Type": ["Brute Force", "Dictionary Attack", "Rainbow Table", "Side-Channel", "Man-in-the-Middle", "Timing Attack"],
        "Target": [
            "Passwords, keys",
            "Passwords",
            "Password hashes",
            "Implementation vulnerabilities",
            "Communication channels",
            "Implementation timing"
        ],
        "Method": [
            "Try all possible combinations",
            "Use common password lists",
            "Precomputed hash tables",
            "Analyze power consumption, timing",
            "Intercept and modify communications",
            "Analyze response times"
        ],
        "Prevention": [
            "Strong passwords, key length",
            "Password policies, complexity",
            "Salt, key stretching",
            "Secure implementation",
            "Authentication, encryption",
            "Constant-time algorithms"
        ]
    }
    
    df = pd.DataFrame(attacks_data)
    st.dataframe(df, use_container_width=True)
    
    # Attack Complexity
    st.markdown("### Attack Complexity Comparison")
    
    complexity_data = {
        "Attack": ["Brute Force (4 chars)", "Brute Force (8 chars)", "Dictionary Attack", "Rainbow Table", "Side-Channel"],
        "Time": ["Seconds", "Years", "Minutes", "Seconds", "Hours"],
        "Resources": ["Low", "Very High", "Low", "Medium", "Medium"],
        "Success Rate": ["100%", "100%", "High", "High", "High"]
    }
    
    df2 = pd.DataFrame(complexity_data)
    st.dataframe(df2, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Defense in Depth:</strong> Use multiple protection mechanisms</li>
            <li><strong>Key Management:</strong> Proper key generation and storage</li>
            <li><strong>Implementation Security:</strong> Secure coding practices</li>
            <li><strong>Regular Updates:</strong> Keep cryptographic libraries updated</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
