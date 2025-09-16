import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_privacy_data_protection():
    """Privacy and Data Protection using TDD pattern"""
    
    st.markdown("## Privacy and Data Protection")
    st.markdown("**Definition:** Legal and regulatory frameworks governing the collection, processing, and protection of personal data.")
    
    st.markdown("---")
    
    # Major Regulations
    st.markdown("### Major Privacy Regulations")
    
    regulations_data = {
        "Regulation": ["GDPR", "CCPA", "HIPAA", "SOX", "PCI DSS"],
        "Region/Scope": ["EU/Global", "California/US", "Healthcare/US", "Public Companies/US", "Payment Cards/Global"],
        "Key Requirements": [
            "Consent, data minimization, right to erasure",
            "Consumer rights, opt-out, data disclosure",
            "Protected health information security",
            "Financial reporting integrity",
            "Cardholder data protection"
        ],
        "Penalties": [
            "Up to 4% of annual revenue",
            "Up to $7,500 per violation",
            "Up to $1.5M per incident",
            "Criminal and civil penalties",
            "Fines and card brand sanctions"
        ]
    }
    
    df = pd.DataFrame(regulations_data)
    st.dataframe(df, use_container_width=True)
    
    # Privacy Principles
    st.markdown("### Privacy by Design Principles")
    
    principles_data = {
        "Principle": ["Lawfulness", "Purpose Limitation", "Data Minimization", "Accuracy", "Storage Limitation", "Security", "Accountability"],
        "Description": [
            "Legal basis for data processing",
            "Data used only for stated purposes",
            "Collect only necessary data",
            "Keep data accurate and up-to-date",
            "Retain data only as long as needed",
            "Appropriate technical and organizational measures",
            "Demonstrate compliance with regulations"
        ]
    }
    
    df2 = pd.DataFrame(principles_data)
    st.dataframe(df2, use_container_width=True)
    
    # Data Subject Rights
    st.markdown("### Data Subject Rights (GDPR)")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Individual Rights:**
        - Right to information
        - Right of access
        - Right to rectification
        - Right to erasure
        """)
    
    with col2:
        st.markdown("""
        **Additional Rights:**
        - Right to restrict processing
        - Right to data portability
        - Right to object
        - Rights related to automated decision making
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Global Compliance:</strong> Privacy laws vary by jurisdiction and industry</li>
            <li><strong>Privacy by Design:</strong> Build privacy protections into systems from the start</li>
            <li><strong>Data Governance:</strong> Implement comprehensive data management policies</li>
            <li><strong>Regular Audits:</strong> Continuously monitor and assess privacy compliance</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
