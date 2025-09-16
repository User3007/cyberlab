import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_ethical_hacking_guidelines():
    """Ethical Hacking Guidelines using TDD pattern"""
    
    st.markdown("## Ethical Hacking Guidelines")
    st.markdown("**Definition:** Principles and standards governing authorized security testing and vulnerability assessment activities.")
    
    st.markdown("---")
    
    # Ethical Hacking Principles
    st.markdown("### Core Ethical Principles")
    
    principles_data = {
        "Principle": ["Authorization", "Scope Limitation", "Data Protection", "Disclosure", "No Harm"],
        "Description": [
            "Obtain explicit written permission",
            "Stay within defined testing boundaries",
            "Protect discovered sensitive data",
            "Report vulnerabilities responsibly",
            "Avoid causing system damage"
        ],
        "Implementation": [
            "Signed contracts, legal agreements",
            "Clear scope documents, IP ranges",
            "Data handling procedures, NDAs",
            "Coordinated disclosure timelines",
            "Safe testing methodologies"
        ]
    }
    
    df = pd.DataFrame(principles_data)
    st.dataframe(df, use_container_width=True)
    
    # Legal Framework
    st.markdown("### Legal Framework")
    
    legal_data = {
        "Aspect": ["Authorization", "Documentation", "Compliance", "Liability", "Reporting"],
        "Requirements": [
            "Written permission from system owner",
            "Detailed testing methodology and scope",
            "Follow industry standards and regulations",
            "Clear liability limitations and insurance",
            "Formal vulnerability reporting process"
        ],
        "Best Practices": [
            "Multiple stakeholder approval",
            "Version-controlled test plans",
            "Regular compliance audits",
            "Professional liability coverage",
            "Encrypted communication channels"
        ]
    }
    
    df2 = pd.DataFrame(legal_data)
    st.dataframe(df2, use_container_width=True)
    
    # Certification Standards
    st.markdown("### Professional Standards")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Industry Certifications:**
        - CEH (Certified Ethical Hacker)
        - OSCP (Offensive Security)
        - CISSP (Security Professional)
        - CISA (Information Systems Auditor)
        """)
    
    with col2:
        st.markdown("""
        **Professional Organizations:**
        - EC-Council
        - (ISC)² 
        - ISACA
        - SANS Institute
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Legal Authorization:</strong> Always obtain written permission before testing</li>
            <li><strong>Professional Standards:</strong> Follow established ethical guidelines and certifications</li>
            <li><strong>Responsible Disclosure:</strong> Report vulnerabilities through proper channels</li>
            <li><strong>Continuous Education:</strong> Stay updated on legal and ethical requirements</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
