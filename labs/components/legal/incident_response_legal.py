import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_incident_response_legal():
    """Legal Aspects of Incident Response using TDD pattern"""
    
    st.markdown("## Legal Aspects of Incident Response")
    st.markdown("**Definition:** Legal considerations, requirements, and procedures that must be followed during cybersecurity incident response.")
    
    st.markdown("---")
    
    # Legal Requirements
    st.markdown("### Legal and Regulatory Requirements")
    
    requirements_data = {
        "Requirement": ["Breach Notification", "Evidence Preservation", "Law Enforcement", "Regulatory Reporting", "Legal Privilege"],
        "Description": [
            "Notify affected parties within specified timeframes",
            "Maintain chain of custody for digital evidence",
            "Coordinate with law enforcement agencies",
            "Report incidents to relevant regulators",
            "Protect attorney-client privileged communications"
        ],
        "Timeline": [
            "72 hours (GDPR), varies by jurisdiction",
            "Immediate upon discovery",
            "As soon as practical",
            "Varies by regulation and severity",
            "Throughout incident response process"
        ],
        "Consequences": [
            "Regulatory fines, legal liability",
            "Evidence inadmissibility",
            "Criminal prosecution obstacles",
            "Regulatory sanctions",
            "Loss of legal protections"
        ]
    }
    
    df = pd.DataFrame(requirements_data)
    st.dataframe(df, use_container_width=True)
    
    # Evidence Handling
    st.markdown("### Digital Evidence Management")
    
    evidence_data = {
        "Phase": ["Identification", "Preservation", "Collection", "Analysis", "Presentation"],
        "Legal Considerations": [
            "Scope of legal authority, search warrants",
            "Chain of custody, write-blocking",
            "Forensically sound methods, documentation",
            "Expert qualifications, methodology validation",
            "Court admissibility, expert testimony"
        ],
        "Best Practices": [
            "Legal counsel involvement, documentation",
            "Forensic imaging, hash verification",
            "Detailed logging, witness statements",
            "Peer review, tool validation",
            "Clear reporting, visual aids"
        ]
    }
    
    df2 = pd.DataFrame(evidence_data)
    st.dataframe(df2, use_container_width=True)
    
    # Notification Requirements
    st.markdown("### Breach Notification Framework")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Internal Notifications:**
        - Executive leadership
        - Legal counsel
        - Privacy officer
        - Board of directors
        """)
    
    with col2:
        st.markdown("""
        **External Notifications:**
        - Regulatory authorities
        - Affected individuals
        - Law enforcement
        - Business partners
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Legal Counsel:</strong> Involve legal team early in incident response</li>
            <li><strong>Evidence Integrity:</strong> Maintain proper chain of custody procedures</li>
            <li><strong>Timely Notification:</strong> Meet regulatory and legal notification deadlines</li>
            <li><strong>Documentation:</strong> Maintain detailed records for legal proceedings</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
