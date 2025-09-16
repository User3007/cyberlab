import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_itil_framework():
    """ITIL Framework using TDD pattern"""
    
    st.markdown("## ITIL Framework")
    st.markdown("**Definition:** Information Technology Infrastructure Library - a set of best practices for IT service management that focuses on aligning IT services with business needs.")
    
    st.markdown("---")
    
    # ITIL Service Lifecycle
    st.markdown("### ITIL 4 Service Value System")
    
    lifecycle_data = {
        "Component": ["Service Strategy", "Service Design", "Service Transition", "Service Operation", "Continual Improvement"],
        "Purpose": [
            "Define strategy and policies for IT services",
            "Design new or changed services",
            "Build and deploy services into production",
            "Deliver and support services day-to-day",
            "Continuously improve services and processes"
        ],
        "Key Activities": [
            "Portfolio management, financial management",
            "Service catalog, SLA design, capacity planning",
            "Change management, release management, testing",
            "Incident management, problem management, access management",
            "Process improvement, metrics analysis, reporting"
        ]
    }
    
    df = pd.DataFrame(lifecycle_data)
    st.dataframe(df, use_container_width=True)
    
    # ITIL 4 Practices
    st.markdown("### ITIL 4 Key Practices")
    
    practices_data = {
        "Practice Category": ["General Management", "Service Management", "Technical Management"],
        "Examples": [
            "Strategy management, Portfolio management, Architecture management",
            "Service catalog management, SLA management, Incident management",
            "Infrastructure management, Software development, Deployment management"
        ],
        "Focus": [
            "Overall governance and strategy",
            "Service delivery and support",
            "Technical implementation and operations"
        ]
    }
    
    df2 = pd.DataFrame(practices_data)
    st.dataframe(df2, use_container_width=True)
    
    # ITIL Benefits
    st.markdown("### ITIL Implementation Benefits")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Business Benefits:**
        - Improved customer satisfaction
        - Reduced costs and risks
        - Better resource utilization
        - Enhanced decision making
        """)
    
    with col2:
        st.markdown("""
        **Technical Benefits:**
        - Standardized processes
        - Improved service quality
        - Better incident resolution
        - Enhanced change control
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Service-Oriented:</strong> Focus on delivering value to customers</li>
            <li><strong>Process-Based:</strong> Standardized, repeatable processes</li>
            <li><strong>Continuous Improvement:</strong> Regular assessment and enhancement</li>
            <li><strong>Business Alignment:</strong> IT services aligned with business needs</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
