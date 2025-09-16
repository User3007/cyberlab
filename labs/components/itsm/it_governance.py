import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_it_governance():
    """IT Governance using TDD pattern"""
    
    st.markdown("## IT Governance")
    st.markdown("**Definition:** Framework of processes, structures, and mechanisms that ensure IT investments support business objectives while managing risks and optimizing value delivery.")
    
    st.markdown("---")
    
    # IT Governance Framework
    st.markdown("### IT Governance Framework Components")
    
    framework_data = {
        "Component": ["Strategy & Planning", "Risk Management", "Resource Management", "Performance Management", "Compliance"],
        "Description": [
            "IT strategy alignment with business goals",
            "Identification and mitigation of IT risks",
            "Optimal allocation of IT resources",
            "Monitoring and measuring IT performance",
            "Adherence to regulations and standards"
        ],
        "Key Activities": [
            "Strategic planning, portfolio management",
            "Risk assessment, control implementation",
            "Budget planning, capacity management",
            "KPI tracking, performance reporting",
            "Audit preparation, regulatory reporting"
        ],
        "Stakeholders": [
            "Executive leadership, business units",
            "Risk managers, security teams",
            "IT managers, finance teams",
            "Service managers, business users",
            "Compliance officers, auditors"
        ]
    }
    
    df = pd.DataFrame(framework_data)
    st.dataframe(df, use_container_width=True)
    
    # COBIT Framework
    st.markdown("### COBIT 2019 Framework")
    
    cobit_data = {
        "Domain": ["Evaluate, Direct and Monitor", "Align, Plan and Organize", "Build, Acquire and Implement", "Deliver, Service and Support"],
        "Focus": [
            "Governance and oversight",
            "Strategy and planning",
            "Development and acquisition",
            "Service delivery and support"
        ],
        "Key Processes": [
            "Governance framework, benefits realization",
            "IT strategy, architecture management",
            "Solution development, change management",
            "Service operations, incident management"
        ],
        "Outcomes": [
            "Effective governance, stakeholder satisfaction",
            "Strategic alignment, optimized investments",
            "Quality solutions, managed changes",
            "Reliable services, satisfied users"
        ]
    }
    
    df2 = pd.DataFrame(cobit_data)
    st.dataframe(df2, use_container_width=True)
    
    # Governance Structures
    st.markdown("### IT Governance Structures")
    
    structures_data = {
        "Structure": ["IT Steering Committee", "Enterprise Architecture Board", "Risk Committee", "Investment Committee"],
        "Purpose": [
            "Strategic oversight and decision making",
            "Technical standards and architecture",
            "Risk management and compliance",
            "IT investment prioritization"
        ],
        "Composition": [
            "Senior executives, business leaders",
            "Chief architect, technical leads",
            "Risk managers, security officers",
            "CFO, business unit heads"
        ],
        "Frequency": [
            "Monthly/Quarterly",
            "Bi-weekly/Monthly",
            "Quarterly",
            "Quarterly/As needed"
        ]
    }
    
    df3 = pd.DataFrame(structures_data)
    st.dataframe(df3, use_container_width=True)
    
    # Governance Metrics
    st.markdown("### IT Governance Metrics")
    
    metrics_data = {
        "Category": ["Strategic Alignment", "Value Delivery", "Risk Management", "Resource Optimization", "Performance"],
        "Key Metrics": [
            "% of IT projects aligned with business strategy",
            "ROI on IT investments, business value delivered",
            "Number of security incidents, compliance score",
            "IT cost per employee, resource utilization",
            "System availability, user satisfaction"
        ],
        "Target Range": [
            ">80% alignment",
            ">15% ROI",
            "<5 incidents/month, >95% compliance",
            "Industry benchmark ±10%",
            ">99% uptime, >4.0/5.0 satisfaction"
        ]
    }
    
    df4 = pd.DataFrame(metrics_data)
    st.dataframe(df4, use_container_width=True)
    
    # Governance Maturity
    st.markdown("### IT Governance Maturity Levels")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Level 1 - Initial:**
        - Ad hoc processes
        - Reactive approach
        - Limited oversight
        """)
        
        st.markdown("""
        **Level 2 - Managed:**
        - Basic processes defined
        - Some governance structures
        - Project-level management
        """)
    
    with col2:
        st.markdown("""
        **Level 3 - Defined:**
        - Standardized processes
        - Formal governance bodies
        - Enterprise-wide approach
        """)
        
        st.markdown("""
        **Level 4 - Optimized:**
        - Continuous improvement
        - Metrics-driven decisions
        - Strategic value focus
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Strategic Alignment:</strong> Ensure IT investments support business objectives</li>
            <li><strong>Risk Management:</strong> Proactively identify and manage IT-related risks</li>
            <li><strong>Value Optimization:</strong> Maximize return on IT investments</li>
            <li><strong>Continuous Improvement:</strong> Regularly assess and improve governance maturity</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
