import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_service_level_management():
    """Service Level Management using TDD pattern"""
    
    st.markdown("## Service Level Management")
    st.markdown("**Definition:** Process of negotiating, agreeing, monitoring, and reporting on service level agreements (SLAs) to ensure IT services meet business requirements.")
    
    st.markdown("---")
    
    # SLA Components
    st.markdown("### Service Level Agreement Components")
    
    sla_components_data = {
        "Component": ["Service Description", "Performance Metrics", "Availability Targets", "Response Times", "Penalties/Incentives"],
        "Description": [
            "Clear definition of services provided",
            "Measurable performance indicators",
            "Uptime requirements and maintenance windows",
            "Time limits for incident response and resolution",
            "Consequences for not meeting targets"
        ],
        "Example": [
            "Email service, database hosting",
            "99.9% uptime, <2s response time",
            "99.5% availability, 4-hour maintenance window",
            "P1: 15 min response, 4hr resolution",
            "Service credits, performance bonuses"
        ],
        "Measurement": [
            "Service catalog definition",
            "Automated monitoring tools",
            "Uptime monitoring, planned downtime",
            "Ticket system timestamps",
            "Financial reporting, customer satisfaction"
        ]
    }
    
    df = pd.DataFrame(sla_components_data)
    st.dataframe(df, use_container_width=True)
    
    # SLA Types
    st.markdown("### Types of Service Level Agreements")
    
    sla_types_data = {
        "SLA Type": ["Internal SLA", "External SLA", "Multi-level SLA"],
        "Parties": [
            "IT department and internal business units",
            "Service provider and external customer",
            "Multiple service providers and customer"
        ],
        "Characteristics": [
            "Internal commitments, cost centers",
            "Legal contracts, commercial terms",
            "Complex relationships, shared responsibilities"
        ],
        "Examples": [
            "IT helpdesk to HR department",
            "Cloud provider to enterprise customer",
            "Prime contractor with subcontractors"
        ]
    }
    
    df2 = pd.DataFrame(sla_types_data)
    st.dataframe(df2, use_container_width=True)
    
    # SLA Metrics
    st.markdown("### Common SLA Metrics")
    
    metrics_data = {
        "Metric Category": ["Availability", "Performance", "Quality", "Support"],
        "Key Metrics": [
            "Uptime %, Planned downtime",
            "Response time, Throughput",
            "Error rate, Defect density",
            "Response time, Resolution time"
        ],
        "Typical Targets": [
            "99.9% uptime, <4hrs maintenance",
            "<2s response, >1000 TPS",
            "<1% error rate, <0.1% defects",
            "<1hr response, <24hr resolution"
        ],
        "Measurement Tools": [
            "Monitoring systems, uptime tools",
            "APM tools, load testing",
            "Error tracking, quality metrics",
            "Ticketing system, surveys"
        ]
    }
    
    df3 = pd.DataFrame(metrics_data)
    st.dataframe(df3, use_container_width=True)
    
    # SLA Management Process
    st.markdown("### SLA Management Process")
    
    process_data = {
        "Phase": ["Negotiate", "Agree", "Monitor", "Report", "Review"],
        "Activities": [
            "Define requirements, establish metrics",
            "Formalize SLA document, sign agreement",
            "Collect performance data, track metrics",
            "Generate reports, communicate status",
            "Assess performance, identify improvements"
        ],
        "Stakeholders": [
            "Business users, IT service provider",
            "Legal, procurement, service management",
            "Operations team, monitoring tools",
            "Service manager, business stakeholders",
            "All parties, continuous improvement team"
        ],
        "Deliverables": [
            "SLA requirements, draft agreement",
            "Signed SLA, service catalog update",
            "Performance dashboard, alerts",
            "Monthly/quarterly reports",
            "Improvement plan, updated SLA"
        ]
    }
    
    df4 = pd.DataFrame(process_data)
    st.dataframe(df4, use_container_width=True)
    
    # SLA Best Practices
    st.markdown("### SLA Best Practices")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **SLA Design:**
        - Realistic and achievable targets
        - Clear measurement criteria
        - Balanced penalties and incentives
        - Regular review cycles
        """)
    
    with col2:
        st.markdown("""
        **SLA Management:**
        - Automated monitoring
        - Regular reporting
        - Proactive communication
        - Continuous improvement
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Business Alignment:</strong> SLAs should reflect business priorities and requirements</li>
            <li><strong>Measurable Targets:</strong> Use specific, measurable, and achievable metrics</li>
            <li><strong>Continuous Monitoring:</strong> Implement automated monitoring and reporting</li>
            <li><strong>Regular Reviews:</strong> Periodically review and update SLAs based on performance</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
