import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_devops_culture():
    """DevOps Culture using TDD pattern"""
    
    st.markdown("## DevOps Culture")
    st.markdown("**Definition:** Cultural movement that emphasizes collaboration between development and operations teams.")
    
    st.markdown("---")
    
    # DevOps Pillars
    st.markdown("### DevOps Pillars")
    
    pillars_data = {
        "Pillar": ["Collaboration", "Automation", "Measurement", "Sharing"],
        "Description": [
            "Break down silos between teams",
            "Automate repetitive processes",
            "Monitor and measure everything",
            "Share knowledge and practices"
        ],
        "Benefits": [
            "Faster delivery",
            "Reduced errors",
            "Data-driven decisions",
            "Continuous learning"
        ]
    }
    
    df = pd.DataFrame(pillars_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Culture First:</strong> DevOps starts with cultural change</li>
            <li><strong>Shared Responsibility:</strong> Everyone owns quality and reliability</li>
            <li><strong>Continuous Learning:</strong> Embrace failure as learning opportunity</li>
            <li><strong>Customer Focus:</strong> Deliver value to customers faster</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_continuous_deployment():
    """Continuous Deployment using TDD pattern"""
    
    st.markdown("## Continuous Deployment")
    st.markdown("**Definition:** Automated deployment of code changes to production environments.")
    
    st.markdown("---")
    
    # CD Pipeline
    st.markdown("### CD Pipeline Stages")
    
    stages = [
        "Code Commit",
        "Build",
        "Test",
        "Deploy to Staging",
        "Deploy to Production"
    ]
    
    for i, stage in enumerate(stages, 1):
        st.markdown(f"**{i}. {stage}**")
        st.markdown(f"   - Automated trigger on code changes")
        st.markdown(f"   - Compile and package application")
        st.markdown(f"   - Run automated test suite")
        st.markdown(f"   - Deploy to staging environment")
        st.markdown(f"   - Deploy to production with monitoring")
        st.markdown("")
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Automation is Key:</strong> Minimize manual intervention</li>
            <li><strong>Fast Feedback:</strong> Quick detection of issues</li>
            <li><strong>Rollback Strategy:</strong> Plan for quick rollbacks</li>
            <li><strong>Monitoring:</strong> Continuous monitoring in production</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_infrastructure_as_code():
    """Infrastructure as Code using TDD pattern"""
    
    st.markdown("## Infrastructure as Code")
    st.markdown("**Definition:** Managing and provisioning infrastructure through code and automation.")
    
    st.markdown("---")
    
    # IaC Benefits
    st.markdown("### IaC Benefits")
    
    benefits_data = {
        "Benefit": ["Version Control", "Consistency", "Automation", "Documentation", "Testing"],
        "Description": [
            "Track infrastructure changes",
            "Identical environments",
            "Reduce manual errors",
            "Self-documenting infrastructure",
            "Test infrastructure changes"
        ]
    }
    
    df = pd.DataFrame(benefits_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Treat Infrastructure as Code:</strong> Apply software practices to infrastructure</li>
            <li><strong>Immutable Infrastructure:</strong> Replace rather than modify</li>
            <li><strong>Idempotent Operations:</strong> Safe to run multiple times</li>
            <li><strong>Environment Parity:</strong> Keep environments consistent</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_monitoring_logging():
    """Monitoring and Logging using TDD pattern"""
    
    st.markdown("## Monitoring and Logging")
    st.markdown("**Definition:** Continuous observation and recording of system behavior and performance.")
    
    st.markdown("---")
    
    # Monitoring Types
    st.markdown("### Monitoring Types")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Application Monitoring:**
        - Response times
        - Error rates
        - Throughput
        - User experience
        """)
    
    with col2:
        st.markdown("""
        **Infrastructure Monitoring:**
        - CPU usage
        - Memory usage
        - Disk I/O
        - Network traffic
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Monitor Everything:</strong> Track all critical metrics</li>
            <li><strong>Set Alerts:</strong> Proactive issue detection</li>
            <li><strong>Centralized Logging:</strong> Aggregate logs for analysis</li>
            <li><strong>Dashboards:</strong> Visualize system health</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
