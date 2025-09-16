import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_system_monitoring():
    """System Monitoring using TDD pattern"""
    
    st.markdown("## System Monitoring")
    st.markdown("**Definition:** Continuous observation and measurement of system performance, availability, and security to ensure optimal operation.")
    
    st.markdown("---")
    
    # Monitoring Categories
    st.markdown("### Monitoring Categories")
    
    monitoring_data = {
        "Category": ["Performance", "Availability", "Security", "Capacity", "Application"],
        "Metrics": [
            "CPU, memory, disk I/O, network throughput",
            "Uptime, response time, service availability",
            "Failed logins, intrusion attempts, malware",
            "Storage usage, bandwidth utilization",
            "Response times, error rates, transactions"
        ],
        "Tools": [
            "Nagios, Zabbix, PRTG, SolarWinds",
            "Pingdom, UptimeRobot, StatusPage",
            "SIEM, IDS/IPS, Security scanners",
            "Capacity planning tools, trend analysis",
            "APM tools, New Relic, AppDynamics"
        ],
        "Thresholds": [
            "CPU >80%, Memory >85%, Disk >90%",
            "Uptime >99.9%, Response <2s",
            "Failed logins >5/min, Anomalies",
            "Storage >85%, Growth trends",
            "Error rate >1%, Response >5s"
        ]
    }
    
    df = pd.DataFrame(monitoring_data)
    st.dataframe(df, use_container_width=True)
    
    # Monitoring Architecture
    st.markdown("### Monitoring Architecture")
    
    architecture_data = {
        "Component": ["Agents", "Collectors", "Storage", "Analytics", "Alerting", "Dashboard"],
        "Function": [
            "Collect metrics from monitored systems",
            "Aggregate data from multiple agents",
            "Store historical monitoring data",
            "Process and analyze collected metrics",
            "Generate notifications for issues",
            "Visualize data and system status"
        ],
        "Examples": [
            "SNMP agents, WMI, custom scripts",
            "Fluentd, Logstash, Telegraf",
            "InfluxDB, Elasticsearch, Prometheus",
            "Machine learning, statistical analysis",
            "Email, SMS, Slack, PagerDuty",
            "Grafana, Kibana, custom web interfaces"
        ]
    }
    
    df2 = pd.DataFrame(architecture_data)
    st.dataframe(df2, use_container_width=True)
    
    # Alert Management
    st.markdown("### Alert Management Best Practices")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Alert Levels:**
        - Critical: Immediate action required
        - Warning: Attention needed soon
        - Info: Informational only
        - Debug: Troubleshooting data
        """)
    
    with col2:
        st.markdown("""
        **Alert Strategies:**
        - Escalation procedures
        - Alert correlation
        - Noise reduction
        - Response automation
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Comprehensive Coverage:</strong> Monitor all critical system components</li>
            <li><strong>Proactive Alerting:</strong> Set appropriate thresholds and escalation</li>
            <li><strong>Historical Analysis:</strong> Use trends to predict and prevent issues</li>
            <li><strong>Automation:</strong> Implement automated responses where possible</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
