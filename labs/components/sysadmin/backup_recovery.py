import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_backup_recovery():
    """Backup and Recovery using TDD pattern"""
    
    st.markdown("## Backup and Recovery")
    st.markdown("**Definition:** Strategies and procedures for protecting data through regular backups and ensuring rapid recovery from system failures or data loss.")
    
    st.markdown("---")
    
    # Backup Types
    st.markdown("### Backup Types")
    
    backup_types_data = {
        "Type": ["Full Backup", "Incremental", "Differential", "Mirror", "Snapshot"],
        "Description": [
            "Complete copy of all selected data",
            "Only data changed since last backup",
            "Data changed since last full backup",
            "Exact replica maintained in real-time",
            "Point-in-time copy of data state"
        ],
        "Advantages": [
            "Complete data protection, simple restore",
            "Fast backup, minimal storage",
            "Faster restore than incremental",
            "Real-time protection, instant failover",
            "Fast backup, consistent data state"
        ],
        "Disadvantages": [
            "Slow backup, high storage requirements",
            "Complex restore, multiple files needed",
            "More storage than incremental",
            "High storage and bandwidth requirements",
            "Storage overhead, limited retention"
        ]
    }
    
    df = pd.DataFrame(backup_types_data)
    st.dataframe(df, use_container_width=True)
    
    # Recovery Strategies
    st.markdown("### Recovery Strategies")
    
    recovery_data = {
        "Strategy": ["Cold Site", "Warm Site", "Hot Site", "Cloud DR", "Mobile DR"],
        "Setup Time": ["Days-Weeks", "Hours-Days", "Minutes-Hours", "Minutes-Hours", "Hours-Days"],
        "Cost": ["Low", "Medium", "High", "Variable", "Medium"],
        "Data Currency": ["Outdated", "Recent", "Current", "Near Real-time", "Recent"],
        "Best For": [
            "Non-critical systems, cost-conscious",
            "Moderate criticality, balanced approach",
            "Mission-critical, minimal downtime",
            "Scalable, flexible requirements",
            "Temporary or remote operations"
        ]
    }
    
    df2 = pd.DataFrame(recovery_data)
    st.dataframe(df2, use_container_width=True)
    
    # 3-2-1 Rule
    st.markdown("### 3-2-1 Backup Rule")
    
    fig = go.Figure()
    
    # Create visual representation of 3-2-1 rule
    categories = ['3 Copies', '2 Different Media', '1 Offsite']
    values = [3, 2, 1]
    colors = ['lightblue', 'lightgreen', 'lightcoral']
    
    fig.add_trace(go.Bar(
        x=categories,
        y=values,
        marker_color=colors,
        text=[f'{v} copies', '2 media types', '1 offsite'],
        textposition='auto'
    ))
    
    fig.update_layout(
        title="3-2-1 Backup Rule",
        xaxis_title="Backup Components",
        yaxis_title="Count",
        height=300
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Recovery Metrics
    st.markdown("### Recovery Metrics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **RTO (Recovery Time Objective):**
        - Maximum acceptable downtime
        - Business impact consideration
        - Technology and process dependent
        - Measured in hours or days
        """)
    
    with col2:
        st.markdown("""
        **RPO (Recovery Point Objective):**
        - Maximum acceptable data loss
        - Backup frequency dependent
        - Business criticality based
        - Measured in minutes or hours
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Regular Testing:</strong> Test backup and recovery procedures regularly</li>
            <li><strong>Multiple Strategies:</strong> Use combination of backup types and locations</li>
            <li><strong>Documentation:</strong> Maintain detailed recovery procedures</li>
            <li><strong>Business Alignment:</strong> Align backup strategy with business requirements</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
