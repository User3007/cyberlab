import streamlit as st
import pandas as pd

def explain_performance_analysis():
    """Performance Analysis using TDD pattern"""
    
    st.markdown("## Performance Analysis")
    st.markdown("**Definition:** Process of measuring and optimizing system performance to ensure efficient operation.")
    
    st.markdown("---")
    
    # Performance Metrics
    st.markdown("### Performance Metrics")
    
    metrics_data = {
        "Metric": ["CPU Usage", "Memory Usage", "Disk I/O", "Network Throughput", "Response Time", "Throughput"],
        "Description": [
            "Percentage of CPU utilization",
            "Amount of RAM being used",
            "Disk read/write operations",
            "Data transfer rate",
            "Time to complete operations",
            "Operations per second"
        ]
    }
    
    df = pd.DataFrame(metrics_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Baseline Establishment:</strong> Measure performance under normal conditions</li>
            <li><strong>Bottleneck Identification:</strong> Find the limiting factor in system performance</li>
            <li><strong>Continuous Monitoring:</strong> Track performance over time</li>
            <li><strong>Optimization Strategies:</strong> Implement targeted improvements</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
