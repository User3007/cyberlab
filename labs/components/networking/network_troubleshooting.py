import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_network_troubleshooting():
    """Network Troubleshooting using TDD pattern"""
    
    st.markdown("## Network Troubleshooting")
    st.markdown("**Definition:** Systematic process of identifying and resolving network connectivity and performance issues.")
    
    st.markdown("---")
    
    # Troubleshooting Steps
    st.markdown("### Troubleshooting Methodology")
    
    steps_data = {
        "Step": ["1. Identify Problem", "2. Gather Information", "3. Isolate Issue", "4. Test Solution", "5. Document"],
        "Description": [
            "Define the problem clearly",
            "Collect relevant data and logs",
            "Narrow down the root cause",
            "Verify the fix works",
            "Record solution for future reference"
        ]
    }
    
    df = pd.DataFrame(steps_data)
    st.dataframe(df, use_container_width=True)
    
    # Common Tools
    st.markdown("### Common Troubleshooting Tools")
    
    tools_data = {
        "Tool": ["ping", "traceroute", "netstat", "nslookup", "tcpdump", "Wireshark"],
        "Purpose": [
            "Test connectivity",
            "Trace network path",
            "Show network connections",
            "Resolve DNS names",
            "Capture packets",
            "Analyze network traffic"
        ]
    }
    
    df2 = pd.DataFrame(tools_data)
    st.dataframe(df2, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Systematic Approach:</strong> Follow structured troubleshooting process</li>
            <li><strong>Tool Mastery:</strong> Know your troubleshooting tools well</li>
            <li><strong>Documentation:</strong> Keep records of solutions and procedures</li>
            <li><strong>Prevention:</strong> Implement monitoring to prevent issues</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
