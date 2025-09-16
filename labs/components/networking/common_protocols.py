import streamlit as st
import pandas as pd

def explain_common_protocols():
    """Common Protocols using TDD pattern"""
    
    st.markdown("## Common Network Protocols")
    st.markdown("**Definition:** Standardized rules and procedures for communication between network devices.")
    
    st.markdown("---")
    
    # Protocol Categories
    st.markdown("### Protocol Categories")
    
    protocols_data = {
        "Protocol": ["HTTP/HTTPS", "FTP", "SMTP", "DNS", "DHCP", "SNMP", "SSH", "Telnet"],
        "Port": ["80/443", "21", "25", "53", "67/68", "161", "22", "23"],
        "Purpose": [
            "Web browsing",
            "File transfer",
            "Email sending",
            "Domain resolution",
            "IP assignment",
            "Network management",
            "Secure shell",
            "Remote terminal"
        ]
    }
    
    df = pd.DataFrame(protocols_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Port Knowledge:</strong> Understand common port assignments</li>
            <li><strong>Security Implications:</strong> Know security risks of each protocol</li>
            <li><strong>Protocol Selection:</strong> Choose appropriate protocol for task</li>
            <li><strong>Modern Alternatives:</strong> Use secure versions when available</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
