import streamlit as st
import pandas as pd

def explain_ip_subnetting():
    """IP Subnetting using TDD pattern"""
    
    st.markdown("## IP Subnetting")
    st.markdown("**Definition:** Process of dividing a network into smaller, more manageable sub-networks.")
    
    st.markdown("---")
    
    # Subnetting Concepts
    st.markdown("### Subnetting Concepts")
    
    concepts_data = {
        "Concept": ["Subnet Mask", "CIDR Notation", "Network ID", "Host ID", "Broadcast Address"],
        "Description": [
            "Identifies network portion of IP address",
            "Compact notation for subnet masks",
            "Identifies the network",
            "Identifies specific host",
            "Address for all hosts in subnet"
        ]
    }
    
    df = pd.DataFrame(concepts_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Efficient Addressing:</strong> Optimize IP address usage</li>
            <li><strong>Network Segmentation:</strong> Improve security and performance</li>
            <li><strong>Subnet Planning:</strong> Plan for current and future needs</li>
            <li><strong>CIDR Benefits:</strong> Flexible and scalable addressing</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
