import streamlit as st
import pandas as pd

def explain_network_devices():
    """Network Devices using TDD pattern"""
    
    st.markdown("## Network Devices")
    st.markdown("**Definition:** Hardware components that enable communication and data transfer in computer networks.")
    
    st.markdown("---")
    
    # Network Device Types
    st.markdown("### Network Device Types")
    
    devices_data = {
        "Device": ["Hub", "Switch", "Router", "Firewall", "Access Point", "Modem"],
        "Layer": ["Physical", "Data Link", "Network", "Network", "Data Link", "Physical"],
        "Function": [
            "Broadcast to all ports",
            "Forward based on MAC address",
            "Route between networks",
            "Filter network traffic",
            "Wireless connectivity",
            "Convert digital to analog"
        ]
    }
    
    df = pd.DataFrame(devices_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Layer Understanding:</strong> Know which OSI layer each device operates</li>
            <li><strong>Function Selection:</strong> Choose right device for specific needs</li>
            <li><strong>Security Considerations:</strong> Implement appropriate security measures</li>
            <li><strong>Performance Impact:</strong> Consider device impact on network performance</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
