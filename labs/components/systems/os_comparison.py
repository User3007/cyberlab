import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_os_comparison():
    """Operating System Comparison using TDD pattern"""
    
    st.markdown("## Operating System Comparison")
    st.markdown("**Definition:** Analysis of different operating systems including Windows, Linux, and macOS, comparing their features, strengths, and use cases.")
    
    st.markdown("---")
    
    # OS Overview
    st.markdown("### Major Operating Systems Overview")
    
    os_overview_data = {
        "Operating System": ["Windows", "Linux", "macOS", "Unix"],
        "Developer": ["Microsoft", "Open Source Community", "Apple", "Various (AT&T origin)"],
        "Architecture": ["Monolithic/Hybrid", "Monolithic", "Hybrid (XNU)", "Monolithic"],
        "License": ["Proprietary", "Open Source (GPL)", "Proprietary", "Various"],
        "Primary Use": [
            "Desktop, Enterprise, Gaming",
            "Servers, Embedded, Desktop",
            "Creative, Development, Desktop",
            "Servers, Workstations"
        ]
    }
    
    df = pd.DataFrame(os_overview_data)
    st.dataframe(df, use_container_width=True)
    
    # Feature Comparison
    st.markdown("### Feature Comparison")
    
    features_data = {
        "Feature": ["User Interface", "Security Model", "File System", "Package Management", "Hardware Support"],
        "Windows": [
            "GUI-focused, PowerShell CLI",
            "UAC, Windows Defender, BitLocker",
            "NTFS, FAT32, exFAT",
            "Windows Store, MSI, executable files",
            "Extensive driver support"
        ],
        "Linux": [
            "Multiple DEs, powerful CLI",
            "Permissions, SELinux, AppArmor",
            "ext4, XFS, Btrfs, ZFS",
            "APT, YUM, Pacman, Snap",
            "Good support, open drivers"
        ],
        "macOS": [
            "Aqua GUI, Terminal",
            "Gatekeeper, FileVault, SIP",
            "APFS, HFS+",
            "App Store, Homebrew, DMG",
            "Optimized for Apple hardware"
        ]
    }
    
    df2 = pd.DataFrame(features_data)
    st.dataframe(df2, use_container_width=True)
    
    # Market Share Visualization
    st.markdown("### Desktop OS Market Share")
    
    # Create pie chart for market share
    os_names = ['Windows', 'macOS', 'Linux', 'Others']
    market_share = [76.0, 15.0, 3.0, 6.0]  # Approximate values
    colors = ['#0078d4', '#000000', '#fcc624', '#cccccc']
    
    fig = go.Figure(data=[go.Pie(
        labels=os_names, 
        values=market_share,
        marker_colors=colors,
        textinfo='label+percent',
        textposition='auto'
    )])
    
    fig.update_layout(
        title="Desktop Operating System Market Share (2024)",
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Use Case Comparison
    st.markdown("### Use Case Comparison")
    
    use_cases_data = {
        "Use Case": ["Enterprise Desktop", "Web Servers", "Development", "Gaming", "Creative Work", "Mobile Devices"],
        "Best OS": ["Windows", "Linux", "Linux/macOS", "Windows", "macOS", "Android/iOS"],
        "Reason": [
            "Active Directory, Office integration",
            "Stability, security, cost-effectiveness",
            "Development tools, package managers",
            "DirectX, game compatibility",
            "Creative software ecosystem",
            "Touch interfaces, app ecosystems"
        ],
        "Market Share": ["~80%", "~70%", "~50%", "~95%", "~60%", "Android 70%, iOS 28%"]
    }
    
    df3 = pd.DataFrame(use_cases_data)
    st.dataframe(df3, use_container_width=True)
    
    # Strengths and Weaknesses
    st.markdown("### Strengths and Weaknesses")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        **Windows**
        
        *Strengths:*
        - User-friendly interface
        - Extensive software compatibility
        - Strong enterprise features
        - Gaming support
        
        *Weaknesses:*
        - Security vulnerabilities
        - License costs
        - Resource intensive
        - Less customizable
        """)
    
    with col2:
        st.markdown("""
        **Linux**
        
        *Strengths:*
        - Open source and free
        - Highly customizable
        - Excellent security
        - Lightweight options
        
        *Weaknesses:*
        - Learning curve
        - Limited commercial software
        - Hardware compatibility issues
        - Fragmentation
        """)
    
    with col3:
        st.markdown("""
        **macOS**
        
        *Strengths:*
        - Excellent user experience
        - Strong security
        - Creative software ecosystem
        - Unix-based reliability
        
        *Weaknesses:*
        - Expensive hardware
        - Limited hardware choices
        - Less enterprise adoption
        - Proprietary ecosystem
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Use Case Matters:</strong> Choose OS based on specific requirements and use cases</li>
            <li><strong>No Perfect OS:</strong> Each OS has strengths and weaknesses</li>
            <li><strong>Consider Total Cost:</strong> Include licensing, support, and training costs</li>
            <li><strong>Future Trends:</strong> Cloud computing and containerization reduce OS dependency</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
