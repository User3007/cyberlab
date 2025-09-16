import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_security_hardening():
    """Security Hardening using TDD pattern"""
    
    st.markdown("## Security Hardening")
    st.markdown("**Definition:** Process of reducing system vulnerabilities by removing unnecessary services, applying security patches, and implementing security controls to minimize attack surface.")
    
    st.markdown("---")
    
    # Hardening Areas
    st.markdown("### System Hardening Areas")
    
    hardening_data = {
        "Area": ["Operating System", "Network Services", "Applications", "Database", "Web Server"],
        "Common Vulnerabilities": [
            "Default passwords, unnecessary services",
            "Open ports, weak protocols",
            "Unpatched software, misconfigurations",
            "Weak authentication, excessive privileges",
            "Directory traversal, injection attacks"
        ],
        "Hardening Measures": [
            "Disable unused services, strong passwords",
            "Close unused ports, secure protocols",
            "Regular updates, secure configuration",
            "Strong authentication, least privilege",
            "Input validation, secure headers"
        ],
        "Tools": [
            "CIS benchmarks, STIG guides",
            "Nmap, port scanners",
            "Vulnerability scanners",
            "Database security tools",
            "Web application scanners"
        ]
    }
    
    df = pd.DataFrame(hardening_data)
    st.dataframe(df, use_container_width=True)
    
    # Hardening Checklist
    st.markdown("### Security Hardening Checklist")
    
    checklist_data = {
        "Category": ["Account Security", "Service Management", "Network Security", "File System", "Logging & Monitoring"],
        "Actions": [
            "Remove default accounts, enforce password policy",
            "Disable unnecessary services, update software",
            "Configure firewall, secure protocols",
            "Set file permissions, encrypt sensitive data",
            "Enable audit logging, configure monitoring"
        ],
        "Priority": ["Critical", "High", "High", "Medium", "Medium"],
        "Verification": [
            "Account audit, password test",
            "Service inventory, vulnerability scan",
            "Port scan, protocol analysis",
            "Permission audit, encryption check",
            "Log review, alert testing"
        ]
    }
    
    df2 = pd.DataFrame(checklist_data)
    st.dataframe(df2, use_container_width=True)
    
    # CIS Controls
    st.markdown("### CIS Critical Security Controls")
    
    cis_data = {
        "Control": ["Inventory and Control", "Software Asset Management", "Data Protection", "Secure Configuration", "Account Management"],
        "Description": [
            "Maintain inventory of authorized devices",
            "Track and manage software installations",
            "Classify and protect sensitive data",
            "Establish secure configuration standards",
            "Manage user accounts and privileges"
        ],
        "Implementation": [
            "Asset management tools, network discovery",
            "Software inventory, whitelisting",
            "Data classification, encryption",
            "Configuration management, baselines",
            "Identity management, access reviews"
        ]
    }
    
    df3 = pd.DataFrame(cis_data)
    st.dataframe(df3, use_container_width=True)
    
    # Hardening Process
    st.markdown("### Hardening Implementation Process")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Phase 1: Assessment**
        - Current state analysis
        - Vulnerability assessment
        - Risk prioritization
        - Compliance gap analysis
        """)
    
    with col2:
        st.markdown("""
        **Phase 2: Implementation**
        - Hardening plan development
        - Staged deployment
        - Testing and validation
        - Documentation updates
        """)
    
    # Compliance Standards
    st.markdown("### Security Standards and Frameworks")
    
    standards_data = {
        "Standard": ["CIS Benchmarks", "NIST Cybersecurity Framework", "ISO 27001", "STIG", "PCI DSS"],
        "Focus": [
            "System configuration hardening",
            "Comprehensive cybersecurity framework",
            "Information security management",
            "Government/military systems",
            "Payment card industry security"
        ],
        "Key Benefits": [
            "Detailed configuration guides",
            "Risk-based approach",
            "International standard",
            "High security requirements",
            "Industry-specific controls"
        ]
    }
    
    df4 = pd.DataFrame(standards_data)
    st.dataframe(df4, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Defense in Depth:</strong> Implement multiple layers of security controls</li>
            <li><strong>Regular Updates:</strong> Keep systems and applications patched</li>
            <li><strong>Least Privilege:</strong> Grant minimum necessary access rights</li>
            <li><strong>Continuous Monitoring:</strong> Regularly assess and improve security posture</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
