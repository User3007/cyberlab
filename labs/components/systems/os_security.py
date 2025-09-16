import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_os_security():
    """Operating System Security using TDD pattern"""
    
    st.markdown("## Operating System Security")
    st.markdown("**Definition:** Security measures and controls implemented at the operating system level to protect system resources, user data, and maintain system integrity against various threats and vulnerabilities.")
    
    st.markdown("---")
    
    # OS Security Fundamentals
    st.markdown("### OS Security Fundamentals")
    
    fundamentals_data = {
        "Security Principle": ["Authentication", "Authorization", "Auditing", "Accountability", "Availability"],
        "Description": [
            "Verify user/process identity",
            "Control access to resources",
            "Monitor and log system activities",
            "Track user actions and responsibilities",
            "Ensure system and data accessibility"
        ],
        "Implementation": [
            "Passwords, biometrics, multi-factor authentication",
            "Access Control Lists (ACLs), permissions",
            "System logs, event monitoring, SIEM integration",
            "User activity logging, non-repudiation",
            "Redundancy, backup systems, disaster recovery"
        ],
        "Common Threats": [
            "Password attacks, credential theft",
            "Privilege escalation, unauthorized access",
            "Log tampering, covering tracks",
            "Insider threats, malicious activities",
            "DoS attacks, system failures"
        ]
    }
    
    df = pd.DataFrame(fundamentals_data)
    st.dataframe(df, use_container_width=True)
    
    # OS Security Features Comparison
    st.markdown("### OS Security Features by Platform")
    
    # Create OS security comparison chart
    os_platforms = ['Windows', 'Linux', 'macOS']
    security_features = ['Access Control', 'Encryption', 'Malware Protection', 'Network Security', 'Monitoring']
    
    security_scores = {
        'Windows': [8, 9, 9, 7, 8],
        'Linux': [9, 8, 6, 8, 9],
        'macOS': [8, 9, 8, 7, 7]
    }
    
    fig = go.Figure()
    
    colors = ['blue', 'green', 'orange']
    for i, platform in enumerate(os_platforms):
        fig.add_trace(go.Scatterpolar(
            r=security_scores[platform],
            theta=security_features,
            fill='toself',
            name=platform,
            line=dict(color=colors[i])
        ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 10]
            )
        ),
        title="OS Security Features Comparison",
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Access Control Models
    st.markdown("### Access Control Models")
    
    access_control_data = {
        "Model": ["Discretionary (DAC)", "Mandatory (MAC)", "Role-Based (RBAC)", "Attribute-Based (ABAC)"],
        "Control Method": [
            "Owner controls access to resources",
            "System enforces access based on labels",
            "Access based on user roles",
            "Access based on attributes and policies"
        ],
        "Implementation": [
            "File permissions, ACLs",
            "Security labels, clearance levels",
            "Role assignments, group memberships",
            "Policy engines, attribute evaluation"
        ],
        "Advantages": [
            "Flexible, user-friendly, decentralized",
            "High security, centralized control",
            "Scalable, manageable, principle of least privilege",
            "Fine-grained, dynamic, context-aware"
        ],
        "Disadvantages": [
            "Security depends on users, privilege creep",
            "Rigid, complex administration",
            "Role explosion, static assignments",
            "Complex policies, performance overhead"
        ],
        "Use Cases": [
            "Personal computers, small organizations",
            "Government, classified systems",
            "Enterprise environments, large organizations",
            "Cloud environments, dynamic systems"
        ]
    }
    
    df2 = pd.DataFrame(access_control_data)
    st.dataframe(df2, use_container_width=True)
    
    # Common OS Vulnerabilities
    st.markdown("### Common OS Security Vulnerabilities")
    
    vulnerabilities_data = {
        "Vulnerability Type": ["Buffer Overflow", "Privilege Escalation", "Race Conditions", "Input Validation", "Configuration Errors"],
        "Description": [
            "Memory corruption due to buffer overrun",
            "Gaining higher privileges than intended",
            "Timing-dependent security flaws",
            "Improper handling of user input",
            "Insecure default or misconfigured settings"
        ],
        "Impact": [
            "Code execution, system compromise",
            "Full system control, data access",
            "Unauthorized access, data corruption",
            "Code injection, system manipulation",
            "Unauthorized access, information disclosure"
        ],
        "Mitigation": [
            "Address Space Layout Randomization (ASLR), stack canaries",
            "Least privilege principle, proper permission management",
            "Proper synchronization, atomic operations",
            "Input sanitization, validation, parameterized queries",
            "Security baselines, configuration management"
        ],
        "Examples": [
            "Stack/heap overflows, format string bugs",
            "SUID/SGID abuse, kernel exploits",
            "TOCTOU attacks, file system races",
            "SQL injection, command injection",
            "Default passwords, open services"
        ]
    }
    
    df3 = pd.DataFrame(vulnerabilities_data)
    st.dataframe(df3, use_container_width=True)
    
    # Security Hardening Checklist
    st.markdown("### OS Security Hardening Checklist")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **User Account Security:**
        - Remove/disable default accounts
        - Enforce strong password policies
        - Implement account lockout policies
        - Use multi-factor authentication
        - Regular password changes
        """)
        
        st.markdown("""
        **Service Management:**
        - Disable unnecessary services
        - Remove unused software
        - Update and patch regularly
        - Configure service permissions
        - Monitor service activities
        """)
    
    with col2:
        st.markdown("""
        **Network Security:**
        - Configure host-based firewall
        - Disable unused network protocols
        - Secure remote access (SSH, RDP)
        - Network service hardening
        - Port security configuration
        """)
        
        st.markdown("""
        **File System Security:**
        - Set appropriate file permissions
        - Enable file system encryption
        - Configure audit logging
        - Implement file integrity monitoring
        - Secure backup procedures
        """)
    
    # Security Tools by OS
    st.markdown("### Security Tools by Operating System")
    
    tools_data = {
        "Category": ["Antivirus/Anti-malware", "Host Firewall", "Encryption", "Monitoring", "Vulnerability Scanner"],
        "Windows": [
            "Windows Defender, Symantec, McAfee",
            "Windows Firewall, ZoneAlarm",
            "BitLocker, VeraCrypt",
            "Event Viewer, Sysmon, WMIC",
            "Nessus, OpenVAS, Microsoft Baseline Security Analyzer"
        ],
        "Linux": [
            "ClamAV, Sophos, ESET",
            "iptables, ufw, firewalld",
            "LUKS, dm-crypt, eCryptfs",
            "rsyslog, auditd, AIDE",
            "Nessus, OpenVAS, Lynis"
        ],
        "macOS": [
            "XProtect, Malwarebytes, Bitdefender",
            "pfctl, Little Snitch",
            "FileVault, VeraCrypt",
            "Console, fs_usage, DTrace",
            "Nessus, Rapid7, Qualys"
        ]
    }
    
    df4 = pd.DataFrame(tools_data)
    st.dataframe(df4, use_container_width=True)
    
    # Incident Response
    st.markdown("### OS Security Incident Response")
    
    incident_response_data = {
        "Phase": ["Preparation", "Identification", "Containment", "Eradication", "Recovery", "Lessons Learned"],
        "Activities": [
            "Develop procedures, train team, prepare tools",
            "Detect and analyze security incidents",
            "Isolate affected systems, prevent spread",
            "Remove threats, patch vulnerabilities",
            "Restore systems, verify security",
            "Document lessons, improve procedures"
        ],
        "OS-Specific Tasks": [
            "Install monitoring tools, backup procedures",
            "Analyze logs, network traffic, system behavior",
            "Network isolation, process termination",
            "Malware removal, system patching",
            "System restoration, security validation",
            "Update security policies, tool configuration"
        ],
        "Key Tools": [
            "SIEM, backup systems, incident response kit",
            "Log analyzers, network monitors, forensic tools",
            "Network controls, system isolation tools",
            "Anti-malware, patch management systems",
            "Backup systems, integrity checkers",
            "Documentation systems, training platforms"
        ]
    }
    
    df5 = pd.DataFrame(incident_response_data)
    st.dataframe(df5, use_container_width=True)
    
    # Compliance and Standards
    st.markdown("### Security Standards and Compliance")
    
    compliance_data = {
        "Standard/Framework": ["CIS Controls", "NIST Cybersecurity Framework", "ISO 27001", "SANS Top 20", "OWASP"],
        "Focus Area": [
            "Critical security controls implementation",
            "Comprehensive cybersecurity framework",
            "Information security management system",
            "Most critical security controls",
            "Application security (relevant to OS)"
        ],
        "OS Relevance": [
            "OS hardening, configuration management",
            "OS security within broader framework",
            "OS security policies and procedures",
            "OS-level security controls",
            "Secure coding affecting OS security"
        ],
        "Key Benefits": [
            "Prioritized, actionable security measures",
            "Risk-based approach to security",
            "International standard, certification",
            "Focus on highest impact controls",
            "Security best practices and tools"
        ]
    }
    
    df6 = pd.DataFrame(compliance_data)
    st.dataframe(df6, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Layered Security:</strong> Implement multiple security controls at different OS levels</li>
            <li><strong>Regular Updates:</strong> Keep OS and security tools updated with latest patches</li>
            <li><strong>Least Privilege:</strong> Grant minimum necessary permissions to users and processes</li>
            <li><strong>Continuous Monitoring:</strong> Implement comprehensive logging and monitoring systems</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
