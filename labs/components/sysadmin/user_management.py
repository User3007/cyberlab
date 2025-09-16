import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_user_management():
    """User Management using TDD pattern"""
    
    st.markdown("## User Management")
    st.markdown("**Definition:** Process of managing user accounts, permissions, and access rights in computer systems and networks.")
    
    st.markdown("---")
    
    # User Account Types
    st.markdown("### User Account Types")
    
    account_types_data = {
        "Account Type": ["Administrator", "Standard User", "Service Account", "Guest", "System Account"],
        "Privileges": [
            "Full system access, configuration changes",
            "Limited access, personal files only",
            "Application-specific permissions",
            "Minimal access, temporary use",
            "System-level operations, background tasks"
        ],
        "Use Cases": [
            "System administration, software installation",
            "Daily work activities, office applications",
            "Database services, web servers",
            "Temporary access for visitors",
            "Operating system services, scheduled tasks"
        ],
        "Security Considerations": [
            "Highest risk, require strong authentication",
            "Balanced security and usability",
            "Automated management, regular rotation",
            "Disable when not needed",
            "Never use for interactive login"
        ]
    }
    
    df = pd.DataFrame(account_types_data)
    st.dataframe(df, use_container_width=True)
    
    # Access Control Models
    st.markdown("### Access Control Models")
    
    access_control_data = {
        "Model": ["RBAC", "ABAC", "MAC", "DAC"],
        "Full Name": [
            "Role-Based Access Control",
            "Attribute-Based Access Control",
            "Mandatory Access Control",
            "Discretionary Access Control"
        ],
        "Description": [
            "Permissions assigned to roles, users assigned to roles",
            "Access based on attributes of users, resources, environment",
            "System-enforced access based on security labels",
            "Resource owners control access permissions"
        ],
        "Best For": [
            "Organizations with defined job functions",
            "Complex, dynamic environments",
            "High-security environments",
            "Small teams, flexible access"
        ]
    }
    
    df2 = pd.DataFrame(access_control_data)
    st.dataframe(df2, use_container_width=True)
    
    # User Lifecycle Management
    st.markdown("### User Lifecycle Management")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Provisioning:**
        - Account creation
        - Initial permissions
        - Resource allocation
        - Training and orientation
        """)
    
    with col2:
        st.markdown("""
        **Deprovisioning:**
        - Account deactivation
        - Access revocation
        - Data transfer
        - Exit procedures
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Least Privilege:</strong> Grant minimum necessary permissions</li>
            <li><strong>Regular Reviews:</strong> Audit user access and permissions regularly</li>
            <li><strong>Automation:</strong> Use identity management systems for efficiency</li>
            <li><strong>Documentation:</strong> Maintain clear policies and procedures</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
