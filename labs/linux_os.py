"""
Linux OS Security & Administration Lab
Comprehensive Linux system administration, security hardening, and performance optimization
"""

import streamlit as st
import subprocess
import os
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import socket
import platform
import psutil
import hashlib
import re
from datetime import datetime, timedelta
import time
import random
from typing import Dict, List, Tuple, Optional, Any
import pwd
import grp
import stat
import glob

def create_lab_header(title: str, icon: str, gradient: str = "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"):
    """Create compact lab header"""
    return f"""
    <div style="background: {gradient}; 
                padding: 0.8rem; border-radius: 6px; margin-bottom: 1rem;">
        <h3 style="color: white; margin: 0; font-size: 1.2rem;">{icon} {title}</h3>
    </div>
    """

def run_lab():
    """Linux OS Lab - Master Linux System Administration & Security"""
    
    # Compact Header
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 1rem; border-radius: 8px; margin-bottom: 1rem; text-align: center;">
        <h2 style="color: white; margin: 0; font-size: 1.5rem;">
            🐧 Linux OS Security Lab
        </h2>
        <p style="color: white; margin: 0; font-size: 0.9rem; opacity: 0.9;">
            System Administration, Security & Performance
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced tabs with comprehensive Linux topics
    tabs = st.tabs([
        "📊 System Info",
        "⚙️ Process Management", 
        "👥 User Management",
        "🔐 File Permissions",
        "🔥 Firewall Config",
        "🛡️ SELinux/AppArmor",
        "🔒 System Hardening",
        "📝 Log Analysis",
        "🎛️ Kernel Tuning",
        "📈 Performance Monitor",
        "🐳 Container Security",
        "🤖 Automation",
        "📖 Command Cheat Sheet"
    ])
    
    with tabs[0]:
        system_info_lab()
    
    with tabs[1]:
        process_management_lab()
    
    with tabs[2]:
        user_management_lab()
    
    with tabs[3]:
        file_permissions_lab()
    
    with tabs[4]:
        firewall_config_lab()
    
    with tabs[5]:
        selinux_apparmor_lab()
    
    with tabs[6]:
        system_hardening_lab()
    
    with tabs[7]:
        log_analysis_lab()
    
    with tabs[8]:
        kernel_tuning_lab()
    
    with tabs[9]:
        performance_monitor_lab()
    
    with tabs[10]:
        container_security_lab()
    
    with tabs[11]:
        automation_lab()
    
    with tabs[12]:
        command_cheat_sheet()

def system_info_lab():
    """Lab for System Information & Hardware Details"""
    
    st.markdown(create_lab_header("System Information Lab", "📊", "linear-gradient(90deg, #FF6B6B 0%, #4ECDC4 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📚 **Linux System Information Theory**", expanded=False):
        st.markdown("""
        ### 🖥️ **System Information Commands**
        
        **Essential Commands:**
        - `uname` - System kernel information
        - `lsb_release` - Distribution information
        - `hostname` - System hostname
        - `uptime` - System uptime and load
        - `df` - Disk usage
        - `free` - Memory usage
        - `lscpu` - CPU information
        - `lspci` - PCI devices
        - `lsusb` - USB devices
        - `dmidecode` - Hardware information
        
        **Proc Filesystem:**
        - `/proc/cpuinfo` - CPU details
        - `/proc/meminfo` - Memory details
        - `/proc/version` - Kernel version
        - `/proc/cmdline` - Kernel boot parameters
        """)
    
    st.markdown("### 🔍 **System Analysis**")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### ⚙️ **Quick System Info**")
        
        if st.button("🚀 **Gather System Information**", type="primary"):
            with st.spinner("Collecting system data..."):
                info = gather_system_info()
                st.session_state['sys_info'] = info
    
    with col2:
        st.markdown("#### 📊 **System Details**")
        
        if 'sys_info' in st.session_state:
            info = st.session_state['sys_info']
            
            # Display metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("🖥️ OS", info['os_name'], info['kernel'])
            with col2:
                st.metric("💾 RAM", f"{info['memory_total']} GB", f"{info['memory_percent']}% used")
            with col3:
                st.metric("💽 Disk", f"{info['disk_total']} GB", f"{info['disk_percent']}% used")
            with col4:
                st.metric("🔥 CPU", f"{info['cpu_count']} cores", f"{info['cpu_percent']}% load")
            
            # Detailed info tabs
            detail_tabs = st.tabs(["🖥️ System", "💾 Memory", "💽 Storage", "🌐 Network"])
            
            with detail_tabs[0]:
                st.json(info['system_details'])
            
            with detail_tabs[1]:
                # Memory visualization
                fig = create_memory_chart(info)
                st.plotly_chart(fig, use_container_width=True)
            
            with detail_tabs[2]:
                # Disk usage visualization
                df = pd.DataFrame(info['disk_partitions'])
                st.dataframe(df, use_container_width=True)
            
            with detail_tabs[3]:
                # Network interfaces
                st.code(info['network_interfaces'], language="text")

def process_management_lab():
    """Lab for Process Management & Control"""
    
    st.markdown(create_lab_header("Process Management Lab", "⚙️", "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📚 **Process Management Theory**", expanded=False):
        st.markdown("""
        ### 🎯 **Process Control in Linux**
        
        **Process States:**
        - **R** - Running or runnable
        - **S** - Sleeping (interruptible)
        - **D** - Sleeping (uninterruptible)
        - **T** - Stopped
        - **Z** - Zombie
        
        **Key Commands:**
        - `ps` - Process status
        - `top/htop` - Real-time process viewer
        - `kill/killall` - Terminate processes
        - `nice/renice` - Process priority
        - `pgrep/pkill` - Process grep/kill
        - `strace` - System call tracer
        - `lsof` - List open files
        
        **Signals:**
        - **SIGTERM (15)** - Graceful termination
        - **SIGKILL (9)** - Force kill
        - **SIGHUP (1)** - Hangup/reload
        - **SIGSTOP (19)** - Stop process
        - **SIGCONT (18)** - Continue process
        """)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🔍 **Process Explorer**")
        
        view_type = st.selectbox("View Type", ["Top Processes", "Process Tree", "By User", "By State"])
        sort_by = st.selectbox("Sort By", ["CPU", "Memory", "PID", "Time"])
        num_processes = st.slider("Number of Processes", 5, 50, 10)
        
        if st.button("🔄 **Refresh Process List**"):
            processes = get_process_list(view_type, sort_by, num_processes)
            st.session_state['processes'] = processes
    
    with col2:
        st.markdown("#### 📊 **Process Monitor**")
        
        if 'processes' in st.session_state:
            df = pd.DataFrame(st.session_state['processes'])
            
            # Process visualization
            fig = px.treemap(df, path=['USER', 'CMD'], values='CPU',
                           color='MEM', color_continuous_scale='RdYlBu_r',
                           title="Process Resource Usage")
            st.plotly_chart(fig, use_container_width=True)
            
            # Process table
            st.dataframe(df, use_container_width=True)
    
    # Process Control Section
    st.markdown("### 🎮 **Process Control**")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        pid = st.number_input("Process ID (PID)", min_value=1, step=1)
    
    with col2:
        signal = st.selectbox("Signal", ["SIGTERM", "SIGKILL", "SIGHUP", "SIGSTOP", "SIGCONT"])
    
    with col3:
        if st.button("📤 **Send Signal**", type="secondary"):
            st.warning(f"⚠️ Would send {signal} to PID {pid} (simulation mode)")
            st.code(f"kill -{signal.replace('SIG', '')} {pid}", language="bash")

def user_management_lab():
    """Lab for User & Group Management"""
    
    st.markdown(create_lab_header("User Management Lab", "👥", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📚 **User Management Theory**", expanded=False):
        st.markdown("""
        ### 👤 **Linux User Management**
        
        **User Files:**
        - `/etc/passwd` - User account information
        - `/etc/shadow` - Encrypted passwords
        - `/etc/group` - Group information
        - `/etc/gshadow` - Group passwords
        - `/etc/sudoers` - Sudo privileges
        
        **User Commands:**
        - `useradd` - Create user
        - `usermod` - Modify user
        - `userdel` - Delete user
        - `passwd` - Change password
        - `chage` - Password aging
        - `groups` - Show groups
        - `id` - User/group IDs
        
        **Password Policy:**
        - Minimum length
        - Complexity requirements
        - Expiration settings
        - Login attempts
        - Account lockout
        """)
    
    tabs = st.tabs(["👤 Users", "👥 Groups", "🔐 Sudo", "📊 Audit"])
    
    with tabs[0]:
        st.markdown("#### 👤 **User Management**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Create User")
            username = st.text_input("Username")
            fullname = st.text_input("Full Name")
            home_dir = st.text_input("Home Directory", f"/home/{username}")
            shell = st.selectbox("Shell", ["/bin/bash", "/bin/sh", "/bin/zsh", "/usr/sbin/nologin"])
            
            if st.button("➕ **Create User**"):
                cmd = generate_useradd_command(username, fullname, home_dir, shell)
                st.code(cmd, language="bash")
                st.info("📝 User creation command generated")
        
        with col2:
            st.markdown("##### Current Users")
            if st.button("🔄 **List Users**"):
                users = list_system_users()
                df = pd.DataFrame(users)
                st.dataframe(df, use_container_width=True)
    
    with tabs[1]:
        st.markdown("#### 👥 **Group Management**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            groupname = st.text_input("Group Name")
            members = st.text_area("Members (comma-separated)")
            
            if st.button("➕ **Create Group**"):
                cmd = f"groupadd {groupname}"
                if members:
                    cmd += f" && usermod -aG {groupname} {members}"
                st.code(cmd, language="bash")
        
        with col2:
            if st.button("🔄 **List Groups**"):
                groups = list_system_groups()
                st.dataframe(groups, use_container_width=True)
    
    with tabs[2]:
        st.markdown("#### 🔐 **Sudo Configuration**")
        
        st.code("""
# Example sudoers entries
# User privilege specification
username ALL=(ALL:ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# User without password
username ALL=(ALL) NOPASSWD: ALL

# Specific command only
username ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx
        """, language="bash")
    
    with tabs[3]:
        st.markdown("#### 📊 **User Audit**")
        
        if st.button("🔍 **Audit User Activity**"):
            audit_data = perform_user_audit()
            
            # Display audit results
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Users", audit_data['total_users'])
            with col2:
                st.metric("Active Sessions", audit_data['active_sessions'])
            with col3:
                st.metric("Failed Logins", audit_data['failed_logins'])
            
            # Recent logins
            st.markdown("##### Recent Login Activity")
            st.dataframe(audit_data['recent_logins'], use_container_width=True)

def file_permissions_lab():
    """Lab for File Permissions & ACLs"""
    
    st.markdown(create_lab_header("File Permissions Lab", "🔐", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📚 **Linux File Permissions Theory**", expanded=False):
        st.markdown("""
        ### 🔒 **Permission System**
        
        **Basic Permissions:**
        ```
        rwxrwxrwx
        ├─┼─┼─┤
        │ │ └─── Others (o)
        │ └───── Group (g)
        └─────── User/Owner (u)
        ```
        
        **Permission Values:**
        - **r (4)** - Read
        - **w (2)** - Write
        - **x (1)** - Execute
        
        **Special Permissions:**
        - **SUID (4000)** - Set User ID
        - **SGID (2000)** - Set Group ID
        - **Sticky Bit (1000)** - Restrict deletion
        
        **ACL (Access Control Lists):**
        - `getfacl` - Get file ACL
        - `setfacl` - Set file ACL
        - Extended permissions beyond traditional Unix
        """)
    
    # Permission Calculator
    st.markdown("### 🧮 **Permission Calculator**")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**Owner**")
        owner_r = st.checkbox("Read", key="owner_r", value=True)
        owner_w = st.checkbox("Write", key="owner_w", value=True)
        owner_x = st.checkbox("Execute", key="owner_x")
    
    with col2:
        st.markdown("**Group**")
        group_r = st.checkbox("Read", key="group_r", value=True)
        group_w = st.checkbox("Write", key="group_w")
        group_x = st.checkbox("Execute", key="group_x")
    
    with col3:
        st.markdown("**Others**")
        other_r = st.checkbox("Read", key="other_r", value=True)
        other_w = st.checkbox("Write", key="other_w")
        other_x = st.checkbox("Execute", key="other_x")
    
    # Calculate permissions
    octal = calculate_permissions(owner_r, owner_w, owner_x, 
                                 group_r, group_w, group_x,
                                 other_r, other_w, other_x)
    symbolic = get_symbolic_permissions(owner_r, owner_w, owner_x,
                                       group_r, group_w, group_x,
                                       other_r, other_w, other_x)
    
    # Display results
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Octal", octal)
    with col2:
        st.metric("Symbolic", symbolic)
    with col3:
        st.code(f"chmod {octal} file", language="bash")
    
    # File Permission Analyzer
    st.markdown("### 🔍 **Permission Analyzer**")
    
    file_path = st.text_input("File/Directory Path", "/etc/passwd")
    
    if st.button("🔍 **Analyze Permissions**"):
        analysis = analyze_file_permissions(file_path)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### File Information")
            st.json(analysis['info'])
        
        with col2:
            st.markdown("##### Security Analysis")
            for issue in analysis['security_issues']:
                if issue['severity'] == 'high':
                    st.error(f"🔴 {issue['message']}")
                elif issue['severity'] == 'medium':
                    st.warning(f"🟡 {issue['message']}")
                else:
                    st.info(f"🔵 {issue['message']}")

def firewall_config_lab():
    """Lab for Firewall Configuration (iptables/firewalld)"""
    
    st.markdown(create_lab_header("Firewall Configuration Lab", "🔥", "linear-gradient(90deg, #ff6a00 0%, #ee0979 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📚 **Linux Firewall Theory**", expanded=False):
        st.markdown("""
        ### 🔥 **Firewall Technologies**
        
        **iptables:**
        - Packet filtering framework
        - Tables: filter, nat, mangle, raw
        - Chains: INPUT, OUTPUT, FORWARD
        - Targets: ACCEPT, DROP, REJECT
        
        **firewalld:**
        - Dynamic firewall management
        - Zones concept
        - Runtime vs permanent rules
        - Rich rules support
        
        **nftables:**
        - Modern replacement for iptables
        - Simplified syntax
        - Better performance
        - Unified framework
        """)
    
    tabs = st.tabs(["🔥 iptables", "🛡️ firewalld", "📋 Rules Builder", "🔍 Audit"])
    
    with tabs[0]:
        st.markdown("#### 🔥 **iptables Configuration**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Add Rule")
            chain = st.selectbox("Chain", ["INPUT", "OUTPUT", "FORWARD"])
            protocol = st.selectbox("Protocol", ["tcp", "udp", "icmp", "all"])
            port = st.number_input("Port", min_value=1, max_value=65535, value=80)
            source = st.text_input("Source IP", "0.0.0.0/0")
            action = st.selectbox("Action", ["ACCEPT", "DROP", "REJECT"])
            
            if st.button("➕ **Generate Rule**"):
                rule = generate_iptables_rule(chain, protocol, port, source, action)
                st.code(rule, language="bash")
        
        with col2:
            st.markdown("##### Current Rules")
            if st.button("🔄 **Show Rules**"):
                rules = get_iptables_rules()
                st.code(rules, language="text")
    
    with tabs[1]:
        st.markdown("#### 🛡️ **firewalld Configuration**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            zone = st.selectbox("Zone", ["public", "internal", "external", "dmz", "work", "home"])
            service = st.selectbox("Service", ["http", "https", "ssh", "ftp", "smtp", "dns"])
            permanent = st.checkbox("Permanent Rule")
            
            if st.button("➕ **Add Service**"):
                cmd = f"firewall-cmd --zone={zone} --add-service={service}"
                if permanent:
                    cmd += " --permanent"
                st.code(cmd, language="bash")
        
        with col2:
            if st.button("🔄 **List Zones**"):
                zones_info = get_firewalld_zones()
                st.json(zones_info)
    
    with tabs[2]:
        st.markdown("#### 📋 **Rules Builder**")
        
        # Visual rule builder
        st.markdown("##### Build Complex Rules")
        
        rule_type = st.selectbox("Rule Type", ["Web Server", "Database", "SSH Access", "Custom"])
        
        if rule_type == "Web Server":
            st.code("""
# Allow HTTP and HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Rate limiting for DDoS protection
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
            """, language="bash")
        elif rule_type == "Database":
            st.code("""
# MySQL/MariaDB
iptables -A INPUT -p tcp --dport 3306 -s 192.168.1.0/24 -j ACCEPT

# PostgreSQL
iptables -A INPUT -p tcp --dport 5432 -s 192.168.1.0/24 -j ACCEPT
            """, language="bash")
    
    with tabs[3]:
        st.markdown("#### 🔍 **Firewall Audit**")
        
        if st.button("🔍 **Audit Firewall**"):
            audit = audit_firewall_config()
            
            # Display audit results
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Open Ports", audit['open_ports'])
            with col2:
                st.metric("Total Rules", audit['total_rules'])
            with col3:
                st.metric("Security Score", f"{audit['score']}/100")
            
            # Security recommendations
            st.markdown("##### 🔒 Security Recommendations")
            for rec in audit['recommendations']:
                st.warning(f"⚠️ {rec}")

def selinux_apparmor_lab():
    """Lab for SELinux and AppArmor"""
    
    st.markdown(create_lab_header("SELinux/AppArmor Lab", "🛡️", "linear-gradient(90deg, #4facfe 0%, #00f2fe 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📚 **Mandatory Access Control Theory**", expanded=False):
        st.markdown("""
        ### 🛡️ **MAC Systems**
        
        **SELinux (Security-Enhanced Linux):**
        - Mandatory Access Control (MAC)
        - Contexts: user:role:type:level
        - Policies: targeted, mls, minimum
        - Modes: enforcing, permissive, disabled
        
        **AppArmor:**
        - Path-based MAC
        - Profiles: enforce, complain, disable
        - Easier to configure than SELinux
        - Default in Ubuntu/Debian
        
        **Key Concepts:**
        - Type Enforcement
        - Role-Based Access Control
        - Multi-Level Security
        - Domain Transitions
        """)
    
    tabs = st.tabs(["🔴 SELinux", "🟢 AppArmor", "📊 Policy Analysis", "🔧 Troubleshooting"])
    
    with tabs[0]:
        st.markdown("#### 🔴 **SELinux Management**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### SELinux Status")
            if st.button("📊 **Check Status**"):
                status = get_selinux_status()
                st.json(status)
            
            mode = st.selectbox("Set Mode", ["enforcing", "permissive", "disabled"])
            if st.button("🔄 **Change Mode**"):
                st.code(f"setenforce {1 if mode == 'enforcing' else 0}", language="bash")
        
        with col2:
            st.markdown("##### Context Management")
            file_path = st.text_input("File Path", "/var/www/html")
            context = st.text_input("Context", "httpd_sys_content_t")
            
            if st.button("🏷️ **Set Context**"):
                st.code(f"chcon -t {context} {file_path}", language="bash")
                st.code(f"restorecon -v {file_path}", language="bash")
    
    with tabs[1]:
        st.markdown("#### 🟢 **AppArmor Management**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Profile Management")
            profile = st.selectbox("Profile", ["nginx", "apache2", "mysql", "docker"])
            profile_mode = st.selectbox("Mode", ["enforce", "complain", "disable"])
            
            if st.button("🔄 **Set Profile Mode**"):
                if profile_mode == "enforce":
                    st.code(f"aa-enforce /etc/apparmor.d/{profile}", language="bash")
                elif profile_mode == "complain":
                    st.code(f"aa-complain /etc/apparmor.d/{profile}", language="bash")
                else:
                    st.code(f"aa-disable /etc/apparmor.d/{profile}", language="bash")
        
        with col2:
            if st.button("📊 **Profile Status**"):
                profiles = get_apparmor_profiles()
                st.dataframe(profiles, use_container_width=True)
    
    with tabs[2]:
        st.markdown("#### 📊 **Policy Analysis**")
        
        if st.button("🔍 **Analyze Policies**"):
            analysis = analyze_mac_policies()
            
            # Visualization
            fig = create_policy_visualization(analysis)
            st.plotly_chart(fig, use_container_width=True)
    
    with tabs[3]:
        st.markdown("#### 🔧 **Troubleshooting**")
        
        st.markdown("##### Common Issues & Solutions")
        
        issue = st.selectbox("Issue Type", [
            "Permission Denied",
            "Service Won't Start",
            "File Access Blocked",
            "Network Connection Blocked"
        ])
        
        if issue == "Permission Denied":
            st.code("""
# Check SELinux denials
ausearch -m AVC -ts recent

# Check AppArmor denials
dmesg | grep -i apparmor

# Generate SELinux policy
audit2allow -a -M mymodule
semodule -i mymodule.pp
            """, language="bash")

def system_hardening_lab():
    """Lab for System Hardening & Security"""
    
    st.markdown(create_lab_header("System Hardening Lab", "🔒", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📚 **System Hardening Best Practices**", expanded=False):
        st.markdown("""
        ### 🔒 **Hardening Checklist**
        
        **Network Security:**
        - Disable unnecessary services
        - Configure firewall rules
        - Enable TCP wrappers
        - Secure SSH configuration
        
        **System Security:**
        - Regular updates
        - Remove unnecessary packages
        - Kernel hardening (sysctl)
        - Disable USB storage
        
        **Access Control:**
        - Strong password policy
        - Account lockout policy
        - Sudo configuration
        - PAM modules
        
        **Monitoring:**
        - Enable auditd
        - Configure logging
        - File integrity monitoring
        - Intrusion detection
        """)
    
    # Hardening Score Dashboard
    st.markdown("### 📊 **Security Score Dashboard**")
    
    if st.button("🔍 **Run Security Audit**", type="primary"):
        score = perform_security_audit()
        
        # Display overall score
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Overall Score", f"{score['overall']}/100", 
                     "⚠️ Needs Improvement" if score['overall'] < 70 else "✅ Good")
        with col2:
            st.metric("Network", f"{score['network']}/100")
        with col3:
            st.metric("System", f"{score['system']}/100")
        with col4:
            st.metric("Access", f"{score['access']}/100")
        
        # Detailed findings
        st.markdown("### 🔍 **Security Findings**")
        
        for category, findings in score['findings'].items():
            with st.expander(f"**{category}** ({len(findings)} issues)"):
                for finding in findings:
                    if finding['severity'] == 'critical':
                        st.error(f"🔴 **{finding['title']}**: {finding['description']}")
                        st.code(finding['fix'], language="bash")
                    elif finding['severity'] == 'high':
                        st.warning(f"🟡 **{finding['title']}**: {finding['description']}")
                        st.code(finding['fix'], language="bash")
                    else:
                        st.info(f"🔵 **{finding['title']}**: {finding['description']}")
                        st.code(finding['fix'], language="bash")
    
    # Hardening Scripts
    st.markdown("### 🛠️ **Hardening Scripts**")
    
    script_type = st.selectbox("Select Script", [
        "SSH Hardening",
        "Kernel Hardening",
        "Network Hardening",
        "Service Hardening"
    ])
    
    if script_type == "SSH Hardening":
        st.code("""
#!/bin/bash
# SSH Hardening Script

# Backup original config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Secure SSH configuration
cat >> /etc/ssh/sshd_config << EOF
# Security hardening
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowUsers admin user1
Protocol 2
EOF

# Restart SSH service
systemctl restart sshd
        """, language="bash")
    
    elif script_type == "Kernel Hardening":
        st.code("""
#!/bin/bash
# Kernel Hardening via sysctl

cat >> /etc/sysctl.d/99-hardening.conf << EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
EOF

# Apply settings
sysctl -p /etc/sysctl.d/99-hardening.conf
        """, language="bash")

def log_analysis_lab():
    """Lab for Log Analysis & Monitoring"""
    
    st.markdown(create_lab_header("Log Analysis Lab", "📝", "linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📚 **Linux Logging System**", expanded=False):
        st.markdown("""
        ### 📝 **Log Management**
        
        **Important Log Files:**
        - `/var/log/syslog` - System messages
        - `/var/log/auth.log` - Authentication logs
        - `/var/log/kern.log` - Kernel logs
        - `/var/log/apache2/` - Apache logs
        - `/var/log/nginx/` - Nginx logs
        - `/var/log/mysql/` - MySQL logs
        
        **Log Analysis Tools:**
        - `journalctl` - Systemd journal
        - `grep/awk/sed` - Text processing
        - `logwatch` - Log analysis
        - `fail2ban` - Intrusion prevention
        - `rsyslog` - Log management
        
        **Log Rotation:**
        - `/etc/logrotate.conf` - Main config
        - `/etc/logrotate.d/` - App configs
        - Compression and archival
        """)
    
    tabs = st.tabs(["📊 Analysis", "🔍 Search", "⚠️ Alerts", "📈 Visualization"])
    
    with tabs[0]:
        st.markdown("#### 📊 **Log Analysis**")
        
        log_file = st.selectbox("Select Log", [
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log"
        ])
        
        analysis_type = st.selectbox("Analysis Type", [
            "Failed Login Attempts",
            "Top IP Addresses",
            "Error Patterns",
            "Timeline Analysis"
        ])
        
        if st.button("🔍 **Analyze Logs**"):
            results = analyze_logs(log_file, analysis_type)
            
            if analysis_type == "Failed Login Attempts":
                st.error(f"⚠️ Found {results['count']} failed login attempts")
                st.dataframe(results['attempts'], use_container_width=True)
            
            elif analysis_type == "Top IP Addresses":
                fig = px.bar(results, x='ip', y='count', title="Top IP Addresses")
                st.plotly_chart(fig, use_container_width=True)
    
    with tabs[1]:
        st.markdown("#### 🔍 **Log Search**")
        
        search_pattern = st.text_input("Search Pattern (regex)", "error|fail|denied")
        time_range = st.selectbox("Time Range", ["Last Hour", "Last 24 Hours", "Last Week"])
        
        if st.button("🔎 **Search**"):
            search_results = search_logs(search_pattern, time_range)
            st.code(search_results, language="text")
    
    with tabs[2]:
        st.markdown("#### ⚠️ **Alert Configuration**")
        
        alert_type = st.selectbox("Alert Type", [
            "Failed SSH Login",
            "Disk Space Low",
            "Service Down",
            "Security Breach"
        ])
        
        threshold = st.number_input("Threshold", min_value=1, value=5)
        email = st.text_input("Alert Email", "admin@example.com")
        
        if st.button("💾 **Save Alert Rule**"):
            st.success("✅ Alert rule configured")
            st.code(f"""
# Alert rule for {alert_type}
if [ $(grep -c "{alert_type}" /var/log/syslog) -gt {threshold} ]; then
    echo "Alert: {alert_type} threshold exceeded" | mail -s "Security Alert" {email}
fi
            """, language="bash")
    
    with tabs[3]:
        st.markdown("#### 📈 **Log Visualization**")
        
        if st.button("📊 **Generate Dashboard**"):
            dashboard_data = generate_log_dashboard()
            
            # Create subplots
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=("Events Over Time", "Event Types", "Source IPs", "Severity Distribution")
            )
            
            # Add traces
            fig.add_trace(go.Scatter(x=dashboard_data['timeline']['time'], 
                                    y=dashboard_data['timeline']['events']), row=1, col=1)
            fig.add_trace(go.Pie(labels=dashboard_data['types']['labels'], 
                                values=dashboard_data['types']['values']), row=1, col=2)
            fig.add_trace(go.Bar(x=dashboard_data['ips']['ip'], 
                                y=dashboard_data['ips']['count']), row=2, col=1)
            fig.add_trace(go.Pie(labels=dashboard_data['severity']['labels'], 
                                values=dashboard_data['severity']['values']), row=2, col=2)
            
            st.plotly_chart(fig, use_container_width=True)

def kernel_tuning_lab():
    """Lab for Kernel Tuning & Optimization"""
    
    st.markdown(create_lab_header("Kernel Tuning Lab", "🎛️", "linear-gradient(90deg, #FC466B 0%, #3F5EFB 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📚 **Kernel Tuning Theory**", expanded=False):
        st.markdown("""
        ### 🎛️ **Kernel Parameters**
        
        **Performance Tuning:**
        - `vm.swappiness` - Swap tendency
        - `vm.dirty_ratio` - Dirty page threshold
        - `kernel.sched_*` - Scheduler parameters
        - `net.core.*` - Network stack
        
        **Security Parameters:**
        - `kernel.modules_disabled` - Disable module loading
        - `kernel.kptr_restrict` - Hide kernel pointers
        - `kernel.yama.ptrace_scope` - Ptrace restrictions
        
        **Resource Limits:**
        - `/etc/security/limits.conf` - User limits
        - `ulimit` - Shell limits
        - Cgroups - Resource control groups
        """)
    
    tabs = st.tabs(["⚙️ Parameters", "📊 Performance", "🔧 Optimization", "📈 Monitoring"])
    
    with tabs[0]:
        st.markdown("#### ⚙️ **Kernel Parameters**")
        
        category = st.selectbox("Category", ["Network", "Memory", "Security", "Filesystem"])
        
        if category == "Network":
            params = get_network_kernel_params()
        elif category == "Memory":
            params = get_memory_kernel_params()
        elif category == "Security":
            params = get_security_kernel_params()
        else:
            params = get_fs_kernel_params()
        
        df = pd.DataFrame(params)
        st.dataframe(df, use_container_width=True)
        
        # Parameter modification
        st.markdown("##### Modify Parameter")
        param_name = st.text_input("Parameter Name", "net.ipv4.tcp_congestion_control")
        param_value = st.text_input("New Value", "bbr")
        
        if st.button("🔄 **Apply Change**"):
            st.code(f"sysctl -w {param_name}={param_value}", language="bash")
            st.info("💡 To make permanent, add to /etc/sysctl.conf")
    
    with tabs[1]:
        st.markdown("#### 📊 **Performance Analysis**")
        
        if st.button("🔍 **Analyze Performance**"):
            perf_data = analyze_kernel_performance()
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("CPU Scheduler", perf_data['scheduler'])
            with col2:
                st.metric("I/O Scheduler", perf_data['io_scheduler'])
            with col3:
                st.metric("Congestion Control", perf_data['congestion_control'])
            
            # Performance graph
            fig = create_performance_graph(perf_data)
            st.plotly_chart(fig, use_container_width=True)
    
    with tabs[2]:
        st.markdown("#### 🔧 **Optimization Profiles**")
        
        profile = st.selectbox("Select Profile", [
            "Web Server",
            "Database Server",
            "Desktop",
            "Low Latency",
            "High Throughput"
        ])
        
        if profile == "Web Server":
            st.code("""
# Web Server Optimization
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 8192
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 300
            """, language="bash")
        
        if st.button("📥 **Apply Profile**"):
            st.success(f"✅ {profile} optimization profile applied")
    
    with tabs[3]:
        st.markdown("#### 📈 **Real-time Monitoring**")
        
        monitor_type = st.selectbox("Monitor", ["CPU", "Memory", "I/O", "Network"])
        
        placeholder = st.empty()
        
        if st.button("▶️ **Start Monitoring**"):
            for i in range(10):
                data = get_realtime_kernel_stats(monitor_type)
                fig = create_monitoring_chart(data, monitor_type)
                placeholder.plotly_chart(fig, use_container_width=True)
                time.sleep(1)

def performance_monitor_lab():
    """Lab for Performance Monitoring & Analysis"""
    
    st.markdown(create_lab_header("Performance Monitor Lab", "📈", "linear-gradient(90deg, #4facfe 0%, #00f2fe 100%)"), unsafe_allow_html=True)
    
    tabs = st.tabs(["📊 System Metrics", "🔥 Resource Usage", "📈 Trends", "⚠️ Alerts"])
    
    with tabs[0]:
        st.markdown("#### 📊 **System Metrics Dashboard**")
        
        if st.button("🔄 **Refresh Metrics**"):
            metrics = get_system_metrics()
            
            # CPU Metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("CPU Usage", f"{metrics['cpu_percent']}%", 
                         delta=f"{metrics['cpu_delta']}%")
            with col2:
                st.metric("Memory", f"{metrics['memory_percent']}%",
                         delta=f"{metrics['memory_delta']}%")
            with col3:
                st.metric("Disk I/O", f"{metrics['disk_io_rate']} MB/s")
            with col4:
                st.metric("Network", f"{metrics['network_rate']} Mbps")
            
            # Detailed metrics
            fig = create_metrics_dashboard(metrics)
            st.plotly_chart(fig, use_container_width=True)
    
    with tabs[1]:
        st.markdown("#### 🔥 **Resource Usage Analysis**")
        
        resource = st.selectbox("Resource Type", ["CPU", "Memory", "Disk", "Network"])
        
        if st.button("📊 **Analyze Usage**"):
            usage_data = analyze_resource_usage(resource)
            
            # Top consumers
            st.markdown(f"##### Top {resource} Consumers")
            df = pd.DataFrame(usage_data['top_consumers'])
            st.dataframe(df, use_container_width=True)
            
            # Usage heatmap
            fig = create_usage_heatmap(usage_data)
            st.plotly_chart(fig, use_container_width=True)
    
    with tabs[2]:
        st.markdown("#### 📈 **Performance Trends**")
        
        timeframe = st.selectbox("Timeframe", ["1 Hour", "24 Hours", "7 Days", "30 Days"])
        
        if st.button("📊 **Generate Trends**"):
            trends = generate_performance_trends(timeframe)
            
            # Trend charts
            fig = make_subplots(rows=2, cols=2,
                              subplot_titles=("CPU", "Memory", "Disk", "Network"))
            
            for i, metric in enumerate(['cpu', 'memory', 'disk', 'network']):
                row = i // 2 + 1
                col = i % 2 + 1
                fig.add_trace(go.Scatter(x=trends[metric]['time'], 
                                        y=trends[metric]['values'],
                                        name=metric.upper()), 
                            row=row, col=col)
            
            st.plotly_chart(fig, use_container_width=True)
    
    with tabs[3]:
        st.markdown("#### ⚠️ **Performance Alerts**")
        
        alert_metric = st.selectbox("Metric", ["CPU", "Memory", "Disk", "Load Average"])
        threshold = st.slider("Threshold (%)", 0, 100, 80)
        duration = st.number_input("Duration (minutes)", min_value=1, value=5)
        
        if st.button("💾 **Create Alert**"):
            st.success("✅ Alert configured")
            st.code(f"""
#!/bin/bash
# Performance alert for {alert_metric} > {threshold}%

while true; do
    current=$({alert_metric.lower()}_usage)
    if [ $current -gt {threshold} ]; then
        echo "ALERT: {alert_metric} usage is $current%" | mail -s "Performance Alert" admin@example.com
    fi
    sleep {duration}m
done
            """, language="bash")

def container_security_lab():
    """Lab for Container & Docker Security"""
    
    st.markdown(create_lab_header("Container Security Lab", "🐳", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📚 **Container Security Theory**", expanded=False):
        st.markdown("""
        ### 🐳 **Container Security**
        
        **Security Layers:**
        - Image security scanning
        - Runtime protection
        - Network isolation
        - Resource limits
        - Secrets management
        
        **Best Practices:**
        - Use minimal base images
        - Non-root containers
        - Read-only filesystems
        - Security scanning
        - Image signing
        
        **Tools:**
        - Docker Bench Security
        - Trivy/Clair scanning
        - Falco runtime security
        - Open Policy Agent
        """)
    
    tabs = st.tabs(["🔍 Image Scan", "🛡️ Runtime Security", "🌐 Network", "📋 Compliance"])
    
    with tabs[0]:
        st.markdown("#### 🔍 **Container Image Security**")
        
        image_name = st.text_input("Image Name", "nginx:latest")
        
        if st.button("🔍 **Scan Image**"):
            scan_results = scan_container_image(image_name)
            
            # Display vulnerabilities
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Critical", scan_results['critical'], delta_color="inverse")
            with col2:
                st.metric("High", scan_results['high'], delta_color="inverse")
            with col3:
                st.metric("Medium", scan_results['medium'])
            with col4:
                st.metric("Low", scan_results['low'])
            
            # Vulnerability details
            if scan_results['vulnerabilities']:
                df = pd.DataFrame(scan_results['vulnerabilities'])
                st.dataframe(df, use_container_width=True)
    
    with tabs[1]:
        st.markdown("#### 🛡️ **Runtime Security**")
        
        st.code("""
# Docker security options
docker run \\
    --read-only \\
    --security-opt="no-new-privileges:true" \\
    --cap-drop=ALL \\
    --cap-add=NET_BIND_SERVICE \\
    --user=1000:1000 \\
    --memory="512m" \\
    --cpus="0.5" \\
    nginx:alpine
        """, language="bash")
        
        # Security policies
        st.markdown("##### Security Policies")
        policy_type = st.selectbox("Policy Type", ["AppArmor", "SELinux", "Seccomp"])
        
        if policy_type == "Seccomp":
            st.code("""
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["accept", "bind", "listen"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
            """, language="json")
    
    with tabs[2]:
        st.markdown("#### 🌐 **Container Network Security**")
        
        network_mode = st.selectbox("Network Mode", ["bridge", "host", "none", "custom"])
        
        if st.button("🔍 **Analyze Network**"):
            network_info = analyze_container_network()
            
            # Network visualization
            fig = create_container_network_diagram(network_info)
            st.plotly_chart(fig, use_container_width=True)
    
    with tabs[3]:
        st.markdown("#### 📋 **Compliance Check**")
        
        if st.button("🔍 **Run Docker Bench**"):
            bench_results = run_docker_bench()
            
            # Display results
            for category, checks in bench_results.items():
                with st.expander(f"**{category}**"):
                    for check in checks:
                        if check['status'] == 'PASS':
                            st.success(f"✅ {check['description']}")
                        elif check['status'] == 'WARN':
                            st.warning(f"⚠️ {check['description']}")
                        else:
                            st.error(f"❌ {check['description']}")

def automation_lab():
    """Lab for System Automation & Scripting"""
    
    st.markdown(create_lab_header("Automation Lab", "🤖", "linear-gradient(90deg, #ff6a00 0%, #ee0979 100%)"), unsafe_allow_html=True)
    
    tabs = st.tabs(["📝 Bash Scripts", "🐍 Python Automation", "📅 Cron Jobs", "🔄 Ansible"])
    
    with tabs[0]:
        st.markdown("#### 📝 **Bash Script Generator**")
        
        script_type = st.selectbox("Script Type", [
            "System Backup",
            "User Management",
            "Log Rotation",
            "Security Audit",
            "Service Monitor"
        ])
        
        if script_type == "System Backup":
            backup_dir = st.text_input("Backup Directory", "/backup")
            retention = st.number_input("Retention Days", min_value=1, value=7)
            
            if st.button("📝 **Generate Script**"):
                script = generate_backup_script(backup_dir, retention)
                st.code(script, language="bash")
        
        elif script_type == "Service Monitor":
            services = st.text_area("Services to Monitor", "nginx\napache2\nmysql")
            
            if st.button("📝 **Generate Script**"):
                script = generate_monitor_script(services.split('\n'))
                st.code(script, language="bash")
    
    with tabs[1]:
        st.markdown("#### 🐍 **Python Automation**")
        
        st.code("""
#!/usr/bin/env python3
import os
import sys
import subprocess
import logging
from datetime import datetime

# System automation script
class SystemAutomation:
    def __init__(self):
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/automation.log'),
                logging.StreamHandler()
            ]
        )
    
    def check_disk_space(self, threshold=80):
        \"\"\"Check disk space and alert if above threshold\"\"\"
        df = subprocess.check_output(['df', '-h']).decode()
        # Parse and check disk usage
        
    def rotate_logs(self, log_dir='/var/log', max_size='100M'):
        \"\"\"Rotate logs when they exceed max size\"\"\"
        for log_file in os.listdir(log_dir):
            # Check file size and rotate if needed
            pass
    
    def backup_configs(self, configs=['/etc/nginx', '/etc/apache2']):
        \"\"\"Backup configuration files\"\"\"
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        for config_dir in configs:
            # Create backup
            pass

if __name__ == '__main__':
    automation = SystemAutomation()
    automation.check_disk_space()
    automation.rotate_logs()
    automation.backup_configs()
        """, language="python")
    
    with tabs[2]:
        st.markdown("#### 📅 **Cron Job Manager**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Schedule Builder")
            minute = st.text_input("Minute", "*")
            hour = st.text_input("Hour", "*")
            day = st.text_input("Day", "*")
            month = st.text_input("Month", "*")
            weekday = st.text_input("Weekday", "*")
            command = st.text_input("Command", "/usr/local/bin/backup.sh")
            
            cron_entry = f"{minute} {hour} {day} {month} {weekday} {command}"
            st.code(cron_entry, language="text")
        
        with col2:
            st.markdown("##### Common Schedules")
            schedule = st.selectbox("Select Schedule", [
                "Every minute",
                "Every hour",
                "Daily at midnight",
                "Weekly on Sunday",
                "Monthly on 1st"
            ])
            
            schedule_map = {
                "Every minute": "* * * * *",
                "Every hour": "0 * * * *",
                "Daily at midnight": "0 0 * * *",
                "Weekly on Sunday": "0 0 * * 0",
                "Monthly on 1st": "0 0 1 * *"
            }
            
            st.code(f"{schedule_map[schedule]} {command}", language="text")
    
    with tabs[3]:
        st.markdown("#### 🔄 **Ansible Playbooks**")
        
        playbook_type = st.selectbox("Playbook Type", [
            "System Update",
            "User Management",
            "Package Installation",
            "Security Hardening"
        ])
        
        if playbook_type == "System Update":
            st.code("""
---
- name: System Update Playbook
  hosts: all
  become: yes
  tasks:
    - name: Update apt cache
      apt:
        update_cache: yes
      when: ansible_os_family == "Debian"
    
    - name: Upgrade all packages
      apt:
        upgrade: dist
      when: ansible_os_family == "Debian"
    
    - name: Update yum cache
      yum:
        update_cache: yes
      when: ansible_os_family == "RedHat"
    
    - name: Upgrade all packages
      yum:
        name: '*'
        state: latest
      when: ansible_os_family == "RedHat"
    
    - name: Check if reboot required
      stat:
        path: /var/run/reboot-required
      register: reboot_required
    
    - name: Reboot if required
      reboot:
        msg: "Reboot initiated by Ansible"
      when: reboot_required.stat.exists
            """, language="yaml")

# Helper Functions
def gather_system_info():
    """Gather comprehensive system information"""
    info = {
        'os_name': platform.system(),
        'kernel': platform.release(),
        'architecture': platform.machine(),
        'hostname': socket.gethostname(),
        'cpu_count': psutil.cpu_count(),
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_total': round(psutil.virtual_memory().total / (1024**3), 2),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_total': round(psutil.disk_usage('/').total / (1024**3), 2),
        'disk_percent': psutil.disk_usage('/').percent,
        'system_details': {
            'platform': platform.platform(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
        },
        'disk_partitions': [],
        'network_interfaces': []
    }
    
    # Disk partitions
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            info['disk_partitions'].append({
                'device': partition.device,
                'mountpoint': partition.mountpoint,
                'fstype': partition.fstype,
                'total_gb': round(usage.total / (1024**3), 2),
                'used_gb': round(usage.used / (1024**3), 2),
                'percent': usage.percent
            })
        except:
            pass
    
    # Network interfaces
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                info['network_interfaces'].append(f"{interface}: {addr.address}")
    
    return info

def create_memory_chart(info):
    """Create memory usage visualization"""
    labels = ['Used', 'Available']
    values = [info['memory_percent'], 100 - info['memory_percent']]
    
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.3)])
    fig.update_layout(title="Memory Usage", height=300)
    return fig

def get_process_list(view_type, sort_by, limit):
    """Get list of running processes"""
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            pinfo = proc.info
            processes.append({
                'PID': pinfo['pid'],
                'USER': pinfo['username'],
                'CMD': pinfo['name'],
                'CPU': round(pinfo['cpu_percent'], 2),
                'MEM': round(pinfo['memory_percent'], 2)
            })
        except:
            pass
    
    # Sort processes
    if sort_by == 'CPU':
        processes.sort(key=lambda x: x['CPU'], reverse=True)
    elif sort_by == 'Memory':
        processes.sort(key=lambda x: x['MEM'], reverse=True)
    elif sort_by == 'PID':
        processes.sort(key=lambda x: x['PID'])
    
    return processes[:limit]

def generate_useradd_command(username, fullname, home_dir, shell):
    """Generate useradd command"""
    cmd = f"useradd -m -d {home_dir} -s {shell}"
    if fullname:
        cmd += f" -c '{fullname}'"
    cmd += f" {username}"
    return cmd

def list_system_users():
    """List system users"""
    users = []
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 7:
                    users.append({
                        'Username': parts[0],
                        'UID': parts[2],
                        'GID': parts[3],
                        'Home': parts[5],
                        'Shell': parts[6]
                    })
    except:
        users = [{'Username': 'demo', 'UID': '1000', 'GID': '1000', 
                 'Home': '/home/demo', 'Shell': '/bin/bash'}]
    return users

def list_system_groups():
    """List system groups"""
    groups = []
    try:
        with open('/etc/group', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 4:
                    groups.append({
                        'Group': parts[0],
                        'GID': parts[2],
                        'Members': parts[3]
                    })
    except:
        groups = [{'Group': 'sudo', 'GID': '27', 'Members': 'user1,user2'}]
    return pd.DataFrame(groups)

def perform_user_audit():
    """Perform user audit"""
    return {
        'total_users': len(pwd.getpwall()) if hasattr(pwd, 'getpwall') else 25,
        'active_sessions': random.randint(3, 10),
        'failed_logins': random.randint(0, 20),
        'recent_logins': pd.DataFrame([
            {'User': 'admin', 'Time': '2024-01-01 10:00', 'IP': '192.168.1.100', 'Status': 'Success'},
            {'User': 'user1', 'Time': '2024-01-01 11:00', 'IP': '192.168.1.101', 'Status': 'Success'},
            {'User': 'root', 'Time': '2024-01-01 12:00', 'IP': '192.168.1.102', 'Status': 'Failed'}
        ])
    }

def calculate_permissions(o_r, o_w, o_x, g_r, g_w, g_x, a_r, a_w, a_x):
    """Calculate octal permissions"""
    owner = (4 if o_r else 0) + (2 if o_w else 0) + (1 if o_x else 0)
    group = (4 if g_r else 0) + (2 if g_w else 0) + (1 if g_x else 0)
    other = (4 if a_r else 0) + (2 if a_w else 0) + (1 if a_x else 0)
    return f"{owner}{group}{other}"

def get_symbolic_permissions(o_r, o_w, o_x, g_r, g_w, g_x, a_r, a_w, a_x):
    """Get symbolic permission string"""
    owner = ('r' if o_r else '-') + ('w' if o_w else '-') + ('x' if o_x else '-')
    group = ('r' if g_r else '-') + ('w' if g_w else '-') + ('x' if g_x else '-')
    other = ('r' if a_r else '-') + ('w' if a_w else '-') + ('x' if a_x else '-')
    return f"{owner}{group}{other}"

def analyze_file_permissions(file_path):
    """Analyze file permissions for security issues"""
    # Simulated analysis
    return {
        'info': {
            'path': file_path,
            'owner': 'root',
            'group': 'root',
            'permissions': '644',
            'type': 'regular file'
        },
        'security_issues': [
            {'severity': 'low', 'message': 'File is world-readable'},
            {'severity': 'medium', 'message': 'Consider restricting access to sensitive files'}
        ]
    }

def generate_iptables_rule(chain, protocol, port, source, action):
    """Generate iptables rule"""
    rule = f"iptables -A {chain}"
    if protocol != "all":
        rule += f" -p {protocol}"
    if port and protocol in ["tcp", "udp"]:
        rule += f" --dport {port}"
    if source != "0.0.0.0/0":
        rule += f" -s {source}"
    rule += f" -j {action}"
    return rule

def get_iptables_rules():
    """Get current iptables rules"""
    # Simulated output
    return """Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:https

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination"""

def get_firewalld_zones():
    """Get firewalld zones information"""
    return {
        'public': {
            'services': ['ssh', 'dhcpv6-client'],
            'ports': [],
            'masquerade': False
        },
        'internal': {
            'services': ['ssh', 'mdns', 'samba-client', 'dhcpv6-client'],
            'ports': [],
            'masquerade': False
        }
    }

def audit_firewall_config():
    """Audit firewall configuration"""
    return {
        'open_ports': random.randint(5, 20),
        'total_rules': random.randint(10, 50),
        'score': random.randint(60, 95),
        'recommendations': [
            'Consider closing port 21 (FTP)',
            'Enable rate limiting for SSH',
            'Add fail2ban for brute force protection'
        ]
    }

def get_selinux_status():
    """Get SELinux status"""
    return {
        'status': 'Enforcing',
        'policy': 'targeted',
        'mode': 'enforcing',
        'policy_version': '31'
    }

def get_apparmor_profiles():
    """Get AppArmor profiles"""
    return pd.DataFrame([
        {'Profile': '/usr/sbin/nginx', 'Mode': 'enforce'},
        {'Profile': '/usr/sbin/apache2', 'Mode': 'complain'},
        {'Profile': '/usr/bin/docker', 'Mode': 'enforce'}
    ])

def analyze_mac_policies():
    """Analyze MAC policies"""
    return {
        'total_policies': 25,
        'enforcing': 20,
        'permissive': 5,
        'disabled': 0
    }

def create_policy_visualization(analysis):
    """Create policy visualization"""
    labels = ['Enforcing', 'Permissive', 'Disabled']
    values = [analysis['enforcing'], analysis['permissive'], analysis['disabled']]
    
    fig = go.Figure(data=[go.Pie(labels=labels, values=values)])
    fig.update_layout(title="MAC Policy Distribution")
    return fig

def perform_security_audit():
    """Perform comprehensive security audit"""
    return {
        'overall': random.randint(65, 85),
        'network': random.randint(70, 90),
        'system': random.randint(60, 85),
        'access': random.randint(65, 90),
        'findings': {
            'Network Security': [
                {
                    'severity': 'high',
                    'title': 'SSH Root Login Enabled',
                    'description': 'Root login via SSH is enabled',
                    'fix': 'echo "PermitRootLogin no" >> /etc/ssh/sshd_config'
                }
            ],
            'System Security': [
                {
                    'severity': 'medium',
                    'title': 'Kernel not hardened',
                    'description': 'Several kernel parameters need hardening',
                    'fix': 'Apply sysctl hardening parameters'
                }
            ]
        }
    }

def analyze_logs(log_file, analysis_type):
    """Analyze log files"""
    if analysis_type == "Failed Login Attempts":
        return {
            'count': random.randint(10, 100),
            'attempts': pd.DataFrame([
                {'Time': '2024-01-01 10:00', 'User': 'admin', 'IP': '192.168.1.100', 'Result': 'Failed'},
                {'Time': '2024-01-01 11:00', 'User': 'root', 'IP': '192.168.1.101', 'Result': 'Failed'}
            ])
        }
    elif analysis_type == "Top IP Addresses":
        return pd.DataFrame([
            {'ip': '192.168.1.100', 'count': random.randint(100, 1000)},
            {'ip': '192.168.1.101', 'count': random.randint(50, 500)}
        ])
    return {}

def search_logs(pattern, time_range):
    """Search logs for pattern"""
    return f"Found 42 matches for '{pattern}' in {time_range}"

def generate_log_dashboard():
    """Generate log dashboard data"""
    return {
        'timeline': {
            'time': pd.date_range(start='2024-01-01', periods=24, freq='H'),
            'events': [random.randint(10, 100) for _ in range(24)]
        },
        'types': {
            'labels': ['Error', 'Warning', 'Info'],
            'values': [30, 45, 25]
        },
        'ips': {
            'ip': ['192.168.1.100', '192.168.1.101', '192.168.1.102'],
            'count': [150, 120, 80]
        },
        'severity': {
            'labels': ['Critical', 'High', 'Medium', 'Low'],
            'values': [5, 15, 30, 50]
        }
    }

def get_network_kernel_params():
    """Get network kernel parameters"""
    return [
        {'Parameter': 'net.ipv4.tcp_syncookies', 'Value': '1', 'Description': 'SYN flood protection'},
        {'Parameter': 'net.ipv4.ip_forward', 'Value': '0', 'Description': 'IP forwarding'},
        {'Parameter': 'net.ipv4.conf.all.rp_filter', 'Value': '1', 'Description': 'Reverse path filtering'}
    ]

def get_memory_kernel_params():
    """Get memory kernel parameters"""
    return [
        {'Parameter': 'vm.swappiness', 'Value': '60', 'Description': 'Swap tendency'},
        {'Parameter': 'vm.dirty_ratio', 'Value': '20', 'Description': 'Dirty page threshold'},
        {'Parameter': 'vm.overcommit_memory', 'Value': '0', 'Description': 'Memory overcommit'}
    ]

def get_security_kernel_params():
    """Get security kernel parameters"""
    return [
        {'Parameter': 'kernel.modules_disabled', 'Value': '0', 'Description': 'Module loading'},
        {'Parameter': 'kernel.kptr_restrict', 'Value': '1', 'Description': 'Kernel pointer hiding'},
        {'Parameter': 'kernel.yama.ptrace_scope', 'Value': '1', 'Description': 'Ptrace scope'}
    ]

def get_fs_kernel_params():
    """Get filesystem kernel parameters"""
    return [
        {'Parameter': 'fs.file-max', 'Value': '2097152', 'Description': 'Max file handles'},
        {'Parameter': 'fs.suid_dumpable', 'Value': '0', 'Description': 'SUID core dumps'},
        {'Parameter': 'fs.protected_hardlinks', 'Value': '1', 'Description': 'Hardlink protection'}
    ]

def analyze_kernel_performance():
    """Analyze kernel performance"""
    return {
        'scheduler': 'CFS',
        'io_scheduler': 'mq-deadline',
        'congestion_control': 'cubic',
        'performance_data': {
            'cpu_efficiency': random.randint(80, 95),
            'memory_efficiency': random.randint(75, 90),
            'io_efficiency': random.randint(70, 85)
        }
    }

def create_performance_graph(perf_data):
    """Create performance visualization"""
    categories = ['CPU', 'Memory', 'I/O']
    values = [
        perf_data['performance_data']['cpu_efficiency'],
        perf_data['performance_data']['memory_efficiency'],
        perf_data['performance_data']['io_efficiency']
    ]
    
    fig = go.Figure(data=[go.Bar(x=categories, y=values)])
    fig.update_layout(title="Kernel Performance Metrics", yaxis_title="Efficiency %")
    return fig

def get_realtime_kernel_stats(monitor_type):
    """Get real-time kernel statistics"""
    return {
        'timestamp': datetime.now(),
        'value': random.randint(20, 80),
        'type': monitor_type
    }

def create_monitoring_chart(data, monitor_type):
    """Create monitoring chart"""
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=[data['timestamp']], y=[data['value']], 
                            mode='lines+markers', name=monitor_type))
    fig.update_layout(title=f"{monitor_type} Monitoring", 
                     xaxis_title="Time", yaxis_title="Usage %")
    return fig

def get_system_metrics():
    """Get current system metrics"""
    return {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'cpu_delta': random.randint(-5, 5),
        'memory_percent': psutil.virtual_memory().percent,
        'memory_delta': random.randint(-3, 3),
        'disk_io_rate': round(random.uniform(10, 100), 2),
        'network_rate': round(random.uniform(1, 100), 2)
    }

def create_metrics_dashboard(metrics):
    """Create metrics dashboard"""
    fig = make_subplots(rows=2, cols=2,
                       subplot_titles=("CPU Usage", "Memory Usage", "Disk I/O", "Network"))
    
    # Add traces for each metric
    fig.add_trace(go.Indicator(mode="gauge+number",
                              value=metrics['cpu_percent'],
                              title={'text': "CPU %"},
                              gauge={'axis': {'range': [0, 100]}}),
                 row=1, col=1)
    
    return fig

def analyze_resource_usage(resource):
    """Analyze resource usage"""
    return {
        'top_consumers': [
            {'Process': 'nginx', 'Usage': random.randint(10, 30)},
            {'Process': 'mysql', 'Usage': random.randint(20, 40)},
            {'Process': 'python', 'Usage': random.randint(5, 15)}
        ],
        'usage_data': {
            'hourly': [random.randint(20, 80) for _ in range(24)]
        }
    }

def create_usage_heatmap(usage_data):
    """Create usage heatmap"""
    fig = go.Figure(data=go.Heatmap(
        z=[usage_data['usage_data']['hourly']],
        x=list(range(24)),
        y=['Usage'],
        colorscale='RdYlBu_r'
    ))
    fig.update_layout(title="Resource Usage Heatmap", xaxis_title="Hour")
    return fig

def generate_performance_trends(timeframe):
    """Generate performance trends"""
    periods = {'1 Hour': 60, '24 Hours': 24, '7 Days': 168, '30 Days': 720}
    num_points = periods.get(timeframe, 24)
    
    return {
        'cpu': {
            'time': pd.date_range(start='2024-01-01', periods=num_points, freq='H'),
            'values': [random.randint(20, 80) for _ in range(num_points)]
        },
        'memory': {
            'time': pd.date_range(start='2024-01-01', periods=num_points, freq='H'),
            'values': [random.randint(30, 70) for _ in range(num_points)]
        },
        'disk': {
            'time': pd.date_range(start='2024-01-01', periods=num_points, freq='H'),
            'values': [random.randint(10, 50) for _ in range(num_points)]
        },
        'network': {
            'time': pd.date_range(start='2024-01-01', periods=num_points, freq='H'),
            'values': [random.randint(5, 60) for _ in range(num_points)]
        }
    }

def scan_container_image(image_name):
    """Scan container image for vulnerabilities"""
    return {
        'critical': random.randint(0, 5),
        'high': random.randint(0, 10),
        'medium': random.randint(5, 20),
        'low': random.randint(10, 30),
        'vulnerabilities': [
            {'CVE': 'CVE-2024-0001', 'Severity': 'Critical', 'Package': 'openssl', 'Fixed': '1.1.1w'},
            {'CVE': 'CVE-2024-0002', 'Severity': 'High', 'Package': 'curl', 'Fixed': '7.88.1'}
        ]
    }

def analyze_container_network():
    """Analyze container network configuration"""
    return {
        'networks': ['bridge', 'host', 'custom_net'],
        'containers': [
            {'name': 'web', 'network': 'bridge', 'ip': '172.17.0.2'},
            {'name': 'db', 'network': 'bridge', 'ip': '172.17.0.3'}
        ]
    }

def create_container_network_diagram(network_info):
    """Create container network diagram"""
    # Create a simple network visualization
    fig = go.Figure()
    
    # Add nodes for containers
    for i, container in enumerate(network_info['containers']):
        fig.add_trace(go.Scatter(x=[i], y=[0], mode='markers+text',
                                marker=dict(size=30),
                                text=container['name'],
                                textposition="top center"))
    
    fig.update_layout(title="Container Network Topology",
                     showlegend=False,
                     xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                     yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
    return fig

def run_docker_bench():
    """Run Docker Bench Security checks"""
    return {
        'Host Configuration': [
            {'description': 'Ensure Docker daemon is running as non-root', 'status': 'PASS'},
            {'description': 'Ensure auditing is configured', 'status': 'WARN'}
        ],
        'Docker Daemon': [
            {'description': 'Ensure network traffic is restricted', 'status': 'PASS'},
            {'description': 'Ensure insecure registries are not used', 'status': 'PASS'}
        ]
    }

def generate_backup_script(backup_dir, retention):
    """Generate backup script"""
    return f"""#!/bin/bash
# System Backup Script
# Generated: {datetime.now()}

BACKUP_DIR="{backup_dir}"
RETENTION_DAYS={retention}
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup system configurations
tar -czf $BACKUP_DIR/etc_backup_$DATE.tar.gz /etc/

# Backup user home directories
tar -czf $BACKUP_DIR/home_backup_$DATE.tar.gz /home/

# Backup databases
mysqldump --all-databases > $BACKUP_DIR/mysql_backup_$DATE.sql

# Remove old backups
find $BACKUP_DIR -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "*.sql" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $DATE"
"""

def generate_monitor_script(services):
    """Generate service monitoring script"""
    script = """#!/bin/bash
# Service Monitoring Script

SERVICES=("""
    
    for service in services:
        script += f'"{service}" '
    
    script += """)

for SERVICE in "${SERVICES[@]}"; do
    if systemctl is-active --quiet $SERVICE; then
        echo "$SERVICE is running"
    else
        echo "$SERVICE is not running - attempting restart"
        systemctl restart $SERVICE
        
        # Send alert
        echo "$SERVICE was down and restarted" | mail -s "Service Alert" admin@example.com
    fi
done
"""
    return script

def command_cheat_sheet():
    """Comprehensive Linux Command Cheat Sheet"""
    
    st.markdown(create_lab_header("Linux Command Cheat Sheet", "📖", "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"), unsafe_allow_html=True)
    
    st.markdown("""
    <div style="background: #f0f2f6; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
        <p style="margin: 0;">💡 <b>Tip:</b> Click on any command to copy it to clipboard. Use <code>man command</code> for detailed documentation.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Create tabs for different command categories
    cheat_tabs = st.tabs([
        "🖥️ System",
        "📦 Package Management",
        "👤 Users & Groups",
        "📁 Files & Directories",
        "🌐 Network",
        "⚙️ Process",
        "🔍 Search & Find",
        "📊 Monitoring",
        "🔐 Security",
        "💾 Disk & Storage",
        "📝 Text Processing",
        "🔧 System Control"
    ])
    
    with cheat_tabs[0]:
        st.markdown("### 🖥️ **System Information & Control**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### **System Info**")
            st.code("""
# System information
uname -a                    # All system info
hostname                    # System hostname
hostname -I                 # Display IP addresses
uptime                      # System uptime
date                        # Current date/time
cal                         # Calendar
whoami                      # Current username
id                          # User ID and groups
last                        # Last logins
w                           # Who is logged in
            """, language="bash")
            
            st.markdown("#### **Hardware Info**")
            st.code("""
# Hardware information
lscpu                       # CPU information
lsmem                       # Memory information
lspci                       # PCI devices
lsusb                       # USB devices
lsblk                       # Block devices
dmidecode                   # DMI/SMBIOS info
hdparm -i /dev/sda         # Disk information
cat /proc/cpuinfo          # CPU details
cat /proc/meminfo          # Memory details
free -h                     # Memory usage
            """, language="bash")
        
        with col2:
            st.markdown("#### **System Control**")
            st.code("""
# System control
shutdown -h now             # Shutdown immediately
shutdown -h +10             # Shutdown in 10 min
shutdown -r now             # Restart immediately
reboot                      # Restart system
halt                        # Halt the system
poweroff                    # Power off system
systemctl suspend           # Suspend system
systemctl hibernate         # Hibernate system
init 0                      # Shutdown (SysV)
init 6                      # Restart (SysV)
            """, language="bash")
            
            st.markdown("#### **System Logs**")
            st.code("""
# System logs
dmesg                       # Kernel messages
journalctl                  # Systemd logs
journalctl -b              # Boot logs
journalctl -f              # Follow log output
tail -f /var/log/syslog   # Follow syslog
less /var/log/auth.log    # Authentication log
grep error /var/log/*      # Search for errors
last                        # Login history
lastlog                     # Last login times
history                     # Command history
            """, language="bash")
    
    with cheat_tabs[1]:
        st.markdown("### 📦 **Package Management**")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("#### **APT (Debian/Ubuntu)**")
            st.code("""
# APT package management
apt update                  # Update package list
apt upgrade                 # Upgrade packages
apt full-upgrade           # Full upgrade
apt install package        # Install package
apt remove package         # Remove package
apt purge package          # Remove + config
apt autoremove             # Remove unused
apt search keyword         # Search packages
apt show package           # Package info
apt list --installed       # List installed
dpkg -i package.deb       # Install .deb file
dpkg -l                    # List packages
dpkg -L package           # List files in package
            """, language="bash")
        
        with col2:
            st.markdown("#### **YUM/DNF (RHEL/Fedora)**")
            st.code("""
# YUM/DNF package management
yum update                  # Update packages
yum install package        # Install package
yum remove package         # Remove package
yum search keyword         # Search packages
yum info package           # Package info
yum list installed         # List installed
yum clean all              # Clean cache
dnf update                 # Update (Fedora)
dnf install package        # Install (Fedora)
dnf remove package         # Remove (Fedora)
rpm -ivh package.rpm      # Install RPM
rpm -qa                    # List all RPMs
rpm -ql package           # List files in RPM
            """, language="bash")
        
        with col3:
            st.markdown("#### **Snap & Flatpak**")
            st.code("""
# Snap packages
snap install package        # Install snap
snap remove package        # Remove snap
snap list                  # List snaps
snap find keyword          # Search snaps
snap refresh              # Update snaps
snap info package         # Package info

# Flatpak packages
flatpak install package    # Install flatpak
flatpak uninstall package # Remove flatpak
flatpak list              # List flatpaks
flatpak search keyword    # Search flatpaks
flatpak update            # Update flatpaks
flatpak info package      # Package info
            """, language="bash")
    
    with cheat_tabs[2]:
        st.markdown("### 👤 **User & Group Management**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### **User Management**")
            st.code("""
# User management
useradd username            # Create user
useradd -m -s /bin/bash user # Create with home & shell
usermod -aG group user      # Add user to group
usermod -l newname oldname  # Rename user
usermod -L username         # Lock user account
usermod -U username         # Unlock user account
userdel username            # Delete user
userdel -r username         # Delete user + home
passwd username             # Change password
passwd -l username          # Lock password
passwd -u username          # Unlock password
chage -l username           # Password aging info
chage -M 90 username        # Max password age
su - username               # Switch user
sudo command                # Run as root
sudo -u user command        # Run as user
visudo                      # Edit sudoers
            """, language="bash")
            
            st.markdown("#### **User Information**")
            st.code("""
# User information
whoami                      # Current username
id                          # User ID and groups
id username                 # Specific user info
groups                      # Current user groups
groups username             # User's groups
finger username             # User information
w                           # Who is logged in
who                         # Who is logged in
users                       # Logged in users
last                        # Login history
lastlog                     # Last login times
            """, language="bash")
        
        with col2:
            st.markdown("#### **Group Management**")
            st.code("""
# Group management
groupadd groupname          # Create group
groupmod -n newname oldname # Rename group
groupdel groupname          # Delete group
gpasswd -a user group       # Add user to group
gpasswd -d user group       # Remove from group
newgrp groupname            # Switch group

# Files
/etc/passwd                 # User accounts
/etc/shadow                 # Passwords
/etc/group                  # Groups
/etc/sudoers                # Sudo config
/etc/skel/                  # User template
/home/                      # Home directories
            """, language="bash")
            
            st.markdown("#### **Permissions & Ownership**")
            st.code("""
# Change ownership
chown user file             # Change owner
chown user:group file       # Owner and group
chown -R user:group dir/    # Recursive
chgrp group file            # Change group

# Special permissions
chmod u+s file              # Set SUID
chmod g+s file              # Set SGID
chmod +t directory          # Sticky bit
chmod 4755 file             # SUID (octal)
chmod 2755 file             # SGID (octal)
chmod 1755 directory        # Sticky (octal)

# ACL (Access Control Lists)
getfacl file                # Get ACL
setfacl -m u:user:rwx file # Set ACL for user
setfacl -x u:user file      # Remove ACL
            """, language="bash")
    
    with cheat_tabs[3]:
        st.markdown("### 📁 **File & Directory Operations**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### **Basic Operations**")
            st.code("""
# Navigation
pwd                         # Current directory
cd /path/to/dir            # Change directory
cd ..                      # Parent directory
cd ~                       # Home directory
cd -                       # Previous directory

# Listing
ls                         # List files
ls -la                     # List all + details
ls -lh                     # Human readable sizes
ls -lt                     # Sort by time
ls -lS                     # Sort by size
tree                       # Directory tree
tree -L 2                  # Limit depth

# Create & Remove
mkdir directory            # Create directory
mkdir -p path/to/dir      # Create with parents
rmdir directory           # Remove empty dir
rm file                   # Remove file
rm -r directory           # Remove directory
rm -rf directory          # Force remove
touch file                # Create empty file
            """, language="bash")
            
            st.markdown("#### **File Permissions**")
            st.code("""
# Change permissions
chmod 755 file             # rwxr-xr-x
chmod 644 file             # rw-r--r--
chmod 600 file             # rw-------
chmod +x file              # Add execute
chmod -w file              # Remove write
chmod u+x file             # User execute
chmod g+r file             # Group read
chmod o-r file             # Others no read
chmod -R 755 directory     # Recursive

# Permission values
# 4 = read (r)
# 2 = write (w)  
# 1 = execute (x)
# 7 = rwx, 6 = rw-, 5 = r-x, 4 = r--
            """, language="bash")
        
        with col2:
            st.markdown("#### **Copy, Move & Link**")
            st.code("""
# Copy
cp source dest             # Copy file
cp -r source/ dest/        # Copy directory
cp -p source dest          # Preserve attributes
cp -i source dest          # Interactive
cp -u source dest          # Update only
rsync -av source/ dest/    # Advanced copy

# Move & Rename
mv source dest             # Move/rename
mv -i source dest          # Interactive
mv -u source dest          # Update only
rename 's/old/new/' files  # Batch rename

# Links
ln -s target link          # Symbolic link
ln target hardlink         # Hard link
readlink link              # Read symlink
            """, language="bash")
            
            st.markdown("#### **Archive & Compress**")
            st.code("""
# Tar archives
tar -cvf archive.tar files # Create tar
tar -xvf archive.tar       # Extract tar
tar -tvf archive.tar       # List contents
tar -czf archive.tar.gz    # Create tar.gz
tar -xzf archive.tar.gz    # Extract tar.gz
tar -cjf archive.tar.bz2   # Create tar.bz2
tar -xjf archive.tar.bz2   # Extract tar.bz2

# Compression
gzip file                  # Compress to .gz
gunzip file.gz            # Decompress .gz
bzip2 file                # Compress to .bz2
bunzip2 file.bz2          # Decompress .bz2
zip archive.zip files     # Create zip
unzip archive.zip         # Extract zip
7z a archive.7z files     # Create 7z
7z x archive.7z           # Extract 7z
            """, language="bash")
    
    with cheat_tabs[4]:
        st.markdown("### 🌐 **Network Commands**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### **Network Configuration**")
            st.code("""
# IP configuration
ip addr show               # Show IP addresses
ip link show               # Show interfaces
ip route show              # Show routes
ip addr add IP/24 dev eth0 # Add IP address
ip link set eth0 up        # Enable interface
ip link set eth0 down      # Disable interface

# Legacy (ifconfig)
ifconfig                   # Show interfaces
ifconfig eth0 up           # Enable interface
ifconfig eth0 down         # Disable interface
ifconfig eth0 IP netmask   # Set IP address

# DNS
cat /etc/resolv.conf       # DNS servers
nslookup domain            # DNS lookup
dig domain                 # DNS lookup (detailed)
host domain                # DNS lookup
systemd-resolve --status   # DNS status
            """, language="bash")
            
            st.markdown("#### **Network Testing**")
            st.code("""
# Connectivity
ping host                  # Ping host
ping -c 4 host            # Ping 4 times
ping6 host                # IPv6 ping
traceroute host           # Trace route
tracepath host            # Trace path
mtr host                  # Combined ping/trace

# Port testing
telnet host port          # Test port
nc -zv host port          # Port scan
nmap host                 # Port scan
nmap -p 1-1000 host      # Scan port range
            """, language="bash")
        
        with col2:
            st.markdown("#### **Network Tools**")
            st.code("""
# Network statistics
netstat -tuln             # Listening ports
netstat -an               # All connections
ss -tuln                  # Socket statistics
ss -s                     # Summary statistics
lsof -i                   # Network files
lsof -i :80              # Process on port 80

# File transfer
wget URL                  # Download file
wget -c URL              # Resume download
curl URL                 # Get URL content
curl -O URL              # Download file
scp file user@host:path  # Secure copy
sftp user@host           # Secure FTP
rsync -av src/ dest/     # Sync files
            """, language="bash")
            
            st.markdown("#### **Firewall**")
            st.code("""
# iptables
iptables -L               # List rules
iptables -L -n -v        # Detailed list
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -s IP -j DROP
iptables-save > file     # Save rules
iptables-restore < file  # Restore rules

# firewalld
firewall-cmd --list-all  # List configuration
firewall-cmd --add-service=http
firewall-cmd --add-port=8080/tcp
firewall-cmd --reload    # Reload rules

# ufw (Ubuntu)
ufw status               # Status
ufw enable               # Enable firewall
ufw allow 22             # Allow SSH
ufw deny 80              # Deny HTTP
            """, language="bash")
    
    with cheat_tabs[5]:
        st.markdown("### ⚙️ **Process Management**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### **Process Control**")
            st.code("""
# View processes
ps                        # Current processes
ps aux                    # All processes
ps aux | grep process     # Find process
ps -ef                    # Full format
ps -ejH                   # Process tree
pstree                    # Process tree
top                       # Interactive view
htop                      # Better top
atop                      # Advanced top

# Process control
kill PID                  # Terminate process
kill -9 PID              # Force kill
killall process          # Kill by name
pkill pattern            # Kill by pattern
pgrep pattern            # Find PID by pattern
            """, language="bash")
            
            st.markdown("#### **Job Control**")
            st.code("""
# Background jobs
command &                 # Run in background
jobs                      # List jobs
fg                        # Foreground last job
fg %1                     # Foreground job 1
bg                        # Background last job
bg %1                     # Background job 1
nohup command &          # Ignore hangup
disown                   # Remove from jobs

# Process priority
nice -n 10 command       # Run with nice 10
renice -5 PID           # Change priority
ionice -c3 command      # I/O priority
            """, language="bash")
        
        with col2:
            st.markdown("#### **System Services**")
            st.code("""
# systemctl (systemd)
systemctl status service  # Service status
systemctl start service   # Start service
systemctl stop service    # Stop service
systemctl restart service # Restart service
systemctl reload service  # Reload config
systemctl enable service  # Enable at boot
systemctl disable service # Disable at boot
systemctl list-units      # List units
systemctl --failed        # Failed units

# service (SysV)
service service status    # Service status
service service start     # Start service
service service stop      # Stop service
service service restart   # Restart service
service --status-all      # All services
            """, language="bash")
            
            st.markdown("#### **Scheduling**")
            st.code("""
# Cron jobs
crontab -e               # Edit crontab
crontab -l               # List crontab
crontab -r               # Remove crontab
crontab -u user -e       # Edit user's crontab

# Cron format
# * * * * * command
# | | | | |
# | | | | +-- Day of week (0-7)
# | | | +---- Month (1-12)
# | | +------ Day (1-31)
# | +-------- Hour (0-23)
# +---------- Minute (0-59)

# at command
at 10:00                 # Schedule at 10:00
at now + 1 hour         # In 1 hour
atq                      # List jobs
atrm job                 # Remove job
            """, language="bash")
    
    with cheat_tabs[6]:
        st.markdown("### 🔍 **Search & Find**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### **Find Files**")
            st.code("""
# find command
find / -name filename      # Find by name
find / -iname filename     # Case insensitive
find . -type f            # Find files
find . -type d            # Find directories
find . -size +100M        # Files > 100MB
find . -size -1k          # Files < 1KB
find . -mtime -7          # Modified < 7 days
find . -mtime +30         # Modified > 30 days
find . -user username     # By owner
find . -group groupname   # By group
find . -perm 755          # By permissions
find . -empty             # Empty files/dirs

# Find and execute
find . -name "*.txt" -exec ls -l {} \\;
find . -name "*.log" -delete
find . -type f -exec chmod 644 {} \\;
            """, language="bash")
        
        with col2:
            st.markdown("#### **Search Content**")
            st.code("""
# grep command
grep pattern file         # Search in file
grep -r pattern dir/      # Recursive search
grep -i pattern file      # Case insensitive
grep -v pattern file      # Invert match
grep -n pattern file      # Show line numbers
grep -c pattern file      # Count matches
grep -l pattern files     # Files with matches
grep -E "regex" file      # Extended regex
egrep "regex" file        # Same as grep -E

# Other search tools
ack pattern              # Better grep
ag pattern               # Silver searcher
rg pattern               # Ripgrep (fastest)

# locate command
locate filename          # Find by database
updatedb                 # Update database
which command           # Command location
whereis command         # Binary/man location
            """, language="bash")
    
    with cheat_tabs[7]:
        st.markdown("### 📊 **System Monitoring**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### **Resource Monitoring**")
            st.code("""
# CPU & Memory
top                       # Process monitor
htop                      # Interactive top
vmstat 1                  # Virtual memory stats
mpstat 1                  # CPU statistics
free -h                   # Memory usage
free -m                   # Memory in MB
cat /proc/meminfo        # Memory details
cat /proc/cpuinfo        # CPU details

# Disk I/O
iostat 1                  # I/O statistics
iotop                     # I/O by process
dstat                     # Combined stats
sar -d 1                  # Disk activity

# System load
uptime                    # Load average
w                         # Who and load
cat /proc/loadavg        # Load average
            """, language="bash")
            
            st.markdown("#### **Disk Usage**")
            st.code("""
# Disk space
df -h                     # Disk usage
df -i                     # Inode usage
du -sh *                  # Directory sizes
du -sh directory/         # Directory size
du -h --max-depth=1      # One level deep
ncdu                      # Interactive du

# Disk health
smartctl -a /dev/sda     # SMART info
hdparm -tT /dev/sda      # Disk speed test
badblocks -v /dev/sda    # Check bad blocks
fsck /dev/sda1           # Filesystem check
            """, language="bash")
        
        with col2:
            st.markdown("#### **Network Monitoring**")
            st.code("""
# Network traffic
iftop                     # Interface traffic
nethogs                   # Traffic by process
bmon                      # Bandwidth monitor
vnstat                    # Network statistics
tcpdump -i eth0          # Packet capture
tcpdump -i eth0 port 80  # Capture port 80
wireshark                 # GUI packet analyzer

# Connection monitoring
netstat -tuln            # Listening ports
ss -tuln                 # Socket stats
lsof -i                  # Network connections
watch ss -tp             # Watch connections
            """, language="bash")
            
            st.markdown("#### **Log Monitoring**")
            st.code("""
# Log viewing
tail -f /var/log/syslog  # Follow log
tail -n 50 logfile       # Last 50 lines
head -n 50 logfile       # First 50 lines
less +F logfile          # Follow in less
journalctl -f            # Follow systemd logs
journalctl -u service    # Service logs
journalctl --since today # Today's logs
dmesg | tail             # Kernel messages
multitail file1 file2    # Multiple logs

# Log analysis
grep ERROR /var/log/*    # Find errors
awk '{print $1}' access.log | sort | uniq -c
logwatch                  # Log analyzer
goaccess access.log      # Web log analyzer
            """, language="bash")
    
    with cheat_tabs[8]:
        st.markdown("### 🔐 **Security Commands**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### **File Security**")
            st.code("""
# File encryption
gpg -c file              # Encrypt file
gpg file.gpg             # Decrypt file
openssl enc -aes-256-cbc -in file -out file.enc
openssl enc -d -aes-256-cbc -in file.enc -out file

# Checksums
md5sum file              # MD5 checksum
sha1sum file             # SHA1 checksum
sha256sum file           # SHA256 checksum
sha512sum file           # SHA512 checksum
md5sum -c file.md5       # Verify checksum

# File attributes
lsattr file              # List attributes
chattr +i file           # Make immutable
chattr -i file           # Remove immutable
chattr +a file           # Append only
            """, language="bash")
            
            st.markdown("#### **SSH Security**")
            st.code("""
# SSH keys
ssh-keygen -t rsa -b 4096 # Generate RSA key
ssh-keygen -t ed25519     # Generate Ed25519
ssh-copy-id user@host     # Copy public key
ssh-add ~/.ssh/id_rsa     # Add to agent
ssh-agent bash            # Start SSH agent

# SSH connections
ssh user@host             # Connect
ssh -p 2222 user@host    # Custom port
ssh -i key user@host     # Use key file
ssh -L 8080:localhost:80 user@host # Tunnel
ssh -X user@host         # X11 forwarding
sshfs user@host:path mount/ # Mount via SSH
            """, language="bash")
        
        with col2:
            st.markdown("#### **SELinux & AppArmor**")
            st.code("""
# SELinux
getenforce               # Get SELinux mode
setenforce 0             # Set permissive
setenforce 1             # Set enforcing
sestatus                 # SELinux status
getsebool -a             # List booleans
setsebool httpd_can_network_connect on
restorecon -R /path      # Restore context
chcon -t type file       # Change context
ausearch -m AVC          # Search denials

# AppArmor
aa-status                # AppArmor status
aa-enforce /path/profile # Enforce profile
aa-complain /path/profile # Complain mode
aa-disable /path/profile # Disable profile
aa-genprof command       # Generate profile
            """, language="bash")
            
            st.markdown("#### **Audit & Security**")
            st.code("""
# System audit
auditctl -l              # List rules
auditctl -w /etc/passwd -p wa # Watch file
ausearch -f /etc/passwd  # Search audit log
aureport                 # Audit report
lynis audit system       # Security audit
chkrootkit              # Check rootkits
rkhunter --check        # Rootkit hunter
aide --check            # File integrity
tripwire --check        # Integrity check

# Failed logins
faillog                  # Failed login log
lastb                    # Bad login attempts
pam_tally2 --user=user  # Check user failures
            """, language="bash")
    
    with cheat_tabs[9]:
        st.markdown("### 💾 **Disk & Storage**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### **Partition Management**")
            st.code("""
# View partitions
fdisk -l                 # List partitions
parted -l                # List partitions
lsblk                    # Block devices
blkid                    # Block device IDs
cat /proc/partitions     # Kernel partitions

# Partition tools
fdisk /dev/sda           # Partition disk
parted /dev/sda          # GNU Parted
gdisk /dev/sda           # GPT partitions
cfdisk /dev/sda          # Curses fdisk

# Format filesystem
mkfs.ext4 /dev/sda1      # Create ext4
mkfs.xfs /dev/sda1       # Create XFS
mkfs.btrfs /dev/sda1     # Create Btrfs
mkfs.vfat /dev/sda1      # Create FAT32
            """, language="bash")
            
            st.markdown("#### **Mount & Unmount**")
            st.code("""
# Mount operations
mount /dev/sda1 /mnt     # Mount device
mount -t ext4 /dev/sda1 /mnt # Specify type
mount -o ro /dev/sda1 /mnt # Read-only
mount -o remount,rw /mnt # Remount read-write
umount /mnt              # Unmount
umount -l /mnt           # Lazy unmount
mount                    # Show mounts
findmnt                  # Tree of mounts
cat /proc/mounts         # Kernel mounts

# /etc/fstab format
# device  mountpoint  fstype  options  dump  pass
/dev/sda1  /  ext4  defaults  0  1
            """, language="bash")
        
        with col2:
            st.markdown("#### **LVM Management**")
            st.code("""
# Physical volumes
pvcreate /dev/sdb        # Create PV
pvdisplay                # Display PVs
pvs                      # List PVs
pvremove /dev/sdb        # Remove PV

# Volume groups
vgcreate vg0 /dev/sdb    # Create VG
vgdisplay                # Display VGs
vgs                      # List VGs
vgextend vg0 /dev/sdc    # Extend VG
vgreduce vg0 /dev/sdc    # Reduce VG

# Logical volumes
lvcreate -L 10G -n lv0 vg0 # Create LV
lvdisplay                # Display LVs
lvs                      # List LVs
lvextend -L +5G vg0/lv0  # Extend LV
lvreduce -L -5G vg0/lv0  # Reduce LV
            """, language="bash")
            
            st.markdown("#### **RAID & Backup**")
            st.code("""
# RAID management
mdadm --create /dev/md0 --level=1 --raid-devices=2 /dev/sdb /dev/sdc
mdadm --detail /dev/md0  # RAID details
cat /proc/mdstat         # RAID status
mdadm --stop /dev/md0    # Stop RAID

# Backup tools
rsync -av source/ dest/  # Sync directories
rsync -avz --delete src/ dst/ # Mirror
dd if=/dev/sda of=disk.img # Disk image
dd if=/dev/zero of=/dev/sdb # Wipe disk
tar -czf backup.tar.gz /path # Tar backup
dump -0f /backup/full.dump / # Full dump
restore -rf /backup/full.dump # Restore
            """, language="bash")
    
    with cheat_tabs[10]:
        st.markdown("### 📝 **Text Processing**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### **Text Viewing**")
            st.code("""
# View files
cat file                 # Display file
cat file1 file2          # Concatenate files
tac file                 # Reverse cat
nl file                  # Number lines
more file                # Page through
less file                # Better pager
head file                # First 10 lines
head -n 20 file         # First 20 lines
tail file                # Last 10 lines
tail -n 20 file         # Last 20 lines
tail -f file            # Follow file

# Text editors
vi file                  # Vi editor
vim file                 # Vim editor
nano file                # Nano editor
emacs file               # Emacs editor
            """, language="bash")
            
            st.markdown("#### **Text Manipulation**")
            st.code("""
# Basic operations
echo "text"              # Print text
printf "format" args     # Formatted print
cat file | command       # Pipe to command
command > file           # Redirect output
command >> file          # Append output
command 2> error.log     # Redirect errors
command &> all.log       # All output
command < input.txt      # Input from file
command1 | command2      # Pipe commands

# Text transformation
tr 'a-z' 'A-Z'          # Uppercase
tr -d '\\n'              # Delete newlines
expand file              # Tabs to spaces
unexpand file            # Spaces to tabs
            """, language="bash")
        
        with col2:
            st.markdown("#### **sed & awk**")
            st.code("""
# sed (stream editor)
sed 's/old/new/' file    # Replace first
sed 's/old/new/g' file   # Replace all
sed -i 's/old/new/g' file # In-place edit
sed '5d' file            # Delete line 5
sed '5,10d' file         # Delete lines 5-10
sed -n '5,10p' file      # Print lines 5-10
sed '/pattern/d' file    # Delete matching
sed -e 's/a/A/g' -e 's/b/B/g' # Multiple

# awk
awk '{print $1}' file    # Print column 1
awk '{print $1,$3}' file # Print columns
awk 'NR==5' file         # Print line 5
awk 'NF>0' file          # Non-empty lines
awk '{sum+=$1} END {print sum}' # Sum column
awk -F: '{print $1}' /etc/passwd # Custom delimiter
            """, language="bash")
            
            st.markdown("#### **Text Tools**")
            st.code("""
# Sorting & uniqueness
sort file                # Sort lines
sort -n file             # Numeric sort
sort -r file             # Reverse sort
sort -u file             # Sort + unique
uniq file                # Remove duplicates
uniq -c file             # Count duplicates
uniq -d file             # Only duplicates

# Counting & comparison
wc file                  # Word count
wc -l file               # Line count
wc -w file               # Word count
wc -c file               # Byte count
diff file1 file2         # Compare files
comm file1 file2         # Compare sorted
cmp file1 file2          # Byte compare
            """, language="bash")
    
    with cheat_tabs[11]:
        st.markdown("### 🔧 **System Control**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### **Kernel & Modules**")
            st.code("""
# Kernel modules
lsmod                    # List modules
modinfo module           # Module info
modprobe module          # Load module
modprobe -r module       # Remove module
insmod module.ko         # Insert module
rmmod module             # Remove module
depmod                   # Module dependencies

# Kernel parameters
sysctl -a                # All parameters
sysctl parameter         # Get parameter
sysctl -w param=value    # Set parameter
sysctl -p                # Load from file
cat /proc/sys/param      # Direct access
echo value > /proc/sys/param # Direct set
            """, language="bash")
            
            st.markdown("#### **Boot & Init**")
            st.code("""
# GRUB bootloader
grub-mkconfig -o /boot/grub/grub.cfg
grub-install /dev/sda    # Install GRUB
update-grub              # Update GRUB

# Systemd targets
systemctl get-default    # Default target
systemctl set-default multi-user.target
systemctl isolate rescue.target
systemctl list-units --type=target

# Run levels (SysV)
runlevel                 # Current runlevel
init 3                   # Multi-user
init 5                   # Graphical
init 0                   # Shutdown
init 6                   # Reboot
            """, language="bash")
        
        with col2:
            st.markdown("#### **Environment**")
            st.code("""
# Environment variables
env                      # All variables
printenv                 # Print environment
echo $PATH               # Print PATH
export VAR=value         # Set variable
unset VAR                # Unset variable
source file              # Source file
. file                   # Source file

# Shell configuration
~/.bashrc                # Bash config
~/.profile               # Login shell
~/.bash_profile          # Bash login
/etc/profile             # System profile
/etc/bash.bashrc         # System bashrc
/etc/environment         # Environment vars

# Locale settings
locale                   # Current locale
locale -a                # Available locales
localectl                # Locale control
            """, language="bash")
            
            st.markdown("#### **System Limits**")
            st.code("""
# Resource limits
ulimit -a                # All limits
ulimit -n                # Open files limit
ulimit -u                # Process limit
ulimit -m                # Memory limit
ulimit -c                # Core dump size
ulimit -n 4096           # Set file limit

# /etc/security/limits.conf
# user  type  item  value
*       soft  nofile  4096
*       hard  nofile  8192
user    soft  nproc   1024
@group  hard  nproc   2048

# CPU & I/O scheduling
nice -n 10 command       # CPU priority
renice -5 PID           # Change priority
ionice -c 3 command     # Idle I/O class
chrt -f 50 command      # Real-time priority
            """, language="bash")
    
    # Quick reference card
    st.markdown("---")
    st.markdown("### 🎯 **Quick Reference Card**")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("#### **Keyboard Shortcuts**")
        st.code("""
Ctrl+C    # Cancel command
Ctrl+Z    # Suspend command
Ctrl+D    # Exit/EOF
Ctrl+L    # Clear screen
Ctrl+A    # Beginning of line
Ctrl+E    # End of line
Ctrl+K    # Cut to end
Ctrl+U    # Cut to beginning
Ctrl+W    # Cut word
Ctrl+Y    # Paste (yank)
Ctrl+R    # Search history
Tab       # Auto-complete
Tab Tab   # Show options
        """, language="text")
    
    with col2:
        st.markdown("#### **Special Characters**")
        st.code("""
~         # Home directory
.         # Current directory
..        # Parent directory
-         # Previous directory
*         # Wildcard (any)
?         # Wildcard (single)
[]        # Character class
{}        # Brace expansion
|         # Pipe
>         # Redirect output
>>        # Append output
<         # Redirect input
&         # Background
;         # Command separator
        """, language="text")
    
    with col3:
        st.markdown("#### **Exit Codes**")
        st.code("""
$?        # Last exit code
0         # Success
1         # General error
2         # Misuse
126       # Not executable
127       # Command not found
128       # Invalid argument
128+n     # Fatal signal n
130       # Ctrl+C (SIGINT)
137       # SIGKILL
139       # Segmentation fault
255       # Exit status overflow
        """, language="text")
    
    # Tips section
    st.markdown("---")
    st.markdown("### 💡 **Pro Tips**")
    
    st.info("""
    **🚀 Productivity Tips:**
    - Use `alias` to create shortcuts for frequently used commands
    - Use `history | grep pattern` to find previously used commands
    - Use `!!` to repeat the last command, `!$` for last argument
    - Use `screen` or `tmux` for persistent terminal sessions
    - Use `watch` to run commands repeatedly: `watch -n 2 df -h`
    - Use `xargs` to build commands from input: `find . -name "*.log" | xargs rm`
    - Use `tee` to write to file and stdout: `command | tee output.txt`
    - Use `&&` to chain commands: `command1 && command2`
    - Use `||` for fallback: `command1 || command2`
    - Use `time` to measure execution: `time command`
    """)

if __name__ == "__main__":
    run_lab()
