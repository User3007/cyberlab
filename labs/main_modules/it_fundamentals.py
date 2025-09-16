"""
IT Fundamentals Lab - Main Controller
Refactored from original it_fundamentals.py using modular architecture
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import random

# Import shared utilities
from ..shared.color_schemes import IT_FUNDAMENTALS_COLORS
from ..shared.ui_components import create_banner, create_takeaways

# Import systems components
from ..components.systems.computer_architecture import explain_computer_architecture
from ..components.systems.operating_systems import explain_operating_systems
from ..components.systems.virtualization import explain_virtualization
from ..components.systems.database_concepts import explain_database_concepts
from ..components.systems import (
    explain_process_management,
    explain_memory_management,
    explain_file_systems,
    explain_relational_databases,
    explain_sql_basics,
    explain_database_design,
    explain_os_comparison
)

# Import sysadmin components
from ..components.sysadmin import (
    explain_user_management,
    explain_system_monitoring,
    explain_backup_recovery,
    explain_performance_tuning,
    explain_security_hardening
)

# Import ITSM components
from ..components.itsm import (
    explain_itil_framework,
    explain_incident_management,
    explain_change_management,
    explain_service_level_management,
    explain_it_governance
)

# Import networking components
from ..components.networking.common_protocols import explain_common_protocols
from ..components.networking import explain_network_models, explain_routing_switching, explain_network_security_basics


def run_lab():
    """IT Fundamentals Lab - Enhanced modular version"""
    
    # Create enhanced banner
    create_banner(
        title="IT Fundamentals Lab",
        description="Kiến thức cơ bản CNTT - Computer Systems, Networking, and Infrastructure",
        color_scheme=IT_FUNDAMENTALS_COLORS,
        icon="💻",
        estimated_time="60-90 minutes",
        difficulty="beginner"
    )
    
    # Enhanced navigation with logical grouping
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🖥️ Computer Systems", 
        "🌐 Networking Basics",
        "💾 Operating Systems", 
        "🗄️ Database Fundamentals",
        "🔧 System Administration",
        "📊 IT Service Management"
    ])
    
    with tab1:
        computer_systems_lab()
    
    with tab2:
        networking_basics_lab()
    
    with tab3:
        operating_systems_lab()
        
    with tab4:
        database_fundamentals_lab()
        
    with tab5:
        system_administration_lab()
        
    with tab6:
        it_service_management_lab()


def computer_systems_lab():
    """Computer systems section with enhanced components"""
    st.subheader("🖥️ Computer Systems Lab")
    
    topic_choice = st.selectbox("Chọn chủ đề:", [
        "Computer Architecture",
        "CPU & Memory",
        "Storage Systems",
        "Input/Output Systems",
        "Performance Analysis"
    ], key="it_computer_topic")
    
    if topic_choice == "Computer Architecture":
        explain_computer_architecture()
    elif topic_choice == "CPU & Memory":
        from ..components.systems import explain_cpu_memory
        explain_cpu_memory()
    elif topic_choice == "Storage Systems":
        from ..components.systems import explain_storage_systems
        explain_storage_systems()
    elif topic_choice == "Input/Output Systems":
        explain_io_systems()
    elif topic_choice == "Performance Analysis":
        explain_performance_analysis()


def networking_basics_lab():
    """Networking basics section"""
    st.subheader("🌐 Networking Basics Lab")
    
    networking_topic = st.selectbox("Chọn chủ đề networking:", [
        "Network Models (OSI/TCP-IP)",
        "Network Protocols",
        "Routing & Switching",
        "Network Troubleshooting",
        "Network Security Basics"
    ], key="it_networking_topic")
    
    if networking_topic == "Network Models (OSI/TCP-IP)":
        explain_network_models()
    elif networking_topic == "Network Protocols":
        explain_common_protocols()
    elif networking_topic == "Routing & Switching":
        explain_routing_switching()
    elif networking_topic == "Network Troubleshooting":
        explain_network_troubleshooting()
    elif networking_topic == "Network Security Basics":
        explain_network_security_basics()


def operating_systems_lab():
    """Operating systems section"""
    st.subheader("💾 Operating Systems Lab")
    
    os_topic = st.selectbox("Chọn chủ đề OS:", [
        "OS Fundamentals",
        "OS Comparison",
        "Process Management", 
        "Memory Management", 
        "File Systems",
        "OS Security"
    ], key="it_os_topic")
    
    if os_topic == "OS Fundamentals":
        explain_operating_systems()
    elif os_topic == "OS Comparison":
        explain_os_comparison()
    elif os_topic == "Process Management":
        explain_process_management()
    elif os_topic == "Memory Management":
        explain_memory_management()
    elif os_topic == "File Systems":
        explain_file_systems()
    elif os_topic == "OS Security":
        from ..components.systems import explain_os_security
        explain_os_security()


def database_fundamentals_lab():
    """Database fundamentals section"""
    st.subheader("🗄️ Database Fundamentals Lab")
    
    db_topic = st.selectbox("Chọn chủ đề database:", [
        "Database Concepts",
        "Relational Databases",
        "SQL Fundamentals",
        "Database Design",
        "Database Security",
        "NoSQL Databases"
    ], key="it_db_topic")
    
    if db_topic == "Database Concepts":
        explain_database_concepts()
    elif db_topic == "Relational Databases":
        explain_relational_databases()
    elif db_topic == "SQL Fundamentals":
        explain_sql_basics()
    elif db_topic == "Database Design":
        explain_database_design()
    elif db_topic == "Database Security":
        explain_database_security()
    elif db_topic == "NoSQL Databases":
        from ..components.systems import explain_nosql_databases
        explain_nosql_databases()


def system_administration_lab():
    """System administration section"""
    st.subheader("🔧 System Administration Lab")
    
    sysadmin_topic = st.selectbox("Chọn chủ đề system admin:", [
        "Virtualization Fundamentals",
        "User & Group Management",
        "System Monitoring",
        "Backup & Recovery",
        "Performance Tuning",
        "Security Hardening",
        "Automation & Scripting"
    ], key="it_sysadmin_topic")
    
    if sysadmin_topic == "Virtualization Fundamentals":
        explain_virtualization()
    elif sysadmin_topic == "User & Group Management":
        explain_user_management()
    elif sysadmin_topic == "System Monitoring":
        explain_system_monitoring()
    elif sysadmin_topic == "Backup & Recovery":
        explain_backup_recovery()
    elif sysadmin_topic == "Performance Tuning":
        explain_performance_tuning()
    elif sysadmin_topic == "Security Hardening":
        explain_security_hardening()
    elif sysadmin_topic == "Automation & Scripting":
        explain_automation_scripting()


def it_service_management_lab():
    """IT service management section"""
    st.subheader("📊 IT Service Management Lab")
    
    itsm_topic = st.selectbox("Chọn chủ đề ITSM:", [
        "ITIL Framework",
        "Incident Management",
        "Change Management",
        "Service Level Management",
        "IT Governance"
    ], key="it_itsm_topic")
    
    if itsm_topic == "ITIL Framework":
        explain_itil_framework()
    elif itsm_topic == "Incident Management":
        explain_incident_management()
    elif itsm_topic == "Change Management":
        explain_change_management()
    elif itsm_topic == "Service Level Management":
        explain_service_level_management()
    elif itsm_topic == "IT Governance":
        explain_it_governance()


# Legacy functions that still need to be refactored
# These will be gradually moved to components



def explain_io_systems():
    """I/O systems explanation - to be refactored"""
    st.markdown("### 🔌 Input/Output Systems")
    st.info("🚧 I/O Systems component is being refactored. Coming soon!")


def explain_performance_analysis():
    """Performance analysis explanation - to be refactored"""
    st.markdown("### 📈 Performance Analysis")
    st.info("🚧 Performance Analysis component is being refactored. Coming soon!")


def explain_network_troubleshooting():
    from ..components.networking import explain_network_troubleshooting as _impl
    _impl()




def explain_database_security():
    """Database security - to be refactored"""
    st.markdown("### 🔒 Database Security")
    st.info("🚧 Database Security component is being refactored. Coming soon!")


def explain_automation_scripting():
    """Automation & scripting - to be refactored"""
    st.markdown("### 🤖 Automation & Scripting")
    st.info("🚧 Automation & Scripting component is being refactored. Coming soon!")


# Add takeaways for the entire module
def show_module_takeaways():
    """Show key takeaways for IT Fundamentals module"""
    takeaways = [
        "Computer architecture understanding is fundamental to IT security",
        "Network knowledge enables better security implementation and troubleshooting",
        "Operating system security forms the foundation of system protection",
        "Database security requires understanding of both technology and access controls",
        "System administration skills are essential for maintaining secure environments"
    ]
    
    create_takeaways(
        takeaways,
        title="🎯 IT Fundamentals Key Takeaways",
        color_scheme=IT_FUNDAMENTALS_COLORS
    )
