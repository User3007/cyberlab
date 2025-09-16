"""
Theory & Concepts Lab - Main Controller
Enhanced modular version using refactored components
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Import shared utilities
from ..shared.color_schemes import THEORY_CONCEPTS_COLORS
from ..shared.ui_components import create_banner, create_takeaways

# Import networking components
from ..components.networking import (
    explain_osi_model,
    explain_tcpip_stack,
    explain_network_protocols,
    explain_ip_addressing,
    explain_routing_switching,
    explain_network_topologies
)

# Import security components
from ..components.security import (
    explain_cia_triad,
    explain_defense_in_depth,
    explain_zero_trust,
    explain_risk_assessment,
    explain_cyber_kill_chain,
    explain_mitre_attack,
    explain_least_privilege,
    explain_attack_vectors,
    explain_social_engineering,
    explain_security_by_design,
    explain_advanced_persistent_threats
)

# Import cryptography components
from ..components.cryptography import (
    explain_encryption_types,
    explain_hash_signatures,
    explain_key_management,
    explain_modern_crypto
)


def main():
    """Theory & Concepts Lab - Enhanced modular version"""
    
    # Create enhanced banner
    create_banner(
        title="Theory & Concepts Lab",
        description="Học các khái niệm và thủ thuật cybersecurity",
        color_scheme=THEORY_CONCEPTS_COLORS,
        icon="📚",
        estimated_time="45-60 minutes",
        difficulty="intermediate"
    )
    
    # Enhanced navigation with more intuitive categories
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🌐 Network Fundamentals", 
        "🔒 Security Principles",
        "⚔️ Attack Methodologies", 
        "🔐 Cryptography Concepts",
        "📊 Risk Assessment",
        "⚖️ Legal & Ethics"
    ])
    
    with tab1:
        network_fundamentals()
    
    with tab2:
        security_principles()
    
    with tab3:
        attack_methodologies()
        
    with tab4:
        cryptography_concepts()
        
    with tab5:
        risk_assessment_section()
        
    with tab6:
        legal_ethics()
    
    # Show module takeaways
    show_module_takeaways()


def network_fundamentals():
    """Network fundamentals section with enhanced components"""
    st.subheader("🌐 Network Fundamentals")
    
    # Network Fundamentals section
    st.header("🌐 Network Fundamentals")
    
    network_tab1, network_tab2, network_tab3, network_tab4, network_tab5, network_tab6 = st.tabs([
        "📊 OSI Model", 
        "🌐 TCP/IP Stack",
        "🔗 Network Protocols", 
        "🌐 IP Addressing",
        "🔀 Routing & Switching",
        "🕸️ Network Topologies"
    ])
    
    with network_tab1:
        explain_osi_model()
    
    with network_tab2:
        explain_tcpip_stack()
    
    with network_tab3:
        explain_network_protocols()
    
    with network_tab4:
        explain_ip_addressing()
    
    with network_tab5:
        explain_routing_switching()
    
    with network_tab6:
        explain_network_topologies()


def security_principles():
    """Security principles section using modular components"""
    st.subheader("🔒 Security Principles")
    
    # Security Principles section
    st.header("🛡️ Security Principles")
    
    security_tab1, security_tab2, security_tab3, security_tab4, security_tab5 = st.tabs([
        "🔺 CIA Triad",
        "🛡️ Defense in Depth", 
        "🚫 Zero Trust",
        "🔐 Least Privilege",
        "🛡️ Security by Design"
    ])
    
    with security_tab1:
        explain_cia_triad()
    
    with security_tab2:
        explain_defense_in_depth()
    
    with security_tab3:
        explain_zero_trust()
    
    with security_tab4:
        explain_least_privilege()
    
    with security_tab5:
        explain_security_by_design()


def attack_methodologies():
    """Attack methodologies section"""
    st.subheader("⚔️ Attack Methodologies")
    
    # Attack Methodologies section
    st.header("⚔️ Attack Methodologies")
    
    attack_tab1, attack_tab2, attack_tab3, attack_tab4, attack_tab5 = st.tabs([
        "⚔️ Cyber Kill Chain",
        "🎯 MITRE ATT&CK",
        "🎯 Attack Vectors",
        "🎭 Social Engineering",
        "🎭 Advanced Persistent Threats"
    ])
    
    with attack_tab1:
        explain_cyber_kill_chain()
    
    with attack_tab2:
        explain_mitre_attack()
    
    with attack_tab3:
        explain_attack_vectors()
    
    with attack_tab4:
        explain_social_engineering()
    
    with attack_tab5:
        explain_advanced_persistent_threats()


def cryptography_concepts():
    """Cryptography concepts section using modular components"""
    st.subheader("🔐 Cryptography Concepts")
    
    # Cryptography Concepts section
    st.header("🔐 Cryptography Concepts")
    
    crypto_tab1, crypto_tab2, crypto_tab3, crypto_tab4 = st.tabs([
        "🔐 Encryption Types",
        "🔒 Hash & Signatures",
        "🗝️ Key Management",
        "🚀 Modern Crypto"
    ])
    
    with crypto_tab1:
        explain_encryption_types()
    
    with crypto_tab2:
        explain_hash_signatures()
    
    with crypto_tab3:
        explain_key_management()
    
    with crypto_tab4:
        explain_modern_crypto()


def risk_assessment_section():
    """Risk assessment section using modular component"""
    st.subheader("📊 Risk Assessment")
    
    # Use the modular risk assessment component
    explain_risk_assessment()


def legal_ethics():
    """Legal and ethics section"""
    st.subheader("⚖️ Legal & Ethics")
    
    st.info("🚧 Legal & Ethics components are being developed. Coming soon!")
    
    legal_concepts = [
        "**Cybersecurity Laws & Regulations** - GDPR, CCPA, SOX compliance",
        "**Ethical Hacking Guidelines** - Responsible disclosure, authorization",
        "**Privacy & Data Protection** - Data handling, breach notification",
        "**Incident Response Legal** - Evidence preservation, law enforcement"
    ]
    
    for concept in legal_concepts:
        st.markdown(concept)


# Add takeaways for the entire module
def show_module_takeaways():
    """Show key takeaways for Theory & Concepts module"""
    takeaways = [
        "Security principles form the foundation of all cybersecurity practices",
        "Understanding network fundamentals is crucial for identifying vulnerabilities",
        "Attack methodologies help in building effective defense strategies", 
        "Modern cryptography provides mathematical foundation for data protection",
        "Risk assessment guides security investment and prioritization decisions"
    ]
    
    create_takeaways(
        takeaways,
        title="🎯 Theory & Concepts Key Takeaways",
        color_scheme=THEORY_CONCEPTS_COLORS
    )


# Legacy compatibility
run_lab = main