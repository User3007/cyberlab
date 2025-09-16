"""
Software Development Lab - Main Controller
Refactored from original software_development.py using modular architecture
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import random
import math

# Import shared utilities
from ..shared.color_schemes import SOFTWARE_DEV_COLORS
from ..shared.ui_components import create_banner, create_takeaways

# Import development components
from ..components.development.sdlc_agile import explain_sdlc
from ..components.development import explain_design_patterns, explain_project_planning
from ..components.algorithms import explain_sorting_algorithms
from ..components.devops import explain_continuous_integration
# from ..components.development.scrum_methodologies import explain_scrum
# from ..components.development.design_patterns import explain_design_patterns
# from ..components.development.programming_paradigms import explain_programming_paradigms


def run_lab():
    """Software Development Fundamentals Lab - Enhanced modular version"""
    
    # Create enhanced banner
    create_banner(
        title="Software Development Fundamentals",
        description="SDLC, Methodologies, and Secure Development Practices",
        color_scheme=SOFTWARE_DEV_COLORS,
        icon="💻",
        estimated_time="75-90 minutes", 
        difficulty="intermediate"
    )
    
    # Enhanced navigation with development focus
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🏗️ SDLC & Methodologies", 
        "💾 Programming Concepts",
        "🗄️ Data Structures & Algorithms", 
        "🧪 Testing & Quality Assurance",
        "🔧 DevOps & CI/CD",
        "📊 Project Management"
    ])
    
    with tab1:
        sdlc_methodologies_lab()
    
    with tab2:
        programming_concepts_lab()
    
    with tab3:
        data_structures_algorithms_lab()
        
    with tab4:
        testing_qa_lab()
        
    with tab5:
        devops_cicd_lab()
        
    with tab6:
        project_management_lab()


def sdlc_methodologies_lab():
    """SDLC and methodologies section with enhanced components"""
    st.subheader("🏗️ SDLC & Methodologies")
    
    methodology_choice = st.selectbox("Chọn methodology:", [
        "Software Development Life Cycle (SDLC)",
        "Waterfall Model",
        "Agile Methodology",
        "Scrum Framework",
        "DevOps Integration"
    ])
    
    if methodology_choice == "Software Development Life Cycle (SDLC)":
        explain_sdlc()
    elif methodology_choice == "Waterfall Model":
        explain_waterfall()
    elif methodology_choice == "Agile Methodology":
        explain_agile()
    elif methodology_choice == "Scrum Framework":
        # explain_scrum()  # Will be implemented
        st.info("🚧 Scrum Framework component is being refactored. Coming soon!")
    elif methodology_choice == "DevOps Integration":
        explain_devops_integration()


def programming_concepts_lab():
    """Programming concepts section"""
    st.subheader("💾 Programming Concepts")
    
    concept_choice = st.selectbox("Chọn programming concept:", [
        "Programming Paradigms",
        "Object-Oriented Programming",
        "Functional Programming",
        "Design Patterns",
        "Code Quality & Best Practices"
    ])
    
    if concept_choice == "Programming Paradigms":
        # explain_programming_paradigms()  # Will be implemented
        st.info("🚧 Programming Paradigms component is being refactored. Coming soon!")
    elif concept_choice == "Object-Oriented Programming":
        explain_oop()
    elif concept_choice == "Functional Programming":
        explain_functional_programming()
    elif concept_choice == "Design Patterns":
        explain_design_patterns()
    elif concept_choice == "Code Quality & Best Practices":
        explain_code_quality()


def data_structures_algorithms_lab():
    """Data structures and algorithms section"""
    st.subheader("🗄️ Data Structures & Algorithms")
    
    # Algorithm components tabs
    algo_tab1, algo_tab2, algo_tab3 = st.tabs([
        "🔢 Sorting Algorithms",
        "🔍 Data Structures", 
        "📊 Algorithm Analysis"
    ])
    
    with algo_tab1:
        explain_sorting_algorithms()
    
    with algo_tab2:
        st.info("🚧 Data Structures components are being developed. Coming soon!")
        data_structures = [
            "**Basic Data Structures** - Arrays, lists, stacks, queues",
            "**Advanced Data Structures** - Trees, graphs, hash tables",
            "**Specialized Structures** - Heaps, tries, bloom filters"
        ]
        for structure in data_structures:
            st.markdown(structure)
    
    with algo_tab3:
        st.info("🚧 Algorithm Analysis components are being developed. Coming soon!")
        analysis_topics = [
            "**Big O Notation** - Time and space complexity analysis",
            "**Algorithm Comparison** - Performance benchmarking",
            "**Optimization Techniques** - Algorithm improvement strategies"
        ]
        for topic in analysis_topics:
            st.markdown(topic)


def testing_qa_lab():
    """Testing and QA section"""
    st.subheader("🧪 Testing & Quality Assurance")
    
    testing_choice = st.selectbox("Chọn testing topic:", [
        "Testing Fundamentals",
        "Unit Testing",
        "Integration Testing",
        "Security Testing",
        "Test Automation"
    ])
    
    if testing_choice == "Testing Fundamentals":
        explain_testing_fundamentals()
    elif testing_choice == "Unit Testing":
        explain_unit_testing()
    elif testing_choice == "Integration Testing":
        explain_integration_testing()
    elif testing_choice == "Security Testing":
        explain_security_testing()
    elif testing_choice == "Test Automation":
        explain_test_automation()


def devops_cicd_lab():
    """DevOps and CI/CD section"""
    st.subheader("🔧 DevOps & CI/CD")
    
    devops_choice = st.selectbox("Chọn DevOps topic:", [
        "DevOps Principles",
        "Continuous Integration",
        "Continuous Deployment",
        "Infrastructure as Code",
        "Container Security"
    ])
    
    if devops_choice == "DevOps Principles":
        explain_devops_principles()
    elif devops_choice == "Continuous Integration":
        explain_continuous_integration()
    elif devops_choice == "Continuous Deployment":
        explain_continuous_deployment()
    elif devops_choice == "Infrastructure as Code":
        explain_infrastructure_as_code()
    elif devops_choice == "Container Security":
        explain_container_security()


def project_management_lab():
    """Project management section"""
    st.subheader("📊 Project Management")
    
    pm_choice = st.selectbox("Chọn project management topic:", [
        "Project Management Fundamentals",
        "Agile Project Management",
        "Risk Management",
        "Team Management",
        "Quality Management"
    ])
    
    if pm_choice == "Project Management Fundamentals":
        explain_project_planning()
    elif pm_choice == "Agile Project Management":
        explain_agile_pm()
    elif pm_choice == "Risk Management":
        explain_project_risk_management()
    elif pm_choice == "Team Management":
        explain_team_management()
    elif pm_choice == "Quality Management":
        explain_quality_management()


# Legacy functions that still need to be refactored
# These will be gradually moved to components

def explain_waterfall():
    """Waterfall model explanation - to be refactored"""
    st.markdown("### 🌊 Waterfall Model")
    st.info("🚧 Waterfall Model component is being refactored. Coming soon!")


def explain_devops_integration():
    """DevOps integration - to be refactored"""
    st.markdown("### 🔧 DevOps Integration")
    st.info("🚧 DevOps Integration component is being refactored. Coming soon!")


def explain_oop():
    """Object-oriented programming - to be refactored"""
    st.markdown("### 🎯 Object-Oriented Programming")
    st.info("🚧 OOP component is being refactored. Coming soon!")


def explain_functional_programming():
    """Functional programming - to be refactored"""
    st.markdown("### 🔢 Functional Programming")
    st.info("🚧 Functional Programming component is being refactored. Coming soon!")


def explain_code_quality():
    """Code quality - to be refactored"""
    st.markdown("### ✨ Code Quality & Best Practices")
    st.info("🚧 Code Quality component is being refactored. Coming soon!")


def explain_data_structures():
    """Data structures - to be refactored"""
    st.markdown("### 🗄️ Data Structures Overview")
    st.info("🚧 Data Structures component is being refactored. Coming soon!")


def explain_algorithms_complexity():
    """Algorithms complexity - to be refactored"""
    st.markdown("### ⚡ Algorithms & Complexity")
    st.info("🚧 Algorithms & Complexity component is being refactored. Coming soon!")


def explain_sorting_searching():
    """Sorting and searching - to be refactored"""
    st.markdown("### 🔍 Sorting & Searching")
    st.info("🚧 Sorting & Searching component is being refactored. Coming soon!")


def explain_graph_algorithms():
    """Graph algorithms - to be refactored"""
    st.markdown("### 🕸️ Graph Algorithms")
    st.info("🚧 Graph Algorithms component is being refactored. Coming soon!")


def explain_security_algorithms():
    """Security algorithms - to be refactored"""
    st.markdown("### 🔒 Security Algorithms")
    st.info("🚧 Security Algorithms component is being refactored. Coming soon!")


def explain_testing_fundamentals():
    """Testing fundamentals - to be refactored"""
    st.markdown("### 🧪 Testing Fundamentals")
    st.info("🚧 Testing Fundamentals component is being refactored. Coming soon!")


def explain_unit_testing():
    """Unit testing - to be refactored"""
    st.markdown("### 🔬 Unit Testing")
    st.info("🚧 Unit Testing component is being refactored. Coming soon!")


def explain_integration_testing():
    """Integration testing - to be refactored"""
    st.markdown("### 🔗 Integration Testing")
    st.info("🚧 Integration Testing component is being refactored. Coming soon!")


def explain_security_testing():
    """Security testing - to be refactored"""
    st.markdown("### 🛡️ Security Testing")
    st.info("🚧 Security Testing component is being refactored. Coming soon!")


def explain_test_automation():
    """Test automation - to be refactored"""
    st.markdown("### 🤖 Test Automation")
    st.info("🚧 Test Automation component is being refactored. Coming soon!")


def explain_devops_principles():
    """DevOps principles - to be refactored"""
    st.markdown("### 🔧 DevOps Principles")
    st.info("🚧 DevOps Principles component is being refactored. Coming soon!")


def explain_continuous_integration():
    """Continuous integration - to be refactored"""
    st.markdown("### 🔄 Continuous Integration")
    st.info("🚧 Continuous Integration component is being refactored. Coming soon!")


def explain_continuous_deployment():
    """Continuous deployment - to be refactored"""
    st.markdown("### 🚀 Continuous Deployment")
    st.info("🚧 Continuous Deployment component is being refactored. Coming soon!")


def explain_infrastructure_as_code():
    """Infrastructure as code - to be refactored"""
    st.markdown("### 🏗️ Infrastructure as Code")
    st.info("🚧 Infrastructure as Code component is being refactored. Coming soon!")


def explain_container_security():
    """Container security - to be refactored"""
    st.markdown("### 🐳 Container Security")
    st.info("🚧 Container Security component is being refactored. Coming soon!")


def explain_pm_fundamentals():
    """Project management fundamentals - to be refactored"""
    st.markdown("### 📊 Project Management Fundamentals")
    st.info("🚧 Project Management Fundamentals component is being refactored. Coming soon!")


def explain_agile_pm():
    """Agile project management - to be refactored"""
    st.markdown("### ⚡ Agile Project Management")
    st.info("🚧 Agile Project Management component is being refactored. Coming soon!")


def explain_project_risk_management():
    """Project risk management - to be refactored"""
    st.markdown("### ⚠️ Project Risk Management")
    st.info("🚧 Project Risk Management component is being refactored. Coming soon!")


def explain_team_management():
    """Team management - to be refactored"""
    st.markdown("### 👥 Team Management")
    st.info("🚧 Team Management component is being refactored. Coming soon!")


def explain_quality_management():
    """Quality management - to be refactored"""
    st.markdown("### ✅ Quality Management")
    st.info("🚧 Quality Management component is being refactored. Coming soon!")


# Add takeaways for the entire module
def show_module_takeaways():
    """Show key takeaways for Software Development module"""
    takeaways = [
        "SDLC provides structure and predictability to software development projects",
        "Agile methodologies offer flexibility and continuous improvement opportunities",
        "Security must be integrated throughout the entire development lifecycle",
        "Testing and quality assurance are critical for reliable software systems",
        "DevOps practices enable faster, more secure software delivery"
    ]
    
    create_takeaways(
        takeaways,
        title="🎯 Software Development Key Takeaways",
        color_scheme=SOFTWARE_DEV_COLORS
    )
