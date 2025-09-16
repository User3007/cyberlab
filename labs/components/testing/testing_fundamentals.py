import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_testing_fundamentals():
    """Testing Fundamentals using TDD pattern"""
    
    st.markdown("## Testing Fundamentals")
    st.markdown("**Definition:** Systematic process of verifying software functionality and quality.")
    
    st.markdown("---")
    
    # Testing Principles
    st.markdown("### Core Testing Principles")
    
    principles_data = {
        "Principle": [
            "Testing shows presence of defects",
            "Exhaustive testing is impossible", 
            "Early testing",
            "Defect clustering",
            "Pesticide paradox",
            "Testing is context dependent",
            "Absence of errors fallacy"
        ],
        "Description": [
            "Testing can prove bugs exist, not their absence",
            "Focus testing on high-risk areas",
            "Find defects early when cheaper to fix",
            "Most defects cluster in small modules",
            "Same tests find fewer bugs over time",
            "Testing approach depends on context",
            "No errors doesn't mean system is usable"
        ]
    }
    
    df = pd.DataFrame(principles_data)
    st.dataframe(df, use_container_width=True)
    
    # Testing Pyramid
    st.markdown("### Testing Pyramid")
    
    fig = go.Figure()
    
    # Add pyramid levels
    levels = ['Unit Tests', 'Integration Tests', 'E2E Tests']
    counts = [70, 20, 10]
    colors = ['green', 'orange', 'red']
    
    fig.add_trace(go.Bar(
        x=levels,
        y=counts,
        marker_color=colors,
        text=[f'{c}%' for c in counts],
        textposition='auto'
    ))
    
    fig.update_layout(
        title="Testing Pyramid Distribution",
        xaxis_title="Test Type",
        yaxis_title="Percentage",
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Test Early and Often:</strong> Shift-left testing reduces costs</li>
            <li><strong>Risk-Based Testing:</strong> Focus on high-risk areas</li>
            <li><strong>Automation is Key:</strong> Automate repetitive tests</li>
            <li><strong>Quality is Everyone's Job:</strong> Testing is a team responsibility</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_testing_types():
    """Testing Types using TDD pattern"""
    
    st.markdown("## Testing Types")
    st.markdown("**Definition:** Different categories of testing based on scope, purpose, and execution method.")
    
    st.markdown("---")
    
    # Testing Types Overview
    st.markdown("### Testing Classification")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **By Scope:**
        - Unit Testing
        - Integration Testing
        - System Testing
        - Acceptance Testing
        """)
    
    with col2:
        st.markdown("""
        **By Purpose:**
        - Functional Testing
        - Non-Functional Testing
        - Regression Testing
        - Smoke Testing
        """)
    
    # Testing Matrix
    st.markdown("### Testing Type Matrix")
    
    matrix_data = {
        "Test Type": ["Unit", "Integration", "System", "Acceptance"],
        "Scope": ["Single component", "Multiple components", "Entire system", "User perspective"],
        "Who Tests": ["Developers", "Developers/QA", "QA Team", "Users/QA"],
        "When": ["During development", "After unit tests", "After integration", "Before release"],
        "Tools": ["JUnit, pytest", "TestContainers", "Selenium", "Manual/UAT"]
    }
    
    df = pd.DataFrame(matrix_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Comprehensive Coverage:</strong> Use multiple testing types</li>
            <li><strong>Right Tool for Job:</strong> Choose appropriate tools for each type</li>
            <li><strong>Progressive Testing:</strong> Build from unit to acceptance</li>
            <li><strong>Continuous Testing:</strong> Integrate testing into CI/CD pipeline</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_quality_assurance_process():
    """Quality Assurance Process using TDD pattern"""
    
    st.markdown("## Quality Assurance Process")
    st.markdown("**Definition:** Systematic approach to ensuring software quality throughout the development lifecycle.")
    
    st.markdown("---")
    
    # QA Process Steps
    st.markdown("### QA Process Steps")
    
    steps = [
        "Requirements Analysis",
        "Test Planning", 
        "Test Design",
        "Test Execution",
        "Defect Management",
        "Test Reporting"
    ]
    
    for i, step in enumerate(steps, 1):
        st.markdown(f"**{i}. {step}**")
        st.markdown(f"   - Define quality criteria and test objectives")
        st.markdown(f"   - Create comprehensive test strategy")
        st.markdown(f"   - Develop detailed test cases")
        st.markdown(f"   - Execute tests and track results")
        st.markdown(f"   - Log, prioritize, and track defects")
        st.markdown(f"   - Generate quality metrics and reports")
        st.markdown("")
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Process-Driven:</strong> Follow structured QA methodology</li>
            <li><strong>Continuous Improvement:</strong> Refine processes based on feedback</li>
            <li><strong>Metrics Matter:</strong> Track quality indicators</li>
            <li><strong>Team Collaboration:</strong> QA involves entire development team</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_testing_tools():
    """Testing Tools using TDD pattern"""
    
    st.markdown("## Testing Tools")
    st.markdown("**Definition:** Software applications and frameworks that support various testing activities.")
    
    st.markdown("---")
    
    # Tool Categories
    st.markdown("### Testing Tool Categories")
    
    tools_data = {
        "Category": ["Unit Testing", "Integration Testing", "UI Testing", "API Testing", "Performance Testing"],
        "Tools": [
            "JUnit, pytest, NUnit, Mocha",
            "TestContainers, WireMock, Mockito",
            "Selenium, Cypress, Playwright",
            "Postman, REST Assured, Newman",
            "JMeter, LoadRunner, Gatling"
        ],
        "Purpose": [
            "Test individual components",
            "Test component interactions",
            "Test user interfaces",
            "Test API endpoints",
            "Test system performance"
        ]
    }
    
    df = pd.DataFrame(tools_data)
    st.dataframe(df, use_container_width=True)
    
    # Tool Selection Criteria
    st.markdown("### Tool Selection Criteria")
    
    criteria = [
        "**Compatibility:** Works with your tech stack",
        "**Learning Curve:** Team can adopt quickly",
        "**Community Support:** Active community and documentation",
        "**Integration:** Fits into existing workflow",
        "**Cost:** Budget considerations",
        "**Maintenance:** Long-term sustainability"
    ]
    
    for criterion in criteria:
        st.markdown(f"- {criterion}")
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Tool Selection:</strong> Choose tools that fit your needs</li>
            <li><strong>Automation First:</strong> Prioritize tools that enable automation</li>
            <li><strong>Integration:</strong> Ensure tools work well together</li>
            <li><strong>Training:</strong> Invest in team training for effective tool usage</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
