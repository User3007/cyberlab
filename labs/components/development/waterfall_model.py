import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_waterfall():
    """Waterfall Model using TDD pattern"""
    
    st.markdown("## Waterfall Model")
    st.markdown("**Definition:** Sequential software development approach where progress flows steadily downward through distinct phases like a waterfall.")
    
    st.markdown("---")
    
    # Waterfall Phases
    st.markdown("### Waterfall Development Phases")
    
    phases_data = {
        "Phase": ["Requirements", "System Design", "Implementation", "Integration & Testing", "Deployment", "Maintenance"],
        "Duration": ["2-4 weeks", "3-6 weeks", "8-16 weeks", "4-8 weeks", "1-2 weeks", "Ongoing"],
        "Key Activities": [
            "Gather requirements, document specifications",
            "System architecture, detailed design",
            "Code development, unit testing",
            "System integration, testing phases",
            "Production deployment, user training",
            "Bug fixes, enhancements, support"
        ],
        "Deliverables": [
            "Requirements document, acceptance criteria",
            "System design document, architecture diagrams",
            "Source code, unit test results",
            "Test reports, integration documentation",
            "Deployed system, user documentation",
            "Maintenance reports, change requests"
        ],
        "Success Criteria": [
            "Complete, approved requirements",
            "Approved design, technical feasibility",
            "Code complete, unit tests pass",
            "All tests pass, system integrated",
            "Successful deployment, user acceptance",
            "System stability, user satisfaction"
        ]
    }
    
    df = pd.DataFrame(phases_data)
    st.dataframe(df, use_container_width=True)
    
    # Waterfall Process Flow Visualization
    st.markdown("### Waterfall Process Flow")
    
    # Create waterfall process flow chart using bar chart (more appropriate for effort distribution)
    phases = ['Requirements', 'Design', 'Implementation', 'Testing', 'Deployment', 'Maintenance']
    effort = [15, 20, 40, 15, 5, 5]  # Percentage of total effort
    colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD']
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        name="Effort Distribution",
        x=phases,
        y=effort,
        marker=dict(
            color=colors,
            line=dict(color='rgb(8,48,107)', width=1.5)
        ),
        text=[f'{e}%' for e in effort],
        textposition='auto'
    ))
    
    fig.update_layout(
        title="Waterfall Model - Effort Distribution by Phase",
        xaxis_title="Development Phases",
        yaxis_title="Effort Percentage (%)",
        height=500,
        showlegend=False
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Advantages vs Disadvantages
    st.markdown("### Waterfall Model Analysis")
    
    analysis_data = {
        "Aspect": ["Planning", "Documentation", "Progress Tracking", "Quality Control", "Change Management"],
        "Advantages": [
            "Clear project timeline and milestones",
            "Comprehensive documentation at each phase",
            "Easy to measure progress against plan",
            "Thorough testing before deployment",
            "Structured change control process"
        ],
        "Disadvantages": [
            "Difficult to accommodate changes",
            "Heavy documentation overhead",
            "Late discovery of issues",
            "No working software until end",
            "Expensive to make changes"
        ],
        "Risk Level": ["Low", "Medium", "Medium", "Low", "High"]
    }
    
    df2 = pd.DataFrame(analysis_data)
    st.dataframe(df2, use_container_width=True)
    
    # When to Use Waterfall
    st.markdown("### When to Use Waterfall Model")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Good Fit For:**
        - Well-understood requirements
        - Stable technology environment
        - Regulatory/compliance projects
        - Fixed-price contracts
        - Large, complex systems
        """)
    
    with col2:
        st.markdown("""
        **Poor Fit For:**
        - Evolving requirements
        - New/experimental technology
        - User-facing applications
        - Startup environments
        - Rapid market changes
        """)
    
    # Comparison with Agile
    st.markdown("### Waterfall vs Agile Comparison")
    
    comparison_data = {
        "Aspect": ["Approach", "Requirements", "Customer Involvement", "Risk Management", "Team Structure"],
        "Waterfall": [
            "Sequential, phase-based",
            "Fixed upfront, detailed documentation",
            "Limited to requirements and acceptance",
            "Risk assessment in planning phase",
            "Specialized roles, hierarchical"
        ],
        "Agile": [
            "Iterative, incremental",
            "Evolving, user stories",
            "Continuous collaboration",
            "Continuous risk assessment",
            "Cross-functional, self-organizing"
        ],
        "Best Use Case": [
            "Predictable projects with stable requirements",
            "Well-defined scope, regulatory compliance",
            "Formal approval processes required",
            "Known technology, established processes",
            "Large teams, distributed development"
        ]
    }
    
    df3 = pd.DataFrame(comparison_data)
    st.dataframe(df3, use_container_width=True)
    
    # Modern Variations
    st.markdown("### Modern Waterfall Variations")
    
    variations_data = {
        "Variation": ["V-Model", "Spiral Model", "Incremental Waterfall"],
        "Key Feature": [
            "Testing planned in parallel with development",
            "Risk-driven, iterative approach",
            "Multiple waterfall cycles"
        ],
        "When to Use": [
            "Safety-critical systems, high reliability requirements",
            "High-risk projects, new technology",
            "Large projects, phased delivery"
        ]
    }
    
    df4 = pd.DataFrame(variations_data)
    st.dataframe(df4, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Structure & Predictability:</strong> Waterfall provides clear structure and predictable outcomes</li>
            <li><strong>Documentation Focus:</strong> Emphasizes comprehensive documentation and formal processes</li>
            <li><strong>Limited Flexibility:</strong> Changes are expensive and difficult to implement</li>
            <li><strong>Right Context Matters:</strong> Still valuable for specific project types and industries</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
