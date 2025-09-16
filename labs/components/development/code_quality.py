import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_code_quality():
    """Code Quality & Best Practices using TDD pattern"""
    
    st.markdown("## Code Quality & Best Practices")
    st.markdown("**Definition:** Set of standards, practices, and principles that ensure code is readable, maintainable, reliable, and efficient throughout its lifecycle.")
    
    st.markdown("---")
    
    # Code Quality Dimensions
    st.markdown("### Code Quality Dimensions")
    
    dimensions_data = {
        "Dimension": ["Readability", "Maintainability", "Reliability", "Performance", "Security"],
        "Description": [
            "Code is easy to read and understand",
            "Code is easy to modify and extend",
            "Code works correctly and handles errors",
            "Code executes efficiently and scales well",
            "Code is secure and follows security practices"
        ],
        "Metrics": [
            "Cyclomatic complexity, naming conventions",
            "Coupling, cohesion, code duplication",
            "Test coverage, bug density, error handling",
            "Execution time, memory usage, throughput",
            "Vulnerability count, security scan results"
        ],
        "Tools": [
            "SonarQube, CodeClimate, ESLint",
            "NDepend, Structure101, PMD",
            "JUnit, pytest, coverage tools",
            "Profilers, benchmarks, APM tools",
            "SAST tools, dependency scanners"
        ]
    }
    
    df = pd.DataFrame(dimensions_data)
    st.dataframe(df, use_container_width=True)
    
    # Code Quality Metrics Visualization
    st.markdown("### Code Quality Assessment")
    
    # Create radar chart for code quality assessment
    quality_aspects = ['Readability', 'Maintainability', 'Reliability', 'Performance', 'Security', 'Testability']
    
    # Example project scores
    project_scores = {
        'Good Project': [8, 9, 9, 7, 8, 9],
        'Average Project': [6, 5, 6, 6, 5, 4],
        'Poor Project': [3, 2, 4, 4, 3, 2]
    }
    
    fig = go.Figure()
    
    colors = ['green', 'orange', 'red']
    for i, (project, scores) in enumerate(project_scores.items()):
        fig.add_trace(go.Scatterpolar(
            r=scores,
            theta=quality_aspects,
            fill='toself',
            name=project,
            line=dict(color=colors[i])
        ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 10]
            )
        ),
        title="Code Quality Assessment Example",
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # SOLID Principles
    st.markdown("### SOLID Principles")
    
    solid_data = {
        "Principle": ["Single Responsibility", "Open/Closed", "Liskov Substitution", "Interface Segregation", "Dependency Inversion"],
        "Description": [
            "A class should have one reason to change",
            "Open for extension, closed for modification",
            "Objects should be replaceable with instances of subtypes",
            "Many client-specific interfaces are better than one general-purpose interface",
            "Depend on abstractions, not concretions"
        ],
        "Violation Example": [
            "User class that handles both user data and email sending",
            "Modifying existing class to add new functionality",
            "Square class inheriting from Rectangle but breaking area calculation",
            "Large interface with methods not all clients need",
            "High-level module depending on low-level module directly"
        ],
        "Solution": [
            "Separate User class and EmailService class",
            "Use inheritance or composition to extend functionality",
            "Design proper inheritance hierarchy or use composition",
            "Split large interface into smaller, focused interfaces",
            "Use dependency injection and abstractions"
        ]
    }
    
    df2 = pd.DataFrame(solid_data)
    st.dataframe(df2, use_container_width=True)
    
    # Code Smells and Refactoring
    st.markdown("### Common Code Smells and Solutions")
    
    smells_data = {
        "Code Smell": ["Long Method", "Large Class", "Duplicate Code", "Long Parameter List", "Feature Envy"],
        "Problem": [
            "Method tries to do too much",
            "Class has too many responsibilities",
            "Same code structure repeated",
            "Too many parameters in method",
            "Method uses another class more than its own"
        ],
        "Refactoring Technique": [
            "Extract Method, Decompose Conditional",
            "Extract Class, Extract Subclass",
            "Extract Method, Pull Up Method",
            "Introduce Parameter Object, Preserve Whole Object",
            "Move Method, Extract Method"
        ],
        "Tool Support": [
            "IDE refactoring tools, complexity analyzers",
            "Class size metrics, dependency analysis",
            "Copy-paste detectors, similarity analyzers",
            "Parameter analysis, method signature tools",
            "Dependency analyzers, coupling metrics"
        ]
    }
    
    df3 = pd.DataFrame(smells_data)
    st.dataframe(df3, use_container_width=True)
    
    # Best Practices by Category
    st.markdown("### Best Practices by Category")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Naming Conventions:**
        - Use descriptive, meaningful names
        - Avoid abbreviations and acronyms
        - Use consistent naming patterns
        - Make intent clear from name
        - Use searchable names
        """)
        
        st.markdown("""
        **Function Design:**
        - Keep functions small and focused
        - Limit parameters (max 3-4)
        - Avoid side effects
        - Use pure functions when possible
        - Return early to reduce nesting
        """)
    
    with col2:
        st.markdown("""
        **Error Handling:**
        - Use exceptions for exceptional cases
        - Fail fast and fail clearly
        - Provide meaningful error messages
        - Log errors appropriately
        - Don't ignore exceptions
        """)
        
        st.markdown("""
        **Comments and Documentation:**
        - Write self-documenting code
        - Comment why, not what
        - Keep comments up to date
        - Use meaningful commit messages
        - Document public APIs
        """)
    
    # Code Review Best Practices
    st.markdown("### Code Review Best Practices")
    
    review_data = {
        "Aspect": ["Review Size", "Review Focus", "Feedback Style", "Response Time", "Learning"],
        "Best Practice": [
            "Keep reviews small (200-400 lines)",
            "Focus on logic, design, maintainability",
            "Be constructive, specific, and kind",
            "Review within 24 hours",
            "Use reviews as learning opportunities"
        ],
        "What to Look For": [
            "Logical chunks, related changes",
            "Code smells, SOLID violations, security issues",
            "Suggest improvements, not just problems",
            "Balance thoroughness with speed",
            "Share knowledge, explain decisions"
        ],
        "Tools": [
            "GitHub PR, GitLab MR, Bitbucket PR",
            "SonarQube, CodeClimate integration",
            "Review templates, checklists",
            "Automated reminders, SLA tracking",
            "Knowledge sharing sessions"
        ]
    }
    
    df4 = pd.DataFrame(review_data)
    st.dataframe(df4, use_container_width=True)
    
    # Testing Best Practices
    st.markdown("### Testing Best Practices")
    
    testing_data = {
        "Test Type": ["Unit Tests", "Integration Tests", "End-to-End Tests", "Performance Tests"],
        "Purpose": [
            "Test individual components in isolation",
            "Test component interactions",
            "Test complete user workflows",
            "Test system performance characteristics"
        ],
        "Best Practices": [
            "Fast, isolated, repeatable, self-validating",
            "Test realistic scenarios, use test databases",
            "Test critical user paths, use page objects",
            "Test under realistic load, monitor key metrics"
        ],
        "Coverage Target": ["80-90%", "60-70%", "Critical paths", "Key scenarios"],
        "Tools": [
            "JUnit, pytest, Jest, xUnit",
            "TestContainers, Postman, REST Assured",
            "Selenium, Cypress, Playwright",
            "JMeter, k6, Gatling"
        ]
    }
    
    df5 = pd.DataFrame(testing_data)
    st.dataframe(df5, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Quality is Investment:</strong> Good code quality reduces long-term maintenance costs</li>
            <li><strong>Consistency Matters:</strong> Establish and follow team coding standards</li>
            <li><strong>Continuous Improvement:</strong> Regularly review and refactor code</li>
            <li><strong>Tool Integration:</strong> Use automated tools to enforce quality standards</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
