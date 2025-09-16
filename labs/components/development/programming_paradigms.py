import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_programming_paradigms():
    """Programming Paradigms using TDD pattern"""
    
    st.markdown("## Programming Paradigms")
    st.markdown("**Definition:** Fundamental programming approaches that provide frameworks for structuring and organizing code to solve computational problems.")
    
    st.markdown("---")
    
    # Major Paradigms
    st.markdown("### Major Programming Paradigms")
    
    paradigms_data = {
        "Paradigm": ["Procedural", "Object-Oriented", "Functional", "Declarative", "Event-Driven"],
        "Core Concept": [
            "Step-by-step procedures and functions",
            "Objects with properties and methods",
            "Mathematical functions and immutability",
            "What to do, not how to do it",
            "Response to events and messages"
        ],
        "Key Features": [
            "Functions, modules, structured programming",
            "Encapsulation, inheritance, polymorphism",
            "Pure functions, higher-order functions",
            "Logic programming, constraint programming",
            "Event handlers, callbacks, async programming"
        ],
        "Examples": [
            "C, Pascal, COBOL",
            "Java, C++, Python",
            "Haskell, Lisp, Clojure",
            "SQL, HTML, Prolog",
            "JavaScript, C#, Visual Basic"
        ]
    }
    
    df = pd.DataFrame(paradigms_data)
    st.dataframe(df, use_container_width=True)
    
    # Paradigm Comparison
    st.markdown("### Paradigm Characteristics Comparison")
    
    comparison_data = {
        "Aspect": ["Learning Curve", "Code Reusability", "Maintainability", "Performance", "Problem Solving"],
        "Procedural": ["Easy", "Moderate", "Moderate", "Good", "Sequential"],
        "Object-Oriented": ["Moderate", "High", "High", "Good", "Modeling"],
        "Functional": ["Hard", "High", "High", "Variable", "Mathematical"],
        "Declarative": ["Moderate", "High", "High", "Variable", "Rule-based"]
    }
    
    df2 = pd.DataFrame(comparison_data)
    st.dataframe(df2, use_container_width=True)
    
    # Programming Language Support
    st.markdown("### Multi-Paradigm Language Support")
    
    # Create radar chart for language paradigm support
    languages = ['Python', 'JavaScript', 'C++', 'Java', 'Scala']
    paradigm_support = {
        'Procedural': [4, 4, 5, 2, 3],
        'Object-Oriented': [5, 4, 5, 5, 5],
        'Functional': [4, 4, 2, 3, 5],
        'Event-Driven': [3, 5, 3, 4, 4]
    }
    
    fig = go.Figure()
    
    for i, lang in enumerate(languages):
        values = [paradigm_support[p][i] for p in paradigm_support.keys()]
        fig.add_trace(go.Scatterpolar(
            r=values,
            theta=list(paradigm_support.keys()),
            fill='toself',
            name=lang
        ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 5]
            )
        ),
        title="Programming Language Paradigm Support",
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # When to Use Each Paradigm
    st.markdown("### When to Use Each Paradigm")
    
    usage_data = {
        "Paradigm": ["Procedural", "Object-Oriented", "Functional", "Declarative"],
        "Best For": [
            "Simple scripts, system programming",
            "Large applications, GUI development",
            "Data processing, mathematical computations",
            "Database queries, configuration"
        ],
        "Avoid When": [
            "Complex data relationships",
            "Simple one-off scripts",
            "Performance-critical systems",
            "Complex business logic"
        ],
        "Modern Usage": [
            "Embedded systems, C programming",
            "Enterprise applications, web development",
            "Data science, concurrent programming",
            "Configuration, markup languages"
        ]
    }
    
    df3 = pd.DataFrame(usage_data)
    st.dataframe(df3, use_container_width=True)
    
    # Paradigm Evolution
    st.markdown("### Evolution of Programming Paradigms")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Historical Timeline:**
        - 1950s: Machine/Assembly language
        - 1960s: Procedural programming
        - 1970s: Structured programming
        - 1980s: Object-oriented programming
        """)
    
    with col2:
        st.markdown("""
        **Modern Trends:**
        - 1990s: Functional programming revival
        - 2000s: Multi-paradigm languages
        - 2010s: Reactive programming
        - 2020s: Concurrent/parallel paradigms
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>No Silver Bullet:</strong> Different paradigms solve different types of problems</li>
            <li><strong>Multi-Paradigm Approach:</strong> Modern languages often support multiple paradigms</li>
            <li><strong>Problem-Driven Choice:</strong> Select paradigm based on problem characteristics</li>
            <li><strong>Continuous Learning:</strong> Understanding multiple paradigms makes you a better programmer</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
