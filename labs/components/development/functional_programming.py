import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_functional_programming():
    """Functional Programming using TDD pattern"""
    
    st.markdown("## Functional Programming")
    st.markdown("**Definition:** Programming paradigm that treats computation as the evaluation of mathematical functions, avoiding changing state and mutable data.")
    
    st.markdown("---")
    
    # Core Concepts
    st.markdown("### Core Functional Programming Concepts")
    
    concepts_data = {
        "Concept": ["Pure Functions", "Immutability", "Higher-Order Functions", "Function Composition", "Recursion"],
        "Description": [
            "Functions with no side effects, same input = same output",
            "Data cannot be changed after creation",
            "Functions that take or return other functions",
            "Combining simple functions to build complex ones",
            "Functions that call themselves to solve problems"
        ],
        "Benefits": [
            "Predictable, testable, cacheable",
            "Thread-safe, easier to reason about",
            "Code reuse, abstraction, flexibility",
            "Modularity, readability, maintainability",
            "Elegant solutions for recursive problems"
        ],
        "Example": [
            "Math.max(a, b) - no side effects",
            "const arr = [1,2,3]; // cannot modify",
            "map(), filter(), reduce() functions",
            "compose(f, g)(x) = f(g(x))",
            "factorial(n) = n * factorial(n-1)"
        ]
    }
    
    df = pd.DataFrame(concepts_data)
    st.dataframe(df, use_container_width=True)
    
    # Paradigm Comparison
    st.markdown("### Programming Paradigm Comparison")
    
    # Create radar chart comparing paradigms
    paradigms = ['Functional', 'Object-Oriented', 'Procedural']
    aspects = ['Testability', 'Concurrency', 'Code Reuse', 'Learning Curve', 'Performance']
    
    scores = {
        'Functional': [9, 9, 8, 3, 7],
        'Object-Oriented': [7, 6, 8, 6, 7],
        'Procedural': [6, 4, 5, 9, 8]
    }
    
    fig = go.Figure()
    
    for paradigm in paradigms:
        fig.add_trace(go.Scatterpolar(
            r=scores[paradigm],
            theta=aspects,
            fill='toself',
            name=paradigm
        ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 10]
            )
        ),
        title="Programming Paradigm Comparison",
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Functional Programming Languages
    st.markdown("### Functional Programming Languages")
    
    languages_data = {
        "Language": ["Haskell", "Lisp", "Clojure", "F#", "Scala", "JavaScript"],
        "Type": ["Pure Functional", "Multi-paradigm", "Functional + JVM", "Functional + .NET", "Functional + OOP", "Multi-paradigm"],
        "Key Features": [
            "Lazy evaluation, type system, monads",
            "Homoiconicity, macros, dynamic",
            "Immutable data, JVM interop, STM",
            ".NET integration, type inference",
            "JVM, pattern matching, actors",
            "First-class functions, closures"
        ],
        "Learning Difficulty": ["Hard", "Medium", "Medium", "Medium", "Medium", "Easy"],
        "Use Cases": [
            "Research, compilers, formal verification",
            "AI, symbolic computation, DSLs",
            "Web development, data processing",
            "Enterprise, data analysis, web",
            "Big data, distributed systems",
            "Web development, Node.js"
        ]
    }
    
    df2 = pd.DataFrame(languages_data)
    st.dataframe(df2, use_container_width=True)
    
    # Common Functional Patterns
    st.markdown("### Common Functional Programming Patterns")
    
    patterns_data = {
        "Pattern": ["Map", "Filter", "Reduce", "Curry", "Partial Application"],
        "Purpose": [
            "Transform each element in a collection",
            "Select elements that meet a condition",
            "Combine elements into a single value",
            "Transform multi-argument function to single-argument",
            "Fix some arguments of a function"
        ],
        "JavaScript Example": [
            "[1,2,3].map(x => x * 2) // [2,4,6]",
            "[1,2,3,4].filter(x => x > 2) // [3,4]",
            "[1,2,3].reduce((a,b) => a + b, 0) // 6",
            "const add = a => b => a + b",
            "const add5 = add(5); add5(3) // 8"
        ],
        "Python Example": [
            "list(map(lambda x: x*2, [1,2,3]))",
            "list(filter(lambda x: x>2, [1,2,3,4]))",
            "from functools import reduce",
            "from functools import partial",
            "add5 = partial(add, 5)"
        ]
    }
    
    df3 = pd.DataFrame(patterns_data)
    st.dataframe(df3, use_container_width=True)
    
    # Advantages and Disadvantages
    st.markdown("### Functional Programming Trade-offs")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Advantages:**
        - **Predictability** - Pure functions, no side effects
        - **Testability** - Easy to unit test pure functions
        - **Concurrency** - Immutable data is thread-safe
        - **Modularity** - Function composition promotes reuse
        - **Debugging** - Easier to reason about program flow
        """)
    
    with col2:
        st.markdown("""
        **Disadvantages:**
        - **Learning Curve** - Different mindset from imperative
        - **Performance** - Immutability can create overhead
        - **Memory Usage** - Creating new objects instead of mutating
        - **Verbosity** - Some operations require more code
        - **Limited Libraries** - Fewer libraries in pure FP languages
        """)
    
    # Real-world Applications
    st.markdown("### Real-world Applications")
    
    applications_data = {
        "Domain": ["Web Development", "Data Processing", "Concurrent Systems", "Financial Systems", "AI/ML"],
        "Why Functional": [
            "Predictable UI state management",
            "Pipeline transformations, no side effects",
            "Thread-safe operations, actor model",
            "Reliability, auditability, correctness",
            "Mathematical functions, data transformations"
        ],
        "Technologies": [
            "React (functional components), Redux",
            "Apache Spark, MapReduce, stream processing",
            "Erlang/Elixir, Akka, Go channels",
            "Haskell, F#, functional libraries",
            "TensorFlow, functional APIs, pipelines"
        ],
        "Examples": [
            "Facebook React, Netflix UI",
            "Netflix data processing, Spotify",
            "WhatsApp (Erlang), Discord (Elixir)",
            "Jane Street trading systems",
            "Google TensorFlow, scikit-learn"
        ]
    }
    
    df4 = pd.DataFrame(applications_data)
    st.dataframe(df4, use_container_width=True)
    
    # Getting Started
    st.markdown("### Getting Started with Functional Programming")
    
    getting_started_data = {
        "Step": ["Learn Concepts", "Practice with Familiar Language", "Try Pure Functional Language", "Build Projects", "Study Advanced Topics"],
        "Description": [
            "Understand pure functions, immutability, higher-order functions",
            "Use functional features in JavaScript, Python, or C#",
            "Learn Haskell, Clojure, or F# for deeper understanding",
            "Build real applications using functional principles",
            "Study monads, type theory, category theory"
        ],
        "Resources": [
            "Books: 'Functional Programming in JavaScript'",
            "Practice: LeetCode, Codewars functional problems",
            "Tutorials: Learn You a Haskell, Clojure for the Brave",
            "Projects: Build calculator, data processor, web app",
            "Books: 'Category Theory for Programmers'"
        ],
        "Time Investment": ["1-2 weeks", "2-4 weeks", "2-3 months", "3-6 months", "6+ months"]
    }
    
    df5 = pd.DataFrame(getting_started_data)
    st.dataframe(df5, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Mathematical Foundation:</strong> FP is based on mathematical function theory</li>
            <li><strong>Complementary Paradigm:</strong> Can be combined with OOP and procedural approaches</li>
            <li><strong>Excellent for Concurrency:</strong> Immutable data eliminates race conditions</li>
            <li><strong>Growing Adoption:</strong> Many mainstream languages adding functional features</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
