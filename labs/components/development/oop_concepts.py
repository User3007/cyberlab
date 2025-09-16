import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_oop():
    """Object-Oriented Programming using TDD pattern"""
    
    st.markdown("## Object-Oriented Programming (OOP)")
    st.markdown("**Definition:** Programming paradigm based on the concept of objects containing data (attributes) and code (methods) that can interact with each other.")
    
    st.markdown("---")
    
    # Core OOP Principles
    st.markdown("### Core OOP Principles")
    
    principles_data = {
        "Principle": ["Encapsulation", "Inheritance", "Polymorphism", "Abstraction"],
        "Definition": [
            "Bundling data and methods together, hiding internal details",
            "Creating new classes based on existing classes",
            "Objects of different types responding to same interface",
            "Hiding complex implementation details behind simple interfaces"
        ],
        "Benefits": [
            "Data protection, modularity, maintainability",
            "Code reuse, hierarchical organization, extensibility",
            "Flexibility, code reuse, runtime binding",
            "Simplified complexity, clear interfaces, modularity"
        ],
        "Example": [
            "Private variables with public getter/setter methods",
            "Vehicle -> Car -> SportsCar class hierarchy",
            "Shape.draw() works for Circle, Rectangle, Triangle",
            "Database interface hiding SQL implementation"
        ]
    }
    
    df = pd.DataFrame(principles_data)
    st.dataframe(df, use_container_width=True)
    
    # OOP vs Other Paradigms
    st.markdown("### Programming Paradigm Comparison")
    
    # Create radar chart comparing paradigms
    paradigms = ['Procedural', 'OOP', 'Functional']
    metrics = ['Code Reuse', 'Maintainability', 'Modularity', 'Learning Curve', 'Performance']
    
    scores = {
        'Procedural': [6, 5, 4, 8, 9],
        'OOP': [9, 8, 9, 6, 7],
        'Functional': [8, 7, 8, 4, 8]
    }
    
    fig = go.Figure()
    
    for paradigm in paradigms:
        fig.add_trace(go.Scatterpolar(
            r=scores[paradigm],
            theta=metrics,
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
    
    # OOP Concepts in Practice
    st.markdown("### OOP Concepts in Practice")
    
    concepts_data = {
        "Concept": ["Class", "Object", "Method", "Constructor", "Destructor"],
        "Description": [
            "Blueprint/template for creating objects",
            "Instance of a class with specific data",
            "Function defined within a class",
            "Special method to initialize objects",
            "Special method to clean up objects"
        ],
        "Python Example": [
            "class Car: pass",
            "my_car = Car()",
            "def start_engine(self): ...",
            "def __init__(self, model): ...",
            "def __del__(self): ..."
        ],
        "Java Example": [
            "public class Car { }",
            "Car myCar = new Car();",
            "public void startEngine() { }",
            "public Car(String model) { }",
            "protected void finalize() { }"
        ]
    }
    
    df2 = pd.DataFrame(concepts_data)
    st.dataframe(df2, use_container_width=True)
    
    # Design Patterns
    st.markdown("### Common OOP Design Patterns")
    
    patterns_data = {
        "Pattern": ["Singleton", "Factory", "Observer", "Strategy"],
        "Type": ["Creational", "Creational", "Behavioral", "Behavioral"],
        "Problem Solved": [
            "Ensure only one instance of a class",
            "Create objects without specifying exact class",
            "Notify multiple objects about state changes",
            "Select algorithm at runtime"
        ],
        "Use Cases": [
            "Database connections, logging, configuration",
            "UI components, database drivers",
            "Event handling, MVC architecture",
            "Payment processing, sorting algorithms"
        ]
    }
    
    df3 = pd.DataFrame(patterns_data)
    st.dataframe(df3, use_container_width=True)
    
    # OOP Best Practices
    st.markdown("### OOP Best Practices")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Design Principles:**
        - Single Responsibility Principle
        - Open/Closed Principle
        - Liskov Substitution Principle
        - Interface Segregation Principle
        - Dependency Inversion Principle
        """)
    
    with col2:
        st.markdown("""
        **Coding Practices:**
        - Use meaningful class and method names
        - Keep methods small and focused
        - Favor composition over inheritance
        - Program to interfaces, not implementations
        - Follow consistent naming conventions
        """)
    
    # OOP in Different Languages
    st.markdown("### OOP Language Comparison")
    
    languages_data = {
        "Language": ["Java", "C++", "Python", "C#", "JavaScript"],
        "OOP Support": ["Pure OOP", "Multi-paradigm", "Multi-paradigm", "Pure OOP", "Prototype-based"],
        "Key Features": [
            "Strong typing, interfaces, garbage collection",
            "Multiple inheritance, operator overloading",
            "Dynamic typing, duck typing, metaclasses",
            "Properties, events, LINQ integration",
            "Prototype chain, dynamic objects"
        ],
        "Learning Difficulty": ["Medium", "Hard", "Easy", "Medium", "Medium"],
        "Performance": ["High", "Very High", "Medium", "High", "Medium"]
    }
    
    df4 = pd.DataFrame(languages_data)
    st.dataframe(df4, use_container_width=True)
    
    # Common OOP Mistakes
    st.markdown("### Common OOP Mistakes to Avoid")
    
    mistakes_data = {
        "Mistake": ["God Objects", "Inappropriate Inheritance", "Tight Coupling", "Violation of Encapsulation"],
        "Description": [
            "Classes that do too many things",
            "Using inheritance when composition is better",
            "Classes too dependent on each other",
            "Exposing internal implementation details"
        ],
        "Solution": [
            "Split into smaller, focused classes",
            "Prefer composition, use interfaces",
            "Use dependency injection, loose coupling",
            "Use private members, public interfaces"
        ]
    }
    
    df5 = pd.DataFrame(mistakes_data)
    st.dataframe(df5, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Natural Modeling:</strong> OOP maps well to real-world problem domains</li>
            <li><strong>Code Organization:</strong> Provides structure for large, complex applications</li>
            <li><strong>Reusability:</strong> Inheritance and polymorphism promote code reuse</li>
            <li><strong>Not Always Best:</strong> Consider problem domain and team expertise</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
