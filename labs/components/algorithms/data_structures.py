import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

def explain_advanced_data_structures():
    """Advanced Data Structures using TDD pattern"""
    
    st.markdown("## Advanced Data Structures Fundamentals")
    st.markdown("**Definition:** Complex data structures that provide efficient solutions for specific computational problems.")
    
    st.markdown("---")
    
    # Key Concepts
    st.markdown("### Key Concepts")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Tree Structures:**
        - Binary Trees
        - AVL Trees  
        - Red-Black Trees
        - B-Trees
        - Tries
        """)
    
    with col2:
        st.markdown("""
        **Graph Structures:**
        - Directed/Undirected
        - Weighted/Unweighted
        - Adjacency Lists/Matrices
        - Spanning Trees
        """)
    
    # Cheat Sheet
    st.markdown("### Quick Reference")
    
    cheat_sheet_data = {
        "Structure": ["Array", "Linked List", "Stack", "Queue", "Binary Tree", "Hash Table", "Graph"],
        "Access": ["O(1)", "O(n)", "O(1)", "O(1)", "O(log n)", "O(1)", "O(V+E)"],
        "Search": ["O(n)", "O(n)", "O(n)", "O(n)", "O(log n)", "O(1)", "O(V+E)"],
        "Insert": ["O(n)", "O(1)", "O(1)", "O(1)", "O(log n)", "O(1)", "O(1)"],
        "Delete": ["O(n)", "O(1)", "O(1)", "O(1)", "O(log n)", "O(1)", "O(1)"]
    }
    
    df = pd.DataFrame(cheat_sheet_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Choose Wisely:</strong> Different structures excel at different operations</li>
            <li><strong>Time vs Space:</strong> Consider trade-offs between time and space complexity</li>
            <li><strong>Real-world Applications:</strong> Each structure has specific use cases</li>
            <li><strong>Implementation Matters:</strong> Proper implementation affects performance</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_searching_algorithms():
    """Searching Algorithms using TDD pattern"""
    
    st.markdown("## Searching Algorithms")
    st.markdown("**Definition:** Methods to find specific elements within data structures efficiently.")
    
    st.markdown("---")
    
    # Algorithm Types
    st.markdown("### Algorithm Types")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Linear Search:**
        - Sequential checking
        - O(n) time complexity
        - Works on any data
        - Simple implementation
        """)
    
    with col2:
        st.markdown("""
        **Binary Search:**
        - Divide and conquer
        - O(log n) time complexity
        - Requires sorted data
        - Very efficient
        """)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Choose Based on Data:</strong> Sorted data enables binary search</li>
            <li><strong>Consider Frequency:</strong> Frequent searches benefit from preprocessing</li>
            <li><strong>Memory vs Speed:</strong> Hash tables trade memory for speed</li>
            <li><strong>Implementation Details:</strong> Edge cases matter for correctness</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_algorithm_complexity():
    """Algorithm Complexity using TDD pattern"""
    
    st.markdown("## Algorithm Complexity Analysis")
    st.markdown("**Definition:** Mathematical analysis of algorithm efficiency in terms of time and space.")
    
    st.markdown("---")
    
    # Complexity Classes
    st.markdown("### Big O Notation")
    
    complexity_data = {
        "Notation": ["O(1)", "O(log n)", "O(n)", "O(n log n)", "O(n)", "O(2)"],
        "Name": ["Constant", "Logarithmic", "Linear", "Linearithmic", "Quadratic", "Exponential"],
        "Example": ["Array access", "Binary search", "Linear search", "Merge sort", "Bubble sort", "Fibonacci recursive"],
        "Efficiency": ["Excellent", "Very Good", "Good", "Fair", "Poor", "Very Poor"]
    }
    
    df = pd.DataFrame(complexity_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Worst Case Analysis:</strong> Big O describes worst-case performance</li>
            <li><strong>Scalability Matters:</strong> Consider how algorithms perform with large inputs</li>
            <li><strong>Space vs Time:</strong> Sometimes trade memory for speed</li>
            <li><strong>Real-world Impact:</strong> Small differences become significant at scale</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
