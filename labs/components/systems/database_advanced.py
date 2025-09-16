import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_relational_databases():
    """Relational Databases using TDD pattern"""
    
    st.markdown("## Relational Databases")
    st.markdown("**Definition:** Database systems based on the relational model with tables, rows, and columns.")
    
    st.markdown("---")
    
    # RDBMS Features
    st.markdown("### RDBMS Features")
    
    features_data = {
        "Feature": ["ACID Properties", "Normalization", "SQL", "Referential Integrity", "Indexing"],
        "Description": [
            "Atomicity, Consistency, Isolation, Durability",
            "Eliminate data redundancy",
            "Structured Query Language",
            "Maintain data relationships",
            "Improve query performance"
        ]
    }
    
    df = pd.DataFrame(features_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Data Integrity:</strong> ACID properties ensure reliable transactions</li>
            <li><strong>Normalization:</strong> Reduce redundancy and improve consistency</li>
            <li><strong>SQL Standard:</strong> Universal language for data manipulation</li>
            <li><strong>Scalability:</strong> Handle growing data and user loads</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_sql_basics():
    """SQL Basics using TDD pattern"""
    
    st.markdown("## SQL Basics")
    st.markdown("**Definition:** Structured Query Language for managing and manipulating relational databases.")
    
    st.markdown("---")
    
    # SQL Commands
    st.markdown("### SQL Command Categories")
    
    commands_data = {
        "Category": ["DDL", "DML", "DCL", "TCL"],
        "Commands": ["CREATE, ALTER, DROP", "SELECT, INSERT, UPDATE, DELETE", "GRANT, REVOKE", "COMMIT, ROLLBACK"],
        "Purpose": [
            "Define database structure",
            "Manipulate data",
            "Control access",
            "Manage transactions"
        ]
    }
    
    df = pd.DataFrame(commands_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Standard Language:</strong> SQL is universal across RDBMS</li>
            <li><strong>Powerful Queries:</strong> Complex data retrieval and analysis</li>
            <li><strong>Data Manipulation:</strong> Insert, update, and delete operations</li>
            <li><strong>Performance Optimization:</strong> Use indexes and query optimization</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_database_design():
    """Database Design using TDD pattern"""
    
    st.markdown("## Database Design")
    st.markdown("**Definition:** Process of creating a logical and physical structure for a database system.")
    
    st.markdown("---")
    
    # Design Process
    st.markdown("### Database Design Process")
    
    steps = [
        "Requirements Analysis",
        "Conceptual Design",
        "Logical Design",
        "Physical Design",
        "Implementation",
        "Testing and Optimization"
    ]
    
    for i, step in enumerate(steps, 1):
        st.markdown(f"**{i}. {step}**")
        st.markdown(f"   - Gather and analyze user requirements")
        st.markdown(f"   - Create Entity-Relationship diagrams")
        st.markdown(f"   - Design normalized tables and relationships")
        st.markdown(f"   - Optimize for performance and storage")
        st.markdown(f"   - Create database schema and objects")
        st.markdown(f"   - Test queries and optimize performance")
        st.markdown("")
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Requirements First:</strong> Understand business needs before designing</li>
            <li><strong>Normalization Balance:</strong> Balance normalization with performance</li>
            <li><strong>Indexing Strategy:</strong> Plan indexes for query performance</li>
            <li><strong>Scalability Planning:</strong> Design for future growth</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
