"""
Database Concepts - IT Fundamentals Lab
Enhanced with TDD Pattern - Compact UI, Visual Diagrams, Highlighted Keywords
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

def explain_database_concepts():
    """Database Concepts - Enhanced with compact TDD pattern"""
    
    # No banner - direct content

    # Database Architecture Diagram
    st.markdown("#### Database System Architecture")
    
    fig = go.Figure()
    
    # Database layers
    layers = [
        {"name": "Applications", "y": 4, "color": "#FF6B6B", "desc": "User Applications"},
        {"name": "Database Interface", "y": 3, "color": "#4ECDC4", "desc": "SQL/API Layer"},
        {"name": "Database Engine", "y": 2, "color": "#45B7D1", "desc": "Query Processing"},
        {"name": "Storage Engine", "y": 1, "color": "#96CEB4", "desc": "Data Storage"},
        {"name": "Physical Storage", "y": 0, "color": "#A0A0A0", "desc": "Disk/Memory"}
    ]
    
    for layer in layers:
        fig.add_shape(
            type="rect",
            x0=1, y0=layer["y"]-0.3, x1=9, y1=layer["y"]+0.3,
            fillcolor=layer["color"], opacity=0.7,
            line=dict(color="white", width=2)
        )
        fig.add_annotation(
            x=5, y=layer["y"], text=f"<b>{layer['name']}</b><br>{layer['desc']}",
            showarrow=False, font=dict(color="white", size=11)
        )
    
    fig.update_layout(
        title="Database System Architecture",
        xaxis=dict(visible=False), yaxis=dict(visible=False),
        height=350, showlegend=False,
        margin=dict(l=0, r=0, t=40, b=0)
    )
    
    st.plotly_chart(fig, use_container_width=True)

    # Compact content
    with st.expander(" Database Fundamentals"):
        st.markdown("""
        <div style="line-height: 1.4;">
        
        ## Core Concepts
        **Definition:** A database is an organized collection of structured information stored electronically.
        
        ### Key Benefits
        **Data Integrity:** Ensures data accuracy and consistency  
        **Concurrent Access:** Multiple users can access simultaneously  
        **Security:** Access control and data protection  
        **Backup & Recovery:** Data protection and disaster recovery  
        **Scalability:** Handle growing data volumes efficiently
        
        ### Database Types
        - **Relational (RDBMS):** Structured data in tables with relationships
        - **NoSQL:** Flexible schema for unstructured/semi-structured data
        - **In-Memory:** High-speed data processing in RAM
        - **Graph:** Optimized for connected data relationships
        
        </div>
        """, unsafe_allow_html=True)

    # Compact Cheat Sheet
    st.markdown("##  Database Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["SQL vs NoSQL", "Database Operations", "Data Types"])
    
    with tab1:
        st.markdown("### SQL vs NoSQL Comparison")
        comparison_data = [
            {
                "Aspect": "Data Structure",
                "SQL (Relational)": "Tables with rows/columns",
                "NoSQL": "Documents, Key-Value, Graph",
                "Best For": "Structured data"
            },
            {
                "Aspect": "Schema",
                "SQL (Relational)": "Fixed schema required",
                "NoSQL": "Flexible/Dynamic schema",
                "Best For": "Changing requirements"
            },
            {
                "Aspect": "Scalability",
                "SQL (Relational)": "Vertical scaling (more power)",
                "NoSQL": "Horizontal scaling (more servers)",
                "Best For": "Large scale applications"
            },
            {
                "Aspect": "ACID Compliance",
                "SQL (Relational)": "Full ACID support",
                "NoSQL": "Eventually consistent",
                "Best For": "Financial transactions"
            },
            {
                "Aspect": "Query Language",
                "SQL (Relational)": "Standardized SQL",
                "NoSQL": "Varies by database",
                "Best For": "Complex queries"
            }
        ]
        
        df_comparison = pd.DataFrame(comparison_data)
        st.dataframe(df_comparison, use_container_width=True, height=200)

    with tab2:
        st.markdown("### CRUD Operations")
        crud_data = [
            {
                "Operation": "CREATE",
                "SQL Command": "INSERT INTO table VALUES (...)",
                "Purpose": "Add new records",
                "Example": "INSERT INTO users (name, email) VALUES ('John', 'john@email.com')"
            },
            {
                "Operation": "READ",
                "SQL Command": "SELECT * FROM table WHERE ...",
                "Purpose": "Retrieve data",
                "Example": "SELECT name, email FROM users WHERE age > 18"
            },
            {
                "Operation": "UPDATE",
                "SQL Command": "UPDATE table SET ... WHERE ...",
                "Purpose": "Modify existing records",
                "Example": "UPDATE users SET email = 'new@email.com' WHERE id = 1"
            },
            {
                "Operation": "DELETE",
                "SQL Command": "DELETE FROM table WHERE ...",
                "Purpose": "Remove records",
                "Example": "DELETE FROM users WHERE last_login < '2023-01-01'"
            }
        ]
        
        df_crud = pd.DataFrame(crud_data)
        st.dataframe(df_crud, use_container_width=True, height=200)

    with tab3:
        st.markdown("### Common Data Types")
        datatypes_data = [
            {
                "Category": "Numeric",
                "SQL Types": "INT, DECIMAL, FLOAT",
                "Use Case": "Numbers, calculations",
                "Example": "age INT, price DECIMAL(10,2)"
            },
            {
                "Category": "Text",
                "SQL Types": "VARCHAR, TEXT, CHAR",
                "Use Case": "Strings, descriptions",
                "Example": "name VARCHAR(100), description TEXT"
            },
            {
                "Category": "Date/Time",
                "SQL Types": "DATE, DATETIME, TIMESTAMP",
                "Use Case": "Dates, timestamps",
                "Example": "created_at DATETIME, birth_date DATE"
            },
            {
                "Category": "Boolean",
                "SQL Types": "BOOLEAN, BIT",
                "Use Case": "True/False values",
                "Example": "is_active BOOLEAN, is_verified BIT"
            },
            {
                "Category": "Binary",
                "SQL Types": "BLOB, BINARY",
                "Use Case": "Files, images",
                "Example": "profile_image BLOB, file_data BINARY"
            }
        ]
        
        df_datatypes = pd.DataFrame(datatypes_data)
        st.dataframe(df_datatypes, use_container_width=True, height=200)

    # Interactive SQL Query Builder
    st.markdown("##  Interactive SQL Builder")
    
    with st.expander("SQL Query Constructor"):
        col1, col2 = st.columns([2, 1])
        
        with col1:
            operation = st.selectbox(
                "Select Operation:", 
                ["SELECT", "INSERT", "UPDATE", "DELETE"],
                key="db_sql_operation"
            )
            
            table_name = st.text_input("Table Name:", "users", key="db_table_name")
            
            if operation == "SELECT":
                columns = st.text_input("Columns (comma-separated):", "*", key="db_columns")
                where_clause = st.text_input("WHERE condition (optional):", "", key="db_where")
                
        with col2:
            if st.button("Generate SQL", key="db_generate_sql"):
                if operation == "SELECT":
                    sql_query = f"SELECT {columns} FROM {table_name}"
                    if where_clause:
                        sql_query += f" WHERE {where_clause}"
                    sql_query += ";"
                    
                    st.code(sql_query, language="sql")
                    st.success(" SQL Query Generated!")

    # Database Performance Comparison
    st.markdown("##  Database Performance Comparison")
    
    # Create performance comparison chart
    databases = ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'SQLite']
    read_performance = [85, 90, 95, 100, 70]
    write_performance = [80, 85, 90, 95, 75]
    scalability = [75, 85, 95, 80, 40]
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        name='Read Performance',
        x=databases,
        y=read_performance,
        marker_color='#4ECDC4'
    ))
    
    fig.add_trace(go.Bar(
        name='Write Performance',
        x=databases,
        y=write_performance,
        marker_color='#45B7D1'
    ))
    
    fig.add_trace(go.Bar(
        name='Scalability',
        x=databases,
        y=scalability,
        marker_color='#96CEB4'
    ))
    
    fig.update_layout(
        title="Database Performance Comparison (Relative Scores)",
        xaxis_title="Database Systems",
        yaxis_title="Performance Score",
        barmode='group',
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)

    # Database Design Principles
    st.markdown("##  Database Design Principles")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ** Normalization:**
        - **1NF:** Eliminate duplicate columns
        - **2NF:** Remove partial dependencies
        - **3NF:** Remove transitive dependencies
        
        ** Indexing:**
        - Primary keys for unique identification
        - Foreign keys for relationships
        - Composite indexes for multi-column queries
        """)
    
    with col2:
        st.markdown("""
        ** ACID Properties:**
        - **Atomicity:** All or nothing transactions
        - **Consistency:** Data integrity maintained
        - **Isolation:** Concurrent transaction safety
        - **Durability:** Permanent data storage
        
        ** Performance:**
        - Query optimization techniques
        - Proper indexing strategies
        - Connection pooling
        """)

    # Compact Key Takeaways
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1rem; border-radius: 8px; border-left: 4px solid #56ab2f; margin-top: 1rem;">
        <h4 style="margin: 0 0 0.5rem 0; color: #56ab2f; font-size: 1.1rem;"> Key Takeaways</h4>
        <ul style="margin: 0; padding-left: 1.2rem; line-height: 1.4;">
            <li><strong>Database Purpose:</strong> Organized, secure, and efficient data storage and retrieval</li>
            <li><strong>SQL vs NoSQL:</strong> Choose based on data structure, scalability, and consistency needs</li>
            <li><strong>CRUD Operations:</strong> Create, Read, Update, Delete - fundamental database operations</li>
            <li><strong>ACID Properties:</strong> Ensure reliable and consistent database transactions</li>
            <li><strong>Design Principles:</strong> Normalization, indexing, and performance optimization are crucial</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

    # Resources
    st.markdown("##  Learning Resources")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ** SQL Learning:**
        - [W3Schools SQL Tutorial](https://www.w3schools.com/sql/)
        - [SQLBolt Interactive Lessons](https://sqlbolt.com/)
        - [PostgreSQL Documentation](https://www.postgresql.org/docs/)
        """)
    
    with col2:
        st.markdown("""
        ** Video Courses:**
        - [Database Design Course](https://www.youtube.com/watch?v=ztHopE5Wnpc)
        - [SQL Crash Course](https://www.youtube.com/watch?v=HXV3zeQKqGY)
        - [NoSQL Explained](https://www.youtube.com/watch?v=0buKQHokLK8)
        """)

if __name__ == "__main__":
    explain_database_concepts()
