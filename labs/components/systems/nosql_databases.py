import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_nosql_databases():
    """NoSQL Databases using TDD pattern"""
    
    st.markdown("## NoSQL Databases")
    st.markdown("**Definition:** Non-relational databases designed to handle large volumes of unstructured or semi-structured data with flexible schemas and horizontal scalability.")
    
    st.markdown("---")
    
    # NoSQL Types
    st.markdown("### NoSQL Database Types")
    
    nosql_types_data = {
        "Type": ["Document", "Key-Value", "Column-Family", "Graph"],
        "Data Model": [
            "JSON-like documents with nested structures",
            "Simple key-value pairs",
            "Column families with row keys",
            "Nodes and edges representing relationships"
        ],
        "Use Cases": [
            "Content management, catalogs, user profiles",
            "Caching, session storage, shopping carts",
            "Time-series data, IoT, analytics",
            "Social networks, recommendations, fraud detection"
        ],
        "Examples": [
            "MongoDB, CouchDB, Amazon DocumentDB",
            "Redis, Amazon DynamoDB, Riak",
            "Cassandra, HBase, Amazon SimpleDB",
            "Neo4j, Amazon Neptune, ArangoDB"
        ],
        "Query Language": [
            "MongoDB Query Language, JSON queries",
            "Simple GET/PUT operations",
            "CQL (Cassandra), HBase API",
            "Cypher (Neo4j), Gremlin, SPARQL"
        ]
    }
    
    df = pd.DataFrame(nosql_types_data)
    st.dataframe(df, use_container_width=True)
    
    # NoSQL vs SQL Comparison
    st.markdown("### NoSQL vs SQL Database Comparison")
    
    # Create comparison radar chart
    aspects = ['Scalability', 'Flexibility', 'ACID Compliance', 'Query Complexity', 'Performance', 'Consistency']
    
    database_scores = {
        'SQL (RDBMS)': [6, 4, 10, 9, 7, 10],
        'Document DB': [9, 9, 6, 7, 8, 7],
        'Key-Value': [10, 8, 4, 3, 10, 6],
        'Graph DB': [7, 8, 7, 10, 6, 8]
    }
    
    fig = go.Figure()
    
    colors = ['blue', 'green', 'red', 'purple']
    for i, (db_type, scores) in enumerate(database_scores.items()):
        fig.add_trace(go.Scatterpolar(
            r=scores,
            theta=aspects,
            fill='toself',
            name=db_type,
            line=dict(color=colors[i])
        ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 10]
            )
        ),
        title="Database Types Comparison",
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # CAP Theorem
    st.markdown("### CAP Theorem and NoSQL")
    
    cap_data = {
        "Database": ["MongoDB", "Cassandra", "Redis", "Neo4j", "DynamoDB"],
        "Consistency": ["Strong", "Eventual", "Strong", "Strong", "Eventual"],
        "Availability": ["High", "Very High", "High", "High", "Very High"],
        "Partition Tolerance": ["Yes", "Yes", "Limited", "Limited", "Yes"],
        "CAP Choice": ["CP", "AP", "CA", "CA", "AP"],
        "Trade-offs": [
            "Consistency over availability during partitions",
            "Availability over consistency, eventual consistency",
            "Consistency and availability, limited partition tolerance",
            "Consistency and availability in single node",
            "Availability over consistency, managed by AWS"
        ]
    }
    
    df2 = pd.DataFrame(cap_data)
    st.dataframe(df2, use_container_width=True)
    
    # Popular NoSQL Databases
    st.markdown("### Popular NoSQL Databases Deep Dive")
    
    popular_nosql_data = {
        "Database": ["MongoDB", "Redis", "Cassandra", "Neo4j", "Elasticsearch"],
        "Type": ["Document", "Key-Value", "Column-Family", "Graph", "Search Engine"],
        "Strengths": [
            "Flexible schema, rich queries, horizontal scaling",
            "In-memory speed, data structures, pub/sub",
            "Linear scalability, fault tolerance, no SPOF",
            "Complex relationships, graph algorithms, ACID",
            "Full-text search, analytics, real-time"
        ],
        "Weaknesses": [
            "Memory usage, complex transactions",
            "Memory limitations, persistence complexity",
            "Eventually consistent, complex operations",
            "Scaling challenges, memory intensive",
            "Not for transactional data, complex setup"
        ],
        "Ideal For": [
            "Web applications, content management, IoT",
            "Caching, real-time analytics, gaming",
            "IoT, time-series, distributed applications",
            "Social networks, fraud detection, recommendations",
            "Log analysis, monitoring, e-commerce search"
        ]
    }
    
    df3 = pd.DataFrame(popular_nosql_data)
    st.dataframe(df3, use_container_width=True)
    
    # Data Modeling Patterns
    st.markdown("### NoSQL Data Modeling Patterns")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Document Database Patterns:**
        - **Embedding** - Nest related data in documents
        - **Referencing** - Store references to other documents
        - **Bucketing** - Group time-series data
        - **Schema Versioning** - Handle schema evolution
        """)
        
        st.markdown("""
        **Key-Value Patterns:**
        - **Composite Keys** - Encode multiple values in key
        - **Secondary Indexes** - Use additional key patterns
        - **Time-based Keys** - Include timestamps for ordering
        - **Hierarchical Keys** - Use delimiters for structure
        """)
    
    with col2:
        st.markdown("""
        **Column-Family Patterns:**
        - **Wide Rows** - Store many columns per row
        - **Time Series** - Use time-based row keys
        - **Materialized Views** - Denormalize for queries
        - **Composite Columns** - Encode data in column names
        """)
        
        st.markdown("""
        **Graph Patterns:**
        - **Index-Free Adjacency** - Direct node connections
        - **Property Graphs** - Rich node and edge properties
        - **Path Queries** - Traverse relationships
        - **Recommendation Engines** - Find similar patterns
        """)
    
    # When to Use NoSQL
    st.markdown("### When to Choose NoSQL vs SQL")
    
    choice_data = {
        "Scenario": ["Large Scale Web Apps", "Real-time Analytics", "Content Management", "IoT Data Collection", "Financial Transactions"],
        "Recommended": ["NoSQL (Document/Key-Value)", "NoSQL (Column-Family)", "NoSQL (Document)", "NoSQL (Time-Series)", "SQL (RDBMS)"],
        "Reasoning": [
            "Need horizontal scaling, flexible schema",
            "High write throughput, time-series data",
            "Flexible content structure, rapid development",
            "High volume, variety of sensor data",
            "ACID compliance, complex transactions required"
        ],
        "Example Technologies": [
            "MongoDB + Redis for caching",
            "Cassandra + Spark for processing",
            "MongoDB + Elasticsearch for search",
            "InfluxDB + Grafana for visualization",
            "PostgreSQL + proper indexing"
        ]
    }
    
    df4 = pd.DataFrame(choice_data)
    st.dataframe(df4, use_container_width=True)
    
    # Migration Considerations
    st.markdown("### SQL to NoSQL Migration Considerations")
    
    migration_data = {
        "Aspect": ["Data Modeling", "Query Patterns", "Transactions", "Consistency", "Tooling"],
        "SQL Approach": [
            "Normalized tables, foreign keys",
            "Complex joins, aggregations",
            "ACID transactions across tables",
            "Strong consistency by default",
            "Mature ORMs, reporting tools"
        ],
        "NoSQL Approach": [
            "Denormalized documents/collections",
            "Simple queries, application-level joins",
            "Limited transactions, eventual consistency",
            "Configurable consistency levels",
            "Database-specific tools, less mature ecosystem"
        ],
        "Migration Strategy": [
            "Redesign schema for query patterns",
            "Rewrite queries, add application logic",
            "Identify transaction boundaries, use sagas",
            "Accept eventual consistency where possible",
            "Invest in new tools, training team"
        ]
    }
    
    df5 = pd.DataFrame(migration_data)
    st.dataframe(df5, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Right Tool for Job:</strong> Choose NoSQL based on specific requirements, not trends</li>
            <li><strong>CAP Theorem:</strong> Understand trade-offs between consistency, availability, and partition tolerance</li>
            <li><strong>Data Modeling:</strong> Design schema around query patterns, not normalization rules</li>
            <li><strong>Polyglot Persistence:</strong> Use multiple database types for different parts of your application</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
