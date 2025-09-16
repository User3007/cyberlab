import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_team_management():
    """Team Management using TDD pattern"""
    
    st.markdown("## Team Management")
    st.markdown("**Definition:** Process of leading, motivating, and coordinating team members to achieve project objectives effectively.")
    
    st.markdown("---")
    
    # Team Management Principles
    st.markdown("### Team Management Principles")
    
    principles_data = {
        "Principle": ["Clear Communication", "Delegation", "Motivation", "Conflict Resolution", "Performance Management"],
        "Description": [
            "Establish open and transparent communication",
            "Assign tasks based on skills and capacity",
            "Keep team members engaged and motivated",
            "Address conflicts promptly and fairly",
            "Monitor and improve team performance"
        ],
        "Benefits": [
            "Reduces misunderstandings",
            "Leverages team strengths",
            "Increases productivity",
            "Maintains team harmony",
            "Ensures quality delivery"
        ]
    }
    
    df = pd.DataFrame(principles_data)
    st.dataframe(df, use_container_width=True)
    
    # Team Development Stages
    st.markdown("### Team Development Stages")
    
    stages_data = {
        "Stage": ["Forming", "Storming", "Norming", "Performing", "Adjourning"],
        "Characteristics": [
            "Team members get to know each other",
            "Conflicts and power struggles emerge",
            "Team establishes norms and processes",
            "Team works effectively together",
            "Project ends, team disbands"
        ],
        "Manager Role": [
            "Provide direction and structure",
            "Facilitate conflict resolution",
            "Support team building",
            "Delegate and empower",
            "Celebrate achievements"
        ]
    }
    
    df2 = pd.DataFrame(stages_data)
    st.dataframe(df2, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Leadership Skills:</strong> Develop strong leadership and communication skills</li>
            <li><strong>Team Dynamics:</strong> Understand team development stages</li>
            <li><strong>Motivation Techniques:</strong> Use various methods to motivate team members</li>
            <li><strong>Continuous Improvement:</strong> Regularly assess and improve team performance</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
