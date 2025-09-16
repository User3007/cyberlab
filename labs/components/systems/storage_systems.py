import streamlit as st
import pandas as pd

def explain_storage_systems():
    """Storage Systems using TDD pattern"""
    
    st.markdown("## Storage Systems")
    st.markdown("**Definition:** Technologies and methods for storing and retrieving data in computer systems.")
    
    st.markdown("---")
    
    # Storage Types
    st.markdown("### Storage Types")
    
    storage_data = {
        "Type": ["HDD", "SSD", "NVMe", "Optical", "Tape", "Cloud"],
        "Speed": ["Slow", "Fast", "Very Fast", "Slow", "Very Slow", "Variable"],
        "Capacity": ["High", "Medium", "Medium", "Low", "Very High", "Unlimited"],
        "Cost": ["Low", "Medium", "High", "Low", "Low", "Variable"]
    }
    
    df = pd.DataFrame(storage_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Performance vs Capacity:</strong> Balance speed with storage capacity</li>
            <li><strong>Cost Considerations:</strong> Factor in total cost of ownership</li>
            <li><strong>Reliability:</strong> Consider data durability and backup needs</li>
            <li><strong>Scalability:</strong> Plan for future storage requirements</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
