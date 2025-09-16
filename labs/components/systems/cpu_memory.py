import streamlit as st
import pandas as pd

def explain_cpu_memory():
    """CPU and Memory using TDD pattern"""
    
    st.markdown("## CPU and Memory")
    st.markdown("**Definition:** Core components that determine computer performance and capability.")
    
    st.markdown("---")
    
    # CPU and Memory Concepts
    st.markdown("### CPU and Memory Concepts")
    
    concepts_data = {
        "Component": ["CPU", "RAM", "Cache", "Virtual Memory", "Registers"],
        "Description": [
            "Central Processing Unit - executes instructions",
            "Random Access Memory - temporary storage",
            "High-speed memory near CPU",
            "Extension of RAM using disk storage",
            "Fastest memory in CPU"
        ]
    }
    
    df = pd.DataFrame(concepts_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Performance Impact:</strong> CPU and memory directly affect system performance</li>
            <li><strong>Memory Hierarchy:</strong> Different memory types serve different purposes</li>
            <li><strong>Bottleneck Identification:</strong> Understand which component limits performance</li>
            <li><strong>Optimization Strategies:</strong> Balance CPU and memory for optimal performance</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
