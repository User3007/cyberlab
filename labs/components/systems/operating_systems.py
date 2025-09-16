"""
Operating Systems Fundamentals - IT Fundamentals Lab
Enhanced with TDD Pattern - Compact UI, Visual Diagrams, Highlighted Keywords
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

def explain_operating_systems():
    """Operating Systems Fundamentals - Enhanced with compact TDD pattern"""
    
    # No banner - direct content

    # Main OS Architecture Diagram
    st.markdown("#### OS Architecture Overview")
    
    fig = go.Figure()
    
    # OS Layers - Compact visualization
    layers = [
        {"name": "Applications", "y": 4, "color": "#FF6B6B", "desc": "User Programs"},
        {"name": "System Calls", "y": 3, "color": "#4ECDC4", "desc": "API Interface"},
        {"name": "Kernel", "y": 2, "color": "#45B7D1", "desc": "Core OS"},
        {"name": "Hardware", "y": 1, "color": "#96CEB4", "desc": "Physical Layer"}
    ]
    
    for layer in layers:
        fig.add_shape(
            type="rect",
            x0=0, y0=layer["y"]-0.4, x1=10, y1=layer["y"]+0.4,
            fillcolor=layer["color"], opacity=0.7,
            line=dict(color="white", width=2)
        )
        fig.add_annotation(
            x=5, y=layer["y"], text=f"<b>{layer['name']}</b><br>{layer['desc']}",
            showarrow=False, font=dict(color="white", size=12)
        )
    
    fig.update_layout(
        title="Operating System Layered Architecture",
        xaxis=dict(visible=False), yaxis=dict(visible=False),
        height=300, showlegend=False,
        margin=dict(l=0, r=0, t=40, b=0)
    )
    
    st.plotly_chart(fig, use_container_width=True)

    # Compact content with tight spacing
    with st.expander(" OS Fundamentals"):
        st.markdown("""
        <div style="line-height: 1.4;">
        
        ## **Core Functions**
        **Definition:** An Operating System manages computer hardware and provides services for applications.
        
        ### **Primary Responsibilities**
        **Process Management:** Create, schedule, and terminate processes  
        **Memory Management:** Allocate and deallocate memory efficiently  
        **File System:** Organize and manage data storage  
        **I/O Management:** Handle input/output operations  
        **Security:** Control access and protect resources
        
        ### **Key Components**
        - **Kernel:** Core component managing system resources
        - **Shell:** Command-line interface for user interaction
        - **Device Drivers:** Software controlling hardware devices
        - **System Libraries:** Reusable code for common functions
        
        </div>
        """, unsafe_allow_html=True)

    # Compact Cheat Sheet with highlighted keywords
    st.markdown("##  OS Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["Core Concepts", "Process Management", "Memory & Storage"])
    
    with tab1:
        st.markdown("### Core OS Concepts")
        concepts_data = [
            {
                "Component": "Kernel",
                "Function": "Core OS management",
                "Type": "Monolithic/Microkernel",
                "Example": "Linux kernel, Windows NT"
            },
            {
                "Component": "Shell", 
                "Function": "User interface",
                "Type": "CLI/GUI",
                "Example": "Bash, PowerShell, Desktop"
            },
            {
                "Component": "File System",
                "Function": "Data organization", 
                "Type": "Hierarchical/Database",
                "Example": "NTFS, ext4, APFS"
            },
            {
                "Component": "Device Drivers",
                "Function": "Hardware control",
                "Type": "Kernel/User mode",
                "Example": "Graphics, Network, Storage"
            }
        ]
        
        df_concepts = pd.DataFrame(concepts_data)
        st.dataframe(df_concepts, use_container_width=True, height=200)

    with tab2:
        st.markdown("### Process Management")
        process_data = [
            {
                "State": "New",
                "Description": "Process being created",
                "Action": "Load into memory",
                "Next State": "Ready"
            },
            {
                "State": "Ready", 
                "Description": "Waiting for CPU",
                "Action": "Schedule execution",
                "Next State": "Running"
            },
            {
                "State": "Running",
                "Description": "Executing instructions",
                "Action": "Execute/Interrupt",
                "Next State": "Ready/Waiting/Terminated"
            },
            {
                "State": "Waiting",
                "Description": "Waiting for I/O",
                "Action": "I/O completion",
                "Next State": "Ready"
            },
            {
                "State": "Terminated",
                "Description": "Process finished",
                "Action": "Clean up resources",
                "Next State": "None"
            }
        ]
        
        df_process = pd.DataFrame(process_data)
        st.dataframe(df_process, use_container_width=True, height=200)

    with tab3:
        st.markdown("### Memory & Storage")
        memory_data = [
            {
                "Type": "RAM",
                "Speed": "Very Fast",
                "Volatility": "Volatile",
                "Purpose": "Active programs & data",
                "Management": "Virtual memory, Paging"
            },
            {
                "Type": "Cache",
                "Speed": "Fastest", 
                "Volatility": "Volatile",
                "Purpose": "Frequently used data",
                "Management": "LRU, FIFO algorithms"
            },
            {
                "Type": "SSD/HDD",
                "Speed": "Slow",
                "Volatility": "Non-volatile",
                "Purpose": "Long-term storage",
                "Management": "File systems, Indexing"
            },
            {
                "Type": "Virtual Memory",
                "Speed": "Variable",
                "Volatility": "Mixed",
                "Purpose": "Extended RAM using disk",
                "Management": "Paging, Swapping"
            }
        ]
        
        df_memory = pd.DataFrame(memory_data)
        st.dataframe(df_memory, use_container_width=True, height=200)

    # Compact Interactive Demo
    st.markdown("##  Interactive OS Demo")
    
    with st.expander("Process Scheduler Simulator"):
        col1, col2 = st.columns([2, 1])
        
        with col1:
            algorithm = st.selectbox(
                "Scheduling Algorithm:", 
                ["First-Come-First-Served", "Shortest Job First", "Round Robin"],
                key="os_scheduler_algo"
            )
            
            if algorithm == "Round Robin":
                time_quantum = st.slider("Time Quantum (ms):", 1, 10, 3, key="os_time_quantum")
            
        with col2:
            if st.button("Run Simulation", key="os_run_sim"):
                st.success(" Scheduler running!")
                
                # Simple process simulation
                processes = ["P1", "P2", "P3"]
                if algorithm == "First-Come-First-Served":
                    st.write("**Execution Order:** P1  P2  P3")
                elif algorithm == "Shortest Job First":
                    st.write("**Execution Order:** P3  P1  P2")
                else:  # Round Robin
                    st.write(f"**Time Quantum:** {time_quantum}ms")
                    st.write("**Execution:** P1({time_quantum})  P2({time_quantum})  P3({time_quantum})  ...")

    # OS Comparison
    st.markdown("##  OS Comparison")
    
    comparison_data = [
        {
            "OS": "Windows",
            "Kernel": "Hybrid",
            "Interface": "GUI-focused",
            "Use Case": "Desktop, Gaming",
            "Strengths": "User-friendly, Software compatibility"
        },
        {
            "OS": "Linux",
            "Kernel": "Monolithic",
            "Interface": "CLI/GUI",
            "Use Case": "Servers, Development",
            "Strengths": "Open source, Customizable, Stable"
        },
        {
            "OS": "macOS",
            "Kernel": "Hybrid (XNU)",
            "Interface": "GUI-focused",
            "Use Case": "Creative work, Development",
            "Strengths": "Design, Unix-based, Integration"
        },
        {
            "OS": "Android",
            "Kernel": "Linux-based",
            "Interface": "Touch GUI",
            "Use Case": "Mobile devices",
            "Strengths": "Mobile optimization, App ecosystem"
        }
    ]
    
    df_comparison = pd.DataFrame(comparison_data)
    st.dataframe(df_comparison, use_container_width=True, height=200)

    # Compact Key Takeaways
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1rem; border-radius: 8px; border-left: 4px solid #56ab2f; margin-top: 1rem;">
        <h4 style="margin: 0 0 0.5rem 0; color: #56ab2f; font-size: 1.1rem;"> Key Takeaways</h4>
        <ul style="margin: 0; padding-left: 1.2rem; line-height: 1.4;">
            <li><strong>OS Role:</strong> Manages hardware resources and provides services to applications</li>
            <li><strong>Core Functions:</strong> Process, memory, file system, I/O, and security management</li>
            <li><strong>Architecture:</strong> Layered design with kernel as the core component</li>
            <li><strong>Process States:</strong> New  Ready  Running  Waiting  Terminated lifecycle</li>
            <li><strong>Memory Hierarchy:</strong> Cache  RAM  Virtual Memory  Storage for optimal performance</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

    # Resources section
    st.markdown("##  Learning Resources")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ** Essential Reading:**
        - [Operating System Concepts](https://www.os-book.com/) - Silberschatz textbook
        - [Linux Kernel Documentation](https://www.kernel.org/doc/)
        - [Windows Internals](https://docs.microsoft.com/en-us/sysinternals/)
        """)
    
    with col2:
        st.markdown("""
        ** Video Learning:**
        - [OS Course - MIT](https://ocw.mit.edu/courses/electrical-engineering-and-computer-science/)
        - [Linux System Programming](https://www.youtube.com/watch?v=bkSWJJZNgf8)
        - [Windows Architecture](https://channel9.msdn.com/Shows/Going+Deep)
        """)

if __name__ == "__main__":
    explain_operating_systems()
