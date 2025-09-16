import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_process_management():
    """Process Management using TDD pattern"""
    
    st.markdown("## Process Management")
    st.markdown("**Definition:** Operating system mechanisms for creating, scheduling, and managing processes.")
    
    st.markdown("---")
    
    # Process States
    st.markdown("### Process States")
    
    states_data = {
        "State": ["New", "Ready", "Running", "Waiting", "Terminated"],
        "Description": [
            "Process being created",
            "Waiting for CPU allocation",
            "Currently executing",
            "Waiting for I/O or event",
            "Process has finished"
        ]
    }
    
    df = pd.DataFrame(states_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Process Lifecycle:</strong> Understand state transitions</li>
            <li><strong>Scheduling Algorithms:</strong> Different strategies for different needs</li>
            <li><strong>Context Switching:</strong> Overhead of process switching</li>
            <li><strong>Inter-Process Communication:</strong> Methods for process coordination</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_memory_management():
    """Memory Management using TDD pattern"""
    
    st.markdown("## Memory Management")
    st.markdown("**Definition:** Operating system techniques for managing computer memory efficiently.")
    
    st.markdown("---")
    
    # Memory Management Techniques
    st.markdown("### Memory Management Techniques")
    
    techniques_data = {
        "Technique": ["Paging", "Segmentation", "Virtual Memory", "Swapping"],
        "Description": [
            "Divide memory into fixed-size pages",
            "Divide memory into variable-size segments",
            "Use disk as extension of RAM",
            "Move processes between RAM and disk"
        ],
        "Advantages": [
            "Simple allocation",
            "Logical organization",
            "Larger address space",
            "More processes in memory"
        ]
    }
    
    df = pd.DataFrame(techniques_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Memory Hierarchy:</strong> Understand different memory types</li>
            <li><strong>Virtual Memory:</strong> Enables larger programs than physical RAM</li>
            <li><strong>Memory Fragmentation:</strong> Internal and external fragmentation issues</li>
            <li><strong>Performance Impact:</strong> Memory management affects system performance</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_file_systems():
    """File Systems using TDD pattern"""
    
    st.markdown("## File Systems")
    st.markdown("**Definition:** Operating system component that manages files and directories on storage devices.")
    
    st.markdown("---")
    
    # File System Types
    st.markdown("### File System Types")
    
    filesystems_data = {
        "Type": ["FAT32", "NTFS", "ext4", "APFS", "ZFS"],
        "OS": ["Windows", "Windows", "Linux", "macOS", "Solaris/FreeBSD"],
        "Features": [
            "Simple, compatible",
            "Journaling, security",
            "Journaling, large files",
            "Copy-on-write, snapshots",
            "Pooled storage, checksums"
        ]
    }
    
    df = pd.DataFrame(filesystems_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>File Organization:</strong> Hierarchical directory structure</li>
            <li><strong>Metadata Management:</strong> Track file attributes and permissions</li>
            <li><strong>Journaling:</strong> Maintain consistency after crashes</li>
            <li><strong>Performance Optimization:</strong> Caching and prefetching strategies</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
