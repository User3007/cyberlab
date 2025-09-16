import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_cpu_memory():
    """CPU & Memory Systems using TDD pattern"""
    
    st.markdown("## CPU & Memory Systems")
    st.markdown("**Definition:** Core computer components responsible for processing instructions (CPU) and storing data/programs (Memory) with complex interactions and performance optimizations.")
    
    st.markdown("---")
    
    # CPU Architecture
    st.markdown("### CPU Architecture Components")
    
    cpu_components_data = {
        "Component": ["Control Unit", "Arithmetic Logic Unit", "Registers", "Cache Memory", "Bus Interface"],
        "Function": [
            "Fetches, decodes, and executes instructions",
            "Performs mathematical and logical operations",
            "High-speed temporary storage within CPU",
            "Fast memory buffer between CPU and RAM",
            "Manages data transfer between CPU and system"
        ],
        "Key Characteristics": [
            "Instruction pipeline, branch prediction",
            "Integer, floating-point, vector operations",
            "General purpose, special purpose, status",
            "L1, L2, L3 hierarchy with different speeds",
            "Address, data, control buses"
        ],
        "Performance Impact": [
            "Instruction throughput, pipeline efficiency",
            "Computational performance, parallel execution",
            "Context switching speed, temporary storage",
            "Memory access latency, hit/miss ratios",
            "Data transfer bandwidth, system bottlenecks"
        ]
    }
    
    df = pd.DataFrame(cpu_components_data)
    st.dataframe(df, use_container_width=True)
    
    # Memory Hierarchy
    st.markdown("### Memory Hierarchy")
    
    # Create memory hierarchy visualization
    memory_types = ['Registers', 'L1 Cache', 'L2 Cache', 'L3 Cache', 'RAM', 'SSD', 'HDD']
    speed = [1000, 500, 100, 50, 10, 1, 0.1]  # Relative speed
    capacity = [0.001, 0.01, 0.1, 1, 1000, 100000, 1000000]  # Relative capacity (KB)
    cost_per_gb = [1000000, 100000, 10000, 1000, 10, 1, 0.1]  # Relative cost
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=capacity,
        y=speed,
        mode='markers+text',
        text=memory_types,
        textposition='top center',
        marker=dict(
            size=[20, 25, 30, 35, 40, 45, 50],
            color=cost_per_gb,
            colorscale='Viridis',
            showscale=True,
            colorbar=dict(title="Cost per GB")
        ),
        name='Memory Types'
    ))
    
    fig.update_layout(
        title="Memory Hierarchy: Speed vs Capacity vs Cost",
        xaxis_title="Capacity (Relative Scale)",
        yaxis_title="Speed (Relative Scale)",
        xaxis_type="log",
        yaxis_type="log",
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Memory Types Comparison
    st.markdown("### Memory Types Detailed Comparison")
    
    memory_details_data = {
        "Memory Type": ["SRAM", "DRAM", "DDR4", "DDR5", "GDDR6", "HBM"],
        "Speed": ["Very Fast", "Fast", "Fast", "Very Fast", "Ultra Fast", "Ultra Fast"],
        "Capacity": ["Small", "Large", "Large", "Large", "Medium", "Medium"],
        "Power Usage": ["Low", "Medium", "Medium", "Low", "High", "Medium"],
        "Cost": ["Very High", "Medium", "Medium", "High", "Very High", "Very High"],
        "Use Case": [
            "CPU cache, high-speed buffers",
            "System RAM, general purpose",
            "Desktop/server memory",
            "Latest systems, improved efficiency",
            "Graphics cards, AI/ML workloads",
            "High-performance computing"
        ]
    }
    
    df2 = pd.DataFrame(memory_details_data)
    st.dataframe(df2, use_container_width=True)
    
    # CPU Performance Factors
    st.markdown("### CPU Performance Factors")
    
    performance_data = {
        "Factor": ["Clock Speed", "Core Count", "Cache Size", "Architecture", "Manufacturing Process"],
        "Impact on Performance": [
            "Instructions per second execution rate",
            "Parallel processing capability",
            "Reduced memory access latency",
            "Instruction efficiency and features",
            "Power efficiency and transistor density"
        ],
        "Typical Values": [
            "2-5 GHz for desktop CPUs",
            "4-64 cores for consumer/server",
            "1-64 MB L3 cache",
            "x86-64, ARM, RISC-V",
            "7nm, 5nm, 3nm processes"
        ],
        "Optimization Strategies": [
            "Turbo boost, dynamic frequency scaling",
            "Multi-threading, parallel algorithms",
            "Cache-friendly programming",
            "Vectorization, SIMD instructions",
            "Thermal management, power gating"
        ]
    }
    
    df3 = pd.DataFrame(performance_data)
    st.dataframe(df3, use_container_width=True)
    
    # Memory Management Concepts
    st.markdown("### Memory Management Concepts")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Virtual Memory:**
        - Address space abstraction
        - Page-based memory management
        - Demand paging and swapping
        - Memory protection between processes
        """)
        
        st.markdown("""
        **Cache Management:**
        - Temporal and spatial locality
        - Cache replacement policies (LRU, LFU)
        - Write-through vs write-back
        - Cache coherency in multi-core systems
        """)
    
    with col2:
        st.markdown("""
        **Memory Allocation:**
        - Stack vs heap memory
        - Dynamic memory allocation
        - Garbage collection mechanisms
        - Memory fragmentation issues
        """)
        
        st.markdown("""
        **Performance Optimization:**
        - Memory alignment and padding
        - Cache-friendly data structures
        - Memory prefetching
        - NUMA (Non-Uniform Memory Access)
        """)
    
    # CPU Security Features
    st.markdown("### CPU Security Features")
    
    security_data = {
        "Feature": ["NX Bit", "SMEP/SMAP", "Intel CET", "ARM Pointer Authentication", "Memory Encryption"],
        "Purpose": [
            "Prevent code execution in data segments",
            "Prevent kernel exploitation techniques",
            "Control flow integrity protection",
            "Prevent ROP/JOP attacks",
            "Encrypt memory contents"
        ],
        "Implementation": [
            "Hardware bit in page table entries",
            "Supervisor mode execution/access prevention",
            "Shadow stack, indirect branch tracking",
            "Cryptographic signatures for pointers",
            "Intel TME, AMD SME/SEV"
        ],
        "Security Benefit": [
            "Mitigates buffer overflow exploits",
            "Reduces privilege escalation attacks",
            "Prevents code-reuse attacks",
            "Hardens against memory corruption",
            "Protects against physical memory access"
        ]
    }
    
    df4 = pd.DataFrame(security_data)
    st.dataframe(df4, use_container_width=True)
    
    # Performance Monitoring
    st.markdown("### CPU & Memory Performance Monitoring")
    
    monitoring_data = {
        "Metric": ["CPU Utilization", "Memory Usage", "Cache Hit Rate", "Memory Bandwidth", "Latency"],
        "Description": [
            "Percentage of time CPU is actively processing",
            "Amount of physical/virtual memory in use",
            "Percentage of memory accesses served by cache",
            "Rate of data transfer to/from memory",
            "Time delay in memory access operations"
        ],
        "Tools": [
            "Task Manager, htop, perf, Intel VTune",
            "Resource Monitor, free, vmstat",
            "perf, Intel VTune, CPU performance counters",
            "STREAM benchmark, Intel MLC",
            "Intel MLC, AIDA64, custom benchmarks"
        ],
        "Optimization Targets": [
            "<80% average, load balancing",
            "<85% physical, minimize swapping",
            ">95% L1, >90% L2, >80% L3",
            "Maximize sustained bandwidth",
            "Minimize access latency"
        ]
    }
    
    df5 = pd.DataFrame(monitoring_data)
    st.dataframe(df5, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Hierarchy Matters:</strong> Memory hierarchy balances speed, capacity, and cost</li>
            <li><strong>Cache is Critical:</strong> Cache performance significantly impacts overall system speed</li>
            <li><strong>Security Integration:</strong> Modern CPUs include hardware security features</li>
            <li><strong>Monitor Performance:</strong> Understanding metrics helps optimize system performance</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
