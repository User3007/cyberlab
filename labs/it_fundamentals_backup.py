import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import random

def run_lab():
    """IT Fundamentals Lab - Kiến thức cơ bản CNTT"""
    
    st.title("💻 IT Fundamentals Lab")
    st.markdown("---")
    
    # Tabs cho các chủ đề cơ bản
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🖥️ Computer Systems", 
        "🌐 Networking Basics",
        "💾 Operating Systems", 
        "🗄️ Database Fundamentals",
        "🔧 System Administration",
        "📊 IT Service Management"
    ])
    
    with tab1:
        computer_systems_lab()
    
    with tab2:
        networking_basics_lab()
    
    with tab3:
        operating_systems_lab()
        
    with tab4:
        database_fundamentals_lab()
        
    with tab5:
        system_administration_lab()
        
    with tab6:
        it_service_management_lab()

def computer_systems_lab():
    """Lab về hệ thống máy tính"""
    st.subheader("🖥️ Computer Systems Lab")
    
    topic_choice = st.selectbox("Chọn chủ đề:", [
        "Computer Architecture",
        "CPU & Memory",
        "Storage Systems",
        "Input/Output Systems",
        "Performance Analysis"
    ])
    
    if topic_choice == "Computer Architecture":
        explain_computer_architecture()
    elif topic_choice == "CPU & Memory":
        explain_cpu_memory()
    elif topic_choice == "Storage Systems":
        explain_storage_systems()
    elif topic_choice == "Performance Analysis":
        explain_performance_analysis()

def explain_computer_architecture():
    """Enhanced Computer Architecture explanation using TDD pattern"""
    st.markdown("### Computer Architecture")
    
    # 1. Visual Banner (IT Fundamentals color scheme)
    st.markdown("""
    <div style="background: linear-gradient(90deg, #56ab2f 0%, #a8e6cf 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            Computer Architecture
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Von Neumann Architecture - Foundation of Computing
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 2. Visual Diagram (Enhanced architecture diagram)
    st.markdown("#### Von Neumann Architecture")
    
    fig = go.Figure()
    
    # Create computer architecture components
    components = [
        {"name": "CPU", "x": 0.5, "y": 0.75, "width": 0.3, "height": 0.15, "color": "#e74c3c"},
        {"name": "Memory\n(RAM)", "x": 0.15, "y": 0.5, "width": 0.2, "height": 0.15, "color": "#3498db"},
        {"name": "Input\nDevices", "x": 0.15, "y": 0.25, "width": 0.2, "height": 0.15, "color": "#2ecc71"},
        {"name": "Output\nDevices", "x": 0.65, "y": 0.25, "width": 0.2, "height": 0.15, "color": "#f39c12"},
        {"name": "Storage", "x": 0.5, "y": 0.05, "width": 0.25, "height": 0.1, "color": "#9b59b6"}
    ]
    
    # Draw components
    for comp in components:
        # Component rectangle
        fig.add_shape(
            type="rect",
            x0=comp["x"] - comp["width"]/2, y0=comp["y"] - comp["height"]/2,
            x1=comp["x"] + comp["width"]/2, y1=comp["y"] + comp["height"]/2,
            fillcolor=comp["color"],
            opacity=0.8,
            line=dict(color="white", width=2)
        )
        
        # Component label
        fig.add_annotation(
            x=comp["x"], y=comp["y"],
            text=f"<b>{comp['name']}</b>",
            showarrow=False,
            font=dict(size=12, color="white"),
        )
    
    # Add system bus connections
    bus_connections = [
        # CPU to Memory
        [(0.35, 0.75), (0.25, 0.58)],
        # CPU to Input
        [(0.35, 0.68), (0.25, 0.4)],
        # CPU to Output
        [(0.65, 0.68), (0.75, 0.4)],
        # CPU to Storage
        [(0.5, 0.67), (0.5, 0.15)]
    ]
    
    for start, end in bus_connections:
        fig.add_shape(
            type="line",
            x0=start[0], y0=start[1], x1=end[0], y1=end[1],
            line=dict(color="#34495e", width=3, dash="solid")
        )
        
        # Add arrow
        fig.add_annotation(
            x=end[0], y=end[1],
            ax=start[0], ay=start[1],
            arrowhead=2, arrowsize=1, arrowwidth=2, arrowcolor="#34495e",
            showarrow=True, text=""
        )
    
    # Add bus label
    fig.add_annotation(
        x=0.5, y=0.9,
        text="<b>System Bus</b><br>(Data, Address, Control)",
        showarrow=False,
        font=dict(size=10, color="#2c3e50"),
        bgcolor="rgba(255,255,255,0.8)",
        bordercolor="#2c3e50",
        borderwidth=1
    )
    
    fig.update_layout(
        xaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=400,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # 3. Clean Content with expandable details
    with st.expander("Chi tiết về Computer Architecture"):
        st.markdown("""
        ## Computer Architecture Fundamentals
        
        **Definition:** Computer architecture defines the structure và behavior of computer systems, based on Von Neumann model where instructions và data share the same memory space.
        
        ---
        
        ## Core Components
        
        ### **Central Processing Unit (CPU)**
        **Purpose:** Execute instructions và perform computations
        **Implementation:** Control Unit (CU) + Arithmetic Logic Unit (ALU) + Registers
        **Benefits:** Centralized processing, efficient instruction execution
        
        ### **Memory (RAM)**  
        **Purpose:** Store programs và data temporarily during execution
        **Implementation:** Volatile storage với unique addresses for each location
        **Benefits:** Fast access, random addressing, shared instruction/data space
        
        ### **Input/Output (I/O) Devices**
        **Purpose:** Interface between computer và external world
        **Implementation:** Input devices (keyboard, mouse) + Output devices (monitor, printer)
        **Benefits:** User interaction, data input/output, system communication
        
        ### **System Bus**
        **Purpose:** Communication pathway between all components
        **Implementation:** Data bus + Address bus + Control bus
        **Benefits:** Unified communication, scalable connections, standardized interface
        
        ---
        
        ## Instruction Cycle (Fetch-Decode-Execute)
        
        **Fetch Phase:**
        - **Process:** CPU retrieves instruction from memory location pointed by Program Counter
        - **Components:** Program Counter (PC), Instruction Register (IR), Memory Address Register
        - **Result:** Instruction loaded into CPU for processing
        
        **Decode Phase:**
        - **Process:** Control Unit interprets instruction và determines required operations
        - **Components:** Control Unit, Instruction Decoder, Operand fetching logic
        - **Result:** CPU prepared with necessary resources và control signals
        
        **Execute Phase:**
        - **Process:** ALU performs computation or Control Unit executes operation
        - **Components:** ALU, Registers, Memory interface, I/O controllers
        - **Result:** Operation completed, results stored, PC updated for next instruction
        
        ---
        
        ## Performance Factors
        
        **Clock Speed:**
        - **Definition:** Number of instruction cycles per second (measured in GHz)
        - **Impact:** Higher clock speed = faster instruction execution
        - **Limitations:** Heat generation, power consumption, manufacturing constraints
        
        **Cache Memory Hierarchy:**
        - **L1 Cache:** Fastest access (1-2 cycles), smallest size (32-64KB), per-core
        - **L2 Cache:** Medium access (10-20 cycles), medium size (256KB-1MB), per-core or shared
        - **L3 Cache:** Slower access (30-50 cycles), largest size (8-32MB), shared across cores
        
        **Parallel Processing:**
        - **Multi-core:** Multiple physical CPU cores for parallel execution
        - **Hyper-threading:** Virtual cores through simultaneous multithreading
        - **Pipelining:** Overlapping instruction phases for increased throughput
        """)
    
    # 4. Enhanced Cheat Sheets with highlighted keywords
    st.markdown("---")
    st.markdown("## Computer Architecture Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["Core Components", "Performance Metrics", "Instruction Cycle"])
    
    with tab1:
        st.markdown("### Core Components")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Component** | **Primary Function** | **Sub-components** | **Key Features** | **Performance Impact** | **Example** |
        |---------------|---------------------|-------------------|------------------|------------------------|-------------|
        | **CPU (Central Processing Unit)** | **Instruction execution** và computation | `Control_Unit`, `ALU`, `Registers` | **Multi-core**, hyper-threading, **cache hierarchy** | **Clock speed**, instruction throughput | **Intel i7-12700K** (12 cores, 20 threads) |
        | **Memory (RAM)** | **Temporary storage** for active programs | `Memory_cells`, `Address_decoder`, `Data_bus` | **Volatile**, random access, **shared space** | **Access speed**, bandwidth, **latency** | **32GB DDR4-3200** (3200 MHz, CL16) |
        | **System Bus** | **Communication** between components | `Data_bus`, `Address_bus`, `Control_bus` | **Parallel transmission**, standardized **protocols** | **Bus width**, frequency, **contention** | **64-bit data bus** với PCIe 4.0 interface |
        | **I/O Devices** | **External communication** và interaction | `Input_devices`, `Output_devices`, `Controllers` | **Diverse interfaces**, buffering, **interrupt handling** | **Transfer rates**, latency, **protocol overhead** | **USB 3.2** (10 Gbps), **NVMe SSD** (7 GB/s) |
        """)
        
        # Additional highlighted information
        st.markdown("""
        #### **Key Terminology**
        - **Von Neumann Architecture**: `stored_program_concept` - Instructions và data stored in same memory
        - **Harvard Architecture**: `separate_memory` - Instructions và data in separate memory spaces  
        - **CISC vs RISC**: `instruction_set_complexity` - Complex vs Reduced instruction sets
        """)
    
    with tab2:
        st.markdown("### Performance Metrics")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Metric** | **Definition** | **Typical Range** | **Impact on Performance** | **Limitations** | **Optimization** |
        |------------|----------------|-------------------|---------------------------|-----------------|------------------|
        | **Clock Speed (GHz)** | **Cycles per second** executed by CPU | **2.0-5.0 GHz** (desktop CPUs) | **Linear relationship** với single-thread performance | **Heat generation**, power consumption | **Turbo boost**, dynamic frequency scaling |
        | **Cache Hit Rate** | **Percentage** of memory requests served by cache | **95-99%** for well-optimized applications | **Dramatic improvement** in memory access speed | **Cache size**, access patterns | **Data locality**, cache-friendly algorithms |
        | **Instructions Per Cycle (IPC)** | **Average instructions** executed per clock cycle | **1-4 IPC** for modern CPUs | **Overall throughput** và efficiency | **Instruction dependencies**, pipeline stalls | **Superscalar design**, out-of-order execution |
        | **Memory Bandwidth** | **Data transfer rate** between CPU và memory | **50-100 GB/s** for DDR4/DDR5 | **Memory-intensive** applications benefit most | **Memory controller**, channel configuration | **Multi-channel memory**, higher frequency RAM |
        """)
    
    with tab3:
        st.markdown("### Instruction Cycle Details")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Phase** | **Duration** | **Key Actions** | **Components Used** | **Potential Issues** | **Optimization** |
        |-----------|--------------|-----------------|---------------------|---------------------|------------------|
        | **Fetch** | **1-2 cycles** (with cache hit) | **PC → MAR**, memory read, **IR ← instruction** | `Program_Counter`, `MAR`, `Instruction_Register` | **Cache miss**, memory latency | **Instruction prefetch**, branch prediction |
        | **Decode** | **1 cycle** (parallel với fetch) | **Instruction parsing**, operand identification | `Control_Unit`, `Instruction_Decoder` | **Complex instructions**, dependency detection | **Micro-operations**, parallel decode units |
        | **Execute** | **1-100+ cycles** (operation dependent) | **ALU operation**, memory access, **result storage** | `ALU`, `FPU`, `Memory_interface` | **Resource conflicts**, memory bottlenecks | **Pipelining**, superscalar execution |
        | **Writeback** | **1 cycle** (register write) | **Result → registers**, flag updates | `Register_file`, `Status_flags` | **Write conflicts**, register pressure | **Register renaming**, out-of-order completion |
        """)
    
    # 5. Interactive Demo
    st.markdown("---")
    st.markdown("## Interactive Demo")
    
    with st.expander("System Architecture Simulator"):
        st.markdown("### Computer System Generator")
        
        # Simple interactive element
        system_type = st.selectbox(
            "Choose system type:", 
            ["Gaming Desktop", "Office Workstation", "Server System", "Mobile Device"]
        )
        
        if st.button("🖥️ Generate System Configuration"):
            system_info = generate_system_info()
            
            if system_type == "Gaming Desktop":
                st.markdown("**🎮 Gaming Desktop Configuration:**")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Core Components:**")
                    st.markdown(f"- **CPU**: {system_info['cpu']} (Gaming optimized)")
                    st.markdown(f"- **Cores**: {system_info['cores']} cores, {system_info['threads']} threads")
                    st.markdown(f"- **Clock**: {system_info['clock_speed']} GHz (Turbo boost)")
                    st.markdown(f"- **RAM**: {system_info['ram']} GB DDR4-3600")
                    
                with col2:
                    st.markdown("**Performance Features:**")
                    st.markdown(f"- **L1 Cache**: {system_info['l1_cache']}KB (ultra-fast)")
                    st.markdown(f"- **L2 Cache**: {system_info['l2_cache']}KB (per-core)")
                    st.markdown(f"- **L3 Cache**: {system_info['l3_cache']}MB (shared)")
                    st.markdown(f"- **Storage**: {system_info['storage']} GB NVMe SSD")
                    
                st.success("✅ **Gaming system** optimized for **high-performance** graphics và **low-latency** gaming!")
                
            elif system_type == "Office Workstation":
                st.markdown("**💼 Office Workstation Configuration:**")
                st.markdown(f"""
                **Balanced Performance Setup:**
                - **CPU**: {system_info['cpu']} (Business efficiency)
                - **Configuration**: {system_info['cores']} cores, {system_info['threads']} threads
                - **Memory**: {system_info['ram']} GB DDR4 (Productivity optimized)
                - **Storage**: {system_info['storage']} GB SSD (Fast boot và application loading)
                - **Focus**: **Multitasking**, document processing, **web browsing**
                """)
                st.success("✅ **Office system** designed for **productivity** và **energy efficiency**!")
                
            elif system_type == "Server System":
                st.markdown("**🖥️ Server System Configuration:**")
                st.markdown(f"""
                **Enterprise-Grade Hardware:**
                - **CPU**: {system_info['cpu']} (Server-class processor)
                - **Multi-processing**: {system_info['cores']} cores, {system_info['threads']} threads (High concurrency)
                - **Memory**: {system_info['ram']*4} GB ECC RAM (Error correction)
                - **Storage**: {system_info['storage']*10} GB Enterprise SSD Array
                - **Focus**: **Reliability**, 24/7 uptime, **scalability**
                """)
                st.success("✅ **Server system** built for **high availability** và **concurrent processing**!")
                
            elif system_type == "Mobile Device":
                st.markdown("**📱 Mobile Device Configuration:**")
                st.markdown(f"""
                **Power-Efficient Design:**
                - **SoC**: ARM-based processor (Integrated design)
                - **Cores**: {system_info['cores']//2} efficiency + {system_info['cores']//2} performance cores
                - **Memory**: {system_info['ram']//4} GB LPDDR5 (Low power)
                - **Storage**: {system_info['storage']//4} GB eUFS (Embedded storage)
                - **Focus**: **Battery life**, thermal efficiency, **portability**
                """)
                st.success("✅ **Mobile system** optimized for **power efficiency** và **thermal management**!")
    
    # 6. Key Takeaways
    st.markdown("---")
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1.5rem; border-radius: 10px; border-left: 5px solid #1f77b4;">
        <h4 style="margin-top: 0; color: #1f77b4;">Key Takeaways</h4>
        <ul>
            <li><strong>Von Neumann Foundation</strong>: Modern computers still follow this fundamental architecture với shared memory for instructions và data</li>
            <li><strong>Performance Balance</strong>: CPU speed, memory bandwidth, và I/O capabilities must be balanced for optimal system performance</li>
            <li><strong>Cache Hierarchy</strong>: Multi-level cache systems dramatically improve performance by reducing memory access latency</li>
            <li><strong>Parallel Processing</strong>: Multi-core CPUs và parallel execution techniques enable modern computing performance</li>
            <li><strong>System Optimization</strong>: Understanding architecture helps in choosing appropriate hardware configurations for specific use cases</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_cpu_memory():
    """Giải thích CPU và Memory"""
    st.markdown("### 🧠 CPU & Memory Systems")
    
    with st.expander("📖 Lý thuyết chi tiết về CPU & Memory"):
        st.markdown("""
        ### 🔥 CPU (Central Processing Unit)
        
        **CPU Components:**
        
        **1. Control Unit (CU)**
        - Manages instruction execution
        - Controls data flow between components
        - Handles interrupts và exceptions
        
        **2. Arithmetic Logic Unit (ALU)**
        - **Arithmetic Operations**: Add, subtract, multiply, divide
        - **Logic Operations**: AND, OR, NOT, XOR
        - **Comparison Operations**: Equal, greater than, less than
        
        **3. Registers**
        - **General Purpose**: Store temporary data
        - **Special Purpose**: Program Counter, Stack Pointer
        - **Status Register**: Flags for conditions
        
        ### 💾 Memory Hierarchy
        
        **Speed vs Capacity Trade-off:**
        
        **1. Registers (Fastest)**
        - Inside CPU
        - Access time: < 1 nanosecond
        - Capacity: 32-64 registers
        
        **2. Cache Memory**
        - **L1**: On-chip, 1-2 cycles
        - **L2**: On-chip/off-chip, 3-10 cycles
        - **L3**: Shared among cores, 10-20 cycles
        
        **3. Main Memory (RAM)**
        - **DRAM**: Dynamic RAM, needs refresh
        - **SRAM**: Static RAM, faster but expensive
        - Access time: 50-100 nanoseconds
        
        **4. Secondary Storage**
        - **HDD**: Magnetic storage, slow but cheap
        - **SSD**: Flash memory, faster than HDD
        - **Optical**: CD/DVD/Blu-ray
        
        ### 🚀 Performance Optimization
        
        **Cache Optimization:**
        - **Temporal Locality**: Recently accessed data
        - **Spatial Locality**: Nearby data access
        - **Cache Hit Ratio**: Percentage of cache hits
        
        **Memory Management:**
        - **Virtual Memory**: Extends physical memory
        - **Paging**: Fixed-size memory blocks
        - **Segmentation**: Variable-size memory blocks
        
        **CPU Optimization:**
        - **Pipelining**: Parallel instruction processing
        - **Branch Prediction**: Predict conditional jumps
        - **Out-of-order Execution**: Reorder for efficiency
        """)
    
    # Memory hierarchy visualization
    st.markdown("#### 📊 Memory Hierarchy Visualization")
    
    memory_data = [
        {"Level": "Registers", "Speed": "1 ns", "Capacity": "1 KB", "Cost": "Very High"},
        {"Level": "L1 Cache", "Speed": "2 ns", "Capacity": "64 KB", "Cost": "High"},
        {"Level": "L2 Cache", "Speed": "5 ns", "Capacity": "512 KB", "Cost": "Medium-High"},
        {"Level": "L3 Cache", "Speed": "15 ns", "Capacity": "8 MB", "Cost": "Medium"},
        {"Level": "RAM", "Speed": "100 ns", "Capacity": "16 GB", "Cost": "Low"},
        {"Level": "SSD", "Speed": "0.1 ms", "Capacity": "1 TB", "Cost": "Very Low"},
        {"Level": "HDD", "Speed": "10 ms", "Capacity": "4 TB", "Cost": "Very Low"}
    ]
    
    df = pd.DataFrame(memory_data)
    st.dataframe(df, width='stretch')

def explain_storage_systems():
    """Giải thích hệ thống lưu trữ"""
    st.markdown("### 💾 Storage Systems")
    
    with st.expander("📖 Lý thuyết chi tiết về Storage Systems"):
        st.markdown("""
        ### 🗄️ Types of Storage
        
        **1. Primary Storage (Volatile)**
        - **RAM**: Random Access Memory
        - **Cache**: High-speed temporary storage
        - **Registers**: CPU internal storage
        
        **2. Secondary Storage (Non-volatile)**
        - **HDD**: Hard Disk Drive
        - **SSD**: Solid State Drive
        - **Optical**: CD, DVD, Blu-ray
        - **Tape**: Magnetic tape for backup
        
        ### 🔄 HDD vs SSD Comparison
        
        **Hard Disk Drive (HDD):**
        - **Technology**: Magnetic storage with spinning disks
        - **Speed**: 5400-15000 RPM
        - **Access Time**: 5-10 milliseconds
        - **Capacity**: Up to 20+ TB
        - **Cost**: $0.02-0.05 per GB
        - **Durability**: Mechanical parts, prone to failure
        
        **Solid State Drive (SSD):**
        - **Technology**: NAND flash memory
        - **Speed**: No moving parts
        - **Access Time**: 0.1 milliseconds
        - **Capacity**: Up to 8+ TB (consumer)
        - **Cost**: $0.10-0.30 per GB
        - **Durability**: No mechanical parts, more reliable
        
        ### 📊 Storage Performance Metrics
        
        **IOPS (Input/Output Operations Per Second):**
        - **HDD**: 100-200 IOPS
        - **SSD**: 10,000-100,000+ IOPS
        
        **Throughput:**
        - **HDD**: 100-200 MB/s
        - **SATA SSD**: 500-600 MB/s
        - **NVMe SSD**: 2,000-7,000 MB/s
        
        ### 🔧 Storage Technologies
        
        **RAID (Redundant Array of Independent Disks):**
        - **RAID 0**: Striping (performance, no redundancy)
        - **RAID 1**: Mirroring (redundancy)
        - **RAID 5**: Striping with parity
        - **RAID 10**: Combination of RAID 1+0
        
        **File Systems:**
        - **NTFS**: Windows file system
        - **ext4**: Linux file system
        - **APFS**: Apple file system
        - **ZFS**: Advanced file system with built-in RAID
        """)
    
    # Storage comparison chart
    st.markdown("#### 📊 Storage Performance Comparison")
    
    storage_data = [
        {"Type": "HDD 7200 RPM", "Read Speed": "150 MB/s", "Write Speed": "150 MB/s", "IOPS": "150", "Price/GB": "$0.03"},
        {"Type": "SATA SSD", "Read Speed": "550 MB/s", "Write Speed": "520 MB/s", "IOPS": "90,000", "Price/GB": "$0.15"},
        {"Type": "NVMe SSD", "Read Speed": "3,500 MB/s", "Write Speed": "3,000 MB/s", "IOPS": "500,000", "Price/GB": "$0.20"},
        {"Type": "Optane SSD", "Read Speed": "2,500 MB/s", "Write Speed": "2,000 MB/s", "IOPS": "550,000", "Price/GB": "$1.50"}
    ]
    
    df = pd.DataFrame(storage_data)
    st.dataframe(df, width='stretch')

def explain_performance_analysis():
    """Giải thích phân tích hiệu suất"""
    st.markdown("### 📈 Performance Analysis")
    
    with st.expander("📖 Lý thuyết chi tiết về Performance Analysis"):
        st.markdown("""
        ### 🎯 Performance Metrics
        
        **CPU Performance:**
        - **Clock Speed**: GHz (Gigahertz)
        - **IPC**: Instructions Per Clock cycle
        - **Throughput**: Instructions per second
        - **CPU Utilization**: Percentage of CPU usage
        
        **Memory Performance:**
        - **Bandwidth**: Data transfer rate (GB/s)
        - **Latency**: Access time (nanoseconds)
        - **Hit Ratio**: Cache hit percentage
        - **Memory Utilization**: RAM usage percentage
        
        **Storage Performance:**
        - **IOPS**: Input/Output Operations Per Second
        - **Throughput**: Data transfer rate (MB/s)
        - **Latency**: Response time (milliseconds)
        - **Queue Depth**: Pending I/O operations
        
        **Network Performance:**
        - **Bandwidth**: Data transfer capacity (Mbps/Gbps)
        - **Latency**: Round-trip time (milliseconds)
        - **Packet Loss**: Percentage of lost packets
        - **Jitter**: Variation in latency
        
        ### 🔍 Benchmarking Tools
        
        **CPU Benchmarks:**
        - **Cinebench**: Multi-core rendering performance
        - **Prime95**: CPU stress testing
        - **Geekbench**: Cross-platform CPU benchmark
        
        **Memory Benchmarks:**
        - **MemTest86**: Memory stability testing
        - **AIDA64**: Memory bandwidth testing
        - **Stream**: Memory bandwidth benchmark
        
        **Storage Benchmarks:**
        - **CrystalDiskMark**: Sequential/random performance
        - **ATTO**: Transfer rate across file sizes
        - **FIO**: Flexible I/O tester
        
        ### 📊 Performance Bottlenecks
        
        **Common Bottlenecks:**
        
        **1. CPU Bottleneck**
        - **Symptoms**: High CPU usage (>90%)
        - **Solutions**: Upgrade CPU, optimize code, parallel processing
        
        **2. Memory Bottleneck**
        - **Symptoms**: High memory usage, frequent paging
        - **Solutions**: Add more RAM, optimize memory usage
        
        **3. Storage Bottleneck**
        - **Symptoms**: High disk queue length, slow response
        - **Solutions**: Upgrade to SSD, RAID configuration
        
        **4. Network Bottleneck**
        - **Symptoms**: High network utilization, timeouts
        - **Solutions**: Upgrade network, load balancing
        
        ### 🛠️ Performance Optimization
        
        **System Optimization:**
        - **Process Priority**: Adjust task priorities
        - **Resource Allocation**: CPU affinity, memory limits
        - **Caching**: Implement intelligent caching
        - **Load Balancing**: Distribute workload
        
        **Application Optimization:**
        - **Algorithm Optimization**: Better algorithms
        - **Code Profiling**: Identify bottlenecks
        - **Database Tuning**: Query optimization
        - **Parallel Processing**: Multi-threading
        """)
    
    # Performance monitoring simulation
    st.markdown("#### 📊 System Performance Monitor")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # CPU usage chart
        import numpy as np
        import plotly.graph_objects as go
        
        time_points = list(range(0, 60, 5))
        cpu_usage = np.random.randint(20, 80, len(time_points))
        
        fig1 = go.Figure()
        fig1.add_trace(go.Scatter(
            x=time_points,
            y=cpu_usage,
            mode='lines+markers',
            name='CPU Usage (%)',
            line=dict(color='red', width=2)
        ))
        
        fig1.update_layout(
            title="CPU Usage Over Time",
            xaxis_title="Time (seconds)",
            yaxis_title="Usage (%)",
            height=300
        )
        
        st.plotly_chart(fig1, width='stretch')
    
    with col2:
        # Memory usage chart
        memory_usage = np.random.randint(40, 90, len(time_points))
        
        fig2 = go.Figure()
        fig2.add_trace(go.Scatter(
            x=time_points,
            y=memory_usage,
            mode='lines+markers',
            name='Memory Usage (%)',
            line=dict(color='blue', width=2)
        ))
        
        fig2.update_layout(
            title="Memory Usage Over Time",
            xaxis_title="Time (seconds)",
            yaxis_title="Usage (%)",
            height=300
        )
        
        st.plotly_chart(fig2, width='stretch')

def networking_basics_lab():
    """Lab về networking cơ bản"""
    st.subheader("🌐 Networking Basics Lab")
    
    topic_choice = st.selectbox("Chọn chủ đề:", [
        "Network Models",
        "IP Addressing & Subnetting",
        "Network Devices",
        "Common Protocols",
        "Network Troubleshooting"
    ])
    
    if topic_choice == "Network Models":
        explain_network_models()
    elif topic_choice == "IP Addressing & Subnetting":
        explain_ip_subnetting()
    elif topic_choice == "Network Devices":
        explain_network_devices()
    elif topic_choice == "Common Protocols":
        explain_common_protocols()
    elif topic_choice == "Network Troubleshooting":
        explain_network_troubleshooting()

def explain_network_models():
    """Enhanced Network Models explanation using TDD pattern"""
    st.markdown("### Network Models")
    
    # 1. Visual Banner (IT Fundamentals color scheme)
    st.markdown("""
    <div style="background: linear-gradient(90deg, #56ab2f 0%, #a8e6cf 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            Network Models
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            OSI và TCP/IP - Foundation of Networking
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 2. Visual Diagram (Enhanced layer comparison)
    st.markdown("#### Network Layer Comparison")
    
    fig = go.Figure()
    
    # OSI Model layers (left side)
    osi_layers = ["Application", "Presentation", "Session", "Transport", "Network", "Data Link", "Physical"]
    osi_colors = ['#e74c3c', '#e67e22', '#f39c12', '#f1c40f', '#2ecc71', '#3498db', '#9b59b6']
    
    # TCP/IP Model layers (right side)
    tcpip_layers = ["Application", "", "", "Transport", "Internet", "Network Access", ""]
    tcpip_colors = ['#e74c3c', 'transparent', 'transparent', '#f1c40f', '#2ecc71', '#3498db', 'transparent']
    
    # Create side-by-side layer diagram
    for i, (osi, tcp, osi_color, tcp_color) in enumerate(zip(osi_layers, tcpip_layers, osi_colors, tcpip_colors)):
        y_pos = 6 - i  # Reverse order for proper stacking
        
        # OSI layer (left)
        fig.add_shape(
            type="rect",
            x0=0.1, y0=y_pos-0.4, x1=0.45, y1=y_pos+0.4,
            fillcolor=osi_color,
            opacity=0.8,
            line=dict(color="white", width=2)
        )
        
        fig.add_annotation(
            x=0.275, y=y_pos,
            text=f"<b>Layer {7-i}<br>{osi}</b>",
            showarrow=False,
            font=dict(size=10, color="white"),
        )
        
        # TCP/IP layer (right) - only if not empty
        if tcp and tcp_color != 'transparent':
            fig.add_shape(
                type="rect",
                x0=0.55, y0=y_pos-0.4, x1=0.9, y1=y_pos+0.4,
                fillcolor=tcp_color,
                opacity=0.8,
                line=dict(color="white", width=2)
            )
            
            fig.add_annotation(
                x=0.725, y=y_pos,
                text=f"<b>{tcp}</b>",
                showarrow=False,
                font=dict(size=10, color="white"),
            )
    
    # Add model titles
    fig.add_annotation(x=0.275, y=7.5, text="<b>OSI Model (7 Layers)</b>", showarrow=False, font=dict(size=14, color="#2c3e50"))
    fig.add_annotation(x=0.725, y=7.5, text="<b>TCP/IP Model (4 Layers)</b>", showarrow=False, font=dict(size=14, color="#2c3e50"))
    
    fig.update_layout(
        xaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        yaxis=dict(range=[-0.5, 8], showgrid=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=450,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # 3. Clean Content with expandable details
    with st.expander("Chi tiết về Network Models"):
        st.markdown("""
        ## Network Models Fundamentals
        
        **Definition:** Network models cung cấp framework để hiểu cách data di chuyển qua network, từ application layer đến physical transmission.
        
        ---
        
        ## OSI Model (Open Systems Interconnection)
        
        ### **Layer 7 - Application**
        **Purpose:** Direct user interaction với network services
        **Implementation:** Web browsers, email clients, file transfer applications
        **Benefits:** Standardized application interfaces, protocol independence
        
        ### **Layer 6 - Presentation**  
        **Purpose:** Data formatting, encryption, compression
        **Implementation:** SSL/TLS encryption, JPEG compression, character encoding
        **Benefits:** Data security, efficient transmission, format compatibility
        
        ### **Layer 5 - Session**
        **Purpose:** Session establishment, maintenance, và termination
        **Implementation:** NetBIOS, RPC, SQL sessions, authentication tokens
        **Benefits:** Connection management, synchronization, recovery
        
        ### **Layer 4 - Transport**
        **Purpose:** End-to-end reliable data delivery
        **Implementation:** TCP (reliable), UDP (fast), port addressing
        **Benefits:** Error recovery, flow control, multiplexing
        
        ### **Layer 3 - Network**
        **Purpose:** Routing between different networks
        **Implementation:** IP addressing, routing protocols, path determination
        **Benefits:** Scalable addressing, efficient routing, internetworking
        
        ### **Layer 2 - Data Link**
        **Purpose:** Node-to-node delivery within same network
        **Implementation:** Ethernet, WiFi, MAC addressing, frame checking
        **Benefits:** Error detection, access control, local delivery
        
        ### **Layer 1 - Physical**
        **Purpose:** Bit transmission over physical medium
        **Implementation:** Cables, wireless signals, electrical specifications
        **Benefits:** Hardware standardization, signal integrity
        
        ---
        
        ## TCP/IP Model (Internet Protocol Suite)
        
        **Application Layer:**
        - **Scope:** Combines OSI layers 5, 6, 7
        - **Focus:** Direct application-to-application communication
        - **Protocols:** HTTP, HTTPS, FTP, SMTP, DNS, DHCP
        
        **Transport Layer:**
        - **Scope:** Same as OSI Layer 4
        - **Focus:** End-to-end communication reliability
        - **Protocols:** TCP (connection-oriented), UDP (connectionless)
        
        **Internet Layer:**
        - **Scope:** Same as OSI Layer 3
        - **Focus:** Routing across multiple networks
        - **Protocols:** IP, ICMP, ARP, routing protocols
        
        **Network Access Layer:**
        - **Scope:** Combines OSI layers 1, 2
        - **Focus:** Physical network access và local delivery
        - **Protocols:** Ethernet, WiFi, PPP, hardware-specific protocols
        """)
    
    # 4. Enhanced Cheat Sheets with highlighted keywords
    st.markdown("---")
    st.markdown("## Network Models Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["Layer Functions", "Protocols & Examples", "Troubleshooting Guide"])
    
    with tab1:
        st.markdown("### Layer Functions")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Layer** | **OSI Function** | **TCP/IP Equivalent** | **Key Protocols** | **Primary Purpose** | **Example** |
        |-----------|------------------|-----------------------|-------------------|---------------------|-------------|
        | **Application (7)** | **User interface** và application services | **Application Layer** (combines 5,6,7) | `HTTP`, `HTTPS`, `FTP`, `SMTP` | **Direct user interaction** | **Web browser** requesting webpage |
        | **Transport (4)** | **End-to-end** reliable delivery | **Transport Layer** (identical) | `TCP`, `UDP`, `SCTP` | **Reliable communication** | **TCP connection** for file transfer |
        | **Network (3)** | **Routing** between networks | **Internet Layer** (identical) | `IP`, `ICMP`, `ARP` | **Path determination** | **Router** forwarding packets |
        """)
    
    with tab2:
        st.markdown("### Common Protocols")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Layer Level** | **Common Protocols** | **Port Numbers** | **Use Cases** | **Example** |
        |-----------------|----------------------|------------------|---------------|-------------|
        | **Application (L7)** | `HTTP/HTTPS`, `FTP`, `SMTP/POP3` | **80/443**, 21, **25/110** | **Web browsing**, file transfer, **email** | **Gmail** using HTTPS on port 443 |
        | **Transport (L4)** | `TCP`, `UDP`, `SCTP` | **1-65535** (well-known: 1-1023) | **Reliable delivery**, fast streaming, **connection control** | **TCP connection** for database access |
        | **Network (L3)** | `IPv4/IPv6`, `ICMP`, `ARP` | N/A (uses IP addresses) | **Internet routing**, error reporting, **address resolution** | **Router** forwarding packets to destination |
        """)
    
    with tab3:
        st.markdown("### Quick Reference")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Model** | **Layers** | **Purpose** | **Best For** | **Memory Aid** |
        |-----------|------------|-------------|--------------|----------------|
        | **OSI Model** | **7 layers** (detailed) | **Theoretical** framework | **Understanding** concepts | **Please Do Not Throw Sausage Pizza Away** |
        | **TCP/IP Model** | **4 layers** (practical) | **Real-world** implementation | **Network configuration** | **All Transport Internet Network** |
        """)
    
    # 5. Interactive Demo
    st.markdown("---")
    st.markdown("## Interactive Demo")
    
    with st.expander("Network Model Packet Journey"):
        st.markdown("### Trace Data Through Network Layers")
        
        # Simple interactive element
        scenario = st.selectbox(
            "Choose data transmission scenario:", 
            ["Web Page Request", "Email Sending", "File Transfer"]
        )
        
        if scenario == "Web Page Request":
            st.markdown("**HTTP Request Journey Through Layers:**")
            
            layers_journey = [
                ("**Application Layer**", "User clicks link in browser", "`HTTP GET request` generated"),
                ("**Transport Layer**", "TCP connection established", "`Port 80/443` connection"),
                ("**Network Layer**", "IP packet creation", "`Destination IP` added"),
                ("**Data Link Layer**", "Ethernet frame creation", "`MAC addresses` added"),
                ("**Physical Layer**", "Electrical signals sent", "`Bits transmitted` over cable")
            ]
            
            for i, (layer, action, technical) in enumerate(layers_journey):
                st.markdown(f"**{i+1}.** {layer}: {action} → {technical}")
                
            st.success("✅ **Web request** successfully travels through all network layers!")
            
        elif scenario == "Email Sending":
            st.markdown("**Email Transmission Analysis:**")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**OSI Model Path:**")
                st.markdown("- **L7**: Email client (SMTP)")
                st.markdown("- **L4**: TCP reliable delivery")
                st.markdown("- **L3**: IP routing to mail server")
                st.markdown("- **L2**: Ethernet frame switching")
                st.markdown("- **L1**: Cable signal transmission")
                
            with col2:
                st.markdown("**TCP/IP Model Path:**")
                st.markdown("- **Application**: SMTP protocol")
                st.markdown("- **Transport**: TCP port 25/587")
                st.markdown("- **Internet**: IP packet routing")
                st.markdown("- **Network Access**: Physical delivery")
                
            st.success("✅ **Email** delivered using both model frameworks!")
    
    # 6. Key Takeaways
    st.markdown("---")
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1.5rem; border-radius: 10px; border-left: 5px solid #1f77b4;">
        <h4 style="margin-top: 0; color: #1f77b4;">Key Takeaways</h4>
        <ul>
            <li><strong>Layered Architecture</strong>: Both models use layered approach for modular network design và troubleshooting</li>
            <li><strong>OSI vs TCP/IP</strong>: OSI is theoretical (7 layers), TCP/IP is practical (4 layers) - both essential for understanding</li>
            <li><strong>Protocol Mapping</strong>: Understanding which protocols operate at which layers enables effective network troubleshooting</li>
            <li><strong>Real-world Application</strong>: TCP/IP model directly maps to Internet infrastructure, while OSI provides conceptual framework</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_ip_subnetting():
    """Giải thích IP addressing và subnetting"""
    st.markdown("### 🔢 IP Addressing & Subnetting")
    
    with st.expander("📖 Lý thuyết chi tiết về IP Addressing"):
        st.markdown("""
        ### 🌐 IPv4 Addressing
        
        **IPv4 Format:**
        - **32-bit address**: 4 octets (bytes)
        - **Dotted decimal**: 192.168.1.1
        - **Binary**: 11000000.10101000.00000001.00000001
        
        **Address Classes:**
        
        **Class A (1-126)**
        - **Format**: N.H.H.H (N=Network, H=Host)
        - **Default Mask**: 255.0.0.0 (/8)
        - **Hosts**: 16,777,214 per network
        - **Use**: Large organizations
        
        **Class B (128-191)**
        - **Format**: N.N.H.H
        - **Default Mask**: 255.255.0.0 (/16)
        - **Hosts**: 65,534 per network
        - **Use**: Medium organizations
        
        **Class C (192-223)**
        - **Format**: N.N.N.H
        - **Default Mask**: 255.255.255.0 (/24)
        - **Hosts**: 254 per network
        - **Use**: Small organizations
        
        ### 🔧 Subnetting Concepts
        
        **Why Subnet?**
        - **Efficient IP usage**: Reduce waste
        - **Network segmentation**: Improve security
        - **Broadcast control**: Reduce network traffic
        - **Administrative control**: Easier management
        
        **Subnet Mask:**
        - **Network portion**: 1s in binary
        - **Host portion**: 0s in binary
        - **CIDR notation**: /24 = 255.255.255.0
        
        **Subnetting Example:**
        ```
        Network: 192.168.1.0/24
        Requirement: 4 subnets, 50 hosts each
        
        Solution:
        - Borrow 2 bits for subnets (2² = 4 subnets)
        - Leave 6 bits for hosts (2⁶ - 2 = 62 hosts)
        - New mask: /26 (255.255.255.192)
        
        Subnets:
        1. 192.168.1.0/26 (192.168.1.1-62)
        2. 192.168.1.64/26 (192.168.1.65-126)
        3. 192.168.1.128/26 (192.168.1.129-190)
        4. 192.168.1.192/26 (192.168.1.193-254)
        ```
        
        ### 🌍 IPv6 Addressing
        
        **IPv6 Format:**
        - **128-bit address**: 8 groups of 4 hex digits
        - **Example**: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        - **Compressed**: 2001:db8:85a3::8a2e:370:7334
        
        **Address Types:**
        - **Unicast**: One-to-one communication
        - **Multicast**: One-to-many communication
        - **Anycast**: One-to-nearest communication
        """)
    
    # IP Calculator
    st.markdown("#### 🧮 IP Subnet Calculator")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        ip_address = st.text_input("IP Address:", value="192.168.1.0")
        subnet_mask = st.selectbox("Subnet Mask:", ["/24", "/25", "/26", "/27", "/28"])
        
        if st.button("🔍 Calculate Subnets"):
            subnet_info = calculate_subnet_info(ip_address, subnet_mask)
            st.session_state['subnet_info'] = subnet_info
    
    with col2:
        if 'subnet_info' in st.session_state:
            info = st.session_state['subnet_info']
            
            st.markdown("**📊 Subnet Information:**")
            st.info(f"""
            **Network Address:** {info['network']}
            **Broadcast Address:** {info['broadcast']}
            **Subnet Mask:** {info['mask']}
            **Total Hosts:** {info['total_hosts']}
            **Usable Hosts:** {info['usable_hosts']}
            **First Host:** {info['first_host']}
            **Last Host:** {info['last_host']}
            """)

def explain_network_devices():
    """Giải thích các thiết bị mạng"""
    st.markdown("### 🔌 Network Devices")
    
    with st.expander("📖 Lý thuyết chi tiết về Network Devices"):
        st.markdown("""
        ### 🌐 Network Infrastructure Devices
        
        **1. Hub (Repeater)**
        - **Function**: Repeats signals to all connected devices
        - **Layer**: Physical Layer (Layer 1)
        - **Collision Domain**: Single collision domain for all ports
        - **Broadcast Domain**: Single broadcast domain
        - **Status**: Legacy device, rarely used today
        - **Disadvantages**: Half-duplex, collisions, security issues
        
        **2. Switch**
        - **Function**: Forwards frames based on MAC addresses
        - **Layer**: Data Link Layer (Layer 2)
        - **Collision Domain**: Separate collision domain per port
        - **Broadcast Domain**: Single broadcast domain (unless VLANs)
        - **Features**: Full-duplex, MAC address table, VLAN support
        - **Types**: Unmanaged, managed, Layer 3 switches
        
        **3. Router**
        - **Function**: Routes packets between different networks
        - **Layer**: Network Layer (Layer 3)
        - **Collision Domain**: Separate per interface
        - **Broadcast Domain**: Separate per interface
        - **Features**: Routing tables, NAT, DHCP, firewall
        - **Types**: Home routers, enterprise routers, core routers
        
        **4. Access Point (AP)**
        - **Function**: Provides wireless network access
        - **Layer**: Data Link Layer (Layer 2)
        - **Features**: WiFi standards (802.11), security (WPA/WPA2/WPA3)
        - **Types**: Standalone, controller-based, mesh
        - **Deployment**: Indoor, outdoor, high-density
        
        **5. Firewall**
        - **Function**: Controls network traffic based on security rules
        - **Layer**: Network Layer (Layer 3) and above
        - **Types**: Packet filtering, stateful, application layer
        - **Features**: Access control, logging, VPN support
        - **Deployment**: Network perimeter, internal segmentation
        
        **6. Load Balancer**
        - **Function**: Distributes network traffic across multiple servers
        - **Layer**: Application Layer (Layer 7) or Transport (Layer 4)
        - **Types**: Hardware, software, cloud-based
        - **Algorithms**: Round-robin, least connections, weighted
        - **Features**: Health checks, SSL termination, caching
        
        ### 🔧 Network Device Comparison
        
        **Performance Characteristics:**
        
        **Hub:**
        - **Bandwidth**: Shared among all ports
        - **Duplex**: Half-duplex only
        - **Collision**: Yes, CSMA/CD required
        - **Security**: Low (all traffic visible to all ports)
        
        **Switch:**
        - **Bandwidth**: Dedicated per port
        - **Duplex**: Full-duplex capable
        - **Collision**: None (switched environment)
        - **Security**: Medium (MAC-based forwarding)
        
        **Router:**
        - **Bandwidth**: Varies by interface type
        - **Duplex**: Full-duplex
        - **Collision**: None
        - **Security**: High (Layer 3 filtering, NAT)
        
        ### 📊 Device Selection Criteria
        
        **Network Size:**
        - **Small (< 50 devices)**: Unmanaged switch + router
        - **Medium (50-500 devices)**: Managed switches + enterprise router
        - **Large (500+ devices)**: Layer 3 switches + core routers
        
        **Performance Requirements:**
        - **Basic**: 100 Mbps switches
        - **Standard**: 1 Gbps switches
        - **High-performance**: 10 Gbps+ switches
        
        **Features Needed:**
        - **VLAN Support**: Managed switches
        - **QoS**: Managed switches/routers
        - **Security**: Firewalls, managed devices
        - **Redundancy**: Stackable switches, redundant routers
        
        ### 🏢 Enterprise Network Architecture
        
        **Three-Tier Design:**
        
        **Core Layer:**
        - **Devices**: High-speed routers/switches
        - **Function**: Fast packet switching
        - **Characteristics**: High bandwidth, low latency
        
        **Distribution Layer:**
        - **Devices**: Layer 3 switches
        - **Function**: Policy enforcement, routing
        - **Characteristics**: Access control, QoS, VLAN routing
        
        **Access Layer:**
        - **Devices**: Access switches, wireless APs
        - **Function**: End-device connectivity
        - **Characteristics**: Port density, PoE, basic security
        """)
    
    # Device comparison table
    st.markdown("#### 📊 Network Device Comparison")
    
    device_data = [
        {"Device": "Hub", "Layer": "1", "Collision Domains": "1", "Broadcast Domains": "1", "Duplex": "Half", "Status": "Legacy"},
        {"Device": "Switch", "Layer": "2", "Collision Domains": "Per Port", "Broadcast Domains": "1", "Duplex": "Full", "Status": "Current"},
        {"Device": "Router", "Layer": "3", "Collision Domains": "Per Interface", "Broadcast Domains": "Per Interface", "Duplex": "Full", "Status": "Current"},
        {"Device": "Access Point", "Layer": "2", "Collision Domains": "Wireless", "Broadcast Domains": "1", "Duplex": "Half/Full", "Status": "Current"},
        {"Device": "Firewall", "Layer": "3-7", "Collision Domains": "Per Interface", "Broadcast Domains": "Per Interface", "Duplex": "Full", "Status": "Current"}
    ]
    
    df = pd.DataFrame(device_data)
    st.dataframe(df, width='stretch')

def explain_common_protocols():
    """Giải thích Common Network Protocols"""
    st.markdown("### 📡 Common Network Protocols")
    
    with st.expander("📖 Lý thuyết chi tiết về Network Protocols"):
        st.markdown("""
        ### 🌐 Application Layer Protocols (Layer 7)
        
        **HTTP/HTTPS (HyperText Transfer Protocol)**
        - **Purpose**: Web page transfer
        - **Port**: 80 (HTTP), 443 (HTTPS)
        - **Features**: Stateless, request-response model
        - **Security**: HTTPS uses TLS/SSL encryption
        - **Methods**: GET, POST, PUT, DELETE, HEAD, OPTIONS
        
        **FTP/SFTP (File Transfer Protocol)**
        - **Purpose**: File transfer between systems
        - **Port**: 21 (FTP), 22 (SFTP)
        - **Features**: Separate control and data connections
        - **Security**: SFTP uses SSH encryption
        - **Modes**: Active mode, Passive mode
        
        **SMTP (Simple Mail Transfer Protocol)**
        - **Purpose**: Email transmission
        - **Port**: 25, 587 (submission), 465 (secure)
        - **Features**: Store-and-forward mechanism
        - **Security**: STARTTLS, SMTP AUTH
        - **Related**: POP3 (110), IMAP (143, 993)
        
        **DNS (Domain Name System)**
        - **Purpose**: Domain name to IP address resolution
        - **Port**: 53 (UDP/TCP)
        - **Features**: Hierarchical, distributed database
        - **Record Types**: A, AAAA, CNAME, MX, NS, PTR, TXT
        - **Security**: DNSSEC for integrity
        
        **DHCP (Dynamic Host Configuration Protocol)**
        - **Purpose**: Automatic IP address assignment
        - **Port**: 67 (server), 68 (client)
        - **Process**: DORA (Discover, Offer, Request, Acknowledge)
        - **Options**: IP address, subnet mask, gateway, DNS
        - **Lease**: Time-limited IP assignments
        
        **SNMP (Simple Network Management Protocol)**
        - **Purpose**: Network device management
        - **Port**: 161 (agent), 162 (manager)
        - **Versions**: v1, v2c, v3 (secure)
        - **Operations**: GET, SET, TRAP, WALK
        - **MIB**: Management Information Base
        
        ### 🚀 Transport Layer Protocols (Layer 4)
        
        **TCP (Transmission Control Protocol)**
        - **Type**: Connection-oriented, reliable
        - **Features**: Flow control, error correction, ordering
        - **Handshake**: 3-way handshake (SYN, SYN-ACK, ACK)
        - **Termination**: 4-way handshake (FIN, ACK, FIN, ACK)
        - **Use Cases**: Web browsing, email, file transfer
        
        **UDP (User Datagram Protocol)**
        - **Type**: Connectionless, unreliable
        - **Features**: Fast, low overhead, no guarantees
        - **Header**: Simple 8-byte header
        - **Use Cases**: DNS, DHCP, streaming, gaming
        - **Benefits**: Speed, broadcast/multicast support
        
        ### 🌍 Network Layer Protocols (Layer 3)
        
        **IP (Internet Protocol)**
        - **Versions**: IPv4 (32-bit), IPv6 (128-bit)
        - **Features**: Routing, fragmentation, addressing
        - **IPv4 Header**: 20-60 bytes, TTL, checksum
        - **IPv6 Header**: 40 bytes, flow label, hop limit
        - **Addressing**: Unicast, multicast, broadcast (IPv4)
        
        **ICMP (Internet Control Message Protocol)**
        - **Purpose**: Error reporting and diagnostics
        - **Messages**: Echo (ping), Destination Unreachable
        - **Tools**: ping, traceroute, pathping
        - **Types**: Error messages, informational messages
        - **Security**: Can be used for reconnaissance
        
        **ARP (Address Resolution Protocol)**
        - **Purpose**: MAC address resolution
        - **Process**: Broadcast request, unicast reply
        - **Cache**: Temporary storage of MAC-IP mappings
        - **Security Issues**: ARP spoofing attacks
        - **IPv6 Equivalent**: Neighbor Discovery Protocol
        
        ### 🔒 Security Protocols
        
        **SSL/TLS (Secure Sockets Layer/Transport Layer Security)**
        - **Purpose**: Secure communication channel
        - **Versions**: TLS 1.2, TLS 1.3 (current)
        - **Features**: Authentication, encryption, integrity
        - **Handshake**: Certificate exchange, key agreement
        - **Applications**: HTTPS, FTPS, SMTPS
        
        **SSH (Secure Shell)**
        - **Purpose**: Secure remote access
        - **Port**: 22
        - **Features**: Authentication, encryption, tunneling
        - **Key Types**: RSA, DSA, ECDSA, Ed25519
        - **Applications**: Remote login, file transfer, tunneling
        
        **IPSec (Internet Protocol Security)**
        - **Purpose**: IP packet security
        - **Modes**: Transport mode, Tunnel mode
        - **Protocols**: AH (Authentication Header), ESP (Encapsulating Security Payload)
        - **Applications**: VPNs, site-to-site connections
        - **Key Management**: IKE (Internet Key Exchange)
        
        ### 📊 Protocol Comparison
        
        **Reliability vs Speed:**
        - **TCP**: Reliable but slower (connection overhead)
        - **UDP**: Fast but unreliable (no guarantees)
        - **Choice depends on application requirements**
        
        **Security Considerations:**
        - **Plaintext Protocols**: HTTP, FTP, Telnet (avoid)
        - **Secure Alternatives**: HTTPS, SFTP, SSH
        - **Encryption**: Always use when possible
        
        **Port Management:**
        - **Well-known Ports**: 0-1023 (system services)
        - **Registered Ports**: 1024-49151 (applications)
        - **Dynamic Ports**: 49152-65535 (client connections)
        
        ### 🛠️ Protocol Analysis Tools
        
        **Network Analyzers:**
        - **Wireshark**: Comprehensive packet analysis
        - **tcpdump**: Command-line packet capture
        - **Nmap**: Network discovery and port scanning
        - **Netstat**: Network connection status
        
        **Monitoring Tools:**
        - **SNMP Managers**: Network device monitoring
        - **Flow Analyzers**: Traffic pattern analysis
        - **Protocol Analyzers**: Deep packet inspection
        - **Performance Monitors**: Latency and throughput
        """)
    
    # Protocol comparison table
    st.markdown("#### 📊 Common Protocol Comparison")
    
    protocol_data = [
        {"Protocol": "HTTP", "Layer": "7", "Port": "80", "Transport": "TCP", "Security": "None", "Use Case": "Web browsing"},
        {"Protocol": "HTTPS", "Layer": "7", "Port": "443", "Transport": "TCP", "Security": "TLS", "Use Case": "Secure web"},
        {"Protocol": "FTP", "Layer": "7", "Port": "21", "Transport": "TCP", "Security": "None", "Use Case": "File transfer"},
        {"Protocol": "SSH", "Layer": "7", "Port": "22", "Transport": "TCP", "Security": "Encrypted", "Use Case": "Remote access"},
        {"Protocol": "DNS", "Layer": "7", "Port": "53", "Transport": "UDP/TCP", "Security": "Optional", "Use Case": "Name resolution"},
        {"Protocol": "DHCP", "Layer": "7", "Port": "67/68", "Transport": "UDP", "Security": "None", "Use Case": "IP assignment"},
        {"Protocol": "SMTP", "Layer": "7", "Port": "25/587", "Transport": "TCP", "Security": "Optional", "Use Case": "Email sending"},
        {"Protocol": "SNMP", "Layer": "7", "Port": "161/162", "Transport": "UDP", "Security": "v3 only", "Use Case": "Network mgmt"}
    ]
    
    df = pd.DataFrame(protocol_data)
    st.dataframe(df, width='stretch')

def explain_network_troubleshooting():
    """Giải thích network troubleshooting"""
    st.markdown("### 🔍 Network Troubleshooting")
    
    with st.expander("📖 Lý thuyết chi tiết về Network Troubleshooting"):
        st.markdown("""
        ### 🎯 Network Troubleshooting Methodology
        
        **1. Problem Identification**
        - **Gather Information**: What, when, where, who, how
        - **Define Scope**: Single user, department, or entire network
        - **Document Symptoms**: Error messages, performance issues
        - **Establish Timeline**: When did the problem start?
        
        **2. Theory of Probable Cause**
        - **Layer-by-layer Analysis**: Start with Physical Layer
        - **Common Issues First**: Check obvious problems
        - **Recent Changes**: What changed recently?
        - **Environmental Factors**: Power, temperature, interference
        
        **3. Test the Theory**
        - **Hypothesis Testing**: Test one variable at a time
        - **Use Tools**: Network analyzers, cable testers
        - **Isolate Variables**: Remove complexity
        - **Document Results**: Keep track of what works/doesn't work
        
        **4. Establish Plan of Action**
        - **Prioritize Solutions**: Impact vs. effort matrix
        - **Consider Downtime**: Maintenance windows
        - **Backup Plans**: Rollback procedures
        - **Resource Requirements**: Tools, personnel, time
        
        **5. Implement Solution**
        - **Follow Change Management**: Proper procedures
        - **Monitor Progress**: Real-time monitoring
        - **Document Changes**: What was changed and when
        - **Test Functionality**: Verify solution works
        
        **6. Verify Resolution**
        - **End-to-End Testing**: Complete functionality check
        - **User Acceptance**: Confirm users can work normally
        - **Performance Monitoring**: Ensure no degradation
        - **Documentation Update**: Update network diagrams
        
        ### 🔧 Essential Troubleshooting Tools
        
        **Command Line Tools:**
        
        **ping**
        - **Purpose**: Test basic connectivity
        - **Usage**: `ping 8.8.8.8`
        - **Information**: RTT, packet loss, reachability
        
        **traceroute/tracert**
        - **Purpose**: Trace packet path
        - **Usage**: `traceroute google.com`
        - **Information**: Hop-by-hop routing path
        
        **nslookup/dig**
        - **Purpose**: DNS troubleshooting
        - **Usage**: `nslookup google.com`
        - **Information**: DNS resolution, record types
        
        **netstat**
        - **Purpose**: Network connections and statistics
        - **Usage**: `netstat -an`
        - **Information**: Open ports, connections, routing table
        
        **arp**
        - **Purpose**: ARP table management
        - **Usage**: `arp -a`
        - **Information**: MAC to IP mappings
        
        **ipconfig/ifconfig**
        - **Purpose**: Network interface configuration
        - **Usage**: `ipconfig /all`
        - **Information**: IP settings, DHCP info, DNS servers
        
        **Hardware Tools:**
        
        **Cable Tester**
        - **Purpose**: Test cable integrity
        - **Features**: Continuity, wire mapping, length
        - **Types**: Basic, advanced with TDR
        
        **Network Analyzer**
        - **Purpose**: Packet capture and analysis
        - **Software**: Wireshark, tcpdump
        - **Hardware**: Dedicated analyzers
        
        **Multimeter**
        - **Purpose**: Electrical measurements
        - **Uses**: Power, voltage, continuity
        - **Safety**: Proper electrical safety procedures
        
        ### 🚨 Common Network Problems
        
        **Physical Layer Issues:**
        
        **Cable Problems**
        - **Symptoms**: Intermittent connectivity, slow speeds
        - **Causes**: Damaged cables, loose connections, wrong cable type
        - **Solutions**: Cable testing, replacement, proper termination
        
        **Power Issues**
        - **Symptoms**: Devices not powering on, random reboots
        - **Causes**: Power supply failure, insufficient PoE
        - **Solutions**: Check power sources, UPS, PoE budget
        
        **Environmental Issues**
        - **Symptoms**: Intermittent problems, device overheating
        - **Causes**: Temperature, humidity, electromagnetic interference
        - **Solutions**: Climate control, proper ventilation, shielding
        
        **Data Link Layer Issues:**
        
        **Switch Problems**
        - **Symptoms**: Port not working, VLAN issues
        - **Causes**: Port configuration, spanning tree, duplex mismatch
        - **Solutions**: Port reset, configuration check, STP analysis
        
        **MAC Address Issues**
        - **Symptoms**: Devices can't communicate
        - **Causes**: MAC address conflicts, table overflow
        - **Solutions**: Clear MAC tables, check for duplicates
        
        **Network Layer Issues:**
        
        **IP Configuration**
        - **Symptoms**: Can't reach other networks
        - **Causes**: Wrong IP, subnet mask, gateway
        - **Solutions**: Check IP configuration, DHCP settings
        
        **Routing Problems**
        - **Symptoms**: Some networks unreachable
        - **Causes**: Missing routes, routing loops, metric issues
        - **Solutions**: Check routing tables, add static routes
        
        **DNS Issues**
        - **Symptoms**: Can ping IP but not domain names
        - **Causes**: DNS server down, wrong DNS settings
        - **Solutions**: Check DNS configuration, test DNS servers
        
        ### 📊 Troubleshooting Best Practices
        
        **Documentation:**
        - **Network Diagrams**: Keep current topology maps
        - **Configuration Backups**: Regular device backups
        - **Change Logs**: Track all modifications
        - **Problem History**: Learn from past issues
        
        **Monitoring:**
        - **Baseline Performance**: Know normal behavior
        - **Proactive Monitoring**: Detect issues early
        - **Alerting**: Automated problem notification
        - **Trending**: Identify patterns and growth
        
        **Prevention:**
        - **Regular Maintenance**: Scheduled updates and checks
        - **Redundancy**: Eliminate single points of failure
        - **Security**: Protect against attacks
        - **Training**: Keep skills current
        """)
    
    # Troubleshooting flowchart simulation
    st.markdown("#### 🔄 Troubleshooting Flowchart")
    
    troubleshooting_steps = [
        {"Step": "1. Identify Problem", "Action": "Gather information, define scope", "Tools": "User interviews, logs"},
        {"Step": "2. Physical Layer", "Action": "Check cables, power, LEDs", "Tools": "Cable tester, multimeter"},
        {"Step": "3. Data Link Layer", "Action": "Check switch ports, VLANs", "Tools": "Switch console, port status"},
        {"Step": "4. Network Layer", "Action": "Check IP config, routing", "Tools": "ping, traceroute, ipconfig"},
        {"Step": "5. Transport Layer", "Action": "Check port connectivity", "Tools": "telnet, netstat"},
        {"Step": "6. Application Layer", "Action": "Check services, DNS", "Tools": "nslookup, service status"}
    ]
    
    df = pd.DataFrame(troubleshooting_steps)
    st.dataframe(df, width='stretch')

def operating_systems_lab():
    """Lab về hệ điều hành"""
    st.subheader("💾 Operating Systems Lab")
    
    topic_choice = st.selectbox("Chọn chủ đề:", [
        "OS Fundamentals",
        "Process Management",
        "Memory Management",
        "File Systems",
        "OS Comparison"
    ])
    
    if topic_choice == "OS Fundamentals":
        explain_os_fundamentals()
    elif topic_choice == "Process Management":
        explain_process_management()
    elif topic_choice == "Memory Management":
        explain_memory_management()
    elif topic_choice == "File Systems":
        explain_file_systems()
    elif topic_choice == "OS Comparison":
        explain_os_comparison()

def explain_os_fundamentals():
    """Enhanced Operating System Fundamentals explanation using TDD pattern"""
    st.markdown("### Operating System Fundamentals")
    
    # 1. Visual Banner (IT Fundamentals color scheme)
    st.markdown("""
    <div style="background: linear-gradient(90deg, #56ab2f 0%, #a8e6cf 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            Operating System Fundamentals
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Foundation of Modern Computing Systems
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 2. Visual Diagram (Enhanced OS architecture diagram)
    st.markdown("#### Operating System Architecture")
    
    fig = go.Figure()
    
    # Create layered OS architecture diagram
    layers = [
        {"name": "Applications", "y": 0.8, "color": "#e74c3c", "examples": "Web Browser, Office, Games"},
        {"name": "System Libraries", "y": 0.65, "color": "#f39c12", "examples": "glibc, DirectX, .NET"},
        {"name": "System Calls", "y": 0.5, "color": "#f1c40f", "examples": "open(), read(), write()"},
        {"name": "Operating System Kernel", "y": 0.35, "color": "#2ecc71", "examples": "Process, Memory, I/O Management"},
        {"name": "Device Drivers", "y": 0.2, "color": "#3498db", "examples": "Graphics, Network, Storage"},
        {"name": "Hardware", "y": 0.05, "color": "#9b59b6", "examples": "CPU, RAM, Disk, Network"}
    ]
    
    # Draw layers
    for layer in layers:
        # Layer rectangle
        fig.add_shape(
            type="rect",
            x0=0.1, y0=layer["y"]-0.06, x1=0.9, y1=layer["y"]+0.06,
            fillcolor=layer["color"],
            opacity=0.8,
            line=dict(color="white", width=2)
        )
        
        # Layer name
        fig.add_annotation(
            x=0.25, y=layer["y"],
            text=f"<b>{layer['name']}</b>",
            showarrow=False,
            font=dict(size=12, color="white"),
            xanchor="center"
        )
        
        # Examples
        fig.add_annotation(
            x=0.65, y=layer["y"],
            text=layer["examples"],
            showarrow=False,
            font=dict(size=10, color="white"),
            xanchor="center"
        )
    
    # Add arrows showing interaction
    for i in range(len(layers)-1):
        y_start = layers[i]["y"] - 0.06
        y_end = layers[i+1]["y"] + 0.06
        
        fig.add_annotation(
            x=0.05, y=(y_start + y_end) / 2,
            ax=0.05, ay=y_start,
            arrowhead=2, arrowsize=1, arrowwidth=2, arrowcolor="#34495e",
            showarrow=True, text=""
        )
    
    fig.update_layout(
        xaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=450,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # 3. Clean Content with expandable details
    with st.expander("Chi tiết về Operating System Fundamentals"):
        st.markdown("""
        ## Operating System Fundamentals
        
        **Definition:** Operating System (OS) là software layer quan trọng nhất giữa hardware và applications, quản lý tất cả tài nguyên hệ thống và cung cấp services cho user programs.
        
        ---
        
        ## Core Functions
        
        ### **Resource Management**
        **Purpose:** Quản lý và phân bổ tài nguyên hệ thống một cách hiệu quả
        **Implementation:** CPU scheduling algorithms, memory allocation, I/O device management
        **Benefits:** Optimal performance, resource utilization, system stability
        
        ### **Process Management**  
        **Purpose:** Quản lý lifecycle của processes và threads trong hệ thống
        **Implementation:** Process creation, scheduling, synchronization, inter-process communication
        **Benefits:** Multitasking capability, system responsiveness, process isolation
        
        ### **Memory Management**
        **Purpose:** Quản lý physical và virtual memory space
        **Implementation:** Virtual memory, paging, segmentation, memory protection
        **Benefits:** Memory protection, efficient memory usage, program isolation
        
        ### **File System Management**
        **Purpose:** Tổ chức và quản lý data storage trên persistent devices
        **Implementation:** File allocation, directory structures, access control, metadata management
        **Benefits:** Data organization, persistence, security, efficient access
        
        ### **I/O System Management**
        **Purpose:** Quản lý communication giữa system và external devices
        **Implementation:** Device drivers, interrupt handling, buffering, spooling
        **Benefits:** Hardware abstraction, device independence, efficient I/O operations
        
        ### **Security & Protection**
        **Purpose:** Bảo vệ system resources và user data khỏi unauthorized access
        **Implementation:** User authentication, access control lists, privilege levels, audit logging
        **Benefits:** System security, data protection, user privacy, compliance
        
        ---
        
        ## Modern OS Architecture Types
        
        **Monolithic Kernel:**
        - **Structure:** All OS services execute in kernel space với full hardware access
        - **Advantages:** High performance, efficient communication, direct hardware access
        - **Disadvantages:** Large codebase, complex debugging, kernel crashes affect entire system
        - **Examples:** Linux kernel, traditional Unix systems
        - **Use Cases:** High-performance servers, embedded systems
        
        **Microkernel Architecture:**
        - **Structure:** Minimal kernel với most services running in user space
        - **Advantages:** Better stability, security, modularity, easier maintenance
        - **Disadvantages:** Performance overhead from message passing, complex implementation
        - **Examples:** QNX, Minix, L4 family
        - **Use Cases:** Real-time systems, safety-critical applications
        
        **Hybrid Kernel:**
        - **Structure:** Combines monolithic và microkernel approaches
        - **Advantages:** Balance between performance và modularity
        - **Examples:** Windows NT family, macOS (XNU kernel), ReactOS
        - **Use Cases:** Desktop systems, general-purpose computing
        
        **Exokernel:**
        - **Structure:** Minimal abstraction, applications manage resources directly
        - **Advantages:** Maximum performance, application-specific optimizations
        - **Examples:** Research systems like MIT Exokernel
        - **Use Cases:** High-performance computing, specialized applications
        
        ---
        
        ## Modern Boot Process (UEFI Era)
        
        **Power-On Self Test (POST):**
        - **Process:** Hardware initialization và basic functionality testing
        - **Components:** CPU, RAM, motherboard components, expansion cards
        - **Duration:** 1-30 seconds depending on system complexity
        - **Output:** Beep codes, LED indicators, display messages
        
        **UEFI Firmware:**
        - **Features:** Replaces legacy BIOS với modern capabilities
        - **Advantages:** Faster boot, larger disk support (>2TB), secure boot, GUI interface
        - **Security:** Secure Boot prevents malware loading, TPM integration
        - **Standards:** UEFI 2.x specification, GPT partition support
        
        **Boot Manager:**
        - **GRUB 2:** Advanced bootloader với scripting, network boot, encryption support
        - **Windows Boot Manager:** Integrated với Windows Recovery Environment
        - **systemd-boot:** Lightweight UEFI boot manager for Linux
        - **rEFInd:** Graphical boot manager với automatic OS detection
        
        **Kernel Initialization:**
        - **Phase 1:** Hardware detection, driver loading, memory management setup
        - **Phase 2:** Process scheduler initialization, system call table setup
        - **Phase 3:** File system mounting, device initialization
        - **Phase 4:** User space transition, init system startup
        
        **Init System (Modern):**
        - **systemd:** Modern init system với parallel startup, service management
        - **OpenRC:** Lightweight alternative với dependency-based startup
        - **runit:** Simple, reliable init scheme với service supervision
        - **Features:** Service dependencies, socket activation, resource control
        """)
    
    # 4. Enhanced Cheat Sheets with highlighted keywords
    st.markdown("---")
    st.markdown("## Operating System Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["Core Components", "OS Types Comparison", "Modern Features"])
    
    with tab1:
        st.markdown("### Core Components")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Component** | **Primary Function** | **Key Responsibilities** | **Modern Implementation** | **Performance Impact** | **Example** |
        |---------------|---------------------|--------------------------|---------------------------|------------------------|-------------|
        | **Kernel** | **Core OS functions** execution | Process scheduling, **memory management**, system calls | **Monolithic/Micro/Hybrid** designs | **Critical** - affects all operations | **Linux kernel**, Windows NT kernel |
        | **Process Manager** | **Process lifecycle** management | Creation, scheduling, **termination**, IPC | **CFS scheduler**, Windows scheduler | **High** - determines responsiveness | **systemd**, Task Manager |
        | **Memory Manager** | **RAM allocation** và protection | Virtual memory, **paging**, protection, swapping | **MMU integration**, ASLR, DEP | **Critical** - affects performance | **Virtual memory** systems |
        | **File System** | **Data storage** organization | File allocation, **directory management**, permissions | **ext4**, **NTFS**, **APFS**, **ZFS** | **Medium** - I/O dependent | File explorers, **mount points** |
        | **I/O Subsystem** | **Device communication** management | Driver management, **interrupt handling**, buffering | **Plug-and-play**, hot swapping | **Variable** - device dependent | **Device Manager**, `/dev` filesystem |
        | **Security Module** | **Access control** và protection | Authentication, **authorization**, auditing, encryption | **SELinux**, Windows Defender, **TPM** | **Low-Medium** - security overhead | User login, **file permissions** |
        """)
        
        # Additional highlighted information
        st.markdown("""
        #### **Key Terminology**
        - **Kernel Space**: `privileged_mode` - Protected memory area where OS kernel executes
        - **User Space**: `unprivileged_mode` - Memory area where user applications execute safely  
        - **System Call**: `kernel_interface` - Mechanism for user programs to request OS services
        """)
    
    with tab2:
        st.markdown("### Operating System Types Comparison")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **OS Type** | **Architecture** | **Performance** | **Stability** | **Security** | **Use Cases** | **Examples** |
        |-------------|------------------|-----------------|---------------|--------------|---------------|--------------|
        | **Desktop OS** | **Hybrid/Monolithic** | **High** for single-user | **Good** với regular updates | **Medium-High** với built-in security | Personal computing, **office work** | **Windows 11**, **macOS Ventura**, **Ubuntu** |
        | **Server OS** | **Monolithic/Micro** | **Very High** for multi-user | **Excellent** với enterprise features | **Very High** với advanced security | **Data centers**, web hosting, **enterprise** | **Linux Server**, **Windows Server**, **FreeBSD** |
        | **Mobile OS** | **Hybrid** với power optimization | **Optimized** for battery life | **Good** với app sandboxing | **High** với app permissions | **Smartphones**, tablets, **IoT devices** | **Android**, **iOS**, **HarmonyOS** |
        | **Real-time OS** | **Microkernel** preferred | **Deterministic** timing | **Critical** - no failures allowed | **High** for safety systems | **Embedded systems**, industrial control | **QNX**, **VxWorks**, **FreeRTOS** |
        | **Embedded OS** | **Minimal** footprint | **Efficient** resource usage | **Reliable** for specific tasks | **Variable** based on requirements | **IoT**, automotive, **appliances** | **Embedded Linux**, **ThreadX**, **Zephyr** |
        """)
    
    with tab3:
        st.markdown("### Modern OS Features")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Feature Category** | **Technology** | **Purpose** | **Implementation** | **Benefits** | **Adoption** |
        |---------------------|----------------|-------------|-------------------|--------------|--------------|
        | **Virtualization** | **Hypervisors**, containers | **Resource isolation** và efficiency | `VMware`, `Hyper-V`, `Docker`, `LXC` | **Scalability**, cost reduction | **Widespread** in enterprise |
        | **Security** | **Secure Boot**, TPM, **sandboxing** | **System integrity** protection | UEFI Secure Boot, **Windows Defender**, SELinux | **Malware protection**, data security | **Standard** in modern systems |
        | **Performance** | **SSD optimization**, **multi-core** scheduling | **System responsiveness** | TRIM support, **NUMA awareness**, CPU affinity | **Faster boot**, better multitasking | **Universal** adoption |
        | **Cloud Integration** | **Hybrid cloud**, sync services | **Data accessibility** anywhere | OneDrive, **iCloud**, Google Drive integration | **Seamless experience**, backup | **Growing** rapidly |
        | **AI/ML Integration** | **Neural processing**, **smart features** | **Intelligent assistance** | Windows ML, **Core ML**, TensorFlow Lite | **Personalization**, automation | **Emerging** trend |
        | **Power Management** | **Dynamic scaling**, **sleep states** | **Energy efficiency** | CPU governors, **ACPI**, mobile-first design | **Battery life**, reduced heat | **Critical** for mobile |
        """)
    
    # 5. Interactive Demo
    st.markdown("---")
    st.markdown("## Interactive Demo")
    
    with st.expander("Operating System Scenarios"):
        st.markdown("### OS Selection for Different Use Cases")
        
        # Simple interactive element
        use_case = st.selectbox(
            "Choose a use case scenario:", 
            ["Personal Desktop", "Enterprise Server", "Mobile Device", "IoT/Embedded System", "Gaming System"]
        )
        
        if use_case == "Personal Desktop":
            st.markdown("**💻 Personal Desktop OS Requirements:**")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Primary Requirements:**")
                st.markdown("- **User-friendly interface** for daily tasks")
                st.markdown("- **Software compatibility** với popular applications")
                st.markdown("- **Multimedia support** for entertainment")
                st.markdown("- **Security features** for personal data protection")
                
            with col2:
                st.markdown("**Recommended Options:**")
                st.markdown("- **Windows 11**: Best software compatibility, gaming support")
                st.markdown("- **macOS**: Excellent for creative work, Unix-based")
                st.markdown("- **Ubuntu/Pop!_OS**: Free, secure, customizable Linux")
                st.markdown("- **Chrome OS**: Simple, cloud-focused, budget-friendly")
                
            st.success("✅ **Personal desktop** prioritizes **usability** và **application compatibility**!")
            
        elif use_case == "Enterprise Server":
            st.markdown("**🖥️ Enterprise Server OS Analysis:**")
            
            server_requirements = [
                "**Stability**: 99.9%+ uptime requirements",
                "**Security**: Advanced access control và audit logging", 
                "**Scalability**: Handle thousands of concurrent users",
                "**Management**: Remote administration và monitoring tools",
                "**Support**: Enterprise-grade technical support",
                "**Compliance**: Meet regulatory requirements (SOX, HIPAA, etc.)"
            ]
            
            for req in server_requirements:
                st.markdown(f"- {req}")
                
            st.markdown("**Top Enterprise Choices:**")
            st.markdown("- **Red Hat Enterprise Linux**: Industry standard, comprehensive support")
            st.markdown("- **Windows Server**: Active Directory integration, Microsoft ecosystem")
            st.markdown("- **Ubuntu Server**: Cost-effective, strong community support")
            st.markdown("- **SUSE Linux**: European preference, enterprise features")
            
            st.success("✅ **Enterprise servers** require **maximum reliability** và **professional support**!")
            
        elif use_case == "Mobile Device":
            st.markdown("**📱 Mobile OS Characteristics:**")
            
            st.code("""
# Mobile OS Key Features
Power Management:
  - Aggressive CPU scaling
  - App background limits  
  - Battery optimization

Security Model:
  - App sandboxing
  - Permission-based access
  - Secure boot chain
  - Hardware-backed encryption

User Experience:
  - Touch-optimized interface
  - Gesture navigation
  - Voice assistants
  - Seamless app switching
            """, language="yaml")
            
            st.markdown("**Market Leaders:**")
            st.markdown("- **Android**: Open source, customizable, Google services")
            st.markdown("- **iOS**: Integrated ecosystem, privacy focus, premium experience")
            st.markdown("- **HarmonyOS**: Huawei's cross-device platform")
            
            st.success("✅ **Mobile OS** optimized for **battery life** và **touch interaction**!")
            
        elif use_case == "IoT/Embedded System":
            st.markdown("**🔧 IoT/Embedded OS Requirements:**")
            
            embedded_features = {
                "**Resource Constraints**": "Limited RAM (KB-MB range), low-power CPUs",
                "**Real-time Capabilities**": "Deterministic response times, interrupt handling",
                "**Connectivity**": "WiFi, Bluetooth, cellular, LoRaWAN support",
                "**Security**": "Secure boot, OTA updates, encryption",
                "**Longevity**": "10+ year lifecycle, minimal maintenance"
            }
            
            for feature, description in embedded_features.items():
                st.markdown(f"**{feature.strip('*')}**: {description}")
                
            st.markdown("**Popular Embedded OS:**")
            st.markdown("- **FreeRTOS**: Real-time, lightweight, AWS support")
            st.markdown("- **Zephyr**: Linux Foundation, modular, security-focused") 
            st.markdown("- **Embedded Linux**: Full Linux stack, Yocto/Buildroot")
            st.markdown("- **ThreadX**: Microsoft, safety-certified, commercial")
            
            st.success("✅ **Embedded systems** need **minimal footprint** và **real-time performance**!")
            
        elif use_case == "Gaming System":
            st.markdown("**🎮 Gaming-Optimized OS Features:**")
            
            st.markdown("**Performance Optimizations:**")
            st.markdown("- **Low-latency scheduling**: Minimize input lag")
            st.markdown("- **GPU driver optimization**: DirectX 12, Vulkan support")
            st.markdown("- **Memory management**: Large page support, NUMA awareness")
            st.markdown("- **Storage optimization**: NVMe DirectStorage, fast loading")
            
            st.markdown("**Gaming Platform Integration:**")
            st.markdown("- **Steam**: Cross-platform gaming library")
            st.markdown("- **Xbox Game Pass**: Cloud gaming integration")
            st.markdown("- **Epic Games Store**: Exclusive titles, free games")
            st.markdown("- **Discord**: Built-in social features")
            
            st.markdown("**OS Recommendations:**")
            st.markdown("- **Windows 11**: Best game compatibility, DirectX 12 Ultimate")
            st.markdown("- **SteamOS/Linux**: Valve's gaming-focused Linux distribution")
            st.markdown("- **macOS**: Limited but growing game library, Apple Silicon performance")
            
            st.success("✅ **Gaming OS** focuses on **maximum performance** và **hardware optimization**!")
    
    # 6. Key Takeaways
    st.markdown("---")
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1.5rem; border-radius: 10px; border-left: 5px solid #1f77b4;">
        <h4 style="margin-top: 0; color: #1f77b4;">Key Takeaways</h4>
        <ul>
            <li><strong>Foundation Role</strong>: OS serves as the critical bridge between hardware resources và user applications</li>
            <li><strong>Modern Architecture</strong>: Hybrid kernels balance performance với modularity for optimal system design</li>
            <li><strong>Security Evolution</strong>: Modern OS includes built-in security features like secure boot, sandboxing, và TPM integration</li>
            <li><strong>Specialization Trend</strong>: Different OS types optimized for specific use cases - desktop, server, mobile, embedded</li>
            <li><strong>Cloud Integration</strong>: Contemporary OS designs emphasize cloud services, synchronization, và hybrid computing models</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_process_management():
    """Giải thích Process Management"""
    st.markdown("### ⚙️ Process Management")
    
    with st.expander("📖 Lý thuyết chi tiết về Process Management"):
        st.markdown("""
        ### 🎯 What is a Process?
        
        **Process** là một program đang được thực thi trong memory:
        
        **Process vs Program:**
        - **Program**: Static code stored on disk
        - **Process**: Dynamic instance of program in execution
        - **Multiple Processes**: Same program can have multiple running instances
        
        ### 🔄 Process States
        
        **1. New/Created**
        - Process is being created
        - Resources are being allocated
        - Not yet ready to run
        
        **2. Ready**
        - Process is ready to execute
        - Waiting for CPU allocation
        - In ready queue
        
        **3. Running**
        - Process is currently executing
        - Using CPU resources
        - Only one process per CPU core
        
        **4. Waiting/Blocked**
        - Process is waiting for I/O operation
        - Waiting for resource availability
        - Cannot proceed until condition is met
        
        **5. Terminated/Exit**
        - Process has finished execution
        - Resources are being deallocated
        - Exit code returned to parent
        
        ### 📊 Process Control Block (PCB)
        
        **PCB Contents:**
        - **Process ID (PID)**: Unique identifier
        - **Process State**: Current state information
        - **Program Counter**: Next instruction address
        - **CPU Registers**: Register values when context switched
        - **Memory Management**: Page tables, segment tables
        - **I/O Status**: Open files, I/O devices
        - **Accounting**: CPU time used, time limits
        
        ### 🔄 Process Scheduling
        
        **Scheduling Objectives:**
        - **Maximize CPU Utilization**: Keep CPU busy
        - **Maximize Throughput**: Complete more processes
        - **Minimize Response Time**: Quick response to users
        - **Minimize Waiting Time**: Reduce time in ready queue
        - **Fairness**: All processes get fair share
        
        **Scheduling Algorithms:**
        
        **1. First-Come, First-Served (FCFS)**
        - **Method**: Execute processes in arrival order
        - **Advantages**: Simple, fair
        - **Disadvantages**: Convoy effect, poor response time
        
        **2. Shortest Job First (SJF)**
        - **Method**: Execute shortest process first
        - **Advantages**: Optimal average waiting time
        - **Disadvantages**: Starvation, requires prediction
        
        **3. Round Robin (RR)**
        - **Method**: Time slicing with fixed quantum
        - **Advantages**: Fair, good response time
        - **Disadvantages**: Context switching overhead
        
        **4. Priority Scheduling**
        - **Method**: Execute highest priority first
        - **Advantages**: Important processes get preference
        - **Disadvantages**: Starvation of low priority
        
        **5. Multilevel Queue**
        - **Method**: Multiple queues with different priorities
        - **Advantages**: Flexible, supports different process types
        - **Disadvantages**: Complex, potential starvation
        
        ### 🔄 Context Switching
        
        **What is Context Switching?**
        - Save current process state
        - Load new process state
        - Switch CPU control to new process
        
        **Context Switch Steps:**
        1. **Save Context**: Store PCB of current process
        2. **Update PCB**: Change process state
        3. **Move to Queue**: Place in appropriate queue
        4. **Select New Process**: Choose next process to run
        5. **Load Context**: Restore PCB of new process
        6. **Resume Execution**: Continue new process
        
        **Context Switch Overhead:**
        - **Time Cost**: Saving/loading registers
        - **Cache Pollution**: New process data replaces cache
        - **TLB Flush**: Translation lookaside buffer reset
        
        ### 🔗 Inter-Process Communication (IPC)
        
        **Why IPC?**
        - **Information Sharing**: Share data between processes
        - **Computation Speedup**: Parallel processing
        - **Modularity**: Separate concerns
        - **Convenience**: User multitasking
        
        **IPC Mechanisms:**
        
        **1. Shared Memory**
        - **Method**: Common memory region
        - **Advantages**: Fast, efficient
        - **Disadvantages**: Synchronization issues
        
        **2. Message Passing**
        - **Method**: Send/receive messages
        - **Advantages**: No shared variables, works across networks
        - **Disadvantages**: Slower than shared memory
        
        **3. Pipes**
        - **Anonymous Pipes**: Parent-child communication
        - **Named Pipes (FIFOs)**: Unrelated process communication
        - **Advantages**: Simple, built into shell
        - **Disadvantages**: Limited to local machine
        
        **4. Sockets**
        - **Method**: Network-style communication
        - **Advantages**: Works across networks
        - **Disadvantages**: More complex setup
        
        **5. Signals**
        - **Method**: Software interrupts
        - **Advantages**: Asynchronous notification
        - **Disadvantages**: Limited information transfer
        
        ### 🔒 Process Synchronization
        
        **Race Conditions:**
        - Multiple processes access shared data
        - Outcome depends on execution timing
        - Can lead to inconsistent results
        
        **Critical Section Problem:**
        - Code section accessing shared resources
        - Only one process should execute at a time
        - Need mutual exclusion mechanism
        
        **Synchronization Tools:**
        
        **1. Mutex (Mutual Exclusion)**
        - Binary semaphore (0 or 1)
        - Lock/unlock mechanism
        - Ensures exclusive access
        
        **2. Semaphore**
        - Counter for resource availability
        - P (wait) and V (signal) operations
        - Can control multiple resources
        
        **3. Monitor**
        - High-level synchronization construct
        - Encapsulates shared data and procedures
        - Automatic mutual exclusion
        
        **4. Condition Variables**
        - Wait for specific conditions
        - Used with monitors
        - Avoid busy waiting
        """)
    
    # Process scheduling simulation
    st.markdown("#### 📊 Process Scheduling Simulation")
    
    scheduling_data = [
        {"Process": "P1", "Arrival Time": "0", "Burst Time": "8", "Priority": "3", "Completion": "8"},
        {"Process": "P2", "Arrival Time": "1", "Burst Time": "4", "Priority": "1", "Completion": "5"},
        {"Process": "P3", "Arrival Time": "2", "Burst Time": "2", "Priority": "2", "Completion": "7"},
        {"Process": "P4", "Arrival Time": "3", "Burst Time": "1", "Priority": "4", "Completion": "4"}
    ]
    
    df = pd.DataFrame(scheduling_data)
    st.dataframe(df, width='stretch')

def explain_memory_management():
    """Giải thích Memory Management"""
    st.markdown("### 💾 Memory Management")
    
    with st.expander("📖 Lý thuyết chi tiết về Memory Management"):
        st.markdown("""
        ### 🎯 Memory Management Goals
        
        **Primary Objectives:**
        - **Allocation**: Provide memory to processes
        - **Protection**: Prevent unauthorized access
        - **Sharing**: Allow controlled sharing
        - **Optimization**: Maximize memory utilization
        
        ### 🗂️ Memory Hierarchy
        
        **1. Registers**
        - **Location**: Inside CPU
        - **Speed**: Fastest (< 1 ns)
        - **Size**: Very small (32-64 registers)
        - **Management**: Compiler/programmer
        
        **2. Cache Memory**
        - **Location**: On/near CPU
        - **Speed**: Very fast (1-10 ns)
        - **Size**: Small (KB to MB)
        - **Management**: Hardware automatic
        
        **3. Main Memory (RAM)**
        - **Location**: System memory
        - **Speed**: Fast (50-100 ns)
        - **Size**: Large (GB to TB)
        - **Management**: Operating system
        
        **4. Secondary Storage**
        - **Location**: Hard drives, SSDs
        - **Speed**: Slow (ms)
        - **Size**: Very large (TB to PB)
        - **Management**: File system
        
        ### 📍 Memory Addressing
        
        **Address Types:**
        
        **1. Physical Address**
        - Actual hardware memory location
        - Used by memory hardware
        - Limited by physical RAM size
        
        **2. Logical/Virtual Address**
        - Address generated by CPU
        - Used by programs
        - Translated to physical address
        
        **3. Address Translation**
        - **Memory Management Unit (MMU)**: Hardware translator
        - **Base and Limit Registers**: Simple translation
        - **Page Tables**: Complex translation
        
        ### 📄 Memory Allocation Strategies
        
        **Contiguous Allocation:**
        
        **1. Fixed Partitioning**
        - **Method**: Divide memory into fixed-size partitions
        - **Advantages**: Simple implementation
        - **Disadvantages**: Internal fragmentation, inflexible
        
        **2. Dynamic Partitioning**
        - **Method**: Allocate exact size needed
        - **Advantages**: No internal fragmentation
        - **Disadvantages**: External fragmentation
        
        **Allocation Algorithms:**
        - **First Fit**: First available block
        - **Best Fit**: Smallest sufficient block
        - **Worst Fit**: Largest available block
        
        **Non-Contiguous Allocation:**
        
        **1. Paging**
        - **Method**: Divide memory into fixed-size pages
        - **Advantages**: No external fragmentation
        - **Disadvantages**: Internal fragmentation, overhead
        
        **2. Segmentation**
        - **Method**: Divide program into logical segments
        - **Advantages**: Logical organization, sharing
        - **Disadvantages**: External fragmentation
        
        **3. Segmented Paging**
        - **Method**: Combine segmentation and paging
        - **Advantages**: Benefits of both
        - **Disadvantages**: Complex implementation
        
        ### 🔄 Virtual Memory
        
        **Concept:**
        - Separate logical memory from physical memory
        - Allow programs larger than physical memory
        - Provide memory protection and sharing
        
        **Implementation:**
        
        **1. Demand Paging**
        - **Method**: Load pages only when needed
        - **Advantages**: Reduced memory usage, faster startup
        - **Disadvantages**: Page fault overhead
        
        **2. Page Replacement Algorithms**
        
        **FIFO (First-In, First-Out)**
        - Replace oldest page in memory
        - Simple but may not be optimal
        
        **LRU (Least Recently Used)**
        - Replace least recently accessed page
        - Good performance but expensive to implement
        
        **Clock Algorithm**
        - Approximation of LRU
        - Use reference bit for tracking
        
        **Optimal Algorithm**
        - Replace page that won't be used longest
        - Theoretical optimum, not implementable
        
        ### 🚨 Memory Problems
        
        **1. Fragmentation**
        
        **Internal Fragmentation:**
        - Wasted space within allocated blocks
        - Occurs in fixed-size allocation
        - Solution: Variable-size allocation
        
        **External Fragmentation:**
        - Wasted space between allocated blocks
        - Occurs in variable-size allocation
        - Solution: Compaction, paging
        
        **2. Thrashing**
        - **Cause**: Too many processes, insufficient memory
        - **Symptoms**: High page fault rate, low CPU utilization
        - **Solutions**: Reduce multiprogramming, add memory
        
        **3. Memory Leaks**
        - **Cause**: Programs don't free allocated memory
        - **Symptoms**: Gradual memory consumption
        - **Solutions**: Garbage collection, careful programming
        
        ### 🛡️ Memory Protection
        
        **Protection Mechanisms:**
        
        **1. Base and Limit Registers**
        - Define valid address range for process
        - Hardware checks every memory access
        - Simple but limited flexibility
        
        **2. Page-Level Protection**
        - Protection bits in page table entries
        - Read, write, execute permissions
        - More granular control
        
        **3. Segmentation Protection**
        - Protection per logical segment
        - Different permissions for code, data, stack
        - Matches program structure
        """)
    
    # Memory allocation visualization
    st.markdown("#### 📊 Memory Allocation Example")
    
    memory_data = [
        {"Partition": "OS Kernel", "Size (MB)": "512", "Status": "System", "Protection": "Kernel Mode"},
        {"Partition": "Process A", "Size (MB)": "256", "Status": "Allocated", "Protection": "User Mode"},
        {"Partition": "Free Space", "Size (MB)": "128", "Status": "Available", "Protection": "N/A"},
        {"Partition": "Process B", "Size (MB)": "512", "Status": "Allocated", "Protection": "User Mode"},
        {"Partition": "Free Space", "Size (MB)": "64", "Status": "Available", "Protection": "N/A"}
    ]
    
    df = pd.DataFrame(memory_data)
    st.dataframe(df, width='stretch')

def explain_file_systems():
    """Giải thích File Systems"""
    st.markdown("### 📁 File Systems")
    
    with st.expander("📖 Lý thuyết chi tiết về File Systems"):
        st.markdown("""
        ### 🎯 File System Purpose
        
        **Primary Functions:**
        - **File Organization**: Structure data on storage
        - **Access Control**: Manage file permissions
        - **Space Management**: Allocate storage efficiently
        - **Reliability**: Ensure data integrity
        
        ### 📄 File Concepts
        
        **What is a File?**
        - Named collection of related information
        - Stored on secondary storage
        - Smallest unit of logical storage
        
        **File Attributes:**
        - **Name**: Human-readable identifier
        - **Type**: File format (text, binary, executable)
        - **Size**: Current file size in bytes
        - **Location**: Physical storage location
        - **Protection**: Access permissions
        - **Timestamps**: Creation, modification, access times
        
        **File Operations:**
        - **Create**: Allocate space, create directory entry
        - **Open**: Prepare file for access
        - **Read**: Transfer data from file to memory
        - **Write**: Transfer data from memory to file
        - **Seek**: Move file pointer to specific position
        - **Close**: Release file resources
        - **Delete**: Remove file and free space
        
        ### 📂 Directory Structure
        
        **Directory Purpose:**
        - Organize files into logical groups
        - Provide naming structure
        - Enable file location and access
        
        **Directory Types:**
        
        **1. Single-Level Directory**
        - All files in one directory
        - Simple but limited
        - Name conflicts possible
        
        **2. Two-Level Directory**
        - Separate directory per user
        - Reduces name conflicts
        - Limited organization
        
        **3. Tree-Structured Directory**
        - Hierarchical organization
        - Subdirectories allowed
        - Most common structure
        
        **4. Acyclic Graph Directory**
        - Allows shared files/directories
        - Links and shortcuts
        - More complex management
        
        ### 💾 File System Types
        
        **FAT (File Allocation Table)**
        - **Versions**: FAT12, FAT16, FAT32
        - **Advantages**: Simple, widely supported
        - **Disadvantages**: File size limits, fragmentation
        - **Use Cases**: USB drives, legacy systems
        
        **NTFS (New Technology File System)**
        - **Features**: Large files, security, compression
        - **Advantages**: Reliable, feature-rich
        - **Disadvantages**: Complex, Windows-specific
        - **Use Cases**: Windows systems
        
        **ext (Extended File System)**
        - **Versions**: ext2, ext3, ext4
        - **Features**: Journaling (ext3+), large files
        - **Advantages**: Stable, efficient
        - **Disadvantages**: Linux-specific
        - **Use Cases**: Linux systems
        
        **HFS+ (Hierarchical File System Plus)**
        - **Features**: Case sensitivity, metadata
        - **Advantages**: Mac optimization
        - **Disadvantages**: Apple-specific
        - **Use Cases**: macOS systems
        
        **APFS (Apple File System)**
        - **Features**: Snapshots, encryption, cloning
        - **Advantages**: Modern features, SSD optimized
        - **Disadvantages**: New, Apple-specific
        - **Use Cases**: Modern Apple devices
        
        **ZFS (Zettabyte File System)**
        - **Features**: Checksums, snapshots, RAID
        - **Advantages**: Data integrity, scalability
        - **Disadvantages**: Memory intensive
        - **Use Cases**: Enterprise storage, NAS
        
        ### 🗄️ File Allocation Methods
        
        **1. Contiguous Allocation**
        - **Method**: Store file in consecutive blocks
        - **Advantages**: Fast sequential access, simple
        - **Disadvantages**: External fragmentation, file growth issues
        
        **2. Linked Allocation**
        - **Method**: Each block points to next block
        - **Advantages**: No external fragmentation, dynamic size
        - **Disadvantages**: Slow random access, pointer overhead
        
        **3. Indexed Allocation**
        - **Method**: Index block contains pointers to data blocks
        - **Advantages**: Fast random access, no fragmentation
        - **Disadvantages**: Index block overhead
        
        **4. Combined Approach**
        - **Method**: Mix of direct, indirect, and double-indirect pointers
        - **Advantages**: Efficient for various file sizes
        - **Disadvantages**: Complex implementation
        
        ### 🔒 File System Security
        
        **Access Control Methods:**
        
        **1. Access Control Lists (ACLs)**
        - List of users and their permissions
        - Flexible but can be complex
        - Used in NTFS, some Unix systems
        
        **2. Unix Permissions**
        - Owner, group, other permissions
        - Read, write, execute bits
        - Simple but limited granularity
        
        **3. Role-Based Access Control**
        - Permissions based on user roles
        - Easier management in large organizations
        - Requires role definition and management
        
        **File Encryption:**
        - **Full Disk Encryption**: Encrypt entire storage device
        - **File-Level Encryption**: Encrypt individual files
        - **Folder Encryption**: Encrypt directory contents
        
        ### 🔧 File System Performance
        
        **Performance Factors:**
        
        **1. Disk Layout**
        - **Sequential Access**: Faster for contiguous data
        - **Random Access**: Slower, requires seek time
        - **Fragmentation**: Reduces performance
        
        **2. Caching**
        - **Buffer Cache**: Keep frequently used blocks in memory
        - **Write-Back**: Delay writes for better performance
        - **Read-Ahead**: Prefetch likely-to-be-used blocks
        
        **3. Journaling**
        - **Purpose**: Ensure file system consistency
        - **Methods**: Metadata journaling, full journaling
        - **Trade-off**: Reliability vs. performance
        
        ### 🛠️ File System Maintenance
        
        **Regular Tasks:**
        
        **1. Defragmentation**
        - **Purpose**: Reorganize fragmented files
        - **Benefits**: Improved performance
        - **Frequency**: Depends on usage patterns
        
        **2. Disk Checking**
        - **Purpose**: Find and fix file system errors
        - **Tools**: fsck (Linux), chkdsk (Windows)
        - **Frequency**: After improper shutdowns
        
        **3. Space Management**
        - **Monitoring**: Track disk usage
        - **Cleanup**: Remove temporary and unnecessary files
        - **Quotas**: Limit user disk usage
        
        **4. Backup and Recovery**
        - **Regular Backups**: Protect against data loss
        - **Snapshot Features**: Point-in-time copies
        - **Recovery Planning**: Prepare for disasters
        """)
    
    # File system comparison
    st.markdown("#### 📊 File System Comparison")
    
    fs_data = [
        {"File System": "FAT32", "Max File Size": "4 GB", "Max Volume Size": "2 TB", "Journaling": "No", "Platform": "Cross-platform"},
        {"File System": "NTFS", "Max File Size": "16 TB", "Max Volume Size": "256 TB", "Journaling": "Yes", "Platform": "Windows"},
        {"File System": "ext4", "Max File Size": "16 TB", "Max Volume Size": "1 EB", "Journaling": "Yes", "Platform": "Linux"},
        {"File System": "APFS", "Max File Size": "8 EB", "Max Volume Size": "8 EB", "Journaling": "Yes", "Platform": "macOS/iOS"},
        {"File System": "ZFS", "Max File Size": "16 EB", "Max Volume Size": "256 ZB", "Journaling": "Yes", "Platform": "Solaris/Linux"}
    ]
    
    df = pd.DataFrame(fs_data)
    st.dataframe(df, width='stretch')

def explain_os_comparison():
    """Giải thích OS Comparison"""
    st.markdown("### ⚖️ Operating System Comparison")
    
    with st.expander("📖 Lý thuyết chi tiết về OS Comparison"):
        st.markdown("""
        ### 🖥️ Major Operating Systems
        
        **Desktop Operating Systems:**
        
        **1. Microsoft Windows**
        - **Market Share**: ~75% desktop market
        - **Versions**: Windows 10, Windows 11
        - **Architecture**: Hybrid kernel
        - **Strengths**: User-friendly, software compatibility, gaming
        - **Weaknesses**: Security vulnerabilities, resource usage, cost
        
        **2. macOS**
        - **Market Share**: ~15% desktop market
        - **Versions**: macOS Monterey, Ventura, Sonoma
        - **Architecture**: Hybrid kernel (XNU)
        - **Strengths**: User experience, security, integration
        - **Weaknesses**: Hardware limitations, cost, software availability
        
        **3. Linux**
        - **Market Share**: ~3% desktop market
        - **Distributions**: Ubuntu, Fedora, Debian, Arch
        - **Architecture**: Monolithic kernel
        - **Strengths**: Open source, customizable, secure, free
        - **Weaknesses**: Learning curve, software compatibility
        
        ### 🖲️ Server Operating Systems
        
        **1. Linux Server**
        - **Market Share**: ~70% server market
        - **Distributions**: RHEL, CentOS, Ubuntu Server, SUSE
        - **Strengths**: Stability, security, cost-effective, scalable
        - **Use Cases**: Web servers, cloud computing, containers
        
        **2. Windows Server**
        - **Market Share**: ~20% server market
        - **Versions**: Windows Server 2019, 2022
        - **Strengths**: Active Directory, .NET integration, GUI management
        - **Use Cases**: Enterprise environments, Microsoft ecosystems
        
        **3. Unix Variants**
        - **Market Share**: ~5% server market
        - **Variants**: AIX, Solaris, HP-UX
        - **Strengths**: Stability, scalability, enterprise features
        - **Use Cases**: High-end enterprise, mainframes
        
        ### 📱 Mobile Operating Systems
        
        **1. Android**
        - **Market Share**: ~70% mobile market
        - **Developer**: Google
        - **Base**: Linux kernel
        - **Strengths**: Open source, customizable, wide device support
        - **Weaknesses**: Fragmentation, security concerns
        
        **2. iOS**
        - **Market Share**: ~25% mobile market
        - **Developer**: Apple
        - **Base**: Darwin (Unix-like)
        - **Strengths**: Security, user experience, app quality
        - **Weaknesses**: Closed ecosystem, limited customization
        
        ### 🔧 Technical Comparison
        
        **Kernel Architecture:**
        
        **Monolithic Kernel (Linux):**
        - **Advantages**: Fast system calls, efficient
        - **Disadvantages**: Large kernel, less modular
        - **Stability**: Kernel crash affects entire system
        
        **Hybrid Kernel (Windows, macOS):**
        - **Advantages**: Balance of performance and modularity
        - **Disadvantages**: More complex than pure approaches
        - **Stability**: Better isolation than monolithic
        
        **Microkernel (QNX, Minix):**
        - **Advantages**: Highly modular, stable
        - **Disadvantages**: Performance overhead
        - **Stability**: Service crashes don't affect kernel
        
        ### 🛡️ Security Comparison
        
        **Windows Security:**
        - **Built-in**: Windows Defender, UAC, BitLocker
        - **Challenges**: Large attack surface, frequent updates needed
        - **Enterprise**: Active Directory, Group Policy
        
        **macOS Security:**
        - **Built-in**: Gatekeeper, XProtect, FileVault
        - **Advantages**: Smaller target, Unix foundation
        - **Challenges**: Increasing malware targeting Macs
        
        **Linux Security:**
        - **Built-in**: SELinux, AppArmor, sudo
        - **Advantages**: Open source auditing, permission model
        - **Challenges**: Configuration complexity
        
        ### 💰 Cost Analysis
        
        **Total Cost of Ownership (TCO):**
        
        **Windows:**
        - **License Cost**: $100-200+ per desktop
        - **Support**: Commercial support available
        - **Training**: Familiar to most users
        - **Software**: Wide commercial software availability
        
        **macOS:**
        - **License Cost**: Included with hardware
        - **Hardware Cost**: Premium pricing
        - **Support**: Apple support, limited third-party
        - **Software**: Good availability, some premium pricing
        
        **Linux:**
        - **License Cost**: Free (most distributions)
        - **Support**: Community or commercial options
        - **Training**: Learning curve for new users
        - **Software**: Extensive free software, some commercial gaps
        
        ### 🎯 Use Case Recommendations
        
        **Desktop Environments:**
        
        **Home Users:**
        - **Windows**: Gaming, general use, software compatibility
        - **macOS**: Creative work, premium experience
        - **Linux**: Technical users, privacy-conscious, older hardware
        
        **Business Environments:**
        - **Windows**: Microsoft ecosystem, legacy applications
        - **macOS**: Creative industries, executive users
        - **Linux**: Development, security-focused organizations
        
        **Server Environments:**
        
        **Web Servers:**
        - **Linux**: Cost-effective, stable, secure
        - **Windows**: .NET applications, Microsoft integration
        
        **Enterprise Servers:**
        - **Linux**: Scalability, containerization, cloud
        - **Windows**: Active Directory, Exchange, SharePoint
        - **Unix**: Mission-critical, high-availability systems
        
        ### 📊 Performance Comparison
        
        **Resource Usage:**
        - **Linux**: Generally most efficient
        - **Windows**: Higher resource requirements
        - **macOS**: Optimized for Apple hardware
        
        **Boot Time:**
        - **Linux**: Fast boot, especially with SSD
        - **Windows**: Moderate boot time
        - **macOS**: Fast boot on modern hardware
        
        **File System Performance:**
        - **Linux**: ext4, Btrfs, ZFS options
        - **Windows**: NTFS optimization
        - **macOS**: APFS optimization for SSDs
        
        ### 🔮 Future Trends
        
        **Cloud Integration:**
        - All major OS moving toward cloud services
        - Hybrid local/cloud storage and computing
        - Web-based applications reducing OS dependence
        
        **Container Technology:**
        - Linux leading in container adoption
        - Windows adding container support
        - Kubernetes becoming standard orchestration
        
        **Security Focus:**
        - Zero-trust security models
        - Hardware-based security features
        - Automated threat detection and response
        """)
    
    # OS comparison matrix
    st.markdown("#### 📊 Operating System Comparison Matrix")
    
    comparison_data = [
        {"Aspect": "Ease of Use", "Windows": "High", "macOS": "Very High", "Linux": "Medium"},
        {"Aspect": "Security", "Windows": "Medium", "macOS": "High", "Linux": "High"},
        {"Aspect": "Cost", "Windows": "Medium", "macOS": "High", "Linux": "Low"},
        {"Aspect": "Software Availability", "Windows": "Very High", "macOS": "High", "Linux": "Medium"},
        {"Aspect": "Customization", "Windows": "Medium", "macOS": "Low", "Linux": "Very High"},
        {"Aspect": "Hardware Support", "Windows": "Very High", "macOS": "Limited", "Linux": "High"},
        {"Aspect": "Gaming", "Windows": "Very High", "macOS": "Medium", "Linux": "Medium"},
        {"Aspect": "Enterprise Features", "Windows": "Very High", "macOS": "Medium", "Linux": "High"}
    ]
    
    df = pd.DataFrame(comparison_data)
    st.dataframe(df, width='stretch')

def database_fundamentals_lab():
    """Lab về cơ sở dữ liệu"""
    st.subheader("🗄️ Database Fundamentals Lab")
    
    topic_choice = st.selectbox("Chọn chủ đề:", [
        "Database Concepts",
        "Relational Databases",
        "SQL Basics",
        "Database Design",
        "NoSQL Databases"
    ])
    
    if topic_choice == "Database Concepts":
        explain_database_concepts()
    elif topic_choice == "Relational Databases":
        explain_relational_databases()
    elif topic_choice == "SQL Basics":
        explain_sql_basics()
    elif topic_choice == "Database Design":
        explain_database_design()

def explain_database_concepts():
    """Enhanced Database Concepts explanation using TDD pattern"""
    st.markdown("### Database Concepts")
    
    # 1. Visual Banner (IT Fundamentals color scheme)
    st.markdown("""
    <div style="background: linear-gradient(90deg, #56ab2f 0%, #a8e6cf 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            Database Concepts
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Foundation of Data Management Systems
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 2. Visual Diagram (Enhanced database architecture diagram)
    st.markdown("#### Database System Architecture")
    
    fig = go.Figure()
    
    # Create database system layers
    db_layers = [
        {"name": "Users & Applications", "y": 0.85, "color": "#e74c3c", "width": 0.8, "examples": "Web Apps, Mobile Apps, Analytics Tools"},
        {"name": "Database Interface", "y": 0.7, "color": "#f39c12", "width": 0.7, "examples": "SQL, APIs, Drivers"},
        {"name": "Query Processor", "y": 0.55, "color": "#f1c40f", "width": 0.6, "examples": "Parser, Optimizer, Executor"},
        {"name": "Transaction Manager", "y": 0.4, "color": "#2ecc71", "width": 0.6, "examples": "ACID, Concurrency Control"},
        {"name": "Storage Manager", "y": 0.25, "color": "#3498db", "width": 0.6, "examples": "Buffer, Index, File Manager"},
        {"name": "Physical Storage", "y": 0.1, "color": "#9b59b6", "width": 0.8, "examples": "Disk, SSD, Memory"}
    ]
    
    # Draw database layers
    for layer in db_layers:
        x_center = 0.5
        width = layer["width"]
        
        # Layer rectangle
        fig.add_shape(
            type="rect",
            x0=x_center - width/2, y0=layer["y"]-0.06, 
            x1=x_center + width/2, y1=layer["y"]+0.06,
            fillcolor=layer["color"],
            opacity=0.8,
            line=dict(color="white", width=2)
        )
        
        # Layer name
        fig.add_annotation(
            x=x_center, y=layer["y"],
            text=f"<b>{layer['name']}</b>",
            showarrow=False,
            font=dict(size=12, color="white"),
        )
        
        # Examples (smaller text)
        fig.add_annotation(
            x=x_center, y=layer["y"]-0.03,
            text=layer["examples"],
            showarrow=False,
            font=dict(size=9, color="white"),
        )
    
    # Add data flow arrows
    for i in range(len(db_layers)-1):
        y_start = db_layers[i]["y"] - 0.06
        y_end = db_layers[i+1]["y"] + 0.06
        
        # Downward arrow
        fig.add_annotation(
            x=0.15, y=(y_start + y_end) / 2,
            ax=0.15, ay=y_start,
            arrowhead=2, arrowsize=1, arrowwidth=2, arrowcolor="#34495e",
            showarrow=True, text=""
        )
        
        # Upward arrow (response)
        fig.add_annotation(
            x=0.85, y=(y_start + y_end) / 2,
            ax=0.85, ay=y_end,
            arrowhead=2, arrowsize=1, arrowwidth=2, arrowcolor="#34495e",
            showarrow=True, text=""
        )
    
    fig.update_layout(
        xaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=450,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # 3. Clean Content with expandable details
    with st.expander("Chi tiết về Database Concepts"):
        st.markdown("""
        ## Database Fundamentals
        
        **Definition:** Database là organized collection of structured data được stored và accessed electronically từ computer systems, managed bởi Database Management System (DBMS).
        
        ---
        
        ## Core Database Concepts
        
        ### **Data Hierarchy**
        **Purpose:** Tổ chức data từ basic elements đến complex structures
        **Implementation:** Bit → Byte → Field → Record → Table → Database → Data Warehouse
        **Benefits:** Structured organization, efficient storage, scalable architecture
        
        ### **Database Management System (DBMS)**  
        **Purpose:** Software system quản lý creation, maintenance, và usage của databases
        **Implementation:** Query processing, transaction management, storage optimization
        **Benefits:** Data integrity, concurrent access, security, backup/recovery
        
        ### **Data Models**
        **Purpose:** Định nghĩa logical structure của database và relationships
        **Implementation:** Relational, NoSQL, Object-oriented, Graph models
        **Benefits:** Data organization, query optimization, application design guidance
        
        ### **ACID Properties**
        **Purpose:** Đảm bảo reliable transaction processing trong database systems
        **Implementation:** Atomicity, Consistency, Isolation, Durability mechanisms
        **Benefits:** Data integrity, transaction reliability, system consistency
        
        ---
        
        ## Modern Database Types
        
        **Relational Databases (RDBMS):**
        - **Structure:** Tables với rows và columns, foreign key relationships
        - **Advantages:** ACID compliance, mature ecosystem, standardized SQL
        - **Use Cases:** Enterprise applications, financial systems, e-commerce
        - **Examples:** PostgreSQL, MySQL, Oracle Database, SQL Server
        - **Modern Features:** JSON support, horizontal scaling, cloud integration
        
        **NoSQL Databases:**
        - **Document Stores:** MongoDB, CouchDB - flexible schema, JSON-like documents
        - **Key-Value Stores:** Redis, DynamoDB - simple key-value pairs, high performance
        - **Column-Family:** Cassandra, HBase - wide column storage, big data
        - **Graph Databases:** Neo4j, Amazon Neptune - relationship-focused data
        - **Use Cases:** Big data, real-time applications, content management
        
        **NewSQL Databases:**
        - **Hybrid Approach:** Combines ACID properties với NoSQL scalability
        - **Examples:** Google Spanner, CockroachDB, VoltDB
        - **Features:** Distributed ACID transactions, horizontal scaling
        - **Use Cases:** Global applications, high-performance OLTP
        
        **Cloud-Native Databases:**
        - **Serverless:** Amazon Aurora Serverless, Azure SQL Database Serverless
        - **Multi-Model:** Azure Cosmos DB, Amazon DocumentDB
        - **Analytics:** BigQuery, Snowflake, Redshift
        - **Benefits:** Auto-scaling, managed services, global distribution
        
        ---
        
        ## Database Operations & Performance
        
        **CRUD Operations (Enhanced):**
        - **Create (INSERT):** Bulk inserts, upserts, batch processing
        - **Read (SELECT):** Complex queries, joins, aggregations, window functions
        - **Update (UPDATE):** Conditional updates, bulk updates, merge operations
        - **Delete (DELETE):** Soft deletes, cascading deletes, archival strategies
        
        **Query Optimization:**
        - **Indexing:** B-tree, Hash, Bitmap, Full-text indexes
        - **Query Planning:** Cost-based optimization, execution plans
        - **Caching:** Query result caching, buffer pools, Redis integration
        - **Partitioning:** Horizontal/vertical partitioning, sharding strategies
        
        **Transaction Management:**
        - **Concurrency Control:** Locking mechanisms, MVCC, optimistic concurrency
        - **Isolation Levels:** Read uncommitted, committed, repeatable read, serializable
        - **Deadlock Handling:** Detection, prevention, resolution strategies
        - **Distributed Transactions:** Two-phase commit, saga patterns
        """)
    
    # 4. Enhanced Cheat Sheets with highlighted keywords
    st.markdown("---")
    st.markdown("## Database Concepts Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["Database Types", "ACID & Performance", "Modern Technologies"])
    
    with tab1:
        st.markdown("### Database Types Comparison")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Database Type** | **Data Model** | **Schema** | **Scalability** | **Use Cases** | **Examples** |
        |-------------------|----------------|------------|-----------------|---------------|--------------|
        | **Relational (SQL)** | **Tables** với rows/columns | **Rigid** schema required | **Vertical** scaling primarily | **OLTP**, financial systems, **enterprise apps** | **PostgreSQL**, **MySQL**, Oracle, SQL Server |
        | **Document (NoSQL)** | **JSON-like** documents | **Flexible** schema | **Horizontal** scaling | **Content management**, catalogs, **user profiles** | **MongoDB**, CouchDB, **Amazon DocumentDB** |
        | **Key-Value (NoSQL)** | **Simple** key-value pairs | **Schema-less** | **Highly scalable** | **Caching**, session storage, **real-time** | **Redis**, **DynamoDB**, Riak |
        | **Column-Family** | **Wide columns** với row keys | **Semi-structured** | **Massive scale** | **Big data**, time-series, **IoT data** | **Cassandra**, HBase, **Amazon Timestream** |
        | **Graph** | **Nodes** và **edges** | **Schema-optional** | **Complex relationships** | **Social networks**, recommendations, **fraud detection** | **Neo4j**, **Amazon Neptune**, ArangoDB |
        | **NewSQL** | **Relational** với NoSQL scaling | **ACID** compliance | **Distributed** ACID | **Global applications**, **high-performance OLTP** | **Google Spanner**, CockroachDB |
        """)
        
        # Additional highlighted information
        st.markdown("""
        #### **Key Selection Criteria**
        - **Data Structure**: `structured_data` → SQL, `semi/unstructured` → NoSQL
        - **Scalability Needs**: `vertical_scaling` → SQL, `horizontal_scaling` → NoSQL  
        - **Consistency Requirements**: `ACID_required` → SQL/NewSQL, `eventual_consistency_ok` → NoSQL
        """)
    
    with tab2:
        st.markdown("### ACID Properties & Performance")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **ACID Property** | **Definition** | **Implementation** | **Trade-offs** | **Performance Impact** | **Example** |
        |-------------------|----------------|--------------------|----------------|------------------------|-------------|
        | **Atomicity** | **All-or-nothing** transactions | Transaction logs, **rollback** mechanisms | **Overhead** for logging | **Medium** - log writes | Bank transfer: **both** accounts updated or **neither** |
        | **Consistency** | **Data integrity** rules enforced | Constraints, **triggers**, validation | **Complexity** in rule management | **Low-Medium** - validation checks | **Foreign key** constraints prevent orphaned records |
        | **Isolation** | **Concurrent** transactions don't interfere | **Locking**, MVCC, **isolation levels** | **Concurrency** vs consistency trade-off | **High** - locking overhead | **Serializable** isolation prevents phantom reads |
        | **Durability** | **Committed** changes survive system failures | **Write-ahead** logging, **fsync** | **Performance** cost for persistence | **High** - disk I/O | **Transaction log** survives database crash |
        """)
        
        st.markdown("""
        #### **Performance Optimization Techniques**
        - **Indexing Strategy**: `B-tree_indexes` for range queries, `hash_indexes` for equality
        - **Query Optimization**: `execution_plans`, statistics updates, **query rewriting**
        - **Caching Layers**: `buffer_pools`, **Redis**, **application-level** caching
        """)
    
    with tab3:
        st.markdown("### Modern Database Technologies")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Technology** | **Purpose** | **Key Features** | **Benefits** | **Use Cases** | **Adoption** |
        |----------------|-------------|------------------|--------------|---------------|--------------|
        | **Cloud Databases** | **Managed** database services | **Auto-scaling**, backup, **high availability** | **Reduced** operational overhead | **Startups**, **enterprise migration** | **Widespread** adoption |
        | **Serverless DB** | **Pay-per-use** database computing | **Auto-pause**, **instant scaling** | **Cost optimization** for variable workloads | **Development**, **seasonal apps** | **Growing** rapidly |
        | **Multi-Model DB** | **Single** database, **multiple** data models | **Document**, **graph**, **key-value** support | **Simplified** architecture | **Complex applications** với diverse data | **Emerging** trend |
        | **Time-Series DB** | **Time-stamped** data optimization | **Compression**, **retention policies** | **Efficient** IoT và metrics storage | **Monitoring**, **IoT**, **financial data** | **Specialized** adoption |
        | **In-Memory DB** | **RAM-based** storage | **Microsecond** latency, **high throughput** | **Extreme performance** | **Real-time** analytics, **gaming** | **High-performance** niches |
        | **Blockchain DB** | **Distributed** ledger technology | **Immutability**, **consensus**, **decentralization** | **Trust**, **transparency** | **Cryptocurrency**, **supply chain** | **Experimental** phase |
        """)
    
    # 5. Interactive Demo
    st.markdown("---")
    st.markdown("## Interactive Demo")
    
    with st.expander("Database Selection Guide"):
        st.markdown("### Choose the Right Database")
        
        # Simple interactive element
        app_type = st.selectbox(
            "Select your application type:", 
            ["E-commerce Platform", "Social Media App", "IoT Analytics", "Financial System", "Content Management"]
        )
        
        if app_type == "E-commerce Platform":
            st.markdown("**🛒 E-commerce Database Requirements:**")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Core Requirements:**")
                st.markdown("- **ACID compliance** for financial transactions")
                st.markdown("- **Complex queries** for product search/filtering")
                st.markdown("- **Consistent inventory** management")
                st.markdown("- **Scalable** for traffic spikes")
                
            with col2:
                st.markdown("**Recommended Architecture:**")
                st.markdown("- **PostgreSQL/MySQL**: Core transactional data")
                st.markdown("- **Elasticsearch**: Product search và recommendations")
                st.markdown("- **Redis**: Session storage và caching")
                st.markdown("- **MongoDB**: Product catalog với flexible attributes")
                
            st.success("✅ **E-commerce** needs **hybrid architecture** với **ACID guarantees** for transactions!")
            
        elif app_type == "Social Media App":
            st.markdown("**📱 Social Media Database Analysis:**")
            
            social_requirements = [
                "**High Write Volume**: Millions of posts/messages per second",
                "**Flexible Schema**: Different content types (text, images, videos)",
                "**Graph Relationships**: Friends, followers, connections",
                "**Real-time Features**: Live feeds, notifications, messaging",
                "**Global Scale**: Worldwide user base với low latency",
                "**Analytics**: User behavior, content performance"
            ]
            
            for req in social_requirements:
                st.markdown(f"- {req}")
                
            st.markdown("**Recommended Technology Stack:**")
            st.markdown("- **Cassandra**: User posts và timeline data")
            st.markdown("- **Neo4j**: Social graph và relationships")
            st.markdown("- **Redis**: Real-time messaging và caching")
            st.markdown("- **MongoDB**: User profiles và metadata")
            
            st.success("✅ **Social media** requires **NoSQL** for **scale** và **graph databases** for relationships!")
    
    # 6. Key Takeaways
    st.markdown("---")
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1.5rem; border-radius: 10px; border-left: 5px solid #1f77b4;">
        <h4 style="margin-top: 0; color: #1f77b4;">Key Takeaways</h4>
        <ul>
            <li><strong>No One-Size-Fits-All</strong>: Different database types serve different use cases - choose based on specific requirements</li>
            <li><strong>ACID vs BASE</strong>: Traditional ACID properties vs eventual consistency models each have their place in modern architectures</li>
            <li><strong>Polyglot Persistence</strong>: Modern applications often use multiple database types optimized for different data patterns</li>
            <li><strong>Cloud-Native Evolution</strong>: Managed database services và serverless options reduce operational complexity</li>
            <li><strong>Performance Optimization</strong>: Understanding indexing, caching, và query optimization is crucial for scalable applications</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_relational_databases():
    """Giải thích Relational Databases"""
    st.markdown("### 🗄️ Relational Databases")
    
    with st.expander("📖 Lý thuyết chi tiết về Relational Databases"):
        st.markdown("""
        ### 🎯 Relational Database Model
        
        **Key Concepts:**
        - **Tables (Relations)**: Store data in rows and columns
        - **Rows (Tuples)**: Individual records
        - **Columns (Attributes)**: Data fields
        - **Primary Key**: Unique identifier for each row
        - **Foreign Key**: Reference to another table's primary key
        
        **ACID Properties:**
        - **Atomicity**: All or nothing transactions
        - **Consistency**: Data integrity maintained
        - **Isolation**: Concurrent transactions don't interfere
        - **Durability**: Committed changes are permanent
        
        **Popular RDBMS:**
        - **MySQL**: Open source, web applications
        - **PostgreSQL**: Advanced features, enterprise
        - **Oracle**: Enterprise, high performance
        - **SQL Server**: Microsoft ecosystem
        - **SQLite**: Embedded, lightweight
        """)
    
    # RDBMS comparison
    rdbms_data = [
        {"RDBMS": "MySQL", "License": "Open Source", "Platform": "Cross-platform", "Use Case": "Web applications"},
        {"RDBMS": "PostgreSQL", "License": "Open Source", "Platform": "Cross-platform", "Use Case": "Enterprise"},
        {"RDBMS": "Oracle", "License": "Commercial", "Platform": "Cross-platform", "Use Case": "Large enterprise"},
        {"RDBMS": "SQL Server", "License": "Commercial", "Platform": "Windows/Linux", "Use Case": "Microsoft stack"}
    ]
    
    df = pd.DataFrame(rdbms_data)
    st.dataframe(df, width='stretch')

def explain_sql_basics():
    """Giải thích SQL Basics"""
    st.markdown("### 📝 SQL Basics")
    
    with st.expander("📖 Lý thuyết chi tiết về SQL"):
        st.markdown("""
        ### 🎯 SQL Command Categories
        
        **DDL (Data Definition Language):**
        - **CREATE**: Create database objects
        - **ALTER**: Modify database objects
        - **DROP**: Delete database objects
        - **TRUNCATE**: Remove all data from table
        
        **DML (Data Manipulation Language):**
        - **SELECT**: Retrieve data
        - **INSERT**: Add new data
        - **UPDATE**: Modify existing data
        - **DELETE**: Remove data
        
        **DCL (Data Control Language):**
        - **GRANT**: Give permissions
        - **REVOKE**: Remove permissions
        
        **TCL (Transaction Control Language):**
        - **COMMIT**: Save changes
        - **ROLLBACK**: Undo changes
        - **SAVEPOINT**: Set transaction checkpoint
        
        ### 📝 Basic SQL Syntax
        
        **SELECT Statement:**
        ```sql
        SELECT column1, column2
        FROM table_name
        WHERE condition
        ORDER BY column1;
        ```
        
        **INSERT Statement:**
        ```sql
        INSERT INTO table_name (column1, column2)
        VALUES (value1, value2);
        ```
        
        **UPDATE Statement:**
        ```sql
        UPDATE table_name
        SET column1 = value1
        WHERE condition;
        ```
        
        **DELETE Statement:**
        ```sql
        DELETE FROM table_name
        WHERE condition;
        ```
        
        ### 🔗 JOIN Operations
        
        **INNER JOIN:**
        - Returns matching records from both tables
        
        **LEFT JOIN:**
        - Returns all records from left table
        
        **RIGHT JOIN:**
        - Returns all records from right table
        
        **FULL OUTER JOIN:**
        - Returns all records from both tables
        """)
    
    # SQL command examples
    sql_examples = [
        {"Command": "SELECT", "Purpose": "Retrieve data", "Example": "SELECT * FROM users;"},
        {"Command": "INSERT", "Purpose": "Add data", "Example": "INSERT INTO users (name) VALUES ('John');"},
        {"Command": "UPDATE", "Purpose": "Modify data", "Example": "UPDATE users SET name='Jane' WHERE id=1;"},
        {"Command": "DELETE", "Purpose": "Remove data", "Example": "DELETE FROM users WHERE id=1;"}
    ]
    
    df = pd.DataFrame(sql_examples)
    st.dataframe(df, width='stretch')

def explain_database_design():
    """Giải thích Database Design"""
    st.markdown("### 🏗️ Database Design")
    
    with st.expander("📖 Lý thuyết chi tiết về Database Design"):
        st.markdown("""
        ### 🎯 Database Design Process
        
        **1. Requirements Analysis**
        - Identify data requirements
        - Understand business rules
        - Define user needs
        
        **2. Conceptual Design**
        - Create Entity-Relationship (ER) diagram
        - Identify entities and relationships
        - Define attributes and constraints
        
        **3. Logical Design**
        - Convert ER diagram to relational schema
        - Apply normalization rules
        - Define primary and foreign keys
        
        **4. Physical Design**
        - Choose storage structures
        - Define indexes
        - Optimize performance
        
        ### 📐 Normalization
        
        **First Normal Form (1NF):**
        - Eliminate repeating groups
        - Each cell contains single value
        - Each row is unique
        
        **Second Normal Form (2NF):**
        - Must be in 1NF
        - Eliminate partial dependencies
        - Non-key attributes depend on entire primary key
        
        **Third Normal Form (3NF):**
        - Must be in 2NF
        - Eliminate transitive dependencies
        - Non-key attributes don't depend on other non-key attributes
        
        **Boyce-Codd Normal Form (BCNF):**
        - Stricter version of 3NF
        - Every determinant is a candidate key
        - Eliminates all anomalies
        
        ### 🔗 Relationships
        
        **One-to-One (1:1):**
        - Each record in table A relates to one record in table B
        - Example: Person and Passport
        
        **One-to-Many (1:M):**
        - Each record in table A can relate to many records in table B
        - Example: Customer and Orders
        
        **Many-to-Many (M:M):**
        - Records in both tables can relate to multiple records
        - Requires junction table
        - Example: Students and Courses
        
        ### 🎯 Design Best Practices
        
        **Naming Conventions:**
        - Use descriptive names
        - Be consistent
        - Avoid reserved words
        
        **Data Types:**
        - Choose appropriate data types
        - Consider storage requirements
        - Plan for future growth
        
        **Constraints:**
        - Define primary keys
        - Use foreign keys for referential integrity
        - Add check constraints for data validation
        
        **Indexing:**
        - Index frequently queried columns
        - Consider composite indexes
        - Balance query performance vs. storage
        """)
    
    # Normalization example
    normalization_data = [
        {"Normal Form": "1NF", "Rule": "Atomic values", "Example": "No repeating groups"},
        {"Normal Form": "2NF", "Rule": "No partial dependencies", "Example": "All attributes depend on full key"},
        {"Normal Form": "3NF", "Rule": "No transitive dependencies", "Example": "No non-key dependencies"},
        {"Normal Form": "BCNF", "Rule": "Every determinant is key", "Example": "Eliminates all anomalies"}
    ]
    
    df = pd.DataFrame(normalization_data)
    st.dataframe(df, width='stretch')

def explain_system_monitoring():
    """Giải thích System Monitoring"""
    st.markdown("### 📊 System Monitoring")
    
    with st.expander("📖 Lý thuyết chi tiết về System Monitoring"):
        st.markdown("""
        ### 🎯 Why Monitor Systems?
        
        **Performance Optimization:**
        - Identify bottlenecks
        - Optimize resource usage
        - Plan capacity upgrades
        
        **Problem Detection:**
        - Early warning of issues
        - Prevent system failures
        - Minimize downtime
        
        **Security Monitoring:**
        - Detect intrusions
        - Monitor access patterns
        - Identify anomalies
        
        ### 📊 Key Metrics to Monitor
        
        **CPU Metrics:**
        - **CPU Utilization**: Percentage of CPU usage
        - **Load Average**: System load over time
        - **Context Switches**: Process switching frequency
        - **Interrupts**: Hardware interrupt rate
        
        **Memory Metrics:**
        - **Memory Usage**: RAM utilization
        - **Swap Usage**: Virtual memory usage
        - **Page Faults**: Memory access violations
        - **Buffer/Cache**: System caching efficiency
        
        **Storage Metrics:**
        - **Disk Usage**: Storage space utilization
        - **I/O Operations**: Read/write operations per second
        - **Queue Length**: Pending I/O operations
        - **Response Time**: Storage access latency
        
        **Network Metrics:**
        - **Bandwidth Usage**: Network throughput
        - **Packet Loss**: Network reliability
        - **Latency**: Network response time
        - **Connection Count**: Active network connections
        
        ### 🛠️ Monitoring Tools
        
        **Windows Tools:**
        - **Task Manager**: Basic system monitoring
        - **Performance Monitor**: Detailed performance counters
        - **Resource Monitor**: Real-time resource usage
        - **Event Viewer**: System and application logs
        
        **Linux Tools:**
        - **top/htop**: Process and system overview
        - **iotop**: I/O monitoring
        - **netstat/ss**: Network connections
        - **vmstat**: Virtual memory statistics
        - **iostat**: I/O statistics
        - **sar**: System activity reporter
        
        **Cross-Platform Tools:**
        - **Nagios**: Network and infrastructure monitoring
        - **Zabbix**: Enterprise monitoring solution
        - **PRTG**: Network monitoring
        - **SolarWinds**: IT infrastructure monitoring
        - **Datadog**: Cloud monitoring and analytics
        
        ### 📈 Monitoring Strategies
        
        **Baseline Establishment:**
        - Measure normal performance
        - Identify typical usage patterns
        - Set performance benchmarks
        
        **Threshold Setting:**
        - Define warning levels
        - Set critical alerts
        - Avoid alert fatigue
        
        **Trend Analysis:**
        - Monitor long-term trends
        - Predict capacity needs
        - Identify gradual degradation
        
        **Real-time Monitoring:**
        - Immediate problem detection
        - Automated responses
        - Dashboard visualization
        
        ### 🚨 Alerting Best Practices
        
        **Alert Levels:**
        - **Info**: Informational messages
        - **Warning**: Potential issues
        - **Critical**: Immediate attention required
        - **Emergency**: System failure
        
        **Alert Channels:**
        - **Email**: Non-urgent notifications
        - **SMS**: Critical alerts
        - **Dashboard**: Visual monitoring
        - **Integration**: ITSM tools
        
        **Alert Management:**
        - Avoid duplicate alerts
        - Implement escalation procedures
        - Regular alert review and tuning
        """)
    
    # Monitoring metrics table
    metrics_data = [
        {"Metric": "CPU Usage", "Normal Range": "< 80%", "Warning": "80-90%", "Critical": "> 90%"},
        {"Metric": "Memory Usage", "Normal Range": "< 85%", "Warning": "85-95%", "Critical": "> 95%"},
        {"Metric": "Disk Usage", "Normal Range": "< 80%", "Warning": "80-90%", "Critical": "> 90%"},
        {"Metric": "Network Utilization", "Normal Range": "< 70%", "Warning": "70-85%", "Critical": "> 85%"}
    ]
    
    df = pd.DataFrame(metrics_data)
    st.dataframe(df, width='stretch')

def explain_backup_recovery():
    """Giải thích Backup & Recovery"""
    st.markdown("### 💾 Backup & Recovery")
    
    with st.expander("📖 Lý thuyết chi tiết về Backup & Recovery"):
        st.markdown("""
        ### 🎯 Backup Strategy Fundamentals
        
        **Why Backup?**
        - **Data Protection**: Protect against data loss
        - **Disaster Recovery**: Recover from catastrophic events
        - **Business Continuity**: Maintain operations
        - **Compliance**: Meet regulatory requirements
        
        ### 📦 Backup Types
        
        **Full Backup:**
        - **Description**: Complete copy of all data
        - **Advantages**: Fastest recovery, complete data protection
        - **Disadvantages**: Longest backup time, most storage space
        - **Frequency**: Weekly or monthly
        
        **Incremental Backup:**
        - **Description**: Only data changed since last backup
        - **Advantages**: Fastest backup, least storage space
        - **Disadvantages**: Slower recovery (need multiple backups)
        - **Frequency**: Daily
        
        **Differential Backup:**
        - **Description**: Data changed since last full backup
        - **Advantages**: Faster than full, simpler recovery than incremental
        - **Disadvantages**: Grows larger over time
        - **Frequency**: Daily or weekly
        
        **Mirror Backup:**
        - **Description**: Exact copy of source data
        - **Advantages**: Fast recovery, current data
        - **Disadvantages**: No versioning, accidental deletions replicated
        
        ### 🎯 Recovery Objectives
        
        **RTO (Recovery Time Objective):**
        - Maximum acceptable downtime
        - How quickly systems must be restored
        - Influences backup and recovery strategy
        
        **RPO (Recovery Point Objective):**
        - Maximum acceptable data loss
        - How much data can be lost
        - Determines backup frequency
        
        ### 📍 Backup Storage Locations
        
        **Local Backup:**
        - **Advantages**: Fast backup and recovery
        - **Disadvantages**: Vulnerable to local disasters
        - **Use Case**: Quick recovery from minor issues
        
        **Offsite Backup:**
        - **Advantages**: Protection from local disasters
        - **Disadvantages**: Slower recovery, higher cost
        - **Use Case**: Disaster recovery
        
        **Cloud Backup:**
        - **Advantages**: Scalable, managed, geographically distributed
        - **Disadvantages**: Internet dependency, ongoing costs
        - **Use Case**: Modern backup strategy
        
        ### 🔄 3-2-1 Backup Rule
        
        **3 Copies of Data:**
        - Original data
        - Local backup copy
        - Remote backup copy
        
        **2 Different Media Types:**
        - Different storage technologies
        - Reduces risk of media failure
        - Example: Disk and tape
        
        **1 Offsite Copy:**
        - Protection from local disasters
        - Geographic separation
        - Cloud or remote facility
        
        ### 🛠️ Backup Tools and Technologies
        
        **File-Level Backup:**
        - **Windows**: File History, Backup and Restore
        - **macOS**: Time Machine
        - **Linux**: rsync, tar, duplicity
        
        **Image-Level Backup:**
        - **Windows**: System Image Backup
        - **Cross-platform**: Clonezilla, Acronis
        - **Enterprise**: Veeam, CommVault
        
        **Database Backup:**
        - **MySQL**: mysqldump, binary logs
        - **PostgreSQL**: pg_dump, WAL archiving
        - **SQL Server**: Full, differential, log backups
        
        **Cloud Backup Services:**
        - **Consumer**: Google Drive, OneDrive, Dropbox
        - **Business**: AWS Backup, Azure Backup, Google Cloud
        - **Enterprise**: Carbonite, Backblaze B2
        
        ### 🔧 Recovery Procedures
        
        **Recovery Planning:**
        - **Document Procedures**: Step-by-step recovery guides
        - **Test Regularly**: Verify backup integrity
        - **Prioritize Systems**: Critical systems first
        - **Communication Plan**: Stakeholder notification
        
        **Recovery Types:**
        
        **File Recovery:**
        - Restore individual files or folders
        - Most common recovery scenario
        - Quick and targeted
        
        **System Recovery:**
        - Restore entire system or server
        - Used for hardware failures
        - Longer recovery time
        
        **Disaster Recovery:**
        - Restore entire infrastructure
        - Used for major disasters
        - Involves alternate facilities
        
        ### 📊 Backup Monitoring and Verification
        
        **Backup Monitoring:**
        - **Success/Failure Tracking**: Monitor backup job status
        - **Performance Metrics**: Backup duration, throughput
        - **Storage Usage**: Monitor backup storage consumption
        - **Alerting**: Notify on backup failures
        
        **Backup Verification:**
        - **Integrity Checks**: Verify backup data integrity
        - **Test Restores**: Regular recovery testing
        - **Checksum Validation**: Verify data hasn't changed
        - **Retention Management**: Manage backup lifecycle
        
        ### 🚨 Common Backup Challenges
        
        **Technical Challenges:**
        - **Large Data Volumes**: Backup window constraints
        - **Network Bandwidth**: Slow backup transfers
        - **Storage Costs**: Growing backup storage needs
        - **Complexity**: Multiple systems and applications
        
        **Operational Challenges:**
        - **Backup Windows**: Limited time for backups
        - **Recovery Testing**: Time and resource intensive
        - **Documentation**: Keeping procedures current
        - **Skills**: Trained backup administrators
        """)
    
    # Backup comparison table
    backup_data = [
        {"Backup Type": "Full", "Backup Time": "Long", "Storage Space": "High", "Recovery Time": "Fast", "Complexity": "Low"},
        {"Backup Type": "Incremental", "Backup Time": "Short", "Storage Space": "Low", "Recovery Time": "Slow", "Complexity": "High"},
        {"Backup Type": "Differential", "Backup Time": "Medium", "Storage Space": "Medium", "Recovery Time": "Medium", "Complexity": "Medium"},
        {"Backup Type": "Mirror", "Backup Time": "Medium", "Storage Space": "High", "Recovery Time": "Fast", "Complexity": "Low"}
    ]
    
    df = pd.DataFrame(backup_data)
    st.dataframe(df, width='stretch')

def explain_incident_management():
    """Giải thích Incident Management"""
    st.markdown("### 🚨 Incident Management")
    
    with st.expander("📖 Lý thuyết chi tiết về Incident Management"):
        st.markdown("""
        ### 🎯 What is Incident Management?
        
        **Definition:**
        - Process to manage IT service disruptions
        - Restore normal service operation quickly
        - Minimize impact on business operations
        - Part of ITIL framework
        
        **Goals:**
        - **Minimize Downtime**: Restore services quickly
        - **Reduce Impact**: Limit business disruption
        - **Prevent Recurrence**: Learn from incidents
        - **Improve Services**: Enhance service quality
        
        ### 🔄 Incident Management Process
        
        **1. Incident Detection**
        - **Monitoring Systems**: Automated alerts
        - **User Reports**: Help desk tickets
        - **Service Desk**: Phone calls, emails
        - **Proactive Monitoring**: Performance thresholds
        
        **2. Incident Logging**
        - **Record Details**: What, when, where, who
        - **Assign Ticket Number**: Unique identifier
        - **Initial Classification**: Priority and category
        - **Time Stamping**: Track response times
        
        **3. Incident Categorization**
        - **Service Type**: Email, network, application
        - **Incident Type**: Hardware, software, user error
        - **Configuration Item**: Affected system component
        - **Root Cause**: Initial assessment
        
        **4. Incident Prioritization**
        - **Impact Assessment**: How many users affected?
        - **Urgency Evaluation**: How quickly needs resolution?
        - **Priority Matrix**: Impact × Urgency = Priority
        - **SLA Mapping**: Service level agreement requirements
        
        **5. Initial Diagnosis**
        - **Symptom Analysis**: What is happening?
        - **Quick Fixes**: Known solutions
        - **Escalation Decision**: Can first level resolve?
        - **Workaround**: Temporary solution
        
        **6. Escalation**
        - **Functional Escalation**: To specialist teams
        - **Hierarchical Escalation**: To management
        - **Vendor Escalation**: To external suppliers
        - **Time-based Escalation**: Automatic escalation
        
        **7. Investigation and Diagnosis**
        - **Root Cause Analysis**: Why did it happen?
        - **Impact Assessment**: Full scope of problem
        - **Solution Development**: How to fix it?
        - **Testing**: Verify solution works
        
        **8. Resolution and Recovery**
        - **Implement Solution**: Apply the fix
        - **Test Resolution**: Verify it works
        - **Monitor System**: Ensure stability
        - **User Confirmation**: Verify user satisfaction
        
        **9. Incident Closure**
        - **Documentation**: Record resolution details
        - **User Notification**: Inform affected users
        - **Categorization**: Final incident classification
        - **Satisfaction Survey**: Gather feedback
        
        ### 📊 Incident Priority Matrix
        
        **Impact Levels:**
        - **High**: Multiple users/services affected
        - **Medium**: Single service or department affected
        - **Low**: Individual user affected
        
        **Urgency Levels:**
        - **High**: Business critical, immediate attention
        - **Medium**: Important, resolve within hours
        - **Low**: Can wait, resolve within days
        
        **Priority Calculation:**
        - **Critical (P1)**: High Impact + High Urgency
        - **High (P2)**: High Impact + Medium Urgency OR Medium Impact + High Urgency
        - **Medium (P3)**: Medium Impact + Medium Urgency OR Low Impact + High Urgency
        - **Low (P4)**: Low Impact + Medium/Low Urgency
        
        ### ⏱️ Service Level Agreements (SLAs)
        
        **Response Times:**
        - **P1 Critical**: 15 minutes response, 4 hours resolution
        - **P2 High**: 1 hour response, 8 hours resolution
        - **P3 Medium**: 4 hours response, 24 hours resolution
        - **P4 Low**: 8 hours response, 72 hours resolution
        
        **SLA Metrics:**
        - **First Call Resolution**: Percentage resolved on first contact
        - **Mean Time to Repair (MTTR)**: Average resolution time
        - **Customer Satisfaction**: User satisfaction scores
        - **SLA Compliance**: Percentage meeting SLA targets
        
        ### 🛠️ Incident Management Tools
        
        **Service Desk Software:**
        - **ServiceNow**: Enterprise ITSM platform
        - **Remedy**: BMC's ITSM solution
        - **Jira Service Management**: Atlassian's service desk
        - **Freshservice**: Cloud-based service desk
        
        **Monitoring Tools:**
        - **Nagios**: Infrastructure monitoring
        - **SolarWinds**: Network and system monitoring
        - **PRTG**: Network monitoring
        - **Datadog**: Cloud monitoring and analytics
        
        **Communication Tools:**
        - **Slack**: Team collaboration
        - **Microsoft Teams**: Unified communications
        - **PagerDuty**: Incident response platform
        - **Opsgenie**: Alert and incident management
        
        ### 📈 Incident Management Metrics
        
        **Volume Metrics:**
        - **Incident Count**: Total number of incidents
        - **Incident Rate**: Incidents per time period
        - **Trend Analysis**: Increasing or decreasing trends
        
        **Performance Metrics:**
        - **Response Time**: Time to initial response
        - **Resolution Time**: Time to resolve incident
        - **First Call Resolution**: Resolved on first contact
        - **Escalation Rate**: Percentage requiring escalation
        
        **Quality Metrics:**
        - **Customer Satisfaction**: User satisfaction scores
        - **Repeat Incidents**: Same issue recurring
        - **SLA Compliance**: Meeting service level agreements
        - **Root Cause Identification**: Percentage with known cause
        
        ### 🔄 Continuous Improvement
        
        **Post-Incident Review:**
        - **What Happened**: Incident timeline
        - **Root Cause**: Why it happened
        - **Response Evaluation**: How well did we respond?
        - **Lessons Learned**: What can we improve?
        
        **Process Improvement:**
        - **Knowledge Base**: Update known solutions
        - **Training**: Improve staff skills
        - **Tools**: Enhance monitoring and alerting
        - **Procedures**: Update incident procedures
        
        **Preventive Measures:**
        - **Problem Management**: Address root causes
        - **Change Management**: Control system changes
        - **Capacity Management**: Prevent resource issues
        - **Availability Management**: Improve service reliability
        """)
    
    # Incident priority matrix
    priority_data = [
        {"Priority": "P1 - Critical", "Impact": "High", "Urgency": "High", "Response Time": "15 minutes", "Resolution Time": "4 hours"},
        {"Priority": "P2 - High", "Impact": "High/Medium", "Urgency": "Medium/High", "Response Time": "1 hour", "Resolution Time": "8 hours"},
        {"Priority": "P3 - Medium", "Impact": "Medium/Low", "Urgency": "Medium/High", "Response Time": "4 hours", "Resolution Time": "24 hours"},
        {"Priority": "P4 - Low", "Impact": "Low", "Urgency": "Low/Medium", "Response Time": "8 hours", "Resolution Time": "72 hours"}
    ]
    
    df = pd.DataFrame(priority_data)
    st.dataframe(df, width='stretch')

def system_administration_lab():
    """Lab về quản trị hệ thống"""
    st.subheader("🔧 System Administration Lab")
    
    topic_choice = st.selectbox("Chọn chủ đề:", [
        "User Management",
        "System Monitoring",
        "Backup & Recovery",
        "Performance Tuning",
        "Security Hardening"
    ])
    
    if topic_choice == "User Management":
        explain_user_management()
    elif topic_choice == "System Monitoring":
        explain_system_monitoring()
    elif topic_choice == "Backup & Recovery":
        explain_backup_recovery()
    elif topic_choice == "Performance Tuning":
        explain_performance_tuning()
    elif topic_choice == "Security Hardening":
        explain_security_hardening()

def explain_user_management():
    """Giải thích quản lý người dùng"""
    st.markdown("### 👥 User Management")
    
    with st.expander("📖 Lý thuyết chi tiết về User Management"):
        st.markdown("""
        ### 🎯 User Account Management
        
        **User Accounts** là foundation của system security:
        
        **👤 Account Types:**
        
        **1. Administrator/Root Accounts**
        - **Privileges**: Full system access
        - **Responsibilities**: System configuration, user management
        - **Security**: Should be used sparingly, logged extensively
        
        **2. Standard User Accounts**
        - **Privileges**: Limited system access
        - **Usage**: Daily work, applications
        - **Security**: Principle of least privilege
        
        **3. Service Accounts**
        - **Purpose**: Run system services
        - **Characteristics**: Non-interactive, specific permissions
        - **Security**: Strong passwords, limited access
        
        **4. Guest Accounts**
        - **Purpose**: Temporary access
        - **Privileges**: Very limited
        - **Security**: Disabled by default in secure environments
        
        ### 🔐 Authentication Methods
        
        **1. Password-based Authentication**
        - **Requirements**: Complexity, length, expiration
        - **Storage**: Hashed và salted
        - **Policies**: Lockout, history, minimum age
        
        **2. Multi-Factor Authentication (MFA)**
        - **Something you know**: Password, PIN
        - **Something you have**: Token, smart card
        - **Something you are**: Biometrics
        
        **3. Certificate-based Authentication**
        - **PKI**: Public Key Infrastructure
        - **Digital Certificates**: X.509 certificates
        - **Smart Cards**: Hardware-based certificates
        
        ### 👥 Group Management
        
        **Security Groups:**
        - **Purpose**: Organize users with similar access needs
        - **Benefits**: Easier permission management
        - **Types**: Local groups, domain groups
        
        **Group Policies:**
        - **Windows**: Group Policy Objects (GPOs)
        - **Linux**: sudoers file, PAM configuration
        - **Scope**: User settings, computer settings
        
        ### 🔧 Linux User Management Commands
        
        **User Operations:**
        ```bash
        # Add user
        sudo useradd -m -s /bin/bash username
        
        # Set password
        sudo passwd username
        
        # Modify user
        sudo usermod -aG groupname username
        
        # Delete user
        sudo userdel -r username
        
        # List users
        cat /etc/passwd
        ```
        
        **Group Operations:**
        ```bash
        # Add group
        sudo groupadd groupname
        
        # Add user to group
        sudo usermod -aG groupname username
        
        # List groups
        cat /etc/group
        
        # Show user groups
        groups username
        ```
        
        ### 🛡️ Security Best Practices
        
        **Account Security:**
        - **Strong passwords**: Complexity requirements
        - **Account lockout**: Prevent brute force attacks
        - **Regular audits**: Review account usage
        - **Disable unused accounts**: Remove inactive accounts
        
        **Privilege Management:**
        - **Least privilege**: Minimum necessary access
        - **Regular reviews**: Periodic access reviews
        - **Separation of duties**: Divide critical functions
        - **Privileged access management**: Control admin access
        """)

def explain_performance_tuning():
    """Giải thích Performance Tuning"""
    st.markdown("### ⚡ Performance Tuning")
    
    with st.expander("📖 Lý thuyết chi tiết về Performance Tuning"):
        st.markdown("""
        ### 🎯 Performance Tuning Fundamentals
        
        **Performance Tuning** là quá trình tối ưu hóa hiệu suất hệ thống:
        
        ### 📊 Performance Metrics
        
        **System Performance Indicators:**
        
        **CPU Performance:**
        - **CPU Utilization**: Percentage of CPU usage
        - **Load Average**: System load over time
        - **Context Switches**: Process switching frequency
        - **Interrupts**: Hardware interrupt frequency
        
        **Memory Performance:**
        - **Memory Utilization**: RAM usage percentage
        - **Page Faults**: Virtual memory page faults
        - **Swap Usage**: Virtual memory swap usage
        - **Cache Hit Ratio**: Memory cache effectiveness
        
        **Disk I/O Performance:**
        - **IOPS**: Input/Output Operations Per Second
        - **Throughput**: Data transfer rate (MB/s)
        - **Latency**: Response time for I/O operations
        - **Queue Depth**: Pending I/O operations
        
        **Network Performance:**
        - **Bandwidth Utilization**: Network usage percentage
        - **Packet Loss**: Lost network packets
        - **Latency**: Network response time
        - **Connections**: Active network connections
        
        ### 🔧 CPU Optimization
        
        **CPU Tuning Strategies:**
        
        **Process Priority Management:**
        - **Nice Values**: Adjust process priority (-20 to 19)
        - **Real-time Scheduling**: Critical process scheduling
        - **CPU Affinity**: Bind processes to specific CPUs
        - **Load Balancing**: Distribute load across cores
        
        **CPU Governor Settings:**
        - **Performance**: Maximum CPU frequency
        - **Powersave**: Minimum CPU frequency
        - **Ondemand**: Dynamic frequency scaling
        - **Conservative**: Gradual frequency changes
        
        **Application Optimization:**
        - **Multi-threading**: Parallel processing
        - **Algorithm Optimization**: Efficient algorithms
        - **Compiler Optimization**: Optimized compilation
        - **Code Profiling**: Identify bottlenecks
        
        ### 💾 Memory Optimization
        
        **Memory Tuning Techniques:**
        
        **Virtual Memory Management:**
        - **Swappiness**: Control swap usage (0-100)
        - **Dirty Ratio**: Control write-back behavior
        - **VM Overcommit**: Memory overcommitment settings
        - **Huge Pages**: Large memory pages for performance
        
        **Memory Allocation:**
        - **Memory Pools**: Pre-allocated memory blocks
        - **Garbage Collection**: Automatic memory cleanup
        - **Memory Mapping**: Efficient file access
        - **NUMA Optimization**: Non-Uniform Memory Access
        
        **Cache Optimization:**
        - **CPU Cache**: L1, L2, L3 cache optimization
        - **Page Cache**: File system cache tuning
        - **Buffer Cache**: Disk buffer optimization
        - **Application Cache**: Application-level caching
        
        ### 💿 Storage Optimization
        
        **Disk Performance Tuning:**
        
        **File System Optimization:**
        - **File System Choice**: ext4, XFS, Btrfs selection
        - **Mount Options**: noatime, relatime, barrier
        - **Block Size**: Optimal block size selection
        - **Journaling**: Journal optimization settings
        
        **I/O Scheduling:**
        - **CFQ**: Completely Fair Queuing
        - **Deadline**: Deadline scheduler
        - **NOOP**: No-operation scheduler
        - **mq-deadline**: Multi-queue deadline
        
        **Storage Configuration:**
        - **RAID Configuration**: RAID level selection
        - **SSD Optimization**: TRIM, alignment, over-provisioning
        - **Partition Alignment**: 4K sector alignment
        - **LVM Optimization**: Logical volume management
        
        ### 🌐 Network Optimization
        
        **Network Performance Tuning:**
        
        **TCP/IP Stack Tuning:**
        - **TCP Window Scaling**: Large window sizes
        - **TCP Congestion Control**: CUBIC, BBR algorithms
        - **Buffer Sizes**: Send/receive buffer optimization
        - **Connection Limits**: Maximum connection settings
        
        **Network Interface Optimization:**
        - **Interrupt Coalescing**: Reduce interrupt overhead
        - **Ring Buffer Size**: Network buffer optimization
        - **Offloading**: Hardware acceleration features
        - **Multi-queue**: Multiple network queues
        
        **Application-level Optimization:**
        - **Connection Pooling**: Reuse network connections
        - **Compression**: Reduce network traffic
        - **Caching**: Reduce network requests
        - **CDN Usage**: Content delivery networks
        
        ### 📈 Performance Monitoring Tools
        
        **System Monitoring:**
        - **top/htop**: Real-time process monitoring
        - **iostat**: I/O statistics
        - **vmstat**: Virtual memory statistics
        - **netstat**: Network statistics
        - **sar**: System activity reporter
        
        **Advanced Monitoring:**
        - **perf**: Linux performance analysis
        - **strace**: System call tracing
        - **tcpdump**: Network packet analysis
        - **iotop**: I/O monitoring by process
        - **nmon**: Comprehensive system monitor
        
        **Application Profiling:**
        - **gprof**: GNU profiler
        - **Valgrind**: Memory and performance analysis
        - **Intel VTune**: Intel performance profiler
        - **JProfiler**: Java application profiler
        
        ### 🎯 Performance Tuning Methodology
        
        **Systematic Approach:**
        
        **1. Baseline Measurement:**
        - **Current Performance**: Measure existing performance
        - **Bottleneck Identification**: Find performance constraints
        - **Workload Analysis**: Understand system usage patterns
        - **Resource Utilization**: Monitor resource consumption
        
        **2. Optimization Planning:**
        - **Priority Setting**: Focus on biggest bottlenecks
        - **Change Planning**: Plan optimization changes
        - **Risk Assessment**: Evaluate optimization risks
        - **Rollback Planning**: Prepare rollback procedures
        
        **3. Implementation:**
        - **Incremental Changes**: Make small, measurable changes
        - **Testing**: Validate each optimization
        - **Monitoring**: Track performance improvements
        - **Documentation**: Record all changes
        
        **4. Validation:**
        - **Performance Testing**: Verify improvements
        - **Stability Testing**: Ensure system stability
        - **Load Testing**: Test under realistic loads
        - **Regression Testing**: Check for negative impacts
        
        ### 🏗️ Application-Specific Tuning
        
        **Database Performance:**
        - **Query Optimization**: Efficient SQL queries
        - **Index Optimization**: Proper database indexing
        - **Connection Pooling**: Database connection management
        - **Buffer Pool Tuning**: Database cache optimization
        
        **Web Server Performance:**
        - **Worker Processes**: Optimal process/thread count
        - **Keep-Alive**: Connection reuse
        - **Compression**: Content compression
        - **Static Content**: Efficient static file serving
        
        **Application Server:**
        - **JVM Tuning**: Java Virtual Machine optimization
        - **Garbage Collection**: GC algorithm selection
        - **Thread Pool**: Thread management optimization
        - **Memory Settings**: Heap and stack optimization
        
        ### 📊 Performance Testing
        
        **Load Testing:**
        - **Stress Testing**: Maximum load capacity
        - **Volume Testing**: Large data volumes
        - **Endurance Testing**: Long-term performance
        - **Spike Testing**: Sudden load increases
        
        **Testing Tools:**
        - **Apache Bench**: Simple HTTP load testing
        - **JMeter**: Comprehensive load testing
        - **Gatling**: High-performance load testing
        - **LoadRunner**: Enterprise load testing
        
        ### 🔄 Continuous Performance Optimization
        
        **Ongoing Optimization:**
        - **Regular Monitoring**: Continuous performance tracking
        - **Trend Analysis**: Performance trend identification
        - **Proactive Tuning**: Prevent performance degradation
        - **Capacity Planning**: Plan for future growth
        
        **Performance Culture:**
        - **Performance Awareness**: Team performance consciousness
        - **Performance Goals**: Clear performance targets
        - **Performance Reviews**: Regular performance assessments
        - **Knowledge Sharing**: Share optimization techniques
        """)
    
    # Performance metrics comparison
    st.markdown("#### ⚡ Performance Optimization Areas")
    
    perf_data = [
        {"Component": "CPU", "Key Metrics": "Utilization, Load Average", "Tuning Focus": "Process Priority, Scheduling", "Tools": "top, perf, taskset"},
        {"Component": "Memory", "Key Metrics": "Usage, Page Faults", "Tuning Focus": "Swappiness, Cache", "Tools": "free, vmstat, pmap"},
        {"Component": "Storage", "Key Metrics": "IOPS, Throughput", "Tuning Focus": "I/O Scheduler, File System", "Tools": "iostat, iotop, hdparm"},
        {"Component": "Network", "Key Metrics": "Bandwidth, Latency", "Tuning Focus": "TCP Tuning, Buffers", "Tools": "netstat, iftop, tcpdump"},
        {"Component": "Application", "Key Metrics": "Response Time, Throughput", "Tuning Focus": "Code, Configuration", "Tools": "Profilers, APM tools"}
    ]
    
    df = pd.DataFrame(perf_data)
    st.dataframe(df, width='stretch')

def explain_security_hardening():
    """Giải thích Security Hardening"""
    st.markdown("### 🛡️ Security Hardening")
    
    with st.expander("📖 Lý thuyết chi tiết về Security Hardening"):
        st.markdown("""
        ### 🎯 Security Hardening Fundamentals
        
        **Security Hardening** là quá trình tăng cường bảo mật hệ thống:
        
        ### 🔒 Operating System Hardening
        
        **System Configuration:**
        
        **User Account Security:**
        - **Strong Password Policy**: Complex password requirements
        - **Account Lockout**: Lock accounts after failed attempts
        - **Disable Unused Accounts**: Remove or disable unnecessary accounts
        - **Privilege Separation**: Separate administrative and user accounts
        
        **Service Management:**
        - **Disable Unnecessary Services**: Stop unused network services
        - **Service Configuration**: Secure service configurations
        - **Port Management**: Close unnecessary network ports
        - **Default Credentials**: Change all default passwords
        
        **File System Security:**
        - **File Permissions**: Proper file and directory permissions
        - **Access Control Lists**: Fine-grained access control
        - **Sensitive File Protection**: Secure configuration files
        - **Log File Security**: Protect system logs
        
        ### 🌐 Network Hardening
        
        **Network Security Configuration:**
        
        **Firewall Configuration:**
        - **Default Deny**: Block all traffic by default
        - **Minimal Rules**: Only allow necessary traffic
        - **Stateful Inspection**: Track connection states
        - **Regular Review**: Periodic rule review
        
        **Network Services:**
        - **SSH Hardening**: Secure SSH configuration
        - **SSL/TLS Configuration**: Strong encryption settings
        - **Network Protocols**: Disable insecure protocols
        - **Remote Access**: Secure remote access methods
        
        **Network Monitoring:**
        - **Intrusion Detection**: Monitor for attacks
        - **Log Analysis**: Analyze network logs
        - **Traffic Monitoring**: Monitor network traffic
        - **Anomaly Detection**: Detect unusual activity
        
        ### 🔐 Access Control Hardening
        
        **Authentication Hardening:**
        
        **Multi-Factor Authentication:**
        - **Two-Factor Authentication**: Something you know + have
        - **Biometric Authentication**: Fingerprint, face recognition
        - **Smart Cards**: Hardware-based authentication
        - **Token-based Authentication**: Time-based tokens
        
        **Authorization Controls:**
        - **Role-Based Access Control**: Access based on roles
        - **Principle of Least Privilege**: Minimum necessary access
        - **Separation of Duties**: Divide critical functions
        - **Regular Access Review**: Periodic access audits
        
        **Session Management:**
        - **Session Timeouts**: Automatic session expiration
        - **Session Encryption**: Encrypt session data
        - **Session Monitoring**: Monitor active sessions
        - **Concurrent Session Limits**: Limit simultaneous sessions
        
        ### 📱 Application Hardening
        
        **Application Security:**
        
        **Input Validation:**
        - **Data Sanitization**: Clean input data
        - **Parameter Validation**: Validate all parameters
        - **SQL Injection Prevention**: Parameterized queries
        - **XSS Prevention**: Cross-site scripting protection
        
        **Application Configuration:**
        - **Secure Defaults**: Security-focused default settings
        - **Error Handling**: Don't expose sensitive information
        - **Debug Mode**: Disable debug mode in production
        - **Version Disclosure**: Hide application versions
        
        **Code Security:**
        - **Secure Coding Practices**: Follow security guidelines
        - **Code Review**: Regular security code reviews
        - **Static Analysis**: Automated code security scanning
        - **Dependency Management**: Secure third-party libraries
        
        ### 🗄️ Database Hardening
        
        **Database Security:**
        
        **Access Control:**
        - **Database Users**: Separate application and admin users
        - **Privilege Management**: Grant minimal necessary privileges
        - **Connection Security**: Encrypt database connections
        - **Authentication**: Strong database authentication
        
        **Data Protection:**
        - **Data Encryption**: Encrypt sensitive data at rest
        - **Backup Security**: Secure database backups
        - **Data Masking**: Hide sensitive data in non-production
        - **Audit Logging**: Log database access and changes
        
        **Configuration Security:**
        - **Default Settings**: Change default database settings
        - **Network Configuration**: Secure network access
        - **File Permissions**: Secure database files
        - **Service Account**: Use dedicated service accounts
        
        ### ☁️ Cloud Security Hardening
        
        **Cloud Infrastructure Security:**
        
        **Identity and Access Management:**
        - **IAM Policies**: Granular access policies
        - **Service Accounts**: Dedicated service accounts
        - **API Key Management**: Secure API key handling
        - **Cross-Account Access**: Secure cross-account permissions
        
        **Network Security:**
        - **Virtual Private Cloud**: Isolated network environments
        - **Security Groups**: Network-level firewalls
        - **Network ACLs**: Subnet-level access control
        - **VPN/Private Connectivity**: Secure network connections
        
        **Data Security:**
        - **Encryption at Rest**: Encrypt stored data
        - **Encryption in Transit**: Encrypt data transmission
        - **Key Management**: Secure encryption key management
        - **Data Classification**: Classify and protect data
        
        ### 🔍 Security Monitoring and Logging
        
        **Logging Configuration:**
        
        **System Logging:**
        - **Comprehensive Logging**: Log security-relevant events
        - **Log Centralization**: Central log management
        - **Log Integrity**: Protect logs from tampering
        - **Log Retention**: Appropriate log retention periods
        
        **Security Monitoring:**
        - **Real-time Monitoring**: Continuous security monitoring
        - **Alert Configuration**: Configure security alerts
        - **Incident Response**: Automated incident response
        - **Threat Detection**: Advanced threat detection
        
        **Compliance Monitoring:**
        - **Compliance Frameworks**: Meet regulatory requirements
        - **Audit Trails**: Maintain audit trails
        - **Reporting**: Generate compliance reports
        - **Continuous Compliance**: Ongoing compliance monitoring
        
        ### 🛠️ Hardening Tools and Automation
        
        **Security Scanning Tools:**
        - **Vulnerability Scanners**: Nessus, OpenVAS, Qualys
        - **Configuration Scanners**: Nmap, Nikto, Lynis
        - **Compliance Scanners**: SCAP, CIS-CAT
        - **Web Application Scanners**: OWASP ZAP, Burp Suite
        
        **Hardening Frameworks:**
        - **CIS Benchmarks**: Center for Internet Security guidelines
        - **NIST Guidelines**: National Institute of Standards
        - **SANS Guidelines**: SANS Institute recommendations
        - **OWASP Guidelines**: Web application security guidelines
        
        **Automation Tools:**
        - **Configuration Management**: Ansible, Puppet, Chef
        - **Infrastructure as Code**: Terraform, CloudFormation
        - **Security Orchestration**: SOAR platforms
        - **Continuous Compliance**: Automated compliance checking
        
        ### 📋 Hardening Checklists
        
        **Operating System Checklist:**
        - [ ] Update system and applications
        - [ ] Configure strong password policy
        - [ ] Disable unnecessary services
        - [ ] Configure firewall rules
        - [ ] Set proper file permissions
        - [ ] Enable system logging
        - [ ] Configure user access controls
        - [ ] Install security updates
        
        **Network Security Checklist:**
        - [ ] Configure network firewall
        - [ ] Disable unnecessary protocols
        - [ ] Secure remote access
        - [ ] Enable network monitoring
        - [ ] Configure intrusion detection
        - [ ] Secure wireless networks
        - [ ] Implement network segmentation
        - [ ] Regular security assessments
        
        **Application Security Checklist:**
        - [ ] Secure application configuration
        - [ ] Implement input validation
        - [ ] Configure secure authentication
        - [ ] Enable application logging
        - [ ] Secure data transmission
        - [ ] Regular security testing
        - [ ] Update application dependencies
        - [ ] Implement error handling
        
        ### 🔄 Continuous Hardening
        
        **Ongoing Security Maintenance:**
        - **Regular Updates**: Keep systems updated
        - **Security Assessments**: Periodic security reviews
        - **Vulnerability Management**: Track and fix vulnerabilities
        - **Configuration Drift**: Monitor configuration changes
        
        **Security Culture:**
        - **Security Training**: Regular security education
        - **Security Awareness**: Promote security consciousness
        - **Incident Response**: Prepare for security incidents
        - **Continuous Improvement**: Enhance security over time
        """)
    
    # Security hardening areas comparison
    st.markdown("#### 🛡️ Security Hardening Areas")
    
    hardening_data = [
        {"Area": "Operating System", "Priority": "High", "Complexity": "Medium", "Key Actions": "Updates, Services, Permissions"},
        {"Area": "Network", "Priority": "High", "Complexity": "High", "Key Actions": "Firewall, Monitoring, Segmentation"},
        {"Area": "Applications", "Priority": "High", "Complexity": "Medium", "Key Actions": "Input Validation, Authentication"},
        {"Area": "Database", "Priority": "Medium", "Complexity": "Medium", "Key Actions": "Access Control, Encryption"},
        {"Area": "Cloud", "Priority": "High", "Complexity": "High", "Key Actions": "IAM, Network Security, Encryption"}
    ]
    
    df = pd.DataFrame(hardening_data)
    st.dataframe(df, width='stretch')

def it_service_management_lab():
    """Lab về quản lý dịch vụ IT"""
    st.subheader("📊 IT Service Management Lab")
    
    topic_choice = st.selectbox("Chọn chủ đề:", [
        "ITIL Framework",
        "Incident Management",
        "Change Management",
        "Service Level Management",
        "IT Governance"
    ])
    
    if topic_choice == "ITIL Framework":
        explain_itil_framework()
    elif topic_choice == "Incident Management":
        explain_incident_management()
    elif topic_choice == "Change Management":
        explain_change_management()
    elif topic_choice == "Service Level Management":
        explain_service_level_management()
    elif topic_choice == "IT Governance":
        explain_it_governance()

def explain_itil_framework():
    """Giải thích ITIL framework"""
    st.markdown("### 📋 ITIL Framework")
    
    with st.expander("📖 Lý thuyết chi tiết về ITIL"):
        st.markdown("""
        ### 🎯 ITIL (Information Technology Infrastructure Library)
        
        **ITIL** là best practice framework cho IT Service Management:
        
        **📊 ITIL 4 Service Value System:**
        
        **1. Service Value Chain**
        - **Plan**: Strategy và portfolio decisions
        - **Improve**: Continual improvement
        - **Engage**: Stakeholder relationships
        - **Design & Transition**: New/changed services
        - **Obtain/Build**: Service components
        - **Deliver & Support**: Service delivery
        
        **2. Guiding Principles**
        - **Focus on value**: Everything creates value
        - **Start where you are**: Use existing capabilities
        - **Progress iteratively**: Small steps with feedback
        - **Collaborate**: Work together transparently
        - **Think holistically**: End-to-end service view
        - **Keep it simple**: Eliminate unnecessary complexity
        - **Optimize và automate**: Efficiency through technology
        
        **3. Governance**
        - **Direction**: Strategic direction
        - **Evaluation**: Performance monitoring
        - **Oversight**: Risk management
        
        **4. Service Value Chain Activities**
        
        **Plan:**
        - Strategic planning
        - Portfolio management
        - Architecture management
        
        **Improve:**
        - Continual improvement
        - Performance measurement
        - Knowledge management
        
        **Engage:**
        - Relationship management
        - Supplier management
        - Service desk
        
        **Design & Transition:**
        - Service design
        - Change enablement
        - Release management
        
        **Obtain/Build:**
        - Infrastructure management
        - Software development
        - Deployment management
        
        **Deliver & Support:**
        - Incident management
        - Problem management
        - Service request fulfillment
        
        ### 🔧 Key ITIL Processes
        
        **Service Strategy:**
        - Service portfolio management
        - Financial management
        - Demand management
        
        **Service Design:**
        - Service level management
        - Capacity management
        - Availability management
        - Security management
        
        **Service Transition:**
        - Change management
        - Release management
        - Configuration management
        
        **Service Operation:**
        - Incident management
        - Problem management
        - Event management
        - Access management
        
        **Continual Service Improvement:**
        - Performance measurement
        - Process improvement
        - Service reporting
        """)

# Helper Functions
def generate_system_info():
    """Generate sample system information"""
    cpus = ["Intel Core i7-12700K", "AMD Ryzen 7 5800X", "Intel Core i5-11600K", "AMD Ryzen 5 5600X"]
    
    return {
        'cpu': random.choice(cpus),
        'cores': random.choice([6, 8, 12, 16]),
        'threads': random.choice([12, 16, 24, 32]),
        'clock_speed': round(random.uniform(3.0, 4.5), 1),
        'l1_cache': random.choice([32, 64]),
        'l2_cache': random.choice([256, 512, 1024]),
        'l3_cache': random.choice([8, 16, 20, 32]),
        'ram': random.choice([8, 16, 32, 64]),
        'storage': random.choice([256, 512, 1024, 2048])
    }

def calculate_subnet_info(ip_address, subnet_mask):
    """Calculate subnet information"""
    # Simplified subnet calculation for demonstration
    mask_bits = int(subnet_mask[1:])
    host_bits = 32 - mask_bits
    total_hosts = 2 ** host_bits
    usable_hosts = total_hosts - 2
    
    # Parse IP address
    ip_parts = ip_address.split('.')
    base_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0"
    
    return {
        'network': f"{base_ip}{subnet_mask}",
        'broadcast': f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{total_hosts - 1}",
        'mask': f"255.255.255.{256 - (2 ** (8 - (mask_bits % 8))) if mask_bits % 8 != 0 else 0}",
        'total_hosts': total_hosts,
        'usable_hosts': usable_hosts,
        'first_host': f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1",
        'last_host': f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{total_hosts - 2}"
    }

def explain_change_management():
    """Giải thích Change Management"""
    st.markdown("### 🔄 Change Management")
    
    with st.expander("📖 Lý thuyết chi tiết về Change Management"):
        st.markdown("""
        ### 🎯 Change Management Fundamentals
        
        **Change Management** là quá trình kiểm soát và quản lý các thay đổi trong môi trường IT:
        
        ### 📋 Change Management Process
        
        **Change Lifecycle:**
        
        **1. Change Request (RFC - Request for Change)**
        - **Initiation**: Identify need for change
        - **Documentation**: Detailed change description
        - **Business Justification**: Why change is needed
        - **Impact Assessment**: Potential risks and benefits
        
        **2. Change Assessment**
        - **Technical Review**: Technical feasibility
        - **Risk Assessment**: Identify potential risks
        - **Resource Requirements**: People, time, budget
        - **Dependencies**: Related systems and services
        
        **3. Change Authorization**
        - **Change Advisory Board (CAB)**: Review and approve
        - **Emergency CAB**: For urgent changes
        - **Authorization Levels**: Based on risk and impact
        - **Approval Documentation**: Formal approval records
        
        **4. Change Implementation**
        - **Implementation Planning**: Detailed execution plan
        - **Testing**: Validate changes in test environment
        - **Deployment**: Execute change in production
        - **Monitoring**: Track implementation progress
        
        **5. Change Review**
        - **Post-Implementation Review (PIR)**: Evaluate success
        - **Lessons Learned**: Capture improvement opportunities
        - **Documentation Update**: Update procedures and documentation
        - **Closure**: Formally close change record
        
        ### 🏗️ Change Categories
        
        **By Impact and Risk:**
        
        **Standard Changes:**
        - **Pre-approved**: Low risk, routine changes
        - **Automated**: Can be automated
        - **Examples**: Password resets, standard software installations
        - **Process**: Simplified approval process
        
        **Normal Changes:**
        - **CAB Review**: Requires Change Advisory Board review
        - **Medium Risk**: Moderate impact and risk
        - **Examples**: System updates, configuration changes
        - **Process**: Full change management process
        
        **Emergency Changes:**
        - **Urgent**: Critical business impact
        - **Fast-track**: Expedited approval process
        - **Examples**: Security patches, system failures
        - **Process**: Emergency CAB approval
        
        **Major Changes:**
        - **High Impact**: Significant business impact
        - **High Risk**: Potential for major disruption
        - **Examples**: Infrastructure upgrades, new system deployments
        - **Process**: Extended review and approval
        
        ### 👥 Change Management Roles
        
        **Change Manager:**
        - **Process Owner**: Owns change management process
        - **Coordination**: Coordinate change activities
        - **Reporting**: Change management reporting
        - **Process Improvement**: Continuous improvement
        
        **Change Advisory Board (CAB):**
        - **Multi-disciplinary**: Representatives from different areas
        - **Decision Making**: Approve/reject changes
        - **Risk Assessment**: Evaluate change risks
        - **Prioritization**: Prioritize changes
        
        **Change Implementer:**
        - **Technical Execution**: Implement approved changes
        - **Testing**: Validate changes
        - **Documentation**: Update technical documentation
        - **Rollback**: Execute rollback if needed
        
        **Change Requester:**
        - **Business Need**: Identify need for change
        - **Requirements**: Define change requirements
        - **Acceptance**: Accept implemented change
        - **Feedback**: Provide feedback on change
        
        ### 🔍 Change Assessment Criteria
        
        **Risk Assessment:**
        - **Technical Risk**: Implementation complexity
        - **Business Risk**: Impact on business operations
        - **Security Risk**: Security implications
        - **Compliance Risk**: Regulatory compliance impact
        
        **Impact Assessment:**
        - **Service Impact**: Effect on IT services
        - **User Impact**: Effect on end users
        - **Business Impact**: Effect on business processes
        - **Financial Impact**: Cost and budget implications
        
        **Resource Assessment:**
        - **Human Resources**: Required skills and availability
        - **Technical Resources**: Infrastructure and tools
        - **Time Requirements**: Implementation timeline
        - **Budget Requirements**: Financial resources needed
        
        ### 📊 Change Management Metrics
        
        **Process Metrics:**
        - **Change Success Rate**: Percentage of successful changes
        - **Change Volume**: Number of changes per period
        - **Change Velocity**: Time from request to implementation
        - **Emergency Changes**: Percentage of emergency changes
        
        **Quality Metrics:**
        - **Failed Changes**: Changes that failed or caused incidents
        - **Rollback Rate**: Percentage of changes rolled back
        - **Unauthorized Changes**: Changes made without approval
        - **Change-related Incidents**: Incidents caused by changes
        
        **Efficiency Metrics:**
        - **Approval Time**: Time to approve changes
        - **Implementation Time**: Time to implement changes
        - **Resource Utilization**: Efficient use of resources
        - **Cost per Change**: Average cost of changes
        
        ### 🛠️ Change Management Tools
        
        **Change Management Systems:**
        - **ServiceNow**: Comprehensive ITSM platform
        - **Remedy**: BMC Remedy ITSM
        - **Jira Service Management**: Atlassian ITSM solution
        - **Cherwell**: IT service management platform
        
        **Configuration Management:**
        - **CMDB Integration**: Link changes to configuration items
        - **Impact Analysis**: Understand change dependencies
        - **Version Control**: Track configuration versions
        - **Baseline Management**: Maintain configuration baselines
        
        **Automation Tools:**
        - **Deployment Automation**: Automated change deployment
        - **Testing Automation**: Automated change testing
        - **Approval Workflows**: Automated approval routing
        - **Notification Systems**: Automated stakeholder notifications
        
        ### 🎯 Change Management Best Practices
        
        **Planning and Preparation:**
        - **Change Calendar**: Coordinate change schedules
        - **Blackout Periods**: Avoid changes during critical periods
        - **Change Windows**: Designated times for changes
        - **Rollback Planning**: Always have a rollback plan
        
        **Communication:**
        - **Stakeholder Engagement**: Involve all affected parties
        - **Clear Communication**: Use clear, understandable language
        - **Regular Updates**: Keep stakeholders informed
        - **Change Notifications**: Notify users of upcoming changes
        
        **Risk Management:**
        - **Risk Assessment**: Thorough risk evaluation
        - **Risk Mitigation**: Plans to reduce risks
        - **Testing**: Comprehensive testing before implementation
        - **Monitoring**: Continuous monitoring during and after changes
        
        ### 🔄 Change Management Integration
        
        **ITIL Integration:**
        - **Incident Management**: Changes may be triggered by incidents
        - **Problem Management**: Changes may resolve problems
        - **Release Management**: Coordinate with release processes
        - **Configuration Management**: Update CMDB with changes
        
        **DevOps Integration:**
        - **Continuous Integration**: Integrate with CI/CD pipelines
        - **Automated Testing**: Automated change validation
        - **Infrastructure as Code**: Version-controlled infrastructure
        - **Monitoring**: Continuous monitoring and feedback
        
        **Agile Integration:**
        - **Sprint Planning**: Include changes in sprint planning
        - **User Stories**: Changes as user stories
        - **Retrospectives**: Learn from change experiences
        - **Continuous Improvement**: Iterative process improvement
        
        ### 📈 Change Management Maturity
        
        **Maturity Levels:**
        
        **Level 1 - Initial:**
        - **Ad-hoc**: Informal change processes
        - **Reactive**: Changes made reactively
        - **Limited Control**: Minimal change control
        - **High Risk**: High failure rates
        
        **Level 2 - Repeatable:**
        - **Basic Process**: Basic change procedures
        - **Some Control**: Some change control measures
        - **Documentation**: Basic change documentation
        - **Improving**: Gradual improvement
        
        **Level 3 - Defined:**
        - **Formal Process**: Well-defined change process
        - **Consistent**: Consistent process execution
        - **Roles Defined**: Clear roles and responsibilities
        - **Metrics**: Basic change metrics
        
        **Level 4 - Managed:**
        - **Measured**: Process performance measured
        - **Predictable**: Predictable change outcomes
        - **Continuous Monitoring**: Ongoing process monitoring
        - **Data-driven**: Data-driven decisions
        
        **Level 5 - Optimizing:**
        - **Continuous Improvement**: Ongoing optimization
        - **Innovation**: Process innovation
        - **Automation**: High degree of automation
        - **Excellence**: Change management excellence
        """)
    
    # Change management process flow
    st.markdown("#### 🔄 Change Management Process Flow")
    
    change_data = [
        {"Phase": "Request", "Activities": "RFC Creation, Initial Assessment", "Duration": "1-2 days", "Key Stakeholders": "Requester, Change Manager"},
        {"Phase": "Assessment", "Activities": "Risk Analysis, Impact Assessment", "Duration": "3-5 days", "Key Stakeholders": "Technical Teams, CAB"},
        {"Phase": "Authorization", "Activities": "CAB Review, Approval Decision", "Duration": "1-3 days", "Key Stakeholders": "CAB, Change Manager"},
        {"Phase": "Implementation", "Activities": "Testing, Deployment, Monitoring", "Duration": "Variable", "Key Stakeholders": "Technical Teams, Users"},
        {"Phase": "Review", "Activities": "PIR, Lessons Learned, Closure", "Duration": "1-2 days", "Key Stakeholders": "All Stakeholders"}
    ]
    
    df = pd.DataFrame(change_data)
    st.dataframe(df, width='stretch')

def explain_service_level_management():
    """Giải thích Service Level Management"""
    st.markdown("### 📊 Service Level Management")
    
    with st.expander("📖 Lý thuyết chi tiết về Service Level Management"):
        st.markdown("""
        ### 🎯 Service Level Management Fundamentals
        
        **Service Level Management (SLM)** là quá trình đảm bảo các dịch vụ IT đáp ứng các mục tiêu hiệu suất đã thỏa thuận:
        
        ### 📋 Key Components
        
        **Service Level Agreement (SLA):**
        - **Formal Agreement**: Legally binding contract
        - **Service Definition**: Clear service descriptions
        - **Performance Targets**: Measurable service levels
        - **Responsibilities**: Roles and responsibilities
        - **Penalties**: Consequences for non-compliance
        
        **Operational Level Agreement (OLA):**
        - **Internal Agreement**: Between internal teams
        - **Support Services**: Supporting service levels
        - **Dependencies**: Service dependencies
        - **Escalation**: Internal escalation procedures
        
        **Underpinning Contract (UC):**
        - **External Suppliers**: Third-party service providers
        - **Service Requirements**: Required service levels
        - **Contract Terms**: Commercial terms and conditions
        - **Performance Monitoring**: Supplier performance tracking
        
        ### 📊 Service Level Metrics
        
        **Availability Metrics:**
        - **Uptime Percentage**: System availability percentage
        - **Downtime**: Planned and unplanned downtime
        - **MTBF**: Mean Time Between Failures
        - **MTTR**: Mean Time To Repair/Restore
        
        **Performance Metrics:**
        - **Response Time**: System response time
        - **Throughput**: Transaction processing capacity
        - **Capacity**: System capacity utilization
        - **Quality**: Service quality measures
        
        **Service Metrics:**
        - **Incident Resolution**: Time to resolve incidents
        - **Request Fulfillment**: Time to fulfill requests
        - **Customer Satisfaction**: User satisfaction scores
        - **Service Continuity**: Business continuity measures
        
        ### 🎯 SLA Design Principles
        
        **SMART Objectives:**
        - **Specific**: Clear and specific targets
        - **Measurable**: Quantifiable metrics
        - **Achievable**: Realistic and attainable
        - **Relevant**: Business-relevant measures
        - **Time-bound**: Specific time frames
        
        **Service Level Targets:**
        - **Availability**: 99.9% uptime target
        - **Performance**: Response time < 2 seconds
        - **Capacity**: Support 1000 concurrent users
        - **Recovery**: RTO < 4 hours, RPO < 1 hour
        
        **Measurement Periods:**
        - **Business Hours**: During business operations
        - **24x7**: Continuous monitoring
        - **Monthly**: Monthly reporting periods
        - **Quarterly**: Quarterly reviews
        
        ### 📈 SLA Monitoring and Reporting
        
        **Monitoring Infrastructure:**
        - **Automated Monitoring**: Continuous system monitoring
        - **Real-time Dashboards**: Live performance dashboards
        - **Alert Systems**: Proactive alert notifications
        - **Data Collection**: Comprehensive data gathering
        
        **Reporting Framework:**
        - **Regular Reports**: Scheduled performance reports
        - **Exception Reports**: SLA breach notifications
        - **Trend Analysis**: Performance trend analysis
        - **Executive Dashboards**: High-level performance views
        
        **Performance Analysis:**
        - **Root Cause Analysis**: Identify performance issues
        - **Trend Identification**: Spot performance trends
        - **Capacity Planning**: Plan for future capacity needs
        - **Improvement Opportunities**: Identify enhancement areas
        
        ### 🔧 SLA Management Process
        
        **SLA Lifecycle:**
        
        **1. Requirements Gathering:**
        - **Business Requirements**: Understand business needs
        - **Service Catalog**: Define available services
        - **Stakeholder Input**: Gather stakeholder requirements
        - **Feasibility Assessment**: Assess technical feasibility
        
        **2. SLA Negotiation:**
        - **Service Levels**: Negotiate achievable targets
        - **Cost Implications**: Understand cost impact
        - **Risk Assessment**: Assess delivery risks
        - **Agreement Terms**: Finalize contract terms
        
        **3. SLA Implementation:**
        - **Monitoring Setup**: Implement monitoring systems
        - **Process Integration**: Integrate with ITSM processes
        - **Team Training**: Train support teams
        - **Communication**: Communicate SLA to stakeholders
        
        **4. SLA Monitoring:**
        - **Performance Tracking**: Continuous performance monitoring
        - **Breach Detection**: Identify SLA breaches
        - **Escalation**: Escalate performance issues
        - **Corrective Actions**: Take corrective measures
        
        **5. SLA Review:**
        - **Regular Reviews**: Scheduled SLA reviews
        - **Performance Analysis**: Analyze performance data
        - **Improvement Plans**: Develop improvement plans
        - **SLA Updates**: Update SLA terms as needed
        
        ### 💰 SLA Financial Management
        
        **Cost Modeling:**
        - **Service Costing**: Calculate service delivery costs
        - **Pricing Models**: Develop service pricing
        - **Value Proposition**: Demonstrate service value
        - **Budget Planning**: Plan service budgets
        
        **Penalty Framework:**
        - **Service Credits**: Financial compensation for breaches
        - **Penalty Calculation**: Fair penalty calculations
        - **Escalating Penalties**: Increasing penalties for repeated breaches
        - **Penalty Caps**: Maximum penalty limits
        
        **Incentive Programs:**
        - **Performance Bonuses**: Rewards for exceeding targets
        - **Continuous Improvement**: Incentives for improvements
        - **Innovation Rewards**: Rewards for service innovation
        - **Customer Satisfaction**: Bonuses for high satisfaction
        
        ### 🎯 SLA Best Practices
        
        **SLA Design:**
        - **Customer-focused**: Focus on customer outcomes
        - **Realistic Targets**: Set achievable targets
        - **Clear Language**: Use clear, understandable language
        - **Regular Updates**: Keep SLAs current
        
        **Monitoring and Measurement:**
        - **Automated Monitoring**: Minimize manual effort
        - **Real-time Visibility**: Provide real-time performance data
        - **Accurate Measurement**: Ensure measurement accuracy
        - **Comprehensive Coverage**: Monitor all critical aspects
        
        **Communication:**
        - **Transparent Reporting**: Open performance reporting
        - **Regular Communication**: Regular stakeholder updates
        - **Proactive Notification**: Proactive issue notification
        - **Feedback Loops**: Gather stakeholder feedback
        
        ### 🔄 Continuous Improvement
        
        **Performance Optimization:**
        - **Trend Analysis**: Identify performance trends
        - **Bottleneck Identification**: Find performance bottlenecks
        - **Capacity Optimization**: Optimize system capacity
        - **Process Improvement**: Improve service processes
        
        **SLA Evolution:**
        - **Regular Reviews**: Periodic SLA reviews
        - **Market Benchmarking**: Compare with industry standards
        - **Technology Updates**: Leverage new technologies
        - **Business Alignment**: Align with business changes
        
        **Innovation:**
        - **New Services**: Develop new service offerings
        - **Service Enhancement**: Enhance existing services
        - **Automation**: Automate service delivery
        - **Self-service**: Enable customer self-service
        
        ### 📊 SLA Governance
        
        **Governance Structure:**
        - **SLA Committee**: Cross-functional SLA governance
        - **Service Owner**: Accountable for service delivery
        - **Customer Representative**: Customer voice in governance
        - **Technical Teams**: Technical service delivery
        
        **Review Processes:**
        - **Monthly Reviews**: Regular performance reviews
        - **Quarterly Business Reviews**: Strategic service reviews
        - **Annual SLA Reviews**: Comprehensive SLA assessment
        - **Ad-hoc Reviews**: Event-driven reviews
        
        **Decision Making:**
        - **Escalation Procedures**: Clear escalation paths
        - **Decision Authority**: Clear decision-making authority
        - **Dispute Resolution**: Formal dispute resolution process
        - **Change Management**: SLA change management process
        """)
    
    # SLA metrics comparison
    st.markdown("#### 📊 Common SLA Metrics")
    
    sla_data = [
        {"Metric": "Availability", "Target": "99.9%", "Measurement": "Uptime/Total Time", "Frequency": "Monthly"},
        {"Metric": "Response Time", "Target": "< 2 seconds", "Measurement": "Average Response", "Frequency": "Real-time"},
        {"Metric": "Incident Resolution", "Target": "< 4 hours", "Measurement": "Time to Resolution", "Frequency": "Per Incident"},
        {"Metric": "Customer Satisfaction", "Target": "> 4.0/5.0", "Measurement": "Survey Scores", "Frequency": "Quarterly"},
        {"Metric": "Capacity", "Target": "< 80% utilization", "Measurement": "Resource Usage", "Frequency": "Daily"}
    ]
    
    df = pd.DataFrame(sla_data)
    st.dataframe(df, width='stretch')

def explain_it_governance():
    """Giải thích IT Governance"""
    st.markdown("### 🏛️ IT Governance")
    
    with st.expander("📖 Lý thuyết chi tiết về IT Governance"):
        st.markdown("""
        ### 🎯 IT Governance Fundamentals
        
        **IT Governance** là framework để đảm bảo IT hỗ trợ và mở rộng chiến lược kinh doanh:
        
        ### 🏗️ IT Governance Framework
        
        **COBIT (Control Objectives for Information and Related Technologies):**
        - **Comprehensive Framework**: Complete IT governance framework
        - **Process Focus**: Process-based approach
        - **Control Objectives**: Specific control objectives
        - **Maturity Models**: Process maturity assessment
        
        **ITIL Integration:**
        - **Service Management**: IT service management processes
        - **Best Practices**: Industry best practices
        - **Process Integration**: Integrated process approach
        - **Continuous Improvement**: Ongoing improvement focus
        
        **ISO/IEC 38500:**
        - **International Standard**: Global IT governance standard
        - **Principles-based**: Six key principles
        - **Board-level**: Board and executive focus
        - **Risk Management**: Risk-based approach
        
        ### 📋 Key Governance Domains
        
        **Strategic Alignment:**
        - **Business-IT Alignment**: Align IT with business strategy
        - **Strategic Planning**: IT strategic planning process
        - **Portfolio Management**: IT portfolio management
        - **Investment Prioritization**: Prioritize IT investments
        
        **Value Delivery:**
        - **Value Realization**: Deliver business value from IT
        - **Benefits Management**: Manage IT benefits
        - **Performance Measurement**: Measure IT performance
        - **Return on Investment**: Calculate IT ROI
        
        **Risk Management:**
        - **Risk Assessment**: Identify and assess IT risks
        - **Risk Mitigation**: Implement risk controls
        - **Compliance**: Ensure regulatory compliance
        - **Security Governance**: Information security governance
        
        **Resource Management:**
        - **Resource Optimization**: Optimize IT resources
        - **Capacity Management**: Manage IT capacity
        - **Sourcing Strategy**: IT sourcing decisions
        - **Vendor Management**: Manage IT vendors
        
        **Performance Measurement:**
        - **KPIs and Metrics**: Key performance indicators
        - **Balanced Scorecard**: Balanced performance measurement
        - **Benchmarking**: Compare with industry standards
        - **Reporting**: Regular performance reporting
        
        ### 👥 Governance Structure
        
        **Board of Directors:**
        - **Strategic Oversight**: Overall IT strategy oversight
        - **Risk Appetite**: Define IT risk appetite
        - **Resource Allocation**: Approve IT investments
        - **Performance Monitoring**: Monitor IT performance
        
        **IT Steering Committee:**
        - **Strategic Direction**: Set IT strategic direction
        - **Portfolio Prioritization**: Prioritize IT projects
        - **Resource Allocation**: Allocate IT resources
        - **Performance Review**: Review IT performance
        
        **IT Governance Office:**
        - **Framework Implementation**: Implement governance framework
        - **Policy Development**: Develop IT policies
        - **Compliance Monitoring**: Monitor compliance
        - **Reporting**: Governance reporting
        
        **Business Relationship Management:**
        - **Stakeholder Engagement**: Engage business stakeholders
        - **Requirements Management**: Manage business requirements
        - **Communication**: Facilitate IT-business communication
        - **Value Articulation**: Articulate IT value
        
        ### 📊 Governance Processes
        
        **IT Strategy and Planning:**
        - **Strategic Planning**: Develop IT strategy
        - **Architecture Planning**: Enterprise architecture planning
        - **Capacity Planning**: IT capacity planning
        - **Budget Planning**: IT budget planning
        
        **Portfolio and Project Governance:**
        - **Portfolio Management**: Manage IT portfolio
        - **Project Governance**: Govern IT projects
        - **Investment Evaluation**: Evaluate IT investments
        - **Benefits Realization**: Realize project benefits
        
        **Risk and Compliance:**
        - **Risk Management**: Manage IT risks
        - **Compliance Management**: Ensure regulatory compliance
        - **Audit Management**: Manage IT audits
        - **Control Assessment**: Assess control effectiveness
        
        **Performance Management:**
        - **Performance Monitoring**: Monitor IT performance
        - **Metrics Management**: Manage IT metrics
        - **Reporting**: Performance reporting
        - **Improvement Planning**: Plan performance improvements
        
        ### 🎯 Governance Principles
        
        **Responsibility:**
        - **Clear Accountability**: Clear roles and responsibilities
        - **Decision Rights**: Clear decision-making authority
        - **Escalation**: Clear escalation procedures
        - **Ownership**: Clear ownership of IT assets
        
        **Strategy:**
        - **Business Alignment**: Align IT with business strategy
        - **Value Creation**: Create business value through IT
        - **Innovation**: Drive innovation through IT
        - **Competitive Advantage**: Gain competitive advantage
        
        **Acquisition:**
        - **Investment Decisions**: Make informed IT investments
        - **Procurement**: Effective IT procurement
        - **Vendor Selection**: Select appropriate vendors
        - **Contract Management**: Manage vendor contracts
        
        **Performance:**
        - **Service Delivery**: Deliver quality IT services
        - **Performance Monitoring**: Monitor IT performance
        - **Continuous Improvement**: Continuously improve IT
        - **Benchmarking**: Benchmark against best practices
        
        **Conformance:**
        - **Regulatory Compliance**: Comply with regulations
        - **Policy Compliance**: Comply with IT policies
        - **Standards Adherence**: Adhere to IT standards
        - **Audit Compliance**: Pass IT audits
        
        **Human Behavior:**
        - **Culture**: Foster appropriate IT culture
        - **Skills Development**: Develop IT skills
        - **Change Management**: Manage IT changes
        - **Communication**: Effective IT communication
        
        ### 📈 Governance Maturity
        
        **Maturity Levels:**
        
        **Level 0 - Non-existent:**
        - **No Process**: No governance processes
        - **Ad-hoc**: Ad-hoc IT management
        - **High Risk**: High governance risks
        - **No Awareness**: No governance awareness
        
        **Level 1 - Initial/Ad-hoc:**
        - **Basic Awareness**: Basic governance awareness
        - **Informal Processes**: Informal governance processes
        - **Inconsistent**: Inconsistent application
        - **Reactive**: Reactive governance approach
        
        **Level 2 - Repeatable:**
        - **Basic Processes**: Basic governance processes
        - **Some Documentation**: Some process documentation
        - **Inconsistent Application**: Inconsistent process application
        - **Limited Monitoring**: Limited process monitoring
        
        **Level 3 - Defined:**
        - **Documented Processes**: Well-documented processes
        - **Consistent Application**: Consistent process application
        - **Training**: Process training provided
        - **Basic Monitoring**: Basic process monitoring
        
        **Level 4 - Managed:**
        - **Measured Processes**: Process performance measured
        - **Continuous Monitoring**: Continuous process monitoring
        - **Process Improvement**: Ongoing process improvement
        - **Predictable**: Predictable process outcomes
        
        **Level 5 - Optimized:**
        - **Optimized Processes**: Continuously optimized processes
        - **Innovation**: Process innovation
        - **Best Practice**: Industry best practices
        - **Continuous Improvement**: Culture of improvement
        
        ### 🛠️ Governance Tools and Techniques
        
        **Governance Frameworks:**
        - **COBIT**: Comprehensive IT governance framework
        - **ITIL**: IT service management framework
        - **ISO 27001**: Information security management
        - **TOGAF**: Enterprise architecture framework
        
        **Assessment Tools:**
        - **Maturity Assessments**: Process maturity evaluation
        - **Risk Assessments**: IT risk evaluation
        - **Compliance Audits**: Regulatory compliance checks
        - **Performance Reviews**: IT performance evaluation
        
        **Monitoring Tools:**
        - **Dashboards**: Governance dashboards
        - **Scorecards**: Balanced scorecards
        - **Reporting Tools**: Automated reporting
        - **Analytics**: Governance analytics
        
        ### 📊 Governance Metrics
        
        **Strategic Metrics:**
        - **Business-IT Alignment**: Alignment measurement
        - **IT Investment ROI**: Return on IT investment
        - **Innovation Index**: IT innovation measurement
        - **Strategic Goal Achievement**: Goal achievement rate
        
        **Operational Metrics:**
        - **Service Availability**: IT service availability
        - **Incident Resolution**: Incident resolution time
        - **Project Success Rate**: Project success percentage
        - **Cost Efficiency**: IT cost efficiency
        
        **Risk Metrics:**
        - **Risk Exposure**: IT risk exposure level
        - **Control Effectiveness**: Control effectiveness rate
        - **Compliance Score**: Regulatory compliance score
        - **Security Incidents**: Security incident frequency
        
        **Value Metrics:**
        - **Business Value**: IT business value delivery
        - **Cost Savings**: IT cost savings achieved
        - **Productivity Gains**: Productivity improvements
        - **Customer Satisfaction**: IT customer satisfaction
        """)
    
    # IT Governance framework comparison
    st.markdown("#### 🏛️ IT Governance Frameworks")
    
    governance_data = [
        {"Framework": "COBIT", "Focus": "IT Governance & Control", "Scope": "Comprehensive", "Maturity": "5 Levels"},
        {"Framework": "ITIL", "Focus": "Service Management", "Scope": "Service Lifecycle", "Maturity": "Process-based"},
        {"Framework": "ISO 38500", "Focus": "Corporate Governance", "Scope": "Board Level", "Maturity": "Principle-based"},
        {"Framework": "TOGAF", "Focus": "Enterprise Architecture", "Scope": "Architecture", "Maturity": "ADM Phases"},
        {"Framework": "ISO 27001", "Focus": "Information Security", "Scope": "Security Management", "Maturity": "PDCA Cycle"}
    ]
    
    df = pd.DataFrame(governance_data)
    st.dataframe(df, width='stretch')
