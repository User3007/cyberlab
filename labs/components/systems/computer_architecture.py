"""
Computer Architecture Component
Extracted from it_fundamentals.py - Enhanced with shared utilities
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Any, Optional

# Import shared utilities
from ...shared.color_schemes import IT_FUNDAMENTALS_COLORS
from ...shared.ui_components import create_banner, create_takeaways, create_info_card
from ...shared.diagram_utils import create_basic_figure, add_architecture_diagram
from ...templates.component_template import ComponentTemplate


class ComputerArchitectureComponent(ComponentTemplate):
    """Computer Architecture component using enhanced template"""
    
    def __init__(self):
        super().__init__(
            component_name="🖥️ Computer Architecture",
            description="Understanding computer systems architecture and components",
            color_scheme=IT_FUNDAMENTALS_COLORS,
            estimated_time="25 minutes"
        )
        
        self.set_prerequisites([
            "Basic understanding of computers",
            "Familiarity with hardware concepts"
        ])
        
        self.set_learning_objectives([
            "Understand computer system architecture",
            "Learn about CPU, memory, and storage components",
            "Explore system buses and data flow",
            "Identify security implications of hardware design"
        ])
        
        self.set_key_concepts([
            "Von Neumann Architecture", "CPU Components", "Memory Hierarchy",
            "System Buses", "I/O Systems", "Performance Metrics"
        ])
    
    def render_content(self):
        """Render the Computer Architecture content"""
        
        # Architecture overview
        self._render_architecture_overview()
        
        # CPU components
        self._render_cpu_components()
        
        # Memory hierarchy
        self._render_memory_hierarchy()
        
        # System performance
        self._render_performance_analysis()
        
        # Security considerations
        self._render_security_implications()
    
    def _render_architecture_overview(self):
        """Render computer architecture overview"""
        st.subheader("🏗️ Computer System Architecture")
        
        # Von Neumann Architecture
        architecture_layers = [
            {
                "name": "Input/Output Devices",
                "description": "Keyboards, mice, displays, network interfaces",
                "components": ["Keyboard", "Mouse", "Display", "Network Card"]
            },
            {
                "name": "Control Unit",
                "description": "Manages instruction execution and system control",
                "components": ["Instruction Decoder", "Control Signals", "Program Counter"]
            },
            {
                "name": "Arithmetic Logic Unit (ALU)",
                "description": "Performs mathematical and logical operations",
                "components": ["Adder", "Comparator", "Logic Gates", "Registers"]
            },
            {
                "name": "Memory System",
                "description": "Stores programs and data",
                "components": ["RAM", "Cache", "ROM", "Storage"]
            },
            {
                "name": "System Buses",
                "description": "Data, address, and control buses",
                "components": ["Data Bus", "Address Bus", "Control Bus"]
            }
        ]
        
        fig = create_basic_figure("Von Neumann Architecture", self.color_scheme, height=500)
        fig = add_architecture_diagram(fig, architecture_layers, self.color_scheme)
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Interactive component explorer
        selected_component = st.selectbox(
            "Explore architecture component:",
            [layer["name"] for layer in architecture_layers]
        )
        
        component_info = next(layer for layer in architecture_layers if layer["name"] == selected_component)
        
        create_info_card(
            f"🔍 {component_info['name']}",
            component_info['description'],
            card_type="info",
            color_scheme=self.color_scheme
        )
        
        st.markdown("**Key Components:**")
        for component in component_info['components']:
            st.markdown(f"• {component}")
    
    def _render_cpu_components(self):
        """Render CPU components explanation"""
        st.subheader("⚡ CPU Components & Operation")
        
        cpu_components = {
            "Control Unit (CU)": {
                "function": "Manages instruction execution and coordinates system operations",
                "responsibilities": [
                    "Fetch instructions from memory",
                    "Decode instruction format",
                    "Generate control signals",
                    "Coordinate with other components"
                ],
                "security_impact": "Controls access to system resources and instruction execution"
            },
            "Arithmetic Logic Unit (ALU)": {
                "function": "Performs mathematical and logical operations",
                "responsibilities": [
                    "Arithmetic operations (+, -, ×, ÷)",
                    "Logical operations (AND, OR, NOT)",
                    "Comparison operations",
                    "Bit manipulation"
                ],
                "security_impact": "Executes cryptographic operations and security calculations"
            },
            "Registers": {
                "function": "High-speed storage locations within the CPU",
                "responsibilities": [
                    "Store temporary data",
                    "Hold instruction addresses",
                    "Maintain CPU status",
                    "Cache frequently used values"
                ],
                "security_impact": "May contain sensitive data requiring protection"
            },
            "Cache Memory": {
                "function": "Fast memory that stores frequently accessed data",
                "responsibilities": [
                    "Reduce memory access time",
                    "Store recently used instructions",
                    "Improve system performance",
                    "Bridge CPU-memory speed gap"
                ],
                "security_impact": "Potential side-channel attack vector"
            }
        }
        
        # Create tabs for each CPU component
        tabs = st.tabs(list(cpu_components.keys()))
        
        for tab, (component_name, component_info) in zip(tabs, cpu_components.items()):
            with tab:
                create_info_card(
                    f"⚙️ {component_name}",
                    component_info['function'],
                    card_type="primary",
                    color_scheme=self.color_scheme
                )
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**📋 Responsibilities:**")
                    for responsibility in component_info['responsibilities']:
                        st.markdown(f"• {responsibility}")
                
                with col2:
                    st.markdown("**🔒 Security Impact:**")
                    st.markdown(component_info['security_impact'])
    
    def _render_memory_hierarchy(self):
        """Render memory hierarchy explanation"""
        st.subheader("💾 Memory Hierarchy")
        
        # Memory hierarchy data
        memory_levels = [
            {
                "Level": "CPU Registers",
                "Capacity": "32-64 bits × 16-32",
                "Speed": "1 cycle",
                "Cost": "Very High",
                "Volatility": "Volatile",
                "Purpose": "Immediate data storage"
            },
            {
                "Level": "L1 Cache",
                "Capacity": "16-64 KB",
                "Speed": "1-2 cycles", 
                "Cost": "Very High",
                "Volatility": "Volatile",
                "Purpose": "Recently used instructions/data"
            },
            {
                "Level": "L2 Cache",
                "Capacity": "256 KB - 1 MB",
                "Speed": "3-10 cycles",
                "Cost": "High",
                "Volatility": "Volatile",
                "Purpose": "Secondary cache for CPU"
            },
            {
                "Level": "L3 Cache",
                "Capacity": "1-32 MB",
                "Speed": "10-20 cycles",
                "Cost": "High",
                "Volatility": "Volatile",
                "Purpose": "Shared cache between cores"
            },
            {
                "Level": "Main Memory (RAM)",
                "Capacity": "4-128 GB",
                "Speed": "100-300 cycles",
                "Cost": "Medium",
                "Volatility": "Volatile",
                "Purpose": "System memory for programs/data"
            },
            {
                "Level": "Secondary Storage",
                "Capacity": "500 GB - 10 TB",
                "Speed": "10,000+ cycles",
                "Cost": "Low",
                "Volatility": "Non-volatile",
                "Purpose": "Long-term data storage"
            }
        ]
        
        # Display memory hierarchy table
        df = pd.DataFrame(memory_levels)
        st.dataframe(df, use_container_width=True)
        
        # Memory hierarchy pyramid visualization
        fig = go.Figure()
        
        # Create inverted pyramid
        levels = len(memory_levels)
        for i, memory in enumerate(memory_levels):
            y_bottom = i * 0.8
            y_top = y_bottom + 0.7
            width = 1 - (i * 0.15)  # Narrower at top
            x_left = (1 - width) / 2
            x_right = x_left + width
            
            # Add rectangle for each level
            fig.add_shape(
                type="rect",
                x0=x_left, y0=y_bottom,
                x1=x_right, y1=y_top,
                fillcolor=self.color_scheme['primary'] if i < 3 else self.color_scheme['secondary'],
                opacity=0.7 - (i * 0.1),
                line=dict(color=self.color_scheme['primary'], width=2)
            )
            
            # Add level label
            fig.add_annotation(
                x=0.5, y=(y_bottom + y_top) / 2,
                text=f"<b>{memory['Level']}</b><br>{memory['Capacity']}",
                showarrow=False,
                font=dict(size=10, color="white")
            )
        
        fig.update_layout(
            title="Memory Hierarchy Pyramid",
            xaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
            yaxis=dict(range=[0, levels * 0.8], showgrid=False, showticklabels=False),
            height=400,
            showlegend=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Memory access patterns
        st.markdown("#### 📊 Memory Access Patterns")
        
        # Simulate memory access times
        import numpy as np
        
        access_times = {
            "Register": 1,
            "L1 Cache": 2,
            "L2 Cache": 10,
            "L3 Cache": 20,
            "RAM": 200,
            "SSD": 10000,
            "HDD": 100000
        }
        
        fig = px.bar(
            x=list(access_times.keys()),
            y=list(access_times.values()),
            title="Memory Access Times (CPU Cycles)",
            log_y=True,
            color=list(access_times.values()),
            color_continuous_scale="Viridis"
        )
        
        fig.update_layout(
            xaxis_title="Memory Type",
            yaxis_title="Access Time (CPU Cycles, Log Scale)",
            showlegend=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def _render_performance_analysis(self):
        """Render system performance analysis"""
        st.subheader("📈 System Performance Analysis")
        
        st.markdown("Analyze key performance metrics:")
        
        # Performance metrics calculator
        col1, col2, col3 = st.columns(3)
        
        with col1:
            cpu_speed = st.slider("CPU Speed (GHz):", 1.0, 5.0, 3.0, 0.1)
        with col2:
            memory_size = st.slider("Memory Size (GB):", 4, 64, 16, 4)
        with col3:
            storage_type = st.selectbox("Storage Type:", ["HDD", "SSD", "NVMe"])
        
        if st.button("🚀 Calculate Performance Score"):
            # Simple performance scoring algorithm
            cpu_score = cpu_speed * 20
            memory_score = min(memory_size * 2, 50)  # Cap at 50 points
            
            storage_scores = {"HDD": 10, "SSD": 30, "NVMe": 50}
            storage_score = storage_scores[storage_type]
            
            total_score = cpu_score + memory_score + storage_score
            max_score = 100 + 50 + 50  # Maximum possible score
            
            performance_percentage = (total_score / max_score) * 100
            
            # Display results
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("CPU Score", f"{cpu_score:.0f}/100")
            with col2:
                st.metric("Memory Score", f"{memory_score:.0f}/50")
            with col3:
                st.metric("Storage Score", f"{storage_score}/50")
            with col4:
                st.metric("Total Performance", f"{performance_percentage:.1f}%")
            
            # Performance classification
            if performance_percentage >= 80:
                st.success("🟢 **High Performance System** - Excellent for demanding applications")
            elif performance_percentage >= 60:
                st.warning("🟡 **Medium Performance System** - Good for general use")
            else:
                st.error("🔴 **Basic Performance System** - Suitable for light workloads")
            
            # Bottleneck analysis
            st.markdown("#### 🔍 Bottleneck Analysis")
            
            scores = {"CPU": cpu_score/100*50, "Memory": memory_score, "Storage": storage_score}
            min_component = min(scores, key=scores.get)
            
            st.warning(f"⚠️ **Primary Bottleneck:** {min_component} - Consider upgrading this component first")
    
    def _render_security_implications(self):
        """Render security implications of computer architecture"""
        st.subheader("🔒 Security Implications")
        
        security_considerations = {
            "Hardware-Level Attacks": {
                "description": "Attacks targeting physical components and hardware vulnerabilities",
                "examples": [
                    "Side-channel attacks (timing, power analysis)",
                    "Hardware trojans in chips",
                    "Physical tampering",
                    "Cold boot attacks on RAM"
                ],
                "mitigations": [
                    "Hardware security modules (HSMs)",
                    "Secure boot processes",
                    "Physical security controls",
                    "Memory encryption"
                ]
            },
            "Cache-Based Attacks": {
                "description": "Exploiting cache behavior to extract sensitive information",
                "examples": [
                    "Cache timing attacks",
                    "Flush+Reload attacks",
                    "Prime+Probe attacks",
                    "Spectre and Meltdown vulnerabilities"
                ],
                "mitigations": [
                    "Cache partitioning",
                    "Microcode updates",
                    "Software countermeasures",
                    "Hardware design improvements"
                ]
            },
            "Firmware Security": {
                "description": "Security considerations for system firmware and BIOS",
                "examples": [
                    "BIOS/UEFI rootkits",
                    "Firmware modification",
                    "Boot process attacks",
                    "Supply chain compromises"
                ],
                "mitigations": [
                    "Secure boot",
                    "Firmware signing",
                    "TPM (Trusted Platform Module)",
                    "Regular firmware updates"
                ]
            }
        }
        
        # Display security considerations
        for category, details in security_considerations.items():
            with st.expander(f"🔍 {category}", expanded=False):
                create_info_card(
                    category,
                    details['description'],
                    card_type="warning",
                    color_scheme=self.color_scheme
                )
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**⚠️ Attack Examples:**")
                    for example in details['examples']:
                        st.markdown(f"• {example}")
                
                with col2:
                    st.markdown("**🛡️ Mitigations:**")
                    for mitigation in details['mitigations']:
                        st.markdown(f"• {mitigation}")


def explain_computer_architecture():
    """Main function to render Computer Architecture component"""
    component = ComputerArchitectureComponent()
    
    # Summary points for the component
    summary_points = [
        "Computer architecture defines how system components interact",
        "Memory hierarchy balances speed, capacity, and cost considerations",
        "CPU components work together to execute instructions efficiently",
        "System performance depends on the balance of all components",
        "Hardware security is fundamental to overall system security"
    ]
    
    # Additional resources
    resources = [
        {
            "title": "Computer Architecture: A Quantitative Approach",
            "description": "Comprehensive textbook by Hennessy and Patterson"
        },
        {
            "title": "Intel Architecture Documentation",
            "description": "Official documentation for Intel processor architectures",
            "url": "https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html"
        }
    ]
    
    # Render the complete component
    component.render_full_component(summary_points, resources)
