"""
CPU & Memory Systems - Compact Component
Enhanced với TDD pattern, drawer gọn gàng
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_cpu_memory():
    """CPU & Memory Systems - Compact Design"""
    
    # Compact Visual Banner
    st.markdown("""
    <div style="background: linear-gradient(90deg, #e74c3c 0%, #c0392b 100%); padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
        <h3 style="color: white; text-align: center; margin: 0;">🧠 CPU & Memory Systems</h3>
        <p style="color: white; text-align: center; margin: 0.3rem 0 0 0; opacity: 0.9; font-size: 0.9rem;">
            Processing & Storage Components
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Compact Tabs for Content Organization
    tab1, tab2, tab3 = st.tabs(["🔧 CPU Components", "💾 Memory Hierarchy", "⚡ Performance"])
    
    with tab1:
        # CPU Architecture Diagram - Compact
        col1, col2 = st.columns([1.2, 1])
        
        with col1:
            fig = go.Figure()
            
            # CPU Components - Simplified
            components = [
                ("Control Unit", 0.3, 0.7, "#3498db"),
                ("ALU", 0.7, 0.7, "#e74c3c"), 
                ("Registers", 0.5, 0.4, "#f39c12"),
                ("Cache", 0.5, 0.1, "#27ae60")
            ]
            
            for name, x, y, color in components:
                fig.add_shape(
                    type="rect",
                    x0=x-0.15, y0=y-0.1, x1=x+0.15, y1=y+0.1,
                    fillcolor=color, opacity=0.8,
                    line=dict(color="white", width=1)
                )
                fig.add_annotation(
                    x=x, y=y, text=f"<b>{name}</b>",
                    showarrow=False, font=dict(size=10, color="white")
                )
            
            fig.update_layout(
                title="CPU Architecture",
                xaxis=dict(showgrid=False, showticklabels=False, zeroline=False, range=[0, 1]),
                yaxis=dict(showgrid=False, showticklabels=False, zeroline=False, range=[0, 1]),
                height=250, margin=dict(l=10, r=10, t=30, b=10)
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("**🎯 CPU Functions:**")
            st.markdown("""
            • **Control Unit**: Manages instruction flow
            • **ALU**: Arithmetic & logic operations  
            • **Registers**: High-speed temporary storage
            • **Cache**: Frequently accessed data
            """)
    
    with tab2:
        # Memory Hierarchy - Compact Table
        memory_data = pd.DataFrame({
            '**Level**': ['**Registers**', '**L1 Cache**', '**L2 Cache**', '**RAM**', '**Storage**'],
            '**Speed**': ['**~1 cycle**', '**1-2 cycles**', '**10-20 cycles**', '**100+ cycles**', '**1M+ cycles**'],
            '**Size**': ['**Bytes**', '**KB**', '**MB**', '**GB**', '**TB**'],
            '**Cost/GB**': ['**Highest**', '**Very High**', '**High**', '**Medium**', '**Lowest**']
        })
        st.dataframe(memory_data, use_container_width=True, height=200)
        
        # Quick Memory Types
        st.markdown("**💾 Memory Types:**")
        col1, col2 = st.columns(2)
        with col1:
            st.info("**Volatile:** RAM, Cache, Registers")
        with col2:
            st.success("**Non-Volatile:** SSD, HDD, ROM")
    
    with tab3:
        # Performance Metrics - Interactive
        col1, col2 = st.columns([1, 1])
        
        with col1:
            cpu_speed = st.selectbox("CPU Speed:", ["2.5 GHz", "3.2 GHz", "4.0 GHz", "5.0 GHz"])
            memory_size = st.selectbox("Memory Size:", ["8 GB", "16 GB", "32 GB", "64 GB"])
        
        with col2:
            if st.button("🔍 Calculate Performance"):
                speed_val = float(cpu_speed.split()[0])
                mem_val = int(memory_size.split()[0])
                
                performance_score = (speed_val * 10) + (mem_val * 2)
                
                if performance_score > 80:
                    st.success(f"**High Performance**: {performance_score:.0f} points")
                elif performance_score > 50:
                    st.info(f"**Medium Performance**: {performance_score:.0f} points")
                else:
                    st.warning(f"**Basic Performance**: {performance_score:.0f} points")
    
    # Compact Key Points
    st.markdown("""
    <div style="background-color: #f8f9fa; padding: 1rem; border-radius: 8px; margin-top: 1rem;">
        <h4 style="color: #2c3e50; margin-bottom: 0.5rem;">🎯 Key Points</h4>
        <ul style="color: #2c3e50; line-height: 1.6; margin-bottom: 0;">
            <li><strong>CPU</strong>: Executes instructions via fetch-decode-execute cycle</li>
            <li><strong>Memory Hierarchy</strong>: Trade-off between speed, size, and cost</li>
            <li><strong>Performance</strong>: Depends on CPU speed, memory size, and architecture</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
