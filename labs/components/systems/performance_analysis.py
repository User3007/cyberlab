"""
Performance Analysis - Compact Component
Enhanced với TDD pattern, drawer gọn gàng
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import random

def explain_performance_analysis():
    """Performance Analysis - Compact Design"""
    
    # Compact Visual Banner
    st.markdown("""
    <div style="background: linear-gradient(90deg, #f39c12 0%, #e67e22 100%); padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
        <h3 style="color: white; text-align: center; margin: 0;">⚡ Performance Analysis</h3>
        <p style="color: white; text-align: center; margin: 0.3rem 0 0 0; opacity: 0.9; font-size: 0.9rem;">
            System Performance Monitoring & Optimization
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Compact Tabs
    tab1, tab2, tab3 = st.tabs(["📊 Metrics", "🔍 Monitoring", "🚀 Optimization"])
    
    with tab1:
        # Performance Metrics - Compact Grid
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🎯 Key Metrics:**")
            metrics_data = pd.DataFrame({
                '**Metric**': ['**CPU Usage**', '**Memory Usage**', '**Disk I/O**', '**Network**'],
                '**Good**': ['**< 70%**', '**< 80%**', '**< 80%**', '**< 60%**'],
                '**Warning**': ['**70-90%**', '**80-95%**', '**80-95%**', '**60-80%**'],
                '**Critical**': ['**> 90%**', '**> 95%**', '**> 95%**', '**> 80%**']
            })
            st.dataframe(metrics_data, use_container_width=True, height=180)
        
        with col2:
            # Live Performance Simulation
            st.markdown("**📈 Live Performance:**")
            
            # Simulate real-time metrics
            cpu_usage = random.randint(20, 85)
            memory_usage = random.randint(30, 90)
            disk_io = random.randint(10, 70)
            network_usage = random.randint(5, 60)
            
            # Color coding
            def get_color(value):
                if value < 70: return "🟢"
                elif value < 90: return "🟡"
                else: return "🔴"
            
            st.metric("CPU Usage", f"{cpu_usage}%", delta=f"{random.randint(-5, 5)}%")
            st.metric("Memory", f"{memory_usage}%", delta=f"{random.randint(-3, 8)}%")
            st.metric("Disk I/O", f"{disk_io}%", delta=f"{random.randint(-10, 15)}%")
            st.metric("Network", f"{network_usage}%", delta=f"{random.randint(-8, 12)}%")
    
    with tab2:
        # Monitoring Tools - Compact
        col1, col2 = st.columns([1.2, 1])
        
        with col1:
            # Performance Chart
            fig = go.Figure()
            
            time_points = list(range(1, 11))
            cpu_data = [random.randint(20, 80) for _ in time_points]
            memory_data = [random.randint(30, 85) for _ in time_points]
            
            fig.add_trace(go.Scatter(x=time_points, y=cpu_data, name='CPU %', line=dict(color='#e74c3c')))
            fig.add_trace(go.Scatter(x=time_points, y=memory_data, name='Memory %', line=dict(color='#3498db')))
            
            fig.update_layout(
                title='Real-time Performance',
                xaxis_title='Time (minutes)',
                yaxis_title='Usage (%)',
                height=250,
                margin=dict(l=40, r=20, t=40, b=40)
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("**🛠️ Monitoring Tools:**")
            tools_data = pd.DataFrame({
                '**Tool**': ['**Task Manager**', '**htop**', '**Nagios**', '**Grafana**'],
                '**Platform**': ['**Windows**', '**Linux**', '**Enterprise**', '**Dashboards**']
            })
            st.dataframe(tools_data, use_container_width=True, height=180)
    
    with tab3:
        # Performance Optimization - Interactive
        st.markdown("**🚀 Performance Optimization Guide:**")
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            issue_type = st.selectbox("Performance Issue:", [
                "High CPU Usage",
                "Memory Leak", 
                "Slow Disk I/O",
                "Network Bottleneck",
                "Application Lag"
            ])
        
        with col2:
            if st.button("💡 Get Solution"):
                solutions = {
                    "High CPU Usage": {
                        "causes": "Background processes, inefficient code, malware",
                        "solutions": "• Close unnecessary programs\n• Update drivers\n• Check for malware\n• Upgrade CPU",
                        "tools": "Task Manager, Process Explorer"
                    },
                    "Memory Leak": {
                        "causes": "Faulty applications, insufficient RAM",
                        "solutions": "• Restart applications\n• Add more RAM\n• Update software\n• Check for memory leaks",
                        "tools": "Resource Monitor, Valgrind"
                    },
                    "Slow Disk I/O": {
                        "causes": "Fragmented disk, old HDD, full storage",
                        "solutions": "• Defragment disk\n• Upgrade to SSD\n• Free up space\n• Optimize file system",
                        "tools": "Disk Defragmenter, CrystalDiskInfo"
                    },
                    "Network Bottleneck": {
                        "causes": "Bandwidth limits, network congestion",
                        "solutions": "• Upgrade bandwidth\n• Optimize network settings\n• Use QoS\n• Check network hardware",
                        "tools": "Wireshark, iperf, ping"
                    },
                    "Application Lag": {
                        "causes": "Resource constraints, poor optimization",
                        "solutions": "• Close other applications\n• Lower graphics settings\n• Update application\n• Add more resources",
                        "tools": "Performance Profiler, Application logs"
                    }
                }
                
                solution = solutions[issue_type]
                st.success(f"""
                **🎯 Issue**: {issue_type}
                
                **🔍 Common Causes**: {solution['causes']}
                
                **💡 Solutions**:
                {solution['solutions']}
                
                **🛠️ Tools**: {solution['tools']}
                """)
        
        # Quick Performance Tips
        st.markdown("**⚡ Quick Performance Tips:**")
        col1, col2 = st.columns(2)
        with col1:
            st.info("""
            **Hardware:**
            • Add more RAM
            • Upgrade to SSD
            • Better cooling
            """)
        with col2:
            st.success("""
            **Software:**
            • Regular updates
            • Clean startup
            • Disk cleanup
            """)
    
    # Compact Key Points
    st.markdown("""
    <div style="background-color: #f8f9fa; padding: 1rem; border-radius: 8px; margin-top: 1rem;">
        <h4 style="color: #2c3e50; margin-bottom: 0.5rem;">🎯 Key Points</h4>
        <ul style="color: #2c3e50; line-height: 1.6; margin-bottom: 0;">
            <li><strong>Monitor</strong>: Regular performance monitoring prevents issues</li>
            <li><strong>Baseline</strong>: Know normal performance levels for comparison</li>
            <li><strong>Optimize</strong>: Address bottlenecks systematically for best results</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
