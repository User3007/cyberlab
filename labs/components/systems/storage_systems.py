"""
Storage Systems - Compact Component  
Enhanced với TDD pattern, drawer gọn gàng
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_storage_systems():
    """Storage Systems - Compact Design"""
    
    # Compact Visual Banner
    st.markdown("""
    <div style="background: linear-gradient(90deg, #9b59b6 0%, #8e44ad 100%); padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
        <h3 style="color: white; text-align: center; margin: 0;">💾 Storage Systems</h3>
        <p style="color: white; text-align: center; margin: 0.3rem 0 0 0; opacity: 0.9; font-size: 0.9rem;">
            Data Storage Technologies
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Compact Tabs
    tab1, tab2, tab3 = st.tabs(["🗄️ Storage Types", "⚡ HDD vs SSD", "📊 Performance"])
    
    with tab1:
        # Storage Hierarchy - Visual
        fig = go.Figure()
        
        storage_levels = [
            ("Primary Storage", 0.5, 0.8, 0.3, "#e74c3c"),
            ("Secondary Storage", 0.5, 0.5, 0.4, "#f39c12"),
            ("Tertiary Storage", 0.5, 0.2, 0.5, "#27ae60")
        ]
        
        for name, x, y, width, color in storage_levels:
            fig.add_shape(
                type="rect",
                x0=x-width/2, y0=y-0.08, x1=x+width/2, y1=y+0.08,
                fillcolor=color, opacity=0.7,
                line=dict(color="white", width=2)
            )
            fig.add_annotation(
                x=x, y=y, text=f"<b>{name}</b>",
                showarrow=False, font=dict(size=12, color="white")
            )
        
        fig.update_layout(
            title="Storage Hierarchy",
            xaxis=dict(showgrid=False, showticklabels=False, zeroline=False, range=[0, 1]),
            yaxis=dict(showgrid=False, showticklabels=False, zeroline=False, range=[0, 1]),
            height=250, margin=dict(l=10, r=10, t=30, b=10)
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Storage Types - Compact
        col1, col2, col3 = st.columns(3)
        with col1:
            st.info("**Primary**\n• RAM\n• Cache\n• Registers")
        with col2:
            st.warning("**Secondary**\n• HDD\n• SSD\n• Optical")
        with col3:
            st.success("**Tertiary**\n• Tape\n• Cloud\n• Archive")
    
    with tab2:
        # HDD vs SSD Comparison - Compact
        comparison_data = pd.DataFrame({
            '**Aspect**': ['**Technology**', '**Speed**', '**Capacity**', '**Cost/GB**', '**Durability**'],
            '**HDD**': [
                '**Magnetic** spinning disks',
                '**5,400-15,000** RPM',
                '**Up to 20+ TB**',
                '**$0.02-0.05**',
                '**Mechanical** parts'
            ],
            '**SSD**': [
                '**Flash memory** chips',
                '**No moving** parts',
                '**Up to 8 TB**',
                '**$0.10-0.20**',
                '**Solid state** reliable'
            ]
        })
        st.dataframe(comparison_data, use_container_width=True, height=200)
        
        # Performance Comparison Chart
        categories = ['Speed', 'Reliability', 'Power Usage', 'Noise']
        hdd_scores = [30, 60, 40, 20]
        ssd_scores = [95, 90, 85, 100]
        
        fig = go.Figure()
        fig.add_trace(go.Bar(name='HDD', x=categories, y=hdd_scores, marker_color='#e74c3c'))
        fig.add_trace(go.Bar(name='SSD', x=categories, y=ssd_scores, marker_color='#27ae60'))
        
        fig.update_layout(
            title='HDD vs SSD Performance',
            yaxis_title='Score (%)',
            barmode='group',
            height=250
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        # Interactive Storage Calculator
        col1, col2 = st.columns([1, 1])
        
        with col1:
            storage_type = st.selectbox("Storage Type:", ["HDD", "SSD", "NVMe SSD"])
            capacity = st.selectbox("Capacity:", ["500 GB", "1 TB", "2 TB", "4 TB"])
            usage = st.selectbox("Usage:", ["Basic", "Gaming", "Professional", "Enterprise"])
        
        with col2:
            if st.button("💰 Calculate Cost & Performance"):
                # Simple cost calculation
                cap_val = float(capacity.split()[0]) if 'TB' in capacity else float(capacity.split()[0])/1000
                
                cost_per_gb = {
                    "HDD": 0.03,
                    "SSD": 0.15, 
                    "NVMe SSD": 0.20
                }
                
                total_cost = cap_val * 1000 * cost_per_gb[storage_type]
                
                performance_rating = {
                    ("HDD", "Basic"): "Good",
                    ("HDD", "Gaming"): "Fair", 
                    ("HDD", "Professional"): "Poor",
                    ("SSD", "Basic"): "Excellent",
                    ("SSD", "Gaming"): "Excellent",
                    ("SSD", "Professional"): "Good",
                    ("NVMe SSD", "Professional"): "Excellent",
                    ("NVMe SSD", "Enterprise"): "Excellent"
                }
                
                rating = performance_rating.get((storage_type, usage), "Good")
                
                st.info(f"""
                **💾 {storage_type} - {capacity}**
                
                **Cost**: ~${total_cost:.0f}
                **Performance**: {rating}
                **Best for**: {usage} usage
                """)
    
    # Compact Key Points
    st.markdown("""
    <div style="background-color: #f8f9fa; padding: 1rem; border-radius: 8px; margin-top: 1rem;">
        <h4 style="color: #2c3e50; margin-bottom: 0.5rem;">🎯 Key Points</h4>
        <ul style="color: #2c3e50; line-height: 1.6; margin-bottom: 0;">
            <li><strong>HDD</strong>: Cheaper, larger capacity, slower access</li>
            <li><strong>SSD</strong>: Faster, more reliable, higher cost per GB</li>
            <li><strong>Choice</strong>: Depends on budget, performance needs, and usage</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
