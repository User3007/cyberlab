import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_defense_in_depth():
    """Defense in Depth using TDD pattern"""
    
    st.markdown("## Defense in Depth")
    st.markdown("**Definition:** Security strategy that employs multiple layers of defense to protect information assets.")
    
    st.markdown("---")
    
    # Defense Layers
    st.markdown("### Defense Layers")
    
    layers_data = {
        "Layer": ["Physical", "Network", "Host", "Application", "Data", "User"],
        "Controls": [
            "Access control, surveillance, environmental controls",
            "Firewalls, IDS/IPS, network segmentation",
            "Antivirus, host-based firewalls, hardening",
            "Input validation, secure coding, WAF",
            "Encryption, DLP, backup systems",
            "Authentication, authorization, training"
        ],
        "Purpose": [
            "Prevent physical access",
            "Control network traffic",
            "Protect individual systems",
            "Secure applications",
            "Protect data at rest and in transit",
            "Control user access and behavior"
        ]
    }
    
    df = pd.DataFrame(layers_data)
    st.dataframe(df, use_container_width=True)
    
    # Visual Defense Layers
    st.markdown("### Defense in Depth Visualization")
    
    fig = go.Figure()
    
    # Create concentric circles for defense layers
    layers = ['Data', 'Application', 'Host', 'Network', 'Physical']
    colors = ['red', 'orange', 'yellow', 'lightblue', 'lightgreen']
    
    for i, (layer, color) in enumerate(zip(layers, colors)):
        fig.add_trace(go.Scatter(
            x=[0], y=[0],
            mode='markers',
            marker=dict(
                size=100 - i*15,
                color=color,
                opacity=0.7,
                line=dict(width=2, color='black')
            ),
            name=layer,
            text=[layer],
            textposition="middle center",
            showlegend=True
        ))
    
    fig.update_layout(
        title="Defense in Depth Layers",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1, 1]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1, 1]),
        height=400,
        showlegend=True
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Multiple Layers:</strong> No single point of failure</li>
            <li><strong>Redundancy:</strong> If one layer fails, others provide protection</li>
            <li><strong>Comprehensive Coverage:</strong> Address all attack vectors</li>
            <li><strong>Continuous Monitoring:</strong> Monitor all layers for threats</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
