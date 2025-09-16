"""
OSI Model Component - Network Foundation
Concise, focused explanation of the 7-layer networking model
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from typing import Dict, List, Any

from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class OSIModelComponent(ComponentTemplate):
    """OSI Model component - focused and concise"""
    
    def __init__(self):
        super().__init__(
            component_name=" OSI Model",
            description="7-layer networking model for understanding network communication",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="15 minutes"
        )
        
        self.set_key_concepts([
            "7 Layers", "Data Encapsulation", "Protocol Stack", "Layer Interaction"
        ])
    
    def render_content(self):
        """Render OSI Model content"""
        
        # Core OSI layers
        osi_layers = [
            {"Layer": 7, "Name": "Application", "Function": "User Interface", "Protocols": "HTTP, SMTP, FTP", "Security": "App-level attacks"},
            {"Layer": 6, "Name": "Presentation", "Function": "Data Format", "Protocols": "SSL/TLS, JPEG", "Security": "Encryption"},
            {"Layer": 5, "Name": "Session", "Function": "Session Control", "Protocols": "NetBIOS, RPC", "Security": "Session hijacking"},
            {"Layer": 4, "Name": "Transport", "Function": "End-to-end", "Protocols": "TCP, UDP", "Security": "Port scanning"},
            {"Layer": 3, "Name": "Network", "Function": "Routing", "Protocols": "IP, ICMP", "Security": "IP spoofing"},
            {"Layer": 2, "Name": "Data Link", "Function": "Frame delivery", "Protocols": "Ethernet, WiFi", "Security": "MAC spoofing"},
            {"Layer": 1, "Name": "Physical", "Function": "Bits transmission", "Protocols": "Cables, Radio", "Security": "Wiretapping"}
        ]
        
        # Interactive layer visualization
        fig = go.Figure()
        colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#98D8C8']
        
        for i, layer in enumerate(osi_layers):
            fig.add_shape(
                type="rect",
                x0=0, y0=i, x1=8, y1=i+0.8,
                fillcolor=colors[i], opacity=0.7,
                line=dict(color=colors[i], width=2)
            )
            
            fig.add_annotation(
                x=4, y=i+0.4,
                text=f"<b>L{layer['Layer']}: {layer['Name']}</b><br>{layer['Function']}",
                showarrow=False, font=dict(size=12, color="white")
            )
        
        fig.update_layout(
            title="OSI 7-Layer Model",
            xaxis=dict(showgrid=False, showticklabels=False, range=[0, 8]),
            yaxis=dict(showgrid=False, showticklabels=False, range=[0, 7]),
            height=400, showlegend=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Layer details table
        df = pd.DataFrame(osi_layers)
        st.dataframe(df, use_container_width=True)
        
        # Key concepts
        col1, col2 = st.columns(2)
        
        with col1:
            create_info_card(
                " Data Encapsulation",
                "Each layer adds headers/trailers as data moves down the stack",
                "info", self.color_scheme
            )
        
        with col2:
            create_info_card(
                " Security Implications",
                "Each layer has specific attack vectors and defense mechanisms",
                "warning", self.color_scheme
            )


def explain_osi_model():
    """Main function for OSI Model"""
    component = OSIModelComponent()
    
    summary_points = [
        "OSI model provides a 7-layer framework for network communication",
        "Each layer has specific functions and security considerations",
        "Data encapsulation occurs as information moves through layers",
        "Understanding OSI helps in network troubleshooting and security"
    ]
    
    resources = [
        {"title": "ISO/IEC 7498-1", "description": "Official OSI Reference Model standard"},
        {"title": "Network+ Study Guide", "description": "CompTIA Network+ certification materials"}
    ]
    
    component.render_full_component(summary_points, resources)
