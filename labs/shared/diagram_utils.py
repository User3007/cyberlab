"""
Plotly diagram utilities for creating consistent visualizations
"""

import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Any, Tuple, Optional
import pandas as pd
import numpy as np
from .color_schemes import get_color_scheme
from .constants import DEFAULT_CHART_CONFIG, PLOTLY_THEME


def create_basic_figure(title: str = "",
                       color_scheme: Dict[str, str] = None,
                       height: int = 400,
                       width: int = None) -> go.Figure:
    """Create base figure with consistent styling"""
    
    if not color_scheme:
        color_scheme = get_color_scheme('theory_concepts')
    
    fig = go.Figure()
    
    fig.update_layout(
        title={
            'text': title,
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 18, 'color': color_scheme['text']}
        },
        height=height,
        width=width,
        template=PLOTLY_THEME,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=40, r=40, t=60, b=40),
        font=dict(color=color_scheme['text'])
    )
    
    return fig


def add_network_diagram(fig: go.Figure,
                       nodes: List[Dict[str, Any]],
                       edges: List[Dict[str, Any]],
                       color_scheme: Dict[str, str] = None) -> go.Figure:
    """Add network topology diagram to figure"""
    
    if not color_scheme:
        color_scheme = get_color_scheme('network_security')
    
    # Add edges first (so they appear behind nodes)
    for edge in edges:
        fig.add_trace(go.Scatter(
            x=[edge['from_x'], edge['to_x']],
            y=[edge['from_y'], edge['to_y']],
            mode='lines',
            line=dict(
                color=edge.get('color', color_scheme['accent']),
                width=edge.get('width', 2)
            ),
            showlegend=False,
            hoverinfo='skip'
        ))
    
    # Add nodes
    for node in nodes:
        fig.add_trace(go.Scatter(
            x=[node['x']],
            y=[node['y']],
            mode='markers+text',
            marker=dict(
                size=node.get('size', 30),
                color=node.get('color', color_scheme['primary']),
                symbol=node.get('symbol', 'circle'),
                line=dict(width=2, color='white')
            ),
            text=node['label'],
            textposition='middle center',
            textfont=dict(size=10, color='white'),
            name=node.get('type', 'Node'),
            hovertemplate=f"<b>{node['label']}</b><br>" +
                         f"Type: {node.get('type', 'Unknown')}<br>" +
                         f"IP: {node.get('ip', 'N/A')}<extra></extra>"
        ))
    
    # Update layout for network diagram
    fig.update_layout(
        xaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
        yaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        )
    )
    
    return fig


def add_security_triangle(fig: go.Figure,
                         center: Tuple[float, float] = (0.5, 0.5),
                         size: float = 0.3,
                         color_scheme: Dict[str, str] = None) -> go.Figure:
    """Add CIA Triad security triangle to figure"""
    
    if not color_scheme:
        color_scheme = get_color_scheme('theory_concepts')
    
    cx, cy = center
    
    # Calculate triangle vertices
    vertices = [
        (cx, cy + size),  # Top (Confidentiality)
        (cx - size * 0.866, cy - size * 0.5),  # Bottom left (Integrity)
        (cx + size * 0.866, cy - size * 0.5),  # Bottom right (Availability)
        (cx, cy + size)  # Close the triangle
    ]
    
    # Add triangle shape
    fig.add_shape(
        type="path",
        path=f"M {vertices[0][0]},{vertices[0][1]} " +
             f"L {vertices[1][0]},{vertices[1][1]} " +
             f"L {vertices[2][0]},{vertices[2][1]} Z",
        fillcolor=color_scheme['primary'],
        opacity=0.3,
        line=dict(color=color_scheme['primary'], width=3)
    )
    
    # Add labels
    labels = [
        ("Confidentiality", vertices[0][0], vertices[0][1] + 0.05),
        ("Integrity", vertices[1][0] - 0.1, vertices[1][1] - 0.05),
        ("Availability", vertices[2][0] + 0.1, vertices[2][1] - 0.05)
    ]
    
    colors = [color_scheme['primary'], color_scheme['secondary'], color_scheme['accent']]
    
    for (label, x, y), color in zip(labels, colors):
        fig.add_annotation(
            x=x, y=y,
            text=f"<b>{label}</b>",
            showarrow=False,
            font=dict(size=12, color=color),
            bgcolor="white",
            bordercolor=color,
            borderwidth=2,
            borderpad=4
        )
    
    # Update layout
    fig.update_layout(
        xaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
    )
    
    return fig


def add_architecture_diagram(fig: go.Figure,
                           layers: List[Dict[str, Any]],
                           color_scheme: Dict[str, str] = None) -> go.Figure:
    """Add system architecture diagram with layers"""
    
    if not color_scheme:
        color_scheme = get_color_scheme('it_fundamentals')
    
    layer_height = 0.8 / len(layers)
    colors = [color_scheme['primary'], color_scheme['secondary'], 
              color_scheme['accent'], color_scheme['info']]
    
    for i, layer in enumerate(layers):
        y_bottom = 0.1 + i * layer_height
        y_top = y_bottom + layer_height * 0.8
        
        # Add layer rectangle
        fig.add_shape(
            type="rect",
            x0=0.1, y0=y_bottom,
            x1=0.9, y1=y_top,
            fillcolor=colors[i % len(colors)],
            opacity=0.7,
            line=dict(color=colors[i % len(colors)], width=2)
        )
        
        # Add layer label
        fig.add_annotation(
            x=0.5, y=(y_bottom + y_top) / 2,
            text=f"<b>{layer['name']}</b><br>{layer.get('description', '')}",
            showarrow=False,
            font=dict(size=12, color="white"),
            bgcolor=colors[i % len(colors)],
            bordercolor="white",
            borderwidth=1
        )
        
        # Add components if specified
        if 'components' in layer:
            comp_width = 0.7 / len(layer['components'])
            for j, component in enumerate(layer['components']):
                comp_x = 0.15 + j * comp_width
                fig.add_annotation(
                    x=comp_x + comp_width/2,
                    y=y_bottom + layer_height * 0.2,
                    text=component,
                    showarrow=False,
                    font=dict(size=8, color="white"),
                    bgcolor="rgba(255,255,255,0.2)",
                    bordercolor="white",
                    borderwidth=1
                )
    
    fig.update_layout(
        xaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
    )
    
    return fig


def add_process_flow(fig: go.Figure,
                    steps: List[Dict[str, Any]],
                    color_scheme: Dict[str, str] = None) -> go.Figure:
    """Add process flow diagram"""
    
    if not color_scheme:
        color_scheme = get_color_scheme('software_development')
    
    step_width = 0.8 / len(steps)
    
    for i, step in enumerate(steps):
        x_center = 0.1 + (i + 0.5) * step_width
        
        # Add step box
        fig.add_shape(
            type="rect",
            x0=x_center - step_width * 0.4,
            y0=0.4,
            x1=x_center + step_width * 0.4,
            y1=0.6,
            fillcolor=color_scheme['primary'],
            opacity=0.8,
            line=dict(color=color_scheme['primary'], width=2)
        )
        
        # Add step label
        fig.add_annotation(
            x=x_center, y=0.5,
            text=f"<b>{step['name']}</b>",
            showarrow=False,
            font=dict(size=10, color="white")
        )
        
        # Add arrow to next step
        if i < len(steps) - 1:
            next_x = 0.1 + (i + 1.5) * step_width
            fig.add_annotation(
                x=(x_center + step_width * 0.4 + next_x - step_width * 0.4) / 2,
                y=0.5,
                text="→",
                showarrow=False,
                font=dict(size=20, color=color_scheme['accent'])
            )
        
        # Add description below
        if 'description' in step:
            fig.add_annotation(
                x=x_center, y=0.3,
                text=step['description'],
                showarrow=False,
                font=dict(size=8, color=color_scheme['text'])
            )
    
    fig.update_layout(
        xaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
    )
    
    return fig


def create_comparison_chart(data: pd.DataFrame,
                          x_col: str,
                          y_col: str,
                          color_col: str = None,
                          chart_type: str = 'bar',
                          color_scheme: Dict[str, str] = None) -> go.Figure:
    """Create comparison chart with consistent styling"""
    
    if not color_scheme:
        color_scheme = get_color_scheme('theory_concepts')
    
    if chart_type == 'bar':
        if color_col:
            fig = px.bar(data, x=x_col, y=y_col, color=color_col,
                        color_discrete_sequence=[color_scheme['primary'], 
                                               color_scheme['secondary'],
                                               color_scheme['accent']])
        else:
            fig = px.bar(data, x=x_col, y=y_col,
                        color_discrete_sequence=[color_scheme['primary']])
    
    elif chart_type == 'line':
        fig = px.line(data, x=x_col, y=y_col, color=color_col,
                     color_discrete_sequence=[color_scheme['primary'],
                                            color_scheme['secondary']])
    
    elif chart_type == 'scatter':
        fig = px.scatter(data, x=x_col, y=y_col, color=color_col,
                        color_discrete_sequence=[color_scheme['primary'],
                                               color_scheme['secondary']])
    
    # Apply consistent styling
    fig.update_layout(
        template=PLOTLY_THEME,
        font=dict(color=color_scheme['text']),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)'
    )
    
    return fig


def create_metrics_dashboard(metrics: Dict[str, Any],
                           color_scheme: Dict[str, str] = None) -> go.Figure:
    """Create metrics dashboard with gauges and indicators"""
    
    if not color_scheme:
        color_scheme = get_color_scheme('theory_concepts')
    
    fig = go.Figure()
    
    # Create subplot structure for multiple metrics
    from plotly.subplots import make_subplots
    
    metric_names = list(metrics.keys())
    cols = min(len(metric_names), 3)
    rows = (len(metric_names) + cols - 1) // cols
    
    fig = make_subplots(
        rows=rows, cols=cols,
        subplot_titles=metric_names,
        specs=[[{"type": "indicator"}] * cols for _ in range(rows)]
    )
    
    for i, (name, value) in enumerate(metrics.items()):
        row = i // cols + 1
        col = i % cols + 1
        
        fig.add_trace(
            go.Indicator(
                mode="gauge+number+delta",
                value=value.get('current', 0),
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': name},
                delta={'reference': value.get('target', 100)},
                gauge={
                    'axis': {'range': [None, value.get('max', 100)]},
                    'bar': {'color': color_scheme['primary']},
                    'steps': [
                        {'range': [0, value.get('max', 100) * 0.5], 'color': "lightgray"},
                        {'range': [value.get('max', 100) * 0.5, value.get('max', 100) * 0.8], 'color': "gray"}
                    ],
                    'threshold': {
                        'line': {'color': color_scheme['danger'], 'width': 4},
                        'thickness': 0.75,
                        'value': value.get('threshold', 90)
                    }
                }
            ),
            row=row, col=col
        )
    
    fig.update_layout(
        template=PLOTLY_THEME,
        font=dict(color=color_scheme['text']),
        paper_bgcolor='rgba(0,0,0,0)',
        height=200 * rows
    )
    
    return fig