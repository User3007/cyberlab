"""
Reusable UI components for the cybersecurity lab
"""

import streamlit as st
import pandas as pd
from typing import Dict, List, Any, Optional
from .color_schemes import get_color_scheme, create_gradient_css
from .constants import TIME_ESTIMATES, DIFFICULTY_LEVELS


def create_banner(title: str, 
                 description: str, 
                 color_scheme: Dict[str, str],
                 icon: str = "🔧",
                 estimated_time: str = None,
                 difficulty: str = None) -> None:
    """Create enhanced banner component"""
    
    # Build banner content - Ultra compact
    banner_content = f"""
    <div style="
        {create_gradient_css(color_scheme['primary'], color_scheme['secondary'])}
        padding: 0.5rem;
        border-radius: 4px;
        margin-bottom: 0.5rem;
        color: white;
        text-align: center;
        box-shadow: 0 1px 4px rgba(0, 0, 0, 0.1);
    ">
        <h1 style="margin: 0; font-size: 1.4rem;">{icon} {title}</h1>
        <p style="margin: 0; opacity: 0.9; font-size: 0.85rem;">{description}</p>
    """
    
    # Add metadata if provided - Ultra compact
    if estimated_time or difficulty:
        banner_content += '<div style="display: flex; justify-content: center; gap: 0.5rem; margin-top: 0.2rem;">'
        
        if estimated_time:
            banner_content += f'<div style="background: rgba(255, 255, 255, 0.2); padding: 0.2rem 0.5rem; border-radius: 10px;"><small style="font-size: 0.75rem;">⏱️ {estimated_time}</small></div>'
        
        if difficulty:
            banner_content += f'<div style="background: rgba(255, 255, 255, 0.2); padding: 0.2rem 0.5rem; border-radius: 10px;"><small style="font-size: 0.75rem;">{DIFFICULTY_LEVELS.get(difficulty, difficulty)}</small></div>'
        
        banner_content += '</div>'
    
    banner_content += '</div>'
    
    st.markdown(banner_content, unsafe_allow_html=True)


def create_takeaways(takeaways: List[str], 
                    title: str = "🎯 Key Takeaways",
                    color_scheme: Dict[str, str] = None) -> None:
    """Create key takeaways component"""
    
    if not color_scheme:
        color_scheme = get_color_scheme('theory_concepts')
    
    st.markdown(f"""
    <div style="
        background: {color_scheme['background']};
        border-left: 5px solid {color_scheme['primary']};
        padding: 1.5rem;
        border-radius: 8px;
        margin: 1rem 0;
    ">
        <h3 style="color: {color_scheme['primary']}; margin-top: 0;">{title}</h3>
    </div>
    """, unsafe_allow_html=True)
    
    for i, takeaway in enumerate(takeaways, 1):
        st.markdown(f"""
        <div style="
            background: white;
            padding: 1rem;
            margin: 0.5rem 0;
            border-radius: 6px;
            border-left: 3px solid {color_scheme['accent']};
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        ">
            <strong style="color: {color_scheme['primary']};">{i}.</strong> {takeaway}
        </div>
        """, unsafe_allow_html=True)


def create_cheat_sheet_tabs(cheat_sheets: Dict[str, Dict[str, Any]], 
                          color_scheme: Dict[str, str] = None) -> None:
    """Create tabbed cheat sheets component"""
    
    if not color_scheme:
        color_scheme = get_color_scheme('theory_concepts')
    
    st.markdown(f"### 📋 Cheat Sheets")
    
    # Create tabs
    tab_names = list(cheat_sheets.keys())
    tabs = st.tabs(tab_names)
    
    for tab, (sheet_name, sheet_data) in zip(tabs, cheat_sheets.items()):
        with tab:
            # Commands section
            if 'commands' in sheet_data:
                st.markdown("#### Commands")
                commands_df = pd.DataFrame(sheet_data['commands'])
                st.dataframe(commands_df, use_container_width=True)
            
            # Concepts section
            if 'concepts' in sheet_data:
                st.markdown("#### Key Concepts")
                for concept, description in sheet_data['concepts'].items():
                    st.markdown(f"""
                    <div style="
                        background: {color_scheme['background']};
                        padding: 0.8rem;
                        margin: 0.5rem 0;
                        border-radius: 6px;
                        border-left: 3px solid {color_scheme['primary']};
                    ">
                        <strong style="color: {color_scheme['primary']};">{concept}:</strong> {description}
                    </div>
                    """, unsafe_allow_html=True)
            
            # Examples section
            if 'examples' in sheet_data:
                st.markdown("#### Examples")
                for example in sheet_data['examples']:
                    with st.expander(example['title']):
                        st.code(example['code'], language=example.get('language', 'bash'))
                        if 'explanation' in example:
                            st.markdown(f"**Explanation:** {example['explanation']}")


def create_interactive_demo(demo_function, 
                          demo_params: Dict[str, Any] = None,
                          title: str = "🎮 Interactive Demo",
                          color_scheme: Dict[str, str] = None) -> None:
    """Create interactive demo wrapper"""
    
    if not color_scheme:
        color_scheme = get_color_scheme('theory_concepts')
    
    st.markdown(f"""
    <div style="
        background: {color_scheme['background']};
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
        border: 2px solid {color_scheme['primary']};
    ">
        <h3 style="color: {color_scheme['primary']}; margin-top: 0;">{title}</h3>
    </div>
    """, unsafe_allow_html=True)
    
    if demo_params:
        with st.expander("Demo Parameters", expanded=True):
            updated_params = {}
            
            # Create parameter inputs
            for param, config in demo_params.items():
                if config['type'] == 'slider':
                    updated_params[param] = st.slider(
                        config['label'],
                        min_value=config.get('min', 0),
                        max_value=config.get('max', 100),
                        value=config.get('default', 50),
                        help=config.get('help')
                    )
                elif config['type'] == 'selectbox':
                    updated_params[param] = st.selectbox(
                        config['label'],
                        options=config['options'],
                        index=config.get('default_index', 0),
                        help=config.get('help')
                    )
                elif config['type'] == 'multiselect':
                    updated_params[param] = st.multiselect(
                        config['label'],
                        options=config['options'],
                        default=config.get('default', []),
                        help=config.get('help')
                    )
                elif config['type'] == 'text_input':
                    updated_params[param] = st.text_input(
                        config['label'],
                        value=config.get('default', ''),
                        help=config.get('help')
                    )
                elif config['type'] == 'checkbox':
                    updated_params[param] = st.checkbox(
                        config['label'],
                        value=config.get('default', False),
                        help=config.get('help')
                    )
            
            # Run demo button
            if st.button("🚀 Run Demo", type="primary"):
                try:
                    result = demo_function(**updated_params)
                    _display_demo_result(result)
                except Exception as e:
                    st.error(f"Demo error: {str(e)}")
    else:
        if st.button("🚀 Run Demo", type="primary"):
            try:
                result = demo_function()
                _display_demo_result(result)
            except Exception as e:
                st.error(f"Demo error: {str(e)}")


def _display_demo_result(result: Any) -> None:
    """Display demo results with appropriate formatting"""
    if isinstance(result, dict):
        if 'figure' in result:
            st.plotly_chart(result['figure'], use_container_width=True)
        if 'data' in result:
            st.dataframe(result['data'], use_container_width=True)
        if 'message' in result:
            st.success(result['message'])
        if 'info' in result:
            st.info(result['info'])
        if 'warning' in result:
            st.warning(result['warning'])
        if 'error' in result:
            st.error(result['error'])
    else:
        st.write(result)


def create_info_card(title: str, 
                    content: str,
                    card_type: str = "info",
                    color_scheme: Dict[str, str] = None) -> None:
    """Create information card component"""
    
    if not color_scheme:
        color_scheme = get_color_scheme('theory_concepts')
    
    # Define card styles based on type
    card_styles = {
        'info': {'icon': 'ℹ️', 'color': color_scheme['info']},
        'success': {'icon': '✅', 'color': color_scheme['success']},
        'warning': {'icon': '⚠️', 'color': color_scheme['warning']},
        'danger': {'icon': '❌', 'color': color_scheme['danger']},
        'primary': {'icon': '🔵', 'color': color_scheme['primary']}
    }
    
    style = card_styles.get(card_type, card_styles['info'])
    
    st.markdown(f"""
    <div style="
        background: white;
        border-left: 5px solid {style['color']};
        padding: 1.5rem;
        border-radius: 8px;
        margin: 1rem 0;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    ">
        <h4 style="color: {style['color']}; margin-top: 0;">
            {style['icon']} {title}
        </h4>
        <p style="margin-bottom: 0; line-height: 1.6;">{content}</p>
    </div>
    """, unsafe_allow_html=True)


def create_progress_indicator(current_step: int, 
                            total_steps: int,
                            step_names: List[str] = None,
                            color_scheme: Dict[str, str] = None) -> None:
    """Create progress indicator component"""
    
    if not color_scheme:
        color_scheme = get_color_scheme('theory_concepts')
    
    progress = current_step / total_steps if total_steps > 0 else 0
    
    # Progress bar
    st.markdown(f"""
    <div style="
        background: #f0f2f6;
        border-radius: 10px;
        padding: 3px;
        margin: 1rem 0;
    ">
        <div style="
            background: {color_scheme['primary']};
            width: {progress * 100}%;
            height: 20px;
            border-radius: 8px;
            transition: width 0.3s ease;
        "></div>
    </div>
    """, unsafe_allow_html=True)
    
    # Progress text
    st.markdown(f"""
    <div style="text-align: center; color: {color_scheme['text']};">
        <strong>Step {current_step} of {total_steps}</strong> ({progress * 100:.0f}% Complete)
    </div>
    """, unsafe_allow_html=True)
    
    # Step names if provided
    if step_names and len(step_names) >= total_steps:
        current_step_name = step_names[current_step - 1] if current_step > 0 else "Not started"
        st.markdown(f"""
        <div style="
            text-align: center; 
            color: {color_scheme['primary']};
            font-weight: bold;
            margin-top: 0.5rem;
        ">
            {current_step_name}
        </div>
        """, unsafe_allow_html=True)
