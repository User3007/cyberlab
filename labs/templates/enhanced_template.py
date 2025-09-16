"""
Enhanced Template for creating feature-rich components
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime


class EnhancedTemplate:
    """Enhanced template with rich UI components and features"""
    
    def __init__(self, 
                 title: str,
                 description: str,
                 color_scheme: Dict[str, str],
                 icon: str = "🔧"):
        self.title = title
        self.description = description
        self.color_scheme = color_scheme
        self.icon = icon
        self.session_data = {}
    
    def create_enhanced_header(self):
        """Create enhanced header with styling"""
        st.markdown(f"""
        <div style="
            background: linear-gradient(90deg, {self.color_scheme.get('primary', '#1f77b4')}, {self.color_scheme.get('secondary', '#ff7f0e')});
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 1rem;
            color: white;
            text-align: center;
        ">
            <h1>{self.icon} {self.title}</h1>
            <p style="margin: 0; opacity: 0.9;">{self.description}</p>
        </div>
        """, unsafe_allow_html=True)
    
    def create_info_panel(self, content: Dict[str, Any]):
        """Create informational panel with key points"""
        with st.expander("ℹ️ Key Information", expanded=False):
            for key, value in content.items():
                if isinstance(value, list):
                    st.markdown(f"**{key}:**")
                    for item in value:
                        st.markdown(f"• {item}")
                else:
                    st.markdown(f"**{key}:** {value}")
    
    def create_interactive_demo(self, 
                              demo_function: Callable,
                              demo_params: Dict[str, Any] = None):
        """Create interactive demonstration section"""
        st.subheader("🎮 Interactive Demo")
        
        if demo_params:
            with st.expander("Demo Parameters", expanded=True):
                updated_params = {}
                for param, config in demo_params.items():
                    if config['type'] == 'slider':
                        updated_params[param] = st.slider(
                            config['label'],
                            min_value=config.get('min', 0),
                            max_value=config.get('max', 100),
                            value=config.get('default', 50)
                        )
                    elif config['type'] == 'selectbox':
                        updated_params[param] = st.selectbox(
                            config['label'],
                            options=config['options'],
                            index=config.get('default_index', 0)
                        )
                    elif config['type'] == 'text_input':
                        updated_params[param] = st.text_input(
                            config['label'],
                            value=config.get('default', '')
                        )
                
                if st.button("Run Demo"):
                    result = demo_function(**updated_params)
                    self.display_demo_result(result)
        else:
            if st.button("Run Demo"):
                result = demo_function()
                self.display_demo_result(result)
    
    def display_demo_result(self, result: Any):
        """Display demo results with appropriate formatting"""
        if isinstance(result, dict):
            if 'figure' in result:
                st.plotly_chart(result['figure'], use_container_width=True)
            if 'data' in result:
                st.dataframe(result['data'])
            if 'message' in result:
                st.success(result['message'])
        elif isinstance(result, go.Figure):
            st.plotly_chart(result, use_container_width=True)
        elif isinstance(result, pd.DataFrame):
            st.dataframe(result)
        else:
            st.write(result)
    
    def create_comparison_table(self, 
                              data: List[Dict[str, Any]],
                              title: str = "Comparison Table"):
        """Create enhanced comparison table"""
        st.subheader(f"📊 {title}")
        
        df = pd.DataFrame(data)
        
        # Style the dataframe
        styled_df = df.style.apply(self._highlight_rows, axis=1)
        st.dataframe(styled_df, use_container_width=True)
        
        # Add download button
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"{title.lower().replace(' ', '_')}.csv",
            mime="text/csv"
        )
    
    def _highlight_rows(self, row):
        """Apply row highlighting for better readability"""
        return ['background-color: #f0f2f6' if row.name % 2 == 0 else '' for _ in row]
    
    def create_progress_tracker(self, 
                              steps: List[str],
                              current_step: int):
        """Create progress tracking component"""
        st.subheader("📈 Progress Tracker")
        
        progress = current_step / len(steps)
        st.progress(progress)
        
        st.markdown(f"**Step {current_step} of {len(steps)}:** {steps[current_step-1] if current_step > 0 else 'Not started'}")
        
        with st.expander("All Steps"):
            for i, step in enumerate(steps, 1):
                status = "✅" if i <= current_step else "⏳"
                st.markdown(f"{status} **Step {i}:** {step}")
    
    def create_takeaways_section(self, takeaways: List[str]):
        """Create key takeaways section"""
        st.subheader("🎯 Key Takeaways")
        
        for i, takeaway in enumerate(takeaways, 1):
            st.markdown(f"**{i}.** {takeaway}")
    
    def create_quiz_section(self, questions: List[Dict[str, Any]]):
        """Create interactive quiz section"""
        st.subheader("📝 Knowledge Check")
        
        score = 0
        total_questions = len(questions)
        
        for i, question in enumerate(questions):
            st.markdown(f"**Question {i+1}:** {question['question']}")
            
            user_answer = st.radio(
                "Select your answer:",
                question['options'],
                key=f"q_{i}"
            )
            
            if st.button(f"Check Answer {i+1}", key=f"check_{i}"):
                if user_answer == question['correct']:
                    st.success("✅ Correct!")
                    score += 1
                else:
                    st.error(f"❌ Incorrect. The correct answer is: {question['correct']}")
                
                if 'explanation' in question:
                    st.info(f"💡 **Explanation:** {question['explanation']}")
        
        if st.button("Show Final Score"):
            percentage = (score / total_questions) * 100
            st.metric("Final Score", f"{score}/{total_questions}", f"{percentage:.1f}%")
    
    def save_session_data(self, key: str, value: Any):
        """Save data to session state"""
        if f"enhanced_template_{key}" not in st.session_state:
            st.session_state[f"enhanced_template_{key}"] = value
    
    def get_session_data(self, key: str, default: Any = None):
        """Get data from session state"""
        return st.session_state.get(f"enhanced_template_{key}", default)
