"""
Component Template for creating standardized lab components
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from typing import Dict, List, Any, Optional, Callable
from abc import ABC, abstractmethod


class ComponentTemplate(ABC):
    """Base template for creating standardized lab components"""
    
    def __init__(self, 
                 component_name: str,
                 description: str,
                 color_scheme: Dict[str, str],
                 estimated_time: str = "15 minutes"):
        self.component_name = component_name
        self.description = description
        self.color_scheme = color_scheme
        self.estimated_time = estimated_time
        self.prerequisites = []
        self.learning_objectives = []
        self.key_concepts = []
    
    @abstractmethod
    def render_content(self):
        """Render the main content - must be implemented by subclasses"""
        pass
    
    def set_prerequisites(self, prerequisites: List[str]):
        """Set prerequisites for this component"""
        self.prerequisites = prerequisites
    
    def set_learning_objectives(self, objectives: List[str]):
        """Set learning objectives for this component"""
        self.learning_objectives = objectives
    
    def set_key_concepts(self, concepts: List[str]):
        """Set key concepts covered"""
        self.key_concepts = concepts
    
    def render_header(self):
        """Render standardized header"""
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, {self.color_scheme.get('primary', '#1f77b4')}, {self.color_scheme.get('secondary', '#ff7f0e')});
            padding: 1.5rem;
            border-radius: 12px;
            margin-bottom: 1.5rem;
            color: white;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        ">
            <h2 style="margin: 0 0 0.5rem 0;">{self.component_name}</h2>
            <p style="margin: 0; opacity: 0.9; font-size: 1.1rem;">{self.description}</p>
            <p style="margin: 0.5rem 0 0 0; opacity: 0.8; font-size: 0.9rem;">⏱️ Estimated time: {self.estimated_time}</p>
        </div>
        """, unsafe_allow_html=True)
    
    def render_prerequisites(self):
        """Render prerequisites section"""
        if self.prerequisites:
            with st.expander("📋 Prerequisites", expanded=False):
                for prereq in self.prerequisites:
                    st.markdown(f"• {prereq}")
    
    def render_learning_objectives(self):
        """Render learning objectives section"""
        if self.learning_objectives:
            with st.expander("🎯 Learning Objectives", expanded=False):
                for obj in self.learning_objectives:
                    st.markdown(f"• {obj}")
    
    def render_key_concepts(self):
        """Render key concepts section"""
        if self.key_concepts:
            st.subheader("🔑 Key Concepts")
            
            # Create columns for better layout
            cols = st.columns(min(len(self.key_concepts), 3))
            for i, concept in enumerate(self.key_concepts):
                with cols[i % len(cols)]:
                    st.markdown(f"""
                    <div style="
                        background: {self.color_scheme.get('accent', '#f8f9fa')};
                        padding: 1rem;
                        border-radius: 8px;
                        margin-bottom: 0.5rem;
                        border-left: 4px solid {self.color_scheme.get('primary', '#1f77b4')};
                    ">
                        <strong>{concept}</strong>
                    </div>
                    """, unsafe_allow_html=True)
    
    def render_summary(self, summary_points: List[str]):
        """Render summary section"""
        st.subheader("📝 Summary")
        
        for i, point in enumerate(summary_points, 1):
            st.markdown(f"**{i}.** {point}")
    
    def render_resources(self, resources: List[Dict[str, str]]):
        """Render additional resources section"""
        if resources:
            st.subheader("📚 Additional Resources")
            
            for resource in resources:
                if resource.get('url'):
                    st.markdown(f"• [{resource['title']}]({resource['url']}) - {resource.get('description', '')}")
                else:
                    st.markdown(f"• **{resource['title']}** - {resource.get('description', '')}")
    
    def create_interactive_element(self, 
                                 element_type: str,
                                 config: Dict[str, Any]) -> Any:
        """Create interactive elements based on type"""
        if element_type == "slider":
            return st.slider(
                config['label'],
                min_value=config.get('min', 0),
                max_value=config.get('max', 100),
                value=config.get('default', 50),
                help=config.get('help')
            )
        
        elif element_type == "selectbox":
            return st.selectbox(
                config['label'],
                options=config['options'],
                index=config.get('default_index', 0),
                help=config.get('help')
            )
        
        elif element_type == "multiselect":
            return st.multiselect(
                config['label'],
                options=config['options'],
                default=config.get('default', []),
                help=config.get('help')
            )
        
        elif element_type == "text_input":
            return st.text_input(
                config['label'],
                value=config.get('default', ''),
                help=config.get('help')
            )
        
        elif element_type == "text_area":
            return st.text_area(
                config['label'],
                value=config.get('default', ''),
                height=config.get('height', 100),
                help=config.get('help')
            )
        
        elif element_type == "checkbox":
            return st.checkbox(
                config['label'],
                value=config.get('default', False),
                help=config.get('help')
            )
        
        else:
            st.error(f"Unknown element type: {element_type}")
            return None
    
    def render_full_component(self, 
                            summary_points: Optional[List[str]] = None,
                            resources: Optional[List[Dict[str, str]]] = None):
        """Render the complete component with all sections"""
        # Header
        self.render_header()
        
        # Prerequisites and objectives in columns
        col1, col2 = st.columns(2)
        with col1:
            self.render_prerequisites()
        with col2:
            self.render_learning_objectives()
        
        # Key concepts
        self.render_key_concepts()
        
        # Main content (implemented by subclass)
        self.render_content()
        
        # Summary and resources
        if summary_points:
            self.render_summary(summary_points)
        
        if resources:
            self.render_resources(resources)
    
    def create_feedback_form(self):
        """Create feedback form for the component"""
        with st.expander("💬 Feedback", expanded=False):
            rating = st.select_slider(
                "How would you rate this component?",
                options=["Poor", "Fair", "Good", "Very Good", "Excellent"],
                value="Good"
            )
            
            feedback = st.text_area(
                "Any additional feedback?",
                placeholder="Your feedback helps us improve..."
            )
            
            if st.button("Submit Feedback"):
                # In a real implementation, you'd save this to a database
                st.success("Thank you for your feedback!")
                st.balloons()
