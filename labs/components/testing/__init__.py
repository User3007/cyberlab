"""
Testing & QA Components Package
Software testing and quality assurance components
"""

# Import testing components
try:
    from .testing_fundamentals import (
        explain_testing_fundamentals,
        explain_testing_types,
        explain_quality_assurance_process,
        explain_testing_tools
    )
    _testing_available = True
except ImportError:
    _testing_available = False
    def explain_testing_fundamentals():
        """Placeholder for testing fundamentals component"""
        import streamlit as st
        st.info(" Testing Fundamentals component is being refactored. Coming soon!")
    
    def explain_testing_types():
        """Placeholder for testing types component"""
        import streamlit as st
        st.info(" Testing Types component is being refactored. Coming soon!")
    
    def explain_quality_assurance_process():
        """Placeholder for QA process component"""
        import streamlit as st
        st.info(" Quality Assurance Process component is being refactored. Coming soon!")
    
    def explain_testing_tools():
        """Placeholder for testing tools component"""
        import streamlit as st
        st.info(" Testing Tools component is being refactored. Coming soon!")

__all__ = [
    'explain_testing_fundamentals',
    'explain_testing_types', 
    'explain_quality_assurance_process',
    'explain_testing_tools'
]
