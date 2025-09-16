"""
Development components package
"""

# Import available components
try:
    from .sdlc_agile import explain_sdlc, explain_agile
    _sdlc_agile_available = True
except ImportError:
    _sdlc_agile_available = False

# Placeholder functions for components not yet implemented
def explain_scrum():
    """Placeholder for scrum component"""
    import streamlit as st
    st.info("🚧 Scrum Methodologies component is being refactored. Coming soon!")

try:
    from .design_patterns import explain_design_patterns
    _design_patterns_available = True
except ImportError:
    _design_patterns_available = False
    def explain_design_patterns():
        """Placeholder for design patterns component"""
        import streamlit as st
        st.info("🚧 Design Patterns component is being refactored. Coming soon!")

try:
    from .project_planning import explain_project_planning
    _project_planning_available = True
except ImportError:
    _project_planning_available = False
    def explain_project_planning():
        """Placeholder for project planning component"""
        import streamlit as st
        st.info("🚧 Project Planning component is being refactored. Coming soon!")

def explain_programming_paradigms():
    """Placeholder for programming paradigms component"""
    import streamlit as st
    st.info("🚧 Programming Paradigms component is being refactored. Coming soon!")

__all__ = []
if _sdlc_agile_available:
    __all__.extend(['explain_sdlc', 'explain_agile'])

if _design_patterns_available:
    __all__.append('explain_design_patterns')

if _project_planning_available:
    __all__.append('explain_project_planning')

__all__.extend([
    'explain_scrum',
    'explain_programming_paradigms'
])

# Add placeholders if not available
if not _design_patterns_available:
    __all__.append('explain_design_patterns')
if not _project_planning_available:
    __all__.append('explain_project_planning')
