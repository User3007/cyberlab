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
    st.info(" Scrum Methodologies component is being refactored. Coming soon!")

try:
    from .design_patterns import explain_design_patterns
    _design_patterns_available = True
except ImportError:
    _design_patterns_available = False
    def explain_design_patterns():
        """Placeholder for design patterns component"""
        import streamlit as st
        st.info(" Design Patterns component is being refactored. Coming soon!")

try:
    from .project_planning import explain_project_planning
    _project_planning_available = True
except ImportError:
    _project_planning_available = False
    def explain_project_planning():
        """Placeholder for project planning component"""
        import streamlit as st
        st.info(" Project Planning component is being refactored. Coming soon!")

try:
    from .risk_management_pm import explain_risk_management_pm
    _risk_management_pm_available = True
except ImportError:
    _risk_management_pm_available = False
    def explain_risk_management_pm():
        """Placeholder for risk management component"""
        import streamlit as st
        st.info(" Risk Management component is being refactored. Coming soon!")

try:
    from .team_management import explain_team_management
    _team_management_available = True
except ImportError:
    _team_management_available = False
    def explain_team_management():
        """Placeholder for team management component"""
        import streamlit as st
        st.info(" Team Management component is being refactored. Coming soon!")

try:
    from .programming_paradigms import explain_programming_paradigms
    _programming_paradigms_available = True
except ImportError:
    _programming_paradigms_available = False
    def explain_programming_paradigms():
        """Placeholder for programming paradigms component"""
        import streamlit as st
        st.info(" Programming Paradigms component is being refactored. Coming soon!")

__all__ = []
if _sdlc_agile_available:
    __all__.extend(['explain_sdlc', 'explain_agile'])

if _design_patterns_available:
    __all__.append('explain_design_patterns')

if _project_planning_available:
    __all__.append('explain_project_planning')

if _risk_management_pm_available:
    __all__.append('explain_risk_management_pm')

if _team_management_available:
    __all__.append('explain_team_management')

__all__.extend([
    'explain_scrum'
])

if _programming_paradigms_available:
    __all__.append('explain_programming_paradigms')
else:
    __all__.append('explain_programming_paradigms')  # Include placeholder

try:
    from .pm_fundamentals import explain_pm_fundamentals
    _pm_fundamentals_available = True
except ImportError:
    _pm_fundamentals_available = False
    def explain_pm_fundamentals():
        """Placeholder for PM fundamentals component"""
        import streamlit as st
        st.info(" PM Fundamentals component is being refactored. Coming soon!")

try:
    from .project_tools import explain_project_tools
    _project_tools_available = True
except ImportError:
    _project_tools_available = False
    def explain_project_tools():
        """Placeholder for project tools component"""
        import streamlit as st
        st.info(" Project Tools component is being refactored. Coming soon!")

if _pm_fundamentals_available:
    __all__.append('explain_pm_fundamentals')
else:
    __all__.append('explain_pm_fundamentals')  # Include placeholder

if _project_tools_available:
    __all__.append('explain_project_tools')
else:
    __all__.append('explain_project_tools')  # Include placeholder

try:
    from .scrum_framework import explain_scrum
    _scrum_available = True
except ImportError:
    _scrum_available = False
    def explain_scrum():
        """Placeholder for scrum component"""
        import streamlit as st
        st.info(" Scrum Framework component is being refactored. Coming soon!")

try:
    from .waterfall_model import explain_waterfall
    _waterfall_available = True
except ImportError:
    _waterfall_available = False
    def explain_waterfall():
        """Placeholder for waterfall component"""
        import streamlit as st
        st.info(" Waterfall Model component is being refactored. Coming soon!")

try:
    from .oop_concepts import explain_oop
    _oop_available = True
except ImportError:
    _oop_available = False
    def explain_oop():
        """Placeholder for OOP component"""
        import streamlit as st
        st.info(" OOP component is being refactored. Coming soon!")

if _scrum_available:
    __all__.append('explain_scrum')
else:
    __all__.append('explain_scrum')  # Include placeholder

if _waterfall_available:
    __all__.append('explain_waterfall')
else:
    __all__.append('explain_waterfall')  # Include placeholder

if _oop_available:
    __all__.append('explain_oop')
else:
    __all__.append('explain_oop')  # Include placeholder

try:
    from .functional_programming import explain_functional_programming
    _functional_programming_available = True
except ImportError:
    _functional_programming_available = False
    def explain_functional_programming():
        """Placeholder for functional programming component"""
        import streamlit as st
        st.info(" Functional Programming component is being refactored. Coming soon!")

try:
    from .code_quality import explain_code_quality
    _code_quality_available = True
except ImportError:
    _code_quality_available = False
    def explain_code_quality():
        """Placeholder for code quality component"""
        import streamlit as st
        st.info(" Code Quality component is being refactored. Coming soon!")

if _functional_programming_available:
    __all__.append('explain_functional_programming')
else:
    __all__.append('explain_functional_programming')  # Include placeholder

if _code_quality_available:
    __all__.append('explain_code_quality')
else:
    __all__.append('explain_code_quality')  # Include placeholder

# Add placeholders if not available
if not _design_patterns_available:
    __all__.append('explain_design_patterns')
if not _project_planning_available:
    __all__.append('explain_project_planning')
if not _risk_management_pm_available:
    __all__.append('explain_risk_management_pm')
if not _team_management_available:
    __all__.append('explain_team_management')
