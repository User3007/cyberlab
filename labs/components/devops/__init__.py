"""
DevOps Components Package
DevOps and CI/CD related components
"""

# Import available components
try:
    from .continuous_integration import explain_continuous_integration
    _continuous_integration_available = True
except ImportError:
    _continuous_integration_available = False
    def explain_continuous_integration():
        """Placeholder for continuous integration component"""
        import streamlit as st
        st.info("🚧 Continuous Integration component is being refactored. Coming soon!")

# Placeholder functions for components not yet implemented
def explain_devops_culture():
    """Placeholder for devops culture component"""
    import streamlit as st
    st.info("🚧 DevOps Culture component is being refactored. Coming soon!")

def explain_continuous_deployment():
    """Placeholder for continuous deployment component"""
    import streamlit as st
    st.info("🚧 Continuous Deployment component is being refactored. Coming soon!")

def explain_infrastructure_as_code():
    """Placeholder for infrastructure as code component"""
    import streamlit as st
    st.info("🚧 Infrastructure as Code component is being refactored. Coming soon!")

def explain_monitoring_logging():
    """Placeholder for monitoring logging component"""
    import streamlit as st
    st.info("🚧 Monitoring & Logging component is being refactored. Coming soon!")

__all__ = []
if _continuous_integration_available:
    __all__.append('explain_continuous_integration')
else:
    __all__.append('explain_continuous_integration')  # Include placeholder

__all__.extend([
    'explain_devops_culture',
    'explain_continuous_deployment',
    'explain_infrastructure_as_code',
    'explain_monitoring_logging'
])
