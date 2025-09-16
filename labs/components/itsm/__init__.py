"""
IT Service Management (ITSM) components package
"""

# Import available components
try:
    from .itil_framework import explain_itil_framework
    _itil_framework_available = True
except ImportError:
    _itil_framework_available = False
    def explain_itil_framework():
        """Placeholder for ITIL framework component"""
        import streamlit as st
        st.info("ITIL Framework component is being refactored. Coming soon!")

try:
    from .incident_management import explain_incident_management
    _incident_management_available = True
except ImportError:
    _incident_management_available = False
    def explain_incident_management():
        """Placeholder for incident management component"""
        import streamlit as st
        st.info("Incident Management component is being refactored. Coming soon!")

try:
    from .change_management import explain_change_management
    _change_management_available = True
except ImportError:
    _change_management_available = False
    def explain_change_management():
        """Placeholder for change management component"""
        import streamlit as st
        st.info("Change Management component is being refactored. Coming soon!")

try:
    from .service_level_management import explain_service_level_management
    _service_level_management_available = True
except ImportError:
    _service_level_management_available = False
    def explain_service_level_management():
        """Placeholder for SLA management component"""
        import streamlit as st
        st.info("Service Level Management component is being refactored. Coming soon!")

try:
    from .it_governance import explain_it_governance
    _it_governance_available = True
except ImportError:
    _it_governance_available = False
    def explain_it_governance():
        """Placeholder for IT governance component"""
        import streamlit as st
        st.info("IT Governance component is being refactored. Coming soon!")

__all__ = []
if _itil_framework_available:
    __all__.append('explain_itil_framework')
else:
    __all__.append('explain_itil_framework')  # Include placeholder

if _incident_management_available:
    __all__.append('explain_incident_management')
else:
    __all__.append('explain_incident_management')  # Include placeholder

if _change_management_available:
    __all__.append('explain_change_management')
else:
    __all__.append('explain_change_management')  # Include placeholder

if _service_level_management_available:
    __all__.append('explain_service_level_management')
else:
    __all__.append('explain_service_level_management')  # Include placeholder

if _it_governance_available:
    __all__.append('explain_it_governance')
else:
    __all__.append('explain_it_governance')  # Include placeholder
