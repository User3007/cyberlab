"""
Legal components package
"""

# Import available components
try:
    from .ethical_hacking import explain_ethical_hacking_guidelines
    _ethical_hacking_available = True
except ImportError:
    _ethical_hacking_available = False
    def explain_ethical_hacking_guidelines():
        """Placeholder for ethical hacking component"""
        import streamlit as st
        st.info("Ethical Hacking Guidelines component is being refactored. Coming soon!")

try:
    from .privacy_protection import explain_privacy_data_protection
    _privacy_protection_available = True
except ImportError:
    _privacy_protection_available = False
    def explain_privacy_data_protection():
        """Placeholder for privacy protection component"""
        import streamlit as st
        st.info("Privacy and Data Protection component is being refactored. Coming soon!")

try:
    from .incident_response_legal import explain_incident_response_legal
    _incident_response_legal_available = True
except ImportError:
    _incident_response_legal_available = False
    def explain_incident_response_legal():
        """Placeholder for incident response legal component"""
        import streamlit as st
        st.info("Incident Response Legal component is being refactored. Coming soon!")

__all__ = []
if _ethical_hacking_available:
    __all__.append('explain_ethical_hacking_guidelines')
else:
    __all__.append('explain_ethical_hacking_guidelines')  # Include placeholder

if _privacy_protection_available:
    __all__.append('explain_privacy_data_protection')
else:
    __all__.append('explain_privacy_data_protection')  # Include placeholder

if _incident_response_legal_available:
    __all__.append('explain_incident_response_legal')
else:
    __all__.append('explain_incident_response_legal')  # Include placeholder
