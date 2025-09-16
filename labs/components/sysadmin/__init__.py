"""
System Administration components package
"""

# Import available components
try:
    from .user_management import explain_user_management
    _user_management_available = True
except ImportError:
    _user_management_available = False
    def explain_user_management():
        """Placeholder for user management component"""
        import streamlit as st
        st.info("User Management component is being refactored. Coming soon!")

try:
    from .system_monitoring import explain_system_monitoring
    _system_monitoring_available = True
except ImportError:
    _system_monitoring_available = False
    def explain_system_monitoring():
        """Placeholder for system monitoring component"""
        import streamlit as st
        st.info("System Monitoring component is being refactored. Coming soon!")

try:
    from .backup_recovery import explain_backup_recovery
    _backup_recovery_available = True
except ImportError:
    _backup_recovery_available = False
    def explain_backup_recovery():
        """Placeholder for backup recovery component"""
        import streamlit as st
        st.info("Backup and Recovery component is being refactored. Coming soon!")

try:
    from .performance_tuning import explain_performance_tuning
    _performance_tuning_available = True
except ImportError:
    _performance_tuning_available = False
    def explain_performance_tuning():
        """Placeholder for performance tuning component"""
        import streamlit as st
        st.info("Performance Tuning component is being refactored. Coming soon!")

try:
    from .security_hardening import explain_security_hardening
    _security_hardening_available = True
except ImportError:
    _security_hardening_available = False
    def explain_security_hardening():
        """Placeholder for security hardening component"""
        import streamlit as st
        st.info("Security Hardening component is being refactored. Coming soon!")

__all__ = []
if _user_management_available:
    __all__.append('explain_user_management')
else:
    __all__.append('explain_user_management')  # Include placeholder

if _system_monitoring_available:
    __all__.append('explain_system_monitoring')
else:
    __all__.append('explain_system_monitoring')  # Include placeholder

if _backup_recovery_available:
    __all__.append('explain_backup_recovery')
else:
    __all__.append('explain_backup_recovery')  # Include placeholder

if _performance_tuning_available:
    __all__.append('explain_performance_tuning')
else:
    __all__.append('explain_performance_tuning')  # Include placeholder

if _security_hardening_available:
    __all__.append('explain_security_hardening')
else:
    __all__.append('explain_security_hardening')  # Include placeholder
