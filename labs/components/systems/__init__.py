"""
Systems components package
"""

# Import available components
try:
    from .computer_architecture import explain_computer_architecture
    from .cpu_memory import explain_cpu_memory
    from .storage_systems import explain_storage_systems  
    from .performance_analysis import explain_performance_analysis
    from .operating_systems import explain_operating_systems
    from .virtualization import explain_virtualization
    from .database_concepts import explain_database_concepts
    _systems_components_available = True
except ImportError:
    _systems_components_available = False

# Import advanced OS components
try:
    from .operating_systems_advanced import (
        explain_process_management,
        explain_memory_management,
        explain_file_systems
    )
    _advanced_os_available = True
except ImportError:
    _advanced_os_available = False
    def explain_process_management():
        """Placeholder for process management component"""
        import streamlit as st
        st.info(" Process Management component is being refactored. Coming soon!")
    
    def explain_memory_management():
        """Placeholder for memory management component"""
        import streamlit as st
        st.info(" Memory Management component is being refactored. Coming soon!")
    
    def explain_file_systems():
        """Placeholder for file systems component"""
        import streamlit as st
        st.info(" File Systems component is being refactored. Coming soon!")

# Import advanced database components
try:
    from .database_advanced import (
        explain_relational_databases,
        explain_sql_basics,
        explain_database_design
    )
    _advanced_db_available = True
except ImportError:
    _advanced_db_available = False
    def explain_relational_databases():
        """Placeholder for relational databases component"""
        import streamlit as st
        st.info(" Relational Databases component is being refactored. Coming soon!")
    
    def explain_sql_basics():
        """Placeholder for SQL basics component"""
        import streamlit as st
        st.info(" SQL Basics component is being refactored. Coming soon!")
    
    def explain_database_design():
        """Placeholder for database design component"""
        import streamlit as st
        st.info(" Database Design component is being refactored. Coming soon!")

# Import OS comparison component
try:
    from .os_comparison import explain_os_comparison
    _os_comparison_available = True
except ImportError:
    _os_comparison_available = False
    def explain_os_comparison():
        """Placeholder for OS comparison component"""
        import streamlit as st
        st.info(" OS Comparison component is being refactored. Coming soon!")

# Placeholder functions for components not yet implemented
def explain_os_fundamentals():
    """Redirect to new operating_systems component"""
    explain_operating_systems()

__all__ = []
if _systems_components_available:
    __all__.extend([
        'explain_computer_architecture',
        'explain_cpu_memory', 
        'explain_storage_systems',
        'explain_performance_analysis',
        'explain_operating_systems',
        'explain_virtualization',
        'explain_database_concepts'
    ])

# Add advanced OS v database components
__all__.extend([
    'explain_os_fundamentals',
    'explain_process_management',
    'explain_memory_management',
    'explain_file_systems',
    'explain_relational_databases',
    'explain_sql_basics',
    'explain_database_design',
    'explain_os_comparison'
])
