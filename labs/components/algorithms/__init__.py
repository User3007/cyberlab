"""
Algorithms Components Package
Data structures and algorithms components
"""

# Import available components
try:
    from .sorting_algorithms import explain_sorting_algorithms
    _sorting_algorithms_available = True
except ImportError:
    _sorting_algorithms_available = False
    def explain_sorting_algorithms():
        """Placeholder for sorting algorithms component"""
        import streamlit as st
        st.info("🚧 Sorting Algorithms component is being refactored. Coming soon!")

# Placeholder functions for components not yet implemented
def explain_basic_data_structures():
    """Placeholder for basic data structures component"""
    import streamlit as st
    st.info("🚧 Basic Data Structures component is being refactored. Coming soon!")

def explain_advanced_data_structures():
    """Placeholder for advanced data structures component"""
    import streamlit as st
    st.info("🚧 Advanced Data Structures component is being refactored. Coming soon!")

def explain_searching_algorithms():
    """Placeholder for searching algorithms component"""
    import streamlit as st
    st.info("🚧 Searching Algorithms component is being refactored. Coming soon!")

def explain_algorithm_complexity():
    """Placeholder for algorithm complexity component"""
    import streamlit as st
    st.info("🚧 Algorithm Complexity component is being refactored. Coming soon!")

__all__ = []
if _sorting_algorithms_available:
    __all__.append('explain_sorting_algorithms')
else:
    __all__.append('explain_sorting_algorithms')  # Include placeholder

__all__.extend([
    'explain_basic_data_structures',
    'explain_advanced_data_structures',
    'explain_searching_algorithms',
    'explain_algorithm_complexity'
])
