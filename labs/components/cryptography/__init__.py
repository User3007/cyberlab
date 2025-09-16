"""
Cryptography components package
"""

# Import available components (placeholder for now)
# Components will be added as they are refactored

__all__ = []

# Import available components
try:
    from .encryption_types import explain_encryption_types
    _encryption_types_available = True
except ImportError:
    _encryption_types_available = False
    def explain_encryption_types():
        """Placeholder for encryption types component"""
        import streamlit as st
        st.info("🚧 Encryption Types component is being refactored. Coming soon!")

try:
    from .key_management import explain_key_management
    _key_management_available = True
except ImportError:
    _key_management_available = False
    def explain_key_management():
        """Placeholder for key management component"""
        import streamlit as st
        st.info("🚧 Key Management component is being refactored. Coming soon!")

def explain_hash_signatures():
    """Placeholder for hash signatures component"""
    import streamlit as st
    st.info("🚧 Hash Functions & Digital Signatures component is being refactored. Coming soon!")

def explain_modern_crypto():
    """Placeholder for modern crypto component"""
    import streamlit as st
    st.info("🚧 Modern Cryptography component is being refactored. Coming soon!")

__all__ = []
if _encryption_types_available:
    __all__.append('explain_encryption_types')
else:
    __all__.append('explain_encryption_types')  # Include placeholder

if _key_management_available:
    __all__.append('explain_key_management')
else:
    __all__.append('explain_key_management')  # Include placeholder

__all__.extend([
    'explain_hash_signatures',
    'explain_modern_crypto'
])
