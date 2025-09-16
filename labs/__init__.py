"""
Cybersecurity Labs Package - Refactored Modular Architecture
"""

# Import refactored main modules
from .main_modules import theory_concepts
from .main_modules import it_fundamentals
from .main_modules import software_development

# Import legacy modules (to be refactored)
from . import network_security
from . import cryptography_lab
from . import digital_forensics
from . import web_security
from . import wireless_security
from . import advanced_networking

__all__ = [
    # Refactored modules
    'theory_concepts',
    'it_fundamentals', 
    'software_development',
    
    # Legacy modules (to be refactored)
    'network_security',
    'cryptography_lab',
    'digital_forensics',
    'web_security',
    'wireless_security',
    'advanced_networking'
]