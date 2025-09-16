"""
Main modules package - Controllers for refactored lab modules
"""

from .theory_concepts import run_lab as theory_concepts_lab
from .it_fundamentals import run_lab as it_fundamentals_lab  
from .software_development import run_lab as software_development_lab

__all__ = [
    'theory_concepts_lab',
    'it_fundamentals_lab', 
    'software_development_lab'
]
