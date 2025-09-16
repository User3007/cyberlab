"""
Shared utilities package
"""

from .color_schemes import *
from .constants import *
from .ui_components import *
from .diagram_utils import *
from .data_utils import *

__all__ = [
    # Color schemes
    'THEORY_CONCEPTS_COLORS',
    'IT_FUNDAMENTALS_COLORS',
    'SOFTWARE_DEV_COLORS', 
    'NETWORK_SECURITY_COLORS',
    'CRYPTOGRAPHY_COLORS',
    
    # UI components
    'create_banner',
    'create_takeaways',
    'create_cheat_sheet_tabs',
    'create_interactive_demo',
    
    # Diagram utilities
    'create_basic_figure',
    'add_network_diagram',
    'add_security_triangle',
    'add_architecture_diagram',
    'add_process_flow',
    
    # Data utilities
    'create_comparison_table',
    'format_metrics',
    'generate_demo_data'
]
