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

__all__.extend([
    'explain_os_fundamentals'
])
