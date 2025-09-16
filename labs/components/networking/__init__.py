"""
Networking components package
"""

# Import available components (placeholder for now)
# Components will be added as they are refactored

__all__ = []

# Import available components
try:
    from .osi_model import explain_osi_model
    _osi_model_available = True
except ImportError:
    _osi_model_available = False

try:
    from .tcpip_stack import explain_tcpip_stack
    _tcpip_stack_available = True
except ImportError:
    _tcpip_stack_available = False

try:
    from .network_protocols import explain_network_protocols
    _network_protocols_available = True
except ImportError:
    _network_protocols_available = False

try:
    from .ip_addressing import explain_ip_addressing
    _ip_addressing_available = True
except ImportError:
    _ip_addressing_available = False

try:
    from .routing_switching import explain_routing_switching
    _routing_switching_available = True
except ImportError:
    _routing_switching_available = False

try:
    from .network_topologies import explain_network_topologies
    _network_topologies_available = True
except ImportError:
    _network_topologies_available = False

try:
    from .ip_subnetting import explain_ip_subnetting
    _ip_subnetting_available = True
except ImportError:
    _ip_subnetting_available = False

try:
    from .network_devices import explain_network_devices
    _network_devices_available = True
except ImportError:
    _network_devices_available = False

try:
    from .common_protocols import explain_common_protocols
    _common_protocols_available = True
except ImportError:
    _common_protocols_available = False

try:
    from .network_troubleshooting import explain_network_troubleshooting
    _network_troubleshooting_available = True
except ImportError:
    _network_troubleshooting_available = False

# Import working networking components
from .network_models import explain_network_models
from .routing_switching import explain_routing_switching
from .network_security_basics import explain_network_security_basics

__all__ = []
if _osi_model_available:
    __all__.append('explain_osi_model')
if _tcpip_stack_available:
    __all__.append('explain_tcpip_stack')
if _network_protocols_available:
    __all__.append('explain_network_protocols')
if _ip_addressing_available:
    __all__.append('explain_ip_addressing')
if _network_topologies_available:
    __all__.append('explain_network_topologies')
if _ip_subnetting_available:
    __all__.append('explain_ip_subnetting')
if _network_devices_available:
    __all__.append('explain_network_devices')
if _common_protocols_available:
    __all__.append('explain_common_protocols')
if _network_troubleshooting_available:
    __all__.append('explain_network_troubleshooting')

# Add working components
__all__.extend([
    'explain_network_models',
    'explain_routing_switching', 
    'explain_network_security_basics'
])
