"""
Security components package
"""

# Import available components
try:
    from .cia_triad import explain_cia_triad
    _cia_triad_available = True
except ImportError:
    _cia_triad_available = False

try:
    from .defense_in_depth import explain_defense_in_depth
    _defense_in_depth_available = True
except ImportError:
    _defense_in_depth_available = False

try:
    from .zero_trust import explain_zero_trust
    _zero_trust_available = True
except ImportError:
    _zero_trust_available = False

try:
    from .risk_assessment_simple import explain_risk_assessment
    _risk_assessment_available = True
except ImportError:
    try:
        from .risk_assessment import explain_risk_assessment
        _risk_assessment_available = True
    except ImportError:
        _risk_assessment_available = False

try:
    from .cyber_kill_chain import explain_cyber_kill_chain
    _cyber_kill_chain_available = True
except ImportError:
    _cyber_kill_chain_available = False

try:
    from .mitre_attack import explain_mitre_attack
    _mitre_attack_available = True
except ImportError:
    _mitre_attack_available = False

try:
    from .least_privilege import explain_least_privilege
    _least_privilege_available = True
except ImportError:
    _least_privilege_available = False

try:
    from .attack_vectors import explain_attack_vectors
    _attack_vectors_available = True
except ImportError:
    _attack_vectors_available = False

try:
    from .social_engineering import explain_social_engineering
    _social_engineering_available = True
except ImportError:
    _social_engineering_available = False

try:
    from .security_by_design import explain_security_by_design
    _security_by_design_available = True
except ImportError:
    _security_by_design_available = False

try:
    from .advanced_persistent_threats import explain_advanced_persistent_threats
    _apt_available = True
except ImportError:
    _apt_available = False

try:
    from .risk_management_principles import explain_risk_management_principles
    _risk_management_principles_available = True
except ImportError:
    _risk_management_principles_available = False

__all__ = []
if _cia_triad_available:
    __all__.append('explain_cia_triad')
if _defense_in_depth_available:
    __all__.append('explain_defense_in_depth')
if _zero_trust_available:
    __all__.append('explain_zero_trust')
if _risk_assessment_available:
    __all__.append('explain_risk_assessment')
if _cyber_kill_chain_available:
    __all__.append('explain_cyber_kill_chain')
if _mitre_attack_available:
    __all__.append('explain_mitre_attack')
if _least_privilege_available:
    __all__.append('explain_least_privilege')
if _attack_vectors_available:
    __all__.append('explain_attack_vectors')
if _social_engineering_available:
    __all__.append('explain_social_engineering')
if _security_by_design_available:
    __all__.append('explain_security_by_design')
if _apt_available:
    __all__.append('explain_advanced_persistent_threats')
if _risk_management_principles_available:
    __all__.append('explain_risk_management_principles')
