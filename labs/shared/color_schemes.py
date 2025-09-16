"""
Color schemes for different lab modules
"""

# Theory Concepts Colors
THEORY_CONCEPTS_COLORS = {
    'primary': '#667eea',
    'secondary': '#764ba2', 
    'accent': '#f093fb',
    'background': '#ffecd2',
    'text': '#2d3436',
    'success': '#00b894',
    'warning': '#fdcb6e',
    'danger': '#e17055',
    'info': '#74b9ff'
}

# IT Fundamentals Colors
IT_FUNDAMENTALS_COLORS = {
    'primary': '#4ecdc4',
    'secondary': '#44a08d',
    'accent': '#96ceb4',
    'background': '#dff9fb',
    'text': '#2d3436',
    'success': '#00b894',
    'warning': '#fdcb6e', 
    'danger': '#e17055',
    'info': '#74b9ff'
}

# Software Development Colors
SOFTWARE_DEV_COLORS = {
    'primary': '#ff6b6b',
    'secondary': '#ee5a24',
    'accent': '#ff7675',
    'background': '#ffe8e8',
    'text': '#2d3436',
    'success': '#00b894',
    'warning': '#fdcb6e',
    'danger': '#e17055',
    'info': '#74b9ff'
}

# Alias for backward compatibility
SOFTWARE_DEVELOPMENT_COLORS = SOFTWARE_DEV_COLORS

# Network Security Colors  
NETWORK_SECURITY_COLORS = {
    'primary': '#45b7d1',
    'secondary': '#3742fa',
    'accent': '#70a1ff',
    'background': '#e8f4f8',
    'text': '#2d3436',
    'success': '#00b894',
    'warning': '#fdcb6e',
    'danger': '#e17055', 
    'info': '#74b9ff'
}

# Cryptography Colors
CRYPTOGRAPHY_COLORS = {
    'primary': '#a55eea',
    'secondary': '#8854d0',
    'accent': '#c44569',
    'background': '#f4e8ff',
    'text': '#2d3436',
    'success': '#00b894',
    'warning': '#fdcb6e',
    'danger': '#e17055',
    'info': '#74b9ff'
}

# Universal color mappings
COLOR_MAPPINGS = {
    'theory_concepts': THEORY_CONCEPTS_COLORS,
    'it_fundamentals': IT_FUNDAMENTALS_COLORS,
    'software_development': SOFTWARE_DEV_COLORS,
    'network_security': NETWORK_SECURITY_COLORS,
    'cryptography': CRYPTOGRAPHY_COLORS
}

def get_color_scheme(module_name: str) -> dict:
    """Get color scheme for a specific module"""
    return COLOR_MAPPINGS.get(module_name.lower(), THEORY_CONCEPTS_COLORS)

def create_gradient_css(primary: str, secondary: str) -> str:
    """Create CSS gradient string"""
    return f"background: linear-gradient(135deg, {primary}, {secondary});"
