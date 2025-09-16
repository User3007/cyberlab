"""
Shared constants and configurations
"""

# Application constants
APP_TITLE = "Cybersecurity Lab Environment"
APP_VERSION = "2.0.0"
APP_DESCRIPTION = "Interactive cybersecurity learning platform"

# UI Constants
DEFAULT_CHART_HEIGHT = 400
DEFAULT_CHART_WIDTH = 800
SIDEBAR_WIDTH = 300
CONTENT_PADDING = "1rem"

# Component sizes
COMPONENT_MAX_LINES = 500
LARGE_MODULE_THRESHOLD = 1000
CRITICAL_MODULE_THRESHOLD = 3000

# Time estimates (in minutes)
TIME_ESTIMATES = {
    'quick': '5-10 minutes',
    'short': '10-15 minutes', 
    'medium': '15-30 minutes',
    'long': '30-45 minutes',
    'extended': '45+ minutes'
}

# Difficulty levels
DIFFICULTY_LEVELS = {
    'beginner': '🟢 Beginner',
    'intermediate': '🟡 Intermediate', 
    'advanced': '🔴 Advanced',
    'expert': '⚫ Expert'
}

# Lab categories
LAB_CATEGORIES = [
    'theory_concepts',
    'it_fundamentals', 
    'software_development',
    'network_security',
    'cryptography',
    'digital_forensics',
    'web_security',
    'wireless_security',
    'advanced_networking'
]

# File extensions for different content types
CONTENT_EXTENSIONS = {
    'python': '.py',
    'markdown': '.md',
    'json': '.json',
    'yaml': '.yml',
    'text': '.txt'
}

# Default chart configurations
DEFAULT_CHART_CONFIG = {
    'displayModeBar': False,
    'displaylogo': False,
    'modeBarButtonsToRemove': [
        'pan2d', 'lasso2d', 'select2d', 'autoScale2d',
        'hoverClosestCartesian', 'hoverCompareCartesian'
    ]
}

# Plotly theme
PLOTLY_THEME = "plotly_white"

# Session state keys
SESSION_KEYS = {
    'current_lab': 'current_lab',
    'progress': 'user_progress',
    'preferences': 'user_preferences',
    'quiz_scores': 'quiz_scores',
    'demo_data': 'demo_data'
}

# Progress tracking
PROGRESS_STAGES = [
    'not_started',
    'in_progress', 
    'completed',
    'reviewed'
]

# Quiz configurations
QUIZ_CONFIG = {
    'passing_score': 70,
    'max_attempts': 3,
    'time_limit': 300,  # seconds
    'show_correct_answers': True
}

# Demo data configurations
DEMO_DATA_CONFIG = {
    'sample_size': 100,
    'random_seed': 42,
    'date_range': 30  # days
}
