"""
Design Patterns Component
Software design patterns with practical examples
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Any

from ...shared.color_schemes import SOFTWARE_DEVELOPMENT_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class DesignPatternsComponent(ComponentTemplate):
    """Design Patterns component with practical examples"""
    
    def __init__(self):
        super().__init__(
            component_name=" Design Patterns",
            description="Essential software design patterns with practical implementation examples",
            color_scheme=SOFTWARE_DEVELOPMENT_COLORS,
            estimated_time="30 minutes"
        )
        
        # Design patterns data
        self.patterns_data = {
            "Creational": {
                "Singleton": {
                    "description": "Ensures a class has only one instance and provides global access to it",
                    "use_case": "Database connections, logging, configuration management",
                    "pros": ["Controlled access to sole instance", "Reduced namespace", "Lazy initialization"],
                    "cons": ["Difficult to test", "Hidden dependencies", "Violates Single Responsibility"],
                    "example": """
class Singleton:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
                    """
                },
                "Factory Method": {
                    "description": "Creates objects without specifying exact classes to create",
                    "use_case": "Creating UI elements, database drivers, file parsers",
                    "pros": ["Loose coupling", "Single Responsibility", "Open/Closed Principle"],
                    "cons": ["Code complexity", "Many subclasses needed"],
                    "example": """
class ShapeFactory:
    @staticmethod
    def create_shape(shape_type):
        if shape_type == "circle":
            return Circle()
        elif shape_type == "square":
            return Square()
                    """
                },
                "Builder": {
                    "description": "Constructs complex objects step by step",
                    "use_case": "SQL queries, HTML builders, configuration objects",
                    "pros": ["Step-by-step construction", "Different representations", "Complex object creation"],
                    "cons": ["Code complexity", "More classes needed"],
                    "example": """
class QueryBuilder:
    def __init__(self):
        self.query = ""
    
    def select(self, fields):
        self.query += f"SELECT {fields} "
        return self
    
    def from_table(self, table):
        self.query += f"FROM {table} "
        return self
                    """
                }
            },
            "Structural": {
                "Adapter": {
                    "description": "Allows incompatible interfaces to work together",
                    "use_case": "Third-party libraries, legacy code integration",
                    "pros": ["Reuse existing code", "Separation of concerns"],
                    "cons": ["Code complexity", "Additional abstraction layer"],
                    "example": """
class LegacyPrinter:
    def old_print(self, text):
        print(f"Legacy: {text}")

class PrinterAdapter:
    def __init__(self, legacy_printer):
        self.printer = legacy_printer
    
    def print(self, text):
        self.printer.old_print(text)
                    """
                },
                "Decorator": {
                    "description": "Adds new functionality to objects without altering structure",
                    "use_case": "Middleware, caching, logging, authentication",
                    "pros": ["Runtime behavior extension", "Single Responsibility", "Composition over inheritance"],
                    "cons": ["Many small objects", "Complex decorator stacks"],
                    "example": """
def cache_decorator(func):
    cache = {}
    def wrapper(*args):
        if args in cache:
            return cache[args]
        result = func(*args)
        cache[args] = result
        return result
    return wrapper
                    """
                },
                "Facade": {
                    "description": "Provides simplified interface to complex subsystem",
                    "use_case": "API wrappers, complex library interfaces",
                    "pros": ["Simplified interface", "Loose coupling", "Layered architecture"],
                    "cons": ["May become god object", "Limited functionality exposure"],
                    "example": """
class DatabaseFacade:
    def __init__(self):
        self.connection = DatabaseConnection()
        self.query_builder = QueryBuilder()
        self.validator = DataValidator()
    
    def save_user(self, user_data):
        self.validator.validate(user_data)
        query = self.query_builder.insert('users', user_data)
        return self.connection.execute(query)
                    """
                }
            },
            "Behavioral": {
                "Observer": {
                    "description": "Defines subscription mechanism to notify objects about events",
                    "use_case": "Event systems, MVC architecture, real-time updates",
                    "pros": ["Loose coupling", "Dynamic relationships", "Open/Closed Principle"],
                    "cons": ["Memory leaks if not unsubscribed", "Unexpected updates"],
                    "example": """
class EventManager:
    def __init__(self):
        self.listeners = {}
    
    def subscribe(self, event_type, listener):
        if event_type not in self.listeners:
            self.listeners[event_type] = []
        self.listeners[event_type].append(listener)
    
    def notify(self, event_type, data):
        for listener in self.listeners.get(event_type, []):
            listener.update(data)
                    """
                },
                "Strategy": {
                    "description": "Defines family of algorithms and makes them interchangeable",
                    "use_case": "Payment processing, sorting algorithms, validation rules",
                    "pros": ["Runtime algorithm switching", "Eliminates conditionals", "Open/Closed Principle"],
                    "cons": ["Clients must know strategies", "Increased number of objects"],
                    "example": """
class PaymentProcessor:
    def __init__(self, strategy):
        self.strategy = strategy
    
    def process_payment(self, amount):
        return self.strategy.pay(amount)

class CreditCardStrategy:
    def pay(self, amount):
        return f"Paid ${amount} with credit card"
                    """
                },
                "Command": {
                    "description": "Encapsulates requests as objects for queuing, logging, undo",
                    "use_case": "GUI buttons, macro recording, undo operations",
                    "pros": ["Decouples invoker and receiver", "Undo/redo functionality", "Macro commands"],
                    "cons": ["Code complexity", "Many command classes"],
                    "example": """
class Command:
    def execute(self):
        pass
    
    def undo(self):
        pass

class SaveCommand(Command):
    def __init__(self, document):
        self.document = document
    
    def execute(self):
        self.document.save()
                    """
                }
            }
        }
        
        # Pattern categories with usage statistics
        self.pattern_usage = {
            "Singleton": 85,
            "Factory Method": 78,
            "Observer": 72,
            "Strategy": 68,
            "Decorator": 65,
            "Adapter": 58,
            "Facade": 55,
            "Builder": 52,
            "Command": 45
        }

    def render_content(self):
        """Render the main component content"""
        self._render_pattern_overview()
        self._render_pattern_explorer()
        self._render_implementation_guide()
        self._render_best_practices()

    def _render_pattern_overview(self):
        """Render design patterns overview"""
        st.subheader(" Design Patterns Overview")
        
        col1, col2 = st.columns(2)
        
        with col1:
            create_info_card(
                " What are Design Patterns?",
                "Reusable solutions to commonly occurring problems in software design. They represent best practices evolved over time by experienced developers.",
                card_type="info",
                color_scheme=self.color_scheme
            )
        
        with col2:
            create_info_card(
                " Pattern Categories",
                " **Creational**: Object creation mechanisms\n **Structural**: Object composition\n **Behavioral**: Communication between objects",
                card_type="success",
                color_scheme=self.color_scheme
            )
        
        # Pattern usage chart
        st.subheader(" Pattern Usage in Industry")
        
        usage_df = pd.DataFrame(
            list(self.pattern_usage.items()),
            columns=['Pattern', 'Usage %']
        )
        
        fig = px.bar(
            usage_df,
            x='Pattern',
            y='Usage %',
            title="Design Pattern Popularity in Software Projects",
            color='Usage %',
            color_continuous_scale='viridis'
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)'
        )
        st.plotly_chart(fig, use_container_width=True)

    def _render_pattern_explorer(self):
        """Render interactive pattern explorer"""
        st.subheader(" Pattern Explorer")
        
        # Category selection
        category = st.selectbox(
            "Select Pattern Category:",
            list(self.patterns_data.keys()),
            key="pattern_category_selector"
        )
        
        # Pattern selection within category
        pattern_name = st.selectbox(
            "Select Pattern:",
            list(self.patterns_data[category].keys()),
            key="pattern_name_selector"
        )
        
        pattern = self.patterns_data[category][pattern_name]
        
        # Pattern details
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown(f"### {pattern_name} Pattern")
            st.markdown(f"**Description:** {pattern['description']}")
            st.markdown(f"**Common Use Cases:** {pattern['use_case']}")
            
            # Code example
            st.markdown("####  Implementation Example")
            st.code(pattern['example'], language='python')
        
        with col2:
            # Pros and Cons
            st.markdown("####  Advantages")
            for pro in pattern['pros']:
                st.markdown(f" {pro}")
            
            st.markdown("####  Disadvantages")
            for con in pattern['cons']:
                st.markdown(f" {con}")

    def _render_implementation_guide(self):
        """Render implementation guide"""
        st.subheader(" Implementation Guide")
        
        tabs = st.tabs(["When to Use", "How to Choose", "Common Mistakes"])
        
        with tabs[0]:
            st.markdown("""
            ####  When to Use Design Patterns
            
            ** Good Scenarios:**
            - Recurring design problems
            - Need for code reusability
            - Complex object relationships
            - Framework development
            - Large team projects
            
            ** Avoid When:**
            - Simple, straightforward solutions exist
            - Over-engineering small projects
            - Performance is critical
            - Team unfamiliar with patterns
            """)
        
        with tabs[1]:
            st.markdown("""
            ####  How to Choose the Right Pattern
            
            **Ask These Questions:**
            1. **What problem am I solving?**
               - Object creation  Creational patterns
               - Object composition  Structural patterns
               - Object interaction  Behavioral patterns
            
            2. **What are the constraints?**
               - Performance requirements
               - Memory limitations
               - Team expertise
            
            3. **Future requirements?**
               - Extensibility needs
               - Maintenance considerations
            """)
        
        with tabs[2]:
            st.markdown("""
            ####  Common Implementation Mistakes
            
            **1. Pattern Overuse**
            - Don't force patterns where simple solutions work
            - Avoid "pattern fever" in simple projects
            
            **2. Wrong Pattern Choice**
            - Understand the problem before choosing pattern
            - Consider alternatives and trade-offs
            
            **3. Poor Implementation**
            - Follow pattern structure correctly
            - Don't mix multiple patterns unnecessarily
            
            **4. Ignoring Context**
            - Consider team knowledge
            - Evaluate maintenance burden
            """)

    def _render_best_practices(self):
        """Render best practices and cheat sheet"""
        st.subheader(" Design Patterns Cheat Sheet")
        
        # Quick reference table
        cheat_data = []
        for category, patterns in self.patterns_data.items():
            for pattern_name, pattern_info in patterns.items():
                cheat_data.append({
                    "Category": category,
                    "Pattern": pattern_name,
                    "Problem Solved": pattern_info["description"][:50] + "...",
                    "Use When": pattern_info["use_case"][:40] + "...",
                    "Popularity": f"{self.pattern_usage.get(pattern_name, 0)}%"
                })
        
        df = pd.DataFrame(cheat_data)
        st.dataframe(df, use_container_width=True)
        
        # Resources
        st.subheader(" Learning Resources")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ####  Books
            - **Gang of Four** - Design Patterns: Elements of Reusable Object-Oriented Software
            - **Head First Design Patterns** - Freeman & Robson
            - **Clean Code** - Robert C. Martin
            """)
        
        with col2:
            st.markdown("""
            ####  Online Resources
            - [Refactoring.Guru](https://refactoring.guru/design-patterns) - Interactive examples
            - [SourceMaking](https://sourcemaking.com/design_patterns) - Comprehensive guide
            - [Design Patterns Game](https://designpatternsgame.com/) - Learning through practice
            """)


def explain_design_patterns():
    """Main function to display design patterns component"""
    component = DesignPatternsComponent()
    
    # Summary points for the banner
    summary_points = [
        " Essential software design patterns",
        " Practical implementation examples", 
        " Industry usage statistics",
        " Implementation best practices"
    ]
    
    # Learning resources
    resources = [
        {
            "title": " Gang of Four Design Patterns",
            "url": "https://springframework.guru/gang-of-four-design-patterns/",
            "description": "Classic design patterns reference"
        },
        {
            "title": " Design Patterns Game", 
            "url": "https://designpatternsgame.com/",
            "description": "Interactive learning platform"
        },
        {
            "title": " Refactoring Guru",
            "url": "https://refactoring.guru/design-patterns",
            "description": "Visual design patterns guide"
        }
    ]
    
    component.render_full_component(summary_points, resources)


if __name__ == "__main__":
    explain_design_patterns()
