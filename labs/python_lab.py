"""
Python Programming Lab
Comprehensive Python programming from basics to advanced topics
"""

import streamlit as st
import subprocess
import sys
import io
import os
import json
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import ast
import dis
import traceback
import timeit
import cProfile
import pstats
from datetime import datetime, timedelta
import re
import random
import hashlib
import base64
from typing import Dict, List, Tuple, Optional, Any, Union
import inspect
import importlib
import pkgutil

def create_lab_header(title: str, icon: str, gradient: str = "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"):
    """Create compact lab header"""
    return f"""
    <div style="background: {gradient}; 
                padding: 0.8rem; border-radius: 6px; margin-bottom: 1rem;">
        <h3 style="color: white; margin: 0; font-size: 1.2rem;">{icon} {title}</h3>
    </div>
    """

def run_lab():
    """Python Programming Lab - Master Python Development"""
    
    # Compact Header
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 1rem; border-radius: 8px; margin-bottom: 1rem; text-align: center;">
        <h2 style="color: white; margin: 0; font-size: 1.5rem;">
            🐍 Python Programming Lab
        </h2>
        <p style="color: white; margin: 0; font-size: 0.9rem; opacity: 0.9;">
            From Basics to Advanced Python Development
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced tabs with comprehensive Python topics
    tabs = st.tabs([
        "📚 Basics",
        "🔄 Control Flow",
        "📊 Data Structures",
        "🎯 Functions",
        "🏗️ OOP",
        "📁 File I/O",
        "⚠️ Error Handling",
        "🧩 Modules",
        "🔧 Advanced",
        "🧪 Testing",
        "⚡ Performance",
        "🎨 Best Practices",
        "💻 Code Playground"
    ])
    
    with tabs[0]:
        python_basics_lab()
    
    with tabs[1]:
        control_flow_lab()
    
    with tabs[2]:
        data_structures_lab()
    
    with tabs[3]:
        functions_lab()
    
    with tabs[4]:
        oop_lab()
    
    with tabs[5]:
        file_io_lab()
    
    with tabs[6]:
        error_handling_lab()
    
    with tabs[7]:
        modules_packages_lab()
    
    with tabs[8]:
        advanced_python_lab()
    
    with tabs[9]:
        testing_lab()
    
    with tabs[10]:
        performance_lab()
    
    with tabs[11]:
        best_practices_lab()
    
    with tabs[12]:
        code_playground_lab()

def python_basics_lab():
    """Python Basics - Variables, Data Types, Operators"""
    
    st.markdown(create_lab_header("Python Basics Lab", "📚", "linear-gradient(90deg, #FF6B6B 0%, #4ECDC4 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Python Fundamentals Theory**", expanded=False):
        st.markdown("""
        ### 🐍 **Python Basics**
        
        **Variables & Data Types:**
        - `int` - Integer numbers (42, -17, 0)
        - `float` - Decimal numbers (3.14, -0.5)
        - `str` - Text strings ("Hello", 'Python')
        - `bool` - Boolean values (True, False)
        - `None` - Null value
        
        **Operators:**
        - Arithmetic: `+`, `-`, `*`, `/`, `//`, `%`, `**`
        - Comparison: `==`, `!=`, `>`, `<`, `>=`, `<=`
        - Logical: `and`, `or`, `not`
        - Assignment: `=`, `+=`, `-=`, `*=`, `/=`
        - Identity: `is`, `is not`
        - Membership: `in`, `not in`
        
        **Type Conversion:**
        - `int()`, `float()`, `str()`, `bool()`
        - `list()`, `tuple()`, `dict()`, `set()`
        """)
    
    # Interactive Examples
    st.markdown("### 🎯 **Interactive Examples**")
    
    example_tabs = st.tabs(["Variables", "Data Types", "Operators", "Type Conversion"])
    
    with example_tabs[0]:
        st.markdown("#### **Variables & Assignment**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Try It:")
            var_name = st.text_input("Variable Name", "my_variable")
            var_value = st.text_input("Variable Value", "42")
            var_type = st.selectbox("Type", ["int", "float", "str", "bool"])
            
            if st.button("🚀 **Create Variable**", key="create_var"):
                code = f"{var_name} = {var_type}({repr(var_value)})"
                st.code(code, language="python")
                
                try:
                    exec(code)
                    result = eval(var_name)
                    st.success(f"✅ Created: {var_name} = {result} (type: {type(result).__name__})")
                except Exception as e:
                    st.error(f"❌ Error: {e}")
        
        with col2:
            st.markdown("##### Common Patterns:")
            st.code("""
# Variable assignment
x = 10
name = "Python"
pi = 3.14159
is_active = True

# Multiple assignment
a, b, c = 1, 2, 3
x = y = z = 0

# Variable swapping
a, b = b, a

# Augmented assignment
count += 1
total *= 1.1
            """, language="python")
    
    with example_tabs[1]:
        st.markdown("#### **Data Types Explorer**")
        
        test_value = st.text_input("Enter a value to analyze", "Hello Python")
        
        if st.button("🔍 **Analyze Type**", key="analyze_type"):
            try:
                # Try to evaluate as Python expression
                try:
                    value = eval(test_value)
                except:
                    value = test_value
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Type", type(value).__name__)
                
                with col2:
                    st.metric("Length", len(value) if hasattr(value, '__len__') else "N/A")
                
                with col3:
                    st.metric("Boolean", bool(value))
                
                # Type details
                st.markdown("##### Type Information:")
                type_info = {
                    "Type": type(value).__name__,
                    "Value": str(value)[:100],
                    "Repr": repr(value)[:100],
                    "ID": id(value),
                    "Size (bytes)": sys.getsizeof(value),
                    "Is Iterable": hasattr(value, '__iter__'),
                    "Is Callable": callable(value)
                }
                
                df = pd.DataFrame(list(type_info.items()), columns=["Property", "Value"])
                st.dataframe(df, use_container_width=True)
                
            except Exception as e:
                st.error(f"Error: {e}")
    
    with example_tabs[2]:
        st.markdown("#### **Operators Playground**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Arithmetic Operations")
            num1 = st.number_input("Number 1", value=10.0)
            num2 = st.number_input("Number 2", value=3.0)
            
            operations = {
                "Addition": num1 + num2,
                "Subtraction": num1 - num2,
                "Multiplication": num1 * num2,
                "Division": num1 / num2 if num2 != 0 else "Cannot divide by zero",
                "Floor Division": num1 // num2 if num2 != 0 else "Cannot divide by zero",
                "Modulo": num1 % num2 if num2 != 0 else "Cannot divide by zero",
                "Power": num1 ** num2
            }
            
            for op, result in operations.items():
                st.write(f"**{op}:** {result}")
        
        with col2:
            st.markdown("##### Comparison & Logic")
            
            bool1 = st.checkbox("Value A", value=True)
            bool2 = st.checkbox("Value B", value=False)
            
            logic_ops = {
                "A and B": bool1 and bool2,
                "A or B": bool1 or bool2,
                "not A": not bool1,
                "not B": not bool2,
                "A == B": bool1 == bool2,
                "A != B": bool1 != bool2
            }
            
            for op, result in logic_ops.items():
                st.write(f"**{op}:** {result}")
    
    with example_tabs[3]:
        st.markdown("#### **Type Conversion**")
        
        convert_value = st.text_input("Value to convert", "123")
        target_type = st.selectbox("Convert to", ["int", "float", "str", "bool", "list", "tuple", "set"])
        
        if st.button("🔄 **Convert**", key="convert_type"):
            try:
                original = eval(convert_value) if convert_value not in ["True", "False"] else eval(convert_value)
                converted = eval(f"{target_type}({repr(original)})")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Original:**")
                    st.code(f"Type: {type(original).__name__}\nValue: {original}")
                
                with col2:
                    st.markdown("**Converted:**")
                    st.code(f"Type: {type(converted).__name__}\nValue: {converted}")
                    
            except Exception as e:
                st.error(f"Conversion Error: {e}")

def control_flow_lab():
    """Control Flow - Conditionals and Loops"""
    
    st.markdown(create_lab_header("Control Flow Lab", "🔄", "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Control Flow Theory**", expanded=False):
        st.markdown("""
        ### 🔄 **Control Flow in Python**
        
        **Conditional Statements:**
        ```python
        if condition:
            # code block
        elif another_condition:
            # code block
        else:
            # code block
        ```
        
        **Loops:**
        ```python
        # For loop
        for item in iterable:
            # code block
        
        # While loop
        while condition:
            # code block
        ```
        
        **Control Keywords:**
        - `break` - Exit loop
        - `continue` - Skip to next iteration
        - `pass` - Do nothing (placeholder)
        - `else` - Execute if loop completes normally
        """)
    
    tabs = st.tabs(["If-Else", "For Loops", "While Loops", "Comprehensions"])
    
    with tabs[0]:
        st.markdown("#### **Conditional Logic Builder**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Build Condition")
            
            age = st.slider("Age", 0, 100, 25)
            
            code = f"""
age = {age}

if age < 13:
    category = "Child"
elif age < 20:
    category = "Teenager"
elif age < 60:
    category = "Adult"
else:
    category = "Senior"

print(f"Age {age}: {{category}}")
"""
            
            st.code(code, language="python")
            
            if st.button("▶️ **Run**", key="run_if"):
                exec_globals = {'age': age}
                exec(code.replace('print(f"Age {age}: {category}")', 'result = f"Age {age}: {category}"'), exec_globals)
                st.success(exec_globals.get('result', 'No result'))
        
        with col2:
            st.markdown("##### Advanced Patterns")
            st.code("""
# Ternary operator
result = "Even" if x % 2 == 0 else "Odd"

# Multiple conditions
if x > 0 and y > 0:
    quadrant = "I"
elif x < 0 and y > 0:
    quadrant = "II"

# Nested conditions
if user.is_authenticated:
    if user.has_permission('admin'):
        grant_access()
        
# Match statement (Python 3.10+)
match command:
    case "start":
        start_process()
    case "stop":
        stop_process()
    case _:
        print("Unknown command")
            """, language="python")
    
    with tabs[1]:
        st.markdown("#### **For Loop Explorer**")
        
        loop_type = st.selectbox("Loop Type", ["Range", "List", "String", "Dictionary", "Enumerate", "Zip"])
        
        if loop_type == "Range":
            start = st.number_input("Start", value=0)
            stop = st.number_input("Stop", value=10)
            step = st.number_input("Step", value=1)
            
            code = f"""
for i in range({start}, {stop}, {step}):
    print(f"Iteration {{i}}: {{i**2}}")
"""
        elif loop_type == "List":
            items = st.text_input("List items (comma-separated)", "apple, banana, orange")
            code = f"""
fruits = {items.split(', ')}
for fruit in fruits:
    print(f"Fruit: {{fruit}} ({{len(fruit)}} chars)")
"""
        elif loop_type == "Dictionary":
            code = """
data = {'name': 'Alice', 'age': 30, 'city': 'NYC'}
for key, value in data.items():
    print(f"{key}: {value}")
"""
        else:
            code = "# Select a loop type above"
        
        st.code(code, language="python")
        
        if st.button("▶️ **Run Loop**", key="run_for"):
            output = io.StringIO()
            sys.stdout = output
            try:
                exec(code)
                result = output.getvalue()
                st.text(result)
            except Exception as e:
                st.error(f"Error: {e}")
            finally:
                sys.stdout = sys.__stdout__
    
    with tabs[2]:
        st.markdown("#### **While Loop Simulator**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Countdown Timer")
            count_from = st.number_input("Start from", value=10, min_value=1)
            
            if st.button("🚀 **Start Countdown**", key="countdown"):
                placeholder = st.empty()
                count = count_from
                while count > 0:
                    placeholder.metric("Countdown", count)
                    count -= 1
                    import time
                    time.sleep(0.5)
                placeholder.success("🎉 Blast off!")
        
        with col2:
            st.markdown("##### While Loop Patterns")
            st.code("""
# Basic while loop
count = 0
while count < 5:
    print(count)
    count += 1

# With break
while True:
    user_input = input("Enter 'quit' to exit: ")
    if user_input == 'quit':
        break

# With continue
i = 0
while i < 10:
    i += 1
    if i % 2 == 0:
        continue
    print(i)  # Only odd numbers

# While-else
n = 5
while n > 0:
    n -= 1
else:
    print("Loop completed normally")
            """, language="python")
    
    with tabs[3]:
        st.markdown("#### **Comprehensions Generator**")
        
        comp_type = st.selectbox("Comprehension Type", ["List", "Dictionary", "Set", "Generator"])
        
        if comp_type == "List":
            st.code("""
# List comprehensions
squares = [x**2 for x in range(10)]
evens = [x for x in range(20) if x % 2 == 0]
matrix = [[i*j for j in range(3)] for i in range(3)]

# With conditions
filtered = [x for x in data if x > 0]
transformed = [x.upper() for x in words if len(x) > 3]
            """, language="python")
            
        elif comp_type == "Dictionary":
            st.code("""
# Dictionary comprehensions
squares = {x: x**2 for x in range(5)}
inverted = {v: k for k, v in original.items()}
filtered = {k: v for k, v in data.items() if v > 0}

# From two lists
keys = ['a', 'b', 'c']
values = [1, 2, 3]
combined = {k: v for k, v in zip(keys, values)}
            """, language="python")
            
        elif comp_type == "Set":
            st.code("""
# Set comprehensions
unique_lengths = {len(word) for word in words}
vowels = {char for char in text if char in 'aeiou'}
            """, language="python")
            
        else:  # Generator
            st.code("""
# Generator expressions
gen = (x**2 for x in range(10))
sum_squares = sum(x**2 for x in range(10))
filtered = (line for line in file if 'error' in line)

# Memory efficient for large datasets
large_gen = (process(x) for x in huge_list)
            """, language="python")

def data_structures_lab():
    """Data Structures - Lists, Tuples, Dictionaries, Sets"""
    
    st.markdown(create_lab_header("Data Structures Lab", "📊", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Data Structures Theory**", expanded=True):
        st.markdown("""
        ### 📊 **Understanding Python Data Structures**
        
        Data structures are fundamental building blocks for organizing and storing data efficiently.
        Python provides built-in data structures optimized for different use cases.
        
        **Core Data Structures Comparison:**
        
        | Structure | Mutable | Ordered | Indexed | Duplicates | Use Case |
        |-----------|---------|---------|---------|------------|----------|
        | List | ✅ | ✅ | ✅ | ✅ | General purpose, sequences |
        | Tuple | ❌ | ✅ | ✅ | ✅ | Immutable data, keys |
        | Dict | ✅ | ✅* | ❌ | Keys: ❌ | Key-value mapping |
        | Set | ✅ | ❌ | ❌ | ❌ | Unique items, operations |
        (* Ordered in Python 3.7+)
        
        **Time Complexity (Big O):**
        
        | Operation | List | Dict | Set |
        |-----------|------|------|-----|
        | Access | O(1) | O(1) | N/A |
        | Search | O(n) | O(1) | O(1) |
        | Insert | O(n) | O(1) | O(1) |
        | Delete | O(n) | O(1) | O(1) |
        
        **Lists:**
        - Dynamic arrays
        - Contiguous memory
        - Good for: Sequential access, stacks, queues
        - Bad for: Frequent insertions/deletions in middle
        
        **Tuples:**
        - Immutable sequences
        - Memory efficient
        - Hashable (can be dict keys)
        - Good for: Fixed data, function returns
        
        **Dictionaries:**
        - Hash tables implementation
        - Key-value pairs
        - Average O(1) lookup
        - Good for: Caching, mapping, JSON
        
        **Sets:**
        - Hash tables without values
        - Mathematical set operations
        - No duplicates
        - Good for: Membership testing, deduplication
        
        **Memory Considerations:**
        - Lists: Overallocate for growth
        - Tuples: Exact size allocation
        - Dicts: ~3x memory of data
        - Sets: Similar to dicts
        
        **Best Practices:**
        - Use tuples for immutable data
        - Prefer sets for membership tests
        - Use dicts for lookups
        - List comprehensions for transformations
        - Consider collections module for specialized needs
        """)
    
    tabs = st.tabs(["Lists", "Tuples", "Dictionaries", "Sets", "Collections"])
    
    with tabs[0]:
        st.markdown("#### **List Operations**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### List Methods")
            
            list_input = st.text_input("Initial list", "[1, 2, 3, 4, 5]")
            operation = st.selectbox("Operation", ["append", "extend", "insert", "remove", "pop", "sort", "reverse"])
            
            if operation in ["append", "remove"]:
                value = st.text_input("Value", "6")
            elif operation == "extend":
                value = st.text_input("Values", "[6, 7, 8]")
            elif operation == "insert":
                index = st.number_input("Index", 0)
                value = st.text_input("Value", "0")
            else:
                value = None
            
            if st.button("🔄 **Apply Operation**", key="list_op"):
                try:
                    my_list = eval(list_input)
                    st.write(f"Before: {my_list}")
                    
                    if operation == "append":
                        my_list.append(eval(value))
                    elif operation == "extend":
                        my_list.extend(eval(value))
                    elif operation == "insert":
                        my_list.insert(index, eval(value))
                    elif operation == "remove":
                        my_list.remove(eval(value))
                    elif operation == "pop":
                        my_list.pop()
                    elif operation == "sort":
                        my_list.sort()
                    elif operation == "reverse":
                        my_list.reverse()
                    
                    st.write(f"After: {my_list}")
                except Exception as e:
                    st.error(f"Error: {e}")
        
        with col2:
            st.markdown("##### List Slicing")
            st.code("""
# List slicing
lst = [0, 1, 2, 3, 4, 5]
lst[2:5]     # [2, 3, 4]
lst[:3]      # [0, 1, 2]
lst[3:]      # [3, 4, 5]
lst[-2:]     # [4, 5]
lst[::2]     # [0, 2, 4]
lst[::-1]    # [5, 4, 3, 2, 1, 0]

# List operations
lst + [6, 7]  # Concatenation
lst * 2       # Repetition
3 in lst      # Membership
len(lst)      # Length
min(lst)      # Minimum
max(lst)      # Maximum
sum(lst)      # Sum
            """, language="python")
    
    with tabs[1]:
        st.markdown("#### **Tuple Operations**")
        
        st.code("""
# Tuple creation
tup = (1, 2, 3)
single = (1,)  # Note the comma
empty = ()

# Tuple unpacking
x, y, z = (1, 2, 3)
a, *rest = (1, 2, 3, 4, 5)  # a=1, rest=[2,3,4,5]
first, *middle, last = (1, 2, 3, 4, 5)

# Named tuples
from collections import namedtuple
Point = namedtuple('Point', ['x', 'y'])
p = Point(11, y=22)
print(p.x, p.y)  # 11 22

# Tuple methods
tup.count(2)  # Count occurrences
tup.index(3)  # Find index
        """, language="python")
    
    with tabs[2]:
        st.markdown("#### **Dictionary Operations**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Dictionary Builder")
            
            key = st.text_input("Key", "name")
            value = st.text_input("Value", "Alice")
            
            if 'my_dict' not in st.session_state:
                st.session_state.my_dict = {}
            
            col1_1, col1_2, col1_3 = st.columns(3)
            
            with col1_1:
                if st.button("➕ Add", key="dict_add"):
                    st.session_state.my_dict[key] = value
            
            with col1_2:
                if st.button("🗑️ Remove", key="dict_remove"):
                    st.session_state.my_dict.pop(key, None)
            
            with col1_3:
                if st.button("🔄 Clear", key="dict_clear"):
                    st.session_state.my_dict = {}
            
            st.json(st.session_state.my_dict)
        
        with col2:
            st.markdown("##### Dictionary Methods")
            st.code("""
# Dictionary methods
d = {'a': 1, 'b': 2}

d.get('c', 0)        # Get with default
d.setdefault('c', 3) # Set if not exists
d.update({'d': 4})   # Update/merge
d.pop('a')           # Remove and return
d.popitem()          # Remove last item

# Dictionary views
d.keys()    # Dict keys
d.values()  # Dict values
d.items()   # Key-value pairs

# Dictionary comprehension
squares = {x: x**2 for x in range(5)}
            """, language="python")
    
    with tabs[3]:
        st.markdown("#### **Set Operations**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            set1_input = st.text_input("Set 1", "{1, 2, 3, 4}")
            set2_input = st.text_input("Set 2", "{3, 4, 5, 6}")
            
            if st.button("🔍 **Calculate Operations**", key="set_ops"):
                try:
                    set1 = eval(set1_input)
                    set2 = eval(set2_input)
                    
                    operations = {
                        "Union (|)": set1 | set2,
                        "Intersection (&)": set1 & set2,
                        "Difference (-)": set1 - set2,
                        "Symmetric Diff (^)": set1 ^ set2,
                        "Is Subset": set1 <= set2,
                        "Is Superset": set1 >= set2,
                        "Is Disjoint": set1.isdisjoint(set2)
                    }
                    
                    for op, result in operations.items():
                        st.write(f"**{op}:** {result}")
                        
                except Exception as e:
                    st.error(f"Error: {e}")
        
        with col2:
            st.markdown("##### Set Methods")
            st.code("""
# Set operations
s = {1, 2, 3}
s.add(4)           # Add element
s.remove(2)        # Remove (error if not exists)
s.discard(5)       # Remove (no error)
s.pop()            # Remove arbitrary
s.clear()          # Remove all

# Set comparisons
s1 = {1, 2}
s2 = {1, 2, 3}
s1.issubset(s2)    # True
s2.issuperset(s1)  # True
s1.isdisjoint(s2)  # False

# Frozen sets (immutable)
fs = frozenset([1, 2, 3])
            """, language="python")
    
    with tabs[4]:
        st.markdown("#### **Collections Module**")
        
        st.code("""
from collections import Counter, defaultdict, deque, OrderedDict

# Counter
c = Counter(['a', 'b', 'c', 'a', 'b', 'b'])
c.most_common(2)  # [('b', 3), ('a', 2)]

# defaultdict
dd = defaultdict(list)
dd['key'].append('value')  # No KeyError

# deque (double-ended queue)
d = deque([1, 2, 3])
d.appendleft(0)    # Add to left
d.popleft()        # Remove from left
d.rotate(1)        # Rotate right

# OrderedDict (maintains insertion order)
od = OrderedDict()
od['first'] = 1
od['second'] = 2
        """, language="python")

def functions_lab():
    """Functions - Definition, Parameters, Lambda, Decorators"""
    
    st.markdown(create_lab_header("Functions Lab", "🎯", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Functions Theory**", expanded=True):
        st.markdown("""
        ### 🎯 **Understanding Python Functions**
        
        Functions are reusable blocks of code that perform specific tasks. They promote code 
        modularity, reusability, and maintainability through abstraction.
        
        **Function Types:**
        
        | Type | Description | Example | Use Case |
        |------|-------------|---------|----------|
        | Built-in | Python provided | `len()`, `print()` | Common operations |
        | User-defined | Custom functions | `def my_func()` | Specific logic |
        | Lambda | Anonymous functions | `lambda x: x*2` | Short operations |
        | Generator | Yield values | `yield` keyword | Memory efficient |
        | Async | Asynchronous | `async def` | Concurrent ops |
        
        **Parameter Types:**
        
        1. **Positional Arguments**
           - Order matters
           - Required by default
           - `func(a, b, c)`
        
        2. **Keyword Arguments**
           - Name-value pairs
           - Order independent
           - `func(a=1, b=2)`
        
        3. **Default Parameters**
           - Optional with defaults
           - `def func(a, b=10)`
        
        4. **Variable Arguments**
           - `*args` - Variable positional
           - `**kwargs` - Variable keyword
           - Flexible interfaces
        
        **Function Concepts:**
        
        **Scope (LEGB Rule):**
        - **L**ocal - Inside function
        - **E**nclosing - Nested functions
        - **G**lobal - Module level
        - **B**uilt-in - Predefined
        
        **First-Class Functions:**
        - Assign to variables
        - Pass as arguments
        - Return from functions
        - Store in data structures
        
        **Decorators:**
        - Modify function behavior
        - `@decorator` syntax
        - Common: `@property`, `@staticmethod`
        - Logging, timing, caching
        
        **Lambda Functions:**
        - Single expression
        - No statements
        - Implicit return
        - Good for: map(), filter(), sort()
        
        **Generators:**
        - Lazy evaluation
        - Memory efficient
        - `yield` keyword
        - Iterator protocol
        
        **Performance Tips:**
        - Avoid global variables
        - Use local variables (faster)
        - Minimize function calls in loops
        - Consider `functools.lru_cache`
        
        **Best Practices:**
        - Single responsibility principle
        - Clear, descriptive names
        - Document with docstrings
        - Type hints for clarity
        - Keep functions small (<20 lines)
        - Pure functions when possible
        """)
    
    tabs = st.tabs(["Basic Functions", "Parameters", "Lambda", "Decorators", "Generators"])
    
    with tabs[0]:
        st.markdown("#### **Function Builder**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            func_name = st.text_input("Function name", "calculate")
            params = st.text_input("Parameters", "x, y")
            operation = st.selectbox("Operation", ["add", "multiply", "power", "custom"])
            
            if operation == "custom":
                body = st.text_area("Function body", "return x + y")
            else:
                body_map = {
                    "add": "return x + y",
                    "multiply": "return x * y",
                    "power": "return x ** y"
                }
                body = body_map[operation]
            
            func_code = f"""
def {func_name}({params}):
    {body}

# Test the function
result = {func_name}(5, 3)
print(f"Result: {{result}}")
"""
            st.code(func_code, language="python")
            
            if st.button("▶️ **Run Function**", key="run_func"):
                try:
                    exec_globals = {}
                    exec(func_code, exec_globals)
                    st.success(f"Result: {exec_globals.get('result', 'No result')}")
                except Exception as e:
                    st.error(f"Error: {e}")
        
        with col2:
            st.markdown("##### Function Patterns")
            st.code("""
# Function with docstring
def greet(name: str) -> str:
    \"\"\"
    Greet a person by name.
    
    Args:
        name: Person's name
    
    Returns:
        Greeting message
    \"\"\"
    return f"Hello, {name}!"

# Function with type hints
def add(x: int, y: int) -> int:
    return x + y

# Function with multiple returns
def get_stats(numbers: list) -> tuple:
    return min(numbers), max(numbers), sum(numbers)
            """, language="python")
    
    with tabs[1]:
        st.markdown("#### **Parameter Types**")
        
        st.code("""
# Positional parameters
def func(a, b, c):
    pass

# Default parameters
def greet(name="World"):
    return f"Hello, {name}"

# *args (variable positional)
def sum_all(*args):
    return sum(args)

# **kwargs (variable keyword)
def print_info(**kwargs):
    for key, value in kwargs.items():
        print(f"{key}: {value}")

# Combined parameters
def complex_func(pos, *args, default=10, **kwargs):
    pass

# Keyword-only parameters
def func(*, keyword_only):
    pass

# Positional-only parameters (Python 3.8+)
def func(positional_only, /):
    pass
        """, language="python")
    
    with tabs[2]:
        st.markdown("#### **Lambda Functions**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Lambda Builder")
            
            lambda_expr = st.text_input("Lambda expression", "lambda x: x ** 2")
            test_value = st.number_input("Test value", value=5)
            
            if st.button("🔄 **Execute Lambda**", key="exec_lambda"):
                try:
                    func = eval(lambda_expr)
                    result = func(test_value)
                    st.success(f"Result: {result}")
                except Exception as e:
                    st.error(f"Error: {e}")
        
        with col2:
            st.markdown("##### Lambda Examples")
            st.code("""
# Simple lambda
square = lambda x: x ** 2

# Multiple parameters
add = lambda x, y: x + y

# With map()
numbers = [1, 2, 3, 4, 5]
squared = list(map(lambda x: x**2, numbers))

# With filter()
evens = list(filter(lambda x: x % 2 == 0, numbers))

# With sorted()
students = [('Alice', 85), ('Bob', 75), ('Charlie', 95)]
sorted_students = sorted(students, key=lambda x: x[1])

# In list comprehension alternative
result = [(lambda x: x**2)(x) for x in range(5)]
            """, language="python")
    
    with tabs[3]:
        st.markdown("#### **Decorators**")
        
        st.code("""
# Simple decorator
def timer(func):
    def wrapper(*args, **kwargs):
        import time
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print(f"{func.__name__} took {end-start:.4f} seconds")
        return result
    return wrapper

@timer
def slow_function():
    import time
    time.sleep(1)
    return "Done"

# Decorator with parameters
def repeat(times):
    def decorator(func):
        def wrapper(*args, **kwargs):
            for _ in range(times):
                result = func(*args, **kwargs)
            return result
        return wrapper
    return decorator

@repeat(3)
def greet(name):
    print(f"Hello, {name}")

# Class decorator
def singleton(cls):
    instances = {}
    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    return get_instance

# Property decorator
class Circle:
    def __init__(self, radius):
        self._radius = radius
    
    @property
    def area(self):
        return 3.14159 * self._radius ** 2
        """, language="python")
    
    with tabs[4]:
        st.markdown("#### **Generators**")
        
        st.code("""
# Generator function
def fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        yield a
        a, b = b, a + b

# Using generator
for num in fibonacci(10):
    print(num)

# Generator expression
squares = (x**2 for x in range(10))

# Infinite generator
def infinite_counter():
    count = 0
    while True:
        yield count
        count += 1

# Generator with send()
def accumulator():
    total = 0
    while True:
        value = yield total
        if value is not None:
            total += value

# Using itertools
import itertools
itertools.count(10)  # 10, 11, 12, ...
itertools.cycle([1, 2, 3])  # 1, 2, 3, 1, 2, 3, ...
itertools.repeat(10, 3)  # 10, 10, 10
        """, language="python")

def oop_lab():
    """Object-Oriented Programming Lab"""
    
    st.markdown(create_lab_header("OOP Lab", "🏗️", "linear-gradient(90deg, #ff6a00 0%, #ee0979 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **OOP Theory**", expanded=True):
        st.markdown("""
        ### 🏗️ **Understanding Object-Oriented Programming**
        
        OOP is a programming paradigm based on objects (data + methods) that promotes code 
        organization, reusability, and modeling of real-world entities.
        
        **Core OOP Principles:**
        
        | Principle | Description | Python Implementation | Benefits |
        |-----------|-------------|----------------------|----------|
        | Encapsulation | Data hiding | `_private`, `__private` | Security, modularity |
        | Inheritance | Code reuse | `class Child(Parent)` | DRY principle |
        | Polymorphism | Many forms | Method overriding | Flexibility |
        | Abstraction | Hide complexity | ABC module | Simplification |
        
        **Class Components:**
        
        1. **Attributes**
           - Instance variables (per object)
           - Class variables (shared)
           - Properties (`@property`)
        
        2. **Methods**
           - Instance methods (self)
           - Class methods (`@classmethod`)
           - Static methods (`@staticmethod`)
        
        3. **Constructor**
           - `__init__()` method
           - Initialize object state
           - Called automatically
        
        **Inheritance Types:**
        - **Single**: One parent class
        - **Multiple**: Multiple parents
        - **Multilevel**: Chain of inheritance
        - **Hierarchical**: Multiple children
        - **Hybrid**: Combination
        
        **Method Resolution Order (MRO):**
        - C3 linearization algorithm
        - Left-to-right, depth-first
        - `Class.__mro__` to check
        - Diamond problem solution
        
        **Magic Methods (Dunder):**
        
        | Method | Purpose | Example |
        |--------|---------|---------|
        | `__init__` | Constructor | Object creation |
        | `__str__` | String representation | `print(obj)` |
        | `__repr__` | Developer representation | `repr(obj)` |
        | `__len__` | Length | `len(obj)` |
        | `__getitem__` | Indexing | `obj[key]` |
        | `__eq__` | Equality | `obj1 == obj2` |
        | `__lt__` | Less than | `obj1 < obj2` |
        | `__call__` | Callable object | `obj()` |
        
        **Design Patterns:**
        - **Singleton**: One instance
        - **Factory**: Object creation
        - **Observer**: Event handling
        - **Decorator**: Add functionality
        - **Strategy**: Algorithm selection
        
        **Python-Specific Features:**
        - No true private members
        - Name mangling (`__attr`)
        - Duck typing
        - Multiple inheritance
        - Metaclasses
        
        **Best Practices:**
        - Favor composition over inheritance
        - Keep inheritance shallow
        - Follow SOLID principles
        - Use ABC for interfaces
        - Document with docstrings
        - Type hints for clarity
        """)
    
    tabs = st.tabs(["Classes", "Inheritance", "Polymorphism", "Encapsulation", "Magic Methods"])
    
    with tabs[0]:
        st.markdown("#### **Class Builder**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            class_name = st.text_input("Class name", "Person")
            attributes = st.text_area("Attributes (one per line)", "name\nage")
            
            attr_list = attributes.split('\n')
            init_params = ', '.join(attr_list)
            init_body = '\n        '.join([f"self.{attr} = {attr}" for attr in attr_list])
            
            class_code = f"""
class {class_name}:
    def __init__(self, {init_params}):
        {init_body}
    
    def __str__(self):
        return f"{class_name}({', '.join([f'{attr}={{self.{attr}}}' for attr in attr_list])})"

# Create instance
obj = {class_name}({', '.join([f'"{attr}_value"' if i == 0 else str(i+20) for i, attr in enumerate(attr_list)])})
print(obj)
"""
            st.code(class_code, language="python")
        
        with col2:
            st.markdown("##### Class Patterns")
            st.code("""
# Class with class variables
class Employee:
    company = "TechCorp"  # Class variable
    
    def __init__(self, name, salary):
        self.name = name  # Instance variable
        self.salary = salary
    
    @classmethod
    def from_string(cls, emp_str):
        name, salary = emp_str.split('-')
        return cls(name, int(salary))
    
    @staticmethod
    def is_workday(day):
        return day.weekday() < 5
            """, language="python")
    
    with tabs[1]:
        st.markdown("#### **Inheritance**")
        
        st.code("""
# Single inheritance
class Animal:
    def __init__(self, name):
        self.name = name
    
    def speak(self):
        pass

class Dog(Animal):
    def speak(self):
        return f"{self.name} says Woof!"

class Cat(Animal):
    def speak(self):
        return f"{self.name} says Meow!"

# Multiple inheritance
class Flyable:
    def fly(self):
        return "Flying high!"

class Swimmable:
    def swim(self):
        return "Swimming fast!"

class Duck(Animal, Flyable, Swimmable):
    def speak(self):
        return "Quack!"

# Using super()
class Rectangle:
    def __init__(self, width, height):
        self.width = width
        self.height = height
    
    def area(self):
        return self.width * self.height

class Square(Rectangle):
    def __init__(self, side):
        super().__init__(side, side)
        """, language="python")
    
    with tabs[2]:
        st.markdown("#### **Polymorphism**")
        
        st.code("""
# Method overriding
class Shape:
    def area(self):
        raise NotImplementedError

class Circle(Shape):
    def __init__(self, radius):
        self.radius = radius
    
    def area(self):
        return 3.14159 * self.radius ** 2

class Rectangle(Shape):
    def __init__(self, width, height):
        self.width = width
        self.height = height
    
    def area(self):
        return self.width * self.height

# Duck typing
def calculate_area(shape):
    return shape.area()

# Abstract base classes
from abc import ABC, abstractmethod

class Vehicle(ABC):
    @abstractmethod
    def start(self):
        pass
    
    @abstractmethod
    def stop(self):
        pass

class Car(Vehicle):
    def start(self):
        return "Car started"
    
    def stop(self):
        return "Car stopped"
        """, language="python")
    
    with tabs[3]:
        st.markdown("#### **Encapsulation**")
        
        st.code("""
# Private attributes and methods
class BankAccount:
    def __init__(self, balance):
        self.__balance = balance  # Private attribute
    
    def deposit(self, amount):
        if amount > 0:
            self.__balance += amount
    
    def withdraw(self, amount):
        if 0 < amount <= self.__balance:
            self.__balance -= amount
            return amount
        return 0
    
    def get_balance(self):
        return self.__balance
    
    def __validate_transaction(self):  # Private method
        pass

# Property decorators
class Temperature:
    def __init__(self):
        self._celsius = 0
    
    @property
    def celsius(self):
        return self._celsius
    
    @celsius.setter
    def celsius(self, value):
        if value < -273.15:
            raise ValueError("Temperature below absolute zero!")
        self._celsius = value
    
    @property
    def fahrenheit(self):
        return self._celsius * 9/5 + 32
        """, language="python")
    
    with tabs[4]:
        st.markdown("#### **Magic Methods**")
        
        st.code("""
class Vector:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    
    # String representation
    def __str__(self):
        return f"Vector({self.x}, {self.y})"
    
    def __repr__(self):
        return f"Vector(x={self.x}, y={self.y})"
    
    # Arithmetic operators
    def __add__(self, other):
        return Vector(self.x + other.x, self.y + other.y)
    
    def __sub__(self, other):
        return Vector(self.x - other.x, self.y - other.y)
    
    def __mul__(self, scalar):
        return Vector(self.x * scalar, self.y * scalar)
    
    # Comparison operators
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y
    
    def __lt__(self, other):
        return self.magnitude() < other.magnitude()
    
    # Container methods
    def __len__(self):
        return 2
    
    def __getitem__(self, index):
        if index == 0:
            return self.x
        elif index == 1:
            return self.y
        raise IndexError
    
    # Context manager
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
        """, language="python")

# Add remaining lab functions
def file_io_lab():
    """File Input/Output Operations"""
    
    st.markdown(create_lab_header("File I/O Lab", "📁", "linear-gradient(90deg, #4facfe 0%, #00f2fe 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **File I/O Theory**", expanded=True):
        st.markdown("""
        ### 📁 **Understanding File I/O in Python**
        
        File I/O operations allow programs to persist data, read configurations, and interact 
        with the file system for data processing and storage.
        
        **File Modes:**
        
        | Mode | Description | Creates | Truncates | Position |
        |------|-------------|---------|-----------|----------|
        | 'r' | Read only | No | No | Beginning |
        | 'w' | Write only | Yes | Yes | Beginning |
        | 'a' | Append only | Yes | No | End |
        | 'r+' | Read & Write | No | No | Beginning |
        | 'w+' | Write & Read | Yes | Yes | Beginning |
        | 'x' | Exclusive create | Yes | No | Beginning |
        | 'b' | Binary mode | - | - | - |
        
        **File Operations Best Practices:**
        
        1. **Context Managers**
           - Always use `with` statement
           - Automatic file closing
           - Exception safety
           - Resource cleanup
        
        2. **Text vs Binary**
           - Text: Human-readable, encoding
           - Binary: Raw bytes, no encoding
           - Choose based on data type
        
        3. **Buffering**
           - Line buffering for text
           - Full buffering for binary
           - `flush()` for immediate write
        
        **Common File Formats:**
        
        | Format | Module | Use Case | Human Readable |
        |--------|--------|----------|----------------|
        | TXT | built-in | Simple text | ✅ |
        | CSV | csv | Tabular data | ✅ |
        | JSON | json | Structured data | ✅ |
        | XML | xml | Hierarchical | ✅ |
        | Pickle | pickle | Python objects | ❌ |
        | SQLite | sqlite3 | Database | ❌ |
        
        **Path Operations (pathlib):**
        - Object-oriented paths
        - Cross-platform compatibility
        - Method chaining
        - Better than os.path
        
        **Error Handling:**
        - `FileNotFoundError` - File doesn't exist
        - `PermissionError` - Access denied
        - `IOError` - I/O operation failed
        - `UnicodeDecodeError` - Encoding issue
        
        **Performance Tips:**
        - Read in chunks for large files
        - Use generators for line processing
        - Binary for non-text data
        - Consider memory mapping
        
        **Best Practices:**
        - Always close files (use `with`)
        - Handle exceptions gracefully
        - Use appropriate encoding (UTF-8)
        - Validate file paths
        - Check file existence before operations
        - Use pathlib for path manipulation
        """)
    
    tabs = st.tabs(["Text Files", "Binary Files", "CSV/JSON", "Path Operations"])
    
    with tabs[0]:
        st.markdown("#### **Text File Operations**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### File Writer")
            
            filename = st.text_input("Filename", "test.txt")
            content = st.text_area("Content", "Hello, Python!\nFile I/O is easy.")
            mode = st.selectbox("Mode", ["w", "a", "x"])
            
            if st.button("💾 **Write File**", key="write_file"):
                try:
                    # Simulated write
                    st.code(f"""
with open('{filename}', '{mode}') as f:
    f.write('''{content}''')
                    """, language="python")
                    st.success(f"File '{filename}' written successfully!")
                except Exception as e:
                    st.error(f"Error: {e}")
        
        with col2:
            st.markdown("##### File Patterns")
            st.code("""
# Reading files
with open('file.txt', 'r') as f:
    content = f.read()  # Read entire file
    # or
    lines = f.readlines()  # Read all lines
    # or
    for line in f:  # Iterate line by line
        process(line)

# Writing files
with open('file.txt', 'w') as f:
    f.write('Hello World')
    f.writelines(['Line 1\n', 'Line 2\n'])

# Context manager ensures file closes
with open('file.txt') as f:
    data = f.read()
# File automatically closed here
            """, language="python")
    
    with tabs[1]:
        st.markdown("#### **Binary Files**")
        
        st.code("""
# Reading binary files
with open('image.jpg', 'rb') as f:
    binary_data = f.read()

# Writing binary files
with open('output.bin', 'wb') as f:
    f.write(b'Binary data')

# Pickle for Python objects
import pickle

# Save object
data = {'key': 'value', 'list': [1, 2, 3]}
with open('data.pkl', 'wb') as f:
    pickle.dump(data, f)

# Load object
with open('data.pkl', 'rb') as f:
    loaded_data = pickle.load(f)

# Working with bytes
data = b'Hello'
encoded = data.decode('utf-8')
decoded = encoded.encode('utf-8')
        """, language="python")
    
    with tabs[2]:
        st.markdown("#### **CSV and JSON**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### CSV Operations")
            st.code("""
import csv

# Writing CSV
data = [
    ['Name', 'Age', 'City'],
    ['Alice', 30, 'NYC'],
    ['Bob', 25, 'LA']
]

with open('data.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerows(data)

# Reading CSV
with open('data.csv', 'r') as f:
    reader = csv.reader(f)
    for row in reader:
        print(row)

# Using DictReader/DictWriter
with open('data.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        print(row['Name'], row['Age'])
            """, language="python")
        
        with col2:
            st.markdown("##### JSON Operations")
            st.code("""
import json

# Writing JSON
data = {
    'name': 'Alice',
    'age': 30,
    'hobbies': ['reading', 'coding']
}

with open('data.json', 'w') as f:
    json.dump(data, f, indent=4)

# Reading JSON
with open('data.json', 'r') as f:
    loaded = json.load(f)

# JSON string operations
json_str = json.dumps(data)
parsed = json.loads(json_str)

# Custom encoder
class DateEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)
            """, language="python")
    
    with tabs[3]:
        st.markdown("#### **Path Operations**")
        
        st.code("""
import os
from pathlib import Path

# os module
current_dir = os.getcwd()
os.chdir('/path/to/directory')
os.makedirs('new/directory/path', exist_ok=True)
os.remove('file.txt')
os.rmdir('empty_directory')

# List directory contents
for item in os.listdir('.'):
    if os.path.isfile(item):
        print(f"File: {item}")
    elif os.path.isdir(item):
        print(f"Dir: {item}")

# pathlib (modern approach)
path = Path('.')
path.exists()
path.is_file()
path.is_dir()
path.mkdir(parents=True, exist_ok=True)

# Path operations
file_path = Path('data') / 'files' / 'test.txt'
file_path.parent
file_path.name
file_path.stem
file_path.suffix
file_path.absolute()

# Glob patterns
for txt_file in Path('.').glob('*.txt'):
    print(txt_file)

for py_file in Path('.').rglob('*.py'):  # Recursive
    print(py_file)
        """, language="python")

def error_handling_lab():
    """Error Handling and Exceptions"""
    
    st.markdown(create_lab_header("Error Handling Lab", "⚠️", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Error Handling Theory**", expanded=True):
        st.markdown("""
        ### ⚠️ **Understanding Error Handling in Python**
        
        Error handling allows programs to gracefully handle unexpected situations and provide 
        meaningful feedback instead of crashing.
        
        **Exception Hierarchy:**
        ```
        BaseException
         ├── SystemExit
         ├── KeyboardInterrupt
         └── Exception
              ├── StopIteration
              ├── ArithmeticError
              │    ├── ZeroDivisionError
              │    └── OverflowError
              ├── LookupError
              │    ├── IndexError
              │    └── KeyError
              ├── TypeError
              ├── ValueError
              ├── IOError
              └── RuntimeError
        ```
        
        **Common Exceptions:**
        
        | Exception | Cause | Example |
        |-----------|-------|---------|
        | TypeError | Wrong type | `'2' + 2` |
        | ValueError | Right type, wrong value | `int('abc')` |
        | IndexError | Index out of range | `[1,2][5]` |
        | KeyError | Dict key not found | `{'a':1}['b']` |
        | AttributeError | Attribute not found | `'str'.append()` |
        | FileNotFoundError | File doesn't exist | `open('none.txt')` |
        | ZeroDivisionError | Division by zero | `1/0` |
        
        **Try-Except Structure:**
        
        1. **try** - Code that might raise exception
        2. **except** - Handle specific exceptions
        3. **else** - Runs if no exception
        4. **finally** - Always runs (cleanup)
        
        **Exception Handling Patterns:**
        
        **EAFP vs LBYL:**
        - **EAFP** - Easier to Ask Forgiveness than Permission
        - **LBYL** - Look Before You Leap
        - Python favors EAFP (try-except)
        
        **Raising Exceptions:**
        - `raise ValueError("message")` - New exception
        - `raise` - Re-raise current exception
        - `raise NewError from e` - Exception chaining
        
        **Custom Exceptions:**
        - Inherit from Exception
        - Add custom attributes
        - Provide meaningful messages
        - Document usage
        
        **Best Practices:**
        - Catch specific exceptions
        - Avoid bare except
        - Log exceptions properly
        - Clean up in finally
        - Don't suppress silently
        - Fail fast when appropriate
        - Use context managers
        
        **Anti-patterns to Avoid:**
        ```python
        # BAD: Too broad
        try:
            risky_operation()
        except:
            pass
        
        # GOOD: Specific
        try:
            risky_operation()
        except ValueError as e:
            logger.error(f"Invalid value: {e}")
            raise
        ```
        """)
    
    tabs = st.tabs(["Try-Except", "Raising Exceptions", "Custom Exceptions", "Best Practices"])
    
    with tabs[0]:
        st.markdown("#### **Try-Except Blocks**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Error Handler")
            
            code_input = st.text_area("Code to execute", "result = 10 / 0")
            
            if st.button("▶️ **Run with Error Handling**", key="run_error"):
                try:
                    exec(code_input)
                    st.success("Code executed successfully!")
                except ZeroDivisionError as e:
                    st.error(f"ZeroDivisionError: {e}")
                except NameError as e:
                    st.error(f"NameError: {e}")
                except Exception as e:
                    st.error(f"Unexpected error: {e}")
                finally:
                    st.info("Execution completed")
        
        with col2:
            st.markdown("##### Exception Patterns")
            st.code("""
# Basic try-except
try:
    risky_operation()
except Exception as e:
    print(f"Error: {e}")

# Multiple exceptions
try:
    code()
except (ValueError, TypeError) as e:
    handle_error(e)
except KeyError as e:
    handle_key_error(e)

# Else and finally
try:
    file = open('data.txt')
except FileNotFoundError:
    print("File not found")
else:
    print("File opened successfully")
    file.close()
finally:
    print("Cleanup completed")
            """, language="python")
    
    with tabs[1]:
        st.markdown("#### **Raising Exceptions**")
        
        st.code("""
# Raising exceptions
def validate_age(age):
    if age < 0:
        raise ValueError("Age cannot be negative")
    if age > 150:
        raise ValueError("Age seems unrealistic")
    return age

# Re-raising exceptions
try:
    dangerous_operation()
except Exception as e:
    log_error(e)
    raise  # Re-raise the same exception

# Raising from another exception
try:
    process_data()
except ValueError as e:
    raise RuntimeError("Data processing failed") from e

# Assert statements
def divide(a, b):
    assert b != 0, "Divisor cannot be zero"
    return a / b
        """, language="python")
    
    with tabs[2]:
        st.markdown("#### **Custom Exceptions**")
        
        st.code("""
# Custom exception class
class ValidationError(Exception):
    \"\"\"Base class for validation errors\"\"\"
    pass

class EmailValidationError(ValidationError):
    \"\"\"Raised when email validation fails\"\"\"
    def __init__(self, email, message="Invalid email format"):
        self.email = email
        self.message = message
        super().__init__(self.message)
    
    def __str__(self):
        return f"{self.message}: {self.email}"

# Using custom exceptions
def validate_email(email):
    if '@' not in email:
        raise EmailValidationError(email)
    if not email.endswith(('.com', '.org', '.net')):
        raise EmailValidationError(
            email, 
            "Email must end with valid domain"
        )

# Exception hierarchy
class AppError(Exception):
    \"\"\"Application base exception\"\"\"
    pass

class DatabaseError(AppError):
    \"\"\"Database related errors\"\"\"
    pass

class NetworkError(AppError):
    \"\"\"Network related errors\"\"\"
    pass
        """, language="python")
    
    with tabs[3]:
        st.markdown("#### **Best Practices**")
        
        st.code("""
# 1. Be specific with exceptions
# Bad
try:
    process()
except:
    pass

# Good
try:
    process()
except SpecificError as e:
    handle_error(e)

# 2. Use context managers
# Instead of:
file = open('data.txt')
try:
    data = file.read()
finally:
    file.close()

# Use:
with open('data.txt') as file:
    data = file.read()

# 3. Log exceptions
import logging

try:
    risky_operation()
except Exception as e:
    logging.error(f"Operation failed: {e}", exc_info=True)
    raise

# 4. Clean error messages
class InvalidConfigError(Exception):
    def __init__(self, config_file, error):
        super().__init__(
            f"Failed to load config from '{config_file}': {error}"
        )

# 5. Use exception chaining
try:
    parse_config()
except ParseError as e:
    raise ConfigError("Configuration invalid") from e
        """, language="python")

def modules_packages_lab():
    """Modules and Packages"""
    
    st.markdown(create_lab_header("Modules & Packages Lab", "🧩", "linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Modules & Packages Theory**", expanded=True):
        st.markdown("""
        ### 🧩 **Understanding Python Modules and Packages**
        
        Modules and packages organize code into reusable components, promoting code organization, 
        namespace management, and distribution.
        
        **Module vs Package:**
        
        | Type | Definition | File Structure | Import |
        |------|------------|----------------|--------|
        | Module | Single .py file | `module.py` | `import module` |
        | Package | Directory with `__init__.py` | `package/` | `import package` |
        | Namespace | Package without `__init__.py` | `namespace/` | PEP 420 |
        
        **Import Mechanisms:**
        
        1. **Import Statements**
           - `import module` - Import entire module
           - `from module import func` - Import specific
           - `from module import *` - Import all (avoid)
           - `import module as alias` - Rename
        
        2. **Import Search Path**
           - Current directory
           - PYTHONPATH directories
           - Standard library
           - Site-packages
           - Check with `sys.path`
        
        **Module Attributes:**
        - `__name__` - Module name
        - `__file__` - File path
        - `__doc__` - Docstring
        - `__all__` - Public API
        - `__version__` - Version info
        
        **Package Structure:**
        ```
        mypackage/
        ├── __init__.py
        ├── module1.py
        ├── module2.py
        └── subpackage/
            ├── __init__.py
            └── module3.py
        ```
        
        **Virtual Environments:**
        - Isolated Python environments
        - Project-specific dependencies
        - Avoid version conflicts
        - `venv` or `virtualenv`
        
        **Best Practices:**
        - Use absolute imports
        - Avoid circular imports
        - Define `__all__` for public API
        - Keep `__init__.py` minimal
        - Use virtual environments
        - Document module purpose
        - Follow PEP 8 naming
        """)
    
    tabs = st.tabs(["Import System", "Creating Modules", "Packages", "Virtual Environments"])
    
    with tabs[0]:
        st.markdown("#### **Import System**")
        
        st.code("""
# Different import styles
import math
from math import pi, sqrt
from math import *  # Avoid this
import numpy as np  # Aliasing
from datetime import datetime as dt

# Conditional imports
try:
    import pandas as pd
except ImportError:
    pd = None
    print("Pandas not installed")

# Dynamic imports
module_name = 'json'
module = __import__(module_name)

# importlib (recommended)
import importlib
module = importlib.import_module('json')

# Reload module
importlib.reload(module)

# Import from parent directory
import sys
sys.path.append('..')
import parent_module
        """, language="python")
    
    with tabs[1]:
        st.markdown("#### **Creating Modules**")
        
        st.code("""
# mymodule.py
\"\"\"
My custom module for utility functions.
\"\"\"

__version__ = '1.0.0'
__author__ = 'Your Name'

# Private variable (won't be imported with *)
_private_var = 'hidden'

# Public function
def public_function():
    \"\"\"This will be imported.\"\"\"
    return "Public"

# Private function (convention)
def _private_function():
    \"\"\"This won't be imported with *.\"\"\"
    return "Private"

# Control what gets imported with *
__all__ = ['public_function', 'MyClass']

class MyClass:
    \"\"\"Public class.\"\"\"
    pass

# Module initialization code
print(f"Loading {__name__} module...")

# Run only when executed directly
if __name__ == '__main__':
    print("Module executed directly")
    # Test code here
        """, language="python")
    
    with tabs[2]:
        st.markdown("#### **Package Structure**")
        
        st.code("""
mypackage/
│
├── __init__.py          # Package initializer
├── module1.py           # Submodule
├── module2.py           # Submodule
│
├── subpackage/          # Subpackage
│   ├── __init__.py
│   ├── submodule1.py
│   └── submodule2.py
│
├── tests/               # Test package
│   ├── __init__.py
│   ├── test_module1.py
│   └── test_module2.py
│
├── setup.py             # Package setup
├── requirements.txt     # Dependencies
├── README.md           # Documentation
└── LICENSE             # License file

# __init__.py content
\"\"\"
MyPackage - A sample Python package
\"\"\"

from .module1 import function1
from .module2 import Class2

__version__ = '1.0.0'
__all__ = ['function1', 'Class2']
        """, language="python")
    
    with tabs[3]:
        st.markdown("#### **Virtual Environments**")
        
        st.code("""
# Creating virtual environment
python -m venv myenv

# Activate (Linux/Mac)
source myenv/bin/activate

# Activate (Windows)
myenv\\Scripts\\activate

# Install packages
pip install package_name
pip install -r requirements.txt

# Save dependencies
pip freeze > requirements.txt

# Deactivate
deactivate

# Using conda
conda create -n myenv python=3.9
conda activate myenv
conda install package_name
conda deactivate

# Using pipenv
pipenv install package_name
pipenv install --dev pytest  # Dev dependency
pipenv shell  # Activate
pipenv run python script.py

# Using poetry
poetry new myproject
poetry add package_name
poetry add --dev pytest
poetry shell
        """, language="python")

def advanced_python_lab():
    """Advanced Python Topics"""
    
    st.markdown(create_lab_header("Advanced Python Lab", "🔧", "linear-gradient(90deg, #FC466B 0%, #3F5EFB 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Advanced Python Theory**", expanded=True):
        st.markdown("""
        ### 🔧 **Understanding Advanced Python Concepts**
        
        Advanced Python features enable powerful programming patterns, performance optimizations, 
        and elegant solutions to complex problems.
        
        **Advanced Concepts Overview:**
        
        | Concept | Purpose | Use Case | Complexity |
        |---------|---------|----------|------------|
        | Iterators | Lazy evaluation | Large datasets | Medium |
        | Generators | Memory efficient | Stream processing | Medium |
        | Decorators | Modify behavior | Cross-cutting concerns | Medium |
        | Context Managers | Resource management | File/DB operations | Low |
        | Metaclasses | Class creation | Frameworks | High |
        | Descriptors | Attribute access | ORMs, validation | High |
        | Async/Await | Concurrency | I/O operations | Medium |
        
        **Iterator Protocol:**
        - `__iter__()` - Return iterator
        - `__next__()` - Get next item
        - `StopIteration` - Signal end
        - Memory efficient
        - Lazy evaluation
        
        **Context Managers:**
        - `__enter__()` - Setup
        - `__exit__()` - Cleanup
        - `with` statement
        - Exception safety
        - Resource management
        
        **Metaclasses:**
        - Classes that create classes
        - `type` is default metaclass
        - Control class creation
        - Singleton, ORM, validation
        
        **Async Programming:**
        - `async def` - Coroutine function
        - `await` - Wait for result
        - `asyncio` - Event loop
        - Concurrent I/O operations
        - Not parallel (GIL)
        
        **Descriptors:**
        - `__get__()`, `__set__()`, `__delete__()`
        - Property implementation
        - Attribute validation
        - Computed attributes
        
        **Best Practices:**
        - Use generators for large datasets
        - Context managers for resources
        - Avoid metaclasses unless necessary
        - Async for I/O-bound tasks
        - Document complex patterns
        """)
    
    tabs = st.tabs(["Iterators", "Context Managers", "Metaclasses", "Async Programming"])
    
    with tabs[0]:
        st.markdown("#### **Iterators and Iterables**")
        
        st.code("""
# Custom iterator
class Counter:
    def __init__(self, start, end):
        self.current = start
        self.end = end
    
    def __iter__(self):
        return self
    
    def __next__(self):
        if self.current < self.end:
            num = self.current
            self.current += 1
            return num
        raise StopIteration

# Using the iterator
counter = Counter(1, 5)
for num in counter:
    print(num)

# Iterator protocol
class Reverse:
    def __init__(self, data):
        self.data = data
        self.index = len(data)
    
    def __iter__(self):
        return self
    
    def __next__(self):
        if self.index == 0:
            raise StopIteration
        self.index -= 1
        return self.data[self.index]

# Infinite iterator
class InfiniteSquares:
    def __init__(self):
        self.num = 0
    
    def __iter__(self):
        return self
    
    def __next__(self):
        result = self.num ** 2
        self.num += 1
        return result
        """, language="python")
    
    with tabs[1]:
        st.markdown("#### **Context Managers**")
        
        st.code("""
# Class-based context manager
class FileManager:
    def __init__(self, filename, mode):
        self.filename = filename
        self.mode = mode
        self.file = None
    
    def __enter__(self):
        self.file = open(self.filename, self.mode)
        return self.file
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.file.close()
        # Return False to propagate exceptions

# Using the context manager
with FileManager('test.txt', 'w') as f:
    f.write('Hello')

# Decorator-based context manager
from contextlib import contextmanager

@contextmanager
def timer():
    import time
    start = time.time()
    print("Starting timer...")
    try:
        yield
    finally:
        end = time.time()
        print(f"Elapsed: {end - start:.2f} seconds")

# Using the timer
with timer():
    import time
    time.sleep(1)

# Multiple context managers
with open('input.txt') as infile, open('output.txt', 'w') as outfile:
    data = infile.read()
    outfile.write(data.upper())
        """, language="python")
    
    with tabs[2]:
        st.markdown("#### **Metaclasses**")
        
        st.code("""
# Simple metaclass
class Meta(type):
    def __new__(cls, name, bases, attrs):
        # Modify class creation
        attrs['class_id'] = f"{name}_{id(cls)}"
        return super().__new__(cls, name, bases, attrs)

class MyClass(metaclass=Meta):
    pass

# Singleton metaclass
class Singleton(type):
    _instances = {}
    
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

class Database(metaclass=Singleton):
    def __init__(self):
        self.connection = "Connected"

# Attribute validation metaclass
class ValidatedMeta(type):
    def __new__(cls, name, bases, namespace):
        for key, value in namespace.items():
            if isinstance(value, property):
                continue
            if key.startswith('_'):
                continue
            if callable(value):
                namespace[key] = cls.validate_method(value)
        return super().__new__(cls, name, bases, namespace)
    
    @staticmethod
    def validate_method(func):
        def wrapper(*args, **kwargs):
            # Add validation logic
            return func(*args, **kwargs)
        return wrapper
        """, language="python")
    
    with tabs[3]:
        st.markdown("#### **Async Programming**")
        
        st.code("""
import asyncio

# Basic async function
async def hello():
    print("Hello")
    await asyncio.sleep(1)
    print("World")

# Run async function
asyncio.run(hello())

# Multiple coroutines
async def fetch_data(url):
    print(f"Fetching {url}")
    await asyncio.sleep(2)
    return f"Data from {url}"

async def main():
    # Concurrent execution
    results = await asyncio.gather(
        fetch_data("url1"),
        fetch_data("url2"),
        fetch_data("url3")
    )
    print(results)

# Async context manager
class AsyncResource:
    async def __aenter__(self):
        print("Acquiring resource")
        await asyncio.sleep(1)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        print("Releasing resource")
        await asyncio.sleep(1)

async def use_resource():
    async with AsyncResource() as resource:
        print("Using resource")

# Async iterator
class AsyncCounter:
    def __init__(self, stop):
        self.current = 0
        self.stop = stop
    
    def __aiter__(self):
        return self
    
    async def __anext__(self):
        if self.current < self.stop:
            await asyncio.sleep(0.1)
            self.current += 1
            return self.current
        raise StopAsyncIteration
        """, language="python")

def testing_lab():
    """Testing and Debugging"""
    
    st.markdown(create_lab_header("Testing Lab", "🧪", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Testing Theory**", expanded=True):
        st.markdown("""
        ### 🧪 **Understanding Testing in Python**
        
        Testing ensures code quality, prevents regressions, and documents expected behavior 
        through automated verification.
        
        **Testing Pyramid:**
        ```
             /\\      E2E Tests (Few)
            /  \\     Integration Tests (Some)
           /____\\    Unit Tests (Many)
        ```
        
        **Test Types:**
        
        | Type | Scope | Speed | Isolation | Purpose |
        |------|-------|-------|-----------|----------|
        | Unit | Function/Method | Fast | High | Logic verification |
        | Integration | Components | Medium | Medium | Interface testing |
        | E2E | Full system | Slow | Low | User scenarios |
        | Smoke | Critical paths | Fast | Low | Basic functionality |
        | Regression | Previous bugs | Varies | Varies | Prevent reoccurrence |
        
        **Testing Frameworks:**
        
        1. **unittest**
           - Built-in framework
           - xUnit style
           - Class-based
           - Good for simple tests
        
        2. **pytest**
           - More pythonic
           - Powerful fixtures
           - Better assertions
           - Plugin ecosystem
        
        3. **doctest**
           - Tests in docstrings
           - Documentation + testing
           - Simple cases only
        
        **Test Principles:**
        - **AAA Pattern** - Arrange, Act, Assert
        - **FIRST** - Fast, Independent, Repeatable, Self-validating, Timely
        - **DRY** - Don't Repeat Yourself
        - **Single Assertion** - One test, one thing
        
        **Mocking:**
        - Replace dependencies
        - Control behavior
        - Verify interactions
        - `unittest.mock` or `pytest-mock`
        
        **Coverage:**
        - Line coverage
        - Branch coverage
        - Target: 80%+
        - Tool: coverage.py
        
        **Best Practices:**
        - Test behavior, not implementation
        - Descriptive test names
        - Independent tests
        - Fast test suite
        - CI/CD integration
        - Test edge cases
        """)
    
    tabs = st.tabs(["Unit Testing", "pytest", "Debugging", "Mocking"])
    
    with tabs[0]:
        st.markdown("#### **Unit Testing with unittest**")
        
        st.code("""
import unittest

class Calculator:
    def add(self, a, b):
        return a + b
    
    def divide(self, a, b):
        if b == 0:
            raise ValueError("Cannot divide by zero")
        return a / b

class TestCalculator(unittest.TestCase):
    def setUp(self):
        \"\"\"Run before each test\"\"\"
        self.calc = Calculator()
    
    def tearDown(self):
        \"\"\"Run after each test\"\"\"
        pass
    
    def test_add(self):
        self.assertEqual(self.calc.add(2, 3), 5)
        self.assertEqual(self.calc.add(-1, 1), 0)
    
    def test_divide(self):
        self.assertEqual(self.calc.divide(10, 2), 5)
        self.assertAlmostEqual(self.calc.divide(10, 3), 3.333, places=2)
    
    def test_divide_by_zero(self):
        with self.assertRaises(ValueError):
            self.calc.divide(10, 0)
    
    @unittest.skip("Not implemented yet")
    def test_multiply(self):
        pass

if __name__ == '__main__':
    unittest.main()
        """, language="python")
    
    with tabs[1]:
        st.markdown("#### **Testing with pytest**")
        
        st.code("""
import pytest

# Simple test
def test_addition():
    assert 1 + 1 == 2

# Fixtures
@pytest.fixture
def sample_data():
    return [1, 2, 3, 4, 5]

def test_sum(sample_data):
    assert sum(sample_data) == 15

# Parametrized tests
@pytest.mark.parametrize("input,expected", [
    (2, 4),
    (3, 9),
    (4, 16),
])
def test_square(input, expected):
    assert input ** 2 == expected

# Testing exceptions
def test_exception():
    with pytest.raises(ValueError):
        int("not a number")

# Markers
@pytest.mark.slow
def test_slow_operation():
    import time
    time.sleep(5)
    assert True

# Run with: pytest -m "not slow"

# Conftest.py for shared fixtures
# conftest.py
@pytest.fixture(scope="session")
def db_connection():
    conn = create_connection()
    yield conn
    conn.close()
        """, language="python")
    
    with tabs[2]:
        st.markdown("#### **Debugging Techniques**")
        
        st.code("""
# Using print debugging
def buggy_function(x):
    print(f"Input: {x}")
    result = x * 2
    print(f"Result: {result}")
    return result

# Using pdb debugger
import pdb

def debug_me(x):
    pdb.set_trace()  # Breakpoint
    y = x * 2
    z = y + 10
    return z

# Better with breakpoint() (Python 3.7+)
def modern_debug(x):
    breakpoint()  # Uses pdb by default
    return x ** 2

# Logging for debugging
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def logged_function(x):
    logger.debug(f"Input: {x}")
    try:
        result = process(x)
        logger.info(f"Success: {result}")
        return result
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        raise

# Using decorators for debugging
def debug(func):
    def wrapper(*args, **kwargs):
        print(f"Calling {func.__name__}")
        print(f"Args: {args}, Kwargs: {kwargs}")
        result = func(*args, **kwargs)
        print(f"Result: {result}")
        return result
    return wrapper

@debug
def add(a, b):
    return a + b
        """, language="python")
    
    with tabs[3]:
        st.markdown("#### **Mocking and Patching**")
        
        st.code("""
from unittest.mock import Mock, MagicMock, patch

# Creating mocks
mock = Mock()
mock.method.return_value = 42
result = mock.method()  # Returns 42

# MagicMock supports magic methods
magic = MagicMock()
magic.__len__.return_value = 5
len(magic)  # Returns 5

# Patching
class EmailService:
    def send(self, to, subject, body):
        # Actually sends email
        pass

def notify_user(email_service, user):
    email_service.send(
        user.email,
        "Notification",
        "You have a notification"
    )

# Test with mock
def test_notify_user():
    mock_service = Mock()
    user = Mock(email="test@example.com")
    
    notify_user(mock_service, user)
    
    mock_service.send.assert_called_once_with(
        "test@example.com",
        "Notification",
        "You have a notification"
    )

# Using patch decorator
@patch('module.EmailService')
def test_with_patch(mock_email):
    mock_email.return_value.send.return_value = True
    # Test code here

# Patch as context manager
with patch('builtins.open', mock_open(read_data='data')):
    with open('file.txt') as f:
        content = f.read()  # Returns 'data'
        """, language="python")

def performance_lab():
    """Performance Optimization"""
    
    st.markdown(create_lab_header("Performance Lab", "⚡", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Performance Theory**", expanded=True):
        st.markdown("""
        ### ⚡ **Understanding Python Performance**
        
        Performance optimization involves identifying bottlenecks and applying appropriate 
        techniques to improve speed and reduce resource usage.
        
        **Performance Bottlenecks:**
        
        | Type | Cause | Solution | Tool |
        |------|-------|----------|------|
        | CPU | Heavy computation | Algorithm optimization | cProfile |
        | Memory | Large data | Generators, slots | memory_profiler |
        | I/O | File/Network | Async, caching | line_profiler |
        | GIL | Threading | Multiprocessing | concurrent.futures |
        
        **Optimization Techniques:**
        
        1. **Algorithmic**
           - Better algorithms (O(n) vs O(n²))
           - Data structure choice
           - Caching/Memoization
        
        2. **Pythonic**
           - List comprehensions
           - Generator expressions
           - Built-in functions
           - Local variables
        
        3. **Libraries**
           - NumPy for numerics
           - Pandas for data
           - Cython for speed
           - Numba for JIT
        
        **Profiling Tools:**
        - **cProfile** - Function-level profiling
        - **line_profiler** - Line-by-line
        - **memory_profiler** - Memory usage
        - **py-spy** - Sampling profiler
        - **scalene** - CPU+GPU+memory
        
        **Memory Optimization:**
        - `__slots__` - Reduce instance size
        - Generators - Lazy evaluation
        - `del` - Explicit cleanup
        - Weak references - Avoid cycles
        
        **Concurrency Options:**
        
        | Method | Best For | GIL Impact | Complexity |
        |--------|----------|------------|------------|
        | Threading | I/O bound | Limited by GIL | Low |
        | Multiprocessing | CPU bound | No GIL | Medium |
        | AsyncIO | I/O bound | Single thread | Medium |
        | Concurrent.futures | Both | Abstraction | Low |
        
        **Best Practices:**
        - Profile before optimizing
        - Optimize hotspots only
        - Measure improvements
        - Consider readability
        - Document optimizations
        """)
    
    tabs = st.tabs(["Profiling", "Optimization", "Memory", "Concurrency"])
    
    with tabs[0]:
        st.markdown("#### **Code Profiling**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Profiling Tools")
            
            code_to_profile = st.text_area("Code to profile", 
"""def slow_function():
    result = []
    for i in range(1000):
        result.append(i ** 2)
    return sum(result)

slow_function()""")
            
            if st.button("🔍 **Profile Code**", key="profile"):
                import cProfile
                import pstats
                import io
                
                pr = cProfile.Profile()
                pr.enable()
                
                try:
                    exec(code_to_profile)
                    pr.disable()
                    
                    s = io.StringIO()
                    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
                    ps.print_stats(10)
                    
                    st.code(s.getvalue(), language="text")
                except Exception as e:
                    st.error(f"Error: {e}")
        
        with col2:
            st.markdown("##### Profiling Examples")
            st.code("""
# Using timeit
import timeit

# Time a statement
time = timeit.timeit('sum([i**2 for i in range(100)])', number=10000)

# Time a function
def test():
    return sum([i**2 for i in range(100)])

time = timeit.timeit(test, number=10000)

# Using cProfile
import cProfile

cProfile.run('slow_function()')

# Line profiler
# pip install line_profiler
# @profile decorator on function
# kernprof -l -v script.py

# Memory profiler
# pip install memory_profiler
# @profile decorator
# python -m memory_profiler script.py
            """, language="python")
    
    with tabs[1]:
        st.markdown("#### **Optimization Techniques**")
        
        st.code("""
# 1. Use built-in functions
# Slow
result = []
for i in range(1000):
    result.append(i ** 2)

# Fast
result = [i ** 2 for i in range(1000)]

# Faster
result = list(map(lambda x: x**2, range(1000)))

# 2. Local variables are faster
# Slow
import math
def slow():
    for i in range(1000000):
        x = math.sqrt(i)

# Fast
def fast():
    sqrt = math.sqrt
    for i in range(1000000):
        x = sqrt(i)

# 3. Use sets for membership testing
# Slow - O(n)
if item in list_items:
    pass

# Fast - O(1)
if item in set_items:
    pass

# 4. String concatenation
# Slow
s = ""
for i in range(1000):
    s += str(i)

# Fast
s = "".join(str(i) for i in range(1000))

# 5. Use deque for queue operations
from collections import deque
# Slow with list
queue = []
queue.append(item)  # O(1)
queue.pop(0)  # O(n)

# Fast with deque
queue = deque()
queue.append(item)  # O(1)
queue.popleft()  # O(1)
        """, language="python")
    
    with tabs[2]:
        st.markdown("#### **Memory Optimization**")
        
        st.code("""
# 1. Generators vs Lists
# Memory heavy
def get_squares_list(n):
    return [i**2 for i in range(n)]

# Memory efficient
def get_squares_gen(n):
    for i in range(n):
        yield i**2

# 2. __slots__ for classes
class WithoutSlots:
    def __init__(self, x, y):
        self.x = x
        self.y = y

class WithSlots:
    __slots__ = ['x', 'y']
    def __init__(self, x, y):
        self.x = x
        self.y = y

# 3. Use array for homogeneous data
import array
# Instead of list
numbers = [1, 2, 3, 4, 5]

# Use array
numbers = array.array('i', [1, 2, 3, 4, 5])

# 4. Weak references
import weakref

class MyClass:
    pass

obj = MyClass()
weak_ref = weakref.ref(obj)

# 5. Clear references
large_data = load_data()
process(large_data)
del large_data  # Clear reference
        """, language="python")
    
    with tabs[3]:
        st.markdown("#### **Concurrency & Parallelism**")
        
        st.code("""
# Threading for I/O bound tasks
import threading

def download(url):
    # Simulate download
    import time
    time.sleep(1)
    return f"Data from {url}"

threads = []
for url in urls:
    t = threading.Thread(target=download, args=(url,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()

# Multiprocessing for CPU bound tasks
import multiprocessing

def cpu_bound(n):
    return sum(i**2 for i in range(n))

with multiprocessing.Pool() as pool:
    results = pool.map(cpu_bound, [1000000, 1000000, 1000000])

# Concurrent.futures
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

# Thread pool
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = [executor.submit(download, url) for url in urls]
    results = [f.result() for f in futures]

# Process pool
with ProcessPoolExecutor(max_workers=4) as executor:
    results = executor.map(cpu_bound, data)

# Asyncio for async I/O
import asyncio

async def async_download(url):
    await asyncio.sleep(1)
    return f"Data from {url}"

async def main():
    tasks = [async_download(url) for url in urls]
    results = await asyncio.gather(*tasks)
    return results

asyncio.run(main())
        """, language="python")

def best_practices_lab():
    """Python Best Practices"""
    
    st.markdown(create_lab_header("Best Practices Lab", "🎨", "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"), unsafe_allow_html=True)
    
    tabs = st.tabs(["PEP 8", "Documentation", "Type Hints", "Design Patterns"])
    
    with tabs[0]:
        st.markdown("#### **PEP 8 Style Guide**")
        
        st.code("""
# Naming conventions
module_name = "lowercase_with_underscores"
ClassName = "CapitalizedWords"
function_name = "lowercase_with_underscores"
CONSTANT_NAME = "UPPERCASE_WITH_UNDERSCORES"
_private_variable = "leading_underscore"
__double_leading = "name_mangling"

# Indentation - 4 spaces
def function():
    if condition:
        do_something()
    else:
        do_other()

# Line length - max 79 characters
long_string = ("This is a very long string that exceeds "
               "the maximum line length and needs to be "
               "broken into multiple lines")

# Imports
import os
import sys
from datetime import datetime
import third_party_module
import local_module

# Whitespace
# Good
spam(ham[1], {eggs: 2})
x = 1
y = 2
long_variable = 3

# Bad
spam( ham[ 1 ], { eggs: 2 } )
x             = 1
y             = 2
long_variable = 3

# Comments
# This is a block comment
# explaining the following code

x = x + 1  # Inline comment

# Docstrings
def function(param1, param2):
    \"\"\"
    Brief description of function.
    
    Args:
        param1: Description of param1
        param2: Description of param2
    
    Returns:
        Description of return value
    \"\"\"
    return param1 + param2
        """, language="python")
    
    with tabs[1]:
        st.markdown("#### **Documentation**")
        
        st.code("""
# Module docstring
\"\"\"
Module Name: utilities
Description: Utility functions for data processing
Author: Your Name
Date: 2024-01-01
\"\"\"

# Function docstrings (Google style)
def process_data(data: list, threshold: float = 0.5) -> dict:
    \"\"\"
    Process raw data and return statistics.
    
    Args:
        data: List of numeric values to process
        threshold: Cutoff value for filtering (default: 0.5)
    
    Returns:
        Dictionary containing:
            - mean: Average value
            - filtered: Values above threshold
            - count: Number of values processed
    
    Raises:
        ValueError: If data is empty
        TypeError: If data contains non-numeric values
    
    Examples:
        >>> result = process_data([1, 2, 3, 4, 5], threshold=2.5)
        >>> print(result['mean'])
        3.0
    \"\"\"
    if not data:
        raise ValueError("Data cannot be empty")
    
    # Implementation
    return result

# Class docstrings
class DataProcessor:
    \"\"\"
    A class for processing and analyzing data.
    
    Attributes:
        data (list): The data to process
        config (dict): Configuration parameters
    
    Methods:
        process(): Process the data
        analyze(): Perform analysis
        export(filename): Export results to file
    \"\"\"
    
    def __init__(self, data: list, config: dict = None):
        \"\"\"
        Initialize DataProcessor.
        
        Args:
            data: Input data
            config: Optional configuration
        \"\"\"
        self.data = data
        self.config = config or {}
        """, language="python")
    
    with tabs[2]:
        st.markdown("#### **Type Hints**")
        
        st.code("""
from typing import List, Dict, Tuple, Optional, Union, Any, Callable
from typing import TypeVar, Generic, Protocol

# Basic type hints
def greet(name: str) -> str:
    return f"Hello, {name}"

# Complex types
def process(
    data: List[int],
    config: Dict[str, Any],
    callback: Optional[Callable[[int], int]] = None
) -> Tuple[float, List[int]]:
    # Process data
    return mean, filtered_data

# Union types
def parse(value: Union[str, int, float]) -> float:
    return float(value)

# Optional (same as Union[type, None])
def find(items: List[str], target: str) -> Optional[int]:
    try:
        return items.index(target)
    except ValueError:
        return None

# Type variables
T = TypeVar('T')

def first(items: List[T]) -> Optional[T]:
    return items[0] if items else None

# Generic classes
class Stack(Generic[T]):
    def __init__(self) -> None:
        self._items: List[T] = []
    
    def push(self, item: T) -> None:
        self._items.append(item)
    
    def pop(self) -> T:
        return self._items.pop()

# Protocol (structural subtyping)
class Drawable(Protocol):
    def draw(self) -> None: ...

def render(obj: Drawable) -> None:
    obj.draw()

# Type aliases
Vector = List[float]
Matrix = List[Vector]

def multiply(m: Matrix, v: Vector) -> Vector:
    # Matrix multiplication
    pass
        """, language="python")
    
    with tabs[3]:
        st.markdown("#### **Design Patterns**")
        
        st.code("""
# Singleton Pattern
class Singleton:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

# Factory Pattern
class AnimalFactory:
    @staticmethod
    def create_animal(animal_type: str):
        if animal_type == "dog":
            return Dog()
        elif animal_type == "cat":
            return Cat()
        raise ValueError(f"Unknown animal: {animal_type}")

# Observer Pattern
class Subject:
    def __init__(self):
        self._observers = []
    
    def attach(self, observer):
        self._observers.append(observer)
    
    def notify(self, message):
        for observer in self._observers:
            observer.update(message)

class Observer:
    def update(self, message):
        print(f"Received: {message}")

# Decorator Pattern (not Python decorator)
class Coffee:
    def cost(self):
        return 5

class MilkDecorator:
    def __init__(self, coffee):
        self.coffee = coffee
    
    def cost(self):
        return self.coffee.cost() + 2

# Strategy Pattern
class SortStrategy:
    def sort(self, data):
        raise NotImplementedError

class QuickSort(SortStrategy):
    def sort(self, data):
        # Quick sort implementation
        pass

class MergeSort(SortStrategy):
    def sort(self, data):
        # Merge sort implementation
        pass

class Sorter:
    def __init__(self, strategy: SortStrategy):
        self.strategy = strategy
    
    def sort(self, data):
        return self.strategy.sort(data)
        """, language="python")

def code_playground_lab():
    """Interactive Code Playground"""
    
    st.markdown(create_lab_header("Code Playground", "💻", "linear-gradient(90deg, #ff6a00 0%, #ee0979 100%)"), unsafe_allow_html=True)
    
    st.markdown("### 🎮 **Interactive Python Environment**")
    
    # Code editor
    code = st.text_area("Python Code", height=300, value="""# Write your Python code here
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)

# Test the function
for i in range(10):
    print(f"fibonacci({i}) = {fibonacci(i)}")
""")
    
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        if st.button("▶️ **Run Code**", type="primary", key="run_playground"):
            # Capture output
            old_stdout = sys.stdout
            sys.stdout = output_buffer = io.StringIO()
            
            try:
                # Execute the code
                exec_globals = {}
                exec(code, exec_globals)
                
                # Get the output
                output = output_buffer.getvalue()
                
                # Display results
                st.success("✅ Code executed successfully!")
                if output:
                    st.markdown("##### Output:")
                    st.code(output, language="text")
                    
            except Exception as e:
                st.error(f"❌ Error: {e}")
                
                # Show traceback
                import traceback
                tb = traceback.format_exc()
                st.markdown("##### Traceback:")
                st.code(tb, language="text")
                
            finally:
                sys.stdout = old_stdout
    
    with col2:
        if st.button("🔍 **Analyze Code**", key="analyze_code"):
            try:
                # Parse the code
                tree = ast.parse(code)
                
                # Count elements
                functions = sum(1 for node in ast.walk(tree) if isinstance(node, ast.FunctionDef))
                classes = sum(1 for node in ast.walk(tree) if isinstance(node, ast.ClassDef))
                imports = sum(1 for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)))
                
                st.markdown("##### Code Analysis:")
                st.write(f"Functions: {functions}")
                st.write(f"Classes: {classes}")
                st.write(f"Imports: {imports}")
                st.write(f"Lines: {len(code.splitlines())}")
                
            except SyntaxError as e:
                st.error(f"Syntax Error: {e}")
    
    with col3:
        if st.button("📊 **Show Bytecode**", key="show_bytecode"):
            try:
                compiled = compile(code, '<string>', 'exec')
                
                # Capture dis output
                old_stdout = sys.stdout
                sys.stdout = output_buffer = io.StringIO()
                
                dis.dis(compiled)
                bytecode = output_buffer.getvalue()
                
                sys.stdout = old_stdout
                
                st.markdown("##### Python Bytecode:")
                st.code(bytecode, language="text")
                
            except Exception as e:
                st.error(f"Error: {e}")
    
    # Code examples
    with st.expander("📚 **Example Code Snippets**"):
        example = st.selectbox("Select Example", [
            "Sorting Algorithms",
            "Data Structures",
            "File Operations",
            "Web Scraping",
            "Data Analysis"
        ])
        
        examples = {
            "Sorting Algorithms": """# Quick Sort Implementation
def quicksort(arr):
    if len(arr) <= 1:
        return arr
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]
    return quicksort(left) + middle + quicksort(right)

# Test
numbers = [3, 6, 8, 10, 1, 2, 1]
print(f"Original: {numbers}")
print(f"Sorted: {quicksort(numbers)}")""",
            
            "Data Structures": """# Binary Tree Implementation
class Node:
    def __init__(self, value):
        self.value = value
        self.left = None
        self.right = None

class BinaryTree:
    def __init__(self):
        self.root = None
    
    def insert(self, value):
        if not self.root:
            self.root = Node(value)
        else:
            self._insert(value, self.root)
    
    def _insert(self, value, node):
        if value < node.value:
            if node.left:
                self._insert(value, node.left)
            else:
                node.left = Node(value)
        else:
            if node.right:
                self._insert(value, node.right)
            else:
                node.right = Node(value)

# Test
tree = BinaryTree()
for val in [5, 3, 7, 2, 4, 6, 8]:
    tree.insert(val)
print("Tree created!")""",
            
            "File Operations": """# File handling example
import json

# Write JSON file
data = {
    'name': 'Python Lab',
    'version': '1.0',
    'features': ['basics', 'advanced', 'testing']
}

# Simulate file operations (in memory)
json_string = json.dumps(data, indent=2)
print("JSON Output:")
print(json_string)

# Parse JSON
parsed = json.loads(json_string)
print(f"\\nParsed name: {parsed['name']}")
print(f"Features: {', '.join(parsed['features'])}")""",
            
            "Web Scraping": """# Simple HTML parser
import re

html = '''
<html>
    <head><title>Sample Page</title></head>
    <body>
        <h1>Welcome</h1>
        <p>This is a paragraph.</p>
        <a href="https://example.com">Link</a>
    </body>
</html>
'''

# Extract title
title = re.search(r'<title>(.*?)</title>', html)
if title:
    print(f"Title: {title.group(1)}")

# Extract all links
links = re.findall(r'href="(.*?)"', html)
print(f"Links: {links}")

# Extract text from tags
h1 = re.search(r'<h1>(.*?)</h1>', html)
if h1:
    print(f"H1: {h1.group(1)}")""",
            
            "Data Analysis": """# Data analysis with pandas simulation
import random

# Generate sample data
data = {
    'date': [f'2024-01-{i:02d}' for i in range(1, 11)],
    'sales': [random.randint(100, 1000) for _ in range(10)],
    'customers': [random.randint(10, 100) for _ in range(10)]
}

# Calculate statistics
total_sales = sum(data['sales'])
avg_sales = total_sales / len(data['sales'])
max_sales = max(data['sales'])
min_sales = min(data['sales'])

print("Sales Analysis:")
print(f"Total: ${total_sales}")
print(f"Average: ${avg_sales:.2f}")
print(f"Maximum: ${max_sales}")
print(f"Minimum: ${min_sales}")

# Find best day
best_day_idx = data['sales'].index(max_sales)
print(f"\\nBest day: {data['date'][best_day_idx]} with ${max_sales}")"""
        }
        
        if example in examples:
            st.code(examples[example], language="python")
            if st.button("📋 **Copy to Editor**", key=f"copy_{example}"):
                st.info("💡 Copy the code above and paste it in the editor!")

if __name__ == "__main__":
    run_lab()
