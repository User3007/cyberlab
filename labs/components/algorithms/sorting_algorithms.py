"""
Sorting Algorithms Component
Algorithm fundamentals with interactive demonstrations
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
import time
from typing import Dict, List, Any, Optional

from ...shared.color_schemes import SOFTWARE_DEVELOPMENT_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class SortingAlgorithmsComponent(ComponentTemplate):
    """Sorting Algorithms component with interactive demonstrations"""
    
    def __init__(self):
        super().__init__(
            component_name="🔢 Sorting Algorithms",
            description="Fundamental sorting algorithms with complexity analysis and visual demonstrations",
            color_scheme=SOFTWARE_DEVELOPMENT_COLORS,
            estimated_time="30 minutes"
        )
        
        self.set_key_concepts([
            "Time Complexity", "Space Complexity", "Stability", "In-place Sorting"
        ])
    
    def render_content(self):
        """Render Sorting Algorithms content"""
        
        # Algorithm overview
        self._render_algorithm_overview()
        
        # Interactive sorting demo
        self._render_interactive_demo()
        
        # Complexity analysis
        self._render_complexity_analysis()
        
        # Algorithm comparison
        self._render_algorithm_comparison()
    
    def _render_algorithm_overview(self):
        """Render sorting algorithms overview"""
        st.subheader("🔢 Sorting Algorithms Overview")
        
        # Algorithm categories
        algorithms = {
            "Bubble Sort": {
                "description": "Simple comparison-based algorithm that repeatedly steps through the list",
                "time_complexity": "O(n²)",
                "space_complexity": "O(1)",
                "stability": "Stable",
                "best_case": "O(n) with optimization",
                "use_case": "Educational purposes, small datasets"
            },
            "Selection Sort": {
                "description": "Finds minimum element and places it at the beginning",
                "time_complexity": "O(n²)",
                "space_complexity": "O(1)",
                "stability": "Unstable",
                "best_case": "O(n²)",
                "use_case": "Small datasets, memory-constrained environments"
            },
            "Insertion Sort": {
                "description": "Builds sorted array one element at a time",
                "time_complexity": "O(n²)",
                "space_complexity": "O(1)",
                "stability": "Stable",
                "best_case": "O(n)",
                "use_case": "Small datasets, nearly sorted data"
            },
            "Merge Sort": {
                "description": "Divide-and-conquer algorithm that divides array into halves",
                "time_complexity": "O(n log n)",
                "space_complexity": "O(n)",
                "stability": "Stable",
                "best_case": "O(n log n)",
                "use_case": "Large datasets, guaranteed performance"
            },
            "Quick Sort": {
                "description": "Divide-and-conquer using pivot element partitioning",
                "time_complexity": "O(n log n) average",
                "space_complexity": "O(log n)",
                "stability": "Unstable",
                "best_case": "O(n log n)",
                "use_case": "General purpose, in-place sorting"
            },
            "Heap Sort": {
                "description": "Uses binary heap data structure to sort elements",
                "time_complexity": "O(n log n)",
                "space_complexity": "O(1)",
                "stability": "Unstable",
                "best_case": "O(n log n)",
                "use_case": "Guaranteed performance, in-place sorting"
            }
        }
        
        # Algorithm selector
        selected_algorithm = st.selectbox(
            "🔍 Explore Sorting Algorithm:",
            list(algorithms.keys()),
            key="sorting_algorithm_selector"
        )
        
        algo_info = algorithms[selected_algorithm]
        
        create_info_card(
            f"🔢 {selected_algorithm}",
            algo_info['description'],
            card_type="primary",
            color_scheme=self.color_scheme
        )
        
        # Algorithm details
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**⏱️ Complexity:**")
            st.markdown(f"• **Time:** {algo_info['time_complexity']}")
            st.markdown(f"• **Space:** {algo_info['space_complexity']}")
            st.markdown(f"• **Best Case:** {algo_info['best_case']}")
        
        with col2:
            st.markdown("**🔧 Properties:**")
            st.markdown(f"• **Stability:** {algo_info['stability']}")
            st.markdown(f"• **Use Case:** {algo_info['use_case']}")
    
    def _render_interactive_demo(self):
        """Render interactive sorting demonstration"""
        st.subheader("🎮 Interactive Sorting Demo")
        
        # Input controls
        col1, col2, col3 = st.columns(3)
        
        with col1:
            array_size = st.slider("Array Size:", 5, 20, 10, key="array_size_slider")
        
        with col2:
            demo_algorithm = st.selectbox(
                "Algorithm:",
                ["Bubble Sort", "Selection Sort", "Insertion Sort"],
                key="demo_algorithm_selector"
            )
        
        with col3:
            if st.button("🎲 Generate Random Array", key="generate_array_btn"):
                st.session_state.demo_array = np.random.randint(1, 100, array_size).tolist()
        
        # Initialize array if not exists
        if 'demo_array' not in st.session_state:
            st.session_state.demo_array = np.random.randint(1, 100, array_size).tolist()
        
        # Display current array
        st.markdown("**Current Array:**")
        st.write(st.session_state.demo_array)
        
        # Sorting demonstration
        if st.button("🚀 Sort Array", key="sort_array_btn"):
            if demo_algorithm == "Bubble Sort":
                sorted_array = self._bubble_sort_demo(st.session_state.demo_array.copy())
            elif demo_algorithm == "Selection Sort":
                sorted_array = self._selection_sort_demo(st.session_state.demo_array.copy())
            elif demo_algorithm == "Insertion Sort":
                sorted_array = self._insertion_sort_demo(st.session_state.demo_array.copy())
            
            st.markdown("**Sorted Array:**")
            st.write(sorted_array)
            
            # Create visualization
            self._visualize_sorting_result(st.session_state.demo_array, sorted_array)
    
    def _bubble_sort_demo(self, arr: List[int]) -> List[int]:
        """Bubble sort implementation for demo"""
        n = len(arr)
        for i in range(n):
            for j in range(0, n - i - 1):
                if arr[j] > arr[j + 1]:
                    arr[j], arr[j + 1] = arr[j + 1], arr[j]
        return arr
    
    def _selection_sort_demo(self, arr: List[int]) -> List[int]:
        """Selection sort implementation for demo"""
        n = len(arr)
        for i in range(n):
            min_idx = i
            for j in range(i + 1, n):
                if arr[j] < arr[min_idx]:
                    min_idx = j
            arr[i], arr[min_idx] = arr[min_idx], arr[i]
        return arr
    
    def _insertion_sort_demo(self, arr: List[int]) -> List[int]:
        """Insertion sort implementation for demo"""
        for i in range(1, len(arr)):
            key = arr[i]
            j = i - 1
            while j >= 0 and arr[j] > key:
                arr[j + 1] = arr[j]
                j -= 1
            arr[j + 1] = key
        return arr
    
    def _visualize_sorting_result(self, original: List[int], sorted_arr: List[int]):
        """Visualize sorting results"""
        fig = go.Figure()
        
        # Original array
        fig.add_trace(go.Bar(
            x=list(range(len(original))),
            y=original,
            name="Original",
            marker_color=self.color_scheme['danger'],
            opacity=0.7
        ))
        
        # Sorted array
        fig.add_trace(go.Bar(
            x=list(range(len(sorted_arr))),
            y=sorted_arr,
            name="Sorted",
            marker_color=self.color_scheme['success'],
            opacity=0.7
        ))
        
        fig.update_layout(
            title="Sorting Visualization",
            xaxis_title="Index",
            yaxis_title="Value",
            barmode='group',
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def _render_complexity_analysis(self):
        """Render complexity analysis"""
        st.subheader("📊 Complexity Analysis")
        
        # Time complexity comparison
        complexity_data = [
            {"Algorithm": "Bubble Sort", "Best": "O(n)", "Average": "O(n²)", "Worst": "O(n²)", "Space": "O(1)"},
            {"Algorithm": "Selection Sort", "Best": "O(n²)", "Average": "O(n²)", "Worst": "O(n²)", "Space": "O(1)"},
            {"Algorithm": "Insertion Sort", "Best": "O(n)", "Average": "O(n²)", "Worst": "O(n²)", "Space": "O(1)"},
            {"Algorithm": "Merge Sort", "Best": "O(n log n)", "Average": "O(n log n)", "Worst": "O(n log n)", "Space": "O(n)"},
            {"Algorithm": "Quick Sort", "Best": "O(n log n)", "Average": "O(n log n)", "Worst": "O(n²)", "Space": "O(log n)"},
            {"Algorithm": "Heap Sort", "Best": "O(n log n)", "Average": "O(n log n)", "Worst": "O(n log n)", "Space": "O(1)"}
        ]
        
        df = pd.DataFrame(complexity_data)
        st.dataframe(df, use_container_width=True)
        
        # Big O notation explanation
        st.markdown("#### 🔍 Big O Notation Guide")
        
        big_o_examples = [
            "**O(1)** - Constant time: Array access, hash table lookup",
            "**O(log n)** - Logarithmic: Binary search, heap operations",
            "**O(n)** - Linear: Array traversal, linear search",
            "**O(n log n)** - Linearithmic: Efficient sorting algorithms",
            "**O(n²)** - Quadratic: Nested loops, simple sorting algorithms",
            "**O(2ⁿ)** - Exponential: Brute force algorithms, recursive Fibonacci"
        ]
        
        for example in big_o_examples:
            st.markdown(example)
    
    def _render_algorithm_comparison(self):
        """Render algorithm comparison"""
        st.subheader("⚖️ Algorithm Comparison")
        
        # Performance comparison chart
        algorithms = ["Bubble", "Selection", "Insertion", "Merge", "Quick", "Heap"]
        small_data = [1, 1, 1, 3, 3, 3]  # Relative performance for small datasets
        large_data = [5, 5, 5, 2, 1, 2]  # Relative performance for large datasets
        
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            name='Small Data (n < 100)',
            x=algorithms,
            y=small_data,
            marker_color=self.color_scheme['primary']
        ))
        
        fig.add_trace(go.Bar(
            name='Large Data (n > 1000)',
            x=algorithms,
            y=large_data,
            marker_color=self.color_scheme['secondary']
        ))
        
        fig.update_layout(
            title='Algorithm Performance Comparison',
            xaxis_title='Sorting Algorithm',
            yaxis_title='Relative Performance (lower is better)',
            barmode='group',
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Algorithm selection guide
        st.markdown("#### 🎯 Algorithm Selection Guide")
        
        selection_guide = [
            "**Small datasets (n < 50):** Insertion Sort - Simple and efficient",
            "**General purpose:** Quick Sort - Good average performance",
            "**Guaranteed performance:** Merge Sort - Consistent O(n log n)",
            "**Memory constrained:** Heap Sort - In-place with good performance",
            "**Nearly sorted data:** Insertion Sort - Optimal for partially sorted arrays",
            "**Educational purposes:** Bubble Sort - Easy to understand and implement"
        ]
        
        for guide in selection_guide:
            st.markdown(guide)


def explain_sorting_algorithms():
    """Main function for Sorting Algorithms"""
    component = SortingAlgorithmsComponent()
    
    summary_points = [
        "Sorting algorithms vary in time complexity from O(n²) to O(n log n)",
        "Algorithm choice depends on dataset size, memory constraints, and stability requirements",
        "Divide-and-conquer algorithms (Merge, Quick) generally perform better on large datasets",
        "Understanding Big O notation is crucial for algorithm analysis and selection"
    ]
    
    resources = [
        {"title": "Introduction to Algorithms (CLRS)", "description": "Comprehensive algorithms textbook"},
        {"title": "Algorithm Visualizer", "description": "Interactive algorithm visualization tools"},
        {"title": "LeetCode Sorting Problems", "description": "Practice sorting algorithm implementations"}
    ]
    
    component.render_full_component(summary_points, resources)
