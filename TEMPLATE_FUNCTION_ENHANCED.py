"""
Template Function - TDD Pattern với Highlighted Keywords
Sử dụng template này để upgrade tất cả 82 functions
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import math

def explain_concept_template():
    """Template function using TDD pattern"""
    st.markdown("### Concept Name")
    
    # 1. Visual Banner (Clean, professional)
    st.markdown("""
    <div style="background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            Main Concept Title
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Brief concept description
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 2. Visual Diagram (Using Plotly - like TDD cycle)
    st.markdown("#### Concept Visualization")
    
    # Create interactive diagram
    fig = go.Figure()
    
    # Example: Circular concept diagram
    concepts = ['Concept A', 'Concept B', 'Concept C', 'Concept D']
    colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4']
    positions = [(0.2, 0.8), (0.8, 0.8), (0.2, 0.2), (0.8, 0.2)]
    
    for concept, color, (x, y) in zip(concepts, colors, positions):
        # Add shapes
        fig.add_shape(
            type="circle",
            x0=x-0.15, y0=y-0.15, x1=x+0.15, y1=y+0.15,
            fillcolor=color,
            opacity=0.7,
            line=dict(color=color, width=2)
        )
        
        # Add labels
        fig.add_annotation(
            x=x, y=y,
            text=f"<b>{concept}</b>",
            showarrow=False,
            font=dict(size=12, color="white"),
        )
    
    fig.update_layout(
        xaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=300,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # 3. Clean Content (Minimal icons)
    with st.expander("Chi tiết về Concept"):
        st.markdown("""
        ## Concept Fundamentals
        
        **Definition:** Clear, concise explanation of the concept.
        
        ---
        
        ## Key Components
        
        ### **Component 1**
        **Purpose:** What this component does
        **Implementation:** How to implement it
        **Benefits:** Why it's important
        
        ### **Component 2**  
        **Purpose:** What this component does
        **Implementation:** How to implement it
        **Benefits:** Why it's important
        
        ---
        
        ## Real-world Examples
        
        **Example 1:** Practical application
        - **Scenario:** When to use
        - **Implementation:** How it works
        - **Result:** Expected outcome
        
        **Example 2:** Another practical application
        - **Scenario:** When to use
        - **Implementation:** How it works
        - **Result:** Expected outcome
        """)
    
    # 4. Enhanced Cheat Sheets (Highlighted keywords)
    st.markdown("---")
    st.markdown("## Concept Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["Core Concepts", "Best Practices", "Tools & Techniques"])
    
    with tab1:
        st.markdown("### Core Concepts")
        
        # HIGHLIGHTED KEYWORDS using **bold** và `code`
        core_concepts = [
            {
                "**Concept**": "**Primary Concept**",  # Bold concept name
                "Definition": "Clear definition with `code examples`",
                "**Purpose**": "**Main purpose**",  # Bold purpose
                "Implementation": "`technical_implementation()`",  # Code formatting
                "**Key Benefits**": "**Performance**, **Reliability**",  # Bold benefits
                "Example": "Real-world usage example"
            },
            {
                "**Concept**": "**Secondary Concept**",
                "Definition": "Another definition with `syntax_example`",
                "**Purpose**": "**Supporting purpose**",
                "Implementation": "`another_implementation()`",
                "**Key Benefits**": "**Scalability**, **Maintainability**",
                "Example": "Another practical example"
            },
            {
                "**Concept**": "**Advanced Concept**",
                "Definition": "Complex definition with `advanced_syntax`",
                "**Purpose**": "**Optimization purpose**",
                "Implementation": "`complex_implementation()`",
                "**Key Benefits**": "**Efficiency**, **Flexibility**",
                "Example": "Advanced use case"
            }
        ]
        
        df_concepts = pd.DataFrame(core_concepts)
        st.dataframe(df_concepts, use_container_width=True)
        
        # Additional highlighted information
        st.markdown("""
        #### **Key Terminology**
        - **Term 1**: `definition_1` - Important concept
        - **Term 2**: `definition_2` - Critical understanding  
        - **Term 3**: `definition_3` - Essential knowledge
        """)
    
    with tab2:
        st.markdown("### Best Practices")
        
        best_practices = [
            {
                "**Practice**": "**Practice Name 1**",
                "**Category**": "**Design**",
                "Description": "Detailed explanation of the practice",
                "**Benefits**": "**Quality**, **Performance**",
                "**Implementation**": "`code_example_1()`",
                "**Difficulty**": "Beginner"
            },
            {
                "**Practice**": "**Practice Name 2**",
                "**Category**": "**Performance**", 
                "Description": "Another important practice",
                "**Benefits**": "**Speed**, **Efficiency**",
                "**Implementation**": "`code_example_2()`",
                "**Difficulty**": "Intermediate"
            },
            {
                "**Practice**": "**Practice Name 3**",
                "**Category**": "**Security**",
                "Description": "Security-focused practice",
                "**Benefits**": "**Safety**, **Compliance**", 
                "**Implementation**": "`security_code()`",
                "**Difficulty**": "Advanced"
            }
        ]
        
        df_practices = pd.DataFrame(best_practices)
        st.dataframe(df_practices, use_container_width=True)
    
    with tab3:
        st.markdown("### Tools & Techniques")
        
        tools = [
            {
                "**Tool/Technique**": "**Tool Name 1**",
                "**Type**": "**Framework**",
                "**Purpose**": "Main functionality",
                "**Language**": "`Python`",
                "**Complexity**": "Low",
                "**Example Usage**": "`tool.method()`"
            },
            {
                "**Tool/Technique**": "**Tool Name 2**", 
                "**Type**": "**Library**",
                "**Purpose**": "Specialized functionality",
                "**Language**": "`JavaScript`",
                "**Complexity**": "Medium",
                "**Example Usage**": "`library.function()`"
            },
            {
                "**Tool/Technique**": "**Technique Name**",
                "**Type**": "**Methodology**",
                "**Purpose**": "Process improvement",
                "**Language**": "Language-agnostic",
                "**Complexity**": "High", 
                "**Example Usage**": "Step-by-step process"
            }
        ]
        
        df_tools = pd.DataFrame(tools)
        st.dataframe(df_tools, use_container_width=True)
    
    # 5. Interactive Demo (Simple, focused)
    st.markdown("---")
    st.markdown("## Interactive Demo")
    
    with st.expander("Try the Concept"):
        st.markdown("### Concept Demonstration")
        
        # Simple interactive element
        demo_option = st.selectbox(
            "Choose demonstration type:", 
            ["Basic Example", "Advanced Example", "Real-world Scenario"]
        )
        
        if demo_option == "Basic Example":
            st.markdown("**Basic Implementation:**")
            st.code("""
# Basic example code
def basic_example():
    result = "This demonstrates basic concept"
    return result

print(basic_example())
            """, language="python")
            st.success("✅ This shows the **fundamental concept** in action!")
            
        elif demo_option == "Advanced Example":
            st.markdown("**Advanced Implementation:**")
            st.code("""
# Advanced example with more complexity
class AdvancedConcept:
    def __init__(self, parameter):
        self.parameter = parameter
    
    def advanced_method(self):
        return f"Advanced result: {self.parameter}"

concept = AdvancedConcept("example")
print(concept.advanced_method())
            """, language="python")
            st.success("✅ This demonstrates **advanced usage** with real implementation!")
            
        elif demo_option == "Real-world Scenario":
            st.markdown("**Real-world Application:**")
            st.code("""
# Real-world scenario implementation
import real_world_library

def solve_real_problem():
    data = real_world_library.get_data()
    processed = real_world_library.process(data)
    return real_world_library.optimize(processed)

result = solve_real_problem()
            """, language="python")
            st.success("✅ This shows how the concept **solves real problems**!")
    
    # 6. Key Takeaways (Clean summary)
    st.markdown("---")
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1.5rem; border-radius: 10px; border-left: 5px solid #1f77b4;">
        <h4 style="margin-top: 0; color: #1f77b4;">Key Takeaways</h4>
        <ul>
            <li><strong>Core Understanding</strong>: Main concept provides foundation for advanced topics</li>
            <li><strong>Practical Application</strong>: Real-world usage drives better comprehension</li>
            <li><strong>Best Practices</strong>: Following established patterns ensures quality results</li>
            <li><strong>Tool Knowledge</strong>: Understanding available tools improves efficiency</li>
            <li><strong>Continuous Learning</strong>: Concept evolves with technology advancement</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

# Example of how to apply this template for specific concepts
def explain_cia_triad_enhanced():
    """CIA Triad using enhanced template"""
    st.markdown("### CIA Triad")
    
    # Visual Banner
    st.markdown("""
    <div style="background: linear-gradient(90deg, #ff7b7b 0%, #ff6b6b 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            CIA Triad
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Foundation of Information Security
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # CIA Triangle Diagram
    st.markdown("#### Security Triangle")
    
    fig = go.Figure()
    
    # Create triangle for CIA
    triangle_points = [(0.5, 0.8), (0.2, 0.2), (0.8, 0.2), (0.5, 0.8)]  # Close the triangle
    x_coords = [p[0] for p in triangle_points]
    y_coords = [p[1] for p in triangle_points]
    
    # Add triangle shape
    fig.add_shape(
        type="path",
        path=f"M {x_coords[0]},{y_coords[0]} L {x_coords[1]},{y_coords[1]} L {x_coords[2]},{y_coords[2]} Z",
        fillcolor="rgba(255, 107, 107, 0.3)",
        line=dict(color="#ff6b6b", width=3)
    )
    
    # Add CIA labels at triangle vertices
    cia_labels = [
        ("Confidentiality", 0.5, 0.85, "#ff4757"),
        ("Integrity", 0.15, 0.15, "#2ed573"), 
        ("Availability", 0.85, 0.15, "#3742fa")
    ]
    
    for label, x, y, color in cia_labels:
        fig.add_annotation(
            x=x, y=y,
            text=f"<b>{label}</b>",
            showarrow=False,
            font=dict(size=14, color=color),
            bgcolor="white",
            bordercolor=color,
            borderwidth=2,
            borderpad=4
        )
    
    fig.update_layout(
        xaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=350,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Enhanced cheat sheet with highlighted keywords
    st.markdown("---")
    st.markdown("## CIA Triad Cheat Sheet")
    
    tab1, tab2 = st.tabs(["Core Principles", "Implementation"])
    
    with tab1:
        cia_concepts = [
            {
                "**Principle**": "**Confidentiality**",
                "**Definition**": "Information is accessible only to **authorized** individuals",
                "**Threats**": "Unauthorized access, **data breaches**",
                "**Controls**": "`encryption`, `access_controls`, `authentication`",
                "**Example**": "**Password protection**, encrypted databases"
            },
            {
                "**Principle**": "**Integrity**", 
                "**Definition**": "Information remains **accurate** and **unmodified**",
                "**Threats**": "Data corruption, **unauthorized modifications**",
                "**Controls**": "`checksums`, `digital_signatures`, `version_control`",
                "**Example**": "**Hash verification**, audit trails"
            },
            {
                "**Principle**": "**Availability**",
                "**Definition**": "Information is **accessible** when needed",
                "**Threats**": "System downtime, **DoS attacks**", 
                "**Controls**": "`redundancy`, `backup_systems`, `load_balancing`",
                "**Example**": "**24/7 uptime**, disaster recovery"
            }
        ]
        
        df = pd.DataFrame(cia_concepts)
        st.dataframe(df, use_container_width=True)

# Demo how template scales to different concepts
def explain_agile_enhanced():
    """Agile Methodology using enhanced template"""
    st.markdown("### Agile Methodology")
    
    # Different color scheme for Software Development
    st.markdown("""
    <div style="background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            Agile Development Methodology
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Iterative và Incremental Development
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Agile cycle diagram (similar to TDD but for Agile)
    st.markdown("#### Agile Development Cycle")
    
    fig = go.Figure()
    
    # Agile cycle phases
    phases = ['Plan', 'Design', 'Develop', 'Test', 'Deploy', 'Review']
    colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#feca57', '#ff9ff3']
    
    # Create circular layout
    center_x, center_y = 0.5, 0.5
    radius = 0.35
    
    for i, (phase, color) in enumerate(zip(phases, colors)):
        angle = i * 60  # 60 degrees apart for 6 phases
        rad = math.radians(angle)
        x = center_x + radius * math.cos(rad)
        y = center_y + radius * math.sin(rad)
        
        # Add circles
        fig.add_shape(
            type="circle",
            x0=x-0.08, y0=y-0.08, x1=x+0.08, y1=y+0.08,
            fillcolor=color,
            opacity=0.8,
            line=dict(color=color, width=2)
        )
        
        # Add labels
        fig.add_annotation(
            x=x, y=y,
            text=f"<b>{phase}</b>",
            showarrow=False,
            font=dict(size=10, color="white"),
        )
    
    fig.update_layout(
        xaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=350,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Agile principles with highlighted keywords
    st.markdown("## Agile Principles Cheat Sheet")
    
    agile_principles = [
        {
            "**Principle**": "**Individuals over Processes**",
            "**Focus**": "**People** và **interactions**",
            "**Implementation**": "Team collaboration, `daily_standups`",
            "**Benefit**": "**Flexibility**, **Communication**"
        },
        {
            "**Principle**": "**Working Software over Documentation**", 
            "**Focus**": "**Functional** deliverables",
            "**Implementation**": "Frequent releases, `working_prototypes`",
            "**Benefit**": "**Value delivery**, **User feedback**"
        },
        {
            "**Principle**": "**Customer Collaboration**",
            "**Focus**": "**Stakeholder** engagement", 
            "**Implementation**": "Regular reviews, `customer_feedback`",
            "**Benefit**": "**Requirements clarity**, **Satisfaction**"
        },
        {
            "**Principle**": "**Responding to Change**",
            "**Focus**": "**Adaptability** over rigid plans",
            "**Implementation**": "Sprint planning, `iterative_development`", 
            "**Benefit**": "**Responsiveness**, **Innovation**"
        }
    ]
    
    df = pd.DataFrame(agile_principles)
    st.dataframe(df, use_container_width=True)

if __name__ == "__main__":
    st.title("Enhanced Function Templates")
    
    demo_choice = st.selectbox("Choose template demo:", [
        "Generic Template",
        "CIA Triad Example", 
        "Agile Methodology Example"
    ])
    
    if demo_choice == "Generic Template":
        explain_concept_template()
    elif demo_choice == "CIA Triad Example":
        explain_cia_triad_enhanced()
    elif demo_choice == "Agile Methodology Example":
        explain_agile_enhanced()
