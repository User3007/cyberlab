import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import random
import math

def run_lab():
    """Software Development Fundamentals Lab"""
    
    st.title("💻 Software Development Fundamentals")
    st.markdown("---")
    
    # Tabs cho các chủ đề phát triển phần mềm
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🏗️ SDLC & Methodologies", 
        "💾 Programming Concepts",
        "🗄️ Data Structures & Algorithms", 
        "🧪 Testing & Quality Assurance",
        "🔧 DevOps & CI/CD",
        "📊 Project Management"
    ])
    
    with tab1:
        sdlc_methodologies_lab()
    
    with tab2:
        programming_concepts_lab()
    
    with tab3:
        data_structures_algorithms_lab()
        
    with tab4:
        testing_qa_lab()
        
    with tab5:
        devops_cicd_lab()
        
    with tab6:
        project_management_lab()

def sdlc_methodologies_lab():
    """Lab về SDLC và methodologies"""
    st.subheader("🏗️ SDLC & Methodologies")
    
    methodology_choice = st.selectbox("Chọn methodology:", [
        "Software Development Life Cycle (SDLC)",
        "Waterfall Model",
        "Agile Methodology",
        "Scrum Framework",
        "DevOps Culture"
    ])
    
    if methodology_choice == "Software Development Life Cycle (SDLC)":
        explain_sdlc()
    elif methodology_choice == "Waterfall Model":
        explain_waterfall()
    elif methodology_choice == "Agile Methodology":
        explain_agile()
    elif methodology_choice == "Scrum Framework":
        explain_scrum()
    elif methodology_choice == "DevOps Culture":
        explain_devops_culture()

def explain_sdlc():
    """Enhanced Software Development Life Cycle explanation using TDD pattern"""
    st.markdown("### Software Development Life Cycle (SDLC)")
    
    # 1. Visual Banner (Software Development color scheme)
    st.markdown("""
    <div style="background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            Software Development Life Cycle
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Systematic Approach to Software Development
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 2. Visual Diagram (Enhanced SDLC phases with modern practices)
    st.markdown("#### Modern SDLC Phases")
    
    fig = go.Figure()
    
    # SDLC phases với modern practices
    phases = [
        {"name": "Plan", "x": 1, "y": 3, "color": "#e74c3c", "practices": ["Agile Planning", "User Stories", "Sprint Planning"]},
        {"name": "Design", "x": 2, "y": 3, "color": "#f39c12", "practices": ["System Architecture", "API Design", "UI/UX Design"]},
        {"name": "Develop", "x": 3, "y": 3, "color": "#f1c40f", "practices": ["Clean Code", "TDD", "Code Reviews"]},
        {"name": "Test", "x": 4, "y": 3, "color": "#2ecc71", "practices": ["Automated Testing", "CI/CD", "Quality Gates"]},
        {"name": "Deploy", "x": 5, "y": 3, "color": "#3498db", "practices": ["DevOps", "Blue-Green", "Monitoring"]},
        {"name": "Maintain", "x": 6, "y": 3, "color": "#9b59b6", "practices": ["Bug Fixes", "Updates", "Optimization"]}
    ]
    
    # Add phase boxes
    for i, phase in enumerate(phases):
        # Main phase box
        fig.add_shape(
            type="rect",
            x0=phase["x"]-0.4, y0=phase["y"]-0.3, x1=phase["x"]+0.4, y1=phase["y"]+0.3,
            fillcolor=phase["color"],
            opacity=0.8,
            line=dict(color="white", width=2)
        )
        
        # Phase name
        fig.add_annotation(
            x=phase["x"], y=phase["y"],
            text=f"<b>{phase['name']}</b>",
            showarrow=False,
            font=dict(size=12, color="white")
        )
        
        # Modern practices below each phase
        practices_text = "<br>".join([f"• {practice}" for practice in phase["practices"]])
        fig.add_annotation(
            x=phase["x"], y=phase["y"]-0.8,
            text=practices_text,
            showarrow=False,
            font=dict(size=8, color="#2c3e50"),
            bgcolor="rgba(255,255,255,0.9)",
            bordercolor=phase["color"],
            borderwidth=1,
            borderpad=3
        )
        
        # Add arrows between phases
        if i < len(phases) - 1:
            fig.add_annotation(
                x=phase["x"] + 0.7, y=phase["y"],
                ax=phase["x"] + 0.4, ay=phase["y"],
                arrowhead=2, arrowsize=1.5, arrowwidth=2, arrowcolor="#34495e",
                showarrow=True, text=""
            )
    
    # Add feedback loop arrow (from Maintain back to Plan)
    fig.add_annotation(
        x=1, y=2.2,
        ax=6, ay=2.2,
        arrowhead=2, arrowsize=1, arrowwidth=2, arrowcolor="#e67e22",
        showarrow=True, text="",
        axref="x", ayref="y"
    )
    
    # Add feedback loop label
    fig.add_annotation(
        x=3.5, y=2,
        text="<b>Continuous Feedback Loop</b>",
        showarrow=False,
        font=dict(size=10, color="#e67e22"),
        bgcolor="rgba(255,255,255,0.9)",
        bordercolor="#e67e22",
        borderwidth=1,
        borderpad=3
    )
    
    fig.update_layout(
        xaxis=dict(range=[0, 7], showgrid=False, showticklabels=False),
        yaxis=dict(range=[1.5, 4], showgrid=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=400,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # 3. Clean Content with expandable details
    with st.expander("Chi tiết về Modern SDLC"):
        st.markdown("""
        ## Modern Software Development Life Cycle
        
        **Definition:** SDLC là systematic approach to software development that ensures high-quality software delivery through structured phases và modern practices.
        
        ---
        
        ## Enhanced SDLC Phases (2024)
        
        ### **1. Plan & Analyze** 🎯
        **Traditional Focus:** Requirements gathering, project planning
        **Modern Enhancement:** Agile planning, continuous stakeholder engagement
        **Key Activities:**
        - **User Story Mapping**: Visualize user journey và prioritize features
        - **Design Thinking Workshops**: Understand user needs và pain points
        - **Technical Spike Research**: Explore new technologies và feasibility
        - **Risk Assessment**: Identify technical, business, và security risks
        
        **Modern Deliverables:**
        - **Product Roadmap**: Strategic vision với quarterly milestones
        - **User Personas**: Data-driven user profiles và behavior patterns
        - **Technical Architecture Decision Records (ADRs)**: Documented technical choices
        
        ### **2. Design & Architecture** 🏗️
        **Traditional Focus:** System design, database design
        **Modern Enhancement:** API-first design, cloud-native architecture
        **Key Activities:**
        - **Domain-Driven Design**: Model business domain accurately
        - **API-First Approach**: Design APIs before implementation
        - **Microservices Architecture**: Scalable, maintainable service design
        - **Security by Design**: Integrate security from the beginning
        
        **Modern Deliverables:**
        - **System Architecture Diagrams**: C4 model, service maps
        - **API Specifications**: OpenAPI/Swagger documentation
        - **Database Migration Scripts**: Version-controlled schema changes
        - **Security Threat Models**: STRIDE analysis, attack vectors
        
        ### **3. Develop & Code** 💻
        **Traditional Focus:** Writing code, unit testing
        **Modern Enhancement:** Clean code practices, automated quality gates
        **Key Activities:**
        - **Test-Driven Development (TDD)**: Write tests before code
        - **Pair/Mob Programming**: Collaborative coding practices
        - **Code Reviews**: Automated và human quality checks
        - **Continuous Integration**: Automated build, test, và quality checks
        
        **Modern Deliverables:**
        - **Clean, Tested Code**: High test coverage với quality metrics
        - **Automated Test Suites**: Unit, integration, và contract tests
        - **CI/CD Pipelines**: Automated build, test, và deployment workflows
        - **Code Quality Reports**: SonarQube, CodeClimate metrics
        
        ### **4. Test & Validate** 🧪
        **Traditional Focus:** Manual testing, bug reporting
        **Modern Enhancement:** Automated testing pyramid, shift-left testing
        **Key Activities:**
        - **Automated Testing Strategy**: Unit, integration, E2E test automation
        - **Performance Testing**: Load, stress, và scalability testing
        - **Security Testing**: SAST, DAST, dependency scanning
        - **Accessibility Testing**: WCAG compliance, inclusive design
        
        **Modern Deliverables:**
        - **Test Automation Framework**: Maintainable test suites
        - **Performance Benchmarks**: Response time, throughput metrics
        - **Security Scan Reports**: Vulnerability assessments
        - **Test Coverage Reports**: Code coverage và quality metrics
        
        ### **5. Deploy & Release** 🚀
        **Traditional Focus:** Production deployment, user training
        **Modern Enhancement:** DevOps practices, progressive delivery
        **Key Activities:**
        - **Infrastructure as Code**: Terraform, CloudFormation templates
        - **Blue-Green Deployments**: Zero-downtime releases
        - **Feature Flags**: Controlled feature rollouts
        - **Monitoring & Observability**: Real-time system health tracking
        
        **Modern Deliverables:**
        - **Deployment Automation**: One-click, reliable deployments
        - **Monitoring Dashboards**: Application và infrastructure metrics
        - **Incident Response Playbooks**: Structured problem resolution
        - **Release Notes**: User-facing feature documentation
        
        ### **6. Monitor & Maintain** 🔧
        **Traditional Focus:** Bug fixes, minor enhancements
        **Modern Enhancement:** Continuous improvement, data-driven decisions
        **Key Activities:**
        - **Site Reliability Engineering**: Proactive system reliability
        - **A/B Testing**: Data-driven feature validation
        - **Technical Debt Management**: Systematic code quality improvement
        - **Continuous Learning**: Post-mortems, retrospectives
        
        **Modern Deliverables:**
        - **SLI/SLO Reports**: Service level indicators và objectives
        - **User Analytics**: Feature usage và behavior insights
        - **Technical Debt Backlog**: Prioritized improvement items
        - **Learning Documentation**: Knowledge sharing, lessons learned
        """)
    
    # 4. Enhanced Cheat Sheets with highlighted keywords
    st.markdown("---")
    st.markdown("## SDLC Models & Practices Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["SDLC Models", "Modern Practices", "Quality Metrics"])
    
    with tab1:
        st.markdown("### SDLC Models Comparison")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Model** | **Approach** | **Best For** | **Advantages** | **Disadvantages** | **Modern Usage** |
        |-----------|--------------|--------------|----------------|-------------------|------------------|
        | **Waterfall** | **Sequential phases** | Well-defined requirements | **Simple**, predictable, **clear milestones** | **Inflexible**, late testing, **high risk** | **Legacy systems**, regulatory projects |
        | **Agile** | **Iterative sprints** | Changing requirements | **Flexible**, early delivery, **customer feedback** | Requires **experienced team**, less predictable | **Most common**, startup to enterprise |
        | **DevOps** | **Continuous delivery** | Fast-paced development | **Rapid deployment**, automation, **reliability** | **Complex setup**, cultural change needed | **Modern standard**, cloud-native apps |
        | **Lean** | **Value-focused** | Startups, MVPs | **Waste elimination**, fast learning, **cost-effective** | May lack **documentation**, risky for complex systems | **Startup methodology**, innovation projects |
        | **Spiral** | **Risk-driven iterations** | Large, risky projects | **Risk management**, incremental development | **Complex**, expensive, **time-consuming** | **Enterprise projects**, critical systems |
        | **V-Model** | **Testing at each phase** | Safety-critical systems | **Quality focus**, early testing, **verification** | **Rigid**, documentation heavy, **slow** | **Healthcare**, automotive, aerospace |
        """)
        
        # Model selection guide
        st.markdown("""
        #### **Model Selection Guide**
        - **New Project**: `Agile` - balanced approach với flexibility
        - **Strict Requirements**: `Waterfall` - predictable, documented process
        - **High-Risk Project**: `Spiral` - risk mitigation focus
        - **Continuous Delivery**: `DevOps` - automation và speed
        """)
    
    with tab2:
        st.markdown("### Modern SDLC Practices")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Practice** | **Phase** | **Purpose** | **Tools/Techniques** | **Benefits** | **Adoption Level** |
        |--------------|-----------|-------------|---------------------|--------------|-------------------|
        | **User Story Mapping** | **Planning** | Visualize user journey | `Miro`, `Mural`, **story maps** | **Better prioritization**, user focus | **High** |
        | **API-First Design** | **Design** | Design APIs before implementation | `OpenAPI`, `Swagger`, **design tools** | **Better integration**, clear contracts | **Growing** |
        | **Test-Driven Development** | **Development** | Write tests before code | `Jest`, `JUnit`, **testing frameworks** | **Better design**, fewer bugs | **Medium** |
        | **Continuous Integration** | **Development** | Automated build và test | `GitHub Actions`, `Jenkins`, **CI tools** | **Early bug detection**, quality | **Very High** |
        | **Infrastructure as Code** | **Deployment** | Manage infrastructure with code | `Terraform`, `CloudFormation`, **IaC tools** | **Reproducible deployments**, version control | **High** |
        | **Feature Flags** | **Deployment** | Control feature rollouts | `LaunchDarkly`, `Unleash`, **flag services** | **Safe releases**, A/B testing | **Growing** |
        | **Observability** | **Monitoring** | Monitor system health | `Datadog`, `New Relic`, **monitoring tools** | **Proactive issue detection**, insights | **High** |
        | **Chaos Engineering** | **Testing** | Test system resilience | `Chaos Monkey`, `Gremlin`, **chaos tools** | **Improved reliability**, failure preparation | **Low** |
        """)
        
        st.markdown("""
        #### **Practice Adoption Strategy**
        - **Foundation**: `version_control`, `automated_testing` - essential practices
        - **Intermediate**: `CI/CD`, `code_reviews` - quality và automation
        - **Advanced**: `chaos_engineering`, `observability` - reliability và insights
        """)
    
    with tab3:
        st.markdown("### Quality Metrics & KPIs")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Metric Category** | **Metric** | **Definition** | **Target Range** | **Measurement** | **Business Impact** |
        |-------------------|------------|----------------|------------------|-----------------|-------------------|
        | **Development Velocity** | **Story Points/Sprint** | Team delivery capacity | **20-40 points** | Sprint tracking | **Predictability**, planning accuracy |
        | **Quality** | **Code Coverage** | Percentage of code tested | **>80%** | Automated tools | **Reduced bugs**, confidence |
        | **Deployment** | **Deployment Frequency** | How often releases happen | **Daily/Weekly** | CI/CD metrics | **Faster value delivery** |
        | **Reliability** | **Mean Time to Recovery** | Time to fix production issues | **<1 hour** | Incident tracking | **User satisfaction**, uptime |
        | **Performance** | **Lead Time** | Idea to production time | **<2 weeks** | Value stream mapping | **Market responsiveness** |
        | **Security** | **Vulnerability Remediation** | Time to fix security issues | **<24 hours** | Security scanning | **Risk reduction**, compliance |
        | **User Experience** | **Customer Satisfaction** | User happiness với product | **>4.0/5.0** | Surveys, analytics | **Retention**, growth |
        | **Technical Health** | **Technical Debt Ratio** | Effort to maintain vs new features | **<20%** | Code analysis | **Development speed**, quality |
        """)
        
        st.markdown("""
        #### **Metrics Implementation Guide**
        - **Start Simple**: `deployment_frequency`, `lead_time` - basic flow metrics
        - **Add Quality**: `code_coverage`, `bug_rate` - quality indicators
        - **Monitor Business**: `user_satisfaction`, `feature_adoption` - business outcomes
        """)
    
    # 5. Interactive Demo
    st.markdown("---")
    st.markdown("## Interactive Demo")
    
    with st.expander("SDLC Project Simulator"):
        st.markdown("### Project Scenario Planning")
        
        # Project type selector
        project_type = st.selectbox(
            "Choose your project type:",
            ["E-commerce Platform", "Mobile Banking App", "Healthcare System", "Social Media Platform", "IoT Device Management"]
        )
        
        # Team size selector
        team_size = st.slider("Team Size", 2, 50, 8)
        
        # Timeline selector
        timeline = st.selectbox("Project Timeline:", ["3 months", "6 months", "12 months", "18+ months"])
        
        if st.button("Generate SDLC Recommendation"):
            st.markdown(f"### Recommended SDLC Approach for: **{project_type}**")
            
            if project_type == "E-commerce Platform":
                st.markdown("""
                **🛒 E-commerce Platform Strategy:**
                
                **Recommended Model:** `Agile với DevOps integration`
                **Reasoning:** Fast-changing market, frequent feature updates needed
                
                **Phase Breakdown:**
                - **Sprint 1-2**: MVP với core shopping features
                - **Sprint 3-4**: Payment integration và security
                - **Sprint 5-6**: Advanced features (recommendations, analytics)
                - **Ongoing**: A/B testing, performance optimization
                
                **Key Practices:**
                - **Continuous Deployment**: Multiple releases per week
                - **Feature Flags**: Safe rollout of new features
                - **Performance Monitoring**: Real-time user experience tracking
                - **Security Testing**: Regular penetration testing
                """)
                
                # Show metrics
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Recommended Sprint Length", "2 weeks")
                with col2:
                    st.metric("Expected Velocity", f"{team_size * 3} points/sprint")
                with col3:
                    st.metric("Go-Live Target", "8-12 weeks")
                    
            elif project_type == "Mobile Banking App":
                st.markdown("""
                **🏦 Mobile Banking App Strategy:**
                
                **Recommended Model:** `V-Model với Agile practices`
                **Reasoning:** High security requirements, regulatory compliance
                
                **Phase Breakdown:**
                - **Phase 1**: Security architecture và compliance framework
                - **Phase 2**: Core banking features với extensive testing
                - **Phase 3**: User experience và accessibility features
                - **Phase 4**: Advanced features (AI, analytics)
                
                **Key Practices:**
                - **Security by Design**: Threat modeling from day 1
                - **Compliance Testing**: Regular audit preparations
                - **Penetration Testing**: Monthly security assessments
                - **Accessibility**: WCAG 2.1 AA compliance
                """)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Security Reviews", "Weekly")
                with col2:
                    st.metric("Test Coverage Target", ">95%")
                with col3:
                    st.metric("Compliance Audits", "Quarterly")
                    
            elif project_type == "Healthcare System":
                st.markdown("""
                **🏥 Healthcare System Strategy:**
                
                **Recommended Model:** `Hybrid Waterfall-Agile`
                **Reasoning:** Regulatory requirements với iterative improvement
                
                **Phase Breakdown:**
                - **Waterfall Phase**: HIPAA compliance, system architecture
                - **Agile Phase**: Feature development với clinical validation
                - **Validation Phase**: Clinical testing và regulatory approval
                - **Maintenance**: Continuous monitoring và updates
                
                **Key Practices:**
                - **Regulatory Compliance**: FDA, HIPAA documentation
                - **Clinical Validation**: User acceptance testing với healthcare professionals
                - **Data Security**: End-to-end encryption, audit trails
                - **Interoperability**: HL7 FHIR standards implementation
                """)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Documentation Coverage", "100%")
                with col2:
                    st.metric("Clinical Testing Cycles", "3-4 rounds")
                with col3:
                    st.metric("Regulatory Approval", "6-12 months")
                    
            # Add general recommendations based on team size
            st.markdown("### Team Structure Recommendations:")
            if team_size <= 5:
                st.success("✅ **Small Team**: Use simple Agile practices, minimize overhead")
            elif team_size <= 15:
                st.success("✅ **Medium Team**: Implement Scrum framework với cross-functional teams")
            else:
                st.success("✅ **Large Team**: Consider SAFe or LeSS for scaling Agile practices")
    
    # 6. Key Takeaways
    st.markdown("---")
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1.5rem; border-radius: 10px; border-left: 5px solid #1f77b4;">
        <h4 style="margin-top: 0; color: #1f77b4;">Key Takeaways</h4>
        <ul>
            <li><strong>Context-Driven Selection</strong>: Choose SDLC model based on project requirements, team experience, và organizational constraints</li>
            <li><strong>Modern Practices Integration</strong>: Combine traditional SDLC phases với modern practices like DevOps, automation, và continuous feedback</li>
            <li><strong>Quality Throughout</strong>: Implement testing, security, và quality practices across all phases, not just at the end</li>
            <li><strong>Continuous Improvement</strong>: Use metrics và feedback to continuously optimize your SDLC approach</li>
            <li><strong>People & Process Balance</strong>: Technology enables SDLC success, but people và processes are equally important</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_waterfall():
    """Giải thích Waterfall Model"""
    st.markdown("### 🌊 Waterfall Model")
    
    with st.expander("📖 Lý thuyết chi tiết về Waterfall Model"):
        st.markdown("""
        ### 🎯 Waterfall Model Overview
        
        **Waterfall Model** là traditional, sequential software development approach:
        
        ### 📋 Waterfall Phases
        
        **1. Requirements Analysis**
        - **Complete Documentation**: All requirements documented upfront
        - **Stakeholder Sign-off**: Formal approval of requirements
        - **No Changes**: Requirements are frozen after approval
        - **Detailed Specifications**: Comprehensive requirement specifications
        
        **2. System Design**
        - **Architecture Design**: Overall system architecture
        - **Detailed Design**: Component-level design
        - **Database Design**: Data structure and relationships
        - **Interface Design**: User and system interfaces
        
        **3. Implementation (Coding)**
        - **Code Development**: Write code based on design
        - **Unit Development**: Individual component development
        - **Code Reviews**: Peer review of code
        - **Documentation**: Code documentation and comments
        
        **4. Integration & Testing**
        - **System Integration**: Combine all components
        - **System Testing**: Test complete system
        - **User Acceptance Testing**: Customer validation
        - **Bug Fixing**: Resolve identified issues
        
        **5. Deployment**
        - **Production Deployment**: Release to production
        - **User Training**: Train end users
        - **System Handover**: Transfer to operations team
        - **Go-Live Support**: Support during initial deployment
        
        **6. Maintenance**
        - **Bug Fixes**: Resolve post-deployment issues
        - **Enhancements**: Add new features
        - **Performance Tuning**: Optimize system performance
        - **Support**: Ongoing user support
        
        ### ✅ Waterfall Advantages
        
        **Clear Structure:**
        - **Well-defined Phases**: Clear project phases
        - **Milestone-based**: Clear milestones and deliverables
        - **Easy to Manage**: Simple project management
        - **Predictable**: Predictable timeline and budget
        
        **Documentation:**
        - **Comprehensive Documentation**: Detailed documentation at each phase
        - **Knowledge Transfer**: Easy knowledge transfer
        - **Audit Trail**: Clear audit trail
        - **Compliance**: Good for regulatory compliance
        
        **Quality Control:**
        - **Phase Gates**: Quality gates between phases
        - **Review Process**: Formal review at each phase
        - **Testing Focus**: Dedicated testing phase
        - **Defect Prevention**: Early defect prevention
        
        ### ❌ Waterfall Disadvantages
        
        **Inflexibility:**
        - **No Changes**: Difficult to accommodate changes
        - **Late Feedback**: Customer feedback only at the end
        - **Assumptions**: Based on early assumptions
        - **Risk**: High risk if requirements are wrong
        
        **Time and Cost:**
        - **Long Development**: Long development cycles
        - **Late Delivery**: No working software until the end
        - **High Cost**: Expensive to make changes
        - **Resource Intensive**: Requires significant upfront investment
        
        **Customer Involvement:**
        - **Limited Involvement**: Limited customer involvement during development
        - **Late Validation**: Customer validation only at the end
        - **Expectation Mismatch**: Risk of not meeting expectations
        - **No Early Value**: No early business value delivery
        
        ### 🎯 When to Use Waterfall
        
        **Suitable Projects:**
        - **Well-defined Requirements**: Clear, stable requirements
        - **Regulatory Projects**: Projects with strict compliance requirements
        - **Large Enterprise**: Large-scale enterprise projects
        - **Fixed Scope**: Projects with fixed scope and budget
        
        **Industry Examples:**
        - **Government Projects**: Government software projects
        - **Healthcare Systems**: Medical device software
        - **Financial Systems**: Banking and financial applications
        - **Infrastructure**: Large infrastructure projects
        
        ### 🔄 Waterfall vs Agile
        
        **Key Differences:**
        - **Approach**: Sequential vs Iterative
        - **Flexibility**: Rigid vs Flexible
        - **Customer Involvement**: Limited vs Continuous
        - **Delivery**: Big bang vs Incremental
        - **Documentation**: Heavy vs Light
        - **Risk**: High vs Distributed
        
        **Hybrid Approaches:**
        - **Water-Scrum-Fall**: Waterfall planning + Agile execution + Waterfall deployment
        - **Iterative Waterfall**: Multiple waterfall cycles
        - **Phased Delivery**: Waterfall with phased releases
        - **Agile-Waterfall**: Agile development within waterfall framework
        
        ### 📊 Waterfall Success Factors
        
        **Project Management:**
        - **Strong PM**: Experienced project manager
        - **Clear Communication**: Effective communication channels
        - **Risk Management**: Proactive risk management
        - **Quality Assurance**: Strong QA processes
        
        **Team Factors:**
        - **Experienced Team**: Experienced development team
        - **Stable Team**: Stable team composition
        - **Clear Roles**: Well-defined roles and responsibilities
        - **Training**: Adequate team training
        
        **Organizational Factors:**
        - **Management Support**: Strong management support
        - **Resource Availability**: Adequate resources
        - **Process Maturity**: Mature development processes
        - **Tool Support**: Appropriate development tools
        """)
    
    # Waterfall phases visualization
    st.markdown("#### 🌊 Waterfall Model Phases")
    
    waterfall_data = [
        {"Phase": "Requirements", "Duration": "2-3 months", "Deliverable": "Requirements Document", "Key Activities": "Analysis, Documentation"},
        {"Phase": "Design", "Duration": "2-4 months", "Deliverable": "Design Document", "Key Activities": "Architecture, UI/UX Design"},
        {"Phase": "Implementation", "Duration": "4-8 months", "Deliverable": "Source Code", "Key Activities": "Coding, Unit Testing"},
        {"Phase": "Testing", "Duration": "2-3 months", "Deliverable": "Test Reports", "Key Activities": "System Testing, UAT"},
        {"Phase": "Deployment", "Duration": "1-2 months", "Deliverable": "Live System", "Key Activities": "Release, Training"},
        {"Phase": "Maintenance", "Duration": "Ongoing", "Deliverable": "Updates", "Key Activities": "Support, Enhancements"}
    ]
    
    df = pd.DataFrame(waterfall_data)
    st.dataframe(df, width='stretch')

def explain_agile():
    """Enhanced Agile Methodology explanation using TDD pattern"""
    st.markdown("### Agile Methodology")
    
    # 1. Visual Banner (Software Development color scheme)
    st.markdown("""
    <div style="background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            Agile Methodology
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Iterative và Incremental Development Approach
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 2. Visual Diagram (Enhanced Agile cycle diagram)
    st.markdown("#### Agile Development Cycle")
    
    fig = go.Figure()
    
    # Create Agile cycle phases
    phases = [
        {"name": "Plan", "angle": 0, "color": "#e74c3c", "desc": "Sprint Planning\nUser Stories"},
        {"name": "Design", "angle": 60, "color": "#f39c12", "desc": "Architecture\nUI/UX Design"},
        {"name": "Develop", "angle": 120, "color": "#f1c40f", "desc": "Coding\nPair Programming"},
        {"name": "Test", "angle": 180, "color": "#2ecc71", "desc": "Unit Tests\nIntegration Tests"},
        {"name": "Deploy", "angle": 240, "color": "#3498db", "desc": "CI/CD\nProduction Release"},
        {"name": "Review", "angle": 300, "color": "#9b59b6", "desc": "Retrospective\nFeedback"}
    ]
    
    # Create circular layout
    center_x, center_y = 0.5, 0.5
    radius = 0.3
    
    for i, phase in enumerate(phases):
        # Calculate position
        angle_rad = math.radians(phase["angle"])
        x = center_x + radius * math.cos(angle_rad)
        y = center_y + radius * math.sin(angle_rad)
        
        # Add phase circle
        fig.add_shape(
            type="circle",
            x0=x-0.08, y0=y-0.08, x1=x+0.08, y1=y+0.08,
            fillcolor=phase["color"],
            opacity=0.8,
            line=dict(color="white", width=2)
        )
        
        # Add phase label
        fig.add_annotation(
            x=x, y=y,
            text=f"<b>{phase['name']}</b>",
            showarrow=False,
            font=dict(size=11, color="white"),
        )
        
        # Add description outside circle
        desc_radius = radius + 0.15
        desc_x = center_x + desc_radius * math.cos(angle_rad)
        desc_y = center_y + desc_radius * math.sin(angle_rad)
        
        fig.add_annotation(
            x=desc_x, y=desc_y,
            text=phase["desc"],
            showarrow=False,
            font=dict(size=9, color="#2c3e50"),
            bgcolor="rgba(255,255,255,0.8)",
            bordercolor=phase["color"],
            borderwidth=1,
            borderpad=3
        )
        
        # Add arrows between phases
        next_phase = phases[(i + 1) % len(phases)]
        next_angle_rad = math.radians(next_phase["angle"])
        next_x = center_x + radius * math.cos(next_angle_rad)
        next_y = center_y + radius * math.sin(next_angle_rad)
        
        # Calculate arrow position (slightly inside the circles)
        arrow_start_x = x + 0.06 * math.cos(next_angle_rad - angle_rad)
        arrow_start_y = y + 0.06 * math.sin(next_angle_rad - angle_rad)
        arrow_end_x = next_x - 0.06 * math.cos(next_angle_rad - angle_rad)
        arrow_end_y = next_y - 0.06 * math.sin(next_angle_rad - angle_rad)
        
        fig.add_annotation(
            x=arrow_end_x, y=arrow_end_y,
            ax=arrow_start_x, ay=arrow_start_y,
            arrowhead=2, arrowsize=1, arrowwidth=2, arrowcolor="#34495e",
            showarrow=True, text=""
        )
    
    # Add center text
    fig.add_annotation(
        x=center_x, y=center_y,
        text="<b>Agile<br>Sprint<br>Cycle</b>",
        showarrow=False,
        font=dict(size=12, color="#2c3e50"),
        bgcolor="rgba(255,255,255,0.9)",
        bordercolor="#34495e",
        borderwidth=2,
        borderpad=5
    )
    
    fig.update_layout(
        xaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=450,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # 3. Clean Content with expandable details
    with st.expander("Chi tiết về Agile Methodology"):
        st.markdown("""
        ## Agile Methodology Fundamentals
        
        **Definition:** Agile là iterative approach to software development và project management giúp teams deliver value to customers faster với fewer headaches.
        
        ---
        
        ## Agile Manifesto & Values
        
        ### **Core Values (2001 Agile Manifesto)**
        **Purpose:** Prioritize what matters most in software development
        **Implementation:** Value-based decision making, team empowerment
        **Benefits:** Faster delivery, better quality, customer satisfaction
        
        ### **1. Individuals and Interactions** over processes và tools
        **Focus:** People-first approach, team collaboration, communication
        **Modern Application:** Remote work tools, async communication, team building
        **Benefits:** Higher engagement, better problem solving, knowledge sharing
        
        ### **2. Working Software** over comprehensive documentation  
        **Focus:** Functional deliverables, user value, rapid feedback
        **Modern Application:** MVP approach, continuous deployment, user testing
        **Benefits:** Faster time-to-market, real user feedback, reduced waste
        
        ### **3. Customer Collaboration** over contract negotiation
        **Focus:** Partnership mindset, shared goals, continuous alignment
        **Modern Application:** Product ownership, user research, stakeholder engagement
        **Benefits:** Better product-market fit, reduced rework, customer satisfaction
        
        ### **4. Responding to Change** over following a plan
        **Focus:** Adaptability, learning, continuous improvement
        **Modern Application:** Data-driven decisions, A/B testing, pivot strategies
        **Benefits:** Competitive advantage, risk mitigation, innovation
        
        ---
        
        ## Modern Agile Principles (Updated for 2024)
        
        **Customer-Centricity:**
        - **Continuous Value Delivery:** Deploy features weekly or daily
        - **User Feedback Integration:** Real-time analytics, user interviews
        - **Adaptive Requirements:** Embrace changing market conditions
        
        **Team Excellence:**
        - **Cross-functional Teams:** Full-stack capabilities, shared ownership
        - **Psychological Safety:** Open communication, learning from failures
        - **Sustainable Pace:** Work-life balance, preventing burnout
        
        **Technical Excellence:**
        - **DevOps Integration:** CI/CD pipelines, infrastructure as code
        - **Quality Automation:** Automated testing, code quality gates
        - **Continuous Learning:** Tech debt management, skill development
        
        **Business Alignment:**
        - **Outcome-focused Metrics:** Business value over activity metrics
        - **Stakeholder Engagement:** Regular demos, feedback sessions
        - **Market Responsiveness:** Rapid experimentation, data-driven pivots
        """)
    
    # 4. Enhanced Cheat Sheets with highlighted keywords
    st.markdown("---")
    st.markdown("## Agile Methodology Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["Agile Frameworks", "Modern Practices", "Tools & Metrics"])
    
    with tab1:
        st.markdown("### Agile Frameworks Comparison")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Framework** | **Structure** | **Roles** | **Ceremonies** | **Best For** | **Team Size** |
        |---------------|---------------|-----------|----------------|---------------|---------------|
        | **Scrum** | **Fixed sprints** (1-4 weeks) | **Product Owner**, Scrum Master, **Dev Team** | Daily standup, **sprint planning**, review, **retrospective** | **Product development**, complex projects | **5-9 members** |
        | **Kanban** | **Continuous flow** với WIP limits | **Team members** (no fixed roles) | **Daily standup** (optional), review meetings | **Maintenance**, support, **continuous delivery** | **Flexible** team size |
        | **SAFe** | **Scaled framework** với multiple teams | **Release Train Engineer**, Product Manager | **PI Planning**, scrum of scrums, **system demo** | **Large enterprises**, **multiple teams** | **50-125 members** |
        | **LeSS** | **Large-Scale Scrum** với minimal scaling | **Product Owner**, Scrum Masters, **Teams** | Cross-team coordination, **overall retrospective** | **Product companies**, **2-8 teams** | **10-50 members** |
        | **Scrumban** | **Hybrid** Scrum + Kanban | **Flexible** role assignment | **Planning** on demand, **continuous improvement** | **Transitioning teams**, **mixed workload** | **Variable** size |
        | **XP (Extreme Programming)** | **Engineering-focused** với short releases | **Customer**, Coach, **Programmers** | **Planning game**, small releases, **pair programming** | **Software development**, **high-quality code** | **2-12 members** |
        """)
        
        # Additional highlighted information
        st.markdown("""
        #### **Framework Selection Guide**
        - **New to Agile**: `Scrum` - structured approach với clear guidelines
        - **Continuous Work**: `Kanban` - flexible flow-based management  
        - **Large Organization**: `SAFe` - enterprise-scale coordination
        """)
    
    with tab2:
        st.markdown("### Modern Agile Practices")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Practice** | **Purpose** | **Implementation** | **Benefits** | **Difficulty** | **ROI** |
        |--------------|-------------|-------------------|--------------|----------------|---------|
        | **Continuous Integration** | **Integrate** code frequently | `GitHub Actions`, `Jenkins`, **automated testing** | **Early bug detection**, reduced integration issues | **Medium** | **High** |
        | **Test-Driven Development** | **Write tests** before code | `unit_tests`, `integration_tests`, **red-green-refactor** | **Better design**, fewer bugs, **confidence** | **High** | **Very High** |
        | **Pair Programming** | **Two developers**, one workstation | **Driver-navigator** roles, knowledge sharing | **Code quality**, **knowledge transfer** | **Medium** | **Medium** |
        | **DevOps Integration** | **Development** + **Operations** alignment | `CI/CD_pipelines`, infrastructure as code | **Faster deployment**, reduced errors | **High** | **Very High** |
        | **User Story Mapping** | **Visualize** user journey | **Story maps**, user personas, **journey mapping** | **Better prioritization**, user focus | **Low** | **High** |
        | **Mob Programming** | **Entire team** codes together | **Shared screen**, collective problem solving | **Knowledge sharing**, **quality** | **Medium** | **Medium** |
        """)
        
        st.markdown("""
        #### **Practice Adoption Strategy**
        - **Start Simple**: `daily_standups`, `retrospectives` - low risk, immediate value
        - **Build Foundation**: `automated_testing`, `version_control` - essential practices
        - **Scale Up**: `CI/CD`, `TDD` - higher impact, requires investment
        """)
    
    with tab3:
        st.markdown("### Tools & Metrics")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Category** | **Tool/Metric** | **Purpose** | **Key Features** | **Best For** | **Cost** |
        |--------------|-----------------|-------------|------------------|---------------|----------|
        | **Project Management** | **Jira** | **Issue tracking**, sprint planning | Backlog management, **reporting**, integrations | **Large teams**, complex projects | **Paid** |
        | **Project Management** | **Linear** | **Modern** issue tracking | **Clean UI**, keyboard shortcuts, **automation** | **Startups**, design-focused teams | **Paid** |
        | **Collaboration** | **Slack/Teams** | **Team communication** | Channels, **integrations**, video calls | **Remote teams**, async communication | **Freemium** |
        | **Code Quality** | **SonarQube** | **Code analysis** | Quality gates, **security scanning**, tech debt | **Enterprise**, quality-focused teams | **Freemium** |
        | **Velocity Tracking** | **Story Points** | **Team capacity** estimation | Fibonacci sequence, **planning poker** | **Sprint planning**, capacity planning | **Free** |
        | **Lead Time** | **Cycle Time** | **Delivery speed** measurement | Time from start to **deployment** | **Process improvement**, bottleneck analysis | **Free** |
        """)
        
        st.markdown("""
        #### **Key Agile Metrics (2024)**
        - **Velocity**: `story_points_per_sprint` - team capacity và predictability
        - **Lead Time**: `idea_to_production` - overall delivery efficiency
        - **Deployment Frequency**: `releases_per_day/week` - delivery cadence
        - **MTTR**: `mean_time_to_recovery` - system resilience
        """)
    
    # 5. Interactive Demo
    st.markdown("---")
    st.markdown("## Interactive Demo")
    
    with st.expander("Agile Transformation Scenarios"):
        st.markdown("### Choose Your Agile Journey")
        
        # Simple interactive element
        scenario = st.selectbox(
            "Select your organization scenario:", 
            ["Startup (2-10 people)", "Growing Company (50-200 people)", "Enterprise (500+ people)", "Remote-First Team", "Legacy System Modernization"]
        )
        
        if scenario == "Startup (2-10 people)":
            st.markdown("**🚀 Startup Agile Approach:**")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Recommended Framework:**")
                st.markdown("- **Kanban** for flexibility")
                st.markdown("- **Minimal ceremonies** (daily standup)")
                st.markdown("- **Continuous deployment**")
                st.markdown("- **Direct customer feedback**")
                
            with col2:
                st.markdown("**Key Practices:**")
                st.markdown("- **MVP-driven development**")
                st.markdown("- **Rapid prototyping**")
                st.markdown("- **A/B testing**")
                st.markdown("- **Lean startup principles**")
                
            st.success("✅ **Startups** need **maximum flexibility** với **minimal overhead**!")
            
        elif scenario == "Growing Company (50-200 people)":
            st.markdown("**📈 Growing Company Strategy:**")
            
            growth_practices = [
                "**Scrum Framework**: Structure for multiple teams",
                "**Cross-functional Teams**: Reduce dependencies",
                "**Scaled Agile**: SAFe or LeSS for coordination", 
                "**DevOps Culture**: Automation và continuous delivery",
                "**Agile Coaching**: Internal capability building",
                "**Metrics Dashboard**: Data-driven improvements"
            ]
            
            for practice in growth_practices:
                st.markdown(f"- {practice}")
                
            st.markdown("**Implementation Timeline:**")
            st.markdown("- **Month 1-3**: Team formation và Scrum basics")
            st.markdown("- **Month 4-6**: DevOps và automation setup")
            st.markdown("- **Month 7-12**: Scaling và optimization")
            
            st.success("✅ **Growing companies** need **structured scaling** với **cultural transformation**!")
            
        elif scenario == "Enterprise (500+ people)":
            st.markdown("**🏢 Enterprise Agile Transformation:**")
            
            st.code("""
# Enterprise Agile Transformation Roadmap

Phase 1: Foundation (6 months)
  - Executive alignment và sponsorship
  - Agile Center of Excellence (CoE)
  - Pilot teams và quick wins
  - Training và certification programs

Phase 2: Scaling (12 months)  
  - SAFe or LeSS implementation
  - Agile Release Trains (ARTs)
  - Portfolio-level planning
  - Enterprise DevOps platform

Phase 3: Optimization (18+ months)
  - Continuous improvement culture
  - Advanced metrics và analytics
  - Customer-centricity transformation
  - Innovation và experimentation
            """, language="yaml")
            
            st.markdown("**Success Factors:**")
            st.markdown("- **Leadership commitment**: C-level sponsorship")
            st.markdown("- **Cultural change**: Mindset over process")
            st.markdown("- **Gradual rollout**: Avoid big-bang transformations")
            
            st.success("✅ **Enterprise** transformation requires **long-term commitment** và **cultural change**!")
            
        elif scenario == "Remote-First Team":
            st.markdown("**🌍 Remote-First Agile:**")
            
            remote_adaptations = {
                "**Communication**": "Async-first, documented decisions, over-communication",
                "**Ceremonies**": "Time-zone friendly, recorded sessions, shorter meetings",
                "**Collaboration**": "Digital whiteboarding, shared documents, virtual pairing",
                "**Culture**": "Trust-based, outcome-focused, flexible hours",
                "**Tools**": "Integrated toolchain, automation, self-service"
            }
            
            for aspect, description in remote_adaptations.items():
                st.markdown(f"**{aspect.strip('*')}**: {description}")
                
            st.markdown("**Remote Agile Tools Stack:**")
            st.markdown("- **Miro/Mural**: Virtual collaboration boards")
            st.markdown("- **Slack/Teams**: Async communication")
            st.markdown("- **Zoom/Meet**: Face-to-face connection")
            st.markdown("- **Notion/Confluence**: Knowledge management")
            
            st.success("✅ **Remote teams** need **intentional communication** và **trust-building**!")
            
        elif scenario == "Legacy System Modernization":
            st.markdown("**⚡ Legacy Modernization Agile:**")
            
            st.markdown("**Modernization Strategy:**")
            st.markdown("- **Strangler Fig Pattern**: Gradually replace legacy components")
            st.markdown("- **API-First Approach**: Decouple systems với APIs")
            st.markdown("- **Microservices Migration**: Break monolith incrementally")
            st.markdown("- **Cloud-Native Transition**: Containerization và orchestration")
            
            st.markdown("**Agile Adaptations:**")
            st.markdown("- **Technical Debt Sprints**: Dedicated refactoring time")
            st.markdown("- **Risk-Based Planning**: High-risk components first")
            st.markdown("- **Parallel Development**: New features + modernization")
            st.markdown("- **Continuous Testing**: Regression prevention")
            
            st.success("✅ **Legacy modernization** requires **careful planning** và **risk management**!")
    
    # 6. Key Takeaways
    st.markdown("---")
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1.5rem; border-radius: 10px; border-left: 5px solid #1f77b4;">
        <h4 style="margin-top: 0; color: #1f77b4;">Key Takeaways</h4>
        <ul>
            <li><strong>People Over Process</strong>: Agile success depends more on team culture và collaboration than strict adherence to frameworks</li>
            <li><strong>Context Matters</strong>: Choose Agile practices based on team size, organization maturity, và project requirements</li>
            <li><strong>Continuous Improvement</strong>: Regular retrospectives và adaptation are essential for long-term Agile success</li>
            <li><strong>Customer-Centricity</strong>: Frequent delivery và feedback loops ensure product-market fit và user satisfaction</li>
            <li><strong>Modern Integration</strong>: Combine Agile với DevOps, cloud technologies, và data-driven decision making for maximum impact</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def explain_scrum():
    """Enhanced Scrum Framework explanation using TDD pattern"""
    st.markdown("### Scrum Framework")
    
    # 1. Visual Banner (Software Development color scheme)
    st.markdown("""
    <div style="background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
        <h2 style="color: white; text-align: center; margin: 0;">
            Scrum Framework
        </h2>
        <p style="color: white; text-align: center; margin: 0.5rem 0 0 0; opacity: 0.9; font-size: 1.1rem;">
            Empirical Framework for Complex Product Development
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 2. Visual Diagram (Enhanced Scrum process flow)
    st.markdown("#### Scrum Process Flow")
    
    fig = go.Figure()
    
    # Create Scrum process elements
    elements = [
        {"name": "Product\nBacklog", "x": 1, "y": 3, "color": "#e74c3c", "type": "artifact"},
        {"name": "Sprint\nPlanning", "x": 3, "y": 4, "color": "#f39c12", "type": "event"},
        {"name": "Sprint\nBacklog", "x": 5, "y": 4, "color": "#e74c3c", "type": "artifact"},
        {"name": "Sprint\n(2-4 weeks)", "x": 7, "y": 3, "color": "#3498db", "type": "container"},
        {"name": "Daily\nScrum", "x": 7, "y": 4.5, "color": "#f39c12", "type": "event"},
        {"name": "Sprint\nReview", "x": 9, "y": 4, "color": "#f39c12", "type": "event"},
        {"name": "Sprint\nRetrospective", "x": 9, "y": 2, "color": "#f39c12", "type": "event"},
        {"name": "Product\nIncrement", "x": 11, "y": 3, "color": "#2ecc71", "type": "artifact"}
    ]
    
    # Add process elements
    for element in elements:
        if element["type"] == "container":
            # Sprint container (larger)
            fig.add_shape(
                type="rect",
                x0=element["x"]-0.8, y0=element["y"]-0.6, x1=element["x"]+0.8, y1=element["y"]+0.6,
                fillcolor=element["color"],
                opacity=0.7,
                line=dict(color="white", width=2)
            )
        else:
            # Regular elements
            fig.add_shape(
                type="rect",
                x0=element["x"]-0.6, y0=element["y"]-0.4, x1=element["x"]+0.6, y1=element["y"]+0.4,
                fillcolor=element["color"],
                opacity=0.8,
                line=dict(color="white", width=2)
            )
        
        # Element name
        fig.add_annotation(
            x=element["x"], y=element["y"],
            text=f"<b>{element['name']}</b>",
            showarrow=False,
            font=dict(size=9, color="white")
        )
    
    # Add process flow arrows
    flow_arrows = [
        {"from": (1, 3), "to": (3, 4)},     # Product Backlog → Sprint Planning
        {"from": (3, 4), "to": (5, 4)},     # Sprint Planning → Sprint Backlog
        {"from": (5, 4), "to": (7, 3)},     # Sprint Backlog → Sprint
        {"from": (7, 3), "to": (9, 4)},     # Sprint → Sprint Review
        {"from": (7, 3), "to": (9, 2)},     # Sprint → Sprint Retrospective
        {"from": (9, 4), "to": (11, 3)},    # Sprint Review → Product Increment
        {"from": (9, 2), "to": (1, 3)}      # Sprint Retrospective → Product Backlog (feedback loop)
    ]
    
    for arrow in flow_arrows:
        if arrow["from"] == (9, 2) and arrow["to"] == (1, 3):
            # Feedback loop arrow (curved)
            fig.add_annotation(
                x=arrow["to"][0], y=arrow["to"][1]-0.5,
                ax=arrow["from"][0], ay=arrow["from"][1],
                arrowhead=2, arrowsize=1.5, arrowwidth=2, arrowcolor="#95a5a6",
                showarrow=True, text=""
            )
        else:
            # Regular arrows
            fig.add_annotation(
                x=arrow["to"][0]-0.6, y=arrow["to"][1],
                ax=arrow["from"][0]+0.6, ay=arrow["from"][1],
                arrowhead=2, arrowsize=1.5, arrowwidth=2, arrowcolor="#34495e",
                showarrow=True, text=""
            )
    
    # Add Scrum roles
    roles = [
        {"name": "Product Owner", "x": 1, "y": 1.5, "color": "#9b59b6"},
        {"name": "Scrum Master", "x": 6, "y": 1.5, "color": "#e67e22"},
        {"name": "Development Team", "x": 11, "y": 1.5, "color": "#1abc9c"}
    ]
    
    for role in roles:
        fig.add_shape(
            type="circle",
            x0=role["x"]-0.5, y0=role["y"]-0.3, x1=role["x"]+0.5, y1=role["y"]+0.3,
            fillcolor=role["color"],
            opacity=0.8,
            line=dict(color="white", width=2)
        )
        
        fig.add_annotation(
            x=role["x"], y=role["y"],
            text=f"<b>{role['name']}</b>",
            showarrow=False,
            font=dict(size=8, color="white")
        )
    
    # Add legend
    fig.add_annotation(
        x=6, y=5.5,
        text="<b>Scrum Framework Components</b>",
        showarrow=False,
        font=dict(size=12, color="#2c3e50"),
        bgcolor="rgba(255,255,255,0.9)",
        bordercolor="#34495e",
        borderwidth=2,
        borderpad=5
    )
    
    fig.update_layout(
        xaxis=dict(range=[0, 12], showgrid=False, showticklabels=False),
        yaxis=dict(range=[0.5, 6], showgrid=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=450,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # 3. Clean Content with expandable details
    with st.expander("Chi tiết về Modern Scrum Framework"):
        st.markdown("""
        ## Modern Scrum Framework (2024)
        
        **Definition:** Scrum là lightweight, empirical framework designed to help teams deliver value through adaptive solutions for complex problems.
        
        ---
        
        ## Scrum Theory & Pillars
        
        ### **Empiricism Foundation**
        **Transparency:** All aspects of process visible to those responsible for outcome
        **Inspection:** Frequent inspection of artifacts và progress toward goals
        **Adaptation:** Adjust based on inspection results to minimize deviation
        
        ### **Scrum Values (Foundation for Success)**
        **Commitment:** Dedicated to achieving team goals và supporting each other
        **Courage:** Have courage to do right thing và work on tough problems  
        **Focus:** Concentrate on sprint work và goals of Scrum Team
        **Openness:** Open about work và challenges faced
        **Respect:** Respect each other as capable, independent people
        
        ---
        
        ## Scrum Roles (Accountabilities)
        
        ### **Product Owner** - Value Maximization
        **Primary Accountability:** Maximizing value of product resulting from work of Scrum Team
        
        **Key Responsibilities:**
        - **Product Vision:** Develop và communicate product vision và strategy
        - **Product Backlog Management:** Create, prioritize, và refine product backlog items
        - **Stakeholder Engagement:** Collaborate với stakeholders to understand needs
        - **Requirements Definition:** Define user stories với clear acceptance criteria
        - **Value Optimization:** Make decisions to maximize product value và ROI
        - **Release Planning:** Plan product releases và coordinate với stakeholders
        
        **Modern Skills Required:**
        - **Business Acumen:** Understanding of market, customers, và business strategy
        - **Data Analysis:** Use metrics và analytics to make informed decisions
        - **User Experience:** Focus on user needs và experience design
        - **Technical Understanding:** Basic understanding of technical constraints
        
        ### **Scrum Master** - Process Effectiveness
        **Primary Accountability:** Establishing Scrum as defined in Scrum Guide
        
        **Key Responsibilities:**
        - **Team Coaching:** Coach team on Scrum theory, practices, và rules
        - **Impediment Removal:** Help remove impediments to team's progress
        - **Facilitation:** Facilitate Scrum events as requested or needed
        - **Organizational Change:** Lead, train, và coach organization in Scrum adoption
        - **Continuous Improvement:** Help team improve processes và practices
        - **Protection:** Shield team from external interruptions và distractions
        
        **Modern Skills Required:**
        - **Servant Leadership:** Lead by serving the team và organization
        - **Coaching:** Professional coaching skills for individuals và teams
        - **Facilitation:** Expert facilitation of meetings và workshops
        - **Change Management:** Guide organizational transformation
        - **Metrics & Analytics:** Use data to drive improvement decisions
        
        ### **Developers (Development Team)** - Product Creation
        **Primary Accountability:** Creating usable increment each Sprint
        
        **Key Responsibilities:**
        - **Sprint Planning:** Participate in sprint planning và commit to sprint goal
        - **Daily Coordination:** Coordinate work through daily scrum
        - **Quality Assurance:** Ensure product meets definition of done
        - **Continuous Integration:** Integrate work frequently
        - **Technical Excellence:** Maintain high technical standards
        - **Collaboration:** Work collaboratively với all team members
        
        **Modern Skills Required:**
        - **Cross-functional Skills:** Multiple technical disciplines
        - **DevOps Practices:** CI/CD, automated testing, monitoring
        - **Quality Engineering:** Test automation, quality assurance
        - **User Focus:** Understanding of user needs và experience
        - **Continuous Learning:** Adapt to new technologies và practices
        
        ---
        
        ## Scrum Artifacts & Commitments
        
        ### **Product Backlog** - Ordered List of Features
        **Purpose:** Single source of requirements for any changes to be made to product
        **Commitment:** Product Goal - describes future state of product
        
        **Modern Characteristics:**
        - **User-Centric:** Written from user perspective với clear value
        - **INVEST Criteria:** Independent, Negotiable, Valuable, Estimable, Small, Testable
        - **Acceptance Criteria:** Clear definition of what constitutes completion
        - **Priority-Driven:** Ordered by value, risk, và dependencies
        - **Emergent:** Continuously refined as more is learned
        
        ### **Sprint Backlog** - Sprint Plan
        **Purpose:** Highly visible, real-time picture of work Developers plan to accomplish
        **Commitment:** Sprint Goal - single objective for Sprint
        
        **Modern Components:**
        - **Sprint Goal:** Coherent objective that provides focus
        - **Selected Product Backlog Items:** Items chosen for Sprint
        - **Action Plan:** How to deliver increment và achieve Sprint Goal
        - **Daily Updates:** Updated daily as work progresses
        
        ### **Increment** - Working Product
        **Purpose:** Concrete stepping stone toward Product Goal
        **Commitment:** Definition of Done - shared understanding of work completion
        
        **Modern Standards:**
        - **Potentially Releasable:** Meets quality standards for release
        - **Integrated:** All components work together seamlessly
        - **Tested:** Comprehensive testing at all levels
        - **Documented:** Necessary documentation for users và maintainers
        - **Secure:** Meets security requirements và standards
        
        ---
        
        ## Scrum Events (Time-boxed Ceremonies)
        
        ### **Sprint** - Container Event (1-4 weeks)
        **Purpose:** Create consistent rhythm for work và provide container for other events
        **Duration:** Fixed length, typically 2 weeks for most teams
        **Goal:** Create valuable, usable increment of product
        
        ### **Sprint Planning** - Plan Sprint Work (8 hours max for 4-week Sprint)
        **Purpose:** Define work to be performed in Sprint
        **Participants:** Entire Scrum Team
        **Outcome:** Sprint Goal, Sprint Backlog, action plan
        
        **Modern Practices:**
        - **Capacity Planning:** Consider team capacity và availability
        - **Definition of Ready:** Ensure stories are ready for development
        - **Risk Assessment:** Identify và plan for potential risks
        - **Technical Planning:** Discuss technical approach và architecture
        
        ### **Daily Scrum** - Synchronize & Plan (15 minutes)
        **Purpose:** Inspect progress toward Sprint Goal và adapt Sprint Backlog
        **Participants:** Developers (others may observe)
        **Focus:** What will we do today to achieve Sprint Goal?
        
        **Modern Approaches:**
        - **Goal-Focused:** Focus on Sprint Goal rather than individual tasks
        - **Impediment Identification:** Quickly identify và escalate blockers
        - **Collaboration Planning:** Plan collaboration for the day
        - **Asynchronous Options:** Support remote và distributed teams
        
        ### **Sprint Review** - Inspect Increment (4 hours max for 4-week Sprint)
        **Purpose:** Inspect outcome of Sprint và determine future adaptations
        **Participants:** Scrum Team + Stakeholders
        **Outcome:** Revised Product Backlog, feedback incorporation
        
        **Modern Practices:**
        - **Demo-Driven:** Focus on working software demonstration
        - **Stakeholder Engagement:** Active participation from key stakeholders
        - **Metrics Review:** Review key performance indicators
        - **Market Feedback:** Incorporate user feedback và market insights
        
        ### **Sprint Retrospective** - Inspect Process (3 hours max for 4-week Sprint)
        **Purpose:** Plan ways to increase quality và effectiveness
        **Participants:** Scrum Team only
        **Outcome:** Action items for improvement in next Sprint
        
        **Modern Techniques:**
        - **Data-Driven:** Use metrics to guide improvement discussions
        - **Psychological Safety:** Create safe environment for honest feedback
        - **Continuous Improvement:** Focus on small, incremental improvements
        - **Team Health:** Address team dynamics và well-being
        """)
    
    # 4. Enhanced Cheat Sheets with highlighted keywords
    st.markdown("---")
    st.markdown("## Scrum Framework Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["Roles & Events", "Artifacts & Metrics", "Interactive Demo"])
    
    with tab1:
        st.markdown("### Scrum Roles & Events Quick Reference")
        
        # Enhanced table with proper markdown rendering
        st.markdown("""
        | **Role/Event** | **Duration** | **Key Responsibility** | **Success Metrics** | **Modern Focus** |
        |----------------|--------------|----------------------|-------------------|------------------|
        | **Product Owner** | **Full-time** | **Value maximization** | **ROI**, **User satisfaction** | **Data-driven decisions** |
        | **Scrum Master** | **Full-time** | **Process effectiveness** | **Team velocity**, **Impediment resolution** | **Servant leadership** |
        | **Developers** | **Full-time** | **Product creation** | **Quality**, **Sprint goal achievement** | **Cross-functional skills** |
        | **Sprint Planning** | **8h max** | **Sprint commitment** | **Sprint goal clarity** | **Capacity planning** |
        | **Daily Scrum** | **15 min** | **Daily synchronization** | **Impediment identification** | **Goal-focused discussion** |
        | **Sprint Review** | **4h max** | **Stakeholder feedback** | **Stakeholder engagement** | **Demo-driven approach** |
        | **Sprint Retrospective** | **3h max** | **Process improvement** | **Action item completion** | **Psychological safety** |
        """)
    
    with tab2:
        st.markdown("### Scrum Artifacts & Modern Metrics")
        
        st.markdown("""
        | **Artifact** | **Purpose** | **Modern Enhancement** | **Key Metrics** | **Best Practices** |
        |--------------|-------------|----------------------|----------------|-------------------|
        | **Product Backlog** | **Requirements repository** | **User story mapping** | **Backlog health**, **Value flow** | **INVEST criteria** |
        | **Sprint Backlog** | **Sprint plan** | **Real-time updates** | **Sprint burndown** | **Sprint goal focus** |
        | **Increment** | **Working product** | **Continuous delivery** | **Quality metrics** | **Definition of Done** |
        """)
    
    with tab3:
        st.markdown("### 🎯 Interactive Scrum Scenario Planner")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Team Configuration")
            team_size = st.selectbox("Development Team Size:", [3, 4, 5, 6, 7, 8, 9])
            sprint_length = st.selectbox("Sprint Length:", ["1 week", "2 weeks", "3 weeks", "4 weeks"])
            experience_level = st.selectbox("Team Experience:", ["Beginner", "Intermediate", "Advanced"])
            project_type = st.selectbox("Project Type:", ["New Product", "Feature Enhancement", "Bug Fixes", "Technical Debt"])
        
        with col2:
            st.markdown("#### Context Factors")
            remote_work = st.selectbox("Work Mode:", ["Co-located", "Hybrid", "Fully Remote"])
            stakeholder_availability = st.selectbox("Stakeholder Availability:", ["High", "Medium", "Low"])
            technical_complexity = st.selectbox("Technical Complexity:", ["Low", "Medium", "High"])
            market_pressure = st.selectbox("Market Pressure:", ["Low", "Medium", "High"])
        
        if st.button("🚀 Generate Scrum Recommendations"):
            st.success("✅ **Scrum Configuration Recommendations Generated!**")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("#### Recommended Practices")
                if experience_level == "Beginner":
                    st.info("🎓 **Focus on Scrum fundamentals**, daily coaching, detailed retrospectives")
                elif experience_level == "Advanced":
                    st.info("🚀 **Advanced practices**: Continuous delivery, advanced metrics, self-organization")
                else:
                    st.info("📈 **Balanced approach**: Standard practices with gradual improvements")
            
            with col2:
                st.markdown("#### Expected Outcomes")
                base_velocity = team_size * 8
                st.metric("Estimated Sprint Velocity", f"{base_velocity:.0f} story points")
    
    # 5. Key Takeaways
    st.markdown("---")
    st.markdown("## 🎯 Key Takeaways")
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 1.5rem; border-radius: 10px; margin: 1rem 0;">
        <h3 style="color: white; margin-top: 0;">Essential Scrum Insights</h3>
        <ul style="color: white; margin-bottom: 0;">
            <li><strong>Empirical Process</strong>: Scrum is based on transparency, inspection, và adaptation - not rigid processes</li>
            <li><strong>Value Focus</strong>: Success is measured by business value delivered, not just features completed</li>
            <li><strong>Team Empowerment</strong>: Self-organizing teams make better decisions than hierarchical management</li>
            <li><strong>Continuous Improvement</strong>: Regular retrospectives drive sustainable performance improvements</li>
            <li><strong>Modern Integration</strong>: Combine Scrum với DevOps, Design Thinking, và Lean principles for maximum effectiveness</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def programming_concepts_lab():
    """Lab về programming concepts"""
    st.subheader("💾 Programming Concepts")
    
    concept_choice = st.selectbox("Chọn concept:", [
        "Programming Paradigms",
        "Object-Oriented Programming",
        "Functional Programming",
        "Code Quality & Best Practices",
        "Design Patterns"
    ])
    
    if concept_choice == "Programming Paradigms":
        explain_programming_paradigms()
    elif concept_choice == "Object-Oriented Programming":
        explain_oop()
    elif concept_choice == "Functional Programming":
        explain_functional_programming()
    elif concept_choice == "Code Quality & Best Practices":
        explain_code_quality_best_practices()
    elif concept_choice == "Design Patterns":
        explain_design_patterns()
