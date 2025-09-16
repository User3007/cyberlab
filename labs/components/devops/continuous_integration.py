"""
Continuous Integration Component
DevOps CI/CD fundamentals and best practices
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from typing import Dict, List, Any

from ...shared.color_schemes import SOFTWARE_DEVELOPMENT_COLORS
from ...shared.ui_components import create_banner, create_info_card, create_cheat_sheet_tabs
from ...templates.component_template import ComponentTemplate


class ContinuousIntegrationComponent(ComponentTemplate):
    """Continuous Integration component with modern CI/CD practices"""
    
    def __init__(self):
        super().__init__(
            component_name=" Continuous Integration",
            description="Modern CI/CD practices for automated software delivery",
            color_scheme=SOFTWARE_DEVELOPMENT_COLORS,
            estimated_time="25 minutes"
        )
        
        self.set_key_concepts([
            "Automated Building", "Automated Testing", "Version Control", "Deployment Pipeline"
        ])
    
    def render_content(self):
        """Render Continuous Integration content"""
        
        # CI/CD overview
        self._render_cicd_overview()
        
        # CI pipeline stages
        self._render_pipeline_stages()
        
        # Tools and platforms
        self._render_tools_platforms()
        
        # Best practices
        self._render_best_practices()
    
    def _render_cicd_overview(self):
        """Render CI/CD overview"""
        st.subheader(" CI/CD Overview")
        
        # CI vs CD comparison
        cicd_comparison = [
            {"Aspect": "Focus", "Continuous Integration": "Code integration & testing", "Continuous Deployment": "Automated release to production"},
            {"Aspect": "Frequency", "Continuous Integration": "Multiple times per day", "Continuous Deployment": "Every successful build"},
            {"Aspect": "Main Goal", "Continuous Integration": "Early bug detection", "Continuous Deployment": "Faster time to market"},
            {"Aspect": "Key Activities", "Continuous Integration": "Build, test, merge", "Continuous Deployment": "Deploy, monitor, rollback"},
            {"Aspect": "Risk Level", "Continuous Integration": "Lower", "Continuous Deployment": "Higher (requires maturity)"}
        ]
        
        df = pd.DataFrame(cicd_comparison)
        st.dataframe(df, use_container_width=True)
        
        # Benefits
        col1, col2 = st.columns(2)
        
        with col1:
            create_info_card(
                " CI Benefits",
                "Early detection of integration issues and bugs",
                card_type="success",
                color_scheme=self.color_scheme
            )
            
            ci_benefits = [
                "Faster bug detection",
                "Reduced integration problems", 
                "Improved code quality",
                "Faster development cycles",
                "Better team collaboration"
            ]
            for benefit in ci_benefits:
                st.markdown(f" {benefit}")
        
        with col2:
            create_info_card(
                " CD Benefits",
                "Automated and reliable software delivery",
                card_type="primary",
                color_scheme=self.color_scheme
            )
            
            cd_benefits = [
                "Faster time to market",
                "Reduced deployment risks",
                "Consistent environments",
                "Automated rollbacks",
                "Improved user feedback loop"
            ]
            for benefit in cd_benefits:
                st.markdown(f" {benefit}")
    
    def _render_pipeline_stages(self):
        """Render CI/CD pipeline stages"""
        st.subheader(" CI/CD Pipeline Stages")
        
        pipeline_stages = [
            {
                "stage": "1. Source Control",
                "description": "Code commit triggers the pipeline",
                "tools": ["Git", "GitHub", "GitLab", "Bitbucket"],
                "activities": ["Code commit", "Branch management", "Pull requests", "Code review"]
            },
            {
                "stage": "2. Build",
                "description": "Compile source code into executable artifacts",
                "tools": ["Maven", "Gradle", "npm", "Docker"],
                "activities": ["Compile code", "Dependency management", "Package artifacts", "Version tagging"]
            },
            {
                "stage": "3. Test",
                "description": "Automated testing at multiple levels",
                "tools": ["JUnit", "Jest", "Selenium", "Cypress"],
                "activities": ["Unit tests", "Integration tests", "UI tests", "Security scans"]
            },
            {
                "stage": "4. Quality Gates",
                "description": "Code quality and security checks",
                "tools": ["SonarQube", "ESLint", "Checkmarx", "Snyk"],
                "activities": ["Code coverage", "Static analysis", "Security scanning", "Quality metrics"]
            },
            {
                "stage": "5. Deploy",
                "description": "Automated deployment to environments",
                "tools": ["Kubernetes", "Docker", "Terraform", "Ansible"],
                "activities": ["Environment provisioning", "Application deployment", "Configuration management", "Health checks"]
            },
            {
                "stage": "6. Monitor",
                "description": "Continuous monitoring and feedback",
                "tools": ["Prometheus", "Grafana", "New Relic", "Datadog"],
                "activities": ["Performance monitoring", "Error tracking", "User analytics", "Alerting"]
            }
        ]
        
        # Interactive stage explorer
        selected_stage = st.selectbox(
            " Explore Pipeline Stage:",
            [stage["stage"] for stage in pipeline_stages],
            key="pipeline_stage_selector"
        )
        
        # Find selected stage info
        stage_info = next(stage for stage in pipeline_stages if stage["stage"] == selected_stage)
        
        create_info_card(
            f" {stage_info['stage']}",
            stage_info['description'],
            card_type="primary",
            color_scheme=self.color_scheme
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("** Common Tools:**")
            for tool in stage_info['tools']:
                st.markdown(f" {tool}")
        
        with col2:
            st.markdown("** Key Activities:**")
            for activity in stage_info['activities']:
                st.markdown(f" {activity}")
    
    def _render_tools_platforms(self):
        """Render CI/CD tools and platforms"""
        st.subheader(" CI/CD Tools & Platforms")
        
        cicd_platforms = {
            "GitHub Actions": {
                "type": "Cloud-native",
                "pricing": "Free for public repos",
                "strengths": ["GitHub integration", "Large marketplace", "Easy YAML config"],
                "use_cases": ["Open source projects", "GitHub-hosted repositories"]
            },
            "GitLab CI/CD": {
                "type": "Integrated platform",
                "pricing": "Free tier available",
                "strengths": ["Built-in CI/CD", "Container registry", "Security scanning"],
                "use_cases": ["Complete DevOps platform", "Enterprise environments"]
            },
            "Jenkins": {
                "type": "Self-hosted",
                "pricing": "Open source",
                "strengths": ["Highly customizable", "Extensive plugins", "On-premise control"],
                "use_cases": ["Legacy systems", "Custom requirements"]
            },
            "Azure DevOps": {
                "type": "Cloud platform",
                "pricing": "Free for small teams",
                "strengths": ["Microsoft ecosystem", "Boards integration", "Release management"],
                "use_cases": ["Microsoft stack", "Enterprise projects"]
            },
            "CircleCI": {
                "type": "Cloud-native",
                "pricing": "Free tier + paid plans",
                "strengths": ["Docker support", "Parallel execution", "Orbs ecosystem"],
                "use_cases": ["Docker-based apps", "Fast builds"]
            }
        }
        
        # Platform selector
        selected_platform = st.selectbox(
            " Explore CI/CD Platform:",
            list(cicd_platforms.keys()),
            key="cicd_platform_selector"
        )
        
        platform_info = cicd_platforms[selected_platform]
        
        create_info_card(
            f" {selected_platform}",
            f"Type: {platform_info['type']} | Pricing: {platform_info['pricing']}",
            card_type="info",
            color_scheme=self.color_scheme
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("** Key Strengths:**")
            for strength in platform_info['strengths']:
                st.markdown(f" {strength}")
        
        with col2:
            st.markdown("** Best Use Cases:**")
            for use_case in platform_info['use_cases']:
                st.markdown(f" {use_case}")
    
    def _render_best_practices(self):
        """Render CI/CD best practices"""
        st.subheader(" CI/CD Best Practices")
        
        best_practices = {
            "Code Management": [
                "Commit code frequently (at least daily)",
                "Use feature branches and pull requests",
                "Maintain a stable main branch",
                "Write meaningful commit messages"
            ],
            "Build Process": [
                "Keep builds fast (under 10 minutes)",
                "Make builds deterministic and repeatable",
                "Use dependency caching",
                "Fail fast on errors"
            ],
            "Testing Strategy": [
                "Implement test pyramid (unit > integration > e2e)",
                "Maintain high test coverage (>80%)",
                "Run tests in parallel",
                "Use test data management"
            ],
            "Deployment": [
                "Use infrastructure as code",
                "Implement blue-green deployments",
                "Enable feature flags",
                "Plan rollback strategies"
            ],
            "Monitoring": [
                "Monitor application and infrastructure",
                "Set up alerting and notifications",
                "Track deployment metrics",
                "Implement logging and tracing"
            ]
        }
        
        # Display best practices in expandable sections
        for category, practices in best_practices.items():
            with st.expander(f" {category}"):
                for practice in practices:
                    st.markdown(f" {practice}")
        
        # Common pitfalls
        st.markdown("####  Common CI/CD Pitfalls")
        
        pitfalls = [
            "**Slow builds** - Long feedback loops reduce productivity",
            "**Flaky tests** - Unreliable tests undermine confidence",
            "**Manual processes** - Manual steps break automation",
            "**Poor test coverage** - Bugs slip through to production",
            "**Complex deployments** - Difficult rollbacks and debugging"
        ]
        
        for pitfall in pitfalls:
            st.markdown(pitfall)


def explain_continuous_integration():
    """Main function for Continuous Integration"""
    component = ContinuousIntegrationComponent()
    
    summary_points = [
        "CI/CD automates the software delivery process from code commit to production",
        "Pipeline stages include source control, build, test, quality gates, deploy, and monitor",
        "Modern platforms like GitHub Actions and GitLab CI/CD provide cloud-native solutions",
        "Success requires fast builds, comprehensive testing, and monitoring at every stage"
    ]
    
    resources = [
        {"title": "The DevOps Handbook", "description": "Comprehensive guide to DevOps practices"},
        {"title": "GitHub Actions Documentation", "description": "Official GitHub Actions guides and examples"},
        {"title": "Jenkins User Handbook", "description": "Complete Jenkins automation server guide"},
        {"title": "GitLab CI/CD", "description": "GitLab's built-in CI/CD documentation"}
    ]
    
    component.render_full_component(summary_points, resources)
