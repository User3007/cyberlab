"""
Virtualization Concepts - IT Fundamentals Lab
Enhanced with TDD Pattern - Compact UI, Visual Diagrams, Highlighted Keywords
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

def explain_virtualization():
    """Virtualization Concepts - Enhanced with compact TDD pattern"""
    
    # No banner - direct content

    # Virtualization Architecture Diagram
    st.markdown("#### Virtualization Stack Overview")
    
    fig = go.Figure()
    
    # Virtualization layers
    layers = [
        {"name": "Applications", "y": 5, "color": "#FF6B6B", "width": 8},
        {"name": "Guest OS", "y": 4, "color": "#4ECDC4", "width": 8},
        {"name": "Virtual Machine", "y": 3, "color": "#45B7D1", "width": 8},
        {"name": "Hypervisor", "y": 2, "color": "#96CEB4", "width": 10},
        {"name": "Host OS", "y": 1, "color": "#FECA57", "width": 10},
        {"name": "Physical Hardware", "y": 0, "color": "#A0A0A0", "width": 12}
    ]
    
    for layer in layers:
        x_offset = (12 - layer["width"]) / 2
        fig.add_shape(
            type="rect",
            x0=x_offset, y0=layer["y"]-0.3, 
            x1=x_offset + layer["width"], y1=layer["y"]+0.3,
            fillcolor=layer["color"], opacity=0.7,
            line=dict(color="white", width=2)
        )
        fig.add_annotation(
            x=6, y=layer["y"], text=f"<b>{layer['name']}</b>",
            showarrow=False, font=dict(color="white", size=11)
        )
    
    fig.update_layout(
        title="Virtualization Technology Stack",
        xaxis=dict(visible=False), yaxis=dict(visible=False),
        height=350, showlegend=False,
        margin=dict(l=0, r=0, t=40, b=0)
    )
    
    st.plotly_chart(fig, use_container_width=True)

    # Compact content
    with st.expander("📚 Virtualization Fundamentals"):
        st.markdown("""
        <div style="line-height: 1.4;">
        
        ## **Core Concepts**
        **Definition:** Virtualization creates virtual versions of physical computing resources.
        
        ### **Key Benefits**
        **Resource Efficiency:** Multiple VMs on single hardware  
        **Isolation:** Separate environments for security  
        **Scalability:** Easy to scale up/down resources  
        **Cost Reduction:** Better hardware utilization  
        **Disaster Recovery:** Easy backup and migration
        
        ### **Types of Virtualization**
        - **Server Virtualization:** Multiple OS on one server
        - **Desktop Virtualization:** Virtual desktop infrastructure (VDI)
        - **Network Virtualization:** Software-defined networking (SDN)
        - **Storage Virtualization:** Pooled storage resources
        
        </div>
        """, unsafe_allow_html=True)

    # Compact Cheat Sheet
    st.markdown("## 📋 Virtualization Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["VM vs Containers", "Hypervisors", "Cloud Services"])
    
    with tab1:
        st.markdown("### Virtual Machines vs Containers")
        comparison_data = [
            {
                "Aspect": "Architecture",
                "Virtual Machines": "Full OS + Apps",
                "Containers": "Shared OS kernel + Apps",
                "Winner": "Containers (lighter)"
            },
            {
                "Aspect": "Resource Usage",
                "Virtual Machines": "High (GB RAM per VM)",
                "Containers": "Low (MB RAM per container)",
                "Winner": "Containers"
            },
            {
                "Aspect": "Boot Time",
                "Virtual Machines": "Minutes",
                "Containers": "Seconds",
                "Winner": "Containers"
            },
            {
                "Aspect": "Isolation",
                "Virtual Machines": "Complete isolation",
                "Containers": "Process-level isolation",
                "Winner": "VMs (security)"
            },
            {
                "Aspect": "Portability",
                "Virtual Machines": "Platform dependent",
                "Containers": "Highly portable",
                "Winner": "Containers"
            }
        ]
        
        df_comparison = pd.DataFrame(comparison_data)
        st.dataframe(df_comparison, use_container_width=True, height=200)

    with tab2:
        st.markdown("### Hypervisor Types")
        hypervisor_data = [
            {
                "Type": "Type 1 (Bare Metal)",
                "Installation": "Directly on hardware",
                "Performance": "High",
                "Examples": "VMware ESXi, Hyper-V, Xen",
                "Use Case": "Enterprise servers"
            },
            {
                "Type": "Type 2 (Hosted)",
                "Installation": "On host operating system",
                "Performance": "Lower overhead",
                "Examples": "VMware Workstation, VirtualBox",
                "Use Case": "Development, testing"
            }
        ]
        
        df_hypervisor = pd.DataFrame(hypervisor_data)
        st.dataframe(df_hypervisor, use_container_width=True, height=150)

    with tab3:
        st.markdown("### Cloud Virtualization Services")
        cloud_data = [
            {
                "Service": "IaaS",
                "Full Name": "Infrastructure as a Service",
                "What You Get": "Virtual machines, storage, networks",
                "Examples": "AWS EC2, Azure VMs, GCP Compute",
                "Control Level": "High"
            },
            {
                "Service": "PaaS",
                "Full Name": "Platform as a Service", 
                "What You Get": "Runtime environment, databases",
                "Examples": "Heroku, AWS Elastic Beanstalk",
                "Control Level": "Medium"
            },
            {
                "Service": "SaaS",
                "Full Name": "Software as a Service",
                "What You Get": "Ready-to-use applications",
                "Examples": "Office 365, Google Workspace",
                "Control Level": "Low"
            },
            {
                "Service": "CaaS",
                "Full Name": "Containers as a Service",
                "What You Get": "Container orchestration",
                "Examples": "AWS ECS, Azure Container Instances",
                "Control Level": "Medium-High"
            }
        ]
        
        df_cloud = pd.DataFrame(cloud_data)
        st.dataframe(df_cloud, use_container_width=True, height=200)

    # Interactive Demo
    st.markdown("## 🔧 Virtualization Calculator")
    
    with st.expander("Resource Planning Tool"):
        col1, col2 = st.columns([2, 1])
        
        with col1:
            physical_cpu = st.slider("Physical CPU Cores:", 4, 64, 16, key="virt_cpu_cores")
            physical_ram = st.slider("Physical RAM (GB):", 8, 512, 64, key="virt_ram_gb")
            vm_cpu = st.slider("CPU per VM:", 1, 8, 2, key="virt_vm_cpu")
            vm_ram = st.slider("RAM per VM (GB):", 1, 16, 4, key="virt_vm_ram")
            
        with col2:
            if st.button("Calculate VMs", key="virt_calculate"):
                max_vms_cpu = physical_cpu // vm_cpu
                max_vms_ram = physical_ram // vm_ram
                max_vms = min(max_vms_cpu, max_vms_ram)
                
                st.success(f"**Max VMs:** {max_vms}")
                st.info(f"**CPU Limit:** {max_vms_cpu} VMs")
                st.info(f"**RAM Limit:** {max_vms_ram} VMs")
                
                if max_vms_cpu < max_vms_ram:
                    st.warning("⚠️ CPU is the bottleneck")
                else:
                    st.warning("⚠️ RAM is the bottleneck")

    # Container vs VM Performance Comparison
    st.markdown("## 📊 Performance Comparison")
    
    # Create performance comparison chart
    metrics = ['Boot Time', 'Memory Usage', 'CPU Overhead', 'Storage Efficiency']
    vm_scores = [2, 3, 2, 3]  # Lower is better
    container_scores = [5, 5, 4, 5]  # Higher is better
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatterpolar(
        r=vm_scores,
        theta=metrics,
        fill='toself',
        name='Virtual Machines',
        fillcolor='rgba(255, 107, 107, 0.3)',
        line=dict(color='#FF6B6B')
    ))
    
    fig.add_trace(go.Scatterpolar(
        r=container_scores,
        theta=metrics,
        fill='toself',
        name='Containers',
        fillcolor='rgba(78, 205, 196, 0.3)',
        line=dict(color='#4ECDC4')
    ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 5]
            )),
        title="Performance Comparison: VMs vs Containers",
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)

    # Compact Key Takeaways
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1rem; border-radius: 8px; border-left: 4px solid #667eea; margin-top: 1rem;">
        <h4 style="margin: 0 0 0.5rem 0; color: #667eea; font-size: 1.1rem;">🎯 Key Takeaways</h4>
        <ul style="margin: 0; padding-left: 1.2rem; line-height: 1.4;">
            <li><strong>Virtualization Benefits:</strong> Better resource utilization, isolation, and scalability</li>
            <li><strong>Hypervisor Types:</strong> Type 1 (bare metal) for production, Type 2 (hosted) for development</li>
            <li><strong>VMs vs Containers:</strong> VMs for isolation, containers for efficiency and portability</li>
            <li><strong>Cloud Services:</strong> IaaS (infrastructure), PaaS (platform), SaaS (software)</li>
            <li><strong>Resource Planning:</strong> Consider CPU, RAM, and storage requirements for optimal VM density</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

    # Resources
    st.markdown("## 📚 Learning Resources")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **📖 Documentation:**
        - [VMware vSphere Docs](https://docs.vmware.com/en/VMware-vSphere/)
        - [Docker Documentation](https://docs.docker.com/)
        - [Kubernetes Concepts](https://kubernetes.io/docs/concepts/)
        """)
    
    with col2:
        st.markdown("""
        **🎥 Video Learning:**
        - [Virtualization Explained](https://www.youtube.com/watch?v=FZR0rG3HKIk)
        - [Docker vs VMs](https://www.youtube.com/watch?v=TvnZTi_gaNc)
        - [Cloud Computing Basics](https://www.youtube.com/watch?v=M988_fsOSWo)
        """)

if __name__ == "__main__":
    explain_virtualization()
