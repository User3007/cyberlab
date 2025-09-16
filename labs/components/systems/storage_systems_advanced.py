import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_storage_systems():
    """Storage Systems using TDD pattern"""
    
    st.markdown("## Storage Systems")
    st.markdown("**Definition:** Hardware and software components that store, organize, and provide access to data, ranging from primary storage (RAM) to secondary storage (HDD, SSD) and tertiary storage (tape, optical).")
    
    st.markdown("---")
    
    # Storage Types Comparison
    st.markdown("### Storage Types Comparison")
    
    storage_data = {
        "Storage Type": ["RAM", "SSD", "HDD", "NVMe SSD", "Tape Storage", "Optical Storage"],
        "Technology": ["DRAM/SRAM", "NAND Flash", "Magnetic Disk", "NAND Flash + PCIe", "Magnetic Tape", "Laser + Optical Media"],
        "Speed": ["Very Fast", "Fast", "Slow", "Ultra Fast", "Very Slow", "Slow"],
        "Capacity": ["8-128 GB", "256 GB - 8 TB", "500 GB - 20 TB", "256 GB - 8 TB", "1-30 TB per tape", "25-100 GB"],
        "Cost per GB": ["$8-15", "$0.10-0.20", "$0.02-0.05", "$0.15-0.30", "$0.005-0.01", "$0.50-1.00"],
        "Use Case": [
            "System memory, cache",
            "OS drives, databases, applications",
            "Bulk storage, backups, archives",
            "High-performance computing, gaming",
            "Long-term archival, backup",
            "Media distribution, archival"
        ]
    }
    
    df = pd.DataFrame(storage_data)
    st.dataframe(df, use_container_width=True)
    
    # Performance Comparison Chart
    st.markdown("### Storage Performance Comparison")
    
    storage_types = ['HDD', 'SATA SSD', 'NVMe SSD', 'RAM']
    read_speed = [150, 550, 3500, 25000]  # MB/s
    write_speed = [120, 520, 3000, 25000]  # MB/s
    latency = [10, 0.1, 0.02, 0.001]  # ms
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        name='Read Speed (MB/s)',
        x=storage_types,
        y=read_speed,
        yaxis='y'
    ))
    
    fig.add_trace(go.Bar(
        name='Write Speed (MB/s)',
        x=storage_types,
        y=write_speed,
        yaxis='y'
    ))
    
    fig.add_trace(go.Scatter(
        name='Latency (ms)',
        x=storage_types,
        y=latency,
        yaxis='y2',
        mode='lines+markers',
        line=dict(color='red', width=3),
        marker=dict(size=8)
    ))
    
    fig.update_layout(
        title='Storage Performance Comparison',
        xaxis_title='Storage Type',
        yaxis=dict(
            title='Speed (MB/s)',
            side='left'
        ),
        yaxis2=dict(
            title='Latency (ms)',
            side='right',
            overlaying='y',
            type='log'
        ),
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Storage Architecture
    st.markdown("### Storage Architecture Types")
    
    architecture_data = {
        "Architecture": ["DAS", "NAS", "SAN", "Cloud Storage", "Software-Defined Storage"],
        "Full Name": [
            "Direct Attached Storage",
            "Network Attached Storage", 
            "Storage Area Network",
            "Cloud-based Storage",
            "Software-Defined Storage"
        ],
        "Connection": [
            "Direct to server (SATA, SAS, USB)",
            "Network (Ethernet, TCP/IP)",
            "Dedicated network (Fibre Channel, iSCSI)",
            "Internet (REST APIs, web protocols)",
            "Software abstraction layer"
        ],
        "Scalability": ["Limited", "Medium", "High", "Very High", "High"],
        "Cost": ["Low", "Medium", "High", "Variable", "Medium"],
        "Best Use Case": [
            "Single server, small workloads",
            "File sharing, small to medium business",
            "Enterprise, high-performance applications",
            "Backup, collaboration, scalability",
            "Virtualized environments, flexibility"
        ]
    }
    
    df2 = pd.DataFrame(architecture_data)
    st.dataframe(df2, use_container_width=True)
    
    # File Systems
    st.markdown("### File Systems Overview")
    
    filesystem_data = {
        "File System": ["NTFS", "ext4", "APFS", "ZFS", "Btrfs"],
        "Operating System": ["Windows", "Linux", "macOS", "Solaris/Linux", "Linux"],
        "Max File Size": ["16 TB", "16 TB", "8 EB", "16 EB", "16 EB"],
        "Max Volume Size": ["256 TB", "1 EB", "8 EB", "256 ZB", "16 EB"],
        "Key Features": [
            "Compression, encryption, snapshots",
            "Journaling, extents, delayed allocation",
            "Snapshots, cloning, encryption",
            "Checksums, compression, deduplication",
            "Copy-on-write, snapshots, RAID"
        ],
        "Advantages": [
            "Mature, Windows integration",
            "Stable, good performance",
            "Modern features, SSD optimized",
            "Data integrity, enterprise features",
            "Advanced features, flexibility"
        ]
    }
    
    df3 = pd.DataFrame(filesystem_data)
    st.dataframe(df3, use_container_width=True)
    
    # Storage Technologies Deep Dive
    st.markdown("### Storage Technologies")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Hard Disk Drives (HDD):**
        - Magnetic storage on spinning platters
        - 5400-15000 RPM speeds
        - Sequential vs random access performance
        - SMART monitoring for health
        - Best for: Bulk storage, archives, backups
        """)
        
        st.markdown("""
        **Solid State Drives (SSD):**
        - NAND flash memory technology
        - No moving parts, silent operation
        - Wear leveling and over-provisioning
        - TRIM command for maintenance
        - Best for: OS, applications, databases
        """)
    
    with col2:
        st.markdown("""
        **NVMe (Non-Volatile Memory Express):**
        - PCIe interface for maximum speed
        - Low latency, high IOPS
        - Multiple command queues
        - Direct CPU communication
        - Best for: High-performance computing
        """)
        
        st.markdown("""
        **Emerging Technologies:**
        - 3D XPoint (Intel Optane)
        - QLC NAND (Quad-Level Cell)
        - Storage Class Memory (SCM)
        - DNA storage (experimental)
        - Best for: Specific use cases, future
        """)
    
    # Storage Performance Optimization
    st.markdown("### Storage Performance Optimization")
    
    optimization_data = {
        "Technique": ["RAID Configuration", "Caching", "Tiered Storage", "Compression", "Deduplication"],
        "Purpose": [
            "Redundancy, performance, or both",
            "Faster access to frequently used data",
            "Automatic data movement between tiers",
            "Reduce storage space requirements",
            "Eliminate duplicate data blocks"
        ],
        "Implementation": [
            "RAID 0, 1, 5, 6, 10 configurations",
            "SSD cache, RAM cache, controller cache",
            "Hot, warm, cold storage tiers",
            "Hardware or software compression",
            "Block-level or file-level deduplication"
        ],
        "Performance Impact": [
            "Varies by RAID level and workload",
            "Significant improvement for hot data",
            "Optimizes cost and performance",
            "Slight CPU overhead, space savings",
            "CPU overhead, significant space savings"
        ]
    }
    
    df4 = pd.DataFrame(optimization_data)
    st.dataframe(df4, use_container_width=True)
    
    # Storage Security
    st.markdown("### Storage Security Considerations")
    
    security_data = {
        "Security Aspect": ["Encryption", "Access Control", "Secure Erasure", "Backup Security", "Physical Security"],
        "Technologies": [
            "AES-256, BitLocker, FileVault, LUKS",
            "ACLs, RBAC, file permissions",
            "Cryptographic erasure, degaussing",
            "Encrypted backups, offsite storage",
            "Locked facilities, surveillance"
        ],
        "Best Practices": [
            "Full disk encryption, key management",
            "Principle of least privilege",
            "Multi-pass overwrite, verification",
            "3-2-1 backup rule, test restores",
            "Environmental controls, access logs"
        ]
    }
    
    df5 = pd.DataFrame(security_data)
    st.dataframe(df5, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Choose Right Technology:</strong> Match storage type to workload requirements</li>
            <li><strong>Performance vs Cost:</strong> Balance speed, capacity, and budget constraints</li>
            <li><strong>Plan for Growth:</strong> Consider scalability and future storage needs</li>
            <li><strong>Implement Security:</strong> Protect data with encryption and access controls</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
