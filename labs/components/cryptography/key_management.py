"""
Cryptographic Key Management - Theory & Concepts Lab
Enhanced with TDD Pattern - Compact UI, Visual Diagrams, Highlighted Keywords
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

def explain_key_management():
    """Cryptographic Key Management - Enhanced with compact TDD pattern"""
    
    # No banner - direct content

    # Key Lifecycle Diagram
    st.markdown("#### Cryptographic Key Lifecycle")
    
    fig = go.Figure()
    
    # Key lifecycle stages
    stages = [
        {"name": "Generation", "x": 1, "y": 3, "color": "#FF6B6B", "desc": "Create secure keys"},
        {"name": "Distribution", "x": 3, "y": 3, "color": "#4ECDC4", "desc": "Share keys securely"},
        {"name": "Storage", "x": 5, "y": 3, "color": "#45B7D1", "desc": "Store keys safely"},
        {"name": "Usage", "x": 7, "y": 3, "color": "#96CEB4", "desc": "Use for crypto ops"},
        {"name": "Rotation", "x": 9, "y": 3, "color": "#FECA57", "desc": "Replace old keys"},
        {"name": "Destruction", "x": 11, "y": 3, "color": "#FF7675", "desc": "Securely delete"}
    ]
    
    # Add lifecycle stages
    for i, stage in enumerate(stages):
        fig.add_shape(
            type="circle",
            x0=stage["x"]-0.4, y0=stage["y"]-0.4,
            x1=stage["x"]+0.4, y1=stage["y"]+0.4,
            fillcolor=stage["color"], opacity=0.8,
            line=dict(color="white", width=2)
        )
        fig.add_annotation(
            x=stage["x"], y=stage["y"]+0.1, text=f"<b>{stage['name']}</b>",
            showarrow=False, font=dict(color="white", size=10)
        )
        fig.add_annotation(
            x=stage["x"], y=stage["y"]-0.8, text=stage["desc"],
            showarrow=False, font=dict(size=9)
        )
        
        # Add arrows between stages
        if i < len(stages) - 1:
            fig.add_annotation(
                x=stage["x"]+0.7, y=stage["y"], text="→",
                showarrow=False, font=dict(size=20, color="#2d3436")
            )
    
    fig.update_layout(
        title="Key Management Lifecycle",
        xaxis=dict(visible=False, range=[0, 12]),
        yaxis=dict(visible=False, range=[1.5, 4.5]),
        height=250, showlegend=False,
        margin=dict(l=0, r=0, t=40, b=0)
    )
    
    st.plotly_chart(fig, use_container_width=True)

    # Compact content
    with st.expander("📚 Key Management Fundamentals"):
        st.markdown("""
        <div style="line-height: 1.4;">
        
        ## Core Concepts
        **Definition:** Key management encompasses all processes for handling cryptographic keys throughout their lifecycle.
        
        ### Key Principles
        **Confidentiality:** Keys must be protected from unauthorized access  
        **Integrity:** Keys must not be altered without detection  
        **Availability:** Keys must be accessible when needed  
        **Non-repudiation:** Key usage must be traceable and verifiable  
        **Authentication:** Key ownership must be verifiable
        
        ### Key Types
        - **Symmetric Keys:** Same key for encryption and decryption
        - **Asymmetric Keys:** Public/private key pairs
        - **Session Keys:** Temporary keys for single sessions
        - **Master Keys:** Keys used to encrypt other keys
        
        </div>
        """, unsafe_allow_html=True)

    # Enhanced Key Management Cheat Sheet
    st.markdown("## 🔐 Key Management Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["🔑 Key Types & Uses", "🏪 Storage Methods", "🔄 Best Practices"])
    
    with tab1:
        st.markdown("### 🔑 Key Types & Applications")
        
        # Symmetric Keys Section
        st.markdown("#### 🔄 Symmetric Keys")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    🔐 AES Keys <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">128/256 bit</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Bulk data encryption</p>
                <small style="opacity: 0.8;">🚀 Fast, efficient for large data</small>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div style="background: linear-gradient(135deg, #00b894 0%, #00cec9 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    🔑 Session Keys <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">Temporary</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Single session encryption</p>
                <small style="opacity: 0.8;">⏱️ Short-lived, high security</small>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #fd79a8 0%, #e84393 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    🔓 Public Keys <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">2048+ bit</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Encryption, verification</p>
                <small style="opacity: 0.8;">🌍 Shareable, mathematically linked</small>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div style="background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    🔒 Private Keys <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">2048+ bit</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Decryption, signing</p>
                <small style="opacity: 0.8;">🔐 Secret, never shared</small>
            </div>
            """, unsafe_allow_html=True)

    with tab2:
        st.markdown("### 🏪 Key Storage Methods")
        
        # Hardware vs Software Storage
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🔧 Hardware Storage")
            st.markdown("""
            <div style="background: linear-gradient(135deg, #00b894 0%, #00a085 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0;">🔐 HSM (Hardware Security Module)</h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Dedicated crypto hardware</p>
                <small style="opacity: 0.8;">✅ Highest security, tamper-resistant</small>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div style="background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0;">💳 Smart Cards</h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Portable secure storage</p>
                <small style="opacity: 0.8;">🎫 Personal keys, authentication</small>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("#### 💻 Software Storage")
            st.markdown("""
            <div style="background: linear-gradient(135deg, #fdcb6e 0%, #e17055 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0;">📁 Key Files</h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Encrypted file storage</p>
                <small style="opacity: 0.8;">⚠️ Requires strong file encryption</small>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div style="background: linear-gradient(135deg, #a55eea 0%, #8854d0 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0;">☁️ Key Vaults</h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Cloud-based key storage</p>
                <small style="opacity: 0.8;">🌐 Azure Key Vault, AWS KMS</small>
            </div>
            """, unsafe_allow_html=True)

    with tab3:
        st.markdown("### 🔄 Key Management Best Practices")
        
        # Security Practices
        practices_data = [
            {
                "Practice": "🔄 Regular Rotation",
                "Description": "Change keys periodically",
                "Frequency": "Monthly/Yearly",
                "Risk Level": "🟢 Low"
            },
            {
                "Practice": "🔐 Strong Generation",
                "Description": "Use cryptographically secure random",
                "Frequency": "Every generation",
                "Risk Level": "🟢 Low"
            },
            {
                "Practice": "🚫 Key Separation",
                "Description": "Separate encryption and signing keys",
                "Frequency": "Always",
                "Risk Level": "🟢 Low"
            },
            {
                "Practice": "📝 Access Logging",
                "Description": "Log all key access and usage",
                "Frequency": "Continuous",
                "Risk Level": "🟡 Medium"
            },
            {
                "Practice": "🗑️ Secure Destruction",
                "Description": "Properly delete expired keys",
                "Frequency": "After expiry",
                "Risk Level": "🔴 High"
            }
        ]
        
        df_practices = pd.DataFrame(practices_data)
        st.dataframe(df_practices, use_container_width=True, height=200)

    # Interactive Key Generator Demo
    st.markdown("## 🔧 Key Management Simulator")
    
    with st.expander("Key Generation & Rotation Demo"):
        col1, col2 = st.columns([2, 1])
        
        with col1:
            key_type = st.selectbox(
                "Select Key Type:", 
                ["AES-256", "RSA-2048", "RSA-4096", "ECDSA-P256"],
                key="key_mgmt_type"
            )
            
            key_purpose = st.selectbox(
                "Key Purpose:",
                ["Data Encryption", "Digital Signing", "Key Exchange", "Authentication"],
                key="key_mgmt_purpose"
            )
            
            rotation_period = st.slider("Rotation Period (days):", 30, 365, 90, key="key_mgmt_rotation")
            
        with col2:
            if st.button("Generate Key", key="key_mgmt_generate"):
                import secrets
                
                # Simulate key generation
                if "AES" in key_type:
                    key_length = 32  # 256 bits
                    simulated_key = secrets.token_hex(key_length)[:16] + "..."
                else:
                    simulated_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0B..."
                
                st.success("✅ Key Generated!")
                st.code(f"Key ID: {secrets.token_hex(8)}")
                st.code(f"Type: {key_type}")
                st.code(f"Purpose: {key_purpose}")
                st.info(f"🔄 Next rotation: {rotation_period} days")

    # Key Security Levels Comparison
    st.markdown("## 🛡️ Security Level Comparison")
    
    # Create security comparison chart
    storage_methods = ['File Storage', 'Database', 'Key Vault', 'HSM', 'Air-gapped HSM']
    security_scores = [30, 50, 75, 90, 95]
    cost_scores = [10, 20, 60, 80, 95]
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        name='Security Level',
        x=storage_methods,
        y=security_scores,
        marker_color='#00b894',
        yaxis='y'
    ))
    
    fig.add_trace(go.Scatter(
        name='Cost Level',
        x=storage_methods,
        y=cost_scores,
        mode='lines+markers',
        marker_color='#e17055',
        yaxis='y2'
    ))
    
    fig.update_layout(
        title="Key Storage: Security vs Cost Analysis",
        xaxis_title="Storage Methods",
        yaxis=dict(title="Security Level (%)", side="left"),
        yaxis2=dict(title="Cost Level (%)", side="right", overlaying="y"),
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)

    # Compact Key Takeaways
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1rem; border-radius: 8px; border-left: 4px solid #6c5ce7; margin-top: 1rem;">
        <h4 style="margin: 0 0 0.5rem 0; color: #6c5ce7; font-size: 1.1rem;">🎯 Key Takeaways</h4>
        <ul style="margin: 0; padding-left: 1.2rem; line-height: 1.4;">
            <li><strong>Lifecycle Management:</strong> Keys need proper generation, distribution, storage, rotation, and destruction</li>
            <li><strong>Storage Security:</strong> HSMs provide highest security, cloud vaults balance security and convenience</li>
            <li><strong>Key Types:</strong> Use symmetric keys for bulk data, asymmetric for key exchange and signatures</li>
            <li><strong>Regular Rotation:</strong> Change keys periodically to limit exposure from potential compromise</li>
            <li><strong>Access Control:</strong> Implement strict access controls and audit all key operations</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

    # Resources
    st.markdown("## 📚 Learning Resources")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **📖 Standards & Guidelines:**
        - [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) - Key Management Recommendations
        - [PKCS #11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/) - Cryptographic Token Interface
        - [RFC 3647](https://tools.ietf.org/html/rfc3647) - Certificate Policy Framework
        """)
    
    with col2:
        st.markdown("""
        **🎥 Video Learning:**
        - [Key Management Explained](https://www.youtube.com/watch?v=kY-Bkv3qxMc)
        - [HSM vs Software Keys](https://www.youtube.com/watch?v=2aHkqB2-46k)
        - [PKI and Certificate Management](https://www.youtube.com/watch?v=i-rtxrEz_E4)
        """)

if __name__ == "__main__":
    explain_key_management()
