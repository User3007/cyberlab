import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def explain_modern_cryptography_standards():
    """Modern Cryptography Standards using TDD pattern"""
    
    st.markdown("## Modern Cryptography Standards")
    st.markdown("**Definition:** Current cryptographic algorithms, protocols, and standards used for secure communications and data protection.")
    
    st.markdown("---")
    
    # Symmetric Encryption Standards
    st.markdown("### Symmetric Encryption Standards")
    
    symmetric_data = {
        "Algorithm": ["AES-128", "AES-192", "AES-256", "ChaCha20", "Blowfish", "3DES"],
        "Key Size": ["128 bits", "192 bits", "256 bits", "256 bits", "32-448 bits", "168 bits"],
        "Block Size": ["128 bits", "128 bits", "128 bits", "512 bits", "64 bits", "64 bits"],
        "Status": ["Recommended", "Recommended", "Recommended", "Recommended", "Deprecated", "Deprecated"],
        "Use Case": [
            "General purpose encryption",
            "High security applications",
            "Top secret data",
            "Stream cipher, mobile",
            "Legacy systems",
            "Legacy compatibility"
        ]
    }
    
    df = pd.DataFrame(symmetric_data)
    st.dataframe(df, use_container_width=True)
    
    # Asymmetric Encryption Standards
    st.markdown("### Asymmetric Encryption Standards")
    
    asymmetric_data = {
        "Algorithm": ["RSA-2048", "RSA-3072", "RSA-4096", "ECC P-256", "ECC P-384", "ECC P-521"],
        "Key Size": ["2048 bits", "3072 bits", "4096 bits", "256 bits", "384 bits", "521 bits"],
        "Security Level": ["112 bits", "128 bits", "150 bits", "128 bits", "192 bits", "256 bits"],
        "Performance": ["Fast", "Medium", "Slow", "Very Fast", "Fast", "Medium"],
        "Use Case": [
            "Digital signatures",
            "Key exchange",
            "High security",
            "Mobile, IoT",
            "Government",
            "Military"
        ]
    }
    
    df2 = pd.DataFrame(asymmetric_data)
    st.dataframe(df2, use_container_width=True)
    
    # Hash Function Standards
    st.markdown("### Hash Function Standards")
    
    hash_data = {
        "Algorithm": ["SHA-256", "SHA-384", "SHA-512", "SHA-3-256", "SHA-3-512", "BLAKE2"],
        "Output Size": ["256 bits", "384 bits", "512 bits", "256 bits", "512 bits", "256-512 bits"],
        "Security Level": ["128 bits", "192 bits", "256 bits", "128 bits", "256 bits", "128-256 bits"],
        "Performance": ["Fast", "Medium", "Slow", "Medium", "Slow", "Very Fast"],
        "Status": ["Recommended", "Recommended", "Recommended", "New Standard", "New Standard", "Alternative"]
    }
    
    df3 = pd.DataFrame(hash_data)
    st.dataframe(df3, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Algorithm Selection:</strong> Choose based on security requirements</li>
            <li><strong>Key Length:</strong> Use appropriate key sizes for security level</li>
            <li><strong>Performance Trade-offs:</strong> Balance security with performance</li>
            <li><strong>Standards Compliance:</strong> Follow established cryptographic standards</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
