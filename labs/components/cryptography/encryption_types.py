import streamlit as st
import pandas as pd

def explain_encryption_types():
    """Encryption Types using TDD pattern"""
    
    st.markdown("## Encryption Types")
    st.markdown("**Definition:** Different methods and algorithms for encrypting data to ensure confidentiality.")
    
    st.markdown("---")
    
    # Encryption Categories
    st.markdown("### Encryption Categories")
    
    encryption_data = {
        "Type": ["Symmetric", "Asymmetric", "Hash Functions", "Digital Signatures"],
        "Description": [
            "Same key for encryption and decryption",
            "Public/private key pairs",
            "One-way cryptographic functions",
            "Verify authenticity and integrity"
        ],
        "Examples": [
            "AES, DES, 3DES",
            "RSA, ECC, DSA",
            "SHA-256, MD5",
            "RSA signatures, ECDSA"
        ]
    }
    
    df = pd.DataFrame(encryption_data)
    st.dataframe(df, use_container_width=True)
    
    # Key Takeaways
    st.markdown("### Key Takeaways")
    
    st.markdown("""
    <div style="background-color: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc;">
        <ul>
            <li><strong>Choose Wisely:</strong> Different types serve different purposes</li>
            <li><strong>Key Management:</strong> Proper key handling is crucial</li>
            <li><strong>Performance Trade-offs:</strong> Balance security with performance</li>
            <li><strong>Standards Compliance:</strong> Use approved algorithms and implementations</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
